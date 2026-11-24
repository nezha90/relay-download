package agenta

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"relay-download/internal/auth"
	"relay-download/internal/pki"
	"relay-download/internal/protocol"
	"relay-download/internal/transfer"
)

type Agent struct {
	cfg        *Config
	store      *Store
	logger     *slog.Logger
	httpClient *http.Client
	limiter    *transfer.RateLimiter

	uploadDir string
	readyDir  string

	localSrv  *http.Server
	publicSrv *http.Server

	localLn  net.Listener
	publicLn net.Listener

	streamSem     chan struct{}
	activeStreams atomic.Int32
	outBytes      atomic.Int64
	lastSpeedBps  atomic.Int64

	hbWakeCh    chan struct{}
	eventWakeCh chan struct{}

	// Optional test hook to inject fault during streaming (unused in production).
	StreamChunkHook func(fileID string, sentTotal int64) error

	runMu     sync.Mutex
	runCancel context.CancelFunc
	bgWG      sync.WaitGroup
	closeOnce sync.Once
}

func New(cfg *Config, logger *slog.Logger) (*Agent, error) {
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}

	uploadDir := filepath.Join(cfg.DataDir, "uploading")
	readyDir := filepath.Join(cfg.DataDir, "ready")
	if err := os.MkdirAll(uploadDir, 0o755); err != nil {
		return nil, fmt.Errorf("create upload dir: %w", err)
	}
	if err := os.MkdirAll(readyDir, 0o755); err != nil {
		return nil, fmt.Errorf("create ready dir: %w", err)
	}

	store, err := OpenStore(filepath.Join(cfg.DataDir, "agent-a.db"))
	if err != nil {
		return nil, err
	}

	clientTLS, err := pki.ClientTLSConfig(cfg.CACert)
	if err != nil {
		_ = store.Close()
		return nil, err
	}

	var limiter *transfer.RateLimiter
	if cfg.RateLimitMBps > 0 {
		limiter = transfer.NewRateLimiter(int64(cfg.RateLimitMBps * 1024 * 1024))
	}

	a := &Agent{
		cfg:       cfg,
		store:     store,
		logger:    logger.With("component", "agent-a", "node_id", cfg.NodeID),
		uploadDir: uploadDir,
		readyDir:  readyDir,
		limiter:   limiter,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     clientTLS,
				ForceAttemptHTTP2:   true,
				MaxIdleConns:        16,
				IdleConnTimeout:     60 * time.Second,
				TLSHandshakeTimeout: 10 * time.Second,
			},
		},
		streamSem:   make(chan struct{}, cfg.MaxConcurrentStreams),
		hbWakeCh:    make(chan struct{}, 1),
		eventWakeCh: make(chan struct{}, 1),
	}

	if err := a.reconcileOnStartup(); err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("startup reconcile: %w", err)
	}
	return a, nil
}

func (a *Agent) Start(ctx context.Context) error {
	serverTLS, err := pki.ServerTLSConfig(a.cfg.TLSCert, a.cfg.TLSKey)
	if err != nil {
		return err
	}

	localLn, err := net.Listen("tcp", a.cfg.LocalListen)
	if err != nil {
		return fmt.Errorf("listen local %s: %w", a.cfg.LocalListen, err)
	}
	rawPubLn, err := net.Listen("tcp", a.cfg.PublicListen)
	if err != nil {
		_ = localLn.Close()
		return fmt.Errorf("listen public %s: %w", a.cfg.PublicListen, err)
	}
	pubLn := tls.NewListener(rawPubLn, serverTLS)

	a.localLn = localLn
	a.publicLn = pubLn

	a.localSrv = &http.Server{
		Handler:           a.localRoutes(),
		ReadHeaderTimeout: 30 * time.Second,
	}
	a.publicSrv = &http.Server{
		Handler:           a.publicRoutes(),
		TLSConfig:         serverTLS,
		ReadHeaderTimeout: 30 * time.Second,
	}

	errCh := make(chan error, 2)
	go func() {
		a.logger.Info("local upload server listening", "addr", localLn.Addr().String())
		if err := a.localSrv.Serve(localLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("local server: %w", err)
		}
	}()
	go func() {
		a.logger.Info("public transfer server listening (TLS)", "addr", pubLn.Addr().String())
		if err := a.publicSrv.Serve(pubLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("public server: %w", err)
		}
	}()

	runCtx, runCancel := context.WithCancel(ctx)
	a.runMu.Lock()
	a.runCancel = runCancel
	a.runMu.Unlock()

	launchBG := func(fn func(context.Context)) {
		a.bgWG.Add(1)
		go func() {
			defer a.bgWG.Done()
			fn(runCtx)
		}()
	}
	launchBG(a.speedMeterLoop)
	launchBG(a.reapLoop)
	launchBG(a.heartbeatLoop)
	launchBG(a.eventFlushLoop)

	select {
	case <-ctx.Done():
		return a.Shutdown(context.Background())
	case err := <-errCh:
		_ = a.Shutdown(context.Background())
		return err
	}
}

func (a *Agent) LocalAddr() string {
	if a.localLn != nil {
		return a.localLn.Addr().String()
	}
	return a.cfg.LocalListen
}

func (a *Agent) PublicListenAddr() string {
	if a.publicLn != nil {
		return a.publicLn.Addr().String()
	}
	return a.cfg.PublicListen
}

func (a *Agent) Shutdown(ctx context.Context) error {
	var shutdownErr error
	a.closeOnce.Do(func() {
		a.runMu.Lock()
		cancel := a.runCancel
		a.runMu.Unlock()
		if cancel != nil {
			cancel()
		}
		shCtx, cancelSh := context.WithTimeout(ctx, 10*time.Second)
		defer cancelSh()
		if a.localSrv != nil {
			_ = a.localSrv.Shutdown(shCtx)
		}
		if a.publicSrv != nil {
			_ = a.publicSrv.Shutdown(shCtx)
		}
		a.bgWG.Wait()
		if a.store != nil {
			shutdownErr = a.store.Close()
		}
	})
	return shutdownErr
}

func (a *Agent) reconcileOnStartup() error {
	// Clean any incomplete uploads left from a prior crash.
	if entries, err := os.ReadDir(a.uploadDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				_ = os.Remove(filepath.Join(a.uploadDir, e.Name()))
			}
		}
	}

	knownIDs, err := a.store.AllFileIDs()
	if err != nil {
		return err
	}
	// Remove DB records whose backing file is missing.
	for id := range knownIDs {
		if _, err := os.Stat(a.readyFilePath(id)); errors.Is(err, os.ErrNotExist) {
			_ = a.store.DeleteRecord(id)
			delete(knownIDs, id)
		}
	}
	// Remove orphaned files in readyDir not present in DB.
	if entries, err := os.ReadDir(a.readyDir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			id := strings.TrimSuffix(e.Name(), ".dat")
			if _, ok := knownIDs[id]; !ok {
				_ = os.Remove(filepath.Join(a.readyDir, e.Name()))
			}
		}
	}
	return nil
}

func (a *Agent) readyFilePath(fileID string) string {
	return filepath.Join(a.readyDir, fileID+".dat")
}

func (a *Agent) diskWatermarkStatus(extraBytes uint64) (total, free uint64, usedPct float64, alarm bool, err error) {
	total, free, usedPct, err = transfer.DiskUsage(a.cfg.DataDir)
	if err != nil {
		return 0, 0, 0, false, err
	}
	effFree := free
	if extraBytes > 0 {
		if extraBytes >= effFree {
			effFree = 0
		} else {
			effFree -= extraBytes
		}
	}
	effUsedPct := usedPct
	if total > 0 && extraBytes > 0 {
		effUsedPct = (float64(total-effFree) / float64(total)) * 100.0
	}
	if a.cfg.MaxDiskUsagePct > 0 && effUsedPct >= a.cfg.MaxDiskUsagePct {
		alarm = true
	}
	if a.cfg.MinFreeDiskBytes > 0 && effFree < a.cfg.MinFreeDiskBytes {
		alarm = true
	}
	return total, free, usedPct, alarm, nil
}

func (a *Agent) triggerHeartbeat() {
	select {
	case a.hbWakeCh <- struct{}{}:
	default:
	}
}

func (a *Agent) triggerEventFlush() {
	select {
	case a.eventWakeCh <- struct{}{}:
	default:
	}
}

func (a *Agent) localRoutes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /local/v1/upload", a.requireLocalAuth(a.handleLocalUpload))
	mux.HandleFunc("POST /local/v1/register", a.requireLocalAuth(a.handleLocalRegister))
	mux.HandleFunc("GET /local/v1/status", a.requireLocalAuth(a.handleLocalStatus))
	return mux
}

func (a *Agent) publicRoutes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/claim", a.handleClaim)
	mux.HandleFunc("GET /api/v1/files/{id}/stream", a.handleStream)
	mux.HandleFunc("POST /api/v1/files/{id}/renew", a.handleRenew)
	mux.HandleFunc("POST /api/v1/files/{id}/ack", a.handleAck)
	mux.HandleFunc("POST /api/v1/files/{id}/nack", a.handleNack)
	mux.HandleFunc("GET /internal/v1/files", a.handleInternalLiveFiles)
	return mux
}

func (a *Agent) requireLocalAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := r.Header.Get(protocol.HeaderLocalToken)
		if a.cfg.LocalToken == "" || !auth.EqualConstantTime(tok, a.cfg.LocalToken) {
			protocol.WriteError(w, http.StatusUnauthorized, "invalid local token")
			return
		}
		next(w, r)
	}
}

func (a *Agent) handleLocalUpload(w http.ResponseWriter, r *http.Request) {
	var extraBytes uint64
	if r.ContentLength > 0 {
		extraBytes = uint64(r.ContentLength)
	}
	_, _, _, alarm, err := a.diskWatermarkStatus(extraBytes)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "disk check failed: "+err.Error())
		return
	}
	if alarm {
		a.triggerHeartbeat()
		protocol.WriteError(w, http.StatusInsufficientStorage, "disk watermark exceeded on agent-a")
		return
	}

	var (
		projectID      = strings.TrimSpace(r.Header.Get(protocol.HeaderProject))
		filename       = strings.TrimSpace(r.Header.Get(protocol.HeaderFilename))
		expectedSHA256 = strings.TrimSpace(r.Header.Get(protocol.HeaderExpectedSHA256))
	)

	fileID := uuid.NewString()
	tmpPath := filepath.Join(a.uploadDir, fileID+".tmp")
	var (
		written   int64
		actualSHA string
	)

	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "multipart/form-data") {
		mr, err := r.MultipartReader()
		if err != nil {
			protocol.WriteError(w, http.StatusBadRequest, "invalid multipart upload: "+err.Error())
			return
		}
		var (
			sawFile      bool
			partFilename string
		)
		for {
			part, err := mr.NextPart()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				_ = os.Remove(tmpPath)
				protocol.WriteError(w, http.StatusBadRequest, "read multipart: "+err.Error())
				return
			}
			switch part.FormName() {
			case "project", "project_id":
				b, _ := io.ReadAll(io.LimitReader(part, 1024))
				projectID = strings.TrimSpace(string(b))
				_ = part.Close()
			case "filename":
				b, _ := io.ReadAll(io.LimitReader(part, 4096))
				filename = strings.TrimSpace(string(b))
				_ = part.Close()
			case "sha256", "expected_sha256":
				b, _ := io.ReadAll(io.LimitReader(part, 256))
				expectedSHA256 = strings.TrimSpace(string(b))
				_ = part.Close()
			case "file":
				if sawFile {
					_ = part.Close()
					_ = os.Remove(tmpPath)
					protocol.WriteError(w, http.StatusBadRequest, "multiple 'file' parts not supported")
					return
				}
				sawFile = true
				partFilename = strings.TrimSpace(part.FileName())
				f, createErr := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
				if createErr != nil {
					_ = part.Close()
					protocol.WriteError(w, http.StatusInternalServerError, "create temp file: "+createErr.Error())
					return
				}
				var copyErr error
				written, actualSHA, copyErr = transfer.CopyStream(r.Context(), f, part, nil, nil)
				syncErr := f.Sync()
				closeErr := f.Close()
				_ = part.Close()
				if copyErr != nil || syncErr != nil || closeErr != nil {
					_ = os.Remove(tmpPath)
					errMsg := fmt.Sprintf("upload write failed: %v %v %v", copyErr, syncErr, closeErr)
					protocol.WriteError(w, http.StatusInternalServerError, errMsg)
					return
				}
			default:
				_ = part.Close()
			}
		}
		if !sawFile {
			_ = os.Remove(tmpPath)
			protocol.WriteError(w, http.StatusBadRequest, "missing multipart field 'file'")
			return
		}
		if filename == "" {
			filename = partFilename
		}
		if projectID == "" {
			_ = os.Remove(tmpPath)
			protocol.WriteError(w, http.StatusBadRequest, "project is required")
			return
		}
		if !a.cfg.AllowsProject(projectID) {
			_ = os.Remove(tmpPath)
			protocol.WriteError(w, http.StatusForbidden, "project not allowed on this node")
			return
		}
	} else {
		if projectID == "" {
			protocol.WriteError(w, http.StatusBadRequest, "project is required")
			return
		}
		if !a.cfg.AllowsProject(projectID) {
			protocol.WriteError(w, http.StatusForbidden, "project not allowed on this node")
			return
		}
		if _, err := transfer.SanitizeRelativePath(filename); err != nil {
			protocol.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			protocol.WriteError(w, http.StatusInternalServerError, "create temp file: "+err.Error())
			return
		}
		var copyErr error
		written, actualSHA, copyErr = transfer.CopyStream(r.Context(), f, r.Body, nil, nil)
		syncErr := f.Sync()
		closeErr := f.Close()
		if copyErr != nil || syncErr != nil || closeErr != nil {
			_ = os.Remove(tmpPath)
			errMsg := fmt.Sprintf("upload write failed: %v %v %v", copyErr, syncErr, closeErr)
			protocol.WriteError(w, http.StatusInternalServerError, errMsg)
			return
		}
	}

	cleanName, err := transfer.SanitizeRelativePath(filename)
	if err != nil {
		_ = os.Remove(tmpPath)
		protocol.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Verify checksum BEFORE exposing the file as READY.
	if expectedSHA256 != "" && !strings.EqualFold(expectedSHA256, actualSHA) {
		_ = os.Remove(tmpPath)
		protocol.WriteError(w, http.StatusBadRequest, fmt.Sprintf("sha256 mismatch: expected %s got %s", expectedSHA256, actualSHA))
		return
	}

	// Re-check disk watermark post-write (in case chunked upload had no Content-Length).
	if _, _, _, postAlarm, err := a.diskWatermarkStatus(0); err == nil && postAlarm {
		_ = os.Remove(tmpPath)
		a.triggerHeartbeat()
		protocol.WriteError(w, http.StatusInsufficientStorage, "disk watermark exceeded after upload")
		return
	}

	readyPath := a.readyFilePath(fileID)
	if err := os.Rename(tmpPath, readyPath); err != nil {
		_ = os.Remove(tmpPath)
		protocol.WriteError(w, http.StatusInternalServerError, "commit file: "+err.Error())
		return
	}

	rec := FileRecord{
		FileID:     fileID,
		ProjectID:  projectID,
		Filename:   cleanName,
		Size:       written,
		SHA256:     actualSHA,
		Status:     protocol.FileStatusReady,
		UploadedAt: time.Now().UTC(),
	}
	uplEv := &protocol.SummaryEvent{
		EventID:   "upl-" + fileID,
		ProjectID: projectID,
		ANodeID:   a.cfg.NodeID,
		EventType: protocol.EventUploaded,
		Bytes:     written,
		Timestamp: rec.UploadedAt,
	}
	if err := a.store.PutReady(rec, uplEv); err != nil {
		_ = os.Remove(readyPath)
		protocol.WriteError(w, http.StatusInternalServerError, "persist file metadata: "+err.Error())
		return
	}

	a.triggerEventFlush()
	a.triggerHeartbeat()

	a.logger.Info("local file uploaded and verified READY", "file_id", fileID, "project", projectID, "filename", cleanName, "size", written)
	protocol.WriteJSON(w, http.StatusOK, protocol.LocalUploadResp{
		FileID:    fileID,
		ProjectID: projectID,
		Filename:  cleanName,
		Size:      written,
		SHA256:    actualSHA,
		Status:    protocol.FileStatusReady,
	})
}

func (a *Agent) handleLocalRegister(w http.ResponseWriter, r *http.Request) {
	var req protocol.LocalRegisterReq
	if err := protocol.DecodeJSON(r.Body, &req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if req.ProjectID == "" || req.LocalPath == "" {
		protocol.WriteError(w, http.StatusBadRequest, "project_id and local_path are required")
		return
	}
	if !a.cfg.AllowsProject(req.ProjectID) {
		protocol.WriteError(w, http.StatusForbidden, "project not allowed on this node")
		return
	}
	if req.Filename == "" {
		req.Filename = filepath.Base(req.LocalPath)
	}
	cleanName, err := transfer.SanitizeRelativePath(req.Filename)
	if err != nil {
		protocol.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = "move"
	}
	if mode != "move" && mode != "hardlink" {
		protocol.WriteError(w, http.StatusBadRequest, "mode must be 'move' or 'hardlink'")
		return
	}

	st, err := os.Lstat(req.LocalPath)
	if err != nil || !st.Mode().IsRegular() {
		protocol.WriteError(w, http.StatusBadRequest, "local_path must exist and be a regular file (symlinks not allowed)")
		return
	}
	_, _, _, alarm, err := a.diskWatermarkStatus(0)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "disk check failed: "+err.Error())
		return
	}
	if alarm {
		a.triggerHeartbeat()
		protocol.WriteError(w, http.StatusInsufficientStorage, "disk watermark exceeded on agent-a")
		return
	}

	size, actualSHA, err := transfer.HashFile(r.Context(), req.LocalPath)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "hash local file: "+err.Error())
		return
	}
	if req.ExpectedSHA256 != "" && !strings.EqualFold(strings.TrimSpace(req.ExpectedSHA256), actualSHA) {
		protocol.WriteError(w, http.StatusBadRequest, fmt.Sprintf("sha256 mismatch: expected %s got %s", req.ExpectedSHA256, actualSHA))
		return
	}

	fileID := uuid.NewString()
	readyPath := a.readyFilePath(fileID)
	if mode == "hardlink" {
		if err := os.Link(req.LocalPath, readyPath); err != nil {
			protocol.WriteError(w, http.StatusInternalServerError, "hardlink failed: "+err.Error())
			return
		}
	} else {
		if err := os.Rename(req.LocalPath, readyPath); err != nil {
			// Cross-device fallback requires extra space on DataDir: enforce disk watermark before copying.
			if _, _, _, xAlarm, wErr := a.diskWatermarkStatus(uint64(size)); wErr == nil && xAlarm {
				a.triggerHeartbeat()
				protocol.WriteError(w, http.StatusInsufficientStorage, "disk watermark exceeded on agent-a")
				return
			}
			// Cross-device fallback: stream copy into tmp then rename and delete source.
			if err := a.crossDeviceMove(r.Context(), req.LocalPath, readyPath, actualSHA); err != nil {
				protocol.WriteError(w, http.StatusInternalServerError, "move failed: "+err.Error())
				return
			}
		}
	}

	rec := FileRecord{
		FileID:     fileID,
		ProjectID:  req.ProjectID,
		Filename:   cleanName,
		Size:       size,
		SHA256:     actualSHA,
		Status:     protocol.FileStatusReady,
		UploadedAt: time.Now().UTC(),
	}
	uplEv := &protocol.SummaryEvent{
		EventID:   "upl-" + fileID,
		ProjectID: req.ProjectID,
		ANodeID:   a.cfg.NodeID,
		EventType: protocol.EventUploaded,
		Bytes:     size,
		Timestamp: rec.UploadedAt,
	}
	if err := a.store.PutReady(rec, uplEv); err != nil {
		_ = os.Remove(readyPath)
		protocol.WriteError(w, http.StatusInternalServerError, "persist file metadata: "+err.Error())
		return
	}

	a.triggerEventFlush()
	a.triggerHeartbeat()

	a.logger.Info("local file registered and verified READY", "file_id", fileID, "project", req.ProjectID, "filename", cleanName, "size", size, "mode", mode)
	protocol.WriteJSON(w, http.StatusOK, protocol.LocalUploadResp{
		FileID:    fileID,
		ProjectID: req.ProjectID,
		Filename:  cleanName,
		Size:      size,
		SHA256:    actualSHA,
		Status:    protocol.FileStatusReady,
	})
}

func (a *Agent) crossDeviceMove(ctx context.Context, srcPath, dstPath, expectedSHA string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()
	tmpPath := dstPath + ".copy"
	dst, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, sha, copyErr := transfer.CopyStream(ctx, dst, src, nil, nil)
	syncErr := dst.Sync()
	closeErr := dst.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("cross-device copy failed: %v %v %v", copyErr, syncErr, closeErr)
	}
	if !strings.EqualFold(sha, expectedSHA) {
		_ = os.Remove(tmpPath)
		return ErrChecksumFailed
	}
	if err := os.Rename(tmpPath, dstPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	_ = os.Remove(srcPath)
	return nil
}

func (a *Agent) handleLocalStatus(w http.ResponseWriter, r *http.Request) {
	total, free, pct, alarm, _ := a.diskWatermarkStatus(0)
	files, err := a.store.ListLive(r.URL.Query().Get("project"))
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	protocol.WriteJSON(w, http.StatusOK, protocol.LiveFilesResp{
		ANodeID:     a.cfg.NodeID,
		AName:       a.cfg.NodeName,
		PublicAddr:  a.cfg.PublicAddr,
		Files:       files,
		DiskTotal:   total,
		DiskFree:    free,
		DiskUsedPct: pct,
		DiskAlarm:   alarm,
	})
}

func (a *Agent) validateLeaseTTL(requestedSec int) (time.Duration, error) {
	if requestedSec == 0 {
		return a.cfg.DefaultLeaseTTL(), nil
	}
	maxSec := 3600
	if a.cfg.LeaseTTLSec > maxSec {
		maxSec = a.cfg.LeaseTTLSec
	}
	if requestedSec < 1 || requestedSec > maxSec {
		return 0, fmt.Errorf("lease_ttl_sec must be between 1 and %d", maxSec)
	}
	return time.Duration(requestedSec) * time.Second, nil
}

func (a *Agent) handleClaim(w http.ResponseWriter, r *http.Request) {
	tok := auth.ExtractBearer(r.Header.Get("Authorization"))
	claims, err := auth.VerifyAccessJWT(a.cfg.JWTSecret, tok)
	if err != nil {
		protocol.WriteError(w, http.StatusUnauthorized, err.Error())
		return
	}
	var req protocol.ClaimReq
	if err := protocol.DecodeJSON(r.Body, &req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "invalid claim request")
		return
	}
	if claims.ANodeID != a.cfg.NodeID || claims.ProjectID != req.ProjectID || claims.BNodeID != req.BNodeID {
		protocol.WriteError(w, http.StatusForbidden, "token claims mismatch")
		return
	}

	leaseTTL, err := a.validateLeaseTTL(req.LeaseTTLSec)
	if err != nil {
		protocol.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	rec, err := a.store.ClaimNext(req.ProjectID, req.BNodeID, req.AvailableDiskBytes, leaseTTL)
	if errors.Is(err, ErrNoReadyFile) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	a.triggerHeartbeat()
	a.logger.Info("file claimed", "file_id", rec.FileID, "project", rec.ProjectID, "b_node", req.BNodeID, "lease_id", rec.LeaseID)
	protocol.WriteJSON(w, http.StatusOK, protocol.ClaimResp{
		FileID:         rec.FileID,
		ProjectID:      rec.ProjectID,
		Filename:       rec.Filename,
		Size:           rec.Size,
		SHA256:         rec.SHA256,
		LeaseID:        rec.LeaseID,
		LeaseToken:     rec.LeaseToken,
		LeaseExpiresAt: *rec.LeaseExpiresAt,
		UploadedAt:     rec.UploadedAt,
	})
}

func (a *Agent) handleStream(w http.ResponseWriter, r *http.Request) {
	fileID := r.PathValue("id")
	leaseToken := r.Header.Get(protocol.HeaderLeaseToken)
	if leaseToken == "" {
		protocol.WriteError(w, http.StatusUnauthorized, "missing lease token")
		return
	}
	rec, err := a.store.VerifyActiveLease(fileID, leaseToken)
	if err != nil {
		if errors.Is(err, ErrFileNotFound) {
			protocol.WriteError(w, http.StatusNotFound, "file not found")
			return
		}
		protocol.WriteError(w, http.StatusConflict, "lease expired or invalid")
		return
	}

	select {
	case a.streamSem <- struct{}{}:
		a.activeStreams.Add(1)
		defer func() {
			<-a.streamSem
			a.activeStreams.Add(-1)
		}()
	default:
		w.Header().Set("Retry-After", "2")
		protocol.WriteError(w, http.StatusServiceUnavailable, "max concurrent streams reached")
		return
	}

	f, err := os.Open(a.readyFilePath(fileID))
	if err != nil {
		protocol.WriteError(w, http.StatusNotFound, "backing file missing")
		return
	}
	defer f.Close()

	start, end, isRange, err := parseRangeHeader(r.Header.Get("Range"), rec.Size)
	if err != nil {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", rec.Size))
		protocol.WriteError(w, http.StatusRequestedRangeNotSatisfiable, err.Error())
		return
	}

	var length int64
	if rec.Size == 0 {
		length = 0
		isRange = false
	} else {
		length = end - start + 1
		if start > 0 {
			if _, err := f.Seek(start, io.SeekStart); err != nil {
				protocol.WriteError(w, http.StatusInternalServerError, "seek failed")
				return
			}
		}
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Length", strconv.FormatInt(length, 10))
	if isRange {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, rec.Size))
		w.WriteHeader(http.StatusPartialContent)
	} else {
		w.WriteHeader(http.StatusOK)
	}

	if length == 0 {
		return
	}

	bufPtr := transfer.GetBuf()
	defer transfer.PutBuf(bufPtr)
	buf := *bufPtr

	flusher, _ := w.(http.Flusher)
	remaining := length
	sentSinceStart := int64(0)
	lastRenew := time.Now()
	leaseTTL := a.cfg.DefaultLeaseTTL()
	if rec.LeaseTTLSec > 0 {
		leaseTTL = time.Duration(rec.LeaseTTLSec) * time.Second
	}
	renewEvery := leaseTTL / 3
	if renewEvery < time.Second {
		renewEvery = time.Second
	}
	if renewEvery > 15*time.Second {
		renewEvery = 15 * time.Second
	}

	for remaining > 0 {
		if r.Context().Err() != nil {
			return
		}
		toRead := len(buf)
		if int64(toRead) > remaining {
			toRead = int(remaining)
		}
		nr, rErr := f.Read(buf[:toRead])
		if nr > 0 {
			if a.limiter != nil {
				if err := a.limiter.Wait(r.Context(), nr); err != nil {
					return
				}
			}
			nw, wErr := w.Write(buf[:nr])
			if nw > 0 {
				remaining -= int64(nw)
				sentSinceStart += int64(nw)
				a.outBytes.Add(int64(nw))
				if flusher != nil {
					flusher.Flush()
				}
			}
			if wErr != nil {
				return
			}
			if a.StreamChunkHook != nil {
				if err := a.StreamChunkHook(fileID, start+sentSinceStart); err != nil {
					// Force-abort stream to simulate mid-stream network drop in tests.
					if hj, ok := w.(http.Hijacker); ok {
						if conn, _, hErr := hj.Hijack(); hErr == nil {
							_ = conn.Close()
						}
					}
					return
				}
			}
			// Auto-renew lease periodically while streaming so large files never expire mid-transfer.
			if time.Since(lastRenew) >= renewEvery {
				if _, err := a.store.RenewLease(fileID, rec.LeaseID, leaseToken, rec.ClaimedBy, leaseTTL); err != nil {
					return
				}
				lastRenew = time.Now()
			}
		}
		if rErr == io.EOF {
			return
		}
		if rErr != nil {
			return
		}
	}
}

func (a *Agent) handleRenew(w http.ResponseWriter, r *http.Request) {
	fileID := r.PathValue("id")
	leaseToken := r.Header.Get(protocol.HeaderLeaseToken)
	if leaseToken == "" {
		protocol.WriteError(w, http.StatusUnauthorized, "missing lease token")
		return
	}
	var req protocol.RenewReq
	if err := protocol.DecodeJSON(r.Body, &req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "invalid renew request")
		return
	}
	ttl, err := a.validateLeaseTTL(req.LeaseTTLSec)
	if err != nil {
		protocol.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	exp, err := a.store.RenewLease(fileID, req.LeaseID, leaseToken, req.BNodeID, ttl)
	if err != nil {
		if errors.Is(err, ErrFileNotFound) {
			protocol.WriteError(w, http.StatusNotFound, "file not found")
			return
		}
		protocol.WriteError(w, http.StatusConflict, err.Error())
		return
	}
	protocol.WriteJSON(w, http.StatusOK, protocol.RenewResp{LeaseExpiresAt: exp})
}

func (a *Agent) handleAck(w http.ResponseWriter, r *http.Request) {
	fileID := r.PathValue("id")
	leaseToken := r.Header.Get(protocol.HeaderLeaseToken)
	if leaseToken == "" {
		protocol.WriteError(w, http.StatusUnauthorized, "missing lease token")
		return
	}
	var req protocol.AckReq
	if err := protocol.DecodeJSON(r.Body, &req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "invalid ack request")
		return
	}
	if req.LeaseID == "" || req.BNodeID == "" {
		protocol.WriteError(w, http.StatusBadRequest, "lease_id and b_node_id are required")
		return
	}

	rec, alreadyDeleted, err := a.store.AckAndRemove(fileID, req.LeaseID, leaseToken, req.BNodeID, req.SHA256, func(id string) error {
		if rmErr := os.Remove(a.readyFilePath(id)); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			return rmErr
		}
		return nil
	}, func(r FileRecord) *protocol.SummaryEvent {
		return &protocol.SummaryEvent{
			EventID:    "cmp-" + fileID,
			ProjectID:  r.ProjectID,
			ANodeID:    a.cfg.NodeID,
			BNodeID:    req.BNodeID,
			EventType:  protocol.EventCompleted,
			Bytes:      r.Size,
			DurationMs: req.DurationMs,
			Timestamp:  time.Now().UTC(),
		}
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrFileNotFound):
			protocol.WriteError(w, http.StatusNotFound, "file not found")
		case errors.Is(err, ErrChecksumFailed):
			protocol.WriteError(w, http.StatusBadRequest, "sha256 mismatch on ack")
		case errors.Is(err, ErrLeaseInvalid):
			protocol.WriteError(w, http.StatusConflict, err.Error())
		default:
			protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	if alreadyDeleted {
		protocol.WriteJSON(w, http.StatusOK, protocol.AckResp{Status: "already_deleted"})
		return
	}

	a.triggerEventFlush()
	a.triggerHeartbeat()

	a.logger.Info("file ACK verified and deleted", "file_id", fileID, "project", rec.ProjectID, "b_node", req.BNodeID, "size", rec.Size)
	protocol.WriteJSON(w, http.StatusOK, protocol.AckResp{Status: "deleted"})
}

func (a *Agent) handleNack(w http.ResponseWriter, r *http.Request) {
	fileID := r.PathValue("id")
	leaseToken := r.Header.Get(protocol.HeaderLeaseToken)
	if leaseToken == "" {
		protocol.WriteError(w, http.StatusUnauthorized, "missing lease token")
		return
	}
	var req protocol.NackReq
	if err := protocol.DecodeJSON(r.Body, &req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "invalid nack request")
		return
	}
	_, err := a.store.Nack(fileID, req.LeaseID, leaseToken, req.BNodeID, func(r FileRecord) *protocol.SummaryEvent {
		return &protocol.SummaryEvent{
			EventID:   fmt.Sprintf("fail-%s-%d", fileID, r.RetryCount),
			ProjectID: r.ProjectID,
			ANodeID:   a.cfg.NodeID,
			BNodeID:   req.BNodeID,
			EventType: protocol.EventFailed,
			Bytes:     r.Size,
			Timestamp: time.Now().UTC(),
		}
	})
	if err != nil {
		if errors.Is(err, ErrFileNotFound) {
			protocol.WriteError(w, http.StatusNotFound, "file not found")
			return
		}
		protocol.WriteError(w, http.StatusConflict, err.Error())
		return
	}
	a.triggerEventFlush()
	a.triggerHeartbeat()
	a.logger.Warn("file NACKed and returned to READY", "file_id", fileID, "b_node", req.BNodeID, "reason", req.Reason)
	w.WriteHeader(http.StatusOK)
}

func (a *Agent) handleInternalLiveFiles(w http.ResponseWriter, r *http.Request) {
	sec := r.Header.Get(protocol.HeaderCenterSecret)
	if a.cfg.CenterSecret == "" || !auth.EqualConstantTime(sec, a.cfg.CenterSecret) {
		protocol.WriteError(w, http.StatusUnauthorized, "invalid center secret")
		return
	}
	total, free, pct, alarm, _ := a.diskWatermarkStatus(0)
	files, err := a.store.ListLive(r.URL.Query().Get("project"))
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	protocol.WriteJSON(w, http.StatusOK, protocol.LiveFilesResp{
		ANodeID:     a.cfg.NodeID,
		AName:       a.cfg.NodeName,
		PublicAddr:  a.cfg.PublicAddr,
		Files:       files,
		DiskTotal:   total,
		DiskFree:    free,
		DiskUsedPct: pct,
		DiskAlarm:   alarm,
	})
}

func (a *Agent) speedMeterLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			delta := a.outBytes.Swap(0)
			a.lastSpeedBps.Store(delta)
		}
	}
}

func (a *Agent) reapLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reaped, err := a.store.ReapExpiredLeases(time.Now().UTC())
			if err != nil {
				a.logger.Warn("reap expired leases failed", "err", err)
				continue
			}
			if reaped > 0 {
				a.logger.Info("reaped expired leases back to READY", "count", reaped)
				a.triggerHeartbeat()
			}
		}
	}
}

func (a *Agent) heartbeatLoop(ctx context.Context) {
	a.sendHeartbeat(ctx)
	ticker := time.NewTicker(a.cfg.HeartbeatInterval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.sendHeartbeat(ctx)
		case <-a.hbWakeCh:
			a.sendHeartbeat(ctx)
		}
	}
}

func (a *Agent) sendHeartbeat(ctx context.Context) {
	total, free, pct, alarm, _ := a.diskWatermarkStatus(0)
	avail, err := a.store.ComputeAvailability()
	if err != nil {
		a.logger.Warn("compute availability failed", "err", err)
		return
	}
	payload := protocol.AgentAHeartbeatReq{
		NodeID:         a.cfg.NodeID,
		Name:           a.cfg.NodeName,
		PublicAddr:     a.cfg.PublicAddr,
		Projects:       a.cfg.Projects,
		DiskTotalBytes: total,
		DiskFreeBytes:  free,
		DiskUsedPct:    pct,
		DiskAlarm:      alarm,
		ActiveStreams:  int(a.activeStreams.Load()),
		OutSpeedBps:    a.lastSpeedBps.Load(),
		Availability:   avail,
	}
	body, _ := json.Marshal(payload)
	url := strings.TrimRight(a.cfg.CenterURL, "/") + "/api/v1/a/heartbeat"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(protocol.HeaderNodeID, a.cfg.NodeID)
	req.Header.Set(protocol.HeaderNodeToken, a.cfg.CenterToken)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		a.logger.Warn("center heartbeat failed", "err", err)
		return
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 300 {
		a.logger.Warn("center heartbeat non-2xx", "status", resp.StatusCode)
	}
}

func (a *Agent) eventFlushLoop(ctx context.Context) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.flushPendingEvents(ctx)
		case <-a.eventWakeCh:
			a.flushPendingEvents(ctx)
		}
	}
}

func (a *Agent) flushPendingEvents(ctx context.Context) {
	events, err := a.store.ListPendingEvents(100)
	if err != nil || len(events) == 0 {
		return
	}
	body, _ := json.Marshal(protocol.SummaryEventsReq{Events: events})
	url := strings.TrimRight(a.cfg.CenterURL, "/") + "/api/v1/a/events"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(protocol.HeaderNodeID, a.cfg.NodeID)
	req.Header.Set(protocol.HeaderNodeToken, a.cfg.CenterToken)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		a.logger.Warn("flush summary events failed", "err", err)
		return
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		ids := make([]string, len(events))
		for i, ev := range events {
			ids[i] = ev.EventID
		}
		_ = a.store.DeletePendingEvents(ids)
	}
}

func parseRangeHeader(hdr string, totalSize int64) (start, end int64, isRange bool, err error) {
	if hdr == "" {
		if totalSize == 0 {
			return 0, 0, false, nil
		}
		return 0, totalSize - 1, false, nil
	}
	if !strings.HasPrefix(hdr, "bytes=") {
		return 0, 0, false, errors.New("unsupported range unit")
	}
	spec := strings.TrimPrefix(hdr, "bytes=")
	if strings.Contains(spec, ",") {
		return 0, 0, false, errors.New("multi-range not supported")
	}
	parts := strings.SplitN(spec, "-", 2)
	if len(parts) != 2 {
		return 0, 0, false, errors.New("invalid range syntax")
	}
	if totalSize == 0 {
		if parts[0] == "0" && (parts[1] == "" || parts[1] == "0") {
			return 0, 0, false, nil
		}
		return 0, 0, false, errors.New("range out of bounds for empty file")
	}
	s, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || s < 0 || s >= totalSize {
		return 0, 0, false, errors.New("invalid range start")
	}
	e := totalSize - 1
	if parts[1] != "" {
		parsedEnd, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil || parsedEnd < s {
			return 0, 0, false, errors.New("invalid range end")
		}
		if parsedEnd < e {
			e = parsedEnd
		}
	}
	return s, e, true, nil
}
