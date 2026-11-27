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
	"net/url"
	"os"
	"path/filepath"
	"runtime"
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
	"relay-download/internal/updater"
	"relay-download/internal/version"
)

type Agent struct {
	cfg        *Config
	store      *Store
	logger     *slog.Logger
	httpClient *http.Client
	limiter    *transfer.RateLimiter

	uploadDir string
	readyDir  string

	storageMu       sync.RWMutex
	storageDirs     []string
	disabledDisks   map[string]struct{}
	diskGen         int64
	maxDiskUsagePct float64
	diskHealth      *transfer.DiskHealthTracker
	diskRRIdx       atomic.Uint64

	hintMu       sync.RWMutex
	projectHints map[string]protocol.ProjectAutoHint

	localSrv  *http.Server
	publicSrv *http.Server

	localLn  net.Listener
	publicLn net.Listener

	streamSem     chan struct{}
	activeStreams atomic.Int32
	paused        atomic.Bool
	draining      atomic.Bool

	hbWakeCh     chan struct{}
	eventWakeCh  chan struct{}
	deleteWakeCh chan struct{}
	deleteMu     sync.Mutex
	deleteQueue  []string
	updater      *updater.Updater

	// Optional test hooks (unused in production).
	StreamChunkHook    func(fileID string, sentTotal int64) error
	UpgradeExePath     string
	UpgradeRestartHook func(targetVersion string)

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

	diskHealth := transfer.NewDiskHealthTracker()
	initStorage := make([]string, 0, len(cfg.StorageDirs))
	for _, sd := range cfg.StorageDirs {
		sd = strings.TrimSpace(sd)
		if sd == "" {
			continue
		}
		clean := filepath.Clean(sd)
		_ = diskHealth.SafeMkdirAll(clean, filepath.Join(clean, "uploading"), true)
		_ = diskHealth.SafeMkdirAll(clean, filepath.Join(clean, "ready"), true)
		initStorage = append(initStorage, clean)
	}

	a := &Agent{
		cfg:           cfg,
		store:         store,
		logger:        logger.With("component", "agent-a", "node_id", cfg.NodeID),
		uploadDir:     uploadDir,
		readyDir:      readyDir,
		storageDirs:     initStorage,
		disabledDisks:   make(map[string]struct{}),
		maxDiskUsagePct: transfer.NormalizeMaxDiskUsagePct(cfg.MaxDiskUsagePct),
		diskHealth:      diskHealth,
		projectHints:    make(map[string]protocol.ProjectAutoHint),
		limiter:       limiter,
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
		streamSem:    make(chan struct{}, cfg.MaxConcurrentStreams),
		hbWakeCh:     make(chan struct{}, 1),
		eventWakeCh:  make(chan struct{}, 1),
		deleteWakeCh: make(chan struct{}, 1),
	}

	if err := a.reconcileOnStartup(); err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("startup reconcile: %w", err)
	}

	dlClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:     clientTLS.Clone(),
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}
	a.updater = updater.New(updater.Options{
		Component:    "relay-agent-a",
		NodeID:       cfg.NodeID,
		CenterURL:    cfg.CenterURL,
		CenterToken:  cfg.CenterToken,
		HTTPClient:   dlClient,
		Logger:       a.logger,
		OnStatusSync: a.triggerHeartbeat,
		OnRestart: func(targetVer string) {
			if a.UpgradeRestartHook != nil {
				a.UpgradeRestartHook(targetVer)
				return
			}
			a.runMu.Lock()
			cancel := a.runCancel
			a.runMu.Unlock()
			if cancel != nil {
				cancel()
			}
		},
	})
	return a, nil
}

func (a *Agent) Start(ctx context.Context) error {
	serverTLS, err := pki.ServerTLSConfig(a.cfg.TLSCert, a.cfg.TLSKey)
	if err != nil {
		return err
	}

	if !isLoopbackHost(a.cfg.LocalListen) {
		return fmt.Errorf("local_listen must bind strictly to localhost/loopback (got %q)", a.cfg.LocalListen)
	}
	localLn, err := net.Listen("tcp", a.cfg.LocalListen)
	if err != nil {
		return fmt.Errorf("listen local %s: %w", a.cfg.LocalListen, err)
	}
	if tcpAddr, ok := localLn.Addr().(*net.TCPAddr); !ok || tcpAddr.IP == nil || !tcpAddr.IP.IsLoopback() {
		_ = localLn.Close()
		return fmt.Errorf("local_listen resolved to non-loopback address %q", localLn.Addr().String())
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
		HTTP2: &http.HTTP2Config{
			MaxConcurrentStreams:          1024,
			MaxReadFrameSize:              1 << 20,
			MaxReceiveBufferPerConnection: 3 << 20,
			MaxReceiveBufferPerStream:     3 << 20,
		},
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

	if a.UpgradeExePath != "" {
		a.updater = updater.New(updater.Options{
			Component:    "relay-agent-a",
			NodeID:       a.cfg.NodeID,
			CenterURL:    a.cfg.CenterURL,
			CenterToken:  a.cfg.CenterToken,
			HTTPClient:   a.httpClient,
			Logger:       a.logger,
			ExePath:      a.UpgradeExePath,
			OnStatusSync: a.triggerHeartbeat,
			OnRestart: func(targetVer string) {
				if a.UpgradeRestartHook != nil {
					a.UpgradeRestartHook(targetVer)
					return
				}
				a.runMu.Lock()
				cancel := a.runCancel
				a.runMu.Unlock()
				if cancel != nil {
					cancel()
				}
			},
		})
	}

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
	launchBG(a.reapLoop)
	launchBG(a.heartbeatLoop)
	launchBG(a.eventFlushLoop)
	if a.cfg.DeleteBatchIntervalSec > 0 {
		launchBG(a.deleteFlushLoop)
	}

	select {
	case <-runCtx.Done():
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

func (a *Agent) notifyCenterOffline(ctx context.Context) {
	u := strings.TrimRight(a.cfg.CenterURL, "/") + "/api/v1/a/offline"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		return
	}
	req.Header.Set(protocol.HeaderNodeID, a.cfg.NodeID)
	req.Header.Set(protocol.HeaderNodeToken, a.cfg.CenterToken)
	resp, err := a.httpClient.Do(req)
	if err != nil {
		a.logger.Warn("graceful offline notify to center failed", "err", err)
		return
	}
	_ = resp.Body.Close()
}

func (a *Agent) Shutdown(ctx context.Context) error {
	var shutdownErr error
	a.closeOnce.Do(func() {
		// 1. Immediately stop accepting new claims, streams, and local uploads.
		a.draining.Store(true)
		a.logger.Info("dispatch node shutting down cleanly")

		// 2. Immediately notify Center so receivers stop discovering this node in <100ms
		//    instead of waiting for node_offline_sec.
		offCtx, cancelOff := context.WithTimeout(ctx, 1500*time.Millisecond)
		a.notifyCenterOffline(offCtx)
		cancelOff()

		// 3. Gracefully drain HTTP servers in parallel with a tight 5s cap so host poweroff
		//    or systemctl stop never hangs; any huge in-flight stream is safely interrupted
		//    and preserved on disk for future re-delivery ("没落盘的不准删").
		shCtx, cancelSh := context.WithTimeout(ctx, 5*time.Second)
		var srvWG sync.WaitGroup
		shutdownSrv := func(srv *http.Server) {
			if srv == nil {
				return
			}
			srvWG.Add(1)
			go func() {
				defer srvWG.Done()
				if err := srv.Shutdown(shCtx); err != nil {
					_ = srv.Close()
				}
			}()
		}
		shutdownSrv(a.localSrv)
		shutdownSrv(a.publicSrv)
		srvWG.Wait()
		cancelSh()

		// 4. Stop background loops cleanly.
		a.runMu.Lock()
		cancel := a.runCancel
		a.runMu.Unlock()
		if cancel != nil {
			cancel()
		}
		a.bgWG.Wait()

		// 5. Final best-effort flush of pending summary events & ACK-verified spool deletions
		//    before closing SQLite cleanly.
		if a.store != nil {
			evCtx, cancelEv := context.WithTimeout(ctx, 2*time.Second)
			a.flushPendingEvents(evCtx)
			cancelEv()
			a.flushDeleteQueue()
			shutdownErr = a.store.Close()
		}
	})
	return shutdownErr
}

func (a *Agent) activeCacheDirs() []string {
	a.storageMu.RLock()
	dyn := append([]string(nil), a.storageDirs...)
	a.storageMu.RUnlock()
	if len(dyn) > 0 {
		return dyn
	}
	if a.cfg.AwaitDiskSelection {
		return nil
	}
	if a.cfg.DataDir != "" {
		return []string{a.cfg.DataDir}
	}
	return nil
}

func (a *Agent) awaitingDisk() bool {
	return len(a.activeCacheDirs()) == 0
}

func (a *Agent) isDiskDisabledLocked(root string) bool {
	if len(a.disabledDisks) == 0 {
		return false
	}
	_, ok := a.disabledDisks[filepath.Clean(strings.TrimSpace(root))]
	return ok
}

func (a *Agent) isDiskDisabled(root string) bool {
	a.storageMu.RLock()
	dis := a.isDiskDisabledLocked(root)
	a.storageMu.RUnlock()
	return dis
}

func (a *Agent) effectiveMaxDiskUsagePct() float64 {
	a.storageMu.RLock()
	pct := a.maxDiskUsagePct
	a.storageMu.RUnlock()
	if pct <= 0 {
		pct = a.cfg.MaxDiskUsagePct
	}
	return transfer.NormalizeMaxDiskUsagePct(pct)
}

func (a *Agent) applyDiskConfig(dirs, disabled []string, diskGen int64, maxDiskUsagePct float64) {
	disSet := make(map[string]struct{}, len(disabled))
	for _, d := range disabled {
		d = strings.TrimSpace(d)
		if d != "" {
			disSet[filepath.Clean(d)] = struct{}{}
		}
	}
	a.diskHealth.ApplyConfig(disabled, diskGen)

	clean := make([]string, 0, len(dirs))
	if len(dirs) > 0 {
		seen := make(map[string]struct{}, len(dirs))
		for _, raw := range dirs {
			raw = strings.TrimSpace(raw)
			if !transfer.IsSafeStorageDir(raw) {
				continue
			}
			p := filepath.Clean(raw)
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}
			if _, isDis := disSet[p]; !isDis {
				_ = a.diskHealth.SafeMkdirAll(p, filepath.Join(p, "uploading"), true)
				_ = a.diskHealth.SafeMkdirAll(p, filepath.Join(p, "ready"), true)
			}
			clean = append(clean, p)
		}
	}

	a.storageMu.Lock()
	changed := a.diskGen != diskGen || len(a.disabledDisks) != len(disSet)
	if maxDiskUsagePct > 0 {
		normPct := transfer.NormalizeMaxDiskUsagePct(maxDiskUsagePct)
		if a.maxDiskUsagePct != normPct {
			a.maxDiskUsagePct = normPct
			changed = true
		}
	}
	if !changed {
		for k := range disSet {
			if _, ok := a.disabledDisks[k]; !ok {
				changed = true
				break
			}
		}
	}
	if len(clean) > 0 {
		if len(a.storageDirs) != len(clean) {
			changed = true
		} else {
			for i := range clean {
				if a.storageDirs[i] != clean[i] {
					changed = true
					break
				}
			}
		}
		a.storageDirs = clean
	}
	a.disabledDisks = disSet
	if diskGen > a.diskGen {
		a.diskGen = diskGen
	}
	effWM := a.maxDiskUsagePct
	a.storageMu.Unlock()
	if changed {
		a.logger.Info("updated dispatch cache disk config from center", "storage_dirs", a.activeCacheDirs(), "disabled_disks", len(disSet), "disk_gen", diskGen, "max_disk_usage_pct", effWM)
	}
}

func (a *Agent) reconcileOnStartup() error {
	// Clean any incomplete uploads left from a prior crash across all mounted cache dirs.
	roots := a.activeCacheDirs()
	if len(roots) == 0 && a.cfg.DataDir != "" {
		roots = []string{a.cfg.DataDir}
	}
	detachedRoots := make(map[string]bool, len(roots))
	maxPct := a.effectiveMaxDiskUsagePct()
	for _, root := range roots {
		probe := a.diskHealth.ProbeRoot(root, !a.isDiskDisabled(root), maxPct, a.cfg.MinFreeDiskBytes, 0)
		if probe.Detached || !probe.Mounted {
			detachedRoots[filepath.Clean(root)] = true
			a.logger.Warn("skipping startup reconcile for detached cache disk", "root", root, "reason", probe.StatusReason)
			continue
		}
		uDir := filepath.Join(root, "uploading")
		if entries, err := os.ReadDir(uDir); err == nil {
			for _, e := range entries {
				if !e.IsDir() {
					_ = os.Remove(filepath.Join(uDir, e.Name()))
				}
			}
		}
	}

	knownPaths := a.store.AllFilePaths()
	// Remove DB records whose backing file is missing (ONLY when its backing disk is mounted!).
	for id, dp := range knownPaths {
		p := dp
		if p == "" {
			p = a.readyFilePath(id)
		}
		root := transfer.MatchRootForPath(p, roots)
		if detachedRoots[filepath.Clean(root)] {
			continue
		}
		if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
			_ = a.store.DeleteRecord(id)
			delete(knownPaths, id)
		}
	}
	// Remove orphaned files in mounted readyDir(s) not present in DB.
	for _, root := range roots {
		if detachedRoots[filepath.Clean(root)] {
			continue
		}
		rDir := filepath.Join(root, "ready")
		if entries, err := os.ReadDir(rDir); err == nil {
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				id := strings.TrimSuffix(e.Name(), ".dat")
				if _, ok := knownPaths[id]; !ok {
					_ = os.Remove(filepath.Join(rDir, e.Name()))
				}
			}
		}
	}
	return nil
}

func (a *Agent) readyFilePath(fileID string) string {
	return filepath.Join(a.readyDir, fileID+".dat")
}

func (a *Agent) filePathForID(fileID string) string {
	if p := a.store.DataPathFor(fileID); p != "" {
		return p
	}
	return a.readyFilePath(fileID)
}

func (a *Agent) readyPathForRecord(rec FileRecord) string {
	if rec.DataPath != "" {
		return rec.DataPath
	}
	return a.readyFilePath(rec.FileID)
}

func (a *Agent) checkSingleDiskWatermark(dir string, extraBytes uint64) (total, free, usable uint64, usedPct float64, alarm bool, err error) {
	enabled := !a.isDiskDisabled(dir)
	maxPct := a.effectiveMaxDiskUsagePct()
	probe := a.diskHealth.ProbeRoot(dir, enabled, maxPct, a.cfg.MinFreeDiskBytes, 0)
	if probe.Detached || probe.UnplugLatched || !probe.Mounted || !probe.Writable {
		return 0, 0, 0, 0, true, fmt.Errorf("cache disk %s unavailable: %s", dir, probe.StatusReason)
	}
	usable, overWM := transfer.MandatoryWatermarkFree(probe.TotalBytes, probe.FreeBytes, maxPct, a.cfg.MinFreeDiskBytes)
	if overWM || (extraBytes > 0 && usable < extraBytes) {
		alarm = true
	}
	return probe.TotalBytes, probe.FreeBytes, usable, probe.UsedPct, alarm, nil
}

// pickCacheDir selects a healthy, mounted, enabled cache disk below the mandatory disk watermark,
// spreading concurrent writes across multiple selected disks and sending large files to the freest disk.
func (a *Agent) pickCacheDir(extraBytes uint64) (root string, awaiting bool, alarm bool, err error) {
	roots := a.activeCacheDirs()
	if len(roots) == 0 {
		return "", true, false, nil
	}
	type cand struct {
		root   string
		usable uint64
	}
	healthy := make([]cand, 0, len(roots))
	var lastErr error
	for _, r := range roots {
		if a.isDiskDisabled(r) || a.diskHealth.IsBlocked(r) {
			continue
		}
		_, _, usable, _, over, dErr := a.checkSingleDiskWatermark(r, extraBytes)
		if dErr != nil {
			lastErr = dErr
			continue
		}
		if !over {
			healthy = append(healthy, cand{root: r, usable: usable})
		}
	}
	if len(healthy) == 0 {
		if lastErr != nil {
			a.triggerHeartbeat()
			return "", false, true, lastErr
		}
		return "", false, true, nil
	}
	chosen := healthy[0].root
	if len(healthy) > 1 {
		if extraBytes >= 64<<20 {
			// Large files go to the disk with the most usable headroom above watermark.
			best := healthy[0]
			for _, c := range healthy[1:] {
				if c.usable > best.usable {
					best = c
				}
			}
			chosen = best.root
		} else {
			idx := (a.diskRRIdx.Add(1) - 1) % uint64(len(healthy))
			chosen = healthy[idx].root
		}
	}
	if err := a.diskHealth.SafeMkdirAll(chosen, filepath.Join(chosen, "uploading"), true); err != nil {
		a.triggerHeartbeat()
		return "", false, true, err
	}
	if err := a.diskHealth.SafeMkdirAll(chosen, filepath.Join(chosen, "ready"), true); err != nil {
		a.triggerHeartbeat()
		return "", false, true, err
	}
	return chosen, false, false, nil
}

func (a *Agent) diskWatermarkStatus(extraBytes uint64) (total, free uint64, usedPct float64, alarm bool, err error) {
	roots := a.activeCacheDirs()
	if len(roots) == 0 {
		return 0, 0, 0, false, nil
	}
	seenDev := make(map[uint64]struct{}, len(roots))
	healthyCount := 0
	var lastErr error
	maxPct := a.effectiveMaxDiskUsagePct()
	for _, r := range roots {
		enabled := !a.isDiskDisabled(r)
		probe := a.diskHealth.ProbeRoot(r, enabled, maxPct, a.cfg.MinFreeDiskBytes, 0)
		if probe.Detached || !probe.Mounted {
			lastErr = fmt.Errorf("cache disk %s: %s", r, probe.StatusReason)
			continue
		}
		if enabled && !probe.UnplugLatched && probe.Writable {
			usable, overWM := transfer.MandatoryWatermarkFree(probe.TotalBytes, probe.FreeBytes, maxPct, a.cfg.MinFreeDiskBytes)
			if !overWM && (extraBytes == 0 || usable >= extraBytes) {
				healthyCount++
			}
		}
		if probe.HasDev {
			if _, dup := seenDev[probe.DevID]; dup {
				continue
			}
			seenDev[probe.DevID] = struct{}{}
		}
		total += probe.TotalBytes
		free += probe.FreeBytes
	}
	if total == 0 && lastErr != nil {
		return 0, 0, 0, true, lastErr
	}
	if total > 0 {
		usedPct = (float64(total-free) / float64(total)) * 100.0
	}
	alarm = healthyCount == 0
	return total, free, usedPct, alarm, nil
}

func (a *Agent) collectActiveDiskStatuses() []protocol.DiskStatus {
	roots := a.activeCacheDirs()
	out := make([]protocol.DiskStatus, 0, len(roots))
	maxPct := a.effectiveMaxDiskUsagePct()
	for _, r := range roots {
		enabled := !a.isDiskDisabled(r)
		queued := 0
		if !enabled {
			queued = a.store.CountFilesInRoot(r, a.readyDir)
		}
		probe := a.diskHealth.ProbeRoot(r, enabled, maxPct, a.cfg.MinFreeDiskBytes, queued)
		out = append(out, protocol.DiskStatus{
			Path:          r,
			TotalBytes:    probe.TotalBytes,
			FreeBytes:     probe.FreeBytes,
			UsedPct:       probe.UsedPct,
			Enabled:       enabled && !probe.UnplugLatched,
			LowSpace:      probe.LowSpace,
			Writable:      probe.Writable,
			Detached:      probe.Detached,
			UnplugLatched: probe.UnplugLatched,
			LatchedGen:    probe.LatchedGen,
			InFlight:      probe.InFlight,
			SafeToEject:   probe.SafeToEject,
			StatusReason:  probe.StatusReason,
		})
	}
	return out
}

func (a *Agent) reportDiskWriteErr(root string, err error) {
	if a.diskHealth.ReportIOError(root, err) {
		a.logger.Error("dispatch cache disk I/O fault detected, auto-locking disk", "root", root, "err", err)
		a.triggerHeartbeat()
	}
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
	mux.HandleFunc("PUT /local/v1/upload", a.requireLocalAuth(a.handleLocalUpload))
	mux.HandleFunc("PUT /local/v1/files/{project}/{filename...}", a.requireLocalAuth(a.handleLocalPutFile))
	mux.HandleFunc("POST /local/v1/register", a.requireLocalAuth(a.handleLocalRegister))
	mux.HandleFunc("POST /local/v1/register-batch", a.requireLocalAuth(a.handleLocalRegisterBatch))
	mux.HandleFunc("GET /local/v1/status", a.requireLocalAuth(a.handleLocalStatus))
	return mux
}

func (a *Agent) publicRoutes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/claim", a.handleClaim)
	mux.HandleFunc("POST /api/v1/claim-batch", a.handleClaimBatch)
	mux.HandleFunc("GET /api/v1/files/{id}/stream", a.handleStream)
	mux.HandleFunc("POST /api/v1/files/{id}/renew", a.handleRenew)
	mux.HandleFunc("POST /api/v1/files/{id}/ack", a.handleAck)
	mux.HandleFunc("POST /api/v1/files/batch-ack", a.handleBatchAck)
	mux.HandleFunc("POST /api/v1/files/{id}/nack", a.handleNack)
	return mux
}

func (a *Agent) enqueueDeletePaths(paths ...string) {
	if len(paths) == 0 {
		return
	}
	if a.cfg.DeleteBatchIntervalSec <= 0 {
		for _, p := range paths {
			if rmErr := os.Remove(p); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
				a.logger.Warn("remove verified spool file failed", "path", p, "err", rmErr)
			}
		}
		return
	}
	a.deleteMu.Lock()
	a.deleteQueue = append(a.deleteQueue, paths...)
	shouldWake := len(a.deleteQueue) >= a.cfg.DeleteBatchSize
	a.deleteMu.Unlock()
	if shouldWake {
		select {
		case a.deleteWakeCh <- struct{}{}:
		default:
		}
	}
}

func (a *Agent) flushDeleteQueue() {
	a.deleteMu.Lock()
	if len(a.deleteQueue) == 0 {
		a.deleteMu.Unlock()
		return
	}
	batch := a.deleteQueue
	a.deleteQueue = nil
	a.deleteMu.Unlock()

	var retry []string
	removed := 0
	for _, p := range batch {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			a.logger.Warn("batched spool unlink failed, will retry", "path", p, "err", err)
			retry = append(retry, p)
		} else {
			removed++
		}
	}
	if len(retry) > 0 {
		a.deleteMu.Lock()
		a.deleteQueue = append(retry, a.deleteQueue...)
		a.deleteMu.Unlock()
	}
	if removed > 0 {
		a.logger.Debug("flushed verified spool deletions", "count", removed)
	}
}

func (a *Agent) deleteFlushLoop(ctx context.Context) {
	interval := time.Duration(a.cfg.DeleteBatchIntervalSec) * time.Second
	if interval < 200*time.Millisecond {
		interval = 200 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			a.flushDeleteQueue()
			return
		case <-ticker.C:
			a.flushDeleteQueue()
		case <-a.deleteWakeCh:
			a.flushDeleteQueue()
		}
	}
}

func isLoopbackHost(hostport string) bool {
	s := strings.TrimSpace(hostport)
	if s == "" {
		return false
	}
	host := s
	if h, _, err := net.SplitHostPort(s); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isNonLoopbackOrigin(origin string) bool {
	origin = strings.TrimSpace(origin)
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Hostname() == "" {
		return true
	}
	return !isLoopbackHost(u.Hostname())
}

func (a *Agent) requireLocalAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Strictly localhost-only: unconditionally reject non-loopback peers, DNS-rebinding Host headers,
		// cross-origin browser requests, and reverse-proxied requests.
		if !isLoopbackHost(r.RemoteAddr) {
			protocol.WriteError(w, http.StatusForbidden, "local endpoint only accepts localhost connections")
			return
		}
		if r.Host != "" && !isLoopbackHost(r.Host) {
			protocol.WriteError(w, http.StatusForbidden, "local endpoint only accepts localhost Host header")
			return
		}
		if isNonLoopbackOrigin(r.Header.Get("Origin")) {
			protocol.WriteError(w, http.StatusForbidden, "cross-origin local request forbidden")
			return
		}
		if r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("Forwarded") != "" || r.Header.Get("X-Real-IP") != "" {
			protocol.WriteError(w, http.StatusForbidden, "proxied requests to local endpoint are forbidden")
			return
		}
		if a.cfg.RequireLocalToken {
			tok := r.Header.Get(protocol.HeaderLocalToken)
			if a.cfg.LocalToken == "" || !auth.EqualConstantTime(tok, a.cfg.LocalToken) {
				protocol.WriteError(w, http.StatusUnauthorized, "invalid local token")
				return
			}
		}
		next(w, r)
	}
}

func isValidProjectID(id string) bool {
	p := strings.TrimSpace(id)
	if len(p) == 0 || len(p) > 64 || p == "." || p == ".." || strings.Contains(p, "..") {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func parseCustomerIDList(raws ...string) []string {
	var out []string
	seen := make(map[string]struct{})
	for _, raw := range raws {
		for _, part := range strings.Split(raw, ",") {
			id := strings.TrimSpace(part)
			if id == "" || !isValidProjectID(id) {
				continue
			}
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			out = append(out, id)
			if len(out) >= 16 {
				return out
			}
		}
	}
	return out
}

func sanitizeHintName(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(s, "\r", " "), "\n", " "))
	if r := []rune(s); len(r) > 128 {
		s = string(r[:128])
	}
	return s
}

func extractProjectHintFromRequest(r *http.Request) (projName string, customers []string) {
	q := r.URL.Query()
	projName = sanitizeHintName(r.Header.Get(protocol.HeaderProjectName))
	if projName == "" {
		projName = sanitizeHintName(q.Get("project_name"))
	}
	customers = parseCustomerIDList(
		r.Header.Get(protocol.HeaderCustomer),
		r.Header.Get("X-Account"),
		q.Get("customer"),
		q.Get("account"),
	)
	return projName, customers
}

func (a *Agent) recordProjectHint(projectID, projName string, customers []string) {
	if projectID == "" || (projName == "" && len(customers) == 0) {
		return
	}
	a.hintMu.Lock()
	defer a.hintMu.Unlock()
	if a.projectHints == nil {
		a.projectHints = make(map[string]protocol.ProjectAutoHint)
	}
	if len(a.projectHints) >= 4096 {
		if _, exists := a.projectHints[projectID]; !exists {
			// Clear stale cache once upper bound is hit; active projects re-populate on next upload.
			a.projectHints = make(map[string]protocol.ProjectAutoHint)
		}
	}
	cur := a.projectHints[projectID]
	if cur.Name == "" && projName != "" {
		cur.Name = projName
	}
	if len(cur.CustomerIDs) == 0 && len(customers) > 0 {
		cur.CustomerIDs = append([]string(nil), customers...)
	}
	a.projectHints[projectID] = cur
}

func (a *Agent) snapshotProjectHints(avail []protocol.ProjectAvailability) map[string]protocol.ProjectAutoHint {
	if len(avail) == 0 {
		return nil
	}
	a.hintMu.RLock()
	defer a.hintMu.RUnlock()
	if len(a.projectHints) == 0 {
		return nil
	}
	var out map[string]protocol.ProjectAutoHint
	for _, av := range avail {
		h, ok := a.projectHints[av.ProjectID]
		if !ok || (h.Name == "" && len(h.CustomerIDs) == 0) {
			continue
		}
		if out == nil {
			out = make(map[string]protocol.ProjectAutoHint)
		}
		out[av.ProjectID] = protocol.ProjectAutoHint{
			Name:        h.Name,
			CustomerIDs: append([]string(nil), h.CustomerIDs...),
		}
	}
	return out
}

func (a *Agent) handleLocalPutFile(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.PathValue("project"))
	filename := strings.TrimSpace(r.PathValue("filename"))
	expectedSHA256 := strings.TrimSpace(r.Header.Get(protocol.HeaderExpectedSHA256))
	projName, customers := extractProjectHintFromRequest(r)
	a.ingestRawBody(w, r, projectID, filename, expectedSHA256, projName, customers)
}

func (a *Agent) ingestRawBody(w http.ResponseWriter, r *http.Request, projectID, filename, expectedSHA256, projName string, customers []string) {
	if a.draining.Load() {
		w.Header().Set(protocol.HeaderDraining, "1")
		protocol.WriteError(w, http.StatusServiceUnavailable, "dispatch node is shutting down")
		return
	}
	var extraBytes uint64
	if r.ContentLength > 0 {
		extraBytes = uint64(r.ContentLength)
	}
	cacheRoot, awaiting, alarm, err := a.pickCacheDir(extraBytes)
	if awaiting {
		protocol.WriteError(w, http.StatusServiceUnavailable, "dispatch node awaiting data disk selection in console")
		return
	}
	if alarm {
		a.triggerHeartbeat()
		protocol.WriteError(w, http.StatusInsufficientStorage, "disk watermark exceeded on agent-a")
		return
	}
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "disk check failed: "+err.Error())
		return
	}
	if !isValidProjectID(projectID) {
		protocol.WriteError(w, http.StatusBadRequest, "invalid project id: only [A-Za-z0-9._-] (1-64 chars) allowed")
		return
	}
	if !a.cfg.AllowsProject(projectID) {
		protocol.WriteError(w, http.StatusForbidden, "project not allowed on this node")
		return
	}
	cleanName, err := transfer.SanitizeRelativePath(filename)
	if err != nil {
		protocol.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	fileID := uuid.NewString()
	a.diskHealth.BeginIO(cacheRoot)
	defer a.diskHealth.EndIO(cacheRoot)
	tmpPath := filepath.Join(cacheRoot, "uploading", fileID+".tmp")
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		a.reportDiskWriteErr(cacheRoot, err)
		protocol.WriteError(w, http.StatusInternalServerError, "create temp file: "+err.Error())
		return
	}
	written, actualSHA, copyErr := transfer.CopyStream(r.Context(), f, r.Body, nil, nil)
	syncErr := f.Sync()
	closeErr := f.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		a.reportDiskWriteErr(cacheRoot, copyErr)
		a.reportDiskWriteErr(cacheRoot, syncErr)
		a.reportDiskWriteErr(cacheRoot, closeErr)
		_ = os.Remove(tmpPath)
		protocol.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("upload write failed: %v %v %v", copyErr, syncErr, closeErr))
		return
	}
	if expectedSHA256 != "" && !strings.EqualFold(expectedSHA256, actualSHA) {
		_ = os.Remove(tmpPath)
		protocol.WriteError(w, http.StatusBadRequest, fmt.Sprintf("sha256 mismatch: expected %s got %s", expectedSHA256, actualSHA))
		return
	}
	if _, _, _, _, postAlarm, err := a.checkSingleDiskWatermark(cacheRoot, 0); err == nil && postAlarm {
		_ = os.Remove(tmpPath)
		a.triggerHeartbeat()
		protocol.WriteError(w, http.StatusInsufficientStorage, "disk watermark exceeded after upload")
		return
	}

	readyPath := filepath.Join(cacheRoot, "ready", fileID+".dat")
	if err := os.Rename(tmpPath, readyPath); err != nil {
		_ = os.Remove(tmpPath)
		protocol.WriteError(w, http.StatusInternalServerError, "commit file: "+err.Error())
		return
	}

	rec := FileRecord{
		FileID:     fileID,
		ProjectID:  projectID,
		Filename:   cleanName,
		DataPath:   readyPath,
		Size:       written,
		SHA256:     actualSHA,
		Status:     protocol.FileStatusReady,
		UploadedAt: time.Now().UTC(),
	}
	uplEv := &protocol.SummaryEvent{
		EventID:     "upl-" + fileID,
		ProjectID:   projectID,
		ProjectName: projName,
		CustomerIDs: customers,
		ANodeID:     a.cfg.NodeID,
		EventType:   protocol.EventUploaded,
		Bytes:       written,
		Timestamp:   rec.UploadedAt,
	}
	if err := a.store.PutReady(rec, uplEv); err != nil {
		_ = os.Remove(readyPath)
		protocol.WriteError(w, http.StatusInternalServerError, "persist file metadata: "+err.Error())
		return
	}
	a.recordProjectHint(projectID, projName, customers)

	a.triggerEventFlush()
	a.triggerHeartbeat()

	a.logger.Info("local file uploaded via PUT and verified READY", "file_id", fileID, "project", projectID, "filename", cleanName, "size", written, "customers", customers)
	protocol.WriteJSON(w, http.StatusOK, protocol.LocalUploadResp{
		FileID:      fileID,
		ProjectID:   projectID,
		Filename:    cleanName,
		Size:        written,
		SHA256:      actualSHA,
		Status:      protocol.FileStatusReady,
		CustomerIDs: customers,
	})
}

func (a *Agent) handleLocalUpload(w http.ResponseWriter, r *http.Request) {
	if a.draining.Load() {
		w.Header().Set(protocol.HeaderDraining, "1")
		protocol.WriteError(w, http.StatusServiceUnavailable, "dispatch node is shutting down")
		return
	}
	var extraBytes uint64
	if r.ContentLength > 0 {
		extraBytes = uint64(r.ContentLength)
	}
	cacheRoot, awaiting, alarm, err := a.pickCacheDir(extraBytes)
	if awaiting {
		protocol.WriteError(w, http.StatusServiceUnavailable, "dispatch node awaiting data disk selection in console")
		return
	}
	if alarm {
		a.triggerHeartbeat()
		protocol.WriteError(w, http.StatusInsufficientStorage, "disk watermark exceeded on agent-a")
		return
	}
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "disk check failed: "+err.Error())
		return
	}

	projName, customers := extractProjectHintFromRequest(r)
	var (
		projectID      = strings.TrimSpace(r.Header.Get(protocol.HeaderProject))
		filename       = strings.TrimSpace(r.Header.Get(protocol.HeaderFilename))
		expectedSHA256 = strings.TrimSpace(r.Header.Get(protocol.HeaderExpectedSHA256))
	)

	fileID := uuid.NewString()
	a.diskHealth.BeginIO(cacheRoot)
	defer a.diskHealth.EndIO(cacheRoot)
	tmpPath := filepath.Join(cacheRoot, "uploading", fileID+".tmp")
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
			case "customer", "customers", "account":
				b, _ := io.ReadAll(io.LimitReader(part, 1024))
				if cs := parseCustomerIDList(string(b)); len(cs) > 0 {
					customers = parseCustomerIDList(strings.Join(append(customers, cs...), ","))
				}
				_ = part.Close()
			case "project_name":
				b, _ := io.ReadAll(io.LimitReader(part, 512))
				if nm := sanitizeHintName(string(b)); nm != "" {
					projName = nm
				}
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
					a.reportDiskWriteErr(cacheRoot, copyErr)
					a.reportDiskWriteErr(cacheRoot, syncErr)
					a.reportDiskWriteErr(cacheRoot, closeErr)
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
		if !isValidProjectID(projectID) {
			_ = os.Remove(tmpPath)
			protocol.WriteError(w, http.StatusBadRequest, "invalid project id: only [A-Za-z0-9._-] (1-64 chars) allowed")
			return
		}
		if !a.cfg.AllowsProject(projectID) {
			_ = os.Remove(tmpPath)
			protocol.WriteError(w, http.StatusForbidden, "project not allowed on this node")
			return
		}
	} else {
		if !isValidProjectID(projectID) {
			protocol.WriteError(w, http.StatusBadRequest, "invalid project id: only [A-Za-z0-9._-] (1-64 chars) allowed")
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
			a.reportDiskWriteErr(cacheRoot, copyErr)
			a.reportDiskWriteErr(cacheRoot, syncErr)
			a.reportDiskWriteErr(cacheRoot, closeErr)
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
	if _, _, _, _, postAlarm, err := a.checkSingleDiskWatermark(cacheRoot, 0); err == nil && postAlarm {
		_ = os.Remove(tmpPath)
		a.triggerHeartbeat()
		protocol.WriteError(w, http.StatusInsufficientStorage, "disk watermark exceeded after upload")
		return
	}

	readyPath := filepath.Join(cacheRoot, "ready", fileID+".dat")
	if err := os.Rename(tmpPath, readyPath); err != nil {
		_ = os.Remove(tmpPath)
		protocol.WriteError(w, http.StatusInternalServerError, "commit file: "+err.Error())
		return
	}

	rec := FileRecord{
		FileID:     fileID,
		ProjectID:  projectID,
		Filename:   cleanName,
		DataPath:   readyPath,
		Size:       written,
		SHA256:     actualSHA,
		Status:     protocol.FileStatusReady,
		UploadedAt: time.Now().UTC(),
	}
	uplEv := &protocol.SummaryEvent{
		EventID:     "upl-" + fileID,
		ProjectID:   projectID,
		ProjectName: projName,
		CustomerIDs: customers,
		ANodeID:     a.cfg.NodeID,
		EventType:   protocol.EventUploaded,
		Bytes:       written,
		Timestamp:   rec.UploadedAt,
	}
	if err := a.store.PutReady(rec, uplEv); err != nil {
		_ = os.Remove(readyPath)
		protocol.WriteError(w, http.StatusInternalServerError, "persist file metadata: "+err.Error())
		return
	}
	a.recordProjectHint(projectID, projName, customers)

	a.triggerEventFlush()
	a.triggerHeartbeat()

	a.logger.Info("local file uploaded and verified READY", "file_id", fileID, "project", projectID, "filename", cleanName, "size", written, "customers", customers)
	protocol.WriteJSON(w, http.StatusOK, protocol.LocalUploadResp{
		FileID:      fileID,
		ProjectID:   projectID,
		Filename:    cleanName,
		Size:        written,
		SHA256:      actualSHA,
		Status:      protocol.FileStatusReady,
		CustomerIDs: customers,
	})
}

func (a *Agent) handleLocalRegister(w http.ResponseWriter, r *http.Request) {
	if a.draining.Load() {
		w.Header().Set(protocol.HeaderDraining, "1")
		protocol.WriteError(w, http.StatusServiceUnavailable, "dispatch node is shutting down")
		return
	}
	var req protocol.LocalRegisterReq
	if err := protocol.DecodeJSON(r.Body, &req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if !isValidProjectID(req.ProjectID) || req.LocalPath == "" || strings.ContainsRune(req.LocalPath, 0) {
		protocol.WriteError(w, http.StatusBadRequest, "valid project_id ([A-Za-z0-9._-]) and local_path are required")
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
	cacheRoot, awaiting, alarm, err := a.pickCacheDir(0)
	if awaiting {
		protocol.WriteError(w, http.StatusServiceUnavailable, "dispatch node awaiting data disk selection in console")
		return
	}
	if alarm {
		a.triggerHeartbeat()
		protocol.WriteError(w, http.StatusInsufficientStorage, "disk watermark exceeded on agent-a")
		return
	}
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "disk check failed: "+err.Error())
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
	readyPath := filepath.Join(cacheRoot, "ready", fileID+".dat")
	if mode == "hardlink" {
		if err := os.Link(req.LocalPath, readyPath); err != nil {
			protocol.WriteError(w, http.StatusInternalServerError, "hardlink failed: "+err.Error())
			return
		}
	} else {
		if err := os.Rename(req.LocalPath, readyPath); err != nil {
			// Cross-device fallback requires extra space on cache disk: enforce disk watermark before copying.
			if _, _, _, _, xAlarm, wErr := a.checkSingleDiskWatermark(cacheRoot, uint64(size)); wErr == nil && xAlarm {
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
		DataPath:   readyPath,
		Size:       size,
		SHA256:     actualSHA,
		Status:     protocol.FileStatusReady,
		UploadedAt: time.Now().UTC(),
	}
	reqProjName, reqCustomers := extractProjectHintFromRequest(r)
	if nm := sanitizeHintName(req.ProjectName); nm != "" {
		reqProjName = nm
	}
	regCustomers := parseCustomerIDList(append(append([]string{req.Customer}, req.Customers...), reqCustomers...)...)
	uplEv := &protocol.SummaryEvent{
		EventID:     "upl-" + fileID,
		ProjectID:   req.ProjectID,
		ProjectName: reqProjName,
		CustomerIDs: regCustomers,
		ANodeID:     a.cfg.NodeID,
		EventType:   protocol.EventUploaded,
		Bytes:       size,
		Timestamp:   rec.UploadedAt,
	}
	if err := a.store.PutReady(rec, uplEv); err != nil {
		_ = os.Remove(readyPath)
		protocol.WriteError(w, http.StatusInternalServerError, "persist file metadata: "+err.Error())
		return
	}
	a.recordProjectHint(req.ProjectID, reqProjName, regCustomers)

	a.triggerEventFlush()
	a.triggerHeartbeat()

	a.logger.Info("local file registered and verified READY", "file_id", fileID, "project", req.ProjectID, "filename", cleanName, "size", size, "mode", mode, "customers", regCustomers)
	protocol.WriteJSON(w, http.StatusOK, protocol.LocalUploadResp{
		FileID:      fileID,
		ProjectID:   req.ProjectID,
		Filename:    cleanName,
		Size:        size,
		SHA256:      actualSHA,
		Status:      protocol.FileStatusReady,
		CustomerIDs: regCustomers,
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

func (a *Agent) handleLocalRegisterBatch(w http.ResponseWriter, r *http.Request) {
	if a.draining.Load() {
		w.Header().Set(protocol.HeaderDraining, "1")
		protocol.WriteError(w, http.StatusServiceUnavailable, "dispatch node is shutting down")
		return
	}
	var req protocol.LocalRegisterBatchReq
	if err := protocol.DecodeJSON(r.Body, &req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if len(req.Items) == 0 || len(req.Items) > 256 {
		protocol.WriteError(w, http.StatusBadRequest, "items must contain between 1 and 256 entries")
		return
	}
	if a.awaitingDisk() {
		protocol.WriteError(w, http.StatusServiceUnavailable, "dispatch node awaiting data disk selection in console")
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

	reqProjName, reqCustomers := extractProjectHintFromRequest(r)
	results := make([]protocol.LocalRegisterBatchItemResult, len(req.Items))
	var (
		recs       []FileRecord
		evs        []*protocol.SummaryEvent
		readyPaths []string
		recIdx     []int
	)

	for i, it := range req.Items {
		results[i].Index = i
		if !isValidProjectID(it.ProjectID) || it.LocalPath == "" || strings.ContainsRune(it.LocalPath, 0) {
			results[i].Error = "valid project_id ([A-Za-z0-9._-]) and local_path are required"
			continue
		}
		if !a.cfg.AllowsProject(it.ProjectID) {
			results[i].Error = "project not allowed on this node"
			continue
		}
		fname := it.Filename
		if fname == "" {
			fname = filepath.Base(it.LocalPath)
		}
		cleanName, err := transfer.SanitizeRelativePath(fname)
		if err != nil {
			results[i].Error = err.Error()
			continue
		}
		mode := strings.ToLower(strings.TrimSpace(it.Mode))
		if mode == "" {
			mode = "move"
		}
		if mode != "move" && mode != "hardlink" {
			results[i].Error = "mode must be 'move' or 'hardlink'"
			continue
		}
		st, err := os.Lstat(it.LocalPath)
		if err != nil || !st.Mode().IsRegular() {
			results[i].Error = "local_path must exist and be a regular file (symlinks not allowed)"
			continue
		}
		size, actualSHA, err := transfer.HashFile(r.Context(), it.LocalPath)
		if err != nil {
			results[i].Error = "hash local file: " + err.Error()
			continue
		}
		if it.ExpectedSHA256 != "" && !strings.EqualFold(strings.TrimSpace(it.ExpectedSHA256), actualSHA) {
			results[i].Error = fmt.Sprintf("sha256 mismatch: expected %s got %s", it.ExpectedSHA256, actualSHA)
			continue
		}

		cacheRoot, _, cAlarm, cErr := a.pickCacheDir(0)
		if cErr != nil || cAlarm {
			a.triggerHeartbeat()
			results[i].Error = "disk watermark exceeded on agent-a"
			continue
		}
		fileID := uuid.NewString()
		readyPath := filepath.Join(cacheRoot, "ready", fileID+".dat")
		if mode == "hardlink" {
			if err := os.Link(it.LocalPath, readyPath); err != nil {
				results[i].Error = "hardlink failed: " + err.Error()
				continue
			}
		} else {
			if err := os.Rename(it.LocalPath, readyPath); err != nil {
				if _, _, _, _, xAlarm, wErr := a.checkSingleDiskWatermark(cacheRoot, uint64(size)); wErr == nil && xAlarm {
					a.triggerHeartbeat()
					results[i].Error = "disk watermark exceeded on agent-a"
					continue
				}
				if err := a.crossDeviceMove(r.Context(), it.LocalPath, readyPath, actualSHA); err != nil {
					results[i].Error = "move failed: " + err.Error()
					continue
				}
			}
		}

		now := time.Now().UTC()
		rec := FileRecord{
			FileID:     fileID,
			ProjectID:  it.ProjectID,
			Filename:   cleanName,
			DataPath:   readyPath,
			Size:       size,
			SHA256:     actualSHA,
			Status:     protocol.FileStatusReady,
			UploadedAt: now,
		}
		itProjName := sanitizeHintName(it.ProjectName)
		if itProjName == "" {
			itProjName = reqProjName
		}
		itCustomers := parseCustomerIDList(append(append([]string{it.Customer}, it.Customers...), reqCustomers...)...)
		recs = append(recs, rec)
		evs = append(evs, &protocol.SummaryEvent{
			EventID:     "upl-" + fileID,
			ProjectID:   it.ProjectID,
			ProjectName: itProjName,
			CustomerIDs: itCustomers,
			ANodeID:     a.cfg.NodeID,
			EventType:   protocol.EventUploaded,
			Bytes:       size,
			Timestamp:   now,
		})
		a.recordProjectHint(it.ProjectID, itProjName, itCustomers)
		readyPaths = append(readyPaths, readyPath)
		recIdx = append(recIdx, i)
	}

	if len(recs) > 0 {
		if err := a.store.PutReadyBatch(recs, evs); err != nil {
			for _, p := range readyPaths {
				_ = os.Remove(p)
			}
			protocol.WriteError(w, http.StatusInternalServerError, "persist batch metadata: "+err.Error())
			return
		}
		for k, rec := range recs {
			results[recIdx[k]].File = &protocol.LocalUploadResp{
				FileID:    rec.FileID,
				ProjectID: rec.ProjectID,
				Filename:  rec.Filename,
				Size:      rec.Size,
				SHA256:    rec.SHA256,
				Status:    protocol.FileStatusReady,
			}
		}
		a.triggerEventFlush()
		a.triggerHeartbeat()
	}

	protocol.WriteJSON(w, http.StatusOK, protocol.LocalRegisterBatchResp{Results: results})
}

func (a *Agent) handleLocalStatus(w http.ResponseWriter, r *http.Request) {
	total, free, pct, alarm, _ := a.diskWatermarkStatus(0)
	proj := r.URL.Query().Get("project")
	readyCnt, claimedCnt, readyBytes, claimedBytes, err := a.store.ComputeStats(proj)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if r.URL.Query().Get("summary") == "1" {
		protocol.WriteJSON(w, http.StatusOK, protocol.LiveFilesResp{
			ANodeID:      a.cfg.NodeID,
			AName:        a.cfg.NodeName,
			PublicAddr:   a.cfg.PublicAddr,
			Files:        []protocol.LiveFileItem{},
			TotalFiles:   readyCnt + claimedCnt,
			ReadyCount:   readyCnt,
			ClaimedCount: claimedCnt,
			ReadyBytes:   readyBytes,
			ClaimedBytes: claimedBytes,
			DiskTotal:    total,
			DiskFree:     free,
			DiskUsedPct:  pct,
			DiskAlarm:    alarm,
		})
		return
	}
	limit := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if v, pErr := strconv.Atoi(raw); pErr == nil && v > 0 {
			limit = v
		}
	}
	files, totalFiles, truncated, err := a.store.ListLiveLimit(proj, limit)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	protocol.WriteJSON(w, http.StatusOK, protocol.LiveFilesResp{
		ANodeID:      a.cfg.NodeID,
		AName:        a.cfg.NodeName,
		PublicAddr:   a.cfg.PublicAddr,
		Files:        files,
		TotalFiles:   totalFiles,
		Truncated:    truncated,
		ReadyCount:   readyCnt,
		ClaimedCount: claimedCnt,
		ReadyBytes:   readyBytes,
		ClaimedBytes: claimedBytes,
		DiskTotal:    total,
		DiskFree:     free,
		DiskUsedPct:  pct,
		DiskAlarm:    alarm,
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
	if a.paused.Load() || a.draining.Load() {
		w.WriteHeader(http.StatusNoContent)
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

func (a *Agent) handleClaimBatch(w http.ResponseWriter, r *http.Request) {
	tok := auth.ExtractBearer(r.Header.Get("Authorization"))
	claims, err := auth.VerifyAccessJWT(a.cfg.JWTSecret, tok)
	if err != nil {
		protocol.WriteError(w, http.StatusUnauthorized, err.Error())
		return
	}
	var req protocol.ClaimBatchReq
	if err := protocol.DecodeJSON(r.Body, &req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "invalid claim-batch request")
		return
	}
	if claims.ANodeID != a.cfg.NodeID || claims.ProjectID != req.ProjectID || claims.BNodeID != req.BNodeID {
		protocol.WriteError(w, http.StatusForbidden, "token claims mismatch")
		return
	}
	if a.paused.Load() || a.draining.Load() {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	leaseTTL, err := a.validateLeaseTTL(req.LeaseTTLSec)
	if err != nil {
		protocol.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	maxCount := req.MaxCount
	if maxCount <= 0 {
		maxCount = 16
	}
	if maxCount > 256 {
		maxCount = 256
	}
	recs, err := a.store.ClaimBatch(req.ProjectID, req.BNodeID, req.AvailableDiskBytes, leaseTTL, maxCount)
	if errors.Is(err, ErrNoReadyFile) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	items := make([]protocol.ClaimResp, 0, len(recs))
	for _, rec := range recs {
		items = append(items, protocol.ClaimResp{
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
	a.triggerHeartbeat()
	a.logger.Info("file batch claimed", "count", len(items), "project", req.ProjectID, "b_node", req.BNodeID)
	protocol.WriteJSON(w, http.StatusOK, protocol.ClaimBatchResp{Items: items})
}

func (a *Agent) handleStream(w http.ResponseWriter, r *http.Request) {
	if a.draining.Load() {
		w.Header().Set(protocol.HeaderDraining, "1")
		w.Header().Set("Retry-After", "5")
		protocol.WriteError(w, http.StatusServiceUnavailable, "dispatch node is shutting down")
		return
	}
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

	filePath := a.readyPathForRecord(*rec)
	diskRoot := transfer.MatchRootForPath(filePath, a.activeCacheDirs())
	a.diskHealth.BeginIO(diskRoot)
	defer a.diskHealth.EndIO(diskRoot)

	f, err := os.Open(filePath)
	if err != nil {
		a.reportDiskWriteErr(diskRoot, err)
		probe := a.diskHealth.ProbeRoot(diskRoot, !a.isDiskDisabled(diskRoot), a.effectiveMaxDiskUsagePct(), a.cfg.MinFreeDiskBytes, 0)
		if probe.Detached || !probe.Mounted || transfer.IsDiskIOError(err) {
			a.triggerHeartbeat()
			w.Header().Set("Retry-After", "5")
			protocol.WriteError(w, http.StatusServiceUnavailable, "backing cache disk detached/unavailable")
			return
		}
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
			}
			if wErr != nil {
				return
			}
			if a.StreamChunkHook != nil {
				if flusher != nil {
					flusher.Flush()
				}
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
			a.reportDiskWriteErr(diskRoot, rErr)
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

	var removeFn func(id string) error
	if a.cfg.DeleteBatchIntervalSec <= 0 {
		removeFn = func(id string) error {
			if rmErr := os.Remove(a.filePathForID(id)); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
				return rmErr
			}
			return nil
		}
	}

	rec, alreadyDeleted, err := a.store.AckAndRemove(fileID, req.LeaseID, leaseToken, req.BNodeID, req.SHA256, removeFn, func(r FileRecord) *protocol.SummaryEvent {
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
	if a.cfg.DeleteBatchIntervalSec > 0 {
		a.enqueueDeletePaths(a.readyPathForRecord(*rec))
	}

	a.triggerEventFlush()
	a.triggerHeartbeat()

	a.logger.Info("file ACK verified and deleted", "file_id", fileID, "project", rec.ProjectID, "b_node", req.BNodeID, "size", rec.Size)
	protocol.WriteJSON(w, http.StatusOK, protocol.AckResp{Status: "deleted"})
}

func (a *Agent) handleBatchAck(w http.ResponseWriter, r *http.Request) {
	var req protocol.BatchAckReq
	if err := protocol.DecodeJSON(r.Body, &req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "invalid batch-ack request")
		return
	}
	if strings.TrimSpace(req.BNodeID) == "" || len(req.Items) == 0 {
		protocol.WriteError(w, http.StatusBadRequest, "b_node_id and non-empty items are required")
		return
	}
	if len(req.Items) > 512 {
		protocol.WriteError(w, http.StatusBadRequest, "batch-ack accepts at most 512 items")
		return
	}

	var removeFn func(id string) error
	if a.cfg.DeleteBatchIntervalSec <= 0 {
		removeFn = func(id string) error {
			if rmErr := os.Remove(a.filePathForID(id)); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
				return rmErr
			}
			return nil
		}
	}

	results, deletedRecs, err := a.store.BatchAckAndRemove(req.BNodeID, req.Items, removeFn, func(rec FileRecord, durationMs int64) *protocol.SummaryEvent {
		return &protocol.SummaryEvent{
			EventID:    "cmp-" + rec.FileID,
			ProjectID:  rec.ProjectID,
			ANodeID:    a.cfg.NodeID,
			BNodeID:    req.BNodeID,
			EventType:  protocol.EventCompleted,
			Bytes:      rec.Size,
			DurationMs: durationMs,
			Timestamp:  time.Now().UTC(),
		}
	})
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if len(deletedRecs) > 0 {
		if a.cfg.DeleteBatchIntervalSec > 0 {
			paths := make([]string, len(deletedRecs))
			for i, rec := range deletedRecs {
				paths[i] = a.readyPathForRecord(rec)
			}
			a.enqueueDeletePaths(paths...)
		}
		a.triggerEventFlush()
		a.triggerHeartbeat()
		var totalBytes int64
		for _, rec := range deletedRecs {
			totalBytes += rec.Size
		}
		a.logger.Info("batch ACK verified", "b_node", req.BNodeID, "deleted", len(deletedRecs), "bytes", totalBytes, "delayed_unlink", a.cfg.DeleteBatchIntervalSec > 0)
	}

	protocol.WriteJSON(w, http.StatusOK, protocol.BatchAckResp{Results: results})
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
	lastSent := time.Now()
	const minWakeSpacing = 400 * time.Millisecond

	ticker := time.NewTicker(a.cfg.HeartbeatInterval())
	defer ticker.Stop()
	var debounceTimer *time.Timer
	var debounceCh <-chan time.Time
	defer func() {
		if debounceTimer != nil {
			debounceTimer.Stop()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if debounceTimer != nil {
				debounceTimer.Stop()
				debounceTimer = nil
				debounceCh = nil
			}
			a.sendHeartbeat(ctx)
			lastSent = time.Now()
		case <-debounceCh:
			debounceTimer = nil
			debounceCh = nil
			a.sendHeartbeat(ctx)
			lastSent = time.Now()
		case <-a.hbWakeCh:
			since := time.Since(lastSent)
			if since >= minWakeSpacing {
				if debounceTimer != nil {
					debounceTimer.Stop()
					debounceTimer = nil
					debounceCh = nil
				}
				a.sendHeartbeat(ctx)
				lastSent = time.Now()
			} else if debounceTimer == nil {
				debounceTimer = time.NewTimer(minWakeSpacing - since)
				debounceCh = debounceTimer.C
			}
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
	upgAttempt, upgStatus, upgErr := "", "", ""
	if a.updater != nil {
		upgAttempt, upgStatus, upgErr = a.updater.Status()
	}
	payload := protocol.AgentAHeartbeatReq{
		NodeID:           a.cfg.NodeID,
		Name:             a.cfg.NodeName,
		PublicAddr:       a.cfg.PublicAddr,
		Projects:         a.cfg.Projects,
		Version:          version.Version,
		OS:               runtime.GOOS,
		Arch:             runtime.GOARCH,
		UpgradeAttemptID: upgAttempt,
		UpgradeStatus:    upgStatus,
		UpgradeError:     upgErr,
		DiskTotalBytes:       total,
		DiskFreeBytes:        free,
		DiskUsedPct:          pct,
		DiskAlarm:            alarm,
		MaxDiskUsagePct:      a.effectiveMaxDiskUsagePct(),
		StorageDirs:          a.activeCacheDirs(),
		Disks:                a.collectActiveDiskStatuses(),
		HostDisks:            transfer.DiscoverHostDisks("relay-cache"),
		AwaitingDisk:         a.awaitingDisk(),
		Paused:               a.paused.Load(),
		ActiveStreams:        int(a.activeStreams.Load()),
		MaxConcurrentStreams: a.cfg.MaxConcurrentStreams,
		Availability:         avail,
		ProjectHints:         a.snapshotProjectHints(avail),
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
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		a.logger.Warn("center heartbeat non-2xx", "status", resp.StatusCode)
		return
	}
	var hbResp protocol.HeartbeatResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256*1024)).Decode(&hbResp); err == nil {
		if prev := a.paused.Swap(hbResp.Paused); prev != hbResp.Paused {
			a.logger.Info("dispatch node pause state updated from center", "paused", hbResp.Paused)
		}
		if len(hbResp.StorageDirs) > 0 || hbResp.DiskGen > 0 || len(hbResp.DisabledDisks) > 0 || hbResp.MaxDiskUsagePct > 0 {
			a.applyDiskConfig(hbResp.StorageDirs, hbResp.DisabledDisks, hbResp.DiskGen, hbResp.MaxDiskUsagePct)
		}
		if hbResp.ActiveReceivers != nil || hbResp.ProjectAffinity != nil {
			a.store.SetRoutingState(hbResp.ActiveReceivers, hbResp.ProjectAffinity)
		}
		if hbResp.Upgrade != nil && a.updater != nil {
			a.updater.HandleDirective(ctx, hbResp.Upgrade)
		}
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
	const batchSize = 500
	for {
		if ctx.Err() != nil {
			return
		}
		events, err := a.store.ListPendingEvents(batchSize)
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
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return
		}
		ids := make([]string, len(events))
		for i, ev := range events {
			ids[i] = ev.EventID
		}
		_ = a.store.DeletePendingEvents(ids)
		if len(events) < batchSize {
			return
		}
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
