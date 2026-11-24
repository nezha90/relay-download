package agentb

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"relay-download/internal/pki"
	"relay-download/internal/protocol"
	"relay-download/internal/transfer"
)

type activeProgress struct {
	mu          sync.Mutex
	info        protocol.BActiveTransfer
	windowBytes int64
	windowStart time.Time
}

type Agent struct {
	cfg          *Config
	store        *Store
	logger       *slog.Logger
	apiClient    *http.Client
	streamClient *http.Client
	limiter      *transfer.RateLimiter

	workSem   chan struct{}
	wakeupCh  chan string
	ackWakeCh chan struct{}

	mu       sync.RWMutex
	progress map[string]*activeProgress

	inBytes      atomic.Int64
	lastSpeedBps atomic.Int64

	// Optional metrics for test assertions.
	ResumeCount atomic.Int64

	wg sync.WaitGroup
}

func New(cfg *Config, logger *slog.Logger) (*Agent, error) {
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}

	for proj, dir := range cfg.Projects {
		if err := os.MkdirAll(filepath.Join(dir, ".relay_tmp"), 0o755); err != nil {
			return nil, fmt.Errorf("init dest dir for project %s (%s): %w", proj, dir, err)
		}
	}

	store, err := OpenStore(filepath.Join(cfg.StateDir, "agent-b.db"))
	if err != nil {
		return nil, err
	}

	clientTLS, err := pki.ClientTLSConfig(cfg.CACert)
	if err != nil {
		_ = store.Close()
		return nil, err
	}

	makeTransport := func() *http.Transport {
		return &http.Transport{
			TLSClientConfig:       clientTLS.Clone(),
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          32,
			MaxIdleConnsPerHost:   16,
			IdleConnTimeout:       60 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		}
	}

	var limiter *transfer.RateLimiter
	if cfg.RateLimitMBps > 0 {
		limiter = transfer.NewRateLimiter(int64(cfg.RateLimitMBps * 1024 * 1024))
	}

	return &Agent{
		cfg:     cfg,
		store:   store,
		logger:  logger.With("component", "agent-b", "node_id", cfg.NodeID),
		limiter: limiter,
		apiClient: &http.Client{
			Timeout:   20 * time.Second,
			Transport: makeTransport(),
		},
		// No overall Timeout on streaming/SSE client; bounded by ctx cancellation.
		streamClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig:     clientTLS.Clone(),
				ForceAttemptHTTP2:   true,
				MaxIdleConns:        32,
				MaxIdleConnsPerHost: 16,
				IdleConnTimeout:     90 * time.Second,
				TLSHandshakeTimeout: 10 * time.Second,
			},
		},
		workSem:   make(chan struct{}, cfg.MaxConcurrent),
		wakeupCh:  make(chan string, 64),
		ackWakeCh: make(chan struct{}, 1),
		progress:  make(map[string]*activeProgress),
	}, nil
}

func (a *Agent) Start(ctx context.Context) error {
	defer func() {
		a.wg.Wait()
		_ = a.store.Close()
	}()

	// Resume any downloads persisted before a process restart.
	a.resumePersistedDownloads(ctx)

	go a.speedMeterLoop(ctx)
	go a.heartbeatLoop(ctx)
	go a.ackFlushLoop(ctx)
	go a.sseLoop(ctx)
	go a.dispatchLoop(ctx)

	<-ctx.Done()
	return nil
}

func (a *Agent) resumePersistedDownloads(ctx context.Context) {
	active, err := a.store.ListActive()
	if err != nil {
		a.logger.Warn("load active downloads failed", "err", err)
		return
	}
	for _, dl := range active {
		dlCopy := dl
		select {
		case a.workSem <- struct{}{}:
			a.wg.Add(1)
			go func() {
				defer func() {
					<-a.workSem
					a.wg.Done()
				}()
				a.runDownload(ctx, dlCopy)
			}()
		case <-ctx.Done():
			return
		}
	}
}

func (a *Agent) triggerWakeup(projectID string) {
	select {
	case a.wakeupCh <- projectID:
	default:
	}
}

func (a *Agent) triggerAckFlush() {
	select {
	case a.ackWakeCh <- struct{}{}:
	default:
	}
}

func (a *Agent) speedMeterLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			delta := a.inBytes.Swap(0)
			a.lastSpeedBps.Store(delta)
		}
	}
}

func (a *Agent) sseLoop(ctx context.Context) {
	projects := strings.Join(a.cfg.ProjectIDs(), ",")
	u := strings.TrimRight(a.cfg.CenterURL, "/") + "/api/v1/b/events?projects=" + url.QueryEscape(projects)
	backoff := 500 * time.Millisecond

	for {
		if ctx.Err() != nil {
			return
		}
		err := a.consumeSSE(ctx, u)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			a.logger.Warn("center SSE disconnected, reconnecting", "err", err, "backoff", backoff)
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		backoff *= 2
		if backoff > 15*time.Second {
			backoff = 15 * time.Second
		}
	}
}

func (a *Agent) consumeSSE(ctx context.Context, sseURL string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sseURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set(protocol.HeaderNodeID, a.cfg.NodeID)
	req.Header.Set(protocol.HeaderNodeToken, a.cfg.CenterToken)

	resp, err := a.streamClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("SSE returned HTTP %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	var eventName string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "event:") {
			eventName = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		} else if strings.HasPrefix(line, "data:") {
			data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if eventName == "wakeup" && data != "" {
				// Small jitter to avoid thundering herd across many B nodes.
				jitter := time.Duration(20+rand.IntN(80)) * time.Millisecond
				proj := data
				go func() {
					t := time.NewTimer(jitter)
					defer t.Stop()
					select {
					case <-ctx.Done():
					case <-t.C:
						a.triggerWakeup(proj)
					}
				}()
			}
		} else if line == "" {
			eventName = ""
		}
	}
	return scanner.Err()
}

func (a *Agent) dispatchLoop(ctx context.Context) {
	// Initial scan on startup.
	a.scanAllProjects(ctx)

	ticker := time.NewTicker(a.cfg.PollInterval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case proj := <-a.wakeupCh:
			if _, ok := a.cfg.Projects[proj]; ok {
				a.scanProject(ctx, proj)
			} else {
				a.scanAllProjects(ctx)
			}
		case <-ticker.C:
			a.scanAllProjects(ctx)
		}
	}
}

func (a *Agent) scanAllProjects(ctx context.Context) {
	ids := a.cfg.ProjectIDs()
	rand.Shuffle(len(ids), func(i, j int) { ids[i], ids[j] = ids[j], ids[i] })
	for _, proj := range ids {
		if ctx.Err() != nil {
			return
		}
		if len(a.workSem) >= cap(a.workSem) {
			return
		}
		a.scanProject(ctx, proj)
	}
}

func (a *Agent) scanProject(ctx context.Context, projectID string) {
	destDir, ok := a.cfg.Projects[projectID]
	if !ok {
		return
	}
	if len(a.workSem) >= cap(a.workSem) {
		return
	}

	disc, err := a.discover(ctx, projectID)
	if err != nil {
		a.logger.Warn("discover failed", "project", projectID, "err", err)
		return
	}
	if len(disc.Candidates) == 0 {
		return
	}

	for _, cand := range disc.Candidates {
		for {
			if ctx.Err() != nil {
				return
			}
			// Reserve a worker slot before claiming so we never hold a lease without capacity.
			select {
			case a.workSem <- struct{}{}:
			default:
				return
			}

			availDisk := a.availableDiskFor(destDir)
			if availDisk == 0 && a.cfg.MinFreeDiskBytes > 0 {
				<-a.workSem
				a.logger.Warn("insufficient local disk space, skipping claim", "project", projectID, "dest", destDir)
				return
			}

			claimResp, status, err := a.claimFromA(ctx, cand, projectID, availDisk, disc.LeaseTTLSec)
			if err != nil {
				<-a.workSem
				a.logger.Warn("claim from agent-a failed", "a_node", cand.ANodeID, "err", err)
				break
			}
			if status == http.StatusNoContent {
				<-a.workSem
				break // No more ready files on this A node; try next candidate.
			}
			if status == http.StatusUnauthorized {
				<-a.workSem
				break // JWT expired; next scan will refresh.
			}

			partPath := filepath.Join(destDir, ".relay_tmp", claimResp.FileID+".part")
			dl := ActiveDownload{
				FileID:         claimResp.FileID,
				ProjectID:      projectID,
				ANodeID:        cand.ANodeID,
				PublicAddr:     cand.PublicAddr,
				Filename:       claimResp.Filename,
				Size:           claimResp.Size,
				SHA256:         claimResp.SHA256,
				LeaseID:        claimResp.LeaseID,
				LeaseToken:     claimResp.LeaseToken,
				LeaseExpiresAt: claimResp.LeaseExpiresAt,
				LeaseTTLSec:    disc.LeaseTTLSec,
				ConflictPolicy: disc.ConflictPolicy,
				DestDir:        destDir,
				PartPath:       partPath,
				StartedAt:      time.Now().UTC(),
			}
			if err := a.store.PutActive(dl); err != nil {
				<-a.workSem
				a.logger.Error("persist active download failed", "file_id", dl.FileID, "err", err)
				_ = a.sendNack(ctx, dl, "local state persist failed")
				return
			}

			a.wg.Add(1)
			go func(item ActiveDownload) {
				defer func() {
					<-a.workSem
					a.wg.Done()
					// Immediately check for more queued files on completion.
					a.triggerWakeup(item.ProjectID)
				}()
				a.runDownload(ctx, item)
			}(dl)
		}
	}
}

func (a *Agent) availableDiskFor(dir string) uint64 {
	_, free, _, err := transfer.DiskUsage(dir)
	if err != nil {
		return 0
	}
	if a.cfg.MinFreeDiskBytes == 0 {
		return free
	}
	if free <= a.cfg.MinFreeDiskBytes {
		return 0
	}
	return free - a.cfg.MinFreeDiskBytes
}

func (a *Agent) discover(ctx context.Context, projectID string) (*protocol.DiscoverResp, error) {
	u := strings.TrimRight(a.cfg.CenterURL, "/") + "/api/v1/b/discover?project=" + url.QueryEscape(projectID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(protocol.HeaderNodeID, a.cfg.NodeID)
	req.Header.Set(protocol.HeaderNodeToken, a.cfg.CenterToken)

	resp, err := a.apiClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discover returned HTTP %d", resp.StatusCode)
	}
	var out protocol.DiscoverResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (a *Agent) claimFromA(ctx context.Context, cand protocol.DiscoverCandidate, projectID string, availDisk uint64, leaseTTLSec int) (*protocol.ClaimResp, int, error) {
	body, _ := json.Marshal(protocol.ClaimReq{
		ProjectID:          projectID,
		BNodeID:            a.cfg.NodeID,
		AvailableDiskBytes: availDisk,
		LeaseTTLSec:        leaseTTLSec,
	})
	u := strings.TrimRight(cand.PublicAddr, "/") + "/api/v1/claim"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cand.AccessJWT)

	resp, err := a.apiClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusUnauthorized {
		return nil, resp.StatusCode, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("claim returned HTTP %d", resp.StatusCode)
	}
	var out protocol.ClaimResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, resp.StatusCode, err
	}
	return &out, http.StatusOK, nil
}

func (a *Agent) runDownload(ctx context.Context, dl ActiveDownload) {
	startTime := time.Now()
	a.logger.Info("starting download", "file_id", dl.FileID, "project", dl.ProjectID, "a_node", dl.ANodeID, "filename", dl.Filename, "size", dl.Size)

	prog := &activeProgress{
		info: protocol.BActiveTransfer{
			ProjectID: dl.ProjectID,
			ANodeID:   dl.ANodeID,
			FileID:    dl.FileID,
			Filename:  dl.Filename,
			TotalBytes: dl.Size,
			StartedAt: dl.StartedAt,
		},
		windowStart: time.Now(),
	}
	a.mu.Lock()
	a.progress[dl.FileID] = prog
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		delete(a.progress, dl.FileID)
		a.mu.Unlock()
	}()

	// Background lease renewer so even slow SHA256 hashing or brief reconnects never lose the lease.
	renewCtx, stopRenew := context.WithCancel(ctx)
	defer stopRenew()
	go a.leaseRenewLoop(renewCtx, &dl)

	if err := os.MkdirAll(filepath.Dir(dl.PartPath), 0o755); err != nil {
		a.logger.Error("create tmp dir failed", "err", err)
		_ = a.store.DeleteActive(dl.FileID)
		_ = a.sendNack(ctx, dl, "mkdir tmp failed")
		return
	}

	var (
		continuousSHA string
		resumed       bool
		backoff       = 250 * time.Millisecond
	)

	for {
		if ctx.Err() != nil {
			// Keep .part and BoltDB record intact so next startup can resume!
			return
		}
		var offset int64
		if st, err := os.Stat(dl.PartPath); err == nil {
			offset = st.Size()
			if offset > dl.Size {
				_ = os.Truncate(dl.PartPath, 0)
				offset = 0
			}
		}
		prog.setTransferred(offset)

		if offset == dl.Size {
			break
		}
		if offset > 0 {
			resumed = true
		}

		writtenNow, shaIfZero, statusCode, streamErr := a.streamOnce(ctx, dl, offset, prog)
		if streamErr == nil {
			if offset == 0 && !resumed && shaIfZero != "" {
				continuousSHA = shaIfZero
			}
			// Check if we now have all bytes.
			if st, err := os.Stat(dl.PartPath); err == nil && st.Size() == dl.Size {
				break
			}
		}

		// Lease expired or file already gone on A: abandon cleanly & remove stale .part.
		if statusCode == http.StatusConflict || statusCode == http.StatusNotFound || statusCode == http.StatusGone {
			a.logger.Warn("lease expired or file gone on A, abandoning", "file_id", dl.FileID, "status", statusCode)
			_ = os.Remove(dl.PartPath)
			_ = a.store.DeleteActive(dl.FileID)
			return
		}

		if writtenNow > 0 {
			// Progress made before network drop -> reset backoff and record resume.
			backoff = 250 * time.Millisecond
			resumed = true
			a.ResumeCount.Add(1)
			a.logger.Warn("stream interrupted mid-transfer, will resume", "file_id", dl.FileID, "offset", offset+writtenNow, "total", dl.Size, "err", streamErr)
		} else {
			a.logger.Warn("stream error, retrying with backoff", "file_id", dl.FileID, "backoff", backoff, "err", streamErr)
		}

		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		backoff *= 2
		if backoff > 5*time.Second {
			backoff = 5 * time.Second
		}
	}

	// Verify full-file SHA256 before atomic commit.
	actualSHA := continuousSHA
	if actualSHA == "" || resumed {
		_, computed, err := transfer.HashFile(ctx, dl.PartPath)
		if err != nil {
			a.logger.Error("hash downloaded file failed", "file_id", dl.FileID, "err", err)
			_ = os.Remove(dl.PartPath)
			_ = a.store.DeleteActive(dl.FileID)
			_ = a.sendNack(ctx, dl, "hash failed")
			return
		}
		actualSHA = computed
	}

	if !strings.EqualFold(actualSHA, dl.SHA256) {
		a.logger.Error("SHA256 verification FAILED", "file_id", dl.FileID, "expected", dl.SHA256, "actual", actualSHA)
		_ = os.Remove(dl.PartPath)
		_ = a.store.DeleteActive(dl.FileID)
		_ = a.sendNack(ctx, dl, "sha256 mismatch")
		return
	}

	// Safe atomic commit into project destination directory.
	targetPath, skipCommit, err := resolveTargetPath(dl.DestDir, dl.Filename, dl.ConflictPolicy, dl.FileID)
	if err != nil {
		a.logger.Error("invalid target path", "file_id", dl.FileID, "filename", dl.Filename, "err", err)
		_ = os.Remove(dl.PartPath)
		_ = a.store.DeleteActive(dl.FileID)
		_ = a.sendNack(ctx, dl, "invalid path")
		return
	}
	if skipCommit {
		_ = os.Remove(dl.PartPath)
	} else {
		if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
			a.logger.Error("mkdir target parent failed", "err", err)
			_ = a.sendNack(ctx, dl, "mkdir target failed")
			_ = a.store.DeleteActive(dl.FileID)
			return
		}
		if err := os.Rename(dl.PartPath, targetPath); err != nil {
			a.logger.Error("atomic rename failed", "src", dl.PartPath, "dst", targetPath, "err", err)
			_ = a.sendNack(ctx, dl, "rename failed")
			_ = a.store.DeleteActive(dl.FileID)
			return
		}
	}

	_ = a.store.DeleteActive(dl.FileID)

	ack := PendingAck{
		FileID:     dl.FileID,
		ANodeID:    dl.ANodeID,
		PublicAddr: dl.PublicAddr,
		LeaseID:    dl.LeaseID,
		LeaseToken: dl.LeaseToken,
		SHA256:     actualSHA,
		DurationMs: time.Since(startTime).Milliseconds(),
		CreatedAt:  time.Now().UTC(),
	}
	_ = a.store.PutPendingAck(ack)
	if err := a.sendAck(ctx, ack); err == nil {
		_ = a.store.DeletePendingAck(ack.FileID)
	} else {
		a.logger.Warn("immediate ACK failed, queued for retry", "file_id", dl.FileID, "err", err)
		a.triggerAckFlush()
	}

	a.logger.Info("download verified and committed", "file_id", dl.FileID, "project", dl.ProjectID, "target", targetPath, "size", dl.Size)
}

func (a *Agent) streamOnce(ctx context.Context, dl ActiveDownload, offset int64, prog *activeProgress) (written int64, shaFromZero string, statusCode int, err error) {
	u := strings.TrimRight(dl.PublicAddr, "/") + "/api/v1/files/" + url.PathEscape(dl.FileID) + "/stream"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, "", 0, err
	}
	req.Header.Set(protocol.HeaderLeaseToken, dl.LeaseToken)
	if offset > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}

	resp, err := a.streamClient.Do(req)
	if err != nil {
		return 0, "", 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return 0, "", resp.StatusCode, fmt.Errorf("stream returned HTTP %d", resp.StatusCode)
	}

	f, err := os.OpenFile(dl.PartPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return 0, "", resp.StatusCode, err
	}
	defer f.Close()

	// If server returned 200 OK even though we requested offset > 0, reset file to 0.
	if offset > 0 && resp.StatusCode == http.StatusOK {
		if err := f.Truncate(0); err != nil {
			return 0, "", resp.StatusCode, err
		}
		offset = 0
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return 0, "", resp.StatusCode, err
	}

	bufPtr := transfer.GetBuf()
	defer transfer.PutBuf(bufPtr)
	buf := *bufPtr

	var hasher io.Writer
	h := sha256.New()
	if offset == 0 {
		hasher = h
	}

	for {
		if err := ctx.Err(); err != nil {
			_ = f.Sync()
			return written, "", resp.StatusCode, err
		}
		nr, rErr := resp.Body.Read(buf)
		if nr > 0 {
			if a.limiter != nil {
				if err := a.limiter.Wait(ctx, nr); err != nil {
					_ = f.Sync()
					return written, "", resp.StatusCode, err
				}
			}
			nw, wErr := f.Write(buf[:nr])
			if nw > 0 {
				if hasher != nil {
					_, _ = hasher.Write(buf[:nw])
				}
				written += int64(nw)
				a.inBytes.Add(int64(nw))
				prog.addBytes(offset+written, int64(nw))
			}
			if wErr != nil {
				_ = f.Sync()
				return written, "", resp.StatusCode, wErr
			}
			if nw != nr {
				_ = f.Sync()
				return written, "", resp.StatusCode, io.ErrShortWrite
			}
		}
		if rErr == io.EOF {
			if err := f.Sync(); err != nil {
				return written, "", resp.StatusCode, err
			}
			if offset+written < dl.Size {
				return written, "", resp.StatusCode, io.ErrUnexpectedEOF
			}
			if hasher != nil {
				shaFromZero = hex.EncodeToString(h.Sum(nil))
			}
			return written, shaFromZero, resp.StatusCode, nil
		}
		if rErr != nil {
			_ = f.Sync()
			return written, "", resp.StatusCode, rErr
		}
	}
}

func (a *Agent) leaseRenewLoop(ctx context.Context, dl *ActiveDownload) {
	interval := time.Duration(dl.LeaseTTLSec/3) * time.Second
	if interval < 2*time.Second {
		interval = 2 * time.Second
	}
	if interval > 30*time.Second {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			body, _ := json.Marshal(protocol.RenewReq{
				LeaseID:     dl.LeaseID,
				BNodeID:     a.cfg.NodeID,
				LeaseTTLSec: dl.LeaseTTLSec,
			})
			u := strings.TrimRight(dl.PublicAddr, "/") + "/api/v1/files/" + url.PathEscape(dl.FileID) + "/renew"
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(protocol.HeaderLeaseToken, dl.LeaseToken)
			resp, err := a.apiClient.Do(req)
			if err == nil {
				_ = resp.Body.Close()
			}
		}
	}
}

func (a *Agent) sendAck(ctx context.Context, ack PendingAck) error {
	body, _ := json.Marshal(protocol.AckReq{
		LeaseID:    ack.LeaseID,
		BNodeID:    a.cfg.NodeID,
		SHA256:     ack.SHA256,
		DurationMs: ack.DurationMs,
	})
	u := strings.TrimRight(ack.PublicAddr, "/") + "/api/v1/files/" + url.PathEscape(ack.FileID) + "/ack"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(protocol.HeaderLeaseToken, ack.LeaseToken)

	resp, err := a.apiClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound {
		// 200 (deleted / already_deleted) or 404 (gone after A restart) -> ACK done.
		return nil
	}
	return fmt.Errorf("ack returned HTTP %d", resp.StatusCode)
}

func (a *Agent) sendNack(ctx context.Context, dl ActiveDownload, reason string) error {
	body, _ := json.Marshal(protocol.NackReq{
		LeaseID: dl.LeaseID,
		BNodeID: a.cfg.NodeID,
		Reason:  reason,
	})
	u := strings.TrimRight(dl.PublicAddr, "/") + "/api/v1/files/" + url.PathEscape(dl.FileID) + "/nack"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(protocol.HeaderLeaseToken, dl.LeaseToken)
	resp, err := a.apiClient.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

func (a *Agent) ackFlushLoop(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.flushPendingAcks(ctx)
		case <-a.ackWakeCh:
			a.flushPendingAcks(ctx)
		}
	}
}

func (a *Agent) flushPendingAcks(ctx context.Context) {
	acks, err := a.store.ListPendingAcks()
	if err != nil || len(acks) == 0 {
		return
	}
	for _, ack := range acks {
		if ctx.Err() != nil {
			return
		}
		if err := a.sendAck(ctx, ack); err == nil {
			_ = a.store.DeletePendingAck(ack.FileID)
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
		}
	}
}

func (a *Agent) sendHeartbeat(ctx context.Context) {
	var totalDisk, freeDisk uint64
	var usedPct float64
	for _, dir := range a.cfg.Projects {
		if t, f, pct, err := transfer.DiskUsage(dir); err == nil {
			totalDisk, freeDisk, usedPct = t, f, pct
			break
		}
	}

	a.mu.RLock()
	active := make([]protocol.BActiveTransfer, 0, len(a.progress))
	for _, p := range a.progress {
		active = append(active, p.snapshot())
	}
	a.mu.RUnlock()

	payload := protocol.AgentBHeartbeatReq{
		NodeID:          a.cfg.NodeID,
		Name:            a.cfg.NodeName,
		Projects:        a.cfg.ProjectIDs(),
		DiskTotalBytes:  totalDisk,
		DiskFreeBytes:   freeDisk,
		DiskUsedPct:     usedPct,
		ActiveTransfers: active,
		InSpeedBps:      a.lastSpeedBps.Load(),
	}
	body, _ := json.Marshal(payload)
	u := strings.TrimRight(a.cfg.CenterURL, "/") + "/api/v1/b/heartbeat"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(protocol.HeaderNodeID, a.cfg.NodeID)
	req.Header.Set(protocol.HeaderNodeToken, a.cfg.CenterToken)

	resp, err := a.apiClient.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

func (p *activeProgress) setTransferred(total int64) {
	p.mu.Lock()
	p.info.TransferredBytes = total
	p.mu.Unlock()
}

func (p *activeProgress) addBytes(total, delta int64) {
	p.mu.Lock()
	p.info.TransferredBytes = total
	p.windowBytes += delta
	elapsed := time.Since(p.windowStart).Seconds()
	if elapsed >= 1.0 {
		p.info.SpeedBps = int64(float64(p.windowBytes) / elapsed)
		p.windowBytes = 0
		p.windowStart = time.Now()
	}
	p.mu.Unlock()
}

func (p *activeProgress) snapshot() protocol.BActiveTransfer {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.info
}

func resolveTargetPath(destDir, relFilename, conflictPolicy, fileID string) (string, bool, error) {
	target, err := transfer.SafeJoin(destDir, relFilename)
	if err != nil {
		return "", false, err
	}
	if conflictPolicy == "" || conflictPolicy == protocol.ConflictOverwrite {
		return target, false, nil
	}
	if _, err := os.Stat(target); errors.Is(err, os.ErrNotExist) {
		return target, false, nil
	}
	if conflictPolicy == protocol.ConflictSkip {
		return target, true, nil
	}
	// auto_rename fallback
	ext := filepath.Ext(target)
	stem := strings.TrimSuffix(target, ext)
	suffix := fileID
	if len(suffix) > 8 {
		suffix = suffix[:8]
	}
	return fmt.Sprintf("%s_%s%s", stem, suffix, ext), false, nil
}
