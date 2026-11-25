package agentb

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"relay-download/internal/pki"
	"relay-download/internal/protocol"
	"relay-download/internal/transfer"
	"relay-download/internal/updater"
	"relay-download/internal/version"
)

type activeProgress struct {
	mu          sync.Mutex
	info        protocol.BActiveTransfer
	windowBytes int64
	windowStart time.Time
}

type cachedDiscover struct {
	resp      *protocol.DiscoverResp
	expiresAt time.Time
}

type Agent struct {
	cfg            *Config
	store          *Store
	logger         *slog.Logger
	apiClient      *http.Client
	sseClient      *http.Client
	streamMu       sync.RWMutex
	streamClients  []*http.Client
	makeStreamCli  func() *http.Client
	streamIdx      atomic.Uint64
	limiter        *transfer.RateLimiter

	workSem   chan struct{}
	streamSem chan struct{}
	wakeupCh  chan string
	ackWakeCh chan struct{}
	hbWakeCh  chan struct{}
	updater   *updater.Updater

	discMu    sync.Mutex
	discCache map[string]cachedDiscover

	mu       sync.RWMutex
	progress map[string]*activeProgress

	inBytes         atomic.Int64
	lastSpeedBps    atomic.Int64
	pendingAckCount atomic.Int64

	// Optional metrics & test hooks.
	ResumeCount        atomic.Int64
	UpgradeExePath     string
	UpgradeRestartHook func(targetVersion string)

	runMu     sync.Mutex
	runCancel context.CancelFunc
	commitMu  sync.Mutex
	wg        sync.WaitGroup
	bgWG      sync.WaitGroup
}

func New(cfg *Config, logger *slog.Logger) (*Agent, error) {
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}

	for _, proj := range cfg.ProjectIDs() {
		for _, dir := range cfg.DestDirsFor(proj) {
			if err := os.MkdirAll(filepath.Join(dir, ".relay_tmp"), 0o755); err != nil {
				return nil, fmt.Errorf("init dest dir for project %s (%s): %w", proj, dir, err)
			}
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

	makeAPITransport := func() *http.Transport {
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

	makeH2StreamClient := func() *http.Client {
		return &http.Client{
			// No overall Timeout on streaming/SSE client; bounded by ctx cancellation.
			Transport: &http.Transport{
				TLSClientConfig:     clientTLS.Clone(),
				ForceAttemptHTTP2:   true,
				MaxIdleConns:        8,
				MaxIdleConnsPerHost: 4,
				IdleConnTimeout:     90 * time.Second,
				TLSHandshakeTimeout: 10 * time.Second,
				ReadBufferSize:      256 << 10,
				WriteBufferSize:     64 << 10,
				HTTP2: &http.HTTP2Config{
					MaxReadFrameSize:              512 << 10,
					MaxReceiveBufferPerConnection: 2 << 20,
					MaxReceiveBufferPerStream:     2 << 20,
				},
			},
		}
	}

	var (
		streamClients []*http.Client
		makeStreamCli func() *http.Client
	)
	if cfg.StreamProtocol == "h1" {
		// Strict TLS 1.3 + HTTP/1.1 data-plane transport: eliminates HTTP/2's 4MiB flow-control cap
		// and frame-copy overhead so each TCP socket rides the full 64MiB kernel TCP/BBR window for 10Gbps.
		poolSize := cfg.MaxTotalStreams
		if cfg.StreamConns > poolSize {
			poolSize = cfg.StreamConns
		}
		if poolSize < 64 {
			poolSize = 64
		}
		shards := 1
		if cfg.StreamConnMaxAgeSec > 0 {
			shards = 8
		}
		perShardPool := (poolSize + shards - 1) / shards
		if perShardPool < 16 {
			perShardPool = 16
		}
		idleTimeout := 90 * time.Second
		if cfg.StreamConnMaxAgeSec > 0 {
			idleTimeout = time.Duration(cfg.StreamConnMaxAgeSec) * time.Second
			if idleTimeout < 5*time.Second {
				idleTimeout = 5 * time.Second
			}
		}
		makeStreamCli = func() *http.Client {
			h1TLS := clientTLS.Clone()
			h1TLS.NextProtos = []string{"http/1.1"}
			return &http.Client{
				Transport: &http.Transport{
					TLSClientConfig:     h1TLS,
					ForceAttemptHTTP2:   false,
					TLSNextProto:        make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
					MaxIdleConns:        perShardPool,
					MaxIdleConnsPerHost: perShardPool,
					IdleConnTimeout:     idleTimeout,
					TLSHandshakeTimeout: 10 * time.Second,
					ReadBufferSize:      1 << 20,
					WriteBufferSize:     256 << 10,
				},
			}
		}
		streamClients = make([]*http.Client, shards)
		for i := range streamClients {
			streamClients[i] = makeStreamCli()
		}
	} else {
		makeStreamCli = makeH2StreamClient
		streamClients = make([]*http.Client, cfg.StreamConns)
		for i := range streamClients {
			streamClients[i] = makeStreamCli()
		}
	}

	var limiter *transfer.RateLimiter
	if cfg.RateLimitMBps > 0 {
		limiter = transfer.NewRateLimiter(int64(cfg.RateLimitMBps * 1024 * 1024))
	}

	ag := &Agent{
		cfg:     cfg,
		store:   store,
		logger:  logger.With("component", "agent-b", "node_id", cfg.NodeID),
		limiter: limiter,
		apiClient: &http.Client{
			Timeout:   20 * time.Second,
			Transport: makeAPITransport(),
		},
		sseClient:     makeH2StreamClient(),
		streamClients: streamClients,
		makeStreamCli: makeStreamCli,
		workSem:       make(chan struct{}, cfg.MaxConcurrent),
		streamSem:     make(chan struct{}, cfg.MaxTotalStreams),
		wakeupCh:      make(chan string, 256),
		ackWakeCh:     make(chan struct{}, 1),
		hbWakeCh:      make(chan struct{}, 1),
		discCache:     make(map[string]cachedDiscover),
		progress:      make(map[string]*activeProgress),
	}
	ag.updater = updater.New(updater.Options{
		Component:    "relay-agent-b",
		NodeID:       cfg.NodeID,
		CenterURL:    cfg.CenterURL,
		CenterToken:  cfg.CenterToken,
		HTTPClient:   ag.sseClient,
		Logger:       ag.logger,
		OnStatusSync: ag.triggerHeartbeat,
		OnRestart: func(targetVer string) {
			if ag.UpgradeRestartHook != nil {
				ag.UpgradeRestartHook(targetVer)
				return
			}
			ag.runMu.Lock()
			cancel := ag.runCancel
			ag.runMu.Unlock()
			if cancel != nil {
				cancel()
			}
		},
	})
	return ag, nil
}

func (a *Agent) nextStreamClient() *http.Client {
	a.streamMu.RLock()
	n := uint64(len(a.streamClients))
	if n == 0 {
		a.streamMu.RUnlock()
		return a.sseClient
	}
	idx := a.streamIdx.Add(1) - 1
	cli := a.streamClients[idx%n]
	a.streamMu.RUnlock()
	return cli
}

// streamRotateLoop staggered-rotates data-plane HTTP transports so no single TCP socket
// stays alive long enough to trigger cross-border ISP per-flow QoS policing, without
// ever interrupting in-flight downloads (retired transports drain via CloseIdleConnections).
func (a *Agent) streamRotateLoop(ctx context.Context) {
	a.streamMu.RLock()
	shards := len(a.streamClients)
	a.streamMu.RUnlock()
	if shards == 0 || a.cfg.StreamConnMaxAgeSec <= 0 || a.makeStreamCli == nil {
		return
	}
	maxAge := time.Duration(a.cfg.StreamConnMaxAgeSec) * time.Second
	step := maxAge / time.Duration(shards)
	if step < 250*time.Millisecond {
		step = 250 * time.Millisecond
	}
	ticker := time.NewTicker(step)
	defer ticker.Stop()

	nextShard := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fresh := a.makeStreamCli()
			a.streamMu.Lock()
			idx := nextShard % len(a.streamClients)
			old := a.streamClients[idx]
			a.streamClients[idx] = fresh
			a.streamMu.Unlock()
			nextShard++

			if old != nil {
				if tr, ok := old.Transport.(*http.Transport); ok {
					tr.CloseIdleConnections()
					// Sweep again after in-flight requests on the retired shard finish so
					// aged sockets never sit open until IdleConnTimeout.
					for _, delay := range []time.Duration{3 * time.Second, 10 * time.Second, 25 * time.Second} {
						time.AfterFunc(delay, tr.CloseIdleConnections)
					}
				}
			}
		}
	}
}

func (a *Agent) Start(ctx context.Context) error {
	if a.UpgradeExePath != "" {
		a.updater = updater.New(updater.Options{
			Component:    "relay-agent-b",
			NodeID:       a.cfg.NodeID,
			CenterURL:    a.cfg.CenterURL,
			CenterToken:  a.cfg.CenterToken,
			HTTPClient:   a.sseClient,
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

	defer func() {
		runCancel()
		a.bgWG.Wait()
		a.wg.Wait()
		// Best-effort final flush of already-landed ACKs on graceful shutdown.
		flCtx, flCancel := context.WithTimeout(context.Background(), 3*time.Second)
		a.flushPendingAcks(flCtx)
		flCancel()
		_ = a.store.Close()
	}()

	// Resume any downloads persisted before a process restart.
	a.resumePersistedDownloads(runCtx)

	launchBG := func(fn func(context.Context)) {
		a.bgWG.Add(1)
		go func() {
			defer a.bgWG.Done()
			fn(runCtx)
		}()
	}
	launchBG(a.speedMeterLoop)
	launchBG(a.heartbeatLoop)
	launchBG(a.ackFlushLoop)
	launchBG(a.sseLoop)
	launchBG(a.dispatchLoop)
	if a.cfg.StreamConnMaxAgeSec > 0 {
		launchBG(a.streamRotateLoop)
	}

	<-runCtx.Done()
	return nil
}

func (a *Agent) triggerHeartbeat() {
	select {
	case a.hbWakeCh <- struct{}{}:
	default:
	}
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
		connected, err := a.consumeSSE(ctx, u)
		if ctx.Err() != nil {
			return
		}
		if connected {
			backoff = 500 * time.Millisecond
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

func (a *Agent) consumeSSE(ctx context.Context, sseURL string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sseURL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set(protocol.HeaderNodeID, a.cfg.NodeID)
	req.Header.Set(protocol.HeaderNodeToken, a.cfg.CenterToken)

	resp, err := a.sseClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("SSE returned HTTP %d", resp.StatusCode)
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
	return true, scanner.Err()
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
			if len(a.cfg.DestDirsFor(proj)) > 0 {
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

func (a *Agent) invalidateDiscover(projectID string) {
	a.discMu.Lock()
	delete(a.discCache, projectID)
	a.discMu.Unlock()
}

func (a *Agent) discoverCached(ctx context.Context, projectID string) (*protocol.DiscoverResp, error) {
	a.discMu.Lock()
	if ent, ok := a.discCache[projectID]; ok && time.Now().Before(ent.expiresAt) && ent.resp != nil && len(ent.resp.Candidates) > 0 {
		resp := ent.resp
		a.discMu.Unlock()
		return resp, nil
	}
	a.discMu.Unlock()

	disc, err := a.discover(ctx, projectID)
	if err != nil {
		return nil, err
	}
	if len(disc.Candidates) > 0 {
		a.discMu.Lock()
		a.discCache[projectID] = cachedDiscover{
			resp:      disc,
			expiresAt: time.Now().Add(10 * time.Second),
		}
		a.discMu.Unlock()
	}
	return disc, nil
}

// mediaAffinityKey strips compound metadata suffixes (like .info.json) or the last extension
// so paired files for the same asset (e.g. <video_id>.opus and <video_id>.info.json) hash
// to the same destination disk when multi-disk placement is enabled.
func mediaAffinityKey(filename string) string {
	base := filepath.Base(filename)
	lower := strings.ToLower(base)
	for _, suffix := range []string{".info.json", ".meta.json", ".tar.gz", ".tar.zst"} {
		if strings.HasSuffix(lower, suffix) && len(base) > len(suffix) {
			return base[:len(base)-len(suffix)]
		}
	}
	ext := filepath.Ext(base)
	if ext != "" && len(base) > len(ext) {
		return base[:len(base)-len(ext)]
	}
	return base
}

func (a *Agent) chooseDestDir(projectID, filename string, fileSize int64) string {
	dirs := a.cfg.DestDirsFor(projectID)
	if len(dirs) == 0 {
		return ""
	}
	if len(dirs) == 1 {
		return dirs[0]
	}

	h := fnv.New32a()
	_, _ = h.Write([]byte(mediaAffinityKey(filename)))
	primaryIdx := int(h.Sum32() % uint32(len(dirs)))
	need := uint64(0)
	if fileSize > 0 {
		need = uint64(fileSize)
	}
	if a.availableDiskFor(dirs[primaryIdx]) >= need && (a.cfg.MinFreeDiskBytes == 0 || a.availableDiskFor(dirs[primaryIdx]) > 0) {
		return dirs[primaryIdx]
	}
	// Spill over to whichever configured disk currently has the most free space.
	bestDir := dirs[primaryIdx]
	var bestFree uint64
	for _, d := range dirs {
		free := a.availableDiskFor(d)
		if free > bestFree {
			bestFree = free
			bestDir = d
		}
	}
	return bestDir
}

func (a *Agent) availableDiskForProject(projectID string) uint64 {
	var best uint64
	for _, dir := range a.cfg.DestDirsFor(projectID) {
		if free := a.availableDiskFor(dir); free > best {
			best = free
		}
	}
	return best
}

func (a *Agent) scanProject(ctx context.Context, projectID string) {
	dirs := a.cfg.DestDirsFor(projectID)
	if len(dirs) == 0 {
		return
	}
	if len(a.workSem) >= cap(a.workSem) {
		return
	}

	disc, err := a.discoverCached(ctx, projectID)
	if err != nil {
		a.logger.Warn("discover failed", "project", projectID, "err", err)
		return
	}
	if len(disc.Candidates) == 0 {
		return
	}

	claimedAny := false
	for _, cand := range disc.Candidates {
		for {
			if ctx.Err() != nil {
				return
			}
			// Reserve up to ClaimBatchSize worker slots upfront without blocking.
			reserved := 0
			for reserved < a.cfg.ClaimBatchSize {
				select {
				case a.workSem <- struct{}{}:
					reserved++
				default:
					goto reservedDone
				}
			}
		reservedDone:
			if reserved == 0 {
				return
			}
			releaseSlots := func(n int) {
				for i := 0; i < n; i++ {
					<-a.workSem
				}
			}

			availDisk := a.availableDiskForProject(projectID)
			if availDisk == 0 && a.cfg.MinFreeDiskBytes > 0 {
				releaseSlots(reserved)
				a.logger.Warn("insufficient local disk space, skipping claim", "project", projectID, "dest_dirs", dirs)
				return
			}

			claimed, status, err := a.claimBatchFromA(ctx, cand, projectID, availDisk, disc.LeaseTTLSec, reserved)
			if err != nil {
				releaseSlots(reserved)
				a.invalidateDiscover(projectID)
				a.logger.Warn("claim from agent-a failed", "a_node", cand.ANodeID, "err", err)
				break
			}
			if status == http.StatusNoContent || len(claimed) == 0 {
				releaseSlots(reserved)
				break // No more ready files on this A node; try next candidate.
			}
			if status == http.StatusUnauthorized {
				releaseSlots(reserved)
				a.invalidateDiscover(projectID)
				break // JWT expired; next scan will refresh.
			}

			// Return any unused pre-reserved slots immediately.
			if len(claimed) < reserved {
				releaseSlots(reserved - len(claimed))
			}

			claimedAny = true
			dls := make([]ActiveDownload, 0, len(claimed))
			for _, cr := range claimed {
				destDir := a.chooseDestDir(projectID, cr.Filename, cr.Size)
				partPath := filepath.Join(destDir, ".relay_tmp", cr.FileID+".part")
				dls = append(dls, ActiveDownload{
					FileID:         cr.FileID,
					ProjectID:      projectID,
					ANodeID:        cand.ANodeID,
					PublicAddr:     cand.PublicAddr,
					Filename:       cr.Filename,
					Size:           cr.Size,
					SHA256:         cr.SHA256,
					LeaseID:        cr.LeaseID,
					LeaseToken:     cr.LeaseToken,
					LeaseExpiresAt: cr.LeaseExpiresAt,
					LeaseTTLSec:    disc.LeaseTTLSec,
					ConflictPolicy: disc.ConflictPolicy,
					DestDir:        destDir,
					PartPath:       partPath,
					StartedAt:      time.Now().UTC(),
				})
			}

			if err := a.store.PutActiveBatch(dls); err != nil {
				releaseSlots(len(dls))
				a.logger.Error("persist active batch failed", "count", len(dls), "err", err)
				for _, dl := range dls {
					_ = a.sendNack(ctx, dl, "local state persist failed")
				}
				return
			}

			for _, dl := range dls {
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

			if len(claimed) < reserved {
				// This candidate has no more immediately claimable files.
				break
			}
		}
	}
	if !claimedAny {
		// All cached candidates were empty -> clear cache so next poll/wakeup sees fresh A nodes.
		a.invalidateDiscover(projectID)
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

func (a *Agent) claimBatchFromA(ctx context.Context, cand protocol.DiscoverCandidate, projectID string, availDisk uint64, leaseTTLSec, maxCount int) ([]protocol.ClaimResp, int, error) {
	if maxCount <= 1 {
		cr, status, err := a.claimFromA(ctx, cand, projectID, availDisk, leaseTTLSec)
		if err != nil || cr == nil {
			return nil, status, err
		}
		return []protocol.ClaimResp{*cr}, status, nil
	}
	body, _ := json.Marshal(protocol.ClaimBatchReq{
		ProjectID:          projectID,
		BNodeID:            a.cfg.NodeID,
		AvailableDiskBytes: availDisk,
		LeaseTTLSec:        leaseTTLSec,
		MaxCount:           maxCount,
	})
	u := strings.TrimRight(cand.PublicAddr, "/") + "/api/v1/claim-batch"
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

	// Graceful compatibility fallback for older v1.0 Agent A nodes that only expose /api/v1/claim.
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
		cr, status, err := a.claimFromA(ctx, cand, projectID, availDisk, leaseTTLSec)
		if err != nil || cr == nil {
			return nil, status, err
		}
		return []protocol.ClaimResp{*cr}, status, nil
	}
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusUnauthorized {
		return nil, resp.StatusCode, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("claim-batch returned HTTP %d", resp.StatusCode)
	}
	var out protocol.ClaimBatchResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, resp.StatusCode, err
	}
	return out.Items, http.StatusOK, nil
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

	chunkThreshold := int64(a.cfg.ChunkThresholdMB) << 20
	useChunked := a.cfg.ChunkConcurrency > 1 && dl.Size > 0 && dl.Size >= chunkThreshold
	bitmapPath := dl.PartPath + ".bitmap"
	if useChunked {
		// If a prior single-stream partial file exists WITHOUT a chunk bitmap, preserve single-stream resume compatibility.
		if st, err := os.Stat(dl.PartPath); err == nil && st.Size() > 0 && st.Size() < dl.Size {
			if _, bmErr := os.Stat(bitmapPath); errors.Is(bmErr, os.ErrNotExist) {
				useChunked = false
			}
		}
	}

	if useChunked {
		pipelinedSHA, statusCode, chunkErr := a.downloadChunked(ctx, dl, prog)
		if chunkErr != nil {
			if ctx.Err() != nil {
				// Preserve .part and .part.bitmap so restart resumes only unfinished chunks!
				return
			}
			if statusCode == http.StatusConflict || statusCode == http.StatusNotFound || statusCode == http.StatusGone {
				a.logger.Warn("lease expired or file gone on A during chunked download, abandoning", "file_id", dl.FileID, "status", statusCode)
				_ = os.Remove(dl.PartPath)
				_ = os.Remove(bitmapPath)
				_ = a.store.DeleteActive(dl.FileID)
				return
			}
			a.logger.Warn("chunked download failed, falling back to resumable single-stream", "file_id", dl.FileID, "err", chunkErr)
			_ = os.Remove(dl.PartPath)
			_ = os.Remove(bitmapPath)
			useChunked = false
		} else {
			if pipelinedSHA != "" {
				continuousSHA = pipelinedSHA
			}
			_ = os.Remove(bitmapPath)
		}
	}

	for !useChunked {
		if ctx.Err() != nil {
			// Keep .part and BoltDB record intact so next startup can resume!
			return
		}
		var (
			offset     int64
			partExists bool
		)
		if st, err := os.Stat(dl.PartPath); err == nil {
			partExists = true
			offset = st.Size()
			if offset > dl.Size {
				_ = os.Truncate(dl.PartPath, 0)
				offset = 0
			}
		}
		prog.setTransferred(offset)

		if partExists && offset == dl.Size {
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

	// Safe atomic commit into project destination directory (serialized to prevent conflict-policy TOCTOU).
	a.commitMu.Lock()
	targetPath, skipCommit, err := resolveTargetPath(dl.DestDir, dl.Filename, dl.ConflictPolicy, dl.FileID)
	if err != nil {
		a.commitMu.Unlock()
		a.logger.Error("invalid target path", "file_id", dl.FileID, "filename", dl.Filename, "err", err)
		_ = os.Remove(dl.PartPath)
		_ = a.store.DeleteActive(dl.FileID)
		_ = a.sendNack(ctx, dl, "invalid path")
		return
	}
	if skipCommit {
		_ = os.Remove(dl.PartPath)
		a.commitMu.Unlock()
	} else {
		if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
			a.commitMu.Unlock()
			a.logger.Error("mkdir target parent failed", "err", err)
			_ = os.Remove(dl.PartPath)
			_ = a.store.DeleteActive(dl.FileID)
			_ = a.sendNack(ctx, dl, "mkdir target failed")
			return
		}
		if err := os.Chmod(dl.PartPath, 0o644); err != nil {
			a.logger.Warn("chmod target part file failed", "path", dl.PartPath, "err", err)
		}
		if err := os.Rename(dl.PartPath, targetPath); err != nil {
			a.commitMu.Unlock()
			a.logger.Error("atomic rename failed", "src", dl.PartPath, "dst", targetPath, "err", err)
			_ = os.Remove(dl.PartPath)
			_ = a.store.DeleteActive(dl.FileID)
			_ = a.sendNack(ctx, dl, "rename failed")
			return
		}
		a.commitMu.Unlock()
	}

	ack := PendingAck{
		FileID:     dl.FileID,
		ANodeID:    dl.ANodeID,
		PublicAddr: dl.PublicAddr,
		LeaseID:    dl.LeaseID,
		LeaseToken: dl.LeaseToken,
		SHA256:     actualSHA,
		DurationMs: time.Since(startTime).Milliseconds(),
		DestDir:    filepath.Dir(targetPath),
		CreatedAt:  time.Now().UTC(),
	}
	_ = a.store.CompleteActiveAndQueueAck(dl.FileID, ack)
	if a.cfg.AckBatchIntervalMs <= 0 {
		if !skipCommit {
			_ = transfer.SyncDir(filepath.Dir(targetPath))
		}
		if err := a.sendAck(ctx, ack); err == nil {
			_ = a.store.DeletePendingAck(ack.FileID)
		} else {
			a.logger.Warn("immediate ACK failed, queued for retry", "file_id", dl.FileID, "err", err)
			a.triggerAckFlush()
		}
	} else {
		if a.pendingAckCount.Add(1) >= int64(a.cfg.AckBatchSize) {
			a.triggerAckFlush()
		}
	}

	a.logger.Info("download verified and committed", "file_id", dl.FileID, "project", dl.ProjectID, "target", targetPath, "size", dl.Size)
}

const chunkBitmapHeaderSize = 24

var chunkBitmapMagic = [8]byte{'R', 'C', 'H', 'K', '0', '0', '0', '1'}

// effectiveChunkSize adapts chunk size cleanly across KB..hundreds-of-GB file sizes so
// multi-100GB files keep sequential disk writes and tiny (<10KB) resume bitmaps.
func effectiveChunkSize(fileSize int64, baseMB int) int64 {
	base := int64(baseMB) << 20
	if base <= 0 {
		base = 4 << 20
	}
	switch {
	case fileSize >= 4<<30 && base < 32<<20:
		return 32 << 20 // >= 4 GiB (up to 100s of GiB): 32 MiB chunks
	case fileSize >= 256<<20 && base < 16<<20:
		return 16 << 20 // 256 MiB .. 4 GiB: 16 MiB chunks
	default:
		return base
	}
}

type chunkBitmap struct {
	mu   sync.Mutex
	f    *os.File
	bits []byte
}

func openOrInitChunkBitmap(partPath, bitmapPath string, fileSize, chunkSize int64, numChunks int) (*os.File, *chunkBitmap, bool, error) {
	bitBytes := (numChunks + 7) / 8
	expectedBMSize := int64(chunkBitmapHeaderSize + bitBytes)

	// Try resuming from existing pre-sized .part + matching .bitmap.
	if pSt, pErr := os.Stat(partPath); pErr == nil && pSt.Size() == fileSize {
		if raw, bErr := os.ReadFile(bitmapPath); bErr == nil && int64(len(raw)) == expectedBMSize {
			if bytes.Equal(raw[:8], chunkBitmapMagic[:]) &&
				int64(binary.BigEndian.Uint64(raw[8:16])) == fileSize &&
				int64(binary.BigEndian.Uint64(raw[16:24])) == chunkSize {
				pf, err := os.OpenFile(partPath, os.O_RDWR, 0o644)
				if err == nil {
					bf, bOpenErr := os.OpenFile(bitmapPath, os.O_RDWR, 0o644)
					if bOpenErr == nil {
						bits := make([]byte, bitBytes)
						copy(bits, raw[chunkBitmapHeaderSize:])
						return pf, &chunkBitmap{f: bf, bits: bits}, true, nil
					}
					_ = pf.Close()
				}
			}
		}
	}

	// Fresh chunked download: create pre-sized .part and zeroed .bitmap header.
	pf, err := os.OpenFile(partPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, nil, false, err
	}
	if err := pf.Truncate(fileSize); err != nil {
		_ = pf.Close()
		return nil, nil, false, err
	}
	bf, err := os.OpenFile(bitmapPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o644)
	if err != nil {
		_ = pf.Close()
		return nil, nil, false, err
	}
	initBuf := make([]byte, expectedBMSize)
	copy(initBuf[:8], chunkBitmapMagic[:])
	binary.BigEndian.PutUint64(initBuf[8:16], uint64(fileSize))
	binary.BigEndian.PutUint64(initBuf[16:24], uint64(chunkSize))
	if _, err := bf.WriteAt(initBuf, 0); err != nil {
		_ = bf.Close()
		_ = pf.Close()
		return nil, nil, false, err
	}
	return pf, &chunkBitmap{f: bf, bits: make([]byte, bitBytes)}, false, nil
}

func (cb *chunkBitmap) isDone(idx int) bool {
	cb.mu.Lock()
	done := (cb.bits[idx/8] & (1 << uint(idx%8))) != 0
	cb.mu.Unlock()
	return done
}

func (cb *chunkBitmap) markDone(idx int) {
	cb.mu.Lock()
	bIdx := idx / 8
	cb.bits[bIdx] |= 1 << uint(idx%8)
	val := [1]byte{cb.bits[bIdx]}
	_, _ = cb.f.WriteAt(val[:], int64(chunkBitmapHeaderSize+bIdx))
	cb.mu.Unlock()
}

func (cb *chunkBitmap) close() {
	if cb != nil && cb.f != nil {
		_ = cb.f.Sync()
		_ = cb.f.Close()
	}
}

func (a *Agent) downloadChunked(ctx context.Context, dl ActiveDownload, prog *activeProgress) (string, int, error) {
	chunkSize := effectiveChunkSize(dl.Size, a.cfg.ChunkSizeMB)
	numChunks := int((dl.Size + chunkSize - 1) / chunkSize)
	bitmapPath := dl.PartPath + ".bitmap"

	f, bm, resumed, err := openOrInitChunkBitmap(dl.PartPath, bitmapPath, dl.Size, chunkSize, numChunks)
	if err != nil {
		return "", 0, err
	}
	defer bm.close()

	type byteRange struct {
		idx   int
		start int64
		end   int64
	}

	var (
		completedBytes atomic.Int64
		pendingCount   int
	)
	for i := 0; i < numChunks; i++ {
		start := int64(i) * chunkSize
		end := start + chunkSize - 1
		if end >= dl.Size {
			end = dl.Size - 1
		}
		if bm.isDone(i) {
			completedBytes.Add(end - start + 1)
		} else {
			pendingCount++
		}
	}
	if resumed && completedBytes.Load() > 0 {
		prog.setTransferred(completedBytes.Load())
		a.ResumeCount.Add(1)
		a.logger.Info("resuming chunked download from bitmap", "file_id", dl.FileID, "done_bytes", completedBytes.Load(), "total_bytes", dl.Size, "pending_chunks", pendingCount)
	}
	if pendingCount == 0 {
		if err := f.Sync(); err != nil {
			_ = f.Close()
			return "", 0, err
		}
		if err := f.Close(); err != nil {
			return "", 0, err
		}
		return "", http.StatusOK, nil
	}

	chunkCtx, cancelChunks := context.WithCancel(ctx)
	defer cancelChunks()

	// Pipelined prefix SHA256 hasher (for fresh downloads): hashes completed sequential prefix chunks
	// while they are still hot in Linux page cache, avoiding a full 2x disk re-read on 100s-of-GB files!
	var (
		hashCh       chan int
		hashDone     chan struct{}
		pipelinedSHA string
		hashErr      error
	)
	if !resumed {
		chCap := numChunks
		if chCap > 256 {
			chCap = 256
		}
		hashCh = make(chan int, chCap)
		hashDone = make(chan struct{})
		go func() {
			defer close(hashDone)
			ready := make([]bool, numChunks)
			nextIdx := 0
			h := sha256.New()
			bufPtr := transfer.GetBuf()
			defer transfer.PutBuf(bufPtr)
			buf := *bufPtr

			for idx := range hashCh {
				ready[idx] = true
				for nextIdx < numChunks && ready[nextIdx] {
					if chunkCtx.Err() != nil {
						return
					}
					st := int64(nextIdx) * chunkSize
					ln := chunkSize
					if st+ln > dl.Size {
						ln = dl.Size - st
					}
					sr := io.NewSectionReader(f, st, ln)
					if _, err := io.CopyBuffer(h, sr, buf); err != nil {
						hashErr = err
						return
					}
					nextIdx++
				}
			}
			if nextIdx == numChunks && hashErr == nil {
				pipelinedSHA = hex.EncodeToString(h.Sum(nil))
			}
		}()
	}

	workers := a.cfg.ChunkConcurrency
	if workers > pendingCount {
		workers = pendingCount
	}

	// Bounded channel fed lazily so even a multi-TB file uses O(1) memory.
	jobs := make(chan byteRange, workers*2)
	go func() {
		defer close(jobs)
		for i := 0; i < numChunks; i++ {
			if bm.isDone(i) {
				continue
			}
			start := int64(i) * chunkSize
			end := start + chunkSize - 1
			if end >= dl.Size {
				end = dl.Size - 1
			}
			select {
			case jobs <- byteRange{idx: i, start: start, end: end}:
			case <-chunkCtx.Done():
				return
			}
		}
	}()

	var (
		firstErrMu  sync.Mutex
		firstErr    error
		firstStatus int
		wg          sync.WaitGroup
	)
	recordErr := func(status int, err error) {
		firstErrMu.Lock()
		if firstErr == nil {
			firstErr = err
			firstStatus = status
		}
		firstErrMu.Unlock()
		cancelChunks()
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for rg := range jobs {
				if chunkCtx.Err() != nil {
					return
				}
				status, err := a.fetchRangeWithRetry(chunkCtx, dl, f, rg.start, rg.end, prog, &completedBytes)
				if err != nil {
					recordErr(status, err)
					return
				}
				bm.markDone(rg.idx)
				if hashCh != nil {
					select {
					case hashCh <- rg.idx:
					case <-chunkCtx.Done():
					case <-hashDone:
					}
				}
			}
		}()
	}
	wg.Wait()
	if hashCh != nil {
		close(hashCh)
		<-hashDone
	}

	if firstErr != nil {
		_ = f.Sync()
		_ = f.Close()
		return "", firstStatus, firstErr
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return "", 0, err
	}
	if err := f.Close(); err != nil {
		return "", 0, err
	}
	if hashErr != nil {
		// Fall back safely to post-download full-file HashFile in runDownload.
		pipelinedSHA = ""
	}
	return pipelinedSHA, http.StatusOK, nil
}

func (a *Agent) fetchRangeWithRetry(ctx context.Context, dl ActiveDownload, f *os.File, start, end int64, prog *activeProgress, completedBytes *atomic.Int64) (int, error) {
	u := strings.TrimRight(dl.PublicAddr, "/") + "/api/v1/files/" + url.PathEscape(dl.FileID) + "/stream"
	cur := start
	backoff := 200 * time.Millisecond

	for attempt := 0; attempt < 8; attempt++ {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		select {
		case a.streamSem <- struct{}{}:
		case <-ctx.Done():
			return 0, ctx.Err()
		}

		// Per-attempt stall & slow-flow watchdog: if a single WAN TCP flow stalls for >12s
		// OR degrades below 150 KB/s after 10s (ISP per-flow policer), abort this range attempt
		// and immediately retry on a fresh TCP socket from the rotated pool.
		reqCtx, reqCancel := context.WithCancel(ctx)
		attemptStart := time.Now()
		var lastActivity atomic.Int64
		var attemptBytes atomic.Int64
		lastActivity.Store(attemptStart.UnixNano())
		watchDone := make(chan struct{})
		go func() {
			t := time.NewTicker(3 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-watchDone:
					return
				case <-reqCtx.Done():
					return
				case <-t.C:
					if time.Since(time.Unix(0, lastActivity.Load())) > 12*time.Second {
						reqCancel()
						return
					}
					if a.limiter == nil {
						if elapsed := time.Since(attemptStart); elapsed > 10*time.Second {
							if float64(attemptBytes.Load())/elapsed.Seconds() < 150*1024 {
								reqCancel()
								return
							}
						}
					}
				}
			}
		}()

		written, status, streamErr := a.streamRangeOnce(reqCtx, u, dl.LeaseToken, f, cur, end, prog, completedBytes, &lastActivity, &attemptBytes)
		close(watchDone)
		reqCancel()
		<-a.streamSem

		cur += written
		if streamErr == nil && cur > end {
			return http.StatusPartialContent, nil
		}
		if status == http.StatusConflict || status == http.StatusNotFound || status == http.StatusGone {
			return status, streamErr
		}
		if written > 0 {
			backoff = 200 * time.Millisecond
			if attempt > 0 {
				attempt-- // made forward progress -> don't burn retry budget
			}
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return 0, ctx.Err()
		case <-timer.C:
		}
		backoff *= 2
		if backoff > 3*time.Second {
			backoff = 3 * time.Second
		}
	}
	return 0, fmt.Errorf("range %d-%d exhausted retries at offset %d", start, end, cur)
}

func (a *Agent) streamRangeOnce(ctx context.Context, streamURL, leaseToken string, f *os.File, start, end int64, prog *activeProgress, completedBytes *atomic.Int64, lastActivity *atomic.Int64, attemptBytes *atomic.Int64) (int64, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, streamURL, nil)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set(protocol.HeaderLeaseToken, leaseToken)
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))

	resp, err := a.nextStreamClient().Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusPartialContent && !(start == 0 && resp.StatusCode == http.StatusOK) {
		return 0, resp.StatusCode, fmt.Errorf("range stream returned HTTP %d", resp.StatusCode)
	}

	bufPtr := transfer.GetBuf()
	defer transfer.PutBuf(bufPtr)
	buf := *bufPtr

	want := end - start + 1
	var written int64
	for written < want {
		if err := ctx.Err(); err != nil {
			return written, resp.StatusCode, err
		}
		toRead := len(buf)
		if rem := want - written; int64(toRead) > rem {
			toRead = int(rem)
		}
		nr, rErr := resp.Body.Read(buf[:toRead])
		if nr > 0 {
			lastActivity.Store(time.Now().UnixNano())
			if a.limiter != nil {
				if err := a.limiter.Wait(ctx, nr); err != nil {
					return written, resp.StatusCode, err
				}
			}
			nw, wErr := f.WriteAt(buf[:nr], start+written)
			if nw > 0 {
				written += int64(nw)
				attemptBytes.Add(int64(nw))
				a.inBytes.Add(int64(nw))
				tot := completedBytes.Add(int64(nw))
				prog.addBytes(tot, int64(nw))
			}
			if wErr != nil {
				return written, resp.StatusCode, wErr
			}
			if nw != nr {
				return written, resp.StatusCode, io.ErrShortWrite
			}
		}
		if rErr == io.EOF {
			if written < want {
				return written, resp.StatusCode, io.ErrUnexpectedEOF
			}
			return written, resp.StatusCode, nil
		}
		if rErr != nil {
			return written, resp.StatusCode, rErr
		}
	}
	return written, resp.StatusCode, nil
}

func (a *Agent) streamOnce(ctx context.Context, dl ActiveDownload, offset int64, prog *activeProgress) (written int64, shaFromZero string, statusCode int, err error) {
	select {
	case a.streamSem <- struct{}{}:
		defer func() { <-a.streamSem }()
	case <-ctx.Done():
		return 0, "", 0, ctx.Err()
	}

	reqCtx, reqCancel := context.WithCancel(ctx)
	defer reqCancel()
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())
	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-watchDone:
				return
			case <-reqCtx.Done():
				return
			case <-t.C:
				if time.Since(time.Unix(0, lastActivity.Load())) > 20*time.Second {
					reqCancel()
					return
				}
			}
		}
	}()

	u := strings.TrimRight(dl.PublicAddr, "/") + "/api/v1/files/" + url.PathEscape(dl.FileID) + "/stream"
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, u, nil)
	if err != nil {
		return 0, "", 0, err
	}
	req.Header.Set(protocol.HeaderLeaseToken, dl.LeaseToken)
	if offset > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}

	resp, err := a.nextStreamClient().Do(req)
	if err != nil {
		return 0, "", 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return 0, "", resp.StatusCode, fmt.Errorf("stream returned HTTP %d", resp.StatusCode)
	}

	f, err := os.OpenFile(dl.PartPath, os.O_CREATE|os.O_RDWR, 0o644)
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
		if err := reqCtx.Err(); err != nil {
			_ = f.Sync()
			return written, "", resp.StatusCode, err
		}
		nr, rErr := resp.Body.Read(buf)
		if nr > 0 {
			lastActivity.Store(time.Now().UnixNano())
			if a.limiter != nil {
				if err := a.limiter.Wait(reqCtx, nr); err != nil {
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
	interval := 2 * time.Second
	if a.cfg.AckBatchIntervalMs > 0 {
		interval = time.Duration(a.cfg.AckBatchIntervalMs) * time.Millisecond
		if interval < 50*time.Millisecond {
			interval = 50 * time.Millisecond
		}
	}
	ticker := time.NewTicker(interval)
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

func (a *Agent) sendBatchAck(ctx context.Context, publicAddr string, acks []PendingAck) ([]string, bool, error) {
	items := make([]protocol.BatchAckItem, len(acks))
	for i, ak := range acks {
		items[i] = protocol.BatchAckItem{
			FileID:     ak.FileID,
			LeaseID:    ak.LeaseID,
			LeaseToken: ak.LeaseToken,
			SHA256:     ak.SHA256,
			DurationMs: ak.DurationMs,
		}
	}
	body, _ := json.Marshal(protocol.BatchAckReq{
		BNodeID: a.cfg.NodeID,
		Items:   items,
	})
	u := strings.TrimRight(publicAddr, "/") + "/api/v1/files/batch-ack"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.apiClient.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
		return nil, true, nil // fallback to legacy single ACK
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("batch-ack returned HTTP %d", resp.StatusCode)
	}
	var out protocol.BatchAckResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, false, err
	}
	doneIDs := make([]string, 0, len(out.Results))
	for _, r := range out.Results {
		switch r.Status {
		case "deleted", "already_deleted", "not_found":
			doneIDs = append(doneIDs, r.FileID)
		default:
			a.logger.Warn("batch-ack item not confirmed", "file_id", r.FileID, "status", r.Status, "err", r.Error)
		}
	}
	return doneIDs, false, nil
}

func (a *Agent) flushPendingAcks(ctx context.Context) {
	acks, err := a.store.ListPendingAcks()
	if err != nil || len(acks) == 0 {
		a.pendingAckCount.Store(0)
		return
	}

	// Ensure every destination directory containing newly landed files is fsynced on disk
	// BEFORE confirming ACK to Agent A ("没落盘的不准删").
	syncedDirs := make(map[string]bool)
	failedDirs := make(map[string]bool)
	for _, ak := range acks {
		if ak.DestDir == "" || syncedDirs[ak.DestDir] || failedDirs[ak.DestDir] {
			continue
		}
		if err := transfer.SyncDir(ak.DestDir); err != nil {
			a.logger.Warn("fsync dest dir failed, deferring ACK", "dir", ak.DestDir, "err", err)
			failedDirs[ak.DestDir] = true
		} else {
			syncedDirs[ak.DestDir] = true
		}
	}

	// Group durable ACKs by Agent A address.
	byAddr := make(map[string][]PendingAck)
	for _, ak := range acks {
		if ak.DestDir != "" && failedDirs[ak.DestDir] {
			continue
		}
		byAddr[ak.PublicAddr] = append(byAddr[ak.PublicAddr], ak)
	}

	var allDone []string
	const maxChunk = 128
	for pubAddr, group := range byAddr {
		for start := 0; start < len(group); start += maxChunk {
			if ctx.Err() != nil {
				break
			}
			end := start + maxChunk
			if end > len(group) {
				end = len(group)
			}
			chunk := group[start:end]
			doneIDs, fallback, err := a.sendBatchAck(ctx, pubAddr, chunk)
			if err != nil {
				a.logger.Warn("batch-ack failed, will retry", "public_addr", pubAddr, "count", len(chunk), "err", err)
				continue
			}
			if fallback {
				for _, ak := range chunk {
					if ctx.Err() != nil {
						break
					}
					if err := a.sendAck(ctx, ak); err == nil {
						allDone = append(allDone, ak.FileID)
					}
				}
				continue
			}
			allDone = append(allDone, doneIDs...)
		}
	}

	if len(allDone) > 0 {
		_ = a.store.DeletePendingAcks(allDone)
	}
	a.pendingAckCount.Store(int64(a.store.PendingAckCount()))
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
	var totalDisk, freeDisk uint64
	var usedPct float64
	seenDev := make(map[uint64]struct{})
	for _, projID := range a.cfg.ProjectIDs() {
		for _, dir := range a.cfg.DestDirsFor(projID) {
			var st unix.Stat_t
			if err := unix.Stat(dir, &st); err == nil {
				dev := uint64(st.Dev)
				if _, dup := seenDev[dev]; dup {
					continue
				}
				seenDev[dev] = struct{}{}
			}
			if t, f, _, err := transfer.DiskUsage(dir); err == nil {
				totalDisk += t
				freeDisk += f
			}
		}
	}
	if totalDisk > 0 {
		usedPct = (float64(totalDisk-freeDisk) / float64(totalDisk)) * 100.0
	}

	a.mu.RLock()
	active := make([]protocol.BActiveTransfer, 0, len(a.progress))
	for _, p := range a.progress {
		active = append(active, p.snapshot())
	}
	a.mu.RUnlock()

	upgAttempt, upgStatus, upgErr := "", "", ""
	if a.updater != nil {
		upgAttempt, upgStatus, upgErr = a.updater.Status()
	}

	payload := protocol.AgentBHeartbeatReq{
		NodeID:           a.cfg.NodeID,
		Name:             a.cfg.NodeName,
		Projects:         a.cfg.ProjectIDs(),
		Version:          version.Version,
		OS:               runtime.GOOS,
		Arch:             runtime.GOARCH,
		UpgradeAttemptID: upgAttempt,
		UpgradeStatus:    upgStatus,
		UpgradeError:     upgErr,
		DiskTotalBytes:   totalDisk,
		DiskFreeBytes:    freeDisk,
		DiskUsedPct:      usedPct,
		ActiveTransfers:  active,
		InSpeedBps:       a.lastSpeedBps.Load(),
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
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return
	}
	var hbResp protocol.HeartbeatResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&hbResp); err == nil && hbResp.Upgrade != nil && a.updater != nil {
		a.updater.HandleDirective(ctx, hbResp.Upgrade)
	}
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
