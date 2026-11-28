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
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"relay-download/internal/pki"
	"relay-download/internal/protocol"
	"relay-download/internal/transfer"
	"relay-download/internal/updater"
	"relay-download/internal/version"
)

var errPeerDraining = errors.New("dispatch node is shutting down")

type ackBackoffState struct {
	failures  int
	nextRetry time.Time
}

type cachedDiscover struct {
	resp      *protocol.DiscoverResp
	expiresAt time.Time
}

type Agent struct {
	cfg           *Config
	store         *Store
	logger        *slog.Logger
	apiMu         sync.RWMutex
	apiClient     *http.Client
	makeAPICli    func() *http.Client
	sseClient     *http.Client
	streamMu      sync.RWMutex
	streamClients []*http.Client
	makeStreamCli func() *http.Client
	streamIdx     atomic.Uint64
	limiter       *transfer.RateLimiter

	workGate   *DynamicGate
	streamGate *DynamicGate
	adaptive   *AdaptiveController
	wakeupCh   chan string
	ackWakeCh  chan struct{}
	hbWakeCh   chan struct{}
	updater    *updater.Updater

	discMu    sync.Mutex
	discCache map[string]cachedDiscover

	peerMu         sync.Mutex
	peerCooldown   map[string]time.Time
	ackPeerBackoff map[string]ackBackoffState

	dirMu           sync.RWMutex
	directiveMode   string              // "" | "all" | "selected"
	allowedOrder    []string            // ordered Center-enforced project allowlist when directiveMode=="selected"
	allowedProjects map[string]struct{} // non-nil when directiveMode=="selected"
	knownOrder      []string            // Center-reported known projects ordered by created_at ASC
	projectSchedule  string              // "fifo" | "fair" | "random"
	diskPolicy       string              // "rolling_window" | "round_robin" | "most_free" | "first" | legacy "affinity_hash"
	diskAffinity     bool                // default true: keep paired assets on the same disk across all disk policies
	diskAffinitySet  bool                // distinguishes zero-value struct construction in unit tests from explicit false
	activeDiskWindow int                 // concurrent active disk window for rolling_window policy
	dirStorageDirs   []string            // Center-managed data disk pool roots (overrides cfg.StorageDirs when non-empty)
	disabledDisks    map[string]struct{} // cleaned root paths disabled via Console or auto-locked on unplug
	diskGen          int64               // monotonic Center disk-config generation
	maxDiskUsagePct  float64             // Center-customizable mandatory disk watermark [1..99], default 85
	diskHealth       *transfer.DiskHealthTracker

	stemMu      sync.Mutex
	stemToDir   map[string]string
	stemRing    []string
	stemRingPos int

	hostDiskMu     sync.Mutex
	hostDisksCache []protocol.HostDisk
	hostDisksAt    time.Time

	sseMu     sync.Mutex
	sseCancel context.CancelFunc
	readyDirs sync.Map
	diskRRIdx atomic.Uint64
	projRRIdx atomic.Uint64

	activeCount     atomic.Int32
	pendingAckCount atomic.Int64
	hashRAMBytes    atomic.Int64
	paused          atomic.Bool

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

	diskHealth := transfer.NewDiskHealthTracker()
	for _, sd := range cfg.StorageDirs {
		if err := diskHealth.SafeMkdirAll(sd, filepath.Join(sd, ".relay_tmp"), true); err != nil {
			probe := diskHealth.ProbeRoot(sd, true, cfg.MaxDiskUsagePct, cfg.MinFreeDiskBytes, 0)
			if probe.Detached {
				logger.Warn("storage dir detached at startup, skipping mkdir to protect root filesystem", "dir", sd, "reason", probe.StatusReason)
				continue
			}
			return nil, fmt.Errorf("init storage dir %s: %w", sd, err)
		}
	}
	for _, proj := range cfg.ProjectIDs() {
		for _, dir := range cfg.DestDirsFor(proj) {
			root := transfer.MatchRootForPath(dir, cfg.DiskRoots())
			if err := diskHealth.SafeMkdirAll(root, filepath.Join(root, ".relay_tmp"), true); err != nil {
				probe := diskHealth.ProbeRoot(root, true, cfg.MaxDiskUsagePct, cfg.MinFreeDiskBytes, 0)
				if probe.Detached {
					logger.Warn("dest dir detached at startup, skipping mkdir", "project", proj, "dir", dir, "reason", probe.StatusReason)
					continue
				}
				return nil, fmt.Errorf("init staging dir for project %s (%s): %w", proj, root, err)
			}
			if filepath.Clean(dir) != filepath.Clean(root) {
				if err := diskHealth.SafeMkdirAll(root, dir, true); err != nil {
					probe := diskHealth.ProbeRoot(root, true, cfg.MaxDiskUsagePct, cfg.MinFreeDiskBytes, 0)
					if probe.Detached {
						logger.Warn("dest dir detached at startup, skipping mkdir", "project", proj, "dir", dir, "reason", probe.StatusReason)
						continue
					}
					return nil, fmt.Errorf("init dest dir for project %s (%s): %w", proj, dir, err)
				}
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

	apiIdleTimeout := 60 * time.Second
	if cfg.StreamConnMaxAgeSec > 0 {
		apiIdleTimeout = time.Duration(cfg.StreamConnMaxAgeSec) * time.Second
		if apiIdleTimeout < 5*time.Second {
			apiIdleTimeout = 5 * time.Second
		}
	}
	fastDialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	makeAPIClient := func() *http.Client {
		return &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				DialContext:           fastDialer.DialContext,
				TLSClientConfig:       clientTLS.Clone(),
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          32,
				MaxIdleConnsPerHost:   16,
				IdleConnTimeout:       apiIdleTimeout,
				TLSHandshakeTimeout:   8 * time.Second,
				ResponseHeaderTimeout: 10 * time.Second,
			},
		}
	}

	makeH2StreamClient := func() *http.Client {
		return &http.Client{
			// No overall Timeout on streaming/SSE client; bounded by ctx cancellation.
			Transport: &http.Transport{
				DialContext:           fastDialer.DialContext,
				TLSClientConfig:       clientTLS.Clone(),
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          8,
				MaxIdleConnsPerHost:   4,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 10 * time.Second,
				ReadBufferSize:        256 << 10,
				WriteBufferSize:       64 << 10,
				HTTP2: &http.HTTP2Config{
					MaxReadFrameSize:              512 << 10,
					MaxReceiveBufferPerConnection: 2 << 20,
					MaxReceiveBufferPerStream:     2 << 20,
				},
			},
		}
	}

	makeSSEClient := func() *http.Client {
		return &http.Client{
			// SSE stays open indefinitely waiting for wakeup events; no ResponseHeaderTimeout.
			Transport: &http.Transport{
				TLSClientConfig:     clientTLS.Clone(),
				ForceAttemptHTTP2:   true,
				MaxIdleConns:        4,
				MaxIdleConnsPerHost: 2,
				IdleConnTimeout:     90 * time.Second,
				TLSHandshakeTimeout: 10 * time.Second,
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
					DialContext:           fastDialer.DialContext,
					TLSClientConfig:       h1TLS,
					ForceAttemptHTTP2:     false,
					TLSNextProto:          make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
					MaxIdleConns:          perShardPool,
					MaxIdleConnsPerHost:   perShardPool,
					IdleConnTimeout:       idleTimeout,
					TLSHandshakeTimeout:   8 * time.Second,
					ResponseHeaderTimeout: 8 * time.Second,
					ReadBufferSize:        1 << 20,
					WriteBufferSize:       256 << 10,
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

	limiter := transfer.NewDynamicRateLimiter(int64(cfg.RateLimitMBps * 1024 * 1024))
	workGate := NewDynamicGate(cfg.MaxConcurrent)
	streamGate := NewDynamicGate(cfg.MaxTotalStreams)
	adaptive := NewAdaptiveController(cfg.ConcurrencyMode, cfg.MaxConcurrent, cfg.MaxTotalStreams, cfg.AckBatchSize, workGate, streamGate)

	ag := &Agent{
		cfg:             cfg,
		store:           store,
		logger:          logger.With("component", "agent-b", "node_id", cfg.NodeID),
		limiter:         limiter,
		apiClient:       makeAPIClient(),
		makeAPICli:      makeAPIClient,
		sseClient:       makeSSEClient(),
		streamClients:   streamClients,
		makeStreamCli:   makeStreamCli,
		workGate:        workGate,
		streamGate:      streamGate,
		adaptive:        adaptive,
		wakeupCh:        make(chan string, 256),
		ackWakeCh:       make(chan struct{}, 1),
		hbWakeCh:        make(chan struct{}, 1),
		discCache:       make(map[string]cachedDiscover),
		peerCooldown:    make(map[string]time.Time),
		ackPeerBackoff:  make(map[string]ackBackoffState),
		projectSchedule:  cfg.ProjectSchedule,
		diskPolicy:       cfg.DiskPolicy,
		diskAffinity:     cfg.DiskAffinityEnabled(),
		diskAffinitySet:  true,
		activeDiskWindow: cfg.ActiveDiskWindow,
		maxDiskUsagePct:  transfer.NormalizeMaxDiskUsagePct(cfg.MaxDiskUsagePct),
		diskHealth:       diskHealth,
	}
	upgradeClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:     clientTLS.Clone(),
			ForceAttemptHTTP2:   true,
			DisableKeepAlives:   true,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}
	ag.updater = updater.New(updater.Options{
		Component:    "relay-agent-b",
		NodeID:       cfg.NodeID,
		CenterURL:    cfg.CenterURL,
		CenterToken:  cfg.CenterToken,
		HTTPClient:   upgradeClient,
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

func (a *Agent) getAPIClient() *http.Client {
	a.apiMu.RLock()
	cli := a.apiClient
	a.apiMu.RUnlock()
	return cli
}

// rotateAPIClient swaps the control-plane HTTP client to a fresh transport so an ISP-policed
// or half-open TCP socket can never stall claim-batch / batch-ack / renew / heartbeat calls.
// If expected != nil, rotation only happens if a.apiClient is still expected (prevents stampedes).
func (a *Agent) rotateAPIClient(expected *http.Client) {
	if a.makeAPICli == nil {
		return
	}
	a.apiMu.Lock()
	if expected != nil && a.apiClient != expected {
		a.apiMu.Unlock()
		return
	}
	old := a.apiClient
	a.apiClient = a.makeAPICli()
	a.apiMu.Unlock()

	if old != nil {
		if tr, ok := old.Transport.(*http.Transport); ok {
			tr.CloseIdleConnections()
			for _, delay := range []time.Duration{3 * time.Second, 10 * time.Second, 20 * time.Second} {
				time.AfterFunc(delay, tr.CloseIdleConnections)
			}
		}
	}
}

func (a *Agent) doAPI(req *http.Request) (*http.Response, error) {
	cli := a.getAPIClient()
	resp, err := cli.Do(req)
	if err != nil && req.Context().Err() == nil {
		a.rotateAPIClient(cli)
	}
	return resp, err
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

// streamRotateLoop staggered-rotates data-plane and control-plane HTTP transports so no single
// TCP socket stays alive long enough to trigger cross-border ISP per-flow QoS policing, without
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
			if nextShard%shards == 0 {
				// Proactively rotate control-plane client once per maxAge cycle too so
				// claim-batch / batch-ack never ride an aged ISP-policed TCP connection.
				a.rotateAPIClient(nil)
			}

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
	launchBG(a.heartbeatLoop)
	launchBG(a.ackFlushLoop)
	launchBG(a.sseLoop)
	launchBG(a.dispatchLoop)
	launchBG(a.adaptiveLoop)
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

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalStringSet(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

func (a *Agent) effectiveProjectSchedule() string {
	a.dirMu.RLock()
	s := a.projectSchedule
	a.dirMu.RUnlock()
	if s == "" {
		return a.cfg.ProjectSchedule
	}
	return s
}

func (a *Agent) effectiveDiskPolicy() string {
	a.dirMu.RLock()
	p := a.diskPolicy
	a.dirMu.RUnlock()
	if p == "" {
		return a.cfg.DiskPolicy
	}
	return p
}

func (a *Agent) effectiveDiskAffinity() bool {
	a.dirMu.RLock()
	set := a.diskAffinitySet
	val := a.diskAffinity
	a.dirMu.RUnlock()
	if set {
		return val
	}
	if a.cfg != nil {
		return a.cfg.DiskAffinityEnabled()
	}
	return true
}

const maxStemAffinityEntries = 65536

func (a *Agent) lookupStemDisk(key string) string {
	a.stemMu.Lock()
	dir := a.stemToDir[key]
	a.stemMu.Unlock()
	return dir
}

// rememberOrGetStemDisk atomically associates stem key -> chosenDir. If another goroutine
// concurrently recorded a sibling file for the same stem moments ago, returns that existing dir
// so microsecond-simultaneous paired files still land on the exact same disk.
func (a *Agent) rememberOrGetStemDisk(key, chosenDir string, allowed func(string) bool) string {
	a.stemMu.Lock()
	defer a.stemMu.Unlock()
	if a.stemToDir == nil {
		a.stemToDir = make(map[string]string, 1024)
		a.stemRing = make([]string, maxStemAffinityEntries)
	}
	if prev, ok := a.stemToDir[key]; ok && prev != "" {
		if prev == chosenDir || (allowed != nil && allowed(prev)) {
			return prev
		}
	}
	if _, existed := a.stemToDir[key]; !existed {
		if old := a.stemRing[a.stemRingPos]; old != "" && old != key {
			delete(a.stemToDir, old)
		}
		a.stemRing[a.stemRingPos] = key
		a.stemRingPos = (a.stemRingPos + 1) % len(a.stemRing)
	}
	a.stemToDir[key] = chosenDir
	return chosenDir
}

func (a *Agent) effectiveActiveDiskWindow() int {
	a.dirMu.RLock()
	w := a.activeDiskWindow
	a.dirMu.RUnlock()
	if w <= 0 {
		w = a.cfg.ActiveDiskWindow
	}
	if w <= 0 {
		return 10
	}
	return w
}

func (a *Agent) effectiveMaxDiskUsagePct() float64 {
	a.dirMu.RLock()
	pct := a.maxDiskUsagePct
	a.dirMu.RUnlock()
	if pct <= 0 {
		pct = a.cfg.MaxDiskUsagePct
	}
	return transfer.NormalizeMaxDiskUsagePct(pct)
}

func (a *Agent) isDiskRootDisabledLocked(root string) bool {
	if len(a.disabledDisks) == 0 {
		return false
	}
	clean := filepath.Clean(strings.TrimSpace(root))
	_, ok := a.disabledDisks[clean]
	return ok
}

func (a *Agent) isDirDisabledLocked(dir string) bool {
	if len(a.disabledDisks) == 0 {
		return false
	}
	clean := filepath.Clean(strings.TrimSpace(dir))
	if _, ok := a.disabledDisks[clean]; ok {
		return true
	}
	for dis := range a.disabledDisks {
		if strings.HasPrefix(clean, dis+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func (a *Agent) effectiveStorageDirsLocked() []string {
	if len(a.dirStorageDirs) > 0 {
		return a.dirStorageDirs
	}
	return a.cfg.StorageDirs
}

func (a *Agent) effectiveStorageDirs() []string {
	a.dirMu.RLock()
	out := append([]string(nil), a.effectiveStorageDirsLocked()...)
	a.dirMu.RUnlock()
	return out
}

func (a *Agent) destDirsFor(projectID string) []string {
	a.dirMu.RLock()
	dynStorage := append([]string(nil), a.dirStorageDirs...)
	a.dirMu.RUnlock()
	if len(dynStorage) == 0 {
		return a.cfg.DestDirsFor(projectID)
	}
	only := strings.TrimSpace(a.cfg.OnlyProject)
	if only != "" && projectID != only {
		return nil
	}
	if !SafeProjectSubdir(projectID) {
		return nil
	}
	out := make([]string, 0, len(dynStorage))
	for _, sd := range dynStorage {
		out = append(out, filepath.Join(sd, projectID))
	}
	return out
}

func (a *Agent) diskRoots() []string {
	a.dirMu.RLock()
	dynStorage := append([]string(nil), a.dirStorageDirs...)
	a.dirMu.RUnlock()
	if len(dynStorage) > 0 {
		return dynStorage
	}
	return a.cfg.DiskRoots()
}

func (a *Agent) awaitingDisk() bool {
	return len(a.diskRoots()) == 0
}

func (a *Agent) cachedHostDisks() []protocol.HostDisk {
	// /proc/mounts + statfs on a handful of mounts takes <0.2ms on Linux, so scan fresh
	// on every heartbeat (2s) so newly mounted disks appear immediately upon refresh.
	disks := DiscoverHostDisks()
	a.hostDiskMu.Lock()
	a.hostDisksCache = disks
	a.hostDisksAt = time.Now()
	a.hostDiskMu.Unlock()
	return disks
}

func (a *Agent) isDiskRootDisabled(root string) bool {
	a.dirMu.RLock()
	dis := a.isDiskRootDisabledLocked(root)
	a.dirMu.RUnlock()
	return dis
}

func (a *Agent) diskRootForDestDir(dir string) string {
	return transfer.MatchRootForPath(dir, a.diskRoots())
}

// stagingDirFor returns the temporary staging directory on the same filesystem as destDir.
// In storage-pool mode (destDir sits under a storage root, e.g. /mnt/sda/relay-delivery/<project_id>),
// staging uses <storage_root>/.relay_tmp/<project_id>/ so that:
//   - external removal or moving of <storage_root>/<project_id> mid-download cannot unlink in-flight .part files;
//   - temporary files remain cleanly isolated and inspectable per project;
//   - staging stays on the exact same mount as destDir so os.Rename remains O(1) atomic.
// In legacy static project-mapping mode (no storage_dirs; diskRoot == destDir), staging stays <destDir>/.relay_tmp.
func (a *Agent) stagingDirFor(destDir, projectID string) string {
	root := a.diskRootForDestDir(destDir)
	if root == "" || root == "." {
		root = destDir
	}
	base := filepath.Join(root, ".relay_tmp")
	if filepath.Clean(root) != filepath.Clean(destDir) && SafeProjectSubdir(projectID) {
		return filepath.Join(base, strings.TrimSpace(projectID))
	}
	return base
}

func (a *Agent) evictReadyDirsForRoot(root string) {
	cleanRoot := filepath.Clean(strings.TrimSpace(root))
	if cleanRoot == "" || cleanRoot == "." {
		return
	}
	prefix := cleanRoot + string(filepath.Separator)
	a.readyDirs.Range(func(k, _ any) bool {
		if s, ok := k.(string); ok {
			cs := filepath.Clean(s)
			if cs == cleanRoot || strings.HasPrefix(cs, prefix) {
				a.readyDirs.Delete(k)
			}
		}
		return true
	})
}

func (a *Agent) handleLocalDiskErr(root string, err error) bool {
	if err == nil {
		return false
	}
	if a.diskHealth.ReportIOError(root, err) {
		a.evictReadyDirsForRoot(root)
		a.logger.Error("receiver disk I/O fault detected, auto-locking disk", "root", root, "err", err)
		a.triggerHeartbeat()
		return true
	}
	if transfer.IsDiskIOError(err) {
		a.evictReadyDirsForRoot(root)
		return true
	}
	probe := a.diskHealth.ProbeRoot(root, !a.isDiskRootDisabled(root), a.effectiveMaxDiskUsagePct(), a.cfg.MinFreeDiskBytes, 0)
	if probe.Detached || probe.UnplugLatched || !probe.Mounted {
		a.evictReadyDirsForRoot(root)
		a.logger.Warn("receiver disk detached during transfer, aborting file to protect source", "root", root, "reason", probe.StatusReason, "err", err)
		a.triggerHeartbeat()
		return true
	}
	return false
}

// enabledDestDirsFor returns destination directories for projectID after filtering out any
// disk roots disabled from the Center console or fenced by hot-unplug/IO-fault detection.
func (a *Agent) enabledDestDirsFor(projectID string) []string {
	dirs := a.destDirsFor(projectID)
	if len(dirs) == 0 {
		return nil
	}
	roots := a.diskRoots()
	a.dirMu.RLock()
	defer a.dirMu.RUnlock()
	out := make([]string, 0, len(dirs))
	for _, d := range dirs {
		if a.isDirDisabledLocked(d) {
			continue
		}
		root := transfer.MatchRootForPath(d, roots)
		if a.diskHealth.IsBlocked(root) {
			continue
		}
		out = append(out, d)
	}
	return out
}

func (a *Agent) ensureDestDirReady(dir, projectID string) error {
	root := a.diskRootForDestDir(dir)
	stagingDir := a.stagingDirFor(dir, projectID)
	if a.diskHealth.IsBlocked(root) {
		a.readyDirs.Delete(stagingDir)
		return fmt.Errorf("storage root %s is disabled or detached", root)
	}
	if _, ok := a.readyDirs.Load(stagingDir); ok {
		return nil
	}
	if err := a.diskHealth.SafeMkdirAll(root, stagingDir, true); err != nil {
		a.readyDirs.Delete(stagingDir)
		return err
	}
	a.readyDirs.Store(stagingDir, struct{}{})
	return nil
}

// activeProjectIDs returns the ordered effective list of projects this receiver will pull.
// Order preserves Center's configured allowlist order (selected mode) or project creation order (all mode).
func (a *Agent) activeProjectIDs() []string {
	a.dirMu.RLock()
	mode := a.directiveMode
	allowedOrder := append([]string(nil), a.allowedOrder...)
	allowedSet := a.allowedProjects
	knownOrder := append([]string(nil), a.knownOrder...)
	hasPool := len(a.effectiveStorageDirsLocked()) > 0
	a.dirMu.RUnlock()

	if only := strings.TrimSpace(a.cfg.OnlyProject); only != "" {
		if mode == "selected" && allowedSet != nil {
			if _, ok := allowedSet[only]; !ok {
				return nil
			}
		}
		if len(a.destDirsFor(only)) > 0 {
			return []string{only}
		}
		return nil
	}

	localIDs := a.cfg.ProjectIDs()

	if hasPool {
		if mode == "selected" {
			out := make([]string, 0, len(allowedOrder))
			for _, p := range allowedOrder {
				if len(a.destDirsFor(p)) > 0 {
					out = append(out, p)
				}
			}
			return out
		}
		seen := make(map[string]struct{}, len(knownOrder)+len(localIDs))
		out := make([]string, 0, len(knownOrder)+len(localIDs))
		for _, p := range knownOrder {
			if len(a.destDirsFor(p)) == 0 {
				continue
			}
			if _, dup := seen[p]; !dup {
				seen[p] = struct{}{}
				out = append(out, p)
			}
		}
		for _, p := range localIDs {
			if _, dup := seen[p]; !dup {
				seen[p] = struct{}{}
				out = append(out, p)
			}
		}
		return out
	}

	// Legacy static project mapping mode (no storage_dirs configured).
	localSet := make(map[string]struct{}, len(localIDs))
	for _, p := range localIDs {
		localSet[p] = struct{}{}
	}
	if mode == "selected" && allowedSet != nil {
		out := make([]string, 0, len(allowedOrder))
		for _, p := range allowedOrder {
			if _, ok := localSet[p]; ok {
				out = append(out, p)
			}
		}
		return out
	}
	if len(knownOrder) > 0 {
		seen := make(map[string]struct{}, len(localIDs))
		out := make([]string, 0, len(localIDs))
		for _, p := range knownOrder {
			if _, ok := localSet[p]; ok {
				if _, dup := seen[p]; !dup {
					seen[p] = struct{}{}
					out = append(out, p)
				}
			}
		}
		for _, p := range localIDs {
			if _, dup := seen[p]; !dup {
				seen[p] = struct{}{}
				out = append(out, p)
			}
		}
		return out
	}
	return localIDs
}

func (a *Agent) isProjectAllowed(projectID string) bool {
	if len(a.destDirsFor(projectID)) == 0 {
		return false
	}
	a.dirMu.RLock()
	mode := a.directiveMode
	allowed := a.allowedProjects
	a.dirMu.RUnlock()
	if mode != "selected" || allowed == nil {
		return true
	}
	_, ok := allowed[projectID]
	return ok
}

func (a *Agent) reconnectSSE() {
	a.sseMu.Lock()
	cancel := a.sseCancel
	a.sseMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (a *Agent) setPaused(nextPaused bool) {
	prevPaused := a.paused.Swap(nextPaused)
	if prevPaused != nextPaused {
		a.discMu.Lock()
		a.discCache = make(map[string]cachedDiscover)
		a.discMu.Unlock()
		if a.logger != nil {
			a.logger.Info("receiver node pause state updated from center", "paused", nextPaused)
		}
		if !nextPaused {
			a.triggerWakeup("")
		}
	}
}

func (a *Agent) applyDirective(dir *protocol.ReceiverDirective, legacyAllowed []string) {
	if dir != nil {
		a.setPaused(dir.Paused)
	}

	var (
		nextMode        string
		nextAllowed     []string
		nextAllowSet    map[string]struct{}
		nextKnown       []string
		nextSched       = a.cfg.ProjectSchedule
		nextDiskPol     = a.cfg.DiskPolicy
		nextDiskAff     = a.cfg.DiskAffinityEnabled()
		nextDiskWin     = a.cfg.ActiveDiskWindow
		nextMaxDiskPct  = transfer.NormalizeMaxDiskUsagePct(a.cfg.MaxDiskUsagePct)
		nextStorageDirs []string
		nextDisabled    map[string]struct{}
		nextDiskGen     int64
	)

	if dir != nil {
		nextMode = strings.ToLower(strings.TrimSpace(dir.ProjectMode))
		if nextMode != "selected" {
			nextMode = "all"
		}
		if nextMode == "selected" {
			nextAllowSet = make(map[string]struct{}, len(dir.AllowedProjects))
			for _, p := range dir.AllowedProjects {
				p = strings.TrimSpace(p)
				if p == "" {
					continue
				}
				if _, dup := nextAllowSet[p]; !dup {
					nextAllowSet[p] = struct{}{}
					nextAllowed = append(nextAllowed, p)
				}
			}
		}
		seenK := make(map[string]struct{}, len(dir.KnownProjects))
		for _, p := range dir.KnownProjects {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if _, dup := seenK[p]; !dup {
				seenK[p] = struct{}{}
				nextKnown = append(nextKnown, p)
			}
		}
		switch strings.ToLower(strings.TrimSpace(dir.ProjectSchedule)) {
		case protocol.ScheduleFIFO, protocol.ScheduleFair, protocol.ScheduleRandom:
			nextSched = strings.ToLower(strings.TrimSpace(dir.ProjectSchedule))
		}
		switch strings.ToLower(strings.TrimSpace(dir.DiskPolicy)) {
		case protocol.DiskPolicyAffinityHash, protocol.DiskPolicyMostFree, protocol.DiskPolicyRoundRobin, protocol.DiskPolicyFirst, protocol.DiskPolicyRollingWindow:
			nextDiskPol = strings.ToLower(strings.TrimSpace(dir.DiskPolicy))
		}
		if dir.DiskAffinity != nil {
			nextDiskAff = *dir.DiskAffinity
		}
		if dir.ActiveDiskWindow > 0 {
			nextDiskWin = dir.ActiveDiskWindow
			if nextDiskWin > 256 {
				nextDiskWin = 256
			}
		}
		if dir.MaxDiskUsagePct > 0 {
			nextMaxDiskPct = transfer.NormalizeMaxDiskUsagePct(dir.MaxDiskUsagePct)
		}
		if len(dir.DisabledDisks) > 0 {
			nextDisabled = make(map[string]struct{}, len(dir.DisabledDisks))
			for _, d := range dir.DisabledDisks {
				d = strings.TrimSpace(d)
				if d != "" {
					nextDisabled[filepath.Clean(d)] = struct{}{}
				}
			}
		}
		nextDiskGen = dir.DiskGen
		a.diskHealth.ApplyConfig(dir.DisabledDisks, nextDiskGen)
		if len(dir.StorageDirs) > 0 {
			seenSD := make(map[string]struct{}, len(dir.StorageDirs))
			for _, d := range dir.StorageDirs {
				d = strings.TrimSpace(d)
				if !IsSafeStorageDir(d) {
					continue
				}
				d = filepath.Clean(d)
				if _, dup := seenSD[d]; !dup {
					seenSD[d] = struct{}{}
					nextStorageDirs = append(nextStorageDirs, d)
					if _, isDis := nextDisabled[d]; !isDis {
						if err := a.diskHealth.SafeMkdirAll(d, d, true); err != nil && a.logger != nil {
							a.logger.Warn("skipping mkdir for unavailable storage dir", "dir", d, "err", err)
						}
					} else {
						a.evictReadyDirsForRoot(d)
					}
				}
			}
		}
	} else if len(legacyAllowed) > 0 {
		nextMode = "selected"
		nextAllowSet = make(map[string]struct{}, len(legacyAllowed))
		for _, p := range legacyAllowed {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if _, dup := nextAllowSet[p]; !dup {
				nextAllowSet[p] = struct{}{}
				nextAllowed = append(nextAllowed, p)
			}
		}
	} else {
		nextMode = "all"
	}

	prevActive := a.activeProjectIDs()
	a.dirMu.Lock()
	scopeChanged := a.directiveMode != nextMode ||
		!equalStringSlices(a.allowedOrder, nextAllowed) ||
		!equalStringSlices(a.knownOrder, nextKnown)
	policyChanged := a.projectSchedule != nextSched ||
		a.diskPolicy != nextDiskPol ||
		!a.diskAffinitySet || a.diskAffinity != nextDiskAff ||
		a.activeDiskWindow != nextDiskWin ||
		a.maxDiskUsagePct != nextMaxDiskPct ||
		!equalStringSlices(a.dirStorageDirs, nextStorageDirs) ||
		!equalStringSet(a.disabledDisks, nextDisabled) ||
		a.diskGen != nextDiskGen

	a.directiveMode = nextMode
	a.allowedOrder = nextAllowed
	a.allowedProjects = nextAllowSet
	a.knownOrder = nextKnown
	a.projectSchedule = nextSched
	a.diskPolicy = nextDiskPol
	a.diskAffinity = nextDiskAff
	a.diskAffinitySet = true
	a.activeDiskWindow = nextDiskWin
	a.maxDiskUsagePct = nextMaxDiskPct
	a.dirStorageDirs = nextStorageDirs
	a.disabledDisks = nextDisabled
	if nextDiskGen > a.diskGen {
		a.diskGen = nextDiskGen
	}
	a.dirMu.Unlock()

	if dir != nil {
		if a.adaptive != nil {
			a.adaptive.Configure(dir.ConcurrencyMode, dir.MaxConcurrent, dir.SuggestedStreamCap)
		}
		if a.limiter != nil {
			effRateMBps := dir.RateLimitMBps
			if effRateMBps <= 0 {
				effRateMBps = a.cfg.RateLimitMBps
			}
			a.limiter.SetRate(int64(effRateMBps * 1024 * 1024))
		}
	}

	if scopeChanged || policyChanged {
		nextActive := a.activeProjectIDs()
		a.discMu.Lock()
		a.discCache = make(map[string]cachedDiscover)
		a.discMu.Unlock()
		if a.logger != nil {
			a.logger.Info("applied Center receiver directive",
				"mode", nextMode,
				"schedule", nextSched,
				"disk_policy", nextDiskPol,
				"disabled_disks", len(nextDisabled),
				"effective_projects", nextActive,
			)
		}
		if !equalStringSlices(prevActive, nextActive) {
			a.reconnectSSE()
		}
		a.triggerWakeup("")
	}
}

func (a *Agent) adaptiveLoop(ctx context.Context) {
	if a.adaptive == nil {
		return
	}
	const interval = 10 * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	prevLimit := a.adaptive.Snapshot().EffectiveConcurrent
	prevState := a.adaptive.Snapshot().State
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if a.paused.Load() || a.awaitingDisk() {
				continue
			}
			snap := a.adaptive.Evaluate(interval, a.workGate.InFlight(), a.pendingAckCount.Load())
			if snap.EffectiveConcurrent != prevLimit || snap.State != prevState {
				if a.logger != nil {
					a.logger.Info("adaptive concurrency adjusted",
						"mode", snap.Mode,
						"state", snap.State,
						"concurrent", snap.EffectiveConcurrent,
						"cap", snap.MaxConcurrentCap,
						"streams", snap.EffectiveStreams,
						"reason", snap.Reason,
					)
				}
				if snap.EffectiveConcurrent > prevLimit {
					a.triggerWakeup("")
				}
				prevLimit = snap.EffectiveConcurrent
				prevState = snap.State
			}
		}
	}
}

func (a *Agent) resumePersistedDownloads(ctx context.Context) {
	active, err := a.store.ListActive()
	if err != nil {
		a.logger.Warn("load active downloads failed", "err", err)
		return
	}
	for _, dl := range active {
		if len(a.cfg.DestDirsFor(dl.ProjectID)) == 0 {
			// Skip and release downloads belonging to projects excluded by only_project / updated config.
			a.logger.Info("skipping persisted download excluded by project filter", "file_id", dl.FileID, "project", dl.ProjectID)
			_ = os.Remove(dl.PartPath)
			_ = os.Remove(dl.PartPath + ".bitmap")
			_ = a.store.DeleteActive(dl.FileID)
			_ = a.sendNack(ctx, dl, "project no longer subscribed on receiver")
			continue
		}
		dlCopy := dl
		if err := a.workGate.Acquire(ctx); err != nil {
			return
		}
		a.wg.Add(1)
		go func() {
			defer func() {
				a.workGate.Release()
				a.wg.Done()
			}()
			a.runDownload(ctx, dlCopy)
		}()
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

func (a *Agent) sseProjectsQuery() string {
	a.dirMu.RLock()
	mode := a.directiveMode
	hasPool := len(a.effectiveStorageDirsLocked()) > 0
	a.dirMu.RUnlock()
	if hasPool && a.cfg.OnlyProject == "" && (mode == "" || mode == "all") {
		return "*"
	}
	return strings.Join(a.activeProjectIDs(), ",")
}

func (a *Agent) sseLoop(ctx context.Context) {
	backoff := 500 * time.Millisecond

	for {
		if ctx.Err() != nil {
			return
		}
		projects := a.sseProjectsQuery()
		u := strings.TrimRight(a.cfg.CenterURL, "/") + "/api/v1/b/events?projects=" + url.QueryEscape(projects)
		sseCtx, cancel := context.WithCancel(ctx)
		a.sseMu.Lock()
		a.sseCancel = cancel
		a.sseMu.Unlock()

		connected, err := a.consumeSSE(sseCtx, u)
		restartedByDirective := ctx.Err() == nil && sseCtx.Err() != nil
		cancel()
		if ctx.Err() != nil {
			return
		}
		if restartedByDirective {
			backoff = 500 * time.Millisecond
			continue
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
			if a.paused.Load() {
				continue
			}
			if proj == "" {
				a.scanAllProjects(ctx)
				continue
			}
			if !a.isProjectAllowed(proj) {
				continue
			}
			sched := a.effectiveProjectSchedule()
			if (sched == protocol.ScheduleFIFO || sched == protocol.ScheduleFair) && len(a.activeProjectIDs()) > 1 {
				// Enforce strict FIFO priority or fair multi-project sharing instead of letting
				// one project's wakeup starve earlier or peer projects.
				a.scanAllProjects(ctx)
			} else {
				a.scanProject(ctx, proj)
			}
		case <-ticker.C:
			if a.paused.Load() {
				continue
			}
			a.scanAllProjects(ctx)
		}
	}
}

func (a *Agent) scanAllProjects(ctx context.Context) {
	if a.paused.Load() || a.awaitingDisk() {
		return
	}
	ids := a.activeProjectIDs()
	if len(ids) == 0 {
		return
	}
	sched := a.effectiveProjectSchedule()
	if len(ids) == 1 {
		a.scanProject(ctx, ids[0])
		return
	}

	switch sched {
	case protocol.ScheduleFIFO:
		// Strict creation / configured order: drain earlier projects first, spilling remaining
		// concurrency slots into subsequent projects only if earlier projects cannot fill workGate.
		for _, proj := range ids {
			if ctx.Err() != nil || a.workGate.Free() <= 0 {
				return
			}
			a.scanProject(ctx, proj)
		}
	case protocol.ScheduleFair:
		// Round-robin balanced slot sharing across all active projects.
		start := int((a.projRRIdx.Add(1) - 1) % uint64(len(ids)))
		ordered := make([]string, len(ids))
		for i := range ids {
			ordered[i] = ids[(start+i)%len(ids)]
		}
		for a.workGate.Free() > 0 && ctx.Err() == nil {
			free := a.workGate.Free()
			quantum := free / len(ordered)
			if quantum < 1 {
				quantum = 1
			}
			if quantum > a.cfg.ClaimBatchSize {
				quantum = a.cfg.ClaimBatchSize
			}
			roundClaimed := 0
			for _, proj := range ordered {
				if ctx.Err() != nil || a.workGate.Free() <= 0 {
					return
				}
				roundClaimed += a.scanProjectWithLimit(ctx, proj, quantum)
			}
			if roundClaimed == 0 {
				return
			}
		}
	default:
		// Legacy randomized order.
		shuffled := append([]string(nil), ids...)
		rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		for _, proj := range shuffled {
			if ctx.Err() != nil || a.workGate.Free() <= 0 {
				return
			}
			a.scanProject(ctx, proj)
		}
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

// mediaAffinityKey delegates to transfer.MediaAffinityKey so dispatch nodes and receiver nodes
// always agree on the canonical asset-group stem (e.g. "<video_id>.opus" == "<video_id>.info.json").
func mediaAffinityKey(filename string) string {
	return transfer.MediaAffinityKey(filename)
}

func (a *Agent) chooseDestDir(projectID, filename string, fileSize int64) string {
	dirs := a.enabledDestDirsFor(projectID)
	if len(dirs) == 0 {
		return ""
	}
	if len(dirs) == 1 {
		return dirs[0]
	}

	need := uint64(0)
	if fileSize > 0 {
		need = uint64(fileSize)
	}
	fits := func(d string) bool {
		free := a.availableDiskFor(d)
		if free == 0 {
			return false
		}
		return free >= need
	}
	pickMostFree := func() string {
		bestDir := dirs[0]
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

	dirSet := make(map[string]struct{}, len(dirs))
	for _, d := range dirs {
		dirSet[d] = struct{}{}
	}
	dirEligible := func(d string) bool {
		if _, ok := dirSet[d]; !ok {
			return false
		}
		return fits(d)
	}

	affEnabled := a.effectiveDiskAffinity()
	var stemKey string
	if affEnabled {
		stemKey = projectID + "\x00" + mediaAffinityKey(filename)
		// Universal asset-group affinity across ALL disk policies:
		// if a sibling file (.m4a / .info.json / .srt) already chose a healthy disk with headroom, reuse it.
		if cached := a.lookupStemDisk(stemKey); cached != "" && dirEligible(cached) {
			return cached
		}
	}

	var chosen string
	switch a.effectiveDiskPolicy() {
	case protocol.DiskPolicyMostFree:
		chosen = pickMostFree()
	case protocol.DiskPolicyRoundRobin:
		start := int((a.diskRRIdx.Add(1) - 1) % uint64(len(dirs)))
		for i := range dirs {
			cand := dirs[(start+i)%len(dirs)]
			if fits(cand) {
				chosen = cand
				break
			}
		}
		if chosen == "" {
			chosen = pickMostFree()
		}
	case protocol.DiskPolicyFirst:
		for _, cand := range dirs {
			if fits(cand) {
				chosen = cand
				break
			}
		}
		if chosen == "" {
			chosen = pickMostFree()
		}
	case protocol.DiskPolicyRollingWindow:
		// Sliding active window: concurrently fill the first N healthy non-full disks in order.
		// Once any disk hits the mandatory watermark (or is disabled/detached), disk N+1 automatically slides in.
		winSize := a.effectiveActiveDiskWindow()
		if winSize > len(dirs) {
			winSize = len(dirs)
		}
		activeWin := make([]string, 0, winSize)
		for _, cand := range dirs {
			if fits(cand) {
				activeWin = append(activeWin, cand)
				if len(activeWin) >= winSize {
					break
				}
			}
		}
		if len(activeWin) == 0 {
			chosen = pickMostFree()
		} else if len(activeWin) == 1 {
			chosen = activeWin[0]
		} else if affEnabled {
			h := fnv.New32a()
			_, _ = h.Write([]byte(mediaAffinityKey(filename)))
			chosen = activeWin[int(h.Sum32()%uint32(len(activeWin)))]
		} else {
			idx := int((a.diskRRIdx.Add(1) - 1) % uint64(len(activeWin)))
			chosen = activeWin[idx]
		}
	default:
		// Legacy "affinity_hash" (balanced distribution): hash by stem when affinity is enabled,
		// or pure round-robin when affinity is explicitly turned off.
		if affEnabled {
			h := fnv.New32a()
			_, _ = h.Write([]byte(mediaAffinityKey(filename)))
			primaryIdx := int(h.Sum32() % uint32(len(dirs)))
			if fits(dirs[primaryIdx]) {
				chosen = dirs[primaryIdx]
			} else {
				chosen = pickMostFree()
			}
		} else {
			start := int((a.diskRRIdx.Add(1) - 1) % uint64(len(dirs)))
			for i := range dirs {
				cand := dirs[(start+i)%len(dirs)]
				if fits(cand) {
					chosen = cand
					break
				}
			}
			if chosen == "" {
				chosen = pickMostFree()
			}
		}
	}

	if affEnabled && chosen != "" {
		chosen = a.rememberOrGetStemDisk(stemKey, chosen, dirEligible)
	}
	return chosen
}

func (a *Agent) availableDiskForProject(projectID string) uint64 {
	var best uint64
	for _, dir := range a.enabledDestDirsFor(projectID) {
		if free := a.availableDiskFor(dir); free > best {
			best = free
		}
	}
	return best
}

func (a *Agent) markPeerDead(nodeID string, dur time.Duration) {
	if nodeID == "" {
		return
	}
	a.peerMu.Lock()
	if a.peerCooldown == nil {
		a.peerCooldown = make(map[string]time.Time)
	}
	a.peerCooldown[nodeID] = time.Now().Add(dur)
	a.peerMu.Unlock()
}

func (a *Agent) clearPeerDead(nodeID string) {
	if nodeID == "" {
		return
	}
	a.peerMu.Lock()
	delete(a.peerCooldown, nodeID)
	a.peerMu.Unlock()
}

func (a *Agent) isPeerDead(nodeID string) bool {
	if nodeID == "" {
		return false
	}
	a.peerMu.Lock()
	until, ok := a.peerCooldown[nodeID]
	if ok && time.Now().After(until) {
		delete(a.peerCooldown, nodeID)
		ok = false
	}
	a.peerMu.Unlock()
	return ok
}

func (a *Agent) scanProject(ctx context.Context, projectID string) {
	a.scanProjectWithLimit(ctx, projectID, 0)
}

func (a *Agent) scanProjectWithLimit(ctx context.Context, projectID string, maxSlots int) int {
	if !a.isProjectAllowed(projectID) {
		return 0
	}
	dirs := a.enabledDestDirsFor(projectID)
	if len(dirs) == 0 {
		return 0
	}
	if a.workGate.Free() <= 0 {
		return 0
	}

	disc, err := a.discoverCached(ctx, projectID)
	if err != nil {
		a.logger.Warn("discover failed", "project", projectID, "err", err)
		return 0
	}
	if len(disc.Candidates) == 0 {
		return 0
	}

	totalClaimed := 0
	for idx, cand := range disc.Candidates {
		if a.isPeerDead(cand.ANodeID) {
			continue
		}
		for {
			if ctx.Err() != nil {
				return totalClaimed
			}
			limit := a.cfg.ClaimBatchSize
			if maxSlots > 0 {
				rem := maxSlots - totalClaimed
				if rem <= 0 {
					return totalClaimed
				}
				if rem < limit {
					limit = rem
				}
			}
			// Reserve up to limit worker slots upfront without blocking.
			reserved := 0
			for reserved < limit && a.workGate.TryAcquire() {
				reserved++
			}
			if reserved == 0 {
				return totalClaimed
			}
			releaseSlots := func(n int) {
				for i := 0; i < n; i++ {
					a.workGate.Release()
				}
			}

			availDisk := a.availableDiskForProject(projectID)
			if availDisk == 0 {
				releaseSlots(reserved)
				a.logger.Warn("no healthy disk space above mandatory watermark, skipping claim", "project", projectID, "dest_dirs", dirs)
				return totalClaimed
			}

			claimed, status, err := a.claimBatchFromA(ctx, cand, projectID, availDisk, disc.LeaseTTLSec, reserved)
			if err != nil {
				releaseSlots(reserved)
				a.markPeerDead(cand.ANodeID, 15*time.Second)
				a.invalidateDiscover(projectID)
				a.logger.Warn("claim from dispatch node failed, isolating unreachable peer", "a_node", cand.ANodeID, "err", err)
				// Only apply backoff/adaptive error if no other healthy candidates remain in this scan.
				hasHealthyOther := false
				for _, other := range disc.Candidates[idx+1:] {
					if !a.isPeerDead(other.ANodeID) {
						hasHealthyOther = true
						break
					}
				}
				if !hasHealthyOther {
					a.adaptive.RecordError()
					timer := time.NewTimer(1 * time.Second)
					select {
					case <-ctx.Done():
						timer.Stop()
						return totalClaimed
					case <-timer.C:
					}
				}
				break
			}
			a.clearPeerDead(cand.ANodeID)
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

			dls := make([]ActiveDownload, 0, len(claimed))
			var skippedSlots int
			for _, cr := range claimed {
				destDir := a.chooseDestDir(projectID, cr.Filename, cr.Size)
				if destDir == "" {
					skippedSlots++
					continue
				}
				_ = a.ensureDestDirReady(destDir, projectID)
				partPath := filepath.Join(a.stagingDirFor(destDir, projectID), cr.FileID+".part")
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
			if skippedSlots > 0 {
				releaseSlots(skippedSlots)
			}
			if len(dls) == 0 {
				break
			}

			if err := a.store.PutActiveBatch(dls); err != nil {
				releaseSlots(len(dls))
				a.logger.Error("persist active batch failed", "count", len(dls), "err", err)
				for _, dl := range dls {
					_ = a.sendNack(ctx, dl, "local state persist failed")
				}
				return totalClaimed
			}

			totalClaimed += len(dls)
			for _, dl := range dls {
				a.wg.Add(1)
				go func(item ActiveDownload) {
					defer func() {
						a.workGate.Release()
						a.wg.Done()
						// Immediately check for more queued files on completion.
						if a.effectiveProjectSchedule() == protocol.ScheduleRandom {
							a.triggerWakeup(item.ProjectID)
						} else {
							a.triggerWakeup("")
						}
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
	if totalClaimed == 0 {
		// All cached candidates were empty -> clear cache so next poll/wakeup sees fresh A nodes.
		a.invalidateDiscover(projectID)
	}
	return totalClaimed
}

func (a *Agent) availableDiskFor(dir string) uint64 {
	root := a.diskRootForDestDir(dir)
	if a.isDiskRootDisabled(root) || a.diskHealth.IsBlocked(root) {
		return 0
	}
	maxPct := a.effectiveMaxDiskUsagePct()
	probe := a.diskHealth.ProbeRoot(root, true, maxPct, a.cfg.MinFreeDiskBytes, 0)
	if probe.Detached || probe.UnplugLatched || !probe.Mounted || !probe.Writable {
		a.evictReadyDirsForRoot(root)
		return 0
	}
	usable, _ := transfer.MandatoryWatermarkFree(probe.TotalBytes, probe.FreeBytes, maxPct, a.cfg.MinFreeDiskBytes)
	return usable
}

func (a *Agent) discover(ctx context.Context, projectID string) (*protocol.DiscoverResp, error) {
	u := strings.TrimRight(a.cfg.CenterURL, "/") + "/api/v1/b/discover?project=" + url.QueryEscape(projectID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(protocol.HeaderNodeID, a.cfg.NodeID)
	req.Header.Set(protocol.HeaderNodeToken, a.cfg.CenterToken)

	resp, err := a.doAPI(req)
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

	resp, err := a.doAPI(req)
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

	resp, err := a.doAPI(req)
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

	a.activeCount.Add(1)
	defer a.activeCount.Add(-1)

	diskRoot := a.diskRootForDestDir(dl.DestDir)
	a.diskHealth.BeginIO(diskRoot)
	defer a.diskHealth.EndIO(diskRoot)

	// Background lease renewer so even slow SHA256 hashing or brief reconnects never lose the lease.
	renewCtx, stopRenew := context.WithCancel(ctx)
	defer stopRenew()
	go a.leaseRenewLoop(renewCtx, &dl)

	if err := a.diskHealth.SafeMkdirAll(diskRoot, filepath.Dir(dl.PartPath), !a.isDiskRootDisabled(diskRoot)); err != nil {
		a.logger.Error("create tmp dir failed (disk unavailable)", "root", diskRoot, "err", err)
		a.evictReadyDirsForRoot(diskRoot)
		a.triggerHeartbeat()
		_ = a.store.DeleteActive(dl.FileID)
		_ = a.sendNack(ctx, dl, "dest disk unavailable: "+err.Error())
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
		pipelinedSHA, statusCode, chunkErr := a.downloadChunked(ctx, dl)
		if chunkErr != nil {
			if ctx.Err() != nil {
				// Preserve .part and .part.bitmap so restart resumes only unfinished chunks!
				return
			}
			if errors.Is(chunkErr, errPeerDraining) {
				a.logger.Warn("dispatch node shutting down during chunked download, releasing slot cleanly", "file_id", dl.FileID, "a_node", dl.ANodeID)
				a.markPeerDead(dl.ANodeID, 20*time.Second)
				a.invalidateDiscover(dl.ProjectID)
				_ = os.Remove(dl.PartPath)
				_ = os.Remove(bitmapPath)
				_ = a.store.DeleteActive(dl.FileID)
				return
			}
			if statusCode == http.StatusConflict || statusCode == http.StatusNotFound || statusCode == http.StatusGone {
				a.logger.Warn("lease expired or file gone on A during chunked download, abandoning", "file_id", dl.FileID, "status", statusCode)
				_ = os.Remove(dl.PartPath)
				_ = os.Remove(bitmapPath)
				_ = a.store.DeleteActive(dl.FileID)
				return
			}
			if a.handleLocalDiskErr(diskRoot, chunkErr) {
				_ = os.Remove(dl.PartPath)
				_ = os.Remove(bitmapPath)
				_ = a.store.DeleteActive(dl.FileID)
				_ = a.sendNack(ctx, dl, "receiver disk detached/io fault")
				return
			}
			if !dl.LeaseExpiresAt.IsZero() && time.Now().After(dl.LeaseExpiresAt) {
				a.logger.Warn("chunked download failed past lease expiry, releasing slot", "file_id", dl.FileID, "a_node", dl.ANodeID, "err", chunkErr)
				a.markPeerDead(dl.ANodeID, 15*time.Second)
				a.invalidateDiscover(dl.ProjectID)
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

	const maxConsecutiveNoProgress = 5
	consecutiveNoProgress := 0
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
		if partExists && offset == dl.Size {
			break
		}
		if offset > 0 {
			resumed = true
		}

		writtenNow, shaIfZero, statusCode, streamErr := a.streamOnce(ctx, dl, offset)
		if streamErr == nil {
			if offset == 0 && !resumed && shaIfZero != "" {
				continuousSHA = shaIfZero
			}
			// Check if we now have all bytes.
			if st, err := os.Stat(dl.PartPath); err == nil && st.Size() == dl.Size {
				break
			}
		}

		// Graceful shutdown on dispatch node: release slot immediately without hurting adaptive concurrency.
		if errors.Is(streamErr, errPeerDraining) {
			a.logger.Warn("dispatch node shutting down, releasing worker slot cleanly", "file_id", dl.FileID, "a_node", dl.ANodeID)
			a.markPeerDead(dl.ANodeID, 20*time.Second)
			a.invalidateDiscover(dl.ProjectID)
			_ = os.Remove(dl.PartPath)
			_ = a.store.DeleteActive(dl.FileID)
			return
		}
		// Lease expired or file already gone on A: abandon cleanly & remove stale .part.
		if statusCode == http.StatusConflict || statusCode == http.StatusNotFound || statusCode == http.StatusGone {
			a.logger.Warn("lease expired or file gone on A, abandoning", "file_id", dl.FileID, "status", statusCode)
			_ = os.Remove(dl.PartPath)
			_ = a.store.DeleteActive(dl.FileID)
			return
		}
		// Local destination disk unplugged or I/O fault: immediately abort and NACK so source is preserved & retried on another healthy disk.
		if streamErr != nil && a.handleLocalDiskErr(diskRoot, streamErr) {
			_ = os.Remove(dl.PartPath)
			_ = a.store.DeleteActive(dl.FileID)
			_ = a.sendNack(ctx, dl, "receiver disk detached/io fault")
			return
		}

		if writtenNow > 0 {
			// Progress made before network drop -> reset backoff and record resume.
			consecutiveNoProgress = 0
			backoff = 250 * time.Millisecond
			resumed = true
			a.ResumeCount.Add(1)
			a.logger.Warn("stream interrupted mid-transfer, will resume", "file_id", dl.FileID, "offset", offset+writtenNow, "total", dl.Size, "err", streamErr)
		} else {
			consecutiveNoProgress++
			// If the dispatch server powered off or became unreachable, bound retries so worker slots
			// are freed promptly for healthy dispatch nodes (un-ACKed file stays safe on dispatch disk).
			if consecutiveNoProgress >= maxConsecutiveNoProgress || (!dl.LeaseExpiresAt.IsZero() && time.Now().After(dl.LeaseExpiresAt)) {
				a.logger.Warn("dispatch node unreachable after retries, releasing worker slot to protect other downloads",
					"file_id", dl.FileID, "a_node", dl.ANodeID, "attempts", consecutiveNoProgress, "err", streamErr)
				a.markPeerDead(dl.ANodeID, 15*time.Second)
				a.invalidateDiscover(dl.ProjectID)
				_ = os.Remove(dl.PartPath)
				_ = a.store.DeleteActive(dl.FileID)
				return
			}
			a.logger.Warn("stream error, retrying with backoff", "file_id", dl.FileID, "attempt", consecutiveNoProgress, "backoff", backoff, "err", streamErr)
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
			a.handleLocalDiskErr(diskRoot, err)
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
		targetDir := filepath.Dir(targetPath)
		allowCreate := !a.isDiskRootDisabled(diskRoot)
		if err := a.diskHealth.SafeMkdirAll(diskRoot, targetDir, allowCreate); err != nil {
			a.commitMu.Unlock()
			a.handleLocalDiskErr(diskRoot, err)
			a.logger.Error("mkdir target parent failed", "err", err)
			_ = os.Remove(dl.PartPath)
			_ = a.store.DeleteActive(dl.FileID)
			_ = a.sendNack(ctx, dl, "mkdir target failed")
			return
		}
		if err := os.Chmod(dl.PartPath, 0o644); err != nil {
			a.logger.Warn("chmod target part file failed", "path", dl.PartPath, "err", err)
		}
		renameErr := os.Rename(dl.PartPath, targetPath)
		if renameErr != nil && errors.Is(renameErr, os.ErrNotExist) {
			// Guard against the tiny race where an external consumer removes/moves the project
			// directory between SafeMkdirAll and os.Rename: if our staged .part file is still
			// intact, recreate targetDir once and retry the atomic rename.
			if _, statErr := os.Stat(dl.PartPath); statErr == nil {
				if mkErr := a.diskHealth.SafeMkdirAll(diskRoot, targetDir, allowCreate); mkErr == nil {
					renameErr = os.Rename(dl.PartPath, targetPath)
				}
			}
		}
		if renameErr != nil {
			a.commitMu.Unlock()
			a.handleLocalDiskErr(diskRoot, renameErr)
			a.logger.Error("atomic rename failed", "src", dl.PartPath, "dst", targetPath, "err", renameErr)
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

	a.adaptive.RecordCompleted()
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
		// Temp resume bitmap is deleted right after commit; avoid extra HDD fsync barriers here.
		_ = cb.f.Close()
	}
}

func (a *Agent) downloadChunked(ctx context.Context, dl ActiveDownload) (string, int, error) {
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
		completedBytes int64
		pendingCount   int
	)
	for i := 0; i < numChunks; i++ {
		start := int64(i) * chunkSize
		end := start + chunkSize - 1
		if end >= dl.Size {
			end = dl.Size - 1
		}
		if bm.isDone(i) {
			completedBytes += end - start + 1
		} else {
			pendingCount++
		}
	}
	if resumed && completedBytes > 0 {
		a.ResumeCount.Add(1)
		a.logger.Info("resuming chunked download from bitmap", "file_id", dl.FileID, "done_bytes", completedBytes, "total_bytes", dl.Size, "pending_chunks", pendingCount)
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
	// directly from bounded in-RAM buffers (zero disk readback on spinning HDDs and 10Gbps NVMe!),
	// falling back to SectionReader only if out-of-order lag exceeds the 32MiB RAM cache budget.
	type hashedChunk struct {
		idx  int
		data []byte // nil if omitted to stay within RAM budget
	}
	var (
		hashCh       chan hashedChunk
		hashDone     chan struct{}
		pipelinedSHA string
		hashErr      error
	)
	const maxGlobalHashRAM = 512 << 20
	if !resumed {
		chCap := numChunks
		if chCap > 256 {
			chCap = 256
		}
		hashCh = make(chan hashedChunk, chCap)
		hashDone = make(chan struct{})
		go func() {
			defer close(hashDone)
			ready := make([]bool, numChunks)
			cached := make([][]byte, numChunks)
			defer func() {
				// Release any remaining budgeted RAM on early exit/cancel.
				for i, mem := range cached {
					if mem != nil {
						a.hashRAMBytes.Add(-int64(len(mem)))
						cached[i] = nil
					}
				}
			}()
			nextIdx := 0
			h := sha256.New()
			bufPtr := transfer.GetBuf()
			defer transfer.PutBuf(bufPtr)
			buf := *bufPtr

			for item := range hashCh {
				ready[item.idx] = true
				cached[item.idx] = item.data
				for nextIdx < numChunks && ready[nextIdx] {
					if chunkCtx.Err() != nil {
						return
					}
					if mem := cached[nextIdx]; mem != nil {
						_, _ = h.Write(mem)
						cached[nextIdx] = nil
						a.hashRAMBytes.Add(-int64(len(mem)))
					} else {
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
				var memBuf []byte
				cLen := rg.end - rg.start + 1
				if hashCh != nil && cLen <= 16<<20 && a.hashRAMBytes.Add(cLen) <= maxGlobalHashRAM {
					memBuf = make([]byte, cLen)
				} else if hashCh != nil && cLen <= 16<<20 {
					a.hashRAMBytes.Add(-cLen)
				}
				status, err := a.fetchRangeWithRetry(chunkCtx, dl, f, rg.start, rg.end, memBuf)
				if err != nil {
					if memBuf != nil {
						a.hashRAMBytes.Add(-int64(len(memBuf)))
					}
					recordErr(status, err)
					return
				}
				bm.markDone(rg.idx)
				if hashCh != nil {
					select {
					case hashCh <- hashedChunk{idx: rg.idx, data: memBuf}:
					case <-chunkCtx.Done():
						if memBuf != nil {
							a.hashRAMBytes.Add(-int64(len(memBuf)))
						}
					case <-hashDone:
						if memBuf != nil {
							a.hashRAMBytes.Add(-int64(len(memBuf)))
						}
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
		if a.cfg.AckBatchIntervalMs <= 0 {
			_ = f.Sync()
		}
		_ = f.Close()
		return "", firstStatus, firstErr
	}
	// When AckBatchIntervalMs > 0, durability is guaranteed by a batched filesystem-level SyncFS
	// right before sending batch-ack, avoiding 20-30x/sec per-file fsync barriers on HDDs.
	if a.cfg.AckBatchIntervalMs <= 0 {
		if err := f.Sync(); err != nil {
			_ = f.Close()
			return "", 0, err
		}
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

func (a *Agent) fetchRangeWithRetry(ctx context.Context, dl ActiveDownload, f *os.File, start, end int64, memBuf []byte) (int, error) {
	u := strings.TrimRight(dl.PublicAddr, "/") + "/api/v1/files/" + url.PathEscape(dl.FileID) + "/stream"
	cur := start
	backoff := 200 * time.Millisecond

	for attempt := 0; attempt < 8; attempt++ {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		if err := a.streamGate.Acquire(ctx); err != nil {
			return 0, err
		}

		// Per-attempt stall & slow-flow watchdog: if a single WAN TCP flow stalls for >12s
		// OR degrades below 32 KB/s after 10s (ISP per-flow policer), abort this range attempt
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
					if a.limiter == nil || a.limiter.Rate() <= 0 {
						if elapsed := time.Since(attemptStart); elapsed > 10*time.Second {
							if float64(attemptBytes.Load())/elapsed.Seconds() < 32*1024 {
								reqCancel()
								return
							}
						}
					}
				}
			}
		}()

		var subMem []byte
		if memBuf != nil {
			subMem = memBuf[cur-start:]
		}
		written, status, streamErr := a.streamRangeOnce(reqCtx, u, dl.LeaseToken, f, cur, end, subMem, &lastActivity, &attemptBytes)
		close(watchDone)
		reqCancel()
		a.streamGate.Release()

		cur += written
		if streamErr == nil && cur > end {
			return http.StatusPartialContent, nil
		}
		if errors.Is(streamErr, errPeerDraining) {
			return status, errPeerDraining
		}
		if status == http.StatusServiceUnavailable {
			a.adaptive.RecordBackpressure()
		} else if streamErr != nil && ctx.Err() == nil && status != http.StatusConflict && status != http.StatusNotFound && status != http.StatusGone {
			a.adaptive.RecordError()
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

func (a *Agent) streamRangeOnce(ctx context.Context, streamURL, leaseToken string, f *os.File, start, end int64, memBuf []byte, lastActivity *atomic.Int64, attemptBytes *atomic.Int64) (int64, int, error) {
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
		if resp.Header.Get(protocol.HeaderDraining) == "1" {
			return 0, resp.StatusCode, errPeerDraining
		}
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
				if memBuf != nil && written+int64(nw) <= int64(len(memBuf)) {
					copy(memBuf[written:written+int64(nw)], buf[:nw])
				}
				written += int64(nw)
				attemptBytes.Add(int64(nw))
				a.adaptive.RecordBytes(int64(nw))
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

func (a *Agent) streamOnce(ctx context.Context, dl ActiveDownload, offset int64) (written int64, shaFromZero string, statusCode int, err error) {
	if acqErr := a.streamGate.Acquire(ctx); acqErr != nil {
		return 0, "", 0, acqErr
	}
	defer a.streamGate.Release()

	reqCtx, reqCancel := context.WithCancel(ctx)
	defer reqCancel()
	attemptStart := time.Now()
	var lastActivity atomic.Int64
	var attemptBytes atomic.Int64
	lastActivity.Store(attemptStart.UnixNano())
	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-watchDone:
				return
			case <-reqCtx.Done():
				return
			case <-t.C:
				if time.Since(time.Unix(0, lastActivity.Load())) > 10*time.Second {
					reqCancel()
					return
				}
				if a.limiter == nil || a.limiter.Rate() <= 0 {
					if elapsed := time.Since(attemptStart); elapsed > 10*time.Second {
						if float64(attemptBytes.Load())/elapsed.Seconds() < 32*1024 {
							reqCancel()
							return
						}
					}
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
		if ctx.Err() == nil {
			a.adaptive.RecordError()
		}
		return 0, "", 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		if resp.Header.Get(protocol.HeaderDraining) == "1" {
			return 0, "", resp.StatusCode, errPeerDraining
		}
		if resp.StatusCode == http.StatusServiceUnavailable {
			a.adaptive.RecordBackpressure()
		} else if resp.StatusCode >= 500 {
			a.adaptive.RecordError()
		}
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

	syncPartOnErr := func() {
		if a.cfg.AckBatchIntervalMs <= 0 {
			_ = f.Sync()
		}
	}

	for {
		if err := reqCtx.Err(); err != nil {
			syncPartOnErr()
			return written, "", resp.StatusCode, err
		}
		nr, rErr := resp.Body.Read(buf)
		if nr > 0 {
			lastActivity.Store(time.Now().UnixNano())
			if a.limiter != nil {
				if err := a.limiter.Wait(reqCtx, nr); err != nil {
					syncPartOnErr()
					return written, "", resp.StatusCode, err
				}
			}
			nw, wErr := f.Write(buf[:nr])
			if nw > 0 {
				if hasher != nil {
					_, _ = hasher.Write(buf[:nw])
				}
				written += int64(nw)
				attemptBytes.Add(int64(nw))
				a.adaptive.RecordBytes(int64(nw))
			}
			if wErr != nil {
				syncPartOnErr()
				return written, "", resp.StatusCode, wErr
			}
			if nw != nr {
				syncPartOnErr()
				return written, "", resp.StatusCode, io.ErrShortWrite
			}
		}
		if rErr == io.EOF {
			if a.cfg.AckBatchIntervalMs <= 0 {
				if err := f.Sync(); err != nil {
					return written, "", resp.StatusCode, err
				}
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
			resp, err := a.doAPI(req)
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

	resp, err := a.doAPI(req)
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
	resp, err := a.doAPI(req)
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

	resp, err := a.doAPI(req)
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

func (a *Agent) shouldRetryAckPeer(pubAddr string, now time.Time) bool {
	a.peerMu.Lock()
	defer a.peerMu.Unlock()
	if a.ackPeerBackoff == nil {
		return true
	}
	st, ok := a.ackPeerBackoff[pubAddr]
	return !ok || !now.Before(st.nextRetry)
}

func (a *Agent) recordAckPeerResult(pubAddr string, ok bool) {
	a.peerMu.Lock()
	defer a.peerMu.Unlock()
	if a.ackPeerBackoff == nil {
		a.ackPeerBackoff = make(map[string]ackBackoffState)
	}
	if ok {
		delete(a.ackPeerBackoff, pubAddr)
		return
	}
	st := a.ackPeerBackoff[pubAddr]
	st.failures++
	delay := 10 * time.Second
	switch {
	case st.failures == 2:
		delay = 30 * time.Second
	case st.failures == 3:
		delay = 2 * time.Minute
	case st.failures >= 4:
		delay = 5 * time.Minute
	}
	st.nextRetry = time.Now().Add(delay)
	a.ackPeerBackoff[pubAddr] = st
}

func (a *Agent) flushPendingAcks(ctx context.Context) {
	acks, err := a.store.ListPendingAcks()
	if err != nil || len(acks) == 0 {
		a.pendingAckCount.Store(0)
		return
	}

	const maxPendingAckAge = 72 * time.Hour
	now := time.Now()
	var (
		expiredIDs []string
		dueAcks    = make([]PendingAck, 0, len(acks))
	)
	for _, ak := range acks {
		if !ak.CreatedAt.IsZero() && now.Sub(ak.CreatedAt) > maxPendingAckAge {
			expiredIDs = append(expiredIDs, ak.FileID)
			continue
		}
		if !a.shouldRetryAckPeer(ak.PublicAddr, now) {
			continue
		}
		dueAcks = append(dueAcks, ak)
	}
	if len(expiredIDs) > 0 {
		a.logger.Warn("pruning expired pending ACKs for permanently decommissioned dispatch node(s)", "count", len(expiredIDs))
		_ = a.store.DeletePendingAcks(expiredIDs)
	}
	if len(dueAcks) == 0 {
		a.pendingAckCount.Store(int64(a.store.PendingAckCount()))
		return
	}

	// Ensure every destination filesystem containing newly landed files is durably flushed
	// in parallel across mounts (SyncFS flushes ALL dirty data, inodes, and atomic renames
	// on each mount in one barrier) BEFORE confirming batch-ack to Agent A ("没落盘的不准删").
	uniqueDirs := make([]string, 0, 4)
	seenDirs := make(map[string]struct{}, 4)
	for _, ak := range dueAcks {
		if ak.DestDir == "" {
			continue
		}
		if _, ok := seenDirs[ak.DestDir]; !ok {
			seenDirs[ak.DestDir] = struct{}{}
			uniqueDirs = append(uniqueDirs, ak.DestDir)
		}
	}
	failedDirs := make(map[string]bool)
	if len(uniqueDirs) > 0 {
		var (
			syncWG sync.WaitGroup
			failMu sync.Mutex
		)
		for _, dir := range uniqueDirs {
			syncWG.Add(1)
			go func(d string) {
				defer syncWG.Done()
				err := transfer.SyncFS(d)
				if err != nil && errors.Is(err, os.ErrNotExist) {
					// Project dir may have been moved/removed right after commit; flush the
					// underlying storage root on the same mount so the filesystem is still synced.
					if root := a.diskRootForDestDir(d); root != "" && filepath.Clean(root) != filepath.Clean(d) {
						err = transfer.SyncFS(root)
					}
				}
				if err != nil {
					a.handleLocalDiskErr(a.diskRootForDestDir(d), err)
					a.logger.Warn("syncfs dest dir failed, deferring ACK", "dir", d, "err", err)
					failMu.Lock()
					failedDirs[d] = true
					failMu.Unlock()
				}
			}(dir)
		}
		syncWG.Wait()
	}

	// Group durable ACKs by dispatch node address and flush ALL peers in parallel so one
	// powered-off or unreachable dispatch server NEVER blocks ACKs to healthy dispatch servers.
	byAddr := make(map[string][]PendingAck)
	for _, ak := range dueAcks {
		if ak.DestDir != "" && failedDirs[ak.DestDir] {
			continue
		}
		byAddr[ak.PublicAddr] = append(byAddr[ak.PublicAddr], ak)
	}

	var (
		allDoneMu sync.Mutex
		allDone   []string
		peerWG    sync.WaitGroup
	)
	const maxChunk = 128
	for pubAddr, group := range byAddr {
		peerWG.Add(1)
		go func(addr string, items []PendingAck) {
			defer peerWG.Done()
			peerFailed := false
			var peerDone []string
			for start := 0; start < len(items); start += maxChunk {
				if ctx.Err() != nil {
					break
				}
				end := start + maxChunk
				if end > len(items) {
					end = len(items)
				}
				chunk := items[start:end]
				reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				doneIDs, fallback, err := a.sendBatchAck(reqCtx, addr, chunk)
				cancel()
				if err != nil {
					peerFailed = true
					a.logger.Warn("batch-ack failed, backing off unreachable dispatch peer", "public_addr", addr, "count", len(chunk), "err", err)
					break // stop hammering remaining chunks on this unreachable peer
				}
				if fallback {
					for _, ak := range chunk {
						if ctx.Err() != nil {
							break
						}
						sCtx, sCancel := context.WithTimeout(ctx, 10*time.Second)
						sErr := a.sendAck(sCtx, ak)
						sCancel()
						if sErr == nil {
							peerDone = append(peerDone, ak.FileID)
						} else {
							peerFailed = true
							break
						}
					}
					if peerFailed {
						break
					}
					continue
				}
				peerDone = append(peerDone, doneIDs...)
			}
			a.recordAckPeerResult(addr, !peerFailed)
			if len(peerDone) > 0 {
				allDoneMu.Lock()
				allDone = append(allDone, peerDone...)
				allDoneMu.Unlock()
			}
		}(pubAddr, group)
	}
	peerWG.Wait()

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
	roots := a.diskRoots()
	disks := make([]protocol.DiskStatus, 0, len(roots))
	var totalDisk, freeDisk uint64
	var usedPct float64
	seenEnabledDev := make(map[uint64]struct{})
	seenAllDev := make(map[uint64]struct{})
	var allTotal, allFree uint64

	a.dirMu.RLock()
	enabledByRoot := make(map[string]bool, len(roots))
	for _, root := range roots {
		enabledByRoot[root] = !a.isDiskRootDisabledLocked(root)
	}
	a.dirMu.RUnlock()

	diskPol := a.effectiveDiskPolicy()
	activeWinSize := a.effectiveActiveDiskWindow()
	activeWinUsed := 0

	maxPct := a.effectiveMaxDiskUsagePct()
	for _, root := range roots {
		enabled := enabledByRoot[root]
		probe := a.diskHealth.ProbeRoot(root, enabled, maxPct, a.cfg.MinFreeDiskBytes, 0)
		if probe.Detached || probe.UnplugLatched {
			a.evictReadyDirsForRoot(root)
		}
		role := "active"
		reason := probe.StatusReason
		switch {
		case probe.Detached:
			role = "detached"
		case probe.UnplugLatched:
			role = "locked"
		case !enabled:
			role = "disabled"
		case probe.LowSpace:
			role = "full"
			if probe.InFlight == 0 {
				reason = "已写满水位（在途 0）· 停用即可安全拔盘"
			} else {
				reason = fmt.Sprintf("已写满水位（在途 %d 收尾中）", probe.InFlight)
			}
		default:
			if diskPol == protocol.DiskPolicyRollingWindow {
				activeWinUsed++
				if activeWinUsed <= activeWinSize {
					role = "active"
					reason = fmt.Sprintf("写入窗口中 (%d/%d)", activeWinUsed, activeWinSize)
				} else {
					role = "standby"
					reason = "候补排队中（前序盘满自动顶上）"
				}
			} else {
				role = "active"
			}
		}
		disks = append(disks, protocol.DiskStatus{
			Path:          root,
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
			DiskRole:      role,
			StatusReason:  reason,
		})
		if probe.Mounted && !probe.Detached {
			devKey := probe.DevID
			hasDev := probe.HasDev
			if !hasDev || func() bool { _, dup := seenAllDev[devKey]; return !dup }() {
				if hasDev {
					seenAllDev[devKey] = struct{}{}
				}
				allTotal += probe.TotalBytes
				allFree += probe.FreeBytes
			}
			if enabled && !probe.UnplugLatched && (!hasDev || func() bool { _, dup := seenEnabledDev[devKey]; return !dup }()) {
				if hasDev {
					seenEnabledDev[devKey] = struct{}{}
				}
				totalDisk += probe.TotalBytes
				freeDisk += probe.FreeBytes
			}
		}
	}

	if totalDisk == 0 && allTotal > 0 {
		totalDisk = allTotal
		freeDisk = allFree
	}
	if totalDisk > 0 {
		usedPct = (float64(totalDisk-freeDisk) / float64(totalDisk)) * 100.0
	}

	upgAttempt, upgStatus, upgErr := "", "", ""
	if a.updater != nil {
		upgAttempt, upgStatus, upgErr = a.updater.Status()
	}

	var snap AdaptiveSnapshot
	if a.adaptive != nil {
		snap = a.adaptive.Snapshot()
	}
	var effRateMBps float64
	if a.limiter != nil && a.limiter.Rate() > 0 {
		effRateMBps = float64(a.limiter.Rate()) / (1024 * 1024)
	}

	diskAff := a.effectiveDiskAffinity()
	payload := protocol.AgentBHeartbeatReq{
		NodeID:              a.cfg.NodeID,
		Name:                a.cfg.NodeName,
		Projects:            a.activeProjectIDs(),
		StorageDirs:         a.effectiveStorageDirs(),
		Disks:               disks,
		HostDisks:           a.cachedHostDisks(),
		ProjectSchedule:     a.effectiveProjectSchedule(),
		DiskPolicy:          diskPol,
		DiskAffinity:        &diskAff,
		ActiveDiskWindow:    activeWinSize,
		ConcurrencyMode:     snap.Mode,
		EffectiveConcurrent: snap.EffectiveConcurrent,
		MaxConcurrentCap:    snap.MaxConcurrentCap,
		EffectiveStreams:    snap.EffectiveStreams,
		EffectiveRateMBps:   effRateMBps,
		AdaptiveState:       snap.State,
		AdaptiveReason:      snap.Reason,
		Version:             version.Version,
		OS:               runtime.GOOS,
		Arch:             runtime.GOARCH,
		UpgradeAttemptID: upgAttempt,
		UpgradeStatus:    upgStatus,
		UpgradeError:     upgErr,
		DiskTotalBytes:   totalDisk,
		DiskFreeBytes:    freeDisk,
		DiskUsedPct:      usedPct,
		MaxDiskUsagePct:  maxPct,
		AwaitingDisk:     a.awaitingDisk(),
		Paused:           a.paused.Load(),
		ActiveCount:      int(a.activeCount.Load()),
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

	resp, err := a.doAPI(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return
	}
	var hbResp protocol.HeartbeatResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256*1024)).Decode(&hbResp); err == nil {
		a.setPaused(hbResp.Paused || (hbResp.Directive != nil && hbResp.Directive.Paused))
		a.applyDirective(hbResp.Directive, hbResp.AllowedProjects)
		if hbResp.Upgrade != nil && a.updater != nil {
			a.updater.HandleDirective(ctx, hbResp.Upgrade)
		}
	}
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
