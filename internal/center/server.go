package center

import (
	"context"
	"crypto/tls"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"relay-download/internal/auth"
	"relay-download/internal/deployer"
	"relay-download/internal/pki"
	"relay-download/internal/protocol"
	"relay-download/internal/transfer"
)

var validIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func validateHTTPSAddr(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("public_addr must be a valid https:// URL")
	}
	return nil
}

func sanitizeSingleLine(s string, maxLen int) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s))
	if maxLen > 0 && len(s) > maxLen {
		// Trim safely on UTF-8 rune boundaries.
		runes := []rune(s)
		if len(runes) > maxLen {
			s = string(runes[:maxLen])
		}
	}
	return s
}

func validateSafeDiskPath(p string) error {
	p = strings.TrimSpace(p)
	if len(p) == 0 || len(p) > 256 || !strings.HasPrefix(p, "/") || strings.Contains(p, "..") {
		return fmt.Errorf("invalid disk path %q", p)
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("control characters not allowed in disk path %q", p)
		}
	}
	return nil
}

const strictWebCSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", strictWebCSP)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// checkAdminCSRF blocks cross-site browser requests (especially critical when admin_trusted_cidrs
// enables passwordless console access from an operator's workstation IP).
func checkAdminCSRF(r *http.Request) error {
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
	default:
		return nil
	}
	if sfs := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))); sfs == "cross-site" {
		return errors.New("cross-site admin request blocked")
	}
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || u.Host == "" || !strings.EqualFold(u.Host, r.Host) {
			return errors.New("cross-origin admin request blocked")
		}
	}
	// Reject CORS-safelisted simple content types on state-changing endpoints so malicious pages
	// cannot forge no-cors POSTs with text/plain or form-urlencoded payloads.
	ct := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
	if strings.HasPrefix(ct, "text/plain") || strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		return errors.New("unsupported content-type for admin mutation")
	}
	return nil
}

//go:embed web/*
var embeddedWeb embed.FS

type Server struct {
	cfg          *Config
	store        *Store
	hub          *Hub
	deployer     *deployer.Deployer
	logger       *slog.Logger
	trustedAdmin []netip.Prefix
	httpServer   *http.Server
	ln           net.Listener
	deployMu      sync.RWMutex
	deployTasks   map[string]*protocol.DeployTask
	deployOrder   []string
	knownProjects sync.Map // project_id -> struct{}, caches DB-persisted projects to avoid hot-path SQLite writes
	closeOnce     sync.Once
}

func (s *Server) ensureKnownProjects(ctx context.Context, ids []string, hints map[string]protocol.ProjectAutoHint) {
	var missing []string
	seen := make(map[string]struct{})
	for _, raw := range ids {
		id := strings.TrimSpace(raw)
		if id == "" || !validIDRe.MatchString(id) {
			continue
		}
		if _, ok := s.knownProjects.Load(id); ok {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		missing = append(missing, id)
	}
	if len(missing) == 0 {
		return
	}
	var cleanHints map[string]protocol.ProjectAutoHint
	if len(hints) > 0 {
		cleanHints = make(map[string]protocol.ProjectAutoHint, len(missing))
		for _, id := range missing {
			h, ok := hints[id]
			if !ok {
				continue
			}
			ch := protocol.ProjectAutoHint{
				Name: sanitizeSingleLine(h.Name, 128),
			}
			for _, cid := range h.CustomerIDs {
				cid = strings.TrimSpace(cid)
				if cid != "" && validIDRe.MatchString(cid) {
					ch.CustomerIDs = append(ch.CustomerIDs, cid)
					if len(ch.CustomerIDs) >= 16 {
						break
					}
				}
			}
			if ch.Name != "" || len(ch.CustomerIDs) > 0 {
				cleanHints[id] = ch
			}
		}
	}
	inserted, assigned, missingCustomers, err := s.store.EnsureProjectsWithHints(ctx, missing, cleanHints)
	if err != nil {
		s.logger.Warn("auto-create projects failed", "projects", missing, "err", err)
		return
	}
	for _, id := range missing {
		s.knownProjects.Store(id, struct{}{})
	}
	if len(missingCustomers) > 0 {
		s.logger.Warn("auto-assign skipped unknown or non-customer accounts on project auto-creation", "projects", missing, "missing_customers", missingCustomers)
	}
	if inserted > 0 {
		s.logger.Info("auto-created projects from dispatch activity", "count", inserted, "projects", missing, "assigned_customers", assigned)
	}
}

func New(cfg *Config, logger *slog.Logger) (*Server, error) {
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	trustedPrefixes, err := cfg.ParseAdminTrustedPrefixes()
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	store, err := OpenStore(cfg.DBPath)
	if err != nil {
		return nil, err
	}
	return &Server{
		cfg:          cfg,
		store:        store,
		hub:          NewHub(cfg.NodeOfflineTimeout()),
		trustedAdmin: trustedPrefixes,
		deployer: deployer.New(deployer.Config{
			DefaultSSHKeyPath: cfg.SSHKeyPath,
			CACertPath:        cfg.CACert,
			CAKeyPath:         cfg.CAKey,
			CenterPublicURL:   cfg.PublicURL,
			JWTSecret:         cfg.JWTSecret,
			CenterSecret:      cfg.CenterSecret,
		}),
		logger:      logger.With("component", "center"),
		deployTasks: make(map[string]*protocol.DeployTask),
	}, nil
}

func (s *Server) Store() *Store {
	return s.store
}

func (s *Server) Start(ctx context.Context) error {
	serverTLS, err := pki.ServerTLSConfig(s.cfg.TLSCert, s.cfg.TLSKey)
	if err != nil {
		return err
	}
	rawLn, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen center %s: %w", s.cfg.Listen, err)
	}
	tlsLn := tls.NewListener(rawLn, serverTLS)
	s.ln = tlsLn

	s.httpServer = &http.Server{
		Handler:           s.routes(),
		TLSConfig:         serverTLS,
		ReadHeaderTimeout: 30 * time.Second,
	}

	go s.dedupCleanupLoop(ctx)

	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("center server listening (TLS)", "addr", tlsLn.Addr().String())
		if err := s.httpServer.Serve(tlsLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		return s.Shutdown(context.Background())
	case err := <-errCh:
		_ = s.Shutdown(context.Background())
		return err
	}
}

func (s *Server) Addr() string {
	if s.ln != nil {
		return s.ln.Addr().String()
	}
	return s.cfg.Listen
}

func (s *Server) Shutdown(ctx context.Context) error {
	var err error
	s.closeOnce.Do(func() {
		shCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if s.httpServer != nil {
			_ = s.httpServer.Shutdown(shCtx)
		}
		if s.store != nil {
			err = s.store.Close()
		}
	})
	return err
}

func (s *Server) dedupCleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.store.CleanupOldDedup(ctx, 24*time.Hour); err != nil {
				s.logger.Warn("cleanup dedup failed", "err", err)
			}
			if err := s.store.CleanupOldIntervals(ctx, 31*24*time.Hour); err != nil {
				s.logger.Warn("cleanup interval stats failed", "err", err)
			}
		}
	}
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	// Agent A endpoints
	mux.HandleFunc("POST /api/v1/a/heartbeat", s.requireNode(protocol.RoleAgentA, s.handleAHeartbeat))
	mux.HandleFunc("POST /api/v1/a/events", s.requireNode(protocol.RoleAgentA, s.handleAEvents))

	// Agent B endpoints
	mux.HandleFunc("POST /api/v1/b/heartbeat", s.requireNode(protocol.RoleAgentB, s.handleBHeartbeat))
	mux.HandleFunc("GET /api/v1/b/events", s.requireNode(protocol.RoleAgentB, s.handleBEventsSSE))
	mux.HandleFunc("GET /api/v1/b/discover", s.requireNode(protocol.RoleAgentB, s.handleBDiscover))

	// Shared node release download (Agent A or B pulls its own role's binary over TLS 1.3)
	mux.HandleFunc("GET /api/v1/releases/{id}/download", s.requireNode("", s.handleNodeDownloadRelease))

	// Console & Admin Web UI API (interval/stage summary only; no real-time per-file proxy endpoints)
	// requireConsole permits super-admin and customer accounts (with per-handler RBAC & scoping).
	// requireSuperAdmin strictly forbids customer accounts (HTTP 403).
	mux.HandleFunc("GET /api/v1/admin/overview", s.requireConsole(s.handleAdminOverview))
	mux.HandleFunc("GET /api/v1/admin/projects", s.requireConsole(s.handleAdminListProjects))
	mux.HandleFunc("POST /api/v1/admin/projects", s.requireSuperAdmin(s.handleAdminUpsertProject))
	mux.HandleFunc("PUT /api/v1/admin/projects/{id}/accounts", s.requireSuperAdmin(s.handleAdminAssignProjectAccounts))
	mux.HandleFunc("DELETE /api/v1/admin/projects/{id}", s.requireSuperAdmin(s.handleAdminDeleteProject))
	mux.HandleFunc("GET /api/v1/admin/nodes", s.requireConsole(s.handleAdminListNodes))
	mux.HandleFunc("GET /api/v1/admin/nodes/{id}/disks", s.requireConsole(s.handleAdminGetNodeDisks))
	mux.HandleFunc("POST /api/v1/admin/nodes", s.requireConsole(s.handleAdminCreateNode))
	mux.HandleFunc("PUT /api/v1/admin/nodes/{id}", s.requireConsole(s.handleAdminUpdateNode))
	mux.HandleFunc("DELETE /api/v1/admin/nodes/{id}", s.requireConsole(s.handleAdminDeleteNode))
	mux.HandleFunc("GET /api/v1/admin/stats/intervals", s.requireConsole(s.handleAdminIntervalStats))
	mux.HandleFunc("GET /api/v1/admin/stats/daily", s.requireConsole(s.handleAdminDailyStats))

	// Releases, Batch Upgrades & One-Click Deployment API
	mux.HandleFunc("GET /api/v1/admin/releases", s.requireConsole(s.handleAdminListReleases))
	mux.HandleFunc("POST /api/v1/admin/releases", s.requireSuperAdmin(s.handleAdminUploadRelease))
	mux.HandleFunc("DELETE /api/v1/admin/releases/{id}", s.requireSuperAdmin(s.handleAdminDeleteRelease))
	mux.HandleFunc("POST /api/v1/admin/upgrades", s.requireConsole(s.handleAdminBatchUpgrade))
	mux.HandleFunc("DELETE /api/v1/admin/upgrades/{id}", s.requireConsole(s.handleAdminCancelUpgrade))
	mux.HandleFunc("POST /api/v1/admin/deploy/precheck", s.requireSuperAdmin(s.handleAdminDeployPrecheck))
	mux.HandleFunc("POST /api/v1/admin/deploy/agent-a", s.requireSuperAdmin(s.handleAdminDeployAgentA))
	mux.HandleFunc("GET /api/v1/admin/deploy/tasks", s.requireSuperAdmin(s.handleAdminListDeployTasks))
	mux.HandleFunc("GET /api/v1/admin/deploy/tasks/{id}", s.requireSuperAdmin(s.handleAdminGetDeployTask))
	mux.HandleFunc("POST /api/v1/admin/deploy/agent-a-script", s.requireSuperAdmin(s.handleAdminAgentAInstallScript))
	mux.HandleFunc("POST /api/v1/admin/deploy/agent-b-script", s.requireConsole(s.handleAdminAgentBInstallScript))

	// Customer Account Management API (Super-Admin only)
	mux.HandleFunc("GET /api/v1/admin/accounts", s.requireSuperAdmin(s.handleAdminListAccounts))
	mux.HandleFunc("POST /api/v1/admin/accounts", s.requireSuperAdmin(s.handleAdminCreateAccount))
	mux.HandleFunc("PUT /api/v1/admin/accounts/{id}", s.requireSuperAdmin(s.handleAdminUpdateAccount))
	mux.HandleFunc("POST /api/v1/admin/accounts/{id}/rotate", s.requireSuperAdmin(s.handleAdminRotateAccountToken))
	mux.HandleFunc("DELETE /api/v1/admin/accounts/{id}", s.requireSuperAdmin(s.handleAdminDeleteAccount))

	// Embedded Web UI
	webSub, err := fs.Sub(embeddedWeb, "web")
	if err == nil {
		mux.Handle("/", http.FileServer(http.FS(webSub)))
	}
	return withSecurityHeaders(mux)
}

type nodeHandler func(w http.ResponseWriter, r *http.Request, node *StoredNode)

func (s *Server) requireNode(role string, next nodeHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		nodeID := strings.TrimSpace(r.Header.Get(protocol.HeaderNodeID))
		tok := strings.TrimSpace(r.Header.Get(protocol.HeaderNodeToken))
		if nodeID == "" || tok == "" {
			protocol.WriteError(w, http.StatusUnauthorized, "missing node credentials")
			return
		}
		sn, err := s.store.AuthenticateNode(r.Context(), nodeID, tok, role)
		if err != nil {
			protocol.WriteError(w, http.StatusUnauthorized, "node authentication failed")
			return
		}
		next(w, r, sn)
	}
}

func (s *Server) isTrustedAdminRequest(r *http.Request) bool {
	if len(s.trustedAdmin) == 0 {
		return false
	}
	host := strings.TrimSpace(r.RemoteAddr)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, pfx := range s.trustedAdmin {
		if pfx.Contains(addr) {
			return true
		}
	}
	return false
}

// effectiveReceiverAccess enforces customer account ownership & project authorization on a receiver
// node in real time. If an admin revokes a project or disables/deletes the owning customer account,
// the receiver immediately loses access to revoked projects (zero stale JWT issuance / SSE wakeups).
func (s *Server) effectiveReceiverAccess(ctx context.Context, node *StoredNode) (projects []string, restricted bool, active bool) {
	if strings.TrimSpace(node.OwnerAccountID) == "" {
		// Admin-owned node: follows node.Projects directly (empty = all projects).
		return append([]string(nil), node.Projects...), len(node.Projects) > 0, true
	}
	acc, err := s.store.GetAccount(ctx, node.OwnerAccountID)
	if err != nil || acc == nil || !acc.Enabled || len(acc.Projects) == 0 {
		// Account disabled/deleted or has zero assigned projects -> strictly cut off.
		return []string{}, true, false
	}
	if len(node.Projects) == 0 {
		return append([]string(nil), acc.Projects...), true, true
	}
	allowed := make([]string, 0, len(node.Projects))
	for _, p := range node.Projects {
		if nodeAllowsProject(acc.Projects, p) {
			allowed = append(allowed, p)
		}
	}
	return allowed, true, len(allowed) > 0
}

func (s *Server) processUnplugLatches(ctx context.Context, node *StoredNode, disks []protocol.DiskStatus) {
	if len(disks) == 0 {
		return
	}
	var toLock []string
	for _, d := range disks {
		if !d.UnplugLatched || d.LatchedGen != node.DiskGen {
			continue
		}
		p := strings.TrimSpace(d.Path)
		if p == "" || validateSafeDiskPath(p) != nil {
			continue
		}
		toLock = append(toLock, p)
	}
	if len(toLock) == 0 {
		return
	}
	newDis, newLock, changed, err := s.store.AutoLockUnpluggedDisks(ctx, node.ID, node.DiskGen, toLock)
	if err != nil {
		s.logger.Warn("auto-lock unplugged disks failed", "node_id", node.ID, "disks", toLock, "err", err)
		return
	}
	if changed {
		node.DisabledDisks = newDis
		node.UnplugLockedDisks = newLock
		s.logger.Warn("auto-locked unplugged/swapped disks until manual confirmation", "node_id", node.ID, "disks", toLock, "disk_gen", node.DiskGen)
	}
}

func (s *Server) handleAHeartbeat(w http.ResponseWriter, r *http.Request, node *StoredNode) {
	var req protocol.AgentAHeartbeatReq
	if err := protocol.DecodeJSON(r.Body, &req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "invalid heartbeat payload")
		return
	}
	req.NodeID = node.ID
	req.Name = sanitizeSingleLine(req.Name, 128)
	if req.Name == "" {
		req.Name = node.Name
	}
	req.Version = sanitizeSingleLine(req.Version, 64)
	req.OS = sanitizeSingleLine(req.OS, 32)
	req.Arch = sanitizeSingleLine(req.Arch, 32)
	req.UpgradeError = sanitizeSingleLine(req.UpgradeError, 256)
	if len(req.StorageDirs) > 256 {
		req.StorageDirs = req.StorageDirs[:256]
	}
	for i := range req.StorageDirs {
		req.StorageDirs[i] = sanitizeSingleLine(req.StorageDirs[i], 256)
	}
	if len(req.Disks) > 256 {
		req.Disks = req.Disks[:256]
	}
	for i := range req.Disks {
		req.Disks[i].Path = sanitizeSingleLine(req.Disks[i].Path, 256)
		req.Disks[i].StatusReason = sanitizeSingleLine(req.Disks[i].StatusReason, 160)
	}
	if len(req.HostDisks) > 256 {
		req.HostDisks = req.HostDisks[:256]
	}
	for i := range req.HostDisks {
		req.HostDisks[i].Device = sanitizeSingleLine(req.HostDisks[i].Device, 128)
		req.HostDisks[i].MountPoint = sanitizeSingleLine(req.HostDisks[i].MountPoint, 256)
		req.HostDisks[i].FSType = sanitizeSingleLine(req.HostDisks[i].FSType, 32)
		req.HostDisks[i].SuggestedDir = sanitizeSingleLine(req.HostDisks[i].SuggestedDir, 256)
	}
	// Pin public_addr to the Center-registered address to prevent SSRF via spoofed heartbeats.
	if node.PublicAddr != "" {
		req.PublicAddr = node.PublicAddr
	} else if req.PublicAddr != "" {
		if err := validateHTTPSAddr(req.PublicAddr); err != nil {
			protocol.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if len(node.Projects) > 0 {
		req.Projects = append([]string(nil), node.Projects...)
		filtered := make([]protocol.ProjectAvailability, 0, len(req.Availability))
		for _, av := range req.Availability {
			if nodeAllowsProject(node.Projects, av.ProjectID) {
				filtered = append(filtered, av)
			}
		}
		req.Availability = filtered
	}
	if len(req.Availability) > 0 {
		availIDs := make([]string, 0, len(req.Availability))
		for _, av := range req.Availability {
			availIDs = append(availIDs, av.ProjectID)
		}
		s.ensureKnownProjects(r.Context(), availIDs, req.ProjectHints)
	}
	req.Paused = node.Paused
	s.processUnplugLatches(r.Context(), node, req.Disks)
	s.hub.UpdateA(req)
	hbResp := s.processNodeHeartbeatUpgrade(r.Context(), node.ID, req.Version, req.UpgradeAttemptID, req.UpgradeStatus, req.UpgradeError)
	hbResp.Paused = node.Paused
	hbResp.DiskGen = node.DiskGen
	hbResp.MaxDiskUsagePct = transfer.NormalizeMaxDiskUsagePct(node.MaxDiskUsagePct)
	if len(node.StorageDirs) > 0 {
		hbResp.StorageDirs = append([]string(nil), node.StorageDirs...)
	}
	if len(node.DisabledDisks) > 0 {
		hbResp.DisabledDisks = append([]string(nil), node.DisabledDisks...)
	}
	if projs, err := s.store.ListProjects(r.Context()); err == nil && len(projs) > 0 {
		projIDs := make([]string, 0, len(projs))
		affMap := make(map[string]bool, len(projs))
		for _, p := range projs {
			projIDs = append(projIDs, p.ID)
			affMap[p.ID] = p.GroupAffinityEnabled()
		}
		if dbNodes, nErr := s.store.ListNodes(r.Context()); nErr == nil {
			hbResp.ActiveReceivers = s.hub.ActiveReceiversByProject(projIDs, dbNodes)
		}
		hbResp.ProjectAffinity = affMap
	}
	protocol.WriteJSON(w, http.StatusOK, hbResp)
}

func (s *Server) handleAEvents(w http.ResponseWriter, r *http.Request, node *StoredNode) {
	var req protocol.SummaryEventsReq
	if err := protocol.DecodeJSON(r.Body, &req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "invalid events payload")
		return
	}
	validEvents := make([]protocol.SummaryEvent, 0, len(req.Events))
	evProjects := make([]string, 0, len(req.Events))
	var evHints map[string]protocol.ProjectAutoHint
	for _, ev := range req.Events {
		if !nodeAllowsProject(node.Projects, ev.ProjectID) || ev.Bytes < 0 || ev.DurationMs < 0 {
			continue
		}
		ev.ANodeID = node.ID
		validEvents = append(validEvents, ev)
		evProjects = append(evProjects, ev.ProjectID)
		if ev.ProjectName != "" || len(ev.CustomerIDs) > 0 {
			if evHints == nil {
				evHints = make(map[string]protocol.ProjectAutoHint)
			}
			cur := evHints[ev.ProjectID]
			if cur.Name == "" && ev.ProjectName != "" {
				cur.Name = ev.ProjectName
			}
			if len(cur.CustomerIDs) == 0 && len(ev.CustomerIDs) > 0 {
				cur.CustomerIDs = append([]string(nil), ev.CustomerIDs...)
			}
			evHints[ev.ProjectID] = cur
		}
	}
	if len(evProjects) > 0 {
		s.ensureKnownProjects(r.Context(), evProjects, evHints)
	}
	applied, err := s.store.RecordSummaryEvents(r.Context(), validEvents)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]int{"applied": applied})
}

func (s *Server) handleBHeartbeat(w http.ResponseWriter, r *http.Request, node *StoredNode) {
	var req protocol.AgentBHeartbeatReq
	if err := protocol.DecodeJSON(r.Body, &req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "invalid b heartbeat payload")
		return
	}
	req.NodeID = node.ID
	req.Name = sanitizeSingleLine(req.Name, 128)
	if req.Name == "" {
		req.Name = node.Name
	}
	req.Version = sanitizeSingleLine(req.Version, 64)
	req.OS = sanitizeSingleLine(req.OS, 32)
	req.Arch = sanitizeSingleLine(req.Arch, 32)
	req.UpgradeError = sanitizeSingleLine(req.UpgradeError, 256)
	req.AdaptiveState = sanitizeSingleLine(req.AdaptiveState, 32)
	req.AdaptiveReason = sanitizeSingleLine(req.AdaptiveReason, 160)
	if len(req.StorageDirs) > 256 {
		req.StorageDirs = req.StorageDirs[:256]
	}
	for i := range req.StorageDirs {
		req.StorageDirs[i] = sanitizeSingleLine(req.StorageDirs[i], 256)
	}
	if len(req.Disks) > 256 {
		req.Disks = req.Disks[:256]
	}
	for i := range req.Disks {
		req.Disks[i].Path = sanitizeSingleLine(req.Disks[i].Path, 256)
		req.Disks[i].StatusReason = sanitizeSingleLine(req.Disks[i].StatusReason, 160)
	}
	if len(req.HostDisks) > 256 {
		req.HostDisks = req.HostDisks[:256]
	}
	for i := range req.HostDisks {
		req.HostDisks[i].Device = sanitizeSingleLine(req.HostDisks[i].Device, 128)
		req.HostDisks[i].MountPoint = sanitizeSingleLine(req.HostDisks[i].MountPoint, 256)
		req.HostDisks[i].FSType = sanitizeSingleLine(req.HostDisks[i].FSType, 32)
		req.HostDisks[i].SuggestedDir = sanitizeSingleLine(req.HostDisks[i].SuggestedDir, 256)
	}
	effProjects, restricted, accActive := s.effectiveReceiverAccess(r.Context(), node)
	if restricted {
		filtered := make([]string, 0, len(req.Projects))
		for _, p := range req.Projects {
			if nodeAllowsProject(effProjects, p) {
				filtered = append(filtered, p)
			}
		}
		req.Projects = filtered
	}
	effPaused := node.Paused || !accActive
	req.Paused = effPaused
	s.processUnplugLatches(r.Context(), node, req.Disks)
	s.hub.UpdateB(req)
	hbResp := s.processNodeHeartbeatUpgrade(r.Context(), node.ID, req.Version, req.UpgradeAttemptID, req.UpgradeStatus, req.UpgradeError)
	hbResp.Paused = effPaused
	hbResp.DiskGen = node.DiskGen

	projs, _ := s.store.ListProjects(r.Context())
	knownIDs := make([]string, 0, len(projs))
	for _, p := range projs {
		knownIDs = append(knownIDs, p.ID)
	}
	dbNodes, _ := s.store.ListNodes(r.Context())
	maxConc, suggestedStreamCap, rateLimitMBps := s.hub.ComputeClusterQuotas(node, projs, dbNodes)

	diskAff := node.DiskAffinityEnabled()
	dir := &protocol.ReceiverDirective{
		Paused:             effPaused,
		ProjectMode:        "all",
		KnownProjects:      knownIDs,
		ProjectSchedule:    node.ProjectSchedule,
		DiskPolicy:         node.DiskPolicy,
		DiskAffinity:       &diskAff,
		ActiveDiskWindow:   node.ActiveDiskWindow,
		StorageDirs:        append([]string(nil), node.StorageDirs...),
		DisabledDisks:      append([]string(nil), node.DisabledDisks...),
		DiskGen:            node.DiskGen,
		MaxDiskUsagePct:    transfer.NormalizeMaxDiskUsagePct(node.MaxDiskUsagePct),
		ConcurrencyMode:    node.ConcurrencyMode,
		MaxConcurrent:      maxConc,
		SuggestedStreamCap: suggestedStreamCap,
		RateLimitMBps:      rateLimitMBps,
	}
	if restricted {
		dir.ProjectMode = "selected"
		dir.AllowedProjects = append([]string(nil), effProjects...)
		hbResp.AllowedProjects = append([]string(nil), effProjects...)
	}
	hbResp.Directive = dir
	protocol.WriteJSON(w, http.StatusOK, hbResp)
}

func (s *Server) handleBEventsSSE(w http.ResponseWriter, r *http.Request, node *StoredNode) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		protocol.WriteError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	effProjects, restricted, accActive := s.effectiveReceiverAccess(r.Context(), node)
	projectsParam := strings.TrimSpace(r.URL.Query().Get("projects"))
	var projects []string
	wildcard := false
	if !accActive {
		projects = nil
	} else if projectsParam == "*" && !restricted {
		wildcard = true
		projects = []string{"*"}
	} else if projectsParam != "" {
		for _, p := range strings.Split(projectsParam, ",") {
			p = strings.TrimSpace(p)
			if p == "*" && !restricted {
				wildcard = true
				projects = []string{"*"}
				break
			}
			if p != "" && (!restricted || nodeAllowsProject(effProjects, p)) {
				projects = append(projects, p)
			}
		}
	} else if restricted {
		projects = effProjects
	} else {
		wildcard = true
		projects = []string{"*"}
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	sseCtx, cancelSSE := context.WithCancel(r.Context())
	defer cancelSSE()

	ch, unsub := s.hub.SubscribeB(node.ID, projects, cancelSSE)
	defer unsub()

	// Immediately notify if any subscribed project already has ready files.
	if wildcard {
		aSnap, _ := s.hub.Snapshot()
		notified := make(map[string]struct{})
		for _, aSt := range aSnap {
			if !s.hub.IsOnline(aSt.LastSeen) || aSt.Paused {
				continue
			}
			for pid, av := range aSt.Availability {
				if av.ReadyCount > 0 && validIDRe.MatchString(pid) {
					if _, dup := notified[pid]; !dup {
						notified[pid] = struct{}{}
						_, _ = fmt.Fprintf(w, "event: wakeup\ndata: %s\n\n", pid)
						flusher.Flush()
					}
				}
			}
		}
	} else {
		for _, p := range projects {
			if validIDRe.MatchString(p) && len(s.hub.DiscoverCandidates(p)) > 0 {
				_, _ = fmt.Fprintf(w, "event: wakeup\ndata: %s\n\n", p)
				flusher.Flush()
			}
		}
	}

	keepalive := time.NewTicker(25 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-sseCtx.Done():
			return
		case proj := <-ch:
			if !validIDRe.MatchString(proj) {
				continue
			}
			_, _ = fmt.Fprintf(w, "event: wakeup\ndata: %s\n\n", proj)
			flusher.Flush()
		case <-keepalive.C:
			_, _ = fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

func (s *Server) handleBDiscover(w http.ResponseWriter, r *http.Request, node *StoredNode) {
	projectID := strings.TrimSpace(r.URL.Query().Get("project"))
	if projectID == "" {
		protocol.WriteError(w, http.StatusBadRequest, "project query parameter required")
		return
	}
	effProjects, restricted, accActive := s.effectiveReceiverAccess(r.Context(), node)
	if !accActive || (restricted && !nodeAllowsProject(effProjects, projectID)) {
		protocol.WriteError(w, http.StatusForbidden, "b node not authorized for project")
		return
	}

	conflictPolicy := protocol.ConflictOverwrite
	leaseTTLSec := 300
	if proj, err := s.store.GetProject(r.Context(), projectID); err == nil {
		conflictPolicy = proj.ConflictPolicy
		leaseTTLSec = proj.LeaseTTLSec
	}
	// If receiver is paused in Center, immediately withhold candidates (works even on older agent versions).
	if node.Paused {
		protocol.WriteJSON(w, http.StatusOK, protocol.DiscoverResp{
			ProjectID:      projectID,
			ConflictPolicy: conflictPolicy,
			LeaseTTLSec:    leaseTTLSec,
			Candidates:     []protocol.DiscoverCandidate{},
		})
		return
	}

	candidates := s.hub.DiscoverCandidates(projectID)
	now := time.Now().UTC()
	exp := now.Add(s.cfg.JWTTTL()).Unix()
	for i := range candidates {
		jwtStr, err := auth.SignAccessJWT(s.cfg.JWTSecret, auth.AccessClaims{
			BNodeID:   node.ID,
			ProjectID: projectID,
			ANodeID:   candidates[i].ANodeID,
			IssuedAt:  now.Unix(),
			ExpiresAt: exp,
		})
		if err != nil {
			protocol.WriteError(w, http.StatusInternalServerError, "sign access token failed")
			return
		}
		candidates[i].AccessJWT = jwtStr
	}

	protocol.WriteJSON(w, http.StatusOK, protocol.DiscoverResp{
		ProjectID:      projectID,
		ConflictPolicy: conflictPolicy,
		LeaseTTLSec:    leaseTTLSec,
		Candidates:     candidates,
	})
}

func parseIntervalQuery(r *http.Request) IntervalQuery {
	q := IntervalQuery{
		Now:       time.Now().UTC(),
		Hours:     24,
		ProjectID: strings.TrimSpace(r.URL.Query().Get("project")),
		ANodeID:   strings.TrimSpace(r.URL.Query().Get("a_node")),
		BNodeID:   strings.TrimSpace(r.URL.Query().Get("b_node")),
	}
	if hStr := strings.TrimSpace(r.URL.Query().Get("hours")); hStr != "" {
		if parsed, err := strconv.Atoi(hStr); err == nil && parsed > 0 {
			q.Hours = parsed
		}
	}
	if bStr := strings.TrimSpace(r.URL.Query().Get("bucket_min")); bStr != "" {
		if parsed, err := strconv.Atoi(bStr); err == nil && parsed > 0 {
			q.BucketMinutes = parsed
		}
	}
	parseTimeParam := func(raw string) time.Time {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return time.Time{}
		}
		if sec, err := strconv.ParseInt(raw, 10, 64); err == nil && sec > 0 {
			return time.Unix(sec, 0).UTC()
		}
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			return t.UTC()
		}
		return time.Time{}
	}
	q.Start = parseTimeParam(r.URL.Query().Get("start"))
	q.End = parseTimeParam(r.URL.Query().Get("end"))
	return q
}

func (s *Server) handleAdminOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	principal := principalFromRequest(r)
	iq := parseIntervalQuery(r)
	if !principal.IsAdmin() {
		if iq.ANodeID != "" {
			protocol.WriteError(w, http.StatusForbidden, "customer accounts cannot filter by dispatch node")
			return
		}
		if iq.ProjectID != "" && !principal.AllowsProject(iq.ProjectID) {
			protocol.WriteError(w, http.StatusForbidden, "project not authorized for this account")
			return
		}
		if iq.BNodeID != "" {
			n, err := s.store.GetNode(ctx, iq.BNodeID)
			if err != nil || !principal.CanAccessNode(*n) {
				protocol.WriteError(w, http.StatusForbidden, "receiver node not authorized for this account")
				return
			}
		}
		iq.AllowedProjects = principal.Projects
		iq.ScopeRestricted = true
	}

	allProjects, err := s.store.ListProjects(ctx)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	projects := make([]protocol.Project, 0, len(allProjects))
	for _, p := range allProjects {
		if principal.AllowsProject(p.ID) {
			projects = append(projects, p)
		}
	}
	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	totalsMap, err := s.store.GetAllProjectTotals(ctx)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	emptyCustomerScope := !principal.IsAdmin() && len(principal.Projects) == 0
	var dailyTrend []protocol.DailyStat
	if emptyCustomerScope {
		dailyTrend = []protocol.DailyStat{}
	} else {
		dailyTrend, err = s.store.GetDailyStatsScoped(ctx, iq.ProjectID, iq.AllowedProjects, 14)
		if err != nil {
			protocol.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	intervalResp, err := s.store.QueryIntervalStats(ctx, iq)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var projWindowMap map[string]WindowSummary
	if emptyCustomerScope {
		projWindowMap = map[string]WindowSummary{}
	} else {
		_, _, projWindowMap, err = s.store.GetWindowEntityStatsScoped(ctx, iq.Now, intervalResp.WindowHours, iq.AllowedProjects)
		if err != nil {
			protocol.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	aSnap, bSnap := s.hub.Snapshot()
	overview := protocol.OverviewResp{
		GeneratedAt:        intervalResp.GeneratedAt,
		AuthTrustedIP:      principal.TrustedIP,
		AuthRole:           principal.Role,
		AuthAccountID:      principal.AccountID,
		AuthAccountName:    principal.AccountName,
		AuthProjects:       principal.Projects,
		WindowStart:        intervalResp.WindowStart,
		WindowEnd:          intervalResp.WindowEnd,
		WindowHours:        intervalResp.WindowHours,
		BucketMinutes:      intervalResp.BucketMinutes,
		ProjectFilter:      iq.ProjectID,
		TotalProjects:      len(projects),
		WindowCompleted:    intervalResp.TotalCompleted,
		WindowBytes:        intervalResp.TotalBytes,
		WindowFailed:       intervalResp.TotalFailed,
		WindowAvgSpeedBps:  intervalResp.WindowAvgSpeedBps,
		ActiveAvgSpeedBps:  intervalResp.ActiveAvgSpeedBps,
		WindowPeakSpeedBps: intervalResp.PeakSpeedBps,
		IntervalCurve:      intervalResp.Buckets,
		DailyTrend:         dailyTrend,
	}

	today := time.Now().UTC().Format("2006-01-02")
	for _, d := range dailyTrend {
		if d.Date == today {
			overview.TodayCompleted += d.FilesCompleted
			overview.TodayBytes += d.BytesTransferred
			overview.TodayFailed += d.FilesFailed
		}
	}
	for pid, t := range totalsMap {
		if !principal.AllowsProject(pid) {
			continue
		}
		overview.AllTimeCompleted += t.TotalCompleted
		overview.AllTimeBytes += t.TotalBytes
		overview.AllTimeFailed += t.TotalFailed
	}

	accessibleB := make(map[string]protocol.NodeRecord, len(nodes))
	for _, n := range nodes {
		if n.Role == protocol.RoleAgentA {
			if principal.IsAdmin() {
				overview.TotalANodes++
				if st, ok := aSnap[n.ID]; ok && s.hub.IsOnline(st.LastSeen) {
					overview.OnlineANodes++
				}
			}
		} else if n.Role == protocol.RoleAgentB {
			if !principal.CanAccessNode(n) {
				continue
			}
			accessibleB[n.ID] = n
			overview.TotalBNodes++
			if st, ok := bSnap[n.ID]; ok && s.hub.IsOnline(st.LastSeen) {
				overview.OnlineBNodes++
			}
		}
	}

	projSummaries := make([]protocol.ProjectSummary, 0, len(projects))
	for _, p := range projects {
		t := totalsMap[p.ID]
		pw := projWindowMap[p.ID]
		ps := protocol.ProjectSummary{
			Project:           p,
			TotalUploaded:     t.TotalUploaded,
			TotalCompleted:    t.TotalCompleted,
			TotalFailed:       t.TotalFailed,
			TotalBytes:        t.TotalBytes,
			WindowCompleted:   pw.Completed,
			WindowFailed:      pw.Failed,
			WindowBytes:       pw.Bytes,
			WindowAvgSpeedBps: pw.WindowAvgSpeedBps,
			ActiveAvgSpeedBps: pw.ActiveAvgSpeedBps,
			ANodeAvailability: make([]protocol.ANodeAvailSummary, 0),
		}
		for _, aSt := range aSnap {
			if !s.hub.IsOnline(aSt.LastSeen) {
				continue
			}
			if principal.IsAdmin() && nodeAllowsProject(aSt.Projects, p.ID) {
				ps.OnlineANodes++
			}
			if av, ok := aSt.Availability[p.ID]; ok && (av.ReadyCount > 0 || av.ClaimedCount > 0) {
				ps.QueuedFiles += av.ReadyCount + av.ClaimedCount
				ps.QueuedBytes += av.ReadyBytes
				// Never expose dispatch node IDs, names, or public IPs to customer accounts.
				if principal.IsAdmin() {
					ps.ANodeAvailability = append(ps.ANodeAvailability, protocol.ANodeAvailSummary{
						ANodeID:      aSt.NodeID,
						AName:        aSt.Name,
						PublicAddr:   aSt.PublicAddr,
						ReadyCount:   av.ReadyCount,
						ClaimedCount: av.ClaimedCount,
						ReadyBytes:   av.ReadyBytes,
						DiskAlarm:    aSt.DiskAlarm,
					})
				}
			}
		}
		sort.Slice(ps.ANodeAvailability, func(i, j int) bool {
			return ps.ANodeAvailability[i].ANodeID < ps.ANodeAvailability[j].ANodeID
		})
		for _, bSt := range bSnap {
			if !s.hub.IsOnline(bSt.LastSeen) {
				continue
			}
			if !principal.IsAdmin() {
				if _, ok := accessibleB[bSt.NodeID]; !ok {
					continue
				}
			}
			if nodeAllowsProject(bSt.Projects, p.ID) {
				ps.OnlineBNodes++
			}
		}
		overview.QueuedFiles += ps.QueuedFiles
		overview.QueuedBytes += ps.QueuedBytes
		projSummaries = append(projSummaries, ps)
	}
	overview.Projects = projSummaries

	protocol.WriteJSON(w, http.StatusOK, overview)
}

func (s *Server) handleAdminListProjects(w http.ResponseWriter, r *http.Request) {
	principal := principalFromRequest(r)
	list, err := s.store.ListProjects(r.Context())
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !principal.IsAdmin() {
		filtered := make([]protocol.Project, 0, len(list))
		for _, p := range list {
			if principal.AllowsProject(p.ID) {
				filtered = append(filtered, p)
			}
		}
		list = filtered
	}
	protocol.WriteJSON(w, http.StatusOK, list)
}

func (s *Server) handleAdminUpsertProject(w http.ResponseWriter, r *http.Request) {
	var p protocol.Project
	if err := protocol.DecodeJSON(r.Body, &p); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	p.ID = strings.TrimSpace(p.ID)
	p.Name = sanitizeSingleLine(p.Name, 128)
	p.Description = sanitizeSingleLine(p.Description, 512)
	if p.ID == "" {
		protocol.WriteError(w, http.StatusBadRequest, "project id required")
		return
	}
	if !validIDRe.MatchString(p.ID) {
		protocol.WriteError(w, http.StatusBadRequest, "invalid project id: only [A-Za-z0-9._-] (1-64 chars) allowed")
		return
	}
	if p.Name == "" {
		p.Name = p.ID
	}
	p.ConflictPolicy = strings.TrimSpace(p.ConflictPolicy)
	if p.ConflictPolicy == "" {
		p.ConflictPolicy = protocol.ConflictOverwrite
	}
	switch p.ConflictPolicy {
	case protocol.ConflictOverwrite, protocol.ConflictAutoRename, protocol.ConflictSkip:
	default:
		protocol.WriteError(w, http.StatusBadRequest, "conflict_policy must be overwrite, auto_rename, or skip")
		return
	}
	if p.LeaseTTLSec <= 0 {
		p.LeaseTTLSec = 300
	}
	if p.LeaseTTLSec > 3600 {
		protocol.WriteError(w, http.StatusBadRequest, "lease_ttl_sec must be <= 3600")
		return
	}
	if p.MaxTotalConcurrent < 0 || p.MaxTotalConcurrent > 10000 {
		protocol.WriteError(w, http.StatusBadRequest, "max_total_concurrent must be between 0 and 10000")
		return
	}
	if p.MaxTotalRateMBps < 0 {
		protocol.WriteError(w, http.StatusBadRequest, "max_total_rate_mbps must be >= 0")
		return
	}
	p.CreatedAt = time.Now().UTC()
	if err := s.store.UpsertProject(r.Context(), p); err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.knownProjects.Store(p.ID, struct{}{})
	if saved, err := s.store.GetProject(r.Context(), p.ID); err == nil {
		p = *saved
	}
	protocol.WriteJSON(w, http.StatusOK, p)
}

func (s *Server) handleAdminDeleteProject(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteProject(r.Context(), id); err != nil {
		if errors.Is(err, ErrNotFound) {
			protocol.WriteError(w, http.StatusNotFound, "project not found")
			return
		}
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.knownProjects.Delete(id)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAdminListNodes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	principal := principalFromRequest(r)
	hours := 24
	if hStr := strings.TrimSpace(r.URL.Query().Get("hours")); hStr != "" {
		if parsed, err := strconv.Atoi(hStr); err == nil && parsed > 0 && parsed <= 720 {
			hours = parsed
		}
	}
	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var aWinStats, bWinStats map[string]WindowSummary
	if !principal.IsAdmin() && len(principal.Projects) == 0 {
		aWinStats = map[string]WindowSummary{}
		bWinStats = map[string]WindowSummary{}
	} else {
		aWinStats, bWinStats, _, err = s.store.GetWindowEntityStatsScoped(ctx, time.Now().UTC(), hours, principal.Projects)
		if err != nil {
			protocol.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	aSnap, bSnap := s.hub.Snapshot()
	upgrades, _ := s.store.ListNodeUpgrades(ctx)
	views := make([]protocol.LiveNodeView, 0, len(nodes))
	for _, n := range nodes {
		if !principal.CanAccessNode(n) {
			continue
		}
		diskAff := n.DiskAffinityEnabled()
		v := protocol.LiveNodeView{
			ID:                    n.ID,
			Name:                  n.Name,
			Role:                  n.Role,
			OwnerAccountID:        n.OwnerAccountID,
			Projects:              n.Projects,
			ProjectSchedule:       n.ProjectSchedule,
			DiskPolicy:            n.DiskPolicy,
			DiskAffinity:          &diskAff,
			ActiveDiskWindow:      n.ActiveDiskWindow,
			StorageDirs:           append([]string(nil), n.StorageDirs...),
			DisabledDisks:         n.DisabledDisks,
			UnplugLockedDisks:     n.UnplugLockedDisks,
			DiskGen:               n.DiskGen,
			MaxDiskUsagePct:       transfer.NormalizeMaxDiskUsagePct(n.MaxDiskUsagePct),
			ConcurrencyMode:       n.ConcurrencyMode,
			MaxConcurrentOverride: n.MaxConcurrentOverride,
			RateLimitMBps:         n.RateLimitMBps,
			Paused:                n.Paused,
			PublicAddr:            n.PublicAddr,
			WindowHours:           hours,
		}
		if upg, ok := upgrades[n.ID]; ok {
			v.TargetVersion = upg.TargetVersion
			v.UpgradeStatus = upg.Status
			v.UpgradeMessage = upg.Message
		}
		if n.Role == protocol.RoleAgentA {
			if ws, ok := aWinStats[n.ID]; ok {
				v.WindowCompleted = ws.Completed
				v.WindowFailed = ws.Failed
				v.WindowBytes = ws.Bytes
				v.WindowAvgSpeedBps = ws.WindowAvgSpeedBps
				v.ActiveAvgSpeedBps = ws.ActiveAvgSpeedBps
			}
			if st, ok := aSnap[n.ID]; ok {
				ls := st.LastSeen
				v.LastSeenAt = &ls
				v.Online = s.hub.IsOnline(st.LastSeen)
				v.Version = st.Version
				v.OS = st.OS
				v.Arch = st.Arch
				if st.PublicAddr != "" {
					v.PublicAddr = st.PublicAddr
				}
				v.DiskTotalBytes = st.DiskTotalBytes
				v.DiskFreeBytes = st.DiskFreeBytes
				v.DiskUsedPct = st.DiskUsedPct
				v.DiskAlarm = st.DiskAlarm
				if len(st.StorageDirs) > 0 {
					v.StorageDirs = st.StorageDirs
				}
				v.Disks = st.Disks
				v.HostDisks = st.HostDisks
				v.AwaitingDisk = st.AwaitingDisk
				for _, av := range st.Availability {
					v.Availability = append(v.Availability, av)
				}
				sort.Slice(v.Availability, func(i, j int) bool {
					return v.Availability[i].ProjectID < v.Availability[j].ProjectID
				})
			}
		} else if n.Role == protocol.RoleAgentB {
			if ws, ok := bWinStats[n.ID]; ok {
				v.WindowCompleted = ws.Completed
				v.WindowFailed = ws.Failed
				v.WindowBytes = ws.Bytes
				v.WindowAvgSpeedBps = ws.WindowAvgSpeedBps
				v.ActiveAvgSpeedBps = ws.ActiveAvgSpeedBps
			}
			if st, ok := bSnap[n.ID]; ok {
				ls := st.LastSeen
				v.LastSeenAt = &ls
				v.Online = s.hub.IsOnline(st.LastSeen)
				v.Version = st.Version
				v.OS = st.OS
				v.Arch = st.Arch
				if len(st.StorageDirs) > 0 {
					v.StorageDirs = st.StorageDirs
				}
				v.Disks = st.Disks
				v.HostDisks = st.HostDisks
				v.AwaitingDisk = st.AwaitingDisk
				v.EffectiveConcurrent = st.EffectiveConcurrent
				v.MaxConcurrentCap = st.MaxConcurrentCap
				v.EffectiveStreams = st.EffectiveStreams
				v.EffectiveRateMBps = st.EffectiveRateMBps
				v.AdaptiveState = st.AdaptiveState
				v.AdaptiveReason = st.AdaptiveReason
				v.DiskTotalBytes = st.DiskTotalBytes
				v.DiskFreeBytes = st.DiskFreeBytes
				v.DiskUsedPct = st.DiskUsedPct
			}
		}
		views = append(views, v)
	}
	protocol.WriteJSON(w, http.StatusOK, views)
}

type createNodeReq struct {
	ID                    string   `json:"id"`
	Name                  string   `json:"name"`
	Role                  string   `json:"role"`
	OwnerAccountID        string   `json:"owner_account_id,omitempty"`
	Projects              []string `json:"projects"`
	ProjectSchedule       string   `json:"project_schedule,omitempty"`
	DiskPolicy            string   `json:"disk_policy,omitempty"`
	DiskAffinity          *bool    `json:"disk_affinity,omitempty"`
	ActiveDiskWindow      int      `json:"active_disk_window,omitempty"`
	StorageDirs           []string `json:"storage_dirs,omitempty"`
	DisabledDisks         []string `json:"disabled_disks,omitempty"`
	MaxDiskUsagePct       float64  `json:"max_disk_usage_pct,omitempty"`
	ConcurrencyMode       string   `json:"concurrency_mode,omitempty"`
	MaxConcurrentOverride int      `json:"max_concurrent_override,omitempty"`
	RateLimitMBps         float64  `json:"rate_limit_mbps,omitempty"`
	PublicAddr            string   `json:"public_addr"`
	Token                 string   `json:"token,omitempty"`
}

func (s *Server) handleAdminGetNodeDisks(w http.ResponseWriter, r *http.Request) {
	principal := principalFromRequest(r)
	nodeID := strings.TrimSpace(r.PathValue("id"))
	node, err := s.store.GetNode(r.Context(), nodeID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			protocol.WriteError(w, http.StatusNotFound, "node not found")
			return
		}
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !principal.CanAccessNode(*node) {
		protocol.WriteError(w, http.StatusForbidden, "account not authorized to inspect this node")
		return
	}
	aSnap, bSnap := s.hub.Snapshot()
	resp := map[string]any{
		"id":                  node.ID,
		"role":                node.Role,
		"online":              false,
		"awaiting_disk":       false,
		"disk_gen":            node.DiskGen,
		"disk_policy":         node.DiskPolicy,
		"disk_affinity":       node.DiskAffinityEnabled(),
		"active_disk_window":  node.ActiveDiskWindow,
		"max_disk_usage_pct":  transfer.NormalizeMaxDiskUsagePct(node.MaxDiskUsagePct),
		"storage_dirs":        node.StorageDirs,
		"disabled_disks":      node.DisabledDisks,
		"unplug_locked_disks": node.UnplugLockedDisks,
		"disks":               []protocol.DiskStatus{},
		"host_disks":          []protocol.HostDisk{},
	}
	if node.Role == protocol.RoleAgentA {
		if st, ok := aSnap[node.ID]; ok {
			resp["online"] = s.hub.IsOnline(st.LastSeen)
			resp["awaiting_disk"] = st.AwaitingDisk
			if len(st.StorageDirs) > 0 {
				resp["storage_dirs"] = st.StorageDirs
			}
			if st.Disks != nil {
				resp["disks"] = st.Disks
			}
			if st.HostDisks != nil {
				resp["host_disks"] = st.HostDisks
			}
		}
	} else {
		if st, ok := bSnap[node.ID]; ok {
			resp["online"] = s.hub.IsOnline(st.LastSeen)
			resp["awaiting_disk"] = st.AwaitingDisk
			if len(st.StorageDirs) > 0 {
				resp["storage_dirs"] = st.StorageDirs
			}
			if st.Disks != nil {
				resp["disks"] = st.Disks
			}
			if st.HostDisks != nil {
				resp["host_disks"] = st.HostDisks
			}
		}
	}
	protocol.WriteJSON(w, http.StatusOK, resp)
}

func cleanStorageDirList(raw []string) ([]string, error) {
	out := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, p := range raw {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if err := deployer.ValidateAbsDir(p); err != nil || !transfer.IsSafeStorageDir(p) {
			return nil, fmt.Errorf("invalid or forbidden data disk directory %q", p)
		}
		if _, dup := seen[p]; !dup {
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out, nil
}

func cleanDiskPathList(raw []string) ([]string, error) {
	out := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, p := range raw {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if err := validateSafeDiskPath(p); err != nil {
			return nil, err
		}
		if _, dup := seen[p]; !dup {
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out, nil
}

func cleanProjectIDList(raw []string) ([]string, error) {
	out := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, p := range raw {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !validIDRe.MatchString(p) {
			return nil, fmt.Errorf("invalid project id: %s", p)
		}
		if _, dup := seen[p]; !dup {
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out, nil
}

func (s *Server) handleAdminCreateNode(w http.ResponseWriter, r *http.Request) {
	principal := principalFromRequest(r)
	var req createNodeReq
	if err := protocol.DecodeJSON(r.Body, &req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	req.Name = sanitizeSingleLine(req.Name, 128)
	req.PublicAddr = strings.TrimSpace(req.PublicAddr)
	if req.ID == "" {
		protocol.WriteError(w, http.StatusBadRequest, "node id required")
		return
	}
	if !validIDRe.MatchString(req.ID) {
		protocol.WriteError(w, http.StatusBadRequest, "invalid node id: only [A-Za-z0-9._-] (1-64 chars) allowed")
		return
	}
	if req.Role != protocol.RoleAgentA && req.Role != protocol.RoleAgentB {
		protocol.WriteError(w, http.StatusBadRequest, "role must be agent_a or agent_b")
		return
	}
	ownerAccID := strings.TrimSpace(req.OwnerAccountID)
	if !principal.IsAdmin() {
		if req.Role != protocol.RoleAgentB {
			protocol.WriteError(w, http.StatusForbidden, "customer accounts can only manage receiver nodes")
			return
		}
		req.PublicAddr = ""
		ownerAccID = principal.AccountID
		if existing, err := s.store.GetNode(r.Context(), req.ID); err == nil && !principal.CanAccessNode(*existing) {
			protocol.WriteError(w, http.StatusForbidden, "cannot overwrite an inaccessible node")
			return
		}
	} else if ownerAccID != "" {
		if req.Role != protocol.RoleAgentB {
			ownerAccID = ""
		} else if _, err := s.store.GetAccount(r.Context(), ownerAccID); err != nil {
			protocol.WriteError(w, http.StatusBadRequest, "owner_account_id not found")
			return
		}
	}
	if req.Role == protocol.RoleAgentA && req.PublicAddr != "" {
		if err := validateHTTPSAddr(req.PublicAddr); err != nil {
			protocol.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	cleanProjects, err := cleanProjectIDList(req.Projects)
	if err != nil {
		protocol.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !principal.IsAdmin() && !principal.AllowsAllProjects(cleanProjects) {
		protocol.WriteError(w, http.StatusForbidden, "receiver node projects must be explicitly selected from this account's authorized projects")
		return
	}
	cleanStorageDirs, err := cleanStorageDirList(req.StorageDirs)
	if err != nil {
		protocol.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	cleanDisks, err := cleanDiskPathList(req.DisabledDisks)
	if err != nil {
		protocol.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	sched := normalizeProjectSchedule(req.ProjectSchedule)
	if sched == "" {
		protocol.WriteError(w, http.StatusBadRequest, "project_schedule must be fifo, fair, or random")
		return
	}
	dp := normalizeDiskPolicy(req.DiskPolicy)
	if dp == "" {
		protocol.WriteError(w, http.StatusBadRequest, "disk_policy must be affinity_hash, most_free, round_robin, first, or rolling_window")
		return
	}
	diskWin := req.ActiveDiskWindow
	if diskWin <= 0 {
		diskWin = 10
	}
	if diskWin > 256 {
		protocol.WriteError(w, http.StatusBadRequest, "active_disk_window must be between 1 and 256")
		return
	}
	maxDiskPct := transfer.DefaultMaxDiskUsagePct
	if req.MaxDiskUsagePct != 0 {
		if req.MaxDiskUsagePct < transfer.MinMaxDiskUsagePct || req.MaxDiskUsagePct > transfer.MaxMaxDiskUsagePct {
			protocol.WriteError(w, http.StatusBadRequest, "max_disk_usage_pct must be between 1 and 99")
			return
		}
		maxDiskPct = req.MaxDiskUsagePct
	}
	cm := normalizeConcurrencyMode(req.ConcurrencyMode)
	if cm == "" {
		protocol.WriteError(w, http.StatusBadRequest, "concurrency_mode must be auto or manual")
		return
	}
	if req.MaxConcurrentOverride < 0 || req.MaxConcurrentOverride > 1024 {
		protocol.WriteError(w, http.StatusBadRequest, "max_concurrent_override must be between 0 and 1024")
		return
	}
	if req.RateLimitMBps < 0 {
		protocol.WriteError(w, http.StatusBadRequest, "rate_limit_mbps must be >= 0")
		return
	}
	if req.Name == "" {
		req.Name = req.ID
	}
	rawToken := strings.TrimSpace(req.Token)
	if rawToken == "" {
		rawToken = auth.GenerateRandomToken(24)
	}
	diskAff := true
	if req.DiskAffinity != nil {
		diskAff = *req.DiskAffinity
	}
	rec := protocol.NodeRecord{
		ID:                    req.ID,
		Name:                  req.Name,
		Role:                  req.Role,
		OwnerAccountID:        ownerAccID,
		Projects:              cleanProjects,
		ProjectSchedule:       sched,
		DiskPolicy:            dp,
		DiskAffinity:          &diskAff,
		ActiveDiskWindow:      diskWin,
		StorageDirs:           cleanStorageDirs,
		DisabledDisks:         cleanDisks,
		MaxDiskUsagePct:       maxDiskPct,
		ConcurrencyMode:       cm,
		MaxConcurrentOverride: req.MaxConcurrentOverride,
		RateLimitMBps:         req.RateLimitMBps,
		PublicAddr:            req.PublicAddr,
		CreatedAt:             time.Now().UTC(),
	}
	if err := s.store.UpsertNode(r.Context(), rec, rawToken); err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Disconnect any active SSE stream authenticated under a prior token or project set.
	s.hub.DisconnectSSE(rec.ID)
	protocol.WriteJSON(w, http.StatusOK, map[string]any{
		"node":  rec,
		"token": rawToken,
	})
}

type updateNodeReq struct {
	Name                  string    `json:"name,omitempty"`
	OwnerAccountID        *string   `json:"owner_account_id,omitempty"`
	Projects              *[]string `json:"projects,omitempty"`
	ProjectSchedule       string    `json:"project_schedule,omitempty"`
	DiskPolicy            string    `json:"disk_policy,omitempty"`
	DiskAffinity          *bool     `json:"disk_affinity,omitempty"`
	ActiveDiskWindow      *int      `json:"active_disk_window,omitempty"`
	StorageDirs           *[]string `json:"storage_dirs,omitempty"`
	DisabledDisks         *[]string `json:"disabled_disks,omitempty"`
	MaxDiskUsagePct       *float64  `json:"max_disk_usage_pct,omitempty"`
	ConcurrencyMode       string    `json:"concurrency_mode,omitempty"`
	MaxConcurrentOverride *int      `json:"max_concurrent_override,omitempty"`
	RateLimitMBps         *float64  `json:"rate_limit_mbps,omitempty"`
	Paused                *bool     `json:"paused,omitempty"`
	PublicAddr            string    `json:"public_addr,omitempty"`
}

func (s *Server) handleAdminUpdateNode(w http.ResponseWriter, r *http.Request) {
	principal := principalFromRequest(r)
	nodeID := strings.TrimSpace(r.PathValue("id"))
	existing, err := s.store.GetNode(r.Context(), nodeID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			protocol.WriteError(w, http.StatusNotFound, "node not found")
			return
		}
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !principal.CanAccessNode(*existing) {
		protocol.WriteError(w, http.StatusForbidden, "account not authorized to modify this node")
		return
	}

	var req updateNodeReq
	if err := protocol.DecodeJSON(r.Body, &req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}

	rec := *existing
	if name := sanitizeSingleLine(req.Name, 128); name != "" {
		rec.Name = name
	}
	if req.PublicAddr != "" && rec.Role == protocol.RoleAgentA {
		addr := strings.TrimSpace(req.PublicAddr)
		if err := validateHTTPSAddr(addr); err != nil {
			protocol.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		rec.PublicAddr = addr
	}
	if req.ProjectSchedule != "" {
		sched := normalizeProjectSchedule(req.ProjectSchedule)
		if sched == "" {
			protocol.WriteError(w, http.StatusBadRequest, "project_schedule must be fifo, fair, or random")
			return
		}
		rec.ProjectSchedule = sched
	}
	if req.OwnerAccountID != nil && principal.IsAdmin() && rec.Role == protocol.RoleAgentB {
		owner := strings.TrimSpace(*req.OwnerAccountID)
		if owner != "" {
			if _, err := s.store.GetAccount(r.Context(), owner); err != nil {
				protocol.WriteError(w, http.StatusBadRequest, "owner_account_id not found")
				return
			}
		}
		rec.OwnerAccountID = owner
	}
	if req.DiskPolicy != "" {
		dp := normalizeDiskPolicy(req.DiskPolicy)
		if dp == "" {
			protocol.WriteError(w, http.StatusBadRequest, "disk_policy must be affinity_hash, most_free, round_robin, first, or rolling_window")
			return
		}
		rec.DiskPolicy = dp
	}
	if req.DiskAffinity != nil {
		v := *req.DiskAffinity
		rec.DiskAffinity = &v
	}
	if req.ActiveDiskWindow != nil {
		v := *req.ActiveDiskWindow
		if v < 1 || v > 256 {
			protocol.WriteError(w, http.StatusBadRequest, "active_disk_window must be between 1 and 256")
			return
		}
		rec.ActiveDiskWindow = v
	}
	if req.MaxDiskUsagePct != nil {
		v := *req.MaxDiskUsagePct
		if v < transfer.MinMaxDiskUsagePct || v > transfer.MaxMaxDiskUsagePct {
			protocol.WriteError(w, http.StatusBadRequest, "max_disk_usage_pct must be between 1 and 99")
			return
		}
		rec.MaxDiskUsagePct = v
	}
	diskConfigTouched := false
	if req.StorageDirs != nil {
		cleanStorage, err := cleanStorageDirList(*req.StorageDirs)
		if err != nil {
			protocol.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		rec.StorageDirs = cleanStorage
		diskConfigTouched = true
	}
	if req.DisabledDisks != nil {
		cleanDisks, err := cleanDiskPathList(*req.DisabledDisks)
		if err != nil {
			protocol.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		rec.DisabledDisks = cleanDisks
		diskConfigTouched = true
	}
	if diskConfigTouched {
		// Operator explicitly updated or re-confirmed disk configuration -> bump DiskGen so any
		// prior unplug latch for re-enabled disks clears cleanly, and prune unplug locks for disks
		// that are now re-enabled or removed from disabled_disks.
		rec.DiskGen++
		disSet := make(map[string]struct{}, len(rec.DisabledDisks))
		for _, p := range rec.DisabledDisks {
			disSet[p] = struct{}{}
		}
		keptLocks := make([]string, 0, len(rec.UnplugLockedDisks))
		for _, p := range rec.UnplugLockedDisks {
			if _, stillDis := disSet[p]; stillDis {
				keptLocks = append(keptLocks, p)
			}
		}
		rec.UnplugLockedDisks = keptLocks
	}
	if req.ConcurrencyMode != "" {
		cm := normalizeConcurrencyMode(req.ConcurrencyMode)
		if cm == "" {
			protocol.WriteError(w, http.StatusBadRequest, "concurrency_mode must be auto or manual")
			return
		}
		rec.ConcurrencyMode = cm
	}
	if req.MaxConcurrentOverride != nil {
		v := *req.MaxConcurrentOverride
		if v < 0 || v > 1024 {
			protocol.WriteError(w, http.StatusBadRequest, "max_concurrent_override must be between 0 and 1024")
			return
		}
		rec.MaxConcurrentOverride = v
	}
	if req.RateLimitMBps != nil {
		v := *req.RateLimitMBps
		if v < 0 {
			protocol.WriteError(w, http.StatusBadRequest, "rate_limit_mbps must be >= 0")
			return
		}
		rec.RateLimitMBps = v
	}
	if req.Paused != nil {
		rec.Paused = *req.Paused
	}
	if req.Projects != nil {
		cleanProjects, err := cleanProjectIDList(*req.Projects)
		if err != nil {
			protocol.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if !principal.IsAdmin() && !principal.AllowsAllProjects(cleanProjects) {
			protocol.WriteError(w, http.StatusForbidden, "receiver node projects must be within this account's allowed project list")
			return
		}
		rec.Projects = cleanProjects
	}

	// Empty rawToken tells Store.UpsertNode to keep the existing token_hash untouched.
	if err := s.store.UpsertNode(r.Context(), rec, ""); err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if req.Paused != nil {
		s.hub.SetNodePaused(rec.ID, rec.Paused)
	}
	if req.Projects != nil {
		s.hub.UpdateNodeProjects(rec.ID, rec.Projects)
	}
	protocol.WriteJSON(w, http.StatusOK, rec)
}

func (s *Server) handleAdminDeleteNode(w http.ResponseWriter, r *http.Request) {
	principal := principalFromRequest(r)
	nodeID := strings.TrimSpace(r.PathValue("id"))
	existing, err := s.store.GetNode(r.Context(), nodeID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			protocol.WriteError(w, http.StatusNotFound, "node not found")
			return
		}
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !principal.CanAccessNode(*existing) {
		protocol.WriteError(w, http.StatusForbidden, "account not authorized to delete this node")
		return
	}
	if err := s.store.DeleteNode(r.Context(), nodeID); err != nil {
		if errors.Is(err, ErrNotFound) {
			protocol.WriteError(w, http.StatusNotFound, "node not found")
			return
		}
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.DeleteNodeUpgrade(r.Context(), nodeID)
	s.hub.RemoveNode(nodeID)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAdminIntervalStats(w http.ResponseWriter, r *http.Request) {
	principal := principalFromRequest(r)
	iq := parseIntervalQuery(r)
	if !principal.IsAdmin() {
		if iq.ANodeID != "" {
			protocol.WriteError(w, http.StatusForbidden, "customer accounts cannot filter by dispatch node")
			return
		}
		if iq.ProjectID != "" && !principal.AllowsProject(iq.ProjectID) {
			protocol.WriteError(w, http.StatusForbidden, "project not authorized for this account")
			return
		}
		if iq.BNodeID != "" {
			n, err := s.store.GetNode(r.Context(), iq.BNodeID)
			if err != nil || !principal.CanAccessNode(*n) {
				protocol.WriteError(w, http.StatusForbidden, "receiver node not authorized for this account")
				return
			}
		}
		iq.AllowedProjects = principal.Projects
		iq.ScopeRestricted = true
	}
	resp, err := s.store.QueryIntervalStats(r.Context(), iq)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	protocol.WriteJSON(w, http.StatusOK, resp)
}

func (s *Server) handleAdminDailyStats(w http.ResponseWriter, r *http.Request) {
	principal := principalFromRequest(r)
	projectID := strings.TrimSpace(r.URL.Query().Get("project"))
	if !principal.IsAdmin() && projectID != "" && !principal.AllowsProject(projectID) {
		protocol.WriteError(w, http.StatusForbidden, "project not authorized for this account")
		return
	}
	if !principal.IsAdmin() && len(principal.Projects) == 0 {
		protocol.WriteJSON(w, http.StatusOK, []protocol.DailyStat{})
		return
	}
	days := 14
	if dStr := r.URL.Query().Get("days"); dStr != "" {
		if parsed, err := strconv.Atoi(dStr); err == nil && parsed > 0 && parsed <= 90 {
			days = parsed
		}
	}
	stats, err := s.store.GetDailyStatsScoped(r.Context(), projectID, principal.Projects, days)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	protocol.WriteJSON(w, http.StatusOK, stats)
}

func nodeAllowsProject(allowed []string, projectID string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, p := range allowed {
		if p == projectID {
			return true
		}
	}
	return false
}
