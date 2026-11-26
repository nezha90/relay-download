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
)

var validIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func validateHTTPSAddr(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("public_addr must be a valid https:// URL")
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

func (s *Server) ensureKnownProjects(ctx context.Context, ids []string) {
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
	inserted, err := s.store.EnsureProjects(ctx, missing)
	if err != nil {
		s.logger.Warn("auto-create projects failed", "projects", missing, "err", err)
		return
	}
	for _, id := range missing {
		s.knownProjects.Store(id, struct{}{})
	}
	if inserted > 0 {
		s.logger.Info("auto-created projects from dispatch activity", "count", inserted, "projects", missing)
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

	// Admin & Web UI API (interval/stage summary only; no real-time per-file proxy endpoints)
	mux.HandleFunc("GET /api/v1/admin/overview", s.requireAdmin(s.handleAdminOverview))
	mux.HandleFunc("GET /api/v1/admin/projects", s.requireAdmin(s.handleAdminListProjects))
	mux.HandleFunc("POST /api/v1/admin/projects", s.requireAdmin(s.handleAdminUpsertProject))
	mux.HandleFunc("DELETE /api/v1/admin/projects/{id}", s.requireAdmin(s.handleAdminDeleteProject))
	mux.HandleFunc("GET /api/v1/admin/nodes", s.requireAdmin(s.handleAdminListNodes))
	mux.HandleFunc("POST /api/v1/admin/nodes", s.requireAdmin(s.handleAdminCreateNode))
	mux.HandleFunc("PUT /api/v1/admin/nodes/{id}", s.requireAdmin(s.handleAdminUpdateNode))
	mux.HandleFunc("DELETE /api/v1/admin/nodes/{id}", s.requireAdmin(s.handleAdminDeleteNode))
	mux.HandleFunc("GET /api/v1/admin/stats/intervals", s.requireAdmin(s.handleAdminIntervalStats))
	mux.HandleFunc("GET /api/v1/admin/stats/daily", s.requireAdmin(s.handleAdminDailyStats))

	// Releases, Batch Upgrades & One-Click Deployment API
	mux.HandleFunc("GET /api/v1/admin/releases", s.requireAdmin(s.handleAdminListReleases))
	mux.HandleFunc("POST /api/v1/admin/releases", s.requireAdmin(s.handleAdminUploadRelease))
	mux.HandleFunc("DELETE /api/v1/admin/releases/{id}", s.requireAdmin(s.handleAdminDeleteRelease))
	mux.HandleFunc("POST /api/v1/admin/upgrades", s.requireAdmin(s.handleAdminBatchUpgrade))
	mux.HandleFunc("DELETE /api/v1/admin/upgrades/{id}", s.requireAdmin(s.handleAdminCancelUpgrade))
	mux.HandleFunc("POST /api/v1/admin/deploy/precheck", s.requireAdmin(s.handleAdminDeployPrecheck))
	mux.HandleFunc("POST /api/v1/admin/deploy/agent-a", s.requireAdmin(s.handleAdminDeployAgentA))
	mux.HandleFunc("GET /api/v1/admin/deploy/tasks", s.requireAdmin(s.handleAdminListDeployTasks))
	mux.HandleFunc("GET /api/v1/admin/deploy/tasks/{id}", s.requireAdmin(s.handleAdminGetDeployTask))
	mux.HandleFunc("POST /api/v1/admin/deploy/agent-b-script", s.requireAdmin(s.handleAdminAgentBInstallScript))

	// Embedded Web UI
	webSub, err := fs.Sub(embeddedWeb, "web")
	if err == nil {
		mux.Handle("/", http.FileServer(http.FS(webSub)))
	}
	return mux
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

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.isTrustedAdminRequest(r) {
			next(w, r)
			return
		}
		tok := strings.TrimSpace(r.Header.Get(protocol.HeaderAdminToken))
		if tok == "" {
			tok = auth.ExtractBearer(r.Header.Get("Authorization"))
		}
		if !auth.EqualConstantTime(tok, s.cfg.AdminToken) {
			protocol.WriteError(w, http.StatusUnauthorized, "invalid admin token")
			return
		}
		next(w, r)
	}
}

func (s *Server) handleAHeartbeat(w http.ResponseWriter, r *http.Request, node *StoredNode) {
	var req protocol.AgentAHeartbeatReq
	if err := protocol.DecodeJSON(r.Body, &req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "invalid heartbeat payload")
		return
	}
	req.NodeID = node.ID
	if req.Name == "" {
		req.Name = node.Name
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
		s.ensureKnownProjects(r.Context(), availIDs)
	}
	s.hub.UpdateA(req)
	hbResp := s.processNodeHeartbeatUpgrade(r.Context(), node.ID, req.Version, req.UpgradeAttemptID, req.UpgradeStatus, req.UpgradeError)
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
	for _, ev := range req.Events {
		if !nodeAllowsProject(node.Projects, ev.ProjectID) || ev.Bytes < 0 || ev.DurationMs < 0 {
			continue
		}
		ev.ANodeID = node.ID
		validEvents = append(validEvents, ev)
		evProjects = append(evProjects, ev.ProjectID)
	}
	if len(evProjects) > 0 {
		s.ensureKnownProjects(r.Context(), evProjects)
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
	if req.Name == "" {
		req.Name = node.Name
	}
	if len(node.Projects) > 0 {
		filtered := make([]string, 0, len(req.Projects))
		for _, p := range req.Projects {
			if nodeAllowsProject(node.Projects, p) {
				filtered = append(filtered, p)
			}
		}
		req.Projects = filtered
	}
	s.hub.UpdateB(req)
	hbResp := s.processNodeHeartbeatUpgrade(r.Context(), node.ID, req.Version, req.UpgradeAttemptID, req.UpgradeStatus, req.UpgradeError)

	projs, _ := s.store.ListProjects(r.Context())
	knownIDs := make([]string, 0, len(projs))
	for _, p := range projs {
		knownIDs = append(knownIDs, p.ID)
	}
	dbNodes, _ := s.store.ListNodes(r.Context())
	maxConc, suggestedStreamCap, rateLimitMBps := s.hub.ComputeClusterQuotas(node, projs, dbNodes)

	dir := &protocol.ReceiverDirective{
		ProjectMode:        "all",
		KnownProjects:      knownIDs,
		ProjectSchedule:    node.ProjectSchedule,
		DiskPolicy:         node.DiskPolicy,
		DisabledDisks:      append([]string(nil), node.DisabledDisks...),
		ConcurrencyMode:    node.ConcurrencyMode,
		MaxConcurrent:      maxConc,
		SuggestedStreamCap: suggestedStreamCap,
		RateLimitMBps:      rateLimitMBps,
	}
	if len(node.Projects) > 0 {
		dir.ProjectMode = "selected"
		dir.AllowedProjects = append([]string(nil), node.Projects...)
		hbResp.AllowedProjects = append([]string(nil), node.Projects...)
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
	projectsParam := strings.TrimSpace(r.URL.Query().Get("projects"))
	var projects []string
	wildcard := false
	if projectsParam == "*" && len(node.Projects) == 0 {
		wildcard = true
		projects = []string{"*"}
	} else if projectsParam != "" {
		for _, p := range strings.Split(projectsParam, ",") {
			p = strings.TrimSpace(p)
			if p == "*" && len(node.Projects) == 0 {
				wildcard = true
				projects = []string{"*"}
				break
			}
			if p != "" && nodeAllowsProject(node.Projects, p) {
				projects = append(projects, p)
			}
		}
	} else if len(node.Projects) > 0 {
		projects = node.Projects
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
			if !s.hub.IsOnline(aSt.LastSeen) {
				continue
			}
			for pid, av := range aSt.Availability {
				if av.ReadyCount > 0 {
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
			if len(s.hub.DiscoverCandidates(p)) > 0 {
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
	if !nodeAllowsProject(node.Projects, projectID) {
		protocol.WriteError(w, http.StatusForbidden, "b node not authorized for project")
		return
	}

	conflictPolicy := protocol.ConflictOverwrite
	leaseTTLSec := 300
	if proj, err := s.store.GetProject(r.Context(), projectID); err == nil {
		conflictPolicy = proj.ConflictPolicy
		leaseTTLSec = proj.LeaseTTLSec
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
	iq := parseIntervalQuery(r)

	projects, err := s.store.ListProjects(ctx)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
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
	dailyTrend, err := s.store.GetDailyStats(ctx, iq.ProjectID, 14)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	intervalResp, err := s.store.QueryIntervalStats(ctx, iq)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_, _, projWindowMap, err := s.store.GetWindowEntityStats(ctx, iq.Now, intervalResp.WindowHours)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	aSnap, bSnap := s.hub.Snapshot()
	overview := protocol.OverviewResp{
		GeneratedAt:        intervalResp.GeneratedAt,
		AuthTrustedIP:      s.isTrustedAdminRequest(r),
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
	for _, t := range totalsMap {
		overview.AllTimeCompleted += t.TotalCompleted
		overview.AllTimeBytes += t.TotalBytes
		overview.AllTimeFailed += t.TotalFailed
	}

	for _, n := range nodes {
		if n.Role == protocol.RoleAgentA {
			overview.TotalANodes++
			if st, ok := aSnap[n.ID]; ok && s.hub.IsOnline(st.LastSeen) {
				overview.OnlineANodes++
			}
		} else if n.Role == protocol.RoleAgentB {
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
			if nodeAllowsProject(aSt.Projects, p.ID) {
				ps.OnlineANodes++
			}
			if av, ok := aSt.Availability[p.ID]; ok && (av.ReadyCount > 0 || av.ClaimedCount > 0) {
				ps.QueuedFiles += av.ReadyCount + av.ClaimedCount
				ps.QueuedBytes += av.ReadyBytes
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
		sort.Slice(ps.ANodeAvailability, func(i, j int) bool {
			return ps.ANodeAvailability[i].ANodeID < ps.ANodeAvailability[j].ANodeID
		})
		for _, bSt := range bSnap {
			if s.hub.IsOnline(bSt.LastSeen) && nodeAllowsProject(bSt.Projects, p.ID) {
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
	list, err := s.store.ListProjects(r.Context())
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
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
	p.Name = strings.TrimSpace(p.Name)
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
	aWinStats, bWinStats, _, err := s.store.GetWindowEntityStats(ctx, time.Now().UTC(), hours)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	aSnap, bSnap := s.hub.Snapshot()
	upgrades, _ := s.store.ListNodeUpgrades(ctx)
	views := make([]protocol.LiveNodeView, 0, len(nodes))
	for _, n := range nodes {
		v := protocol.LiveNodeView{
			ID:                    n.ID,
			Name:                  n.Name,
			Role:                  n.Role,
			Projects:              n.Projects,
			ProjectSchedule:       n.ProjectSchedule,
			DiskPolicy:            n.DiskPolicy,
			DisabledDisks:         n.DisabledDisks,
			ConcurrencyMode:       n.ConcurrencyMode,
			MaxConcurrentOverride: n.MaxConcurrentOverride,
			RateLimitMBps:         n.RateLimitMBps,
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
				v.StorageDirs = st.StorageDirs
				v.Disks = st.Disks
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
	Projects              []string `json:"projects"`
	ProjectSchedule       string   `json:"project_schedule,omitempty"`
	DiskPolicy            string   `json:"disk_policy,omitempty"`
	DisabledDisks         []string `json:"disabled_disks,omitempty"`
	ConcurrencyMode       string   `json:"concurrency_mode,omitempty"`
	MaxConcurrentOverride int      `json:"max_concurrent_override,omitempty"`
	RateLimitMBps         float64  `json:"rate_limit_mbps,omitempty"`
	PublicAddr            string   `json:"public_addr"`
	Token                 string   `json:"token,omitempty"`
}

func cleanDiskPathList(raw []string) []string {
	out := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, p := range raw {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, dup := seen[p]; !dup {
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out
}

func (s *Server) handleAdminCreateNode(w http.ResponseWriter, r *http.Request) {
	var req createNodeReq
	if err := protocol.DecodeJSON(r.Body, &req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	req.Name = strings.TrimSpace(req.Name)
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
	if req.Role == protocol.RoleAgentA && req.PublicAddr != "" {
		if err := validateHTTPSAddr(req.PublicAddr); err != nil {
			protocol.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	sched := normalizeProjectSchedule(req.ProjectSchedule)
	if sched == "" {
		protocol.WriteError(w, http.StatusBadRequest, "project_schedule must be fifo, fair, or random")
		return
	}
	dp := normalizeDiskPolicy(req.DiskPolicy)
	if dp == "" {
		protocol.WriteError(w, http.StatusBadRequest, "disk_policy must be affinity_hash, most_free, round_robin, or first")
		return
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
	rec := protocol.NodeRecord{
		ID:                    req.ID,
		Name:                  req.Name,
		Role:                  req.Role,
		Projects:              req.Projects,
		ProjectSchedule:       sched,
		DiskPolicy:            dp,
		DisabledDisks:         cleanDiskPathList(req.DisabledDisks),
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
	Projects              *[]string `json:"projects,omitempty"`
	ProjectSchedule       string    `json:"project_schedule,omitempty"`
	DiskPolicy            string    `json:"disk_policy,omitempty"`
	DisabledDisks         *[]string `json:"disabled_disks,omitempty"`
	ConcurrencyMode       string    `json:"concurrency_mode,omitempty"`
	MaxConcurrentOverride *int      `json:"max_concurrent_override,omitempty"`
	RateLimitMBps         *float64  `json:"rate_limit_mbps,omitempty"`
	PublicAddr            string    `json:"public_addr,omitempty"`
}

func (s *Server) handleAdminUpdateNode(w http.ResponseWriter, r *http.Request) {
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

	var req updateNodeReq
	if err := protocol.DecodeJSON(r.Body, &req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}

	rec := *existing
	if name := strings.TrimSpace(req.Name); name != "" {
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
	if req.DiskPolicy != "" {
		dp := normalizeDiskPolicy(req.DiskPolicy)
		if dp == "" {
			protocol.WriteError(w, http.StatusBadRequest, "disk_policy must be affinity_hash, most_free, round_robin, or first")
			return
		}
		rec.DiskPolicy = dp
	}
	if req.DisabledDisks != nil {
		rec.DisabledDisks = cleanDiskPathList(*req.DisabledDisks)
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
	if req.Projects != nil {
		cleanProjects := make([]string, 0, len(*req.Projects))
		seen := make(map[string]struct{}, len(*req.Projects))
		for _, p := range *req.Projects {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if !validIDRe.MatchString(p) {
				protocol.WriteError(w, http.StatusBadRequest, "invalid project id: "+p)
				return
			}
			if _, dup := seen[p]; !dup {
				seen[p] = struct{}{}
				cleanProjects = append(cleanProjects, p)
			}
		}
		rec.Projects = cleanProjects
	}

	// Empty rawToken tells Store.UpsertNode to keep the existing token_hash untouched.
	if err := s.store.UpsertNode(r.Context(), rec, ""); err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.hub.UpdateNodeProjects(rec.ID, rec.Projects)
	protocol.WriteJSON(w, http.StatusOK, rec)
}

func (s *Server) handleAdminDeleteNode(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("id")
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
	iq := parseIntervalQuery(r)
	resp, err := s.store.QueryIntervalStats(r.Context(), iq)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	protocol.WriteJSON(w, http.StatusOK, resp)
}

func (s *Server) handleAdminDailyStats(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("project"))
	days := 14
	if dStr := r.URL.Query().Get("days"); dStr != "" {
		if parsed, err := strconv.Atoi(dStr); err == nil && parsed > 0 && parsed <= 90 {
			days = parsed
		}
	}
	stats, err := s.store.GetDailyStats(r.Context(), projectID, days)
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
