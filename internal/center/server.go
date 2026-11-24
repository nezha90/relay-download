package center

import (
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"relay-download/internal/auth"
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
	cfg        *Config
	store      *Store
	hub        *Hub
	logger     *slog.Logger
	proxyHTTP  *http.Client
	httpServer *http.Server
	ln         net.Listener
	closeOnce  sync.Once
}

func New(cfg *Config, logger *slog.Logger) (*Server, error) {
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	store, err := OpenStore(cfg.DBPath)
	if err != nil {
		return nil, err
	}
	clientTLS, err := pki.ClientTLSConfig(cfg.CACert)
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	return &Server{
		cfg:    cfg,
		store:  store,
		hub:    NewHub(cfg.NodeOfflineTimeout()),
		logger: logger.With("component", "center"),
		proxyHTTP: &http.Client{
			Timeout: 2 * time.Second, // Strict 2s timeout for live proxy queries to A nodes
			Transport: &http.Transport{
				TLSClientConfig:     clientTLS,
				ForceAttemptHTTP2:   true,
				MaxIdleConns:        32,
				IdleConnTimeout:     30 * time.Second,
				TLSHandshakeTimeout: 2 * time.Second,
			},
		},
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

	// Admin & Web UI API
	mux.HandleFunc("GET /api/v1/admin/overview", s.requireAdmin(s.handleAdminOverview))
	mux.HandleFunc("GET /api/v1/admin/projects", s.requireAdmin(s.handleAdminListProjects))
	mux.HandleFunc("POST /api/v1/admin/projects", s.requireAdmin(s.handleAdminUpsertProject))
	mux.HandleFunc("DELETE /api/v1/admin/projects/{id}", s.requireAdmin(s.handleAdminDeleteProject))
	mux.HandleFunc("GET /api/v1/admin/nodes", s.requireAdmin(s.handleAdminListNodes))
	mux.HandleFunc("POST /api/v1/admin/nodes", s.requireAdmin(s.handleAdminCreateNode))
	mux.HandleFunc("DELETE /api/v1/admin/nodes/{id}", s.requireAdmin(s.handleAdminDeleteNode))
	mux.HandleFunc("GET /api/v1/admin/nodes/{id}/live-files", s.requireAdmin(s.handleAdminNodeLiveFiles))
	mux.HandleFunc("GET /api/v1/admin/projects/{id}/live-files", s.requireAdmin(s.handleAdminProjectLiveFiles))
	mux.HandleFunc("GET /api/v1/admin/stats/daily", s.requireAdmin(s.handleAdminDailyStats))

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

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
	s.hub.UpdateA(req)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleAEvents(w http.ResponseWriter, r *http.Request, node *StoredNode) {
	var req protocol.SummaryEventsReq
	if err := protocol.DecodeJSON(r.Body, &req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "invalid events payload")
		return
	}
	validEvents := make([]protocol.SummaryEvent, 0, len(req.Events))
	for _, ev := range req.Events {
		if !nodeAllowsProject(node.Projects, ev.ProjectID) || ev.Bytes < 0 || ev.DurationMs < 0 {
			continue
		}
		ev.ANodeID = node.ID
		validEvents = append(validEvents, ev)
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
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleBEventsSSE(w http.ResponseWriter, r *http.Request, node *StoredNode) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		protocol.WriteError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	projectsParam := strings.TrimSpace(r.URL.Query().Get("projects"))
	var projects []string
	if projectsParam != "" {
		for _, p := range strings.Split(projectsParam, ",") {
			p = strings.TrimSpace(p)
			if p != "" && nodeAllowsProject(node.Projects, p) {
				projects = append(projects, p)
			}
		}
	} else {
		projects = node.Projects
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
	for _, p := range projects {
		if len(s.hub.DiscoverCandidates(p)) > 0 {
			_, _ = fmt.Fprintf(w, "event: wakeup\ndata: %s\n\n", p)
			flusher.Flush()
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

func (s *Server) handleAdminOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
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
	dailyTrend, err := s.store.GetDailyStats(ctx, "", 14)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	aSnap, bSnap := s.hub.Snapshot()
	overview := protocol.OverviewResp{
		TotalProjects: len(projects),
		DailyTrend:    dailyTrend,
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

	// Build active transfers list from online B nodes.
	allActive := make([]protocol.BActiveTransferView, 0)
	activeByProj := make(map[string][]protocol.BActiveTransferView)
	for _, st := range bSnap {
		if !s.hub.IsOnline(st.LastSeen) {
			continue
		}
		overview.LiveTotalSpeedBps += st.InSpeedBps
		for _, tr := range st.ActiveTransfers {
			v := protocol.BActiveTransferView{
				BNodeID:          st.NodeID,
				BName:            st.Name,
				ProjectID:        tr.ProjectID,
				ANodeID:          tr.ANodeID,
				FileID:           tr.FileID,
				Filename:         tr.Filename,
				TransferredBytes: tr.TransferredBytes,
				TotalBytes:       tr.TotalBytes,
				SpeedBps:         tr.SpeedBps,
				StartedAt:        tr.StartedAt,
			}
			allActive = append(allActive, v)
			activeByProj[tr.ProjectID] = append(activeByProj[tr.ProjectID], v)
		}
	}
	overview.LiveActiveFiles = len(allActive)
	overview.ActiveTransfers = allActive

	projSummaries := make([]protocol.ProjectSummary, 0, len(projects))
	for _, p := range projects {
		t := totalsMap[p.ID]
		act := activeByProj[p.ID]
		if act == nil {
			act = make([]protocol.BActiveTransferView, 0)
		}
		ps := protocol.ProjectSummary{
			Project:           p,
			TotalUploaded:     t.TotalUploaded,
			TotalCompleted:    t.TotalCompleted,
			TotalFailed:       t.TotalFailed,
			TotalBytes:        t.TotalBytes,
			ANodeAvailability: make([]protocol.ANodeAvailSummary, 0),
			ActiveTransfers:   act,
		}
		for _, aSt := range aSnap {
			if !s.hub.IsOnline(aSt.LastSeen) {
				continue
			}
			if nodeAllowsProject(aSt.Projects, p.ID) {
				ps.OnlineANodes++
			}
			if av, ok := aSt.Availability[p.ID]; ok && (av.ReadyCount > 0 || av.ClaimedCount > 0) {
				ps.LiveReadyCount += av.ReadyCount
				ps.LiveClaimedCount += av.ClaimedCount
				ps.LiveReadyBytes += av.ReadyBytes
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
		overview.LiveReadyFiles += ps.LiveReadyCount
		overview.LiveReadyBytes += ps.LiveReadyBytes
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
	p.CreatedAt = time.Now().UTC()
	if err := s.store.UpsertProject(r.Context(), p); err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if saved, err := s.store.GetProject(r.Context(), p.ID); err == nil {
		p = *saved
	}
	protocol.WriteJSON(w, http.StatusOK, p)
}

func (s *Server) handleAdminDeleteProject(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteProject(r.Context(), r.PathValue("id")); err != nil {
		if errors.Is(err, ErrNotFound) {
			protocol.WriteError(w, http.StatusNotFound, "project not found")
			return
		}
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAdminListNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.store.ListNodes(r.Context())
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	aSnap, bSnap := s.hub.Snapshot()
	views := make([]protocol.LiveNodeView, 0, len(nodes))
	for _, n := range nodes {
		v := protocol.LiveNodeView{
			ID:         n.ID,
			Name:       n.Name,
			Role:       n.Role,
			Projects:   n.Projects,
			PublicAddr: n.PublicAddr,
		}
		if n.Role == protocol.RoleAgentA {
			if st, ok := aSnap[n.ID]; ok {
				ls := st.LastSeen
				v.LastSeenAt = &ls
				v.Online = s.hub.IsOnline(st.LastSeen)
				if st.PublicAddr != "" {
					v.PublicAddr = st.PublicAddr
				}
				v.DiskTotalBytes = st.DiskTotalBytes
				v.DiskFreeBytes = st.DiskFreeBytes
				v.DiskUsedPct = st.DiskUsedPct
				v.DiskAlarm = st.DiskAlarm
				v.ActiveStreams = st.ActiveStreams
				v.SpeedBps = st.OutSpeedBps
				for _, av := range st.Availability {
					v.Availability = append(v.Availability, av)
				}
				sort.Slice(v.Availability, func(i, j int) bool {
					return v.Availability[i].ProjectID < v.Availability[j].ProjectID
				})
			}
		} else if n.Role == protocol.RoleAgentB {
			if st, ok := bSnap[n.ID]; ok {
				ls := st.LastSeen
				v.LastSeenAt = &ls
				v.Online = s.hub.IsOnline(st.LastSeen)
				v.DiskTotalBytes = st.DiskTotalBytes
				v.DiskFreeBytes = st.DiskFreeBytes
				v.DiskUsedPct = st.DiskUsedPct
				v.ActiveStreams = len(st.ActiveTransfers)
				v.SpeedBps = st.InSpeedBps
				v.ActiveTransfers = st.ActiveTransfers
			}
		}
		views = append(views, v)
	}
	protocol.WriteJSON(w, http.StatusOK, views)
}

type createNodeReq struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Role       string   `json:"role"`
	Projects   []string `json:"projects"`
	PublicAddr string   `json:"public_addr"`
	Token      string   `json:"token,omitempty"`
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
	if req.Name == "" {
		req.Name = req.ID
	}
	rawToken := strings.TrimSpace(req.Token)
	if rawToken == "" {
		rawToken = auth.GenerateRandomToken(24)
	}
	rec := protocol.NodeRecord{
		ID:         req.ID,
		Name:       req.Name,
		Role:       req.Role,
		Projects:   req.Projects,
		PublicAddr: req.PublicAddr,
		CreatedAt:  time.Now().UTC(),
	}
	if err := s.store.UpsertNode(r.Context(), rec, rawToken); err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]any{
		"node":  rec,
		"token": rawToken,
	})
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
	s.hub.RemoveNode(nodeID)
	w.WriteHeader(http.StatusNoContent)
}

// handleAdminNodeLiveFiles performs a live proxy query directly to an A node (2s timeout)
// without persisting any file list in Center.
func (s *Server) handleAdminNodeLiveFiles(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("id")
	projectFilter := strings.TrimSpace(r.URL.Query().Get("project"))

	publicAddr := ""
	nodeName := nodeID
	if live, ok := s.hub.GetLiveA(nodeID); ok && live.PublicAddr != "" {
		publicAddr = live.PublicAddr
		nodeName = live.Name
	} else if rec, err := s.store.GetNode(r.Context(), nodeID); err == nil && rec.Role == protocol.RoleAgentA {
		publicAddr = rec.PublicAddr
		nodeName = rec.Name
	} else {
		protocol.WriteError(w, http.StatusNotFound, "agent-a node not found")
		return
	}

	resp := s.fetchALiveFiles(r.Context(), nodeID, nodeName, publicAddr, projectFilter)
	protocol.WriteJSON(w, http.StatusOK, resp)
}

// handleAdminProjectLiveFiles fans out live proxy queries ONLY to online A nodes
// that currently report files for this project, with graceful partial results.
func (s *Server) handleAdminProjectLiveFiles(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	activeAs := s.hub.ActiveANodesForProject(projectID)
	results := make([]protocol.LiveFilesResp, len(activeAs))
	var wg sync.WaitGroup
	for i, aNode := range activeAs {
		wg.Add(1)
		go func(idx int, st *LiveAState) {
			defer wg.Done()
			results[idx] = s.fetchALiveFiles(r.Context(), st.NodeID, st.Name, st.PublicAddr, projectID)
		}(i, aNode)
	}
	wg.Wait()
	sort.Slice(results, func(i, j int) bool {
		return results[i].ANodeID < results[j].ANodeID
	})
	protocol.WriteJSON(w, http.StatusOK, results)
}

func (s *Server) fetchALiveFiles(ctx context.Context, nodeID, nodeName, publicAddr, projectFilter string) protocol.LiveFilesResp {
	fallback := protocol.LiveFilesResp{
		ANodeID:    nodeID,
		AName:      nodeName,
		PublicAddr: publicAddr,
		Files:      make([]protocol.LiveFileItem, 0),
	}
	if publicAddr == "" {
		fallback.Error = "node has no public_addr"
		return fallback
	}
	if err := validateHTTPSAddr(publicAddr); err != nil {
		fallback.Error = err.Error()
		return fallback
	}
	u := strings.TrimRight(publicAddr, "/") + "/internal/v1/files"
	if projectFilter != "" {
		u += "?project=" + url.QueryEscape(projectFilter)
	}
	qCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(qCtx, http.MethodGet, u, nil)
	if err != nil {
		fallback.Error = err.Error()
		return fallback
	}
	if s.cfg.CenterSecret != "" {
		req.Header.Set(protocol.HeaderCenterSecret, s.cfg.CenterSecret)
	}
	resp, err := s.proxyHTTP.Do(req)
	if err != nil {
		fallback.Error = "unreachable: " + err.Error()
		return fallback
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fallback.Error = fmt.Sprintf("agent-a returned HTTP %d", resp.StatusCode)
		return fallback
	}
	var live protocol.LiveFilesResp
	if err := json.NewDecoder(resp.Body).Decode(&live); err != nil {
		fallback.Error = "decode error: " + err.Error()
		return fallback
	}
	return live
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
