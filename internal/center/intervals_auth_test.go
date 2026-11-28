package center

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"relay-download/internal/pki"
	"relay-download/internal/protocol"
)

func TestIntervalStatsAggregationAndCleanup(t *testing.T) {
	st, err := OpenStore(filepath.Join(t.TempDir(), "center.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer st.Close()

	ctx := context.Background()
	// Align "now" cleanly on a 1-hour boundary so bucket math is exact.
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

	events := []protocol.SummaryEvent{
		// Bucket 1: 10:00..10:30 (2 hours ago) - 360 MB in 1800s => 200 KB/s (209,715 B/s)
		{
			EventID:   "e1",
			ProjectID: "p1",
			ANodeID:   "a1",
			BNodeID:   "b1",
			EventType: protocol.EventCompleted,
			Bytes:     180 * 1024 * 1024,
			Timestamp: now.Add(-115 * time.Minute),
		},
		{
			EventID:   "e2",
			ProjectID: "p1",
			ANodeID:   "a1",
			BNodeID:   "b1",
			EventType: protocol.EventCompleted,
			Bytes:     180 * 1024 * 1024,
			Timestamp: now.Add(-105 * time.Minute),
		},
		// Bucket 2: 11:00..11:30 (1 hour ago) - 900 MB in 1800s => 512 KB/s (524,288 B/s)
		{
			EventID:   "e3",
			ProjectID: "p2",
			ANodeID:   "a2",
			BNodeID:   "b2",
			EventType: protocol.EventCompleted,
			Bytes:     900 * 1024 * 1024,
			Timestamp: now.Add(-50 * time.Minute),
		},
		// Expired bucket (40 days ago) to verify CleanupOldIntervals
		{
			EventID:   "e-old",
			ProjectID: "p1",
			ANodeID:   "a1",
			BNodeID:   "b1",
			EventType: protocol.EventCompleted,
			Bytes:     50 * 1024 * 1024,
			Timestamp: now.Add(-40 * 24 * time.Hour),
		},
	}

	applied, err := st.RecordSummaryEvents(ctx, events)
	if err != nil || applied != 4 {
		t.Fatalf("RecordSummaryEvents: applied=%d err=%v", applied, err)
	}

	// Query 24h window with 30m buckets (48 buckets).
	resp, err := st.QueryIntervalStats(ctx, IntervalQuery{
		Now:           now,
		Hours:         24,
		BucketMinutes: 30,
	})
	if err != nil {
		t.Fatalf("QueryIntervalStats: %v", err)
	}
	if len(resp.Buckets) != 48 {
		t.Fatalf("expected 48 30m buckets for 24h, got %d", len(resp.Buckets))
	}
	wantTotalBytes := int64(360+900) * 1024 * 1024
	if resp.TotalCompleted != 3 || resp.TotalBytes != wantTotalBytes {
		t.Fatalf("unexpected totals: completed=%d bytes=%d (want 3, %d)", resp.TotalCompleted, resp.TotalBytes, wantTotalBytes)
	}
	wantPeak := int64(900*1024*1024) / 1800
	if resp.PeakSpeedBps != wantPeak {
		t.Fatalf("expected peak=%d B/s, got %d", wantPeak, resp.PeakSpeedBps)
	}
	wantActiveAvg := wantTotalBytes / 3600 // two 1800s active buckets
	if resp.ActiveAvgSpeedBps != wantActiveAvg {
		t.Fatalf("expected active_avg=%d B/s, got %d", wantActiveAvg, resp.ActiveAvgSpeedBps)
	}
	if resp.WindowAvgSpeedBps <= 0 || resp.WindowAvgSpeedBps >= resp.ActiveAvgSpeedBps {
		t.Fatalf("expected 0 < window_avg < active_avg, got window=%d active=%d", resp.WindowAvgSpeedBps, resp.ActiveAvgSpeedBps)
	}

	// Project filter must isolate p1 only.
	p1Resp, err := st.QueryIntervalStats(ctx, IntervalQuery{
		Now:           now,
		Hours:         24,
		BucketMinutes: 30,
		ProjectID:     "p1",
	})
	if err != nil {
		t.Fatalf("QueryIntervalStats p1: %v", err)
	}
	if p1Resp.TotalCompleted != 2 || p1Resp.TotalBytes != int64(360*1024*1024) {
		t.Fatalf("unexpected p1 stats: %+v", p1Resp)
	}

	// Entity stats map should separate a1/a2, b1/b2, p1/p2 cleanly.
	aStats, bStats, pStats, err := st.GetWindowEntityStats(ctx, now, 24)
	if err != nil {
		t.Fatalf("GetWindowEntityStats: %v", err)
	}
	if aStats["a1"].Completed != 2 || aStats["a2"].Completed != 1 {
		t.Fatalf("unexpected aStats: %+v", aStats)
	}
	if bStats["b1"].Completed != 2 || bStats["b2"].Completed != 1 {
		t.Fatalf("unexpected bStats: %+v", bStats)
	}
	if pStats["p1"].Bytes != int64(360*1024*1024) || pStats["p2"].Bytes != int64(900*1024*1024) {
		t.Fatalf("unexpected pStats: %+v", pStats)
	}

	// CleanupOldIntervals removes the 40-day-old bucket while retaining recent rows.
	if err := st.CleanupOldIntervals(ctx, 31*24*time.Hour); err != nil {
		t.Fatalf("CleanupOldIntervals: %v", err)
	}
	var oldCnt int
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM stats_intervals WHERE bucket_ts < ?`, now.Add(-31*24*time.Hour).Unix()).Scan(&oldCnt); err != nil {
		t.Fatalf("count old intervals: %v", err)
	}
	if oldCnt != 0 {
		t.Fatalf("expected old interval rows pruned, found %d", oldCnt)
	}
}

func TestTrustedAdminCIDRAndNoRealtimePayload(t *testing.T) {
	dir := t.TempDir()
	caCert := filepath.Join(dir, "ca.crt")
	caKey := filepath.Join(dir, "ca.key")
	if err := pki.InitCA(caCert, caKey, "Test CA", 365); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	srvCert := filepath.Join(dir, "center.crt")
	srvKey := filepath.Join(dir, "center.key")
	if err := pki.IssueCert(caCert, caKey, srvCert, srvKey, "center", []string{"127.0.0.1"}, nil, 365); err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	// Invalid CIDR must be rejected.
	badCfg := &Config{
		TLSCert:           srvCert,
		TLSKey:            srvKey,
		JWTSecret:         "jwt",
		CenterSecret:      "sec",
		AdminToken:        "adm",
		AdminTrustedCIDRs: []string{"not-an-ip"},
	}
	if err := badCfg.Validate(); err == nil {
		t.Fatalf("expected invalid admin_trusted_cidrs to fail validation")
	}

	srv, err := New(&Config{
		Listen:            "127.0.0.1:0",
		TLSCert:           srvCert,
		TLSKey:            srvKey,
		CACert:            caCert,
		DBPath:            filepath.Join(dir, "center.db"),
		ReleasesDir:       filepath.Join(dir, "releases"),
		JWTSecret:         "jwt-secret",
		CenterSecret:      "center-secret",
		AdminToken:        "secret-admin-token",
		AdminTrustedCIDRs: []string{"120.235.172.200", "127.0.0.1/32"},
	}, nil)
	if err != nil {
		t.Fatalf("New center server: %v", err)
	}
	defer srv.Shutdown(context.Background())

	handler := srv.routes()

	// 1. Trusted IP (bare IP & IPv4-mapped IPv6) succeeds WITHOUT X-Admin-Token and sets auth_trusted_ip=true.
	for _, remote := range []string{"120.235.172.200:54321", "[::ffff:120.235.172.200]:54321", "127.0.0.1:12345"} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/overview?hours=24&bucket_min=30", nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("trusted remote %s: expected 200, got %d (%s)", remote, rec.Code, rec.Body.String())
		}
		rawBody := rec.Body.String()
		if strings.Contains(rawBody, "active_transfers") || strings.Contains(rawBody, "live_total_speed_bps") {
			t.Fatalf("overview response must not contain realtime fields, got: %s", rawBody)
		}
		var ov protocol.OverviewResp
		if err := json.Unmarshal(rec.Body.Bytes(), &ov); err != nil {
			t.Fatalf("decode overview: %v", err)
		}
		if !ov.AuthTrustedIP {
			t.Fatalf("expected auth_trusted_ip=true for %s", remote)
		}
	}

	// 2. Untrusted IP without token MUST receive 401 (even if X-Forwarded-For spoofs a trusted IP!).
	untrustedReq := httptest.NewRequest(http.MethodGet, "/api/v1/admin/overview", nil)
	untrustedReq.RemoteAddr = "198.51.100.42:40000"
	untrustedReq.Header.Set("X-Forwarded-For", "120.235.172.200")
	untrustedRec := httptest.NewRecorder()
	handler.ServeHTTP(untrustedRec, untrustedReq)
	if untrustedRec.Code != http.StatusUnauthorized {
		t.Fatalf("untrusted remote without token: expected 401, got %d", untrustedRec.Code)
	}

	// 3. Untrusted IP WITH valid token succeeds and reports auth_trusted_ip=false.
	tokReq := httptest.NewRequest(http.MethodGet, "/api/v1/admin/overview", nil)
	tokReq.RemoteAddr = "198.51.100.42:40001"
	tokReq.Header.Set(protocol.HeaderAdminToken, "secret-admin-token")
	tokRec := httptest.NewRecorder()
	handler.ServeHTTP(tokRec, tokReq)
	if tokRec.Code != http.StatusOK {
		t.Fatalf("untrusted remote with token: expected 200, got %d", tokRec.Code)
	}
	var ov protocol.OverviewResp
	_ = json.Unmarshal(tokRec.Body.Bytes(), &ov)
	if ov.AuthTrustedIP {
		t.Fatalf("expected auth_trusted_ip=false for token-authenticated untrusted IP")
	}
}

func TestUpdateReceiverSingleProjectWithoutTokenRotation(t *testing.T) {
	dir := t.TempDir()
	caCert := filepath.Join(dir, "ca.crt")
	caKey := filepath.Join(dir, "ca.key")
	if err := pki.InitCA(caCert, caKey, "Test CA", 365); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	srvCert := filepath.Join(dir, "center.crt")
	srvKey := filepath.Join(dir, "center.key")
	if err := pki.IssueCert(caCert, caKey, srvCert, srvKey, "center", []string{"127.0.0.1"}, nil, 365); err != nil {
		t.Fatalf("IssueCert: %v", err)
	}
	srv, err := New(&Config{
		Listen:       "127.0.0.1:0",
		TLSCert:      srvCert,
		TLSKey:       srvKey,
		CACert:       caCert,
		DBPath:       filepath.Join(dir, "center.db"),
		ReleasesDir:  filepath.Join(dir, "releases"),
		JWTSecret:    "jwt-secret",
		CenterSecret: "center-secret",
		AdminToken:   "adm-tok",
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.Shutdown(context.Background())

	h := srv.routes()

	// 1. Register receiver node with unrestricted projects.
	createBody := `{"id":"rx-01","name":"NAS 1","role":"agent_b","projects":[]}`
	cReq := httptest.NewRequest(http.MethodPost, "/api/v1/admin/nodes", strings.NewReader(createBody))
	cReq.Header.Set(protocol.HeaderAdminToken, "adm-tok")
	cRec := httptest.NewRecorder()
	h.ServeHTTP(cRec, cReq)
	if cRec.Code != http.StatusOK {
		t.Fatalf("create node: %d %s", cRec.Code, cRec.Body.String())
	}
	var created struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(cRec.Body.Bytes(), &created)

	// 2. Lock rx-01 to ONLY "proj-alpha" via PUT /api/v1/admin/nodes/rx-01.
	uReq := httptest.NewRequest(http.MethodPut, "/api/v1/admin/nodes/rx-01", strings.NewReader(`{"name":"NAS 1 (Alpha Only)","projects":["proj-alpha"]}`))
	uReq.Header.Set(protocol.HeaderAdminToken, "adm-tok")
	uRec := httptest.NewRecorder()
	h.ServeHTTP(uRec, uReq)
	if uRec.Code != http.StatusOK {
		t.Fatalf("update node: %d %s", uRec.Code, uRec.Body.String())
	}

	// 3. Original token must STILL authenticate on heartbeat and receive allowed_projects=["proj-alpha"].
	hbReq := httptest.NewRequest(http.MethodPost, "/api/v1/b/heartbeat", strings.NewReader(`{"node_id":"rx-01","projects":["proj-alpha","proj-beta"]}`))
	hbReq.Header.Set(protocol.HeaderNodeID, "rx-01")
	hbReq.Header.Set(protocol.HeaderNodeToken, created.Token)
	hbRec := httptest.NewRecorder()
	h.ServeHTTP(hbRec, hbReq)
	if hbRec.Code != http.StatusOK {
		t.Fatalf("heartbeat with original token failed after PUT update: %d %s", hbRec.Code, hbRec.Body.String())
	}
	var hbResp protocol.HeartbeatResp
	_ = json.Unmarshal(hbRec.Body.Bytes(), &hbResp)
	if len(hbResp.AllowedProjects) != 1 || hbResp.AllowedProjects[0] != "proj-alpha" {
		t.Fatalf("expected allowed_projects=[proj-alpha], got %+v", hbResp.AllowedProjects)
	}

	// 4. Discover must ALLOW proj-alpha (200) and FORBID proj-beta (403).
	dOK := httptest.NewRequest(http.MethodGet, "/api/v1/b/discover?project=proj-alpha", nil)
	dOK.Header.Set(protocol.HeaderNodeID, "rx-01")
	dOK.Header.Set(protocol.HeaderNodeToken, created.Token)
	dOKRec := httptest.NewRecorder()
	h.ServeHTTP(dOKRec, dOK)
	if dOKRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for allowed proj-alpha, got %d", dOKRec.Code)
	}

	dDeny := httptest.NewRequest(http.MethodGet, "/api/v1/b/discover?project=proj-beta", nil)
	dDeny.Header.Set(protocol.HeaderNodeID, "rx-01")
	dDeny.Header.Set(protocol.HeaderNodeToken, created.Token)
	dDenyRec := httptest.NewRecorder()
	h.ServeHTTP(dDenyRec, dDeny)
	if dDenyRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for disallowed proj-beta, got %d", dDenyRec.Code)
	}
}

func TestAutoCreateProjectsAndReceiverDirectives(t *testing.T) {
	dir := t.TempDir()
	caCert := filepath.Join(dir, "ca.crt")
	caKey := filepath.Join(dir, "ca.key")
	if err := pki.InitCA(caCert, caKey, "Test CA", 365); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	srvCert := filepath.Join(dir, "center.crt")
	srvKey := filepath.Join(dir, "center.key")
	if err := pki.IssueCert(caCert, caKey, srvCert, srvKey, "center", []string{"127.0.0.1"}, nil, 365); err != nil {
		t.Fatalf("IssueCert: %v", err)
	}
	srv, err := New(&Config{
		Listen:       "127.0.0.1:0",
		TLSCert:      srvCert,
		TLSKey:       srvKey,
		CACert:       caCert,
		DBPath:       filepath.Join(dir, "center.db"),
		ReleasesDir:  filepath.Join(dir, "releases"),
		JWTSecret:    "jwt-secret",
		CenterSecret: "center-secret",
		AdminToken:   "adm-tok",
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.Shutdown(context.Background())

	h := srv.routes()

	createNode := func(body string) string {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/nodes", strings.NewReader(body))
		req.Header.Set(protocol.HeaderAdminToken, "adm-tok")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("create node failed: %d %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Token string `json:"token"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out.Token
	}

	tokA := createNode(`{"id":"edge-01","name":"Edge 1","role":"agent_a","public_addr":"https://10.0.0.1:8443","projects":[]}`)
	tokB := createNode(`{"id":"nas-01","name":"NAS 1","role":"agent_b","projects":[]}`)

	// 1. Dispatch node reports availability for an unseen project -> Center must auto-create it!
	aHB := `{"node_id":"edge-01","public_addr":"https://10.0.0.1:8443","availability":[{"project_id":"auto-proj-1","ready_count":5,"ready_bytes":10240}]}`
	aReq := httptest.NewRequest(http.MethodPost, "/api/v1/a/heartbeat", strings.NewReader(aHB))
	aReq.Header.Set(protocol.HeaderNodeID, "edge-01")
	aReq.Header.Set(protocol.HeaderNodeToken, tokA)
	aRec := httptest.NewRecorder()
	h.ServeHTTP(aRec, aReq)
	if aRec.Code != http.StatusOK {
		t.Fatalf("a heartbeat: %d %s", aRec.Code, aRec.Body.String())
	}

	// Verify auto-proj-1 now exists in /api/v1/admin/projects.
	pReq := httptest.NewRequest(http.MethodGet, "/api/v1/admin/projects", nil)
	pReq.Header.Set(protocol.HeaderAdminToken, "adm-tok")
	pRec := httptest.NewRecorder()
	h.ServeHTTP(pRec, pReq)
	var projects []protocol.Project
	_ = json.Unmarshal(pRec.Body.Bytes(), &projects)
	if len(projects) != 1 || projects[0].ID != "auto-proj-1" {
		t.Fatalf("expected auto-created project [auto-proj-1], got %+v", projects)
	}

	// 2. Admin updates receiver schedule, disk policy, and disabled_disks via PUT.
	updBody := `{"projects":[],"project_schedule":"fair","disk_policy":"most_free","disabled_disks":["/mnt/sda/relay"]}`
	uReq := httptest.NewRequest(http.MethodPut, "/api/v1/admin/nodes/nas-01", strings.NewReader(updBody))
	uReq.Header.Set(protocol.HeaderAdminToken, "adm-tok")
	uRec := httptest.NewRecorder()
	h.ServeHTTP(uRec, uReq)
	if uRec.Code != http.StatusOK {
		t.Fatalf("update receiver: %d %s", uRec.Code, uRec.Body.String())
	}

	// 3. Receiver heartbeat reports its storage_dirs & per-disk telemetry and receives full ReceiverDirective.
	bHB := `{"node_id":"nas-01","storage_dirs":["/mnt/sda/relay","/mnt/sdb/relay"],"disks":[{"path":"/mnt/sda/relay","total_bytes":1000,"free_bytes":400,"used_pct":60,"enabled":false,"writable":true},{"path":"/mnt/sdb/relay","total_bytes":1000,"free_bytes":800,"used_pct":20,"enabled":true,"writable":true}]}`
	bReq := httptest.NewRequest(http.MethodPost, "/api/v1/b/heartbeat", strings.NewReader(bHB))
	bReq.Header.Set(protocol.HeaderNodeID, "nas-01")
	bReq.Header.Set(protocol.HeaderNodeToken, tokB)
	bRec := httptest.NewRecorder()
	h.ServeHTTP(bRec, bReq)
	if bRec.Code != http.StatusOK {
		t.Fatalf("b heartbeat: %d %s", bRec.Code, bRec.Body.String())
	}
	var hbResp protocol.HeartbeatResp
	_ = json.Unmarshal(bRec.Body.Bytes(), &hbResp)
	if hbResp.Directive == nil {
		t.Fatalf("expected ReceiverDirective in HeartbeatResp")
	}
	d := hbResp.Directive
	if d.ProjectMode != "all" || d.ProjectSchedule != "fair" || d.DiskPolicy != "most_free" {
		t.Fatalf("unexpected directive fields: %+v", d)
	}
	if len(d.KnownProjects) != 1 || d.KnownProjects[0] != "auto-proj-1" {
		t.Fatalf("expected KnownProjects=[auto-proj-1], got %+v", d.KnownProjects)
	}
	if len(d.DisabledDisks) != 1 || d.DisabledDisks[0] != "/mnt/sda/relay" {
		t.Fatalf("expected DisabledDisks=[/mnt/sda/relay], got %+v", d.DisabledDisks)
	}

	// 4. /api/v1/admin/nodes must expose per-disk telemetry, storage_dirs, schedule & disk policy.
	nReq := httptest.NewRequest(http.MethodGet, "/api/v1/admin/nodes?hours=24", nil)
	nReq.Header.Set(protocol.HeaderAdminToken, "adm-tok")
	nRec := httptest.NewRecorder()
	h.ServeHTTP(nRec, nReq)
	var views []protocol.LiveNodeView
	_ = json.Unmarshal(nRec.Body.Bytes(), &views)
	var foundB *protocol.LiveNodeView
	for i := range views {
		if views[i].ID == "nas-01" {
			foundB = &views[i]
		}
	}
	if foundB == nil {
		t.Fatalf("nas-01 not found in admin nodes list")
	}
	if foundB.ProjectSchedule != "fair" || foundB.DiskPolicy != "most_free" || len(foundB.Disks) != 2 || len(foundB.StorageDirs) != 2 {
		t.Fatalf("unexpected LiveNodeView for nas-01: %+v", foundB)
	}
}

func TestClusterQuotaFairShareAndActiveReceiversSync(t *testing.T) {
	dir := t.TempDir()
	caCert := filepath.Join(dir, "ca.crt")
	caKey := filepath.Join(dir, "ca.key")
	if err := pki.InitCA(caCert, caKey, "Test CA", 365); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	srvCert := filepath.Join(dir, "center.crt")
	srvKey := filepath.Join(dir, "center.key")
	if err := pki.IssueCert(caCert, caKey, srvCert, srvKey, "center", []string{"127.0.0.1"}, nil, 365); err != nil {
		t.Fatalf("IssueCert: %v", err)
	}
	srv, err := New(&Config{
		Listen:       "127.0.0.1:0",
		TLSCert:      srvCert,
		TLSKey:       srvKey,
		CACert:       caCert,
		DBPath:       filepath.Join(dir, "center.db"),
		ReleasesDir:  filepath.Join(dir, "releases"),
		JWTSecret:    "jwt-secret",
		CenterSecret: "center-secret",
		AdminToken:   "adm-tok",
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.Shutdown(context.Background())
	h := srv.routes()

	postAdmin := func(path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set(protocol.HeaderAdminToken, "adm-tok")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("POST %s failed: %d %s", path, rec.Code, rec.Body.String())
		}
		return rec
	}

	// Create project with group_affinity=true, global max_total_concurrent=200, max_total_rate_mbps=100.
	postAdmin("/api/v1/admin/projects", `{"id":"proj-big","name":"Big","group_affinity":true,"max_total_concurrent":200,"max_total_rate_mbps":100}`)

	createTok := func(body string) string {
		rec := postAdmin("/api/v1/admin/nodes", body)
		var out struct {
			Token string `json:"token"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out.Token
	}

	tokA := createTok(`{"id":"edge-01","role":"agent_a","public_addr":"https://10.0.0.1:8443","projects":[]}`)
	tokB1 := createTok(`{"id":"nas-01","role":"agent_b","projects":["proj-big"]}`)
	tokB2 := createTok(`{"id":"nas-02","role":"agent_b","projects":["proj-big"]}`)

	// 1. Both receivers heartbeat -> each should receive fair-share 50 MB/s and max_concurrent=100!
	hbB := func(id, tok string) protocol.HeartbeatResp {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/b/heartbeat", strings.NewReader(`{"node_id":"`+id+`","projects":["proj-big"],"effective_concurrent":60,"max_concurrent_cap":100,"adaptive_state":"cruising"}`))
		req.Header.Set(protocol.HeaderNodeID, id)
		req.Header.Set(protocol.HeaderNodeToken, tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("b heartbeat %s: %d %s", id, rec.Code, rec.Body.String())
		}
		var out protocol.HeartbeatResp
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out
	}

	// Dispatch heartbeat reports 1000 max_concurrent_streams.
	aReq := httptest.NewRequest(http.MethodPost, "/api/v1/a/heartbeat", strings.NewReader(`{"node_id":"edge-01","public_addr":"https://10.0.0.1:8443","max_concurrent_streams":1000}`))
	aReq.Header.Set(protocol.HeaderNodeID, "edge-01")
	aReq.Header.Set(protocol.HeaderNodeToken, tokA)
	aRec := httptest.NewRecorder()
	h.ServeHTTP(aRec, aReq)

	// First receiver online alone -> gets full 200 concurrent / 100 MB/s!
	r1Solo := hbB("nas-01", tokB1)
	if r1Solo.Directive.MaxConcurrent != 200 || r1Solo.Directive.RateLimitMBps != 100 {
		t.Fatalf("solo receiver expected 200/100MBps, got %+v", r1Solo.Directive)
	}

	// Second receiver joins -> both split evenly to 100 concurrent / 50 MB/s + suggested stream cap = 625!
	r2 := hbB("nas-02", tokB2)
	if r2.Directive.MaxConcurrent != 100 || r2.Directive.RateLimitMBps != 50 || r2.Directive.SuggestedStreamCap != 625 {
		t.Fatalf("2-node fair share expected 100 / 50MBps / 625 streams, got %+v", r2.Directive)
	}

	// Dispatch node heartbeat now receives sorted active_receivers={"proj-big":["nas-01","nas-02"]} and project_affinity={"proj-big":true}!
	aReq2 := httptest.NewRequest(http.MethodPost, "/api/v1/a/heartbeat", strings.NewReader(`{"node_id":"edge-01","public_addr":"https://10.0.0.1:8443","max_concurrent_streams":1000}`))
	aReq2.Header.Set(protocol.HeaderNodeID, "edge-01")
	aReq2.Header.Set(protocol.HeaderNodeToken, tokA)
	aRec2 := httptest.NewRecorder()
	h.ServeHTTP(aRec2, aReq2)
	var aResp protocol.HeartbeatResp
	_ = json.Unmarshal(aRec2.Body.Bytes(), &aResp)
	revs := aResp.ActiveReceivers["proj-big"]
	if len(revs) != 2 || revs[0] != "nas-01" || revs[1] != "nas-02" || !aResp.ProjectAffinity["proj-big"] {
		t.Fatalf("unexpected Agent A HRW routing response: active=%+v affinity=%+v", aResp.ActiveReceivers, aResp.ProjectAffinity)
	}
}

func TestWindowEntityStatsTracksRecentFailedAndLastFailedAt(t *testing.T) {
	st, err := OpenStore(filepath.Join(t.TempDir(), "center.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer st.Close()

	now := time.Now().UTC().Truncate(time.Minute)
	oldFailAt := now.Add(-3 * time.Hour)
	recentFailAt := now.Add(-2 * time.Minute)

	events := []protocol.SummaryEvent{
		{EventID: "f-old-1", ProjectID: "proj-old", ANodeID: "a-1", BNodeID: "b-1", EventType: protocol.EventFailed, Bytes: 100, Timestamp: oldFailAt},
		{EventID: "c-old-1", ProjectID: "proj-old", ANodeID: "a-1", BNodeID: "b-1", EventType: protocol.EventCompleted, Bytes: 100, Timestamp: oldFailAt.Add(time.Minute)},
		{EventID: "f-rec-1", ProjectID: "proj-rec", ANodeID: "a-2", BNodeID: "b-1", EventType: protocol.EventFailed, Bytes: 200, Timestamp: recentFailAt},
	}
	if _, err := st.RecordSummaryEvents(context.Background(), events); err != nil {
		t.Fatalf("RecordSummaryEvents: %v", err)
	}

	aStats, bStats, pStats, err := st.GetWindowEntityStats(context.Background(), now, 24)
	if err != nil {
		t.Fatalf("GetWindowEntityStats: %v", err)
	}

	oldP := pStats["proj-old"]
	if oldP.Failed != 1 || oldP.RecentFailed != 0 || oldP.LastFailedAt == nil {
		t.Fatalf("proj-old expected failed=1 recent_failed=0 last_failed_at!=nil, got %+v", oldP)
	}
	if now.Sub(*oldP.LastFailedAt) < 2*time.Hour {
		t.Fatalf("proj-old last_failed_at should be >2h ago, got %v (now=%v)", oldP.LastFailedAt, now)
	}

	recP := pStats["proj-rec"]
	if recP.Failed != 1 || recP.RecentFailed != 1 || recP.LastFailedAt == nil {
		t.Fatalf("proj-rec expected failed=1 recent_failed=1 last_failed_at!=nil, got %+v", recP)
	}
	if now.Sub(*recP.LastFailedAt) > 10*time.Minute {
		t.Fatalf("proj-rec last_failed_at should be within 10m, got %v (now=%v)", recP.LastFailedAt, now)
	}

	if aStats["a-1"].RecentFailed != 0 || aStats["a-2"].RecentFailed != 1 || bStats["b-1"].Failed != 2 || bStats["b-1"].RecentFailed != 1 {
		t.Fatalf("unexpected node failure stats: a=%+v b=%+v", aStats, bStats)
	}
}
