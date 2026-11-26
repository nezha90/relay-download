package center

import (
	"bytes"
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

func TestCustomerAccountRBACAndProjectScoping(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	caKeyPath := filepath.Join(dir, "ca.key")
	if err := pki.InitCA(caPath, caKeyPath, "relay-rbac-test-ca", 365); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	srvCert := filepath.Join(dir, "center.crt")
	srvKey := filepath.Join(dir, "center.key")
	if err := pki.IssueCert(caPath, caKeyPath, srvCert, srvKey, "center", []string{"127.0.0.1"}, nil, 365); err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	srv, err := New(&Config{
		Listen:            "127.0.0.1:0",
		TLSCert:           srvCert,
		TLSKey:            srvKey,
		CACert:            caPath,
		PublicURL:         "https://center.test:8440",
		ReleasesDir:       filepath.Join(dir, "releases"),
		DBPath:            filepath.Join(dir, "center.db"),
		JWTSecret:         "jwt-secret-rbac-test",
		CenterSecret:      "center-secret-rbac-test",
		AdminToken:        "super-admin-token-123456",
		AdminTrustedCIDRs: []string{"127.0.0.1/32"},
	}, nil)
	if err != nil {
		t.Fatalf("New center: %v", err)
	}
	defer srv.Shutdown(context.Background())

	ctx := context.Background()
	now := time.Now().UTC()

	// Seed projects, nodes (1 dispatch + 2 receivers), releases, live heartbeats, and summary stats.
	for _, pid := range []string{"proj-a", "proj-b"} {
		if err := srv.store.UpsertProject(ctx, protocol.Project{
			ID: pid, Name: pid, ConflictPolicy: protocol.ConflictOverwrite, LeaseTTLSec: 300, CreatedAt: now,
		}); err != nil {
			t.Fatalf("UpsertProject %s: %v", pid, err)
		}
	}
	if err := srv.store.UpsertNode(ctx, protocol.NodeRecord{
		ID: "a-1", Name: "Dispatch-1", Role: protocol.RoleAgentA, PublicAddr: "https://10.0.0.1:8443", CreatedAt: now,
	}, "tok-a-1"); err != nil {
		t.Fatalf("UpsertNode a-1: %v", err)
	}
	if err := srv.store.UpsertNode(ctx, protocol.NodeRecord{
		ID: "b-a", Name: "Recv-A", Role: protocol.RoleAgentB, Projects: []string{"proj-a"}, CreatedAt: now,
	}, "tok-b-a"); err != nil {
		t.Fatalf("UpsertNode b-a: %v", err)
	}
	if err := srv.store.UpsertNode(ctx, protocol.NodeRecord{
		ID: "b-all", Name: "Recv-All", Role: protocol.RoleAgentB, Projects: []string{}, CreatedAt: now,
	}, "tok-b-all"); err != nil {
		t.Fatalf("UpsertNode b-all: %v", err)
	}
	if err := srv.store.InsertRelease(ctx, protocol.ReleaseRecord{
		ID: "rel-a", Role: protocol.RoleAgentA, Version: "v1.9.2", OS: "linux", Arch: "amd64",
		SHA256: strings.Repeat("a", 64), Size: 100, Filename: "a.bin", CreatedAt: now,
	}); err != nil {
		t.Fatalf("InsertRelease a: %v", err)
	}
	if err := srv.store.InsertRelease(ctx, protocol.ReleaseRecord{
		ID: "rel-b", Role: protocol.RoleAgentB, Version: "v1.9.2", OS: "linux", Arch: "amd64",
		SHA256: strings.Repeat("b", 64), Size: 100, Filename: "b.bin", CreatedAt: now,
	}); err != nil {
		t.Fatalf("InsertRelease b: %v", err)
	}

	srv.hub.UpdateA(protocol.AgentAHeartbeatReq{
		NodeID: "a-1", Name: "Dispatch-1", PublicAddr: "https://10.0.0.1:8443",
		Availability: []protocol.ProjectAvailability{
			{ProjectID: "proj-a", ReadyCount: 10, ReadyBytes: 1000},
			{ProjectID: "proj-b", ReadyCount: 20, ReadyBytes: 2000},
		},
	})
	srv.hub.UpdateB(protocol.AgentBHeartbeatReq{NodeID: "b-a", Name: "Recv-A", Projects: []string{"proj-a"}})
	srv.hub.UpdateB(protocol.AgentBHeartbeatReq{NodeID: "b-all", Name: "Recv-All", Projects: []string{}})

	_, err = srv.store.RecordSummaryEvents(ctx, []protocol.SummaryEvent{
		{EventID: "ev-a", ProjectID: "proj-a", ANodeID: "a-1", BNodeID: "b-a", EventType: protocol.EventCompleted, Bytes: 5000, Timestamp: now},
		{EventID: "ev-b", ProjectID: "proj-b", ANodeID: "a-1", BNodeID: "b-all", EventType: protocol.EventCompleted, Bytes: 9000, Timestamp: now},
	})
	if err != nil {
		t.Fatalf("RecordSummaryEvents: %v", err)
	}

	h := srv.routes()
	doReq := func(method, path, token string, body any, remoteAddr string) *httptest.ResponseRecorder {
		var buf bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&buf).Encode(body)
		}
		req := httptest.NewRequest(method, "https://center.test:8440"+path, &buf)
		req.Host = "center.test:8440"
		req.RemoteAddr = remoteAddr
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if token != "" {
			req.Header.Set(protocol.HeaderAdminToken, token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// 1. Admin creates an unscoped customer account & a project-scoped customer account.
	rCreateAll := doReq(http.MethodPost, "/api/v1/admin/accounts", "super-admin-token-123456", map[string]any{
		"id": "cust-global", "name": "Global Customer",
	}, "198.51.100.2:1234")
	if rCreateAll.Code != http.StatusOK {
		t.Fatalf("create cust-global failed: %d %s", rCreateAll.Code, rCreateAll.Body.String())
	}
	var createAllResp struct {
		Account protocol.AccountRecord `json:"account"`
		Token   string                 `json:"token"`
	}
	_ = json.Unmarshal(rCreateAll.Body.Bytes(), &createAllResp)
	custGlobalTok := createAllResp.Token
	if !strings.HasPrefix(custGlobalTok, "rcust_") {
		t.Fatalf("expected rcust_ token prefix, got %q", custGlobalTok)
	}

	rCreateScoped := doReq(http.MethodPost, "/api/v1/admin/accounts", "super-admin-token-123456", map[string]any{
		"id": "cust-proj-a", "name": "Project A Customer", "projects": []string{"proj-a"},
	}, "198.51.100.2:1234")
	if rCreateScoped.Code != http.StatusOK {
		t.Fatalf("create cust-proj-a failed: %d %s", rCreateScoped.Code, rCreateScoped.Body.String())
	}
	var createScopedResp struct {
		Account protocol.AccountRecord `json:"account"`
		Token   string                 `json:"token"`
	}
	_ = json.Unmarshal(rCreateScoped.Body.Bytes(), &createScopedResp)
	custScopedTok := createScopedResp.Token

	// 2. Trusted-IP precedence: explicit customer token from 127.0.0.1 must authenticate as customer, NOT admin!
	rOv := doReq(http.MethodGet, "/api/v1/admin/overview", custGlobalTok, nil, "127.0.0.1:4567")
	if rOv.Code != http.StatusOK {
		t.Fatalf("cust-global overview: %d %s", rOv.Code, rOv.Body.String())
	}
	var ov protocol.OverviewResp
	_ = json.Unmarshal(rOv.Body.Bytes(), &ov)
	if ov.AuthRole != protocol.AccountRoleCustomer || ov.AuthTrustedIP {
		t.Fatalf("expected customer principal even from trusted IP, got role=%s trusted=%v", ov.AuthRole, ov.AuthTrustedIP)
	}
	if ov.TotalANodes != 0 || ov.OnlineANodes != 0 || ov.TotalBNodes != 2 || ov.OnlineBNodes != 2 {
		t.Fatalf("unexpected node counts for customer overview: A=%d/%d B=%d/%d", ov.OnlineANodes, ov.TotalANodes, ov.OnlineBNodes, ov.TotalBNodes)
	}
	for _, ps := range ov.Projects {
		if ps.OnlineANodes != 0 || len(ps.ANodeAvailability) != 0 {
			t.Fatalf("dispatch node details leaked in project %s: onlineA=%d avail=%+v", ps.Project.ID, ps.OnlineANodes, ps.ANodeAvailability)
		}
	}

	// 3. Global customer cannot see or touch dispatch nodes, projects mutations, releases mutations, deploy, or accounts.
	rNodes := doReq(http.MethodGet, "/api/v1/admin/nodes", custGlobalTok, nil, "198.51.100.9:1111")
	if rNodes.Code != http.StatusOK {
		t.Fatalf("cust-global nodes: %d", rNodes.Code)
	}
	var nodes []protocol.LiveNodeView
	_ = json.Unmarshal(rNodes.Body.Bytes(), &nodes)
	for _, n := range nodes {
		if n.Role == protocol.RoleAgentA || n.ID == "a-1" {
			t.Fatalf("dispatch node leaked to customer: %+v", n)
		}
	}
	if len(nodes) != 2 {
		t.Fatalf("expected 2 receiver nodes for global customer, got %d", len(nodes))
	}

	// Customer releases list only shows agent_b; asking for agent_a is 403.
	rRels := doReq(http.MethodGet, "/api/v1/admin/releases", custGlobalTok, nil, "198.51.100.9:1111")
	var rels []protocol.ReleaseRecord
	_ = json.Unmarshal(rRels.Body.Bytes(), &rels)
	if len(rels) != 1 || rels[0].Role != protocol.RoleAgentB {
		t.Fatalf("expected only agent_b release for customer, got %+v", rels)
	}

	forbiddenCases := []struct {
		name   string
		method string
		path   string
		body   any
	}{
		{"list agent_a releases", http.MethodGet, "/api/v1/admin/releases?role=agent_a", nil},
		{"create agent_a node", http.MethodPost, "/api/v1/admin/nodes", map[string]any{"id": "a-evil", "role": "agent_a"}},
		{"overwrite existing a-1 as agent_b", http.MethodPost, "/api/v1/admin/nodes", map[string]any{"id": "a-1", "role": "agent_b"}},
		{"update a-1", http.MethodPut, "/api/v1/admin/nodes/a-1", map[string]any{"name": "pwned"}},
		{"delete a-1", http.MethodDelete, "/api/v1/admin/nodes/a-1", nil},
		{"upgrade a-1 with rel-a", http.MethodPost, "/api/v1/admin/upgrades", map[string]any{"release_id": "rel-a", "node_ids": []string{"a-1"}}},
		{"upgrade a-1 with rel-b", http.MethodPost, "/api/v1/admin/upgrades", map[string]any{"release_id": "rel-b", "node_ids": []string{"b-a", "a-1"}}},
		{"cancel upgrade a-1", http.MethodDelete, "/api/v1/admin/upgrades/a-1", nil},
		{"agent-b script on a-1", http.MethodPost, "/api/v1/admin/deploy/agent-b-script", map[string]any{"node_id": "a-1"}},
		{"deploy precheck", http.MethodPost, "/api/v1/admin/deploy/precheck", map[string]any{"host": "1.2.3.4"}},
		{"deploy agent-a", http.MethodPost, "/api/v1/admin/deploy/agent-a", map[string]any{"host": "1.2.3.4", "node_id": "a-2"}},
		{"list deploy tasks", http.MethodGet, "/api/v1/admin/deploy/tasks", nil},
		{"upsert project", http.MethodPost, "/api/v1/admin/projects", map[string]any{"id": "proj-evil", "name": "evil"}},
		{"delete project", http.MethodDelete, "/api/v1/admin/projects/proj-a", nil},
		{"upload release", http.MethodPost, "/api/v1/admin/releases", map[string]any{}},
		{"delete release", http.MethodDelete, "/api/v1/admin/releases/rel-b", nil},
		{"list accounts", http.MethodGet, "/api/v1/admin/accounts", nil},
		{"create account", http.MethodPost, "/api/v1/admin/accounts", map[string]any{"name": "escalate"}},
		{"filter intervals by a_node", http.MethodGet, "/api/v1/admin/stats/intervals?a_node=a-1", nil},
		{"filter overview by a_node", http.MethodGet, "/api/v1/admin/overview?a_node=a-1", nil},
	}
	for _, tc := range forbiddenCases {
		res := doReq(tc.method, tc.path, custGlobalTok, tc.body, "198.51.100.9:1111")
		if res.Code != http.StatusForbidden {
			t.Fatalf("case %q: expected 403 Forbidden for customer, got %d (%s)", tc.name, res.Code, res.Body.String())
		}
	}

	// 4. Global customer CAN fully manage receiver (agent_b) nodes.
	if res := doReq(http.MethodPost, "/api/v1/admin/nodes", custGlobalTok, map[string]any{
		"id": "b-cust-1", "name": "Customer NAS", "role": "agent_b", "projects": []string{"proj-a"},
	}, "198.51.100.9:1111"); res.Code != http.StatusOK {
		t.Fatalf("customer create agent_b failed: %d %s", res.Code, res.Body.String())
	}
	if res := doReq(http.MethodPut, "/api/v1/admin/nodes/b-cust-1", custGlobalTok, map[string]any{
		"disk_policy": "most_free", "rate_limit_mbps": 50,
	}, "198.51.100.9:1111"); res.Code != http.StatusOK {
		t.Fatalf("customer update agent_b failed: %d %s", res.Code, res.Body.String())
	}
	if res := doReq(http.MethodPost, "/api/v1/admin/upgrades", custGlobalTok, map[string]any{
		"release_id": "rel-b", "node_ids": []string{"b-cust-1"},
	}, "198.51.100.9:1111"); res.Code != http.StatusOK {
		t.Fatalf("customer upgrade agent_b failed: %d %s", res.Code, res.Body.String())
	}
	if res := doReq(http.MethodDelete, "/api/v1/admin/upgrades/b-cust-1", custGlobalTok, nil, "198.51.100.9:1111"); res.Code != http.StatusNoContent {
		t.Fatalf("customer cancel upgrade failed: %d %s", res.Code, res.Body.String())
	}
	if res := doReq(http.MethodPost, "/api/v1/admin/deploy/agent-b-script", custGlobalTok, map[string]any{
		"node_id": "b-cust-1", "storage_dirs": []string{"/mnt/sda/relay"},
	}, "198.51.100.9:1111"); res.Code != http.StatusOK {
		t.Fatalf("customer agent-b-script failed: %d %s", res.Code, res.Body.String())
	}
	if res := doReq(http.MethodDelete, "/api/v1/admin/nodes/b-cust-1", custGlobalTok, nil, "198.51.100.9:1111"); res.Code != http.StatusNoContent {
		t.Fatalf("customer delete agent_b failed: %d %s", res.Code, res.Body.String())
	}

	// 5. Project-scoped customer (proj-a only) cannot view or touch proj-b or wildcard receiver b-all.
	rScopedOv := doReq(http.MethodGet, "/api/v1/admin/overview", custScopedTok, nil, "198.51.100.10:1111")
	if rScopedOv.Code != http.StatusOK {
		t.Fatalf("scoped overview: %d %s", rScopedOv.Code, rScopedOv.Body.String())
	}
	var scopedOv protocol.OverviewResp
	_ = json.Unmarshal(rScopedOv.Body.Bytes(), &scopedOv)
	if len(scopedOv.Projects) != 1 || scopedOv.Projects[0].Project.ID != "proj-a" {
		t.Fatalf("scoped customer should only see proj-a, got %+v", scopedOv.Projects)
	}
	if scopedOv.TotalBNodes != 1 || scopedOv.AllTimeBytes != 5000 {
		t.Fatalf("scoped customer stats leak: B=%d allTimeBytes=%d", scopedOv.TotalBNodes, scopedOv.AllTimeBytes)
	}
	for _, tc := range []struct {
		name, method, path string
		body               any
	}{
		{"overview proj-b", http.MethodGet, "/api/v1/admin/overview?project=proj-b", nil},
		{"intervals proj-b", http.MethodGet, "/api/v1/admin/stats/intervals?project=proj-b", nil},
		{"daily proj-b", http.MethodGet, "/api/v1/admin/stats/daily?project=proj-b", nil},
		{"create wildcard node", http.MethodPost, "/api/v1/admin/nodes", map[string]any{"id": "b-wild", "role": "agent_b", "projects": []string{}}},
		{"create proj-b node", http.MethodPost, "/api/v1/admin/nodes", map[string]any{"id": "b-other", "role": "agent_b", "projects": []string{"proj-b"}}},
		{"edit shared b-all", http.MethodPut, "/api/v1/admin/nodes/b-all", map[string]any{"name": "hijack"}},
		{"expand b-a to proj-b", http.MethodPut, "/api/v1/admin/nodes/b-a", map[string]any{"projects": []string{"proj-a", "proj-b"}}},
		{"delete shared b-all", http.MethodDelete, "/api/v1/admin/nodes/b-all", nil},
		{"script with unauthorized project", http.MethodPost, "/api/v1/admin/deploy/agent-b-script", map[string]any{"node_id": "b-a", "only_project": "proj-b"}},
	} {
		res := doReq(tc.method, tc.path, custScopedTok, tc.body, "198.51.100.10:1111")
		if res.Code != http.StatusForbidden {
			t.Fatalf("scoped case %q: expected 403 Forbidden, got %d (%s)", tc.name, res.Code, res.Body.String())
		}
	}

	// 6. Token rotation & disablement revoke old credentials immediately.
	rRot := doReq(http.MethodPost, "/api/v1/admin/accounts/cust-global/rotate", "super-admin-token-123456", nil, "198.51.100.2:1234")
	if rRot.Code != http.StatusOK {
		t.Fatalf("rotate failed: %d %s", rRot.Code, rRot.Body.String())
	}
	var rotResp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(rRot.Body.Bytes(), &rotResp)
	if res := doReq(http.MethodGet, "/api/v1/admin/overview", custGlobalTok, nil, "127.0.0.1:4567"); res.Code != http.StatusUnauthorized {
		t.Fatalf("old token must return 401 even from trusted IP, got %d", res.Code)
	}
	if res := doReq(http.MethodGet, "/api/v1/admin/overview", rotResp.Token, nil, "198.51.100.9:1111"); res.Code != http.StatusOK {
		t.Fatalf("rotated token should work, got %d", res.Code)
	}
	disabled := false
	if res := doReq(http.MethodPut, "/api/v1/admin/accounts/cust-global", "super-admin-token-123456", map[string]any{
		"enabled": disabled,
	}, "198.51.100.2:1234"); res.Code != http.StatusOK {
		t.Fatalf("disable account failed: %d", res.Code)
	}
	if res := doReq(http.MethodGet, "/api/v1/admin/overview", rotResp.Token, nil, "198.51.100.9:1111"); res.Code != http.StatusUnauthorized {
		t.Fatalf("disabled account must return 401, got %d", res.Code)
	}
	if res := doReq(http.MethodDelete, "/api/v1/admin/accounts/cust-global", "super-admin-token-123456", nil, "198.51.100.2:1234"); res.Code != http.StatusNoContent {
		t.Fatalf("delete account failed: %d", res.Code)
	}
}

func TestNodePauseResumeAndAgentAScript(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	caKeyPath := filepath.Join(dir, "ca.key")
	if err := pki.InitCA(caPath, caKeyPath, "relay-pause-test-ca", 365); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	srvCert := filepath.Join(dir, "center.crt")
	srvKey := filepath.Join(dir, "center.key")
	if err := pki.IssueCert(caPath, caKeyPath, srvCert, srvKey, "center", []string{"127.0.0.1"}, nil, 365); err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	srv, err := New(&Config{
		Listen:       "127.0.0.1:0",
		TLSCert:      srvCert,
		TLSKey:       srvKey,
		CACert:       caPath,
		CAKey:        caKeyPath,
		PublicURL:    "https://center.test:8440",
		ReleasesDir:  filepath.Join(dir, "releases"),
		DBPath:       filepath.Join(dir, "center.db"),
		JWTSecret:    "jwt-secret-pause-test",
		CenterSecret: "center-secret-pause-test",
		AdminToken:   "admin-tok-pause-test",
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.Shutdown(context.Background())

	ctx := context.Background()
	now := time.Now().UTC()
	_ = srv.store.UpsertProject(ctx, protocol.Project{ID: "proj-1", Name: "P1", ConflictPolicy: protocol.ConflictOverwrite, LeaseTTLSec: 300, CreatedAt: now})
	_ = srv.store.UpsertNode(ctx, protocol.NodeRecord{ID: "a-1", Name: "A1", Role: protocol.RoleAgentA, PublicAddr: "https://203.0.113.10:8443", CreatedAt: now}, "tok-a1")
	_ = srv.store.UpsertNode(ctx, protocol.NodeRecord{ID: "b-1", Name: "B1", Role: protocol.RoleAgentB, Projects: []string{"proj-1"}, CreatedAt: now}, "tok-b1")
	_ = srv.store.InsertRelease(ctx, protocol.ReleaseRecord{
		ID: "rel-a", Role: protocol.RoleAgentA, Version: "v1.11.0", OS: "linux", Arch: "amd64",
		SHA256: strings.Repeat("a", 64), Size: 123, Filename: "a.bin", CreatedAt: now,
	})
	_ = srv.store.CreateAccount(ctx, protocol.AccountRecord{ID: "c1", Name: "Cust1", Role: protocol.AccountRoleCustomer, Enabled: true, CreatedAt: now}, "rcust_test_pause_token_123456")

	srv.hub.UpdateA(protocol.AgentAHeartbeatReq{
		NodeID: "a-1", Name: "A1", PublicAddr: "https://203.0.113.10:8443",
		Availability: []protocol.ProjectAvailability{{ProjectID: "proj-1", ReadyCount: 5, ReadyBytes: 500}},
	})
	srv.hub.UpdateB(protocol.AgentBHeartbeatReq{NodeID: "b-1", Name: "B1", Projects: []string{"proj-1"}})

	h := srv.routes()
	reqJSON := func(method, path string, headers map[string]string, body any) *httptest.ResponseRecorder {
		var buf bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&buf).Encode(body)
		}
		r := httptest.NewRequest(method, "https://center.test:8440"+path, &buf)
		r.Host = "center.test:8440"
		r.RemoteAddr = "198.51.100.5:9999"
		if body != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}

	adminHdr := map[string]string{protocol.HeaderAdminToken: "admin-tok-pause-test"}
	custHdr := map[string]string{protocol.HeaderAdminToken: "rcust_test_pause_token_123456"}
	bNodeHdr := map[string]string{protocol.HeaderNodeID: "b-1", protocol.HeaderNodeToken: "tok-b1"}
	aNodeHdr := map[string]string{protocol.HeaderNodeID: "a-1", protocol.HeaderNodeToken: "tok-a1"}

	// 1. Pause receiver b-1 via customer account -> discover returns 0 candidates, heartbeat echoes paused=true, excluded from ActiveReceivers.
	if res := reqJSON(http.MethodPut, "/api/v1/admin/nodes/b-1", custHdr, map[string]any{"paused": true}); res.Code != http.StatusOK {
		t.Fatalf("customer pause b-1 failed: %d %s", res.Code, res.Body.String())
	}
	if res := reqJSON(http.MethodPut, "/api/v1/admin/nodes/a-1", custHdr, map[string]any{"paused": true}); res.Code != http.StatusForbidden {
		t.Fatalf("customer must not pause a-1, got %d", res.Code)
	}
	rDisc := reqJSON(http.MethodGet, "/api/v1/b/discover?project=proj-1", bNodeHdr, nil)
	var disc protocol.DiscoverResp
	_ = json.Unmarshal(rDisc.Body.Bytes(), &disc)
	if len(disc.Candidates) != 0 {
		t.Fatalf("paused receiver should get 0 candidates, got %d", len(disc.Candidates))
	}
	rHB := reqJSON(http.MethodPost, "/api/v1/b/heartbeat", bNodeHdr, protocol.AgentBHeartbeatReq{NodeID: "b-1", Projects: []string{"proj-1"}})
	var hb protocol.HeartbeatResp
	_ = json.Unmarshal(rHB.Body.Bytes(), &hb)
	if !hb.Paused || hb.Directive == nil || !hb.Directive.Paused {
		t.Fatalf("expected paused=true in b heartbeat directive, got %+v", hb)
	}
	dbNodes, _ := srv.store.ListNodes(ctx)
	if active := srv.hub.ActiveReceiversByProject([]string{"proj-1"}, dbNodes); len(active["proj-1"]) != 0 {
		t.Fatalf("paused receiver b-1 must be excluded from ActiveReceiversByProject, got %+v", active)
	}

	// Resume b-1 -> discover returns a-1 again!
	if res := reqJSON(http.MethodPut, "/api/v1/admin/nodes/b-1", custHdr, map[string]any{"paused": false}); res.Code != http.StatusOK {
		t.Fatalf("customer resume b-1 failed: %d %s", res.Code, res.Body.String())
	}
	rDisc2 := reqJSON(http.MethodGet, "/api/v1/b/discover?project=proj-1", bNodeHdr, nil)
	disc = protocol.DiscoverResp{}
	_ = json.Unmarshal(rDisc2.Body.Bytes(), &disc)
	if len(disc.Candidates) != 1 || disc.Candidates[0].ANodeID != "a-1" {
		t.Fatalf("resumed receiver should discover a-1, got %+v", disc.Candidates)
	}

	// 2. Pause dispatch node a-1 via admin -> excluded from DiscoverCandidates and heartbeat reports paused=true.
	if res := reqJSON(http.MethodPut, "/api/v1/admin/nodes/a-1", adminHdr, map[string]any{"paused": true}); res.Code != http.StatusOK {
		t.Fatalf("admin pause a-1 failed: %d %s", res.Code, res.Body.String())
	}
	rDisc3 := reqJSON(http.MethodGet, "/api/v1/b/discover?project=proj-1", bNodeHdr, nil)
	disc = protocol.DiscoverResp{}
	_ = json.Unmarshal(rDisc3.Body.Bytes(), &disc)
	if len(disc.Candidates) != 0 {
		t.Fatalf("paused dispatch node a-1 must not be returned in discover, got %+v", disc.Candidates)
	}
	rAHB := reqJSON(http.MethodPost, "/api/v1/a/heartbeat", aNodeHdr, protocol.AgentAHeartbeatReq{
		NodeID: "a-1", PublicAddr: "https://203.0.113.10:8443",
		Availability: []protocol.ProjectAvailability{{ProjectID: "proj-1", ReadyCount: 5, ReadyBytes: 500}},
	})
	var aHB protocol.HeartbeatResp
	_ = json.Unmarshal(rAHB.Body.Bytes(), &aHB)
	if !aHB.Paused {
		t.Fatalf("expected paused=true in a-1 heartbeat resp")
	}

	// 3. Dispatch node automated install script API: forbidden for customer, valid script for admin.
	if res := reqJSON(http.MethodPost, "/api/v1/admin/deploy/agent-a-script", custHdr, map[string]any{"node_id": "a-1"}); res.Code != http.StatusForbidden {
		t.Fatalf("customer must not generate agent-a script, got %d", res.Code)
	}
	rAS := reqJSON(http.MethodPost, "/api/v1/admin/deploy/agent-a-script", adminHdr, map[string]any{
		"node_id": "a-1", "public_addr": "https://frp.example.com:9443", "rotate_token": true,
	})
	if rAS.Code != http.StatusOK {
		t.Fatalf("admin agent-a-script failed: %d %s", rAS.Code, rAS.Body.String())
	}
	var asResp protocol.AgentAScriptResp
	_ = json.Unmarshal(rAS.Body.Bytes(), &asResp)
	for _, must := range []string{"--tlsv1.3", "sha256sum", "relay-agent-a.service", "frp.example.com:9443", "BEGIN CERTIFICATE", "BEGIN EC PRIVATE KEY"} {
		if !strings.Contains(asResp.Script, must) {
			t.Fatalf("agent-a script missing %q", must)
		}
	}
	if asResp.LocalToken == "" || asResp.RotatedToken == "" {
		t.Fatalf("expected non-empty local_token and rotated_token")
	}
}
