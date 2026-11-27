package center

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
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
		ID: "b-a", Name: "Recv-A", Role: protocol.RoleAgentB, OwnerAccountID: "cust-proj-a", Projects: []string{"proj-a"}, CreatedAt: now,
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

	// 1. Default-deny check: newly created customer account with empty projects sees ZERO projects, ZERO stats, ZERO nodes!
	rCreateEmpty := doReq(http.MethodPost, "/api/v1/admin/accounts", "super-admin-token-123456", map[string]any{
		"id": "cust-empty", "name": "Unassigned Customer",
	}, "198.51.100.2:1234")
	if rCreateEmpty.Code != http.StatusOK {
		t.Fatalf("create cust-empty failed: %d %s", rCreateEmpty.Code, rCreateEmpty.Body.String())
	}
	var createEmptyResp struct {
		Account protocol.AccountRecord `json:"account"`
		Token   string                 `json:"token"`
	}
	_ = json.Unmarshal(rCreateEmpty.Body.Bytes(), &createEmptyResp)
	custEmptyTok := createEmptyResp.Token
	if !strings.HasPrefix(custEmptyTok, "rcust_") {
		t.Fatalf("expected rcust_ token prefix, got %q", custEmptyTok)
	}

	// Trusted-IP precedence: explicit customer token from 127.0.0.1 must authenticate as customer, NOT admin!
	rEmptyOv := doReq(http.MethodGet, "/api/v1/admin/overview", custEmptyTok, nil, "127.0.0.1:4567")
	if rEmptyOv.Code != http.StatusOK {
		t.Fatalf("cust-empty overview: %d %s", rEmptyOv.Code, rEmptyOv.Body.String())
	}
	var emptyOv protocol.OverviewResp
	_ = json.Unmarshal(rEmptyOv.Body.Bytes(), &emptyOv)
	if emptyOv.AuthRole != protocol.AccountRoleCustomer || emptyOv.AuthTrustedIP {
		t.Fatalf("expected customer principal even from trusted IP, got role=%s trusted=%v", emptyOv.AuthRole, emptyOv.AuthTrustedIP)
	}
	if len(emptyOv.Projects) != 0 || emptyOv.TotalBNodes != 0 || emptyOv.AllTimeBytes != 0 || emptyOv.WindowBytes != 0 || len(emptyOv.DailyTrend) != 0 {
		t.Fatalf("default-deny failed for unassigned customer: projs=%d B=%d allBytes=%d winBytes=%d daily=%d",
			len(emptyOv.Projects), emptyOv.TotalBNodes, emptyOv.AllTimeBytes, emptyOv.WindowBytes, len(emptyOv.DailyTrend))
	}
	// Daily & interval endpoints must also return zero/empty for unassigned customer.
	if res := doReq(http.MethodGet, "/api/v1/admin/stats/daily", custEmptyTok, nil, "198.51.100.9:1111"); res.Code != http.StatusOK || strings.TrimSpace(res.Body.String()) != "[]" {
		t.Fatalf("expected empty daily stats for unassigned customer, got %d %s", res.Code, res.Body.String())
	}
	rEmptyInt := doReq(http.MethodGet, "/api/v1/admin/stats/intervals", custEmptyTok, nil, "198.51.100.9:1111")
	var emptyInt protocol.IntervalStatsResp
	_ = json.Unmarshal(rEmptyInt.Body.Bytes(), &emptyInt)
	if emptyInt.TotalBytes != 0 || emptyInt.TotalCompleted != 0 {
		t.Fatalf("expected zero interval stats for unassigned customer, got bytes=%d cmp=%d", emptyInt.TotalBytes, emptyInt.TotalCompleted)
	}

	// Create two tenant customer accounts: cust-proj-a (proj-a) and cust-peer-a (also assigned proj-a, to verify strict node ownership isolation!).
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

	rCreatePeer := doReq(http.MethodPost, "/api/v1/admin/accounts", "super-admin-token-123456", map[string]any{
		"id": "cust-peer-a", "name": "Peer Tenant", "projects": []string{"proj-a"},
	}, "198.51.100.2:1234")
	var createPeerResp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(rCreatePeer.Body.Bytes(), &createPeerResp)
	custPeerTok := createPeerResp.Token

	// 2. Customer cust-proj-a sees ONLY proj-a, ONLY its own receiver b-a, and ZERO dispatch node details.
	rScopedOv := doReq(http.MethodGet, "/api/v1/admin/overview", custScopedTok, nil, "198.51.100.10:1111")
	if rScopedOv.Code != http.StatusOK {
		t.Fatalf("scoped overview: %d %s", rScopedOv.Code, rScopedOv.Body.String())
	}
	var scopedOv protocol.OverviewResp
	_ = json.Unmarshal(rScopedOv.Body.Bytes(), &scopedOv)
	if len(scopedOv.Projects) != 1 || scopedOv.Projects[0].Project.ID != "proj-a" {
		t.Fatalf("scoped customer should only see proj-a, got %+v", scopedOv.Projects)
	}
	if scopedOv.TotalANodes != 0 || scopedOv.OnlineANodes != 0 || scopedOv.TotalBNodes != 1 || scopedOv.AllTimeBytes != 5000 {
		t.Fatalf("scoped customer stats mismatch/leak: A=%d B=%d allTimeBytes=%d", scopedOv.TotalANodes, scopedOv.TotalBNodes, scopedOv.AllTimeBytes)
	}
	if scopedOv.Projects[0].OnlineANodes != 0 || len(scopedOv.Projects[0].ANodeAvailability) != 0 {
		t.Fatalf("dispatch node details leaked in proj-a")
	}

	// Peer tenant (also allowed proj-a) MUST NOT see or touch cust-proj-a's receiver b-a!
	rPeerNodes := doReq(http.MethodGet, "/api/v1/admin/nodes", custPeerTok, nil, "198.51.100.11:1111")
	var peerNodes []protocol.LiveNodeView
	_ = json.Unmarshal(rPeerNodes.Body.Bytes(), &peerNodes)
	if len(peerNodes) != 0 {
		t.Fatalf("peer tenant must NOT see another customer's receiver b-a, got %+v", peerNodes)
	}
	if res := doReq(http.MethodPut, "/api/v1/admin/nodes/b-a", custPeerTok, map[string]any{"paused": true}, "198.51.100.11:1111"); res.Code != http.StatusForbidden {
		t.Fatalf("peer tenant must get 403 editing cust-proj-a's node b-a, got %d", res.Code)
	}
	if res := doReq(http.MethodDelete, "/api/v1/admin/nodes/b-a", custPeerTok, nil, "198.51.100.11:1111"); res.Code != http.StatusForbidden {
		t.Fatalf("peer tenant must get 403 deleting cust-proj-a's node b-a, got %d", res.Code)
	}

	// Customer releases list only shows agent_b; asking for agent_a is 403.
	rRels := doReq(http.MethodGet, "/api/v1/admin/releases", custScopedTok, nil, "198.51.100.9:1111")
	var rels []protocol.ReleaseRecord
	_ = json.Unmarshal(rRels.Body.Bytes(), &rels)
	if len(rels) != 1 || rels[0].Role != protocol.RoleAgentB {
		t.Fatalf("expected only agent_b release for customer, got %+v", rels)
	}

	// 3. Forbidden actions for customer (dispatch nodes, admin endpoints, unauthorized projects, admin-owned b-all).
	forbiddenCases := []struct {
		name   string
		method string
		path   string
		body   any
	}{
		{"list agent_a releases", http.MethodGet, "/api/v1/admin/releases?role=agent_a", nil},
		{"create agent_a node", http.MethodPost, "/api/v1/admin/nodes", map[string]any{"id": "a-evil", "role": "agent_a"}},
		{"overwrite existing a-1 as agent_b", http.MethodPost, "/api/v1/admin/nodes", map[string]any{"id": "a-1", "role": "agent_b", "projects": []string{"proj-a"}}},
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
		{"assign project accounts", http.MethodPut, "/api/v1/admin/projects/proj-a/accounts", map[string]any{"account_ids": []string{"cust-proj-a"}}},
		{"delete project", http.MethodDelete, "/api/v1/admin/projects/proj-a", nil},
		{"upload release", http.MethodPost, "/api/v1/admin/releases", map[string]any{}},
		{"delete release", http.MethodDelete, "/api/v1/admin/releases/rel-b", nil},
		{"list accounts", http.MethodGet, "/api/v1/admin/accounts", nil},
		{"create account", http.MethodPost, "/api/v1/admin/accounts", map[string]any{"name": "escalate"}},
		{"filter intervals by a_node", http.MethodGet, "/api/v1/admin/stats/intervals?a_node=a-1", nil},
		{"filter overview by a_node", http.MethodGet, "/api/v1/admin/overview?a_node=a-1", nil},
		{"overview proj-b", http.MethodGet, "/api/v1/admin/overview?project=proj-b", nil},
		{"intervals proj-b", http.MethodGet, "/api/v1/admin/stats/intervals?project=proj-b", nil},
		{"daily proj-b", http.MethodGet, "/api/v1/admin/stats/daily?project=proj-b", nil},
		{"create wildcard node", http.MethodPost, "/api/v1/admin/nodes", map[string]any{"id": "b-wild", "role": "agent_b", "projects": []string{}}},
		{"create proj-b node", http.MethodPost, "/api/v1/admin/nodes", map[string]any{"id": "b-other", "role": "agent_b", "projects": []string{"proj-b"}}},
		{"edit admin-owned b-all", http.MethodPut, "/api/v1/admin/nodes/b-all", map[string]any{"name": "hijack"}},
		{"expand b-a to proj-b", http.MethodPut, "/api/v1/admin/nodes/b-a", map[string]any{"projects": []string{"proj-a", "proj-b"}}},
		{"delete admin-owned b-all", http.MethodDelete, "/api/v1/admin/nodes/b-all", nil},
		{"script with unauthorized project", http.MethodPost, "/api/v1/admin/deploy/agent-b-script", map[string]any{"node_id": "b-a", "only_project": "proj-b"}},
	}
	for _, tc := range forbiddenCases {
		res := doReq(tc.method, tc.path, custScopedTok, tc.body, "198.51.100.9:1111")
		if res.Code != http.StatusForbidden {
			t.Fatalf("case %q: expected 403 Forbidden for customer, got %d (%s)", tc.name, res.Code, res.Body.String())
		}
	}

	// 4. Customer creates a new receiver node -> auto-stamped with owner_account_id="cust-proj-a" and fully manageable!
	if res := doReq(http.MethodPost, "/api/v1/admin/nodes", custScopedTok, map[string]any{
		"id": "b-cust-1", "name": "Customer NAS", "role": "agent_b", "projects": []string{"proj-a"}, "disk_policy": "rolling_window", "active_disk_window": 10,
	}, "198.51.100.9:1111"); res.Code != http.StatusOK {
		t.Fatalf("customer create agent_b failed: %d %s", res.Code, res.Body.String())
	}
	createdNode, _ := srv.store.GetNode(ctx, "b-cust-1")
	if createdNode == nil || createdNode.OwnerAccountID != "cust-proj-a" || createdNode.DiskPolicy != protocol.DiskPolicyRollingWindow || createdNode.ActiveDiskWindow != 10 {
		t.Fatalf("expected auto-stamped owner_account_id and rolling_window, got %+v", createdNode)
	}
	if res := doReq(http.MethodPut, "/api/v1/admin/nodes/b-cust-1", custScopedTok, map[string]any{
		"disk_policy": "most_free", "rate_limit_mbps": 50,
	}, "198.51.100.9:1111"); res.Code != http.StatusOK {
		t.Fatalf("customer update agent_b failed: %d %s", res.Code, res.Body.String())
	}
	if res := doReq(http.MethodPost, "/api/v1/admin/upgrades", custScopedTok, map[string]any{
		"release_id": "rel-b", "node_ids": []string{"b-cust-1"},
	}, "198.51.100.9:1111"); res.Code != http.StatusOK {
		t.Fatalf("customer upgrade agent_b failed: %d %s", res.Code, res.Body.String())
	}
	if res := doReq(http.MethodDelete, "/api/v1/admin/upgrades/b-cust-1", custScopedTok, nil, "198.51.100.9:1111"); res.Code != http.StatusNoContent {
		t.Fatalf("customer cancel upgrade failed: %d %s", res.Code, res.Body.String())
	}
	if res := doReq(http.MethodPost, "/api/v1/admin/deploy/agent-b-script", custScopedTok, map[string]any{
		"node_id": "b-cust-1", "storage_dirs": []string{"/mnt/sda/relay"},
	}, "198.51.100.9:1111"); res.Code != http.StatusOK {
		t.Fatalf("customer agent-b-script failed: %d %s", res.Code, res.Body.String())
	}
	if res := doReq(http.MethodDelete, "/api/v1/admin/nodes/b-cust-1", custScopedTok, nil, "198.51.100.9:1111"); res.Code != http.StatusNoContent {
		t.Fatalf("customer delete agent_b failed: %d %s", res.Code, res.Body.String())
	}

	// 5. Admin reassigns proj-a away from cust-proj-a via PUT /api/v1/admin/projects/proj-a/accounts
	//    -> b-a immediately loses discover access (403) and heartbeat enforces paused=true!
	if res := doReq(http.MethodPut, "/api/v1/admin/projects/proj-a/accounts", "super-admin-token-123456", map[string]any{
		"account_ids": []string{"cust-empty"},
	}, "198.51.100.2:1234"); res.Code != http.StatusOK {
		t.Fatalf("assign proj-a accounts failed: %d %s", res.Code, res.Body.String())
	}
	reqDiscRevoked := httptest.NewRequest(http.MethodGet, "https://center.test:8440/api/v1/b/discover?project=proj-a", nil)
	reqDiscRevoked.Header.Set(protocol.HeaderNodeID, "b-a")
	reqDiscRevoked.Header.Set(protocol.HeaderNodeToken, "tok-b-a")
	recDiscRevoked := httptest.NewRecorder()
	h.ServeHTTP(recDiscRevoked, reqDiscRevoked)
	if recDiscRevoked.Code != http.StatusForbidden {
		t.Fatalf("expected revoked customer node b-a to receive 403 on discover, got %d %s", recDiscRevoked.Code, recDiscRevoked.Body.String())
	}
	// Meanwhile cust-empty now sees proj-a!
	rNowAssigned := doReq(http.MethodGet, "/api/v1/admin/projects", custEmptyTok, nil, "198.51.100.9:1111")
	var nowProjs []protocol.Project
	_ = json.Unmarshal(rNowAssigned.Body.Bytes(), &nowProjs)
	if len(nowProjs) != 1 || nowProjs[0].ID != "proj-a" {
		t.Fatalf("expected cust-empty to see proj-a after assignment, got %+v", nowProjs)
	}

	// 6. Token rotation & disablement revoke old credentials immediately.
	rRot := doReq(http.MethodPost, "/api/v1/admin/accounts/cust-empty/rotate", "super-admin-token-123456", nil, "198.51.100.2:1234")
	if rRot.Code != http.StatusOK {
		t.Fatalf("rotate failed: %d %s", rRot.Code, rRot.Body.String())
	}
	var rotResp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(rRot.Body.Bytes(), &rotResp)
	if res := doReq(http.MethodGet, "/api/v1/admin/overview", custEmptyTok, nil, "127.0.0.1:4567"); res.Code != http.StatusUnauthorized {
		t.Fatalf("old token must return 401 even from trusted IP, got %d", res.Code)
	}
	if res := doReq(http.MethodGet, "/api/v1/admin/overview", rotResp.Token, nil, "198.51.100.9:1111"); res.Code != http.StatusOK {
		t.Fatalf("rotated token should work, got %d", res.Code)
	}
	disabled := false
	if res := doReq(http.MethodPut, "/api/v1/admin/accounts/cust-empty", "super-admin-token-123456", map[string]any{
		"enabled": disabled,
	}, "198.51.100.2:1234"); res.Code != http.StatusOK {
		t.Fatalf("disable account failed: %d", res.Code)
	}
	if res := doReq(http.MethodGet, "/api/v1/admin/overview", rotResp.Token, nil, "198.51.100.9:1111"); res.Code != http.StatusUnauthorized {
		t.Fatalf("disabled account must return 401, got %d", res.Code)
	}
	if res := doReq(http.MethodDelete, "/api/v1/admin/accounts/cust-empty", "super-admin-token-123456", nil, "198.51.100.2:1234"); res.Code != http.StatusNoContent {
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
	_ = srv.store.UpsertNode(ctx, protocol.NodeRecord{ID: "b-1", Name: "B1", Role: protocol.RoleAgentB, OwnerAccountID: "c1", Projects: []string{"proj-1"}, CreatedAt: now}, "tok-b1")
	_ = srv.store.InsertRelease(ctx, protocol.ReleaseRecord{
		ID: "rel-a", Role: protocol.RoleAgentA, Version: "v1.11.0", OS: "linux", Arch: "amd64",
		SHA256: strings.Repeat("a", 64), Size: 123, Filename: "a.bin", CreatedAt: now,
	})
	_ = srv.store.CreateAccount(ctx, protocol.AccountRecord{ID: "c1", Name: "Cust1", Role: protocol.AccountRoleCustomer, Projects: []string{"proj-1"}, Enabled: true, CreatedAt: now}, "rcust_test_pause_token_123456")

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

	// 4. Auto-creating a new project via dispatch activity WITH X-Customer / ProjectHints:
	//    - New project "auto-cust-proj" with customer hint [cust-auto-1] & name "自动分配测试" is immediately visible to cust-auto-1!
	//    - Pre-existing project "proj-1" with customer hint [cust-auto-2] does NOT overwrite admin's existing permissions!
	//    - Invalid customer ID is ignored safely without failing project creation.
	for _, cid := range []string{"cust-auto-1", "cust-auto-2"} {
		if res := reqJSON(http.MethodPost, "/api/v1/admin/accounts", adminHdr, map[string]any{"id": cid, "name": cid}); res.Code != http.StatusOK {
			t.Fatalf("create %s failed: %d %s", cid, res.Code, res.Body.String())
		}
	}
	rotANodeHdr := map[string]string{protocol.HeaderNodeID: "a-1", protocol.HeaderNodeToken: asResp.RotatedToken}
	recAutoHB := reqJSON(http.MethodPost, "/api/v1/a/heartbeat", rotANodeHdr, protocol.AgentAHeartbeatReq{
		NodeID:     "a-1",
		PublicAddr: "https://frp.example.com:9443",
		Availability: []protocol.ProjectAvailability{
			{ProjectID: "auto-cust-proj", ReadyCount: 1, ReadyBytes: 123},
			{ProjectID: "proj-1", ReadyCount: 1, ReadyBytes: 123},
		},
		ProjectHints: map[string]protocol.ProjectAutoHint{
			"auto-cust-proj": {Name: "自动分配测试", CustomerIDs: []string{"cust-auto-1", "nonexistent-cust"}},
			"proj-1":         {Name: "不应覆盖", CustomerIDs: []string{"cust-auto-2"}},
		},
	})
	if recAutoHB.Code != http.StatusOK {
		t.Fatalf("auto-create heartbeat failed: %d %s", recAutoHB.Code, recAutoHB.Body.String())
	}

	autoProj, err := srv.Store().GetProject(ctx, "auto-cust-proj")
	if err != nil || autoProj.Name != "自动分配测试" {
		t.Fatalf("expected auto-created project with display name '自动分配测试', got %+v err=%v", autoProj, err)
	}
	c1After, err := srv.Store().GetAccount(ctx, "cust-auto-1")
	if err != nil || !slices.Contains(c1After.Projects, "auto-cust-proj") {
		t.Fatalf("expected cust-auto-1 to automatically receive 'auto-cust-proj', got %+v err=%v", c1After, err)
	}
	c2After, err := srv.Store().GetAccount(ctx, "cust-auto-2")
	if err != nil || slices.Contains(c2After.Projects, "proj-1") {
		t.Fatalf("existing project proj-1 must NOT be auto-reassigned to cust-auto-2, got %+v err=%v", c2After, err)
	}

	// Also verify SummaryEvent auto-create path (if events arrive before heartbeat!).
	recAutoEv := reqJSON(http.MethodPost, "/api/v1/a/events", rotANodeHdr, protocol.SummaryEventsReq{
		Events: []protocol.SummaryEvent{
			{
				EventID:     "ev-auto-cust-2",
				ProjectID:   "auto-ev-proj",
				ProjectName: "事件优先创建",
				CustomerIDs: []string{"cust-auto-2"},
				EventType:   protocol.EventUploaded,
				Bytes:       456,
			},
		},
	})
	if recAutoEv.Code != http.StatusOK {
		t.Fatalf("auto-create events failed: %d %s", recAutoEv.Code, recAutoEv.Body.String())
	}
	evProj, err := srv.Store().GetProject(ctx, "auto-ev-proj")
	if err != nil || evProj.Name != "事件优先创建" {
		t.Fatalf("expected event-created project '事件优先创建', got %+v err=%v", evProj, err)
	}
	c2AfterEv, _ := srv.Store().GetAccount(ctx, "cust-auto-2")
	if !slices.Contains(c2AfterEv.Projects, "auto-ev-proj") {
		t.Fatalf("expected cust-auto-2 to automatically receive 'auto-ev-proj' via events, got %+v", c2AfterEv.Projects)
	}
}

func TestOverviewProjectsSortedByActivity(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	caKeyPath := filepath.Join(dir, "ca.key")
	if err := pki.InitCA(caPath, caKeyPath, "relay-sort-test-ca", 365); err != nil {
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
		PublicURL:    "https://center.test:8440",
		ReleasesDir:  filepath.Join(dir, "releases"),
		DBPath:       filepath.Join(dir, "center.db"),
		JWTSecret:    "jwt-secret-sort-test",
		CenterSecret: "center-secret-sort-test",
		AdminToken:   "super-admin-tok",
	}, nil)
	if err != nil {
		t.Fatalf("New center: %v", err)
	}
	defer srv.Shutdown(context.Background())

	ctx := context.Background()
	handler := srv.routes()

	now := time.Now().UTC()
	// Create 3 projects in chronological order: oldest idle, middle recent, newest live-queued.
	for _, p := range []protocol.Project{
		{ID: "proj-old-idle", Name: "Old Idle", CreatedAt: now.Add(-72 * time.Hour)},
		{ID: "proj-mid-window", Name: "Mid Window", CreatedAt: now.Add(-12 * time.Hour)},
		{ID: "proj-live-now", Name: "Live Now", CreatedAt: now.Add(-1 * time.Hour)},
	} {
		if err := srv.Store().UpsertProject(ctx, p); err != nil {
			t.Fatalf("upsert project %s: %v", p.ID, err)
		}
	}
	if err := srv.Store().UpsertNode(ctx, protocol.NodeRecord{
		ID:         "a-sort-1",
		Name:       "a-sort-1",
		Role:       protocol.RoleAgentA,
		PublicAddr: "https://127.0.0.1:8443",
	}, "tok-sort-a"); err != nil {
		t.Fatalf("upsert node: %v", err)
	}
	// Record historical completed event for proj-mid-window (3 hours ago) and live event for proj-live-now (now).
	if _, err := srv.Store().RecordSummaryEvents(ctx, []protocol.SummaryEvent{
		{
			EventID:   "ev-mid-1",
			ProjectID: "proj-mid-window",
			ANodeID:   "a-sort-1",
			BNodeID:   "b-1",
			EventType: protocol.EventCompleted,
			Bytes:     500 << 20,
			Timestamp: now.Add(-3 * time.Hour),
		},
		{
			EventID:   "ev-live-1",
			ProjectID: "proj-live-now",
			ANodeID:   "a-sort-1",
			BNodeID:   "b-1",
			EventType: protocol.EventCompleted,
			Bytes:     100 << 20,
			Timestamp: now,
		},
	}); err != nil {
		t.Fatalf("record summary events: %v", err)
	}
	// Heartbeat with queued files on proj-live-now.
	hbBody, _ := json.Marshal(protocol.AgentAHeartbeatReq{
		NodeID:     "a-sort-1",
		PublicAddr: "https://127.0.0.1:8443",
		Availability: []protocol.ProjectAvailability{
			{ProjectID: "proj-live-now", ReadyCount: 5, ReadyBytes: 20 << 20},
		},
	})
	hbReq := httptest.NewRequest(http.MethodPost, "/api/v1/a/heartbeat", bytes.NewReader(hbBody))
	hbReq.Header.Set(protocol.HeaderNodeID, "a-sort-1")
	hbReq.Header.Set(protocol.HeaderNodeToken, "tok-sort-a")
	hbRec := httptest.NewRecorder()
	handler.ServeHTTP(hbRec, hbReq)
	if hbRec.Code != http.StatusOK {
		t.Fatalf("heartbeat failed: %d %s", hbRec.Code, hbRec.Body.String())
	}

	ovReq := httptest.NewRequest(http.MethodGet, "/api/v1/admin/overview?hours=24", nil)
	ovReq.Header.Set(protocol.HeaderAdminToken, "super-admin-tok")
	ovRec := httptest.NewRecorder()
	handler.ServeHTTP(ovRec, ovReq)
	if ovRec.Code != http.StatusOK {
		t.Fatalf("overview failed: %d %s", ovRec.Code, ovRec.Body.String())
	}
	var ov protocol.OverviewResp
	if err := json.Unmarshal(ovRec.Body.Bytes(), &ov); err != nil {
		t.Fatalf("decode overview: %v", err)
	}
	if len(ov.Projects) != 3 {
		t.Fatalf("expected 3 projects, got %d", len(ov.Projects))
	}
	gotOrder := []string{ov.Projects[0].Project.ID, ov.Projects[1].Project.ID, ov.Projects[2].Project.ID}
	wantOrder := []string{"proj-live-now", "proj-mid-window", "proj-old-idle"}
	if !slices.Equal(gotOrder, wantOrder) {
		t.Fatalf("unexpected project activity order: got %v want %v", gotOrder, wantOrder)
	}
	if ov.Projects[0].RecentBytes <= 0 || ov.Projects[0].RecentSpeedBps <= 0 || ov.Projects[0].LastActivityAt == nil {
		t.Fatalf("expected live recent metrics on proj-live-now, got %+v", ov.Projects[0])
	}
	if ov.Projects[1].LastActivityAt == nil || ov.Projects[1].RecentBytes != 0 {
		t.Fatalf("expected window-only activity on proj-mid-window, got %+v", ov.Projects[1])
	}

	// Verify POST /api/v1/a/offline immediately marks a-sort-1 offline without waiting for node_offline_sec.
	if cands := srv.hub.DiscoverCandidates("proj-live-now"); len(cands) != 1 {
		t.Fatalf("expected 1 discover candidate before offline notify, got %d", len(cands))
	}
	offReq := httptest.NewRequest(http.MethodPost, "/api/v1/a/offline", nil)
	offReq.Header.Set(protocol.HeaderNodeID, "a-sort-1")
	offReq.Header.Set(protocol.HeaderNodeToken, "tok-sort-a")
	offRec := httptest.NewRecorder()
	handler.ServeHTTP(offRec, offReq)
	if offRec.Code != http.StatusNoContent {
		t.Fatalf("POST /api/v1/a/offline expected 204, got %d %s", offRec.Code, offRec.Body.String())
	}
	if cands := srv.hub.DiscoverCandidates("proj-live-now"); len(cands) != 0 {
		t.Fatalf("expected 0 discover candidates immediately after graceful offline, got %d", len(cands))
	}
}
