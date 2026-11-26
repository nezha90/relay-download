package center

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"relay-download/internal/pki"
	"relay-download/internal/protocol"
)

func TestCenterDiskHotPlugAutoLockAndManualReconfirm(t *testing.T) {
	tmp := t.TempDir()
	caPath := filepath.Join(tmp, "ca.crt")
	caKeyPath := filepath.Join(tmp, "ca.key")
	if err := pki.InitCA(caPath, caKeyPath, "relay-hotplug-test-ca", 365); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	srvCert := filepath.Join(tmp, "center.crt")
	srvKey := filepath.Join(tmp, "center.key")
	if err := pki.IssueCert(caPath, caKeyPath, srvCert, srvKey, "center", []string{"127.0.0.1"}, nil, 365); err != nil {
		t.Fatalf("IssueCert: %v", err)
	}
	srv, err := New(&Config{
		Listen:       "127.0.0.1:0",
		TLSCert:      srvCert,
		TLSKey:       srvKey,
		CACert:       caPath,
		PublicURL:    "https://center.test:8440",
		ReleasesDir:  filepath.Join(tmp, "releases"),
		DBPath:       filepath.Join(tmp, "center.db"),
		AdminToken:   "admin-secret",
		JWTSecret:    "jwt-secret-1234567890",
		CenterSecret: "center-secret-123456",
	}, nil)
	if err != nil {
		t.Fatalf("new center: %v", err)
	}
	defer srv.Store().Close()

	ctx := context.Background()
	if err := srv.Store().UpsertNode(ctx, protocol.NodeRecord{
		ID:             "b-nas",
		Name:           "NAS 接收机",
		Role:           protocol.RoleAgentB,
		OwnerAccountID: "cust-1",
		Projects:       []string{"tw-audio"},
		StorageDirs:    []string{"/mnt/sda/relay-delivery", "/mnt/sdb/relay-delivery"},
	}, "b-token"); err != nil {
		t.Fatalf("upsert b node: %v", err)
	}
	if err := srv.Store().UpsertNode(ctx, protocol.NodeRecord{
		ID:          "a-edge",
		Name:        "分发节点",
		Role:        protocol.RoleAgentA,
		PublicAddr:  "https://1.2.3.4:8443",
		StorageDirs: []string{"/mnt/nvme/relay-cache"},
	}, "a-token"); err != nil {
		t.Fatalf("upsert a node: %v", err)
	}
	if err := srv.Store().CreateAccount(ctx, protocol.AccountRecord{
		ID:       "cust-1",
		Name:     "客户1",
		Role:     protocol.AccountRoleCustomer,
		Projects: []string{"tw-audio"},
		Enabled:  true,
	}, "cust-token"); err != nil {
		t.Fatalf("create customer: %v", err)
	}

	handler := srv.routes()

	sendBHB := func(disks []protocol.DiskStatus, hostDisks []protocol.HostDisk) protocol.HeartbeatResp {
		t.Helper()
		raw, _ := json.Marshal(protocol.AgentBHeartbeatReq{
			NodeID:      "b-nas",
			Name:        "NAS 接收机",
			StorageDirs: []string{"/mnt/sda/relay-delivery", "/mnt/sdb/relay-delivery"},
			Disks:       disks,
			HostDisks:   hostDisks,
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/b/heartbeat", bytes.NewReader(raw))
		req.Header.Set(protocol.HeaderNodeID, "b-nas")
		req.Header.Set(protocol.HeaderNodeToken, "b-token")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("heartbeat failed: status=%d body=%s", rec.Code, rec.Body.String())
		}
		var out protocol.HeartbeatResp
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode hb resp: %v", err)
		}
		return out
	}

	// 1. Agent B reports /mnt/sda suddenly unplugged at disk_gen=0 -> Center auto-locks it in SQLite!
	hb1 := sendBHB([]protocol.DiskStatus{
		{
			Path:          "/mnt/sda/relay-delivery",
			Enabled:       false,
			Detached:      true,
			UnplugLatched: true,
			LatchedGen:    0,
			StatusReason:  "数据盘已拔出/未挂载",
		},
		{
			Path:       "/mnt/sdb/relay-delivery",
			Enabled:    true,
			Writable:   true,
			TotalBytes: 10 << 40,
			FreeBytes:  8 << 40,
		},
	}, []protocol.HostDisk{
		{Device: "/dev/sdb", MountPoint: "/mnt/sdb", FSType: "ext4", SuggestedDir: "/mnt/sdb/relay-delivery", Writable: true},
	})
	if hb1.Directive == nil || len(hb1.Directive.DisabledDisks) != 1 || hb1.Directive.DisabledDisks[0] != "/mnt/sda/relay-delivery" {
		t.Fatalf("expected /mnt/sda to be auto-disabled in directive immediately, got %+v", hb1.Directive)
	}
	if hb1.Directive.DiskGen != 0 {
		t.Fatalf("auto-lock must NOT increment disk_gen (expected 0, got %d)", hb1.Directive.DiskGen)
	}

	// Verify persisted in DB (survives restarts!) and exposed via GET /api/v1/admin/nodes/{id}/disks.
	reqDisks := httptest.NewRequest(http.MethodGet, "/api/v1/admin/nodes/b-nas/disks", nil)
	reqDisks.Header.Set(protocol.HeaderAdminToken, "cust-token")
	recDisks := httptest.NewRecorder()
	handler.ServeHTTP(recDisks, reqDisks)
	if recDisks.Code != http.StatusOK {
		t.Fatalf("customer GET b-nas disks failed: %d %s", recDisks.Code, recDisks.Body.String())
	}
	var diskInfo struct {
		DiskGen           int64    `json:"disk_gen"`
		DisabledDisks     []string `json:"disabled_disks"`
		UnplugLockedDisks []string `json:"unplug_locked_disks"`
	}
	_ = json.Unmarshal(recDisks.Body.Bytes(), &diskInfo)
	if len(diskInfo.UnplugLockedDisks) != 1 || diskInfo.UnplugLockedDisks[0] != "/mnt/sda/relay-delivery" {
		t.Fatalf("expected unplug_locked_disks to contain /mnt/sda, got %+v", diskInfo)
	}

	// RBAC check: customer account MUST NOT inspect dispatch node disks.
	reqADisks := httptest.NewRequest(http.MethodGet, "/api/v1/admin/nodes/a-edge/disks", nil)
	reqADisks.Header.Set(protocol.HeaderAdminToken, "cust-token")
	recADisks := httptest.NewRecorder()
	handler.ServeHTTP(recADisks, reqADisks)
	if recADisks.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for customer accessing dispatch disks, got %d", recADisks.Code)
	}

	// 2. Operator confirms reinsertion & re-enables /mnt/sda via PUT /api/v1/admin/nodes/b-nas -> disk_gen becomes 1 & lock clears!
	putBody, _ := json.Marshal(map[string]any{
		"storage_dirs":   []string{"/mnt/sda/relay-delivery", "/mnt/sdb/relay-delivery"},
		"disabled_disks": []string{},
	})
	reqPut := httptest.NewRequest(http.MethodPut, "/api/v1/admin/nodes/b-nas", bytes.NewReader(putBody))
	reqPut.Header.Set(protocol.HeaderAdminToken, "admin-secret")
	recPut := httptest.NewRecorder()
	handler.ServeHTTP(recPut, reqPut)
	if recPut.Code != http.StatusOK {
		t.Fatalf("PUT re-enable failed: %d %s", recPut.Code, recPut.Body.String())
	}
	nAfter, _ := srv.Store().GetNode(ctx, "b-nas")
	if nAfter.DiskGen != 1 || len(nAfter.DisabledDisks) != 0 || len(nAfter.UnplugLockedDisks) != 0 {
		t.Fatalf("expected disk_gen=1 and cleared disabled/unplug locks, got %+v", nAfter)
	}

	// 3. Stale heartbeat with LatchedGen=0 arriving after manual re-enable (DiskGen=1) MUST be ignored (no race)!
	hbStale := sendBHB([]protocol.DiskStatus{
		{
			Path:          "/mnt/sda/relay-delivery",
			Enabled:       false,
			UnplugLatched: true,
			LatchedGen:    0, // stale generation!
		},
	}, nil)
	if hbStale.Directive == nil || hbStale.Directive.DiskGen != 1 || len(hbStale.Directive.DisabledDisks) != 0 {
		t.Fatalf("stale heartbeat must not re-lock disk after operator re-enable, got %+v", hbStale.Directive)
	}
}
