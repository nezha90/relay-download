package agenta

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"relay-download/internal/protocol"
	"relay-download/internal/transfer"
)

func baseValidConfig() Config {
	return Config{
		NodeID:       "a1",
		PublicAddr:   "https://1.2.3.4:8443",
		CenterURL:    "https://5.6.7.8:8440",
		CenterToken:  "node-tok",
		JWTSecret:    "jwt-secret",
		CenterSecret: "center-secret",
		LocalListen:  "127.0.0.1:18081",
		LocalToken:   "local-tok",
		TLSCert:      "/tmp/a1.crt",
		TLSKey:       "/tmp/a1.key",
	}
}

func TestConfigValidationHardening(t *testing.T) {
	ok := baseValidConfig()
	ok.ApplyDefaults()
	if err := ok.Validate(); err != nil {
		t.Fatalf("expected valid config, got: %v", err)
	}

	// Loopback variants must pass.
	for _, addr := range []string{"127.0.0.1:18081", "[::1]:18081", "localhost:18081"} {
		cfg := baseValidConfig()
		cfg.LocalListen = addr
		if err := cfg.Validate(); err != nil {
			t.Fatalf("expected loopback %s to pass, got: %v", addr, err)
		}
	}

	// Non-loopback local_listen must fail.
	for _, addr := range []string{"0.0.0.0:18081", "192.168.1.10:18081", "[::]:18081"} {
		cfg := baseValidConfig()
		cfg.LocalListen = addr
		if err := cfg.Validate(); err == nil {
			t.Fatalf("expected non-loopback local_listen %s to fail validation", addr)
		}
	}

	// Empty local_token is allowed by default on loopback when require_local_token is false.
	noLocalTok := baseValidConfig()
	noLocalTok.LocalToken = ""
	if err := noLocalTok.Validate(); err != nil {
		t.Fatalf("expected empty local_token to pass on loopback by default, got: %v", err)
	}

	// Empty local_token must fail when require_local_token is explicitly enabled.
	reqLocalTok := baseValidConfig()
	reqLocalTok.LocalToken = ""
	reqLocalTok.RequireLocalToken = true
	if err := reqLocalTok.Validate(); err == nil {
		t.Fatalf("expected empty local_token to fail validation when require_local_token=true")
	}

	// Missing center_secret must fail.
	noCenterSec := baseValidConfig()
	noCenterSec.CenterSecret = ""
	if err := noCenterSec.Validate(); err == nil {
		t.Fatalf("expected empty center_secret to fail validation")
	}

	// Plaintext public_addr must fail.
	httpPub := baseValidConfig()
	httpPub.PublicAddr = "http://1.2.3.4:8443"
	if err := httpPub.Validate(); err == nil {
		t.Fatalf("expected plaintext http public_addr to fail validation")
	}
}

func TestStoreNackBackoffAndAuthenticatedAckIdempotency(t *testing.T) {
	st, err := OpenStore(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer st.Close()

	rec := FileRecord{
		FileID:    "f-1",
		ProjectID: "p1",
		Filename:  "test.bin",
		Size:      128,
		SHA256:    "abcd",
	}
	if err := st.PutReady(rec, &protocol.SummaryEvent{
		EventID: "upl-f-1", ProjectID: "p1", ANodeID: "a1", EventType: protocol.EventUploaded, Bytes: 128,
	}); err != nil {
		t.Fatalf("PutReady: %v", err)
	}
	if evs, err := st.ListPendingEvents(10); err != nil || len(evs) != 1 || evs[0].EventID != "upl-f-1" {
		t.Fatalf("expected atomic uploaded event in pending_events, got %+v err=%v", evs, err)
	}

	claimed, err := st.ClaimNext("p1", "b1", 0, 30*time.Second)
	if err != nil {
		t.Fatalf("ClaimNext: %v", err)
	}
	if claimed.LeaseTTLSec != 30 {
		t.Fatalf("expected LeaseTTLSec=30, got %d", claimed.LeaseTTLSec)
	}

	// NACK must put the file into backoff cooldown.
	nacked, err := st.Nack(claimed.FileID, claimed.LeaseID, claimed.LeaseToken, "b1", nil)
	if err != nil {
		t.Fatalf("Nack: %v", err)
	}
	if nacked.NextRetryAt == nil || !nacked.NextRetryAt.After(time.Now().UTC()) {
		t.Fatalf("expected future NextRetryAt after NACK, got %v", nacked.NextRetryAt)
	}
	if _, err := st.ClaimNext("p1", "b1", 0, 30*time.Second); err != ErrNoReadyFile {
		t.Fatalf("expected ErrNoReadyFile during NACK backoff, got %v", err)
	}
	avail, _ := st.ComputeAvailability()
	for _, a := range avail {
		if a.ProjectID == "p1" && a.ReadyCount != 0 {
			t.Fatalf("expected ReadyCount=0 during backoff, got %d", a.ReadyCount)
		}
	}

	// Advancing reaper past NextRetryAt makes it claimable again.
	reaped, err := st.ReapExpiredLeases(nacked.NextRetryAt.Add(time.Second))
	if err != nil || reaped != 1 {
		t.Fatalf("expected 1 woken record, got reaped=%d err=%v", reaped, err)
	}
	reclaimed, err := st.ClaimNext("p1", "b1", 0, 30*time.Second)
	if err != nil {
		t.Fatalf("ClaimNext after backoff: %v", err)
	}

	// Ack and delete atomically with completed event.
	deletedRec, already, err := st.AckAndRemove(reclaimed.FileID, reclaimed.LeaseID, reclaimed.LeaseToken, "b1", "abcd", nil, func(r FileRecord) *protocol.SummaryEvent {
		return &protocol.SummaryEvent{EventID: "cmp-" + r.FileID, ProjectID: r.ProjectID, ANodeID: "a1", EventType: protocol.EventCompleted, Bytes: r.Size}
	})
	if err != nil || already || deletedRec == nil || deletedRec.Status != protocol.FileStatusClaimed {
		t.Fatalf("initial AckAndRemove failed: rec=%v already=%v err=%v", deletedRec, already, err)
	}
	if evs, err := st.ListPendingEvents(10); err != nil || len(evs) != 2 {
		t.Fatalf("expected atomic completed event in pending_events, got %+v err=%v", evs, err)
	}

	// Genuine duplicate ACK with matching credentials returns alreadyDeleted=true.
	_, already, err = st.AckAndRemove(reclaimed.FileID, reclaimed.LeaseID, reclaimed.LeaseToken, "b1", "abcd", nil, nil)
	if err != nil || !already {
		t.Fatalf("expected idempotent already_deleted for matching credentials, got already=%v err=%v", already, err)
	}

	// Forged credentials must NOT get already_deleted (must return ErrFileNotFound).
	_, already, err = st.AckAndRemove(reclaimed.FileID, reclaimed.LeaseID, "wrong-token", "b1", "abcd", nil, nil)
	if err != ErrFileNotFound || already {
		t.Fatalf("expected ErrFileNotFound for forged token, got already=%v err=%v", already, err)
	}
}

func TestLocalAuthLoopbackNoTokenAndOriginGuard(t *testing.T) {
	okHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	// Default mode (RequireLocalToken=false): loopback allowed WITHOUT X-Local-Token,
	// even if LocalToken is present in YAML (backward compatibility with existing nodes).
	cfg := baseValidConfig()
	a := &Agent{cfg: &cfg}
	h := a.requireLocalAuth(okHandler)

	for _, remote := range []string{"127.0.0.1:54321", "[::1]:54321", "localhost:1234"} {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:18081/local/v1/status", nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		h(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected loopback %s without token to return 200, got %d", remote, rec.Code)
		}
	}

	// Cross-origin browser request from non-loopback Origin must be blocked (403).
	for _, badOrigin := range []string{"https://evil.example", "http://192.168.1.50:8080", "null"} {
		req := httptest.NewRequest(http.MethodPut, "http://127.0.0.1:18081/local/v1/files/p/a.bin", nil)
		req.RemoteAddr = "127.0.0.1:54321"
		req.Header.Set("Origin", badOrigin)
		rec := httptest.NewRecorder()
		h(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected cross-origin %q to return 403, got %d", badOrigin, rec.Code)
		}
	}

	// Non-loopback Host header (DNS rebinding) must be blocked (403).
	for _, badHost := range []string{"evil.example:18081", "192.168.1.10:18081", "example.com"} {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:18081/local/v1/status", nil)
		req.RemoteAddr = "127.0.0.1:54321"
		req.Host = badHost
		rec := httptest.NewRecorder()
		h(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected non-loopback Host %q to return 403, got %d", badHost, rec.Code)
		}
	}

	// Reverse-proxied requests (X-Forwarded-For / Forwarded / X-Real-IP) must be blocked (403).
	for _, hdr := range []struct{ k, v string }{
		{"X-Forwarded-For", "203.0.113.9"},
		{"Forwarded", "for=203.0.113.9"},
		{"X-Real-IP", "203.0.113.9"},
	} {
		req := httptest.NewRequest(http.MethodPut, "http://127.0.0.1:18081/local/v1/files/p/a.bin", nil)
		req.RemoteAddr = "127.0.0.1:54321"
		req.Header.Set(hdr.k, hdr.v)
		rec := httptest.NewRecorder()
		h(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected proxied header %s=%s to return 403, got %d", hdr.k, hdr.v, rec.Code)
		}
	}

	// Non-loopback remote address must ALWAYS be rejected (403), even if valid token is supplied.
	reqRemote := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:18081/local/v1/status", nil)
	reqRemote.RemoteAddr = "192.0.2.10:44321"
	reqRemote.Header.Set(protocol.HeaderLocalToken, cfg.LocalToken)
	recRemote := httptest.NewRecorder()
	h(recRemote, reqRemote)
	if recRemote.Code != http.StatusForbidden {
		t.Fatalf("expected non-loopback remote even with token to return 403, got %d", recRemote.Code)
	}

	// Opt-in strict mode (RequireLocalToken=true): loopback without token returns 401; matching token returns 200.
	strictCfg := baseValidConfig()
	strictCfg.RequireLocalToken = true
	strictAgent := &Agent{cfg: &strictCfg}
	strictH := strictAgent.requireLocalAuth(okHandler)

	reqNoTok := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:18081/local/v1/status", nil)
	reqNoTok.RemoteAddr = "127.0.0.1:54321"
	recNoTok := httptest.NewRecorder()
	strictH(recNoTok, reqNoTok)
	if recNoTok.Code != http.StatusUnauthorized {
		t.Fatalf("expected strict mode without token to return 401, got %d", recNoTok.Code)
	}

	reqGoodTok := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:18081/local/v1/status", nil)
	reqGoodTok.RemoteAddr = "127.0.0.1:54321"
	reqGoodTok.Header.Set(protocol.HeaderLocalToken, strictCfg.LocalToken)
	recGoodTok := httptest.NewRecorder()
	strictH(recGoodTok, reqGoodTok)
	if recGoodTok.Code != http.StatusOK {
		t.Fatalf("expected strict mode with matching token to return 200, got %d", recGoodTok.Code)
	}
}

func TestDispatchCustomWatermarkHotUpdate(t *testing.T) {
	cfg := baseValidConfig()
	cfg.ApplyDefaults()
	if cfg.MaxDiskUsagePct != 85.0 {
		t.Fatalf("expected default MaxDiskUsagePct=85, got %.1f", cfg.MaxDiskUsagePct)
	}
	a := &Agent{
		cfg:             &cfg,
		maxDiskUsagePct: cfg.MaxDiskUsagePct,
		disabledDisks:   make(map[string]struct{}),
		diskHealth:      transfer.NewDiskHealthTracker(),
		logger:          slog.Default(),
	}
	if got := a.effectiveMaxDiskUsagePct(); got != 85.0 {
		t.Fatalf("expected default effective watermark 85, got %.1f", got)
	}
	a.applyDiskConfig(nil, nil, 0, 99.0)
	if got := a.effectiveMaxDiskUsagePct(); got != 99.0 {
		t.Fatalf("expected hot-updated 99%% watermark, got %.1f", got)
	}
	a.applyDiskConfig(nil, nil, 0, 1.0)
	if got := a.effectiveMaxDiskUsagePct(); got != 1.0 {
		t.Fatalf("expected hot-updated 1%% watermark, got %.1f", got)
	}
	a.applyDiskConfig(nil, nil, 0, 100.0)
	if got := a.effectiveMaxDiskUsagePct(); got != 99.0 {
		t.Fatalf("expected >99%% clamped to 99%%, got %.1f", got)
	}
}

func TestExtractAndSnapshotProjectCustomerHints(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "http://127.0.0.1:18081/local/v1/files/p-new/a.m4a?customer=cust-2", nil)
	req.Header.Set(protocol.HeaderCustomer, "cust-1, cust-2, ../bad")
	req.Header.Set(protocol.HeaderProjectName, "台湾音频\n测试")
	name, custs := extractProjectHintFromRequest(req)
	if name != "台湾音频 测试" {
		t.Fatalf("unexpected sanitized project name: %q", name)
	}
	if len(custs) != 2 || custs[0] != "cust-1" || custs[1] != "cust-2" {
		t.Fatalf("unexpected parsed customer IDs: %+v", custs)
	}

	a := &Agent{}
	a.recordProjectHint("p-new", name, custs)
	snap := a.snapshotProjectHints([]protocol.ProjectAvailability{{ProjectID: "p-new", ReadyCount: 1}})
	h, ok := snap["p-new"]
	if !ok || h.Name != "台湾音频 测试" || len(h.CustomerIDs) != 2 {
		t.Fatalf("unexpected project hint snapshot: %+v", snap)
	}
}
