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
