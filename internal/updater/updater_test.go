package updater

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"relay-download/internal/protocol"
)

func TestUpdaterRejectsUntrustedDownloadURLs(t *testing.T) {
	var hits atomic.Int32
	evilSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer evilSrv.Close()

	u := New(Options{
		Component:   "relay-agent-b",
		NodeID:      "b-test",
		CenterURL:   "https://127.0.0.1:8440",
		CenterToken: "super-secret-node-token",
		HTTPClient:  evilSrv.Client(),
		ExePath:     t.TempDir() + "/relay-agent-b",
	})

	badURLs := []string{
		"",
		evilSrv.URL + "/api/v1/releases/rel-1/download",
		"https://evil.example.com/api/v1/releases/rel-1/download",
		"//evil.example.com/api/v1/releases/rel-1/download",
		"/api/v1/releases/../../admin/overview",
		"/api/v1/releases/rel-1/download\r\nX-Injected: 1",
		"/api/v1/releases/rel-1\\..\\secret",
		"/api/v1/releases/rel-1?redirect=https://evil.example.com",
		"/api/v1/releases/@evil.example.com/bin",
		"/api/v1/releases/",
	}

	for _, raw := range badURLs {
		err := u.apply(context.Background(), protocol.UpgradeDirective{
			Version:     "v9.9.9",
			DownloadURL: raw,
			SHA256:      "0000000000000000000000000000000000000000000000000000000000000000",
		})
		if err == nil {
			t.Fatalf("expected untrusted download_url %q to be rejected", raw)
		}
	}

	if hits.Load() != 0 {
		t.Fatalf("expected 0 outbound requests to evil server, got %d", hits.Load())
	}

	if !isSafeReleaseDownloadPath("/api/v1/releases/rel_12345/download") {
		t.Fatalf("expected normal release path to be accepted")
	}
}
