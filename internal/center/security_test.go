package center

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"relay-download/internal/pki"
	"relay-download/internal/protocol"
)

func TestSecurityHeadersStrictCSPAndAdminCSRFProtection(t *testing.T) {
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
		Listen:            "127.0.0.1:0",
		TLSCert:           srvCert,
		TLSKey:            srvKey,
		CACert:            caCert,
		DBPath:            filepath.Join(dir, "center.db"),
		ReleasesDir:       filepath.Join(dir, "releases"),
		JWTSecret:         "jwt-secret",
		CenterSecret:      "center-secret",
		AdminToken:        "adm-tok",
		AdminTrustedCIDRs: []string{"127.0.0.1/32"},
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.Shutdown(context.Background())
	h := srv.routes()

	// 1. Web UI root MUST return strict CSP without 'unsafe-inline' in script-src + anti-clickjacking headers.
	getReq := httptest.NewRequest(http.MethodGet, "/", nil)
	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET /: %d", getRec.Code)
	}
	csp := getRec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "script-src 'self' 'unsafe-inline'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("expected strict CSP without script unsafe-inline, got: %q", csp)
	}
	if getRec.Header().Get("X-Content-Type-Options") != "nosniff" || getRec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("missing security headers: %+v", getRec.Header())
	}
	if strings.Contains(getRec.Body.String(), "onclick=") {
		t.Fatalf("index.html must not contain inline onclick handlers under strict CSP")
	}

	// 2. Cross-origin / cross-site CSRF POST from trusted workstation IP MUST be blocked (403).
	csrfCases := []struct {
		name    string
		origin  string
		sfs     string
		ct      string
	}{
		{"cross-origin header", "https://evil.example.com", "", "application/json"},
		{"sec-fetch-site cross-site", "", "cross-site", "application/json"},
		{"no-cors text/plain simple post", "", "", "text/plain;charset=UTF-8"},
		{"form-urlencoded post", "", "", "application/x-www-form-urlencoded"},
	}
	for _, tc := range csrfCases {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/projects", strings.NewReader(`{"id":"csrf-proj","name":"Evil"}`))
		req.Host = "117.55.199.204:8440"
		req.RemoteAddr = "127.0.0.1:50000" // trusted IP!
		if tc.origin != "" {
			req.Header.Set("Origin", tc.origin)
		}
		if tc.sfs != "" {
			req.Header.Set("Sec-Fetch-Site", tc.sfs)
		}
		if tc.ct != "" {
			req.Header.Set("Content-Type", tc.ct)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("CSRF case %q: expected 403 Forbidden, got %d (%s)", tc.name, rec.Code, rec.Body.String())
		}
	}

	// 3. Same-origin JSON POST from trusted IP succeeds cleanly, and invalid project/disk paths are rejected.
	okReq := httptest.NewRequest(http.MethodPost, "/api/v1/admin/projects", strings.NewReader(`{"id":"safe-proj","name":"Safe\nName<script>"}`))
	okReq.Host = "117.55.199.204:8440"
	okReq.RemoteAddr = "127.0.0.1:50001"
	okReq.Header.Set("Origin", "https://117.55.199.204:8440")
	okReq.Header.Set("Sec-Fetch-Site", "same-origin")
	okReq.Header.Set("Content-Type", "application/json")
	okRec := httptest.NewRecorder()
	h.ServeHTTP(okRec, okReq)
	if okRec.Code != http.StatusOK {
		t.Fatalf("same-origin trusted POST failed: %d %s", okRec.Code, okRec.Body.String())
	}
	if strings.Contains(okRec.Body.String(), `\n`) {
		t.Fatalf("expected newline control character stripped from project name, got: %s", okRec.Body.String())
	}

	// 4. Node creation with injected project ID or traversal disabled_disk MUST return 400.
	badNodeReq := httptest.NewRequest(http.MethodPost, "/api/v1/admin/nodes", strings.NewReader(`{"id":"n1","role":"agent_b","projects":["../etc"],"disabled_disks":["/mnt/../../etc"]}`))
	badNodeReq.Header.Set(protocol.HeaderAdminToken, "adm-tok")
	badNodeReq.Header.Set("Content-Type", "application/json")
	badNodeRec := httptest.NewRecorder()
	h.ServeHTTP(badNodeRec, badNodeReq)
	if badNodeRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid project/disk path on node creation, got %d (%s)", badNodeRec.Code, badNodeRec.Body.String())
	}
}
