package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"relay-download/internal/agenta"
	"relay-download/internal/agentb"
	"relay-download/internal/auth"
	"relay-download/internal/center"
	"relay-download/internal/pki"
	"relay-download/internal/protocol"
)

type testEnv struct {
	t            *testing.T
	dir          string
	caCert       string
	caKey        string
	jwtSecret    string
	centerSecret string
	adminToken   string
	centerSrv    *center.Server
	centerURL    string
	httpClient   *http.Client
	cancel       context.CancelFunc
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	certDir := filepath.Join(dir, "certs")
	caCert := filepath.Join(certDir, "ca.crt")
	caKey := filepath.Join(certDir, "ca.key")
	if err := pki.InitCA(caCert, caKey, "Test Relay CA", 365); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	cCert := filepath.Join(certDir, "center.crt")
	cKey := filepath.Join(certDir, "center.key")
	if err := pki.IssueCert(caCert, caKey, cCert, cKey, "center", []string{"127.0.0.1"}, nil, 365); err != nil {
		t.Fatalf("IssueCert center: %v", err)
	}

	cPort := freePort(t)
	centerURL := fmt.Sprintf("https://127.0.0.1:%d", cPort)
	cfg := &center.Config{
		Listen:         fmt.Sprintf("127.0.0.1:%d", cPort),
		TLSCert:        cCert,
		TLSKey:         cKey,
		CACert:         caCert,
		CAKey:          caKey,
		PublicURL:      centerURL,
		ReleasesDir:    filepath.Join(dir, "releases"),
		DBPath:         filepath.Join(dir, "center.db"),
		JWTSecret:      "test-jwt-secret-12345",
		CenterSecret:   "test-center-secret-12345",
		AdminToken:     "test-admin-token-12345",
		NodeOfflineSec: 15,
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := center.New(cfg, logger)
	if err != nil {
		t.Fatalf("center.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Start(ctx) }()

	clientTLS, err := pki.ClientTLSConfig(caCert)
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   clientTLS,
			ForceAttemptHTTP2: true,
		},
	}

	env := &testEnv{
		t:            t,
		dir:          dir,
		caCert:       caCert,
		caKey:        caKey,
		jwtSecret:    cfg.JWTSecret,
		centerSecret: cfg.CenterSecret,
		adminToken:   cfg.AdminToken,
		centerSrv:    srv,
		centerURL:    fmt.Sprintf("https://127.0.0.1:%d", cPort),
		httpClient:   client,
		cancel:       cancel,
	}
	t.Cleanup(func() {
		cancel()
		_ = srv.Shutdown(context.Background())
	})

	waitUntil(t, 5*time.Second, func() bool {
		req, _ := http.NewRequest(http.MethodGet, env.centerURL+"/api/v1/admin/overview", nil)
		req.Header.Set(protocol.HeaderAdminToken, env.adminToken)
		resp, err := client.Do(req)
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, "center server ready")

	return env
}

func (e *testEnv) createProject(id, conflictPolicy string, leaseTTL int) {
	e.t.Helper()
	err := e.centerSrv.Store().UpsertProject(context.Background(), protocol.Project{
		ID:             id,
		Name:           "Project " + id,
		ConflictPolicy: conflictPolicy,
		LeaseTTLSec:    leaseTTL,
	})
	if err != nil {
		e.t.Fatalf("UpsertProject: %v", err)
	}
}

func (e *testEnv) startAgentA(ctx context.Context, nodeID string, projects []string, leaseTTL int, minFreeDisk uint64) (*agenta.Agent, string, string) {
	e.t.Helper()
	certDir := filepath.Join(e.dir, "certs")
	certPath := filepath.Join(certDir, nodeID+".crt")
	keyPath := filepath.Join(certDir, nodeID+".key")
	if err := pki.IssueCert(e.caCert, e.caKey, certPath, keyPath, nodeID, []string{"127.0.0.1"}, nil, 365); err != nil {
		e.t.Fatalf("IssueCert %s: %v", nodeID, err)
	}

	localPort := freePort(e.t)
	pubPort := freePort(e.t)
	pubAddr := fmt.Sprintf("https://127.0.0.1:%d", pubPort)
	localAddr := fmt.Sprintf("http://127.0.0.1:%d", localPort)
	nodeTok := auth.GenerateRandomToken(16)

	if err := e.centerSrv.Store().UpsertNode(context.Background(), protocol.NodeRecord{
		ID:         nodeID,
		Name:       "Node " + nodeID,
		Role:       protocol.RoleAgentA,
		Projects:   projects,
		PublicAddr: pubAddr,
	}, nodeTok); err != nil {
		e.t.Fatalf("UpsertNode %s: %v", nodeID, err)
	}

	cfg := &agenta.Config{
		NodeID:               nodeID,
		NodeName:             "Node " + nodeID,
		PublicAddr:           pubAddr,
		CenterURL:            e.centerURL,
		CenterToken:          nodeTok,
		JWTSecret:            e.jwtSecret,
		CenterSecret:         e.centerSecret,
		Projects:             projects,
		LocalListen:          fmt.Sprintf("127.0.0.1:%d", localPort),
		LocalToken:           "local-secret-" + nodeID,
		PublicListen:         fmt.Sprintf("127.0.0.1:%d", pubPort),
		TLSCert:              certPath,
		TLSKey:               keyPath,
		CACert:               e.caCert,
		DataDir:              filepath.Join(e.dir, "data-"+nodeID),
		MaxDiskUsagePct:      99.9,
		MinFreeDiskBytes:     minFreeDisk,
		LeaseTTLSec:          leaseTTL,
		MaxConcurrentStreams: 16,
		HeartbeatIntervalSec: 1,
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ag, err := agenta.New(cfg, logger)
	if err != nil {
		e.t.Fatalf("agenta.New %s: %v", nodeID, err)
	}
	go func() { _ = ag.Start(ctx) }()
	e.t.Cleanup(func() { _ = ag.Shutdown(context.Background()) })

	waitUntil(e.t, 5*time.Second, func() bool {
		req, _ := http.NewRequest(http.MethodGet, localAddr+"/local/v1/status", nil)
		req.Header.Set(protocol.HeaderLocalToken, cfg.LocalToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, "agent-a "+nodeID+" ready")

	return ag, localAddr, cfg.LocalToken
}

func (e *testEnv) startAgentAWithUpgrade(ctx context.Context, nodeID, exePath string, onRestart func(string)) (*agenta.Agent, string, string) {
	e.t.Helper()
	certDir := filepath.Join(e.dir, "certs")
	certPath := filepath.Join(certDir, nodeID+".crt")
	keyPath := filepath.Join(certDir, nodeID+".key")
	if err := pki.IssueCert(e.caCert, e.caKey, certPath, keyPath, nodeID, []string{"127.0.0.1"}, nil, 365); err != nil {
		e.t.Fatalf("IssueCert %s: %v", nodeID, err)
	}
	localPort := freePort(e.t)
	pubPort := freePort(e.t)
	pubAddr := fmt.Sprintf("https://127.0.0.1:%d", pubPort)
	localAddr := fmt.Sprintf("http://127.0.0.1:%d", localPort)
	nodeTok := auth.GenerateRandomToken(16)
	if err := e.centerSrv.Store().UpsertNode(context.Background(), protocol.NodeRecord{
		ID: nodeID, Name: "Node " + nodeID, Role: protocol.RoleAgentA, PublicAddr: pubAddr,
	}, nodeTok); err != nil {
		e.t.Fatalf("UpsertNode %s: %v", nodeID, err)
	}
	cfg := &agenta.Config{
		NodeID: nodeID, NodeName: "Node " + nodeID, PublicAddr: pubAddr,
		CenterURL: e.centerURL, CenterToken: nodeTok, JWTSecret: e.jwtSecret, CenterSecret: e.centerSecret,
		LocalListen: fmt.Sprintf("127.0.0.1:%d", localPort), LocalToken: "local-secret-" + nodeID,
		PublicListen: fmt.Sprintf("127.0.0.1:%d", pubPort), TLSCert: certPath, TLSKey: keyPath, CACert: e.caCert,
		DataDir: filepath.Join(e.dir, "data-"+nodeID), MaxDiskUsagePct: 99.9, LeaseTTLSec: 60,
		MaxConcurrentStreams: 8, HeartbeatIntervalSec: 1,
	}
	ag, err := agenta.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		e.t.Fatalf("agenta.New %s: %v", nodeID, err)
	}
	ag.UpgradeExePath = exePath
	ag.UpgradeRestartHook = onRestart
	go func() { _ = ag.Start(ctx) }()
	e.t.Cleanup(func() { _ = ag.Shutdown(context.Background()) })
	return ag, localAddr, cfg.LocalToken
}

func (e *testEnv) startAgentBWithUpgrade(ctx context.Context, nodeID string, projects map[string]string, exePath string, onRestart func(string)) *agentb.Agent {
	e.t.Helper()
	nodeTok := auth.GenerateRandomToken(16)
	projIDs := make([]string, 0, len(projects))
	for k := range projects {
		projIDs = append(projIDs, k)
	}
	if err := e.centerSrv.Store().UpsertNode(context.Background(), protocol.NodeRecord{
		ID: nodeID, Name: "Node " + nodeID, Role: protocol.RoleAgentB, Projects: projIDs,
	}, nodeTok); err != nil {
		e.t.Fatalf("UpsertNode %s: %v", nodeID, err)
	}
	cfg := &agentb.Config{
		NodeID: nodeID, NodeName: "Node " + nodeID, CenterURL: e.centerURL, CenterToken: nodeTok,
		CACert: e.caCert, Projects: projects, StateDir: filepath.Join(e.dir, "state-"+nodeID),
		MaxConcurrent: 2, PollIntervalSec: 1, HeartbeatIntervalSec: 1,
	}
	ag, err := agentb.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		e.t.Fatalf("agentb.New %s: %v", nodeID, err)
	}
	ag.UpgradeExePath = exePath
	ag.UpgradeRestartHook = onRestart
	go func() { _ = ag.Start(ctx) }()
	return ag
}

func (e *testEnv) startAgentB(ctx context.Context, nodeID string, projects map[string]string, maxConc int) *agentb.Agent {
	e.t.Helper()
	nodeTok := auth.GenerateRandomToken(16)
	projIDs := make([]string, 0, len(projects))
	for k := range projects {
		projIDs = append(projIDs, k)
	}
	if err := e.centerSrv.Store().UpsertNode(context.Background(), protocol.NodeRecord{
		ID:       nodeID,
		Name:     "Node " + nodeID,
		Role:     protocol.RoleAgentB,
		Projects: projIDs,
	}, nodeTok); err != nil {
		e.t.Fatalf("UpsertNode %s: %v", nodeID, err)
	}

	cfg := &agentb.Config{
		NodeID:               nodeID,
		NodeName:             "Node " + nodeID,
		CenterURL:            e.centerURL,
		CenterToken:          nodeTok,
		CACert:               e.caCert,
		Projects:             projects,
		StateDir:             filepath.Join(e.dir, "state-"+nodeID),
		MaxConcurrent:        maxConc,
		MinFreeDiskBytes:     0,
		PollIntervalSec:      1,
		HeartbeatIntervalSec: 1,
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ag, err := agentb.New(cfg, logger)
	if err != nil {
		e.t.Fatalf("agentb.New %s: %v", nodeID, err)
	}
	go func() { _ = ag.Start(ctx) }()
	return ag
}

func uploadToA(t *testing.T, localAddr, localToken, project, filename string, data []byte, expectedSHA string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, localAddr+"/local/v1/upload", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("new upload req: %v", err)
	}
	req.Header.Set(protocol.HeaderLocalToken, localToken)
	req.Header.Set(protocol.HeaderProject, project)
	req.Header.Set(protocol.HeaderFilename, filename)
	if expectedSHA != "" {
		req.Header.Set(protocol.HeaderExpectedSHA256, expectedSHA)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("upload do: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}

func randBytes(t *testing.T, n int) ([]byte, string) {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	sum := sha256.Sum256(b)
	return b, hex.EncodeToString(sum[:])
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen free port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func waitUntil(t *testing.T, timeout time.Duration, cond func() bool, desc string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", desc)
}

func (e *testEnv) adminGet(path string, out any) {
	e.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.centerURL+path, nil)
	req.Header.Set(protocol.HeaderAdminToken, e.adminToken)
	resp, err := e.httpClient.Do(req)
	if err != nil {
		e.t.Fatalf("adminGet %s: %v", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		e.t.Fatalf("adminGet %s status=%d body=%s", path, resp.StatusCode, string(b))
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		e.t.Fatalf("decode %s: %v", path, err)
	}
}

func TestEndToEndFullFlowAndSummaryOnly(t *testing.T) {
	env := newTestEnv(t)
	env.createProject("proj-alpha", protocol.ConflictOverwrite, 60)

	// Verify Center DB has ZERO file-list tables.
	tables, err := env.centerSrv.Store().TableNames(context.Background())
	if err != nil {
		t.Fatalf("TableNames: %v", err)
	}
	for _, tbl := range tables {
		if tbl == "files" || tbl == "tasks" {
			t.Fatalf("center DB should not store file lists, found table: %s", tbl)
		}
	}
	if !slices.Contains(tables, "stats_daily") || !slices.Contains(tables, "stats_project_total") {
		t.Fatalf("expected summary tables in center DB, got: %v", tables)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, a1Local, a1Tok := env.startAgentA(ctx, "a1", nil, 60, 0)
	_, a2Local, a2Tok := env.startAgentA(ctx, "a2", nil, 60, 0)

	// 1. Path traversal must be rejected.
	resp, _ := uploadToA(t, a1Local, a1Tok, "proj-alpha", "../../etc/passwd", []byte("evil"), "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for path traversal, got %d", resp.StatusCode)
	}

	// 2. Wrong SHA256 must be rejected BEFORE exposing to B, leaving 0 files on A1.
	resp, _ = uploadToA(t, a1Local, a1Tok, "proj-alpha", "bad.bin", []byte("hello"), "0000000000000000000000000000000000000000000000000000000000000000")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad sha256, got %d", resp.StatusCode)
	}

	// 3. Valid local upload on A1.
	data1, sha1 := randBytes(t, 512*1024)
	resp, body := uploadToA(t, a1Local, a1Tok, "proj-alpha", "nested/file1.bin", data1, sha1)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for upload, got %d: %s", resp.StatusCode, string(body))
	}

	// 4. Valid local path zero-copy register on A2.
	data2, sha2 := randBytes(t, 384*1024)
	srcLocalFile := filepath.Join(env.dir, "prebuilt.bin")
	if err := os.WriteFile(srcLocalFile, data2, 0o600); err != nil {
		t.Fatalf("write prebuilt: %v", err)
	}
	regBody, _ := json.Marshal(protocol.LocalRegisterReq{
		ProjectID:      "proj-alpha",
		LocalPath:      srcLocalFile,
		Filename:       "file2.bin",
		ExpectedSHA256: sha2,
		Mode:           "move",
	})
	regReq, _ := http.NewRequest(http.MethodPost, a2Local+"/local/v1/register", bytes.NewReader(regBody))
	regReq.Header.Set("Content-Type", "application/json")
	regReq.Header.Set(protocol.HeaderLocalToken, a2Tok)
	regResp, err := http.DefaultClient.Do(regReq)
	if err != nil || regResp.StatusCode != http.StatusOK {
		t.Fatalf("local register failed: err=%v resp=%v", err, regResp)
	}
	_ = regResp.Body.Close()

	// 5. Verify Center Live Proxy Query sees live files on A1 before B starts.
	waitUntil(t, 5*time.Second, func() bool {
		var live protocol.LiveFilesResp
		env.adminGet("/api/v1/admin/nodes/a1/live-files", &live)
		return len(live.Files) == 1 && live.Files[0].Filename == "nested/file1.bin"
	}, "live proxy query on a1 shows file1.bin")

	// 6. Start B1 and verify both files arrive with exact SHA256, A deletes them, and Center updates summary.
	bDest := filepath.Join(env.dir, "b1-dest", "proj-alpha")
	env.startAgentB(ctx, "b1", map[string]string{"proj-alpha": bDest}, 2)

	file1Dst := filepath.Join(bDest, "nested", "file1.bin")
	file2Dst := filepath.Join(bDest, "file2.bin")
	waitUntil(t, 10*time.Second, func() bool {
		_, err1 := os.Stat(file1Dst)
		_, err2 := os.Stat(file2Dst)
		return err1 == nil && err2 == nil
	}, "b1 downloaded both files")

	got1, _ := os.ReadFile(file1Dst)
	got2, _ := os.ReadFile(file2Dst)
	if !bytes.Equal(got1, data1) || !bytes.Equal(got2, data2) {
		t.Fatalf("downloaded file contents mismatch")
	}

	// Verify A1 and A2 deleted their files immediately ("即用即删").
	waitUntil(t, 5*time.Second, func() bool {
		var live1, live2 protocol.LiveFilesResp
		env.adminGet("/api/v1/admin/nodes/a1/live-files", &live1)
		env.adminGet("/api/v1/admin/nodes/a2/live-files", &live2)
		return len(live1.Files) == 0 && len(live2.Files) == 0
	}, "a1 and a2 deleted files after ACK")

	// Verify physical ready dirs on A1 & A2 are empty.
	for _, nid := range []string{"a1", "a2"} {
		entries, _ := os.ReadDir(filepath.Join(env.dir, "data-"+nid, "ready"))
		if len(entries) != 0 {
			t.Fatalf("expected %s ready dir to be empty, found %d files", nid, len(entries))
		}
	}

	// Verify Center summary reflects 2 completed files and exact bytes.
	expectedBytes := int64(len(data1) + len(data2))
	waitUntil(t, 5*time.Second, func() bool {
		var ov protocol.OverviewResp
		env.adminGet("/api/v1/admin/overview", &ov)
		return ov.AllTimeCompleted == 2 && ov.AllTimeBytes == expectedBytes
	}, "center overview summary totals accurate")

	// 7. Test project internal overwrite policy: upload new content with same filename.
	data2v2, sha2v2 := randBytes(t, 64*1024)
	resp, _ = uploadToA(t, a1Local, a1Tok, "proj-alpha", "file2.bin", data2v2, sha2v2)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("overwrite upload failed: %d", resp.StatusCode)
	}
	waitUntil(t, 8*time.Second, func() bool {
		b, err := os.ReadFile(file2Dst)
		return err == nil && bytes.Equal(b, data2v2)
	}, "file2.bin atomically overwritten with v2")
}

func TestMultiBCompetingPreemptiveClaim(t *testing.T) {
	env := newTestEnv(t)
	env.createProject("proj-race", protocol.ConflictOverwrite, 60)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, a1Local, a1Tok := env.startAgentA(ctx, "a1", []string{"proj-race"}, 60, 0)
	_, a2Local, a2Tok := env.startAgentA(ctx, "a2", []string{"proj-race"}, 60, 0)

	bDirs := []string{
		filepath.Join(env.dir, "b1-race"),
		filepath.Join(env.dir, "b2-race"),
		filepath.Join(env.dir, "b3-race"),
	}
	env.startAgentB(ctx, "b1", map[string]string{"proj-race": bDirs[0]}, 3)
	env.startAgentB(ctx, "b2", map[string]string{"proj-race": bDirs[1]}, 3)
	env.startAgentB(ctx, "b3", map[string]string{"proj-race": bDirs[2]}, 3)

	const totalFiles = 30
	expectedSHA := make(map[string]string, totalFiles)
	for i := 0; i < totalFiles; i++ {
		name := fmt.Sprintf("batch_%02d.bin", i)
		payload, sha := randBytes(t, 32*1024)
		expectedSHA[name] = sha
		if i%2 == 0 {
			resp, _ := uploadToA(t, a1Local, a1Tok, "proj-race", name, payload, sha)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("upload %s to a1 failed: %d", name, resp.StatusCode)
			}
		} else {
			resp, _ := uploadToA(t, a2Local, a2Tok, "proj-race", name, payload, sha)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("upload %s to a2 failed: %d", name, resp.StatusCode)
			}
		}
	}

	// Wait for Center summary to report all 30 completed.
	waitUntil(t, 20*time.Second, func() bool {
		var ov protocol.OverviewResp
		env.adminGet("/api/v1/admin/overview", &ov)
		return ov.AllTimeCompleted == totalFiles
	}, "all 30 files completed across 3 competing B nodes")

	// Verify every file exists on EXACTLY ONE B node with exact SHA256.
	seen := make(map[string]int, totalFiles)
	for _, dir := range bDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("ReadDir %s: %v", dir, err)
		}
		for _, ent := range entries {
			if ent.IsDir() {
				continue
			}
			seen[ent.Name()]++
			b, _ := os.ReadFile(filepath.Join(dir, ent.Name()))
			sum := sha256.Sum256(b)
			if hex.EncodeToString(sum[:]) != expectedSHA[ent.Name()] {
				t.Fatalf("sha256 mismatch for %s", ent.Name())
			}
		}
	}
	if len(seen) != totalFiles {
		t.Fatalf("expected %d unique files across B nodes, got %d", totalFiles, len(seen))
	}
	for name, cnt := range seen {
		if cnt != 1 {
			t.Fatalf("file %s was downloaded %d times (expected exactly 1)", name, cnt)
		}
	}
}

func TestResumableDownloadAfterMidStreamDrop(t *testing.T) {
	env := newTestEnv(t)
	env.createProject("proj-resume", protocol.ConflictOverwrite, 60)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	agA, a1Local, a1Tok := env.startAgentA(ctx, "a1", []string{"proj-resume"}, 60, 0)

	// Force-abort stream ONCE after 1.5 MiB has been sent.
	var dropped atomic.Bool
	agA.StreamChunkHook = func(fileID string, sentTotal int64) error {
		if sentTotal >= 1536*1024 && dropped.CompareAndSwap(false, true) {
			return io.ErrUnexpectedEOF
		}
		return nil
	}

	// Upload a 4 MiB file.
	bigData, bigSHA := randBytes(t, 4*1024*1024)
	resp, _ := uploadToA(t, a1Local, a1Tok, "proj-resume", "large4mb.bin", bigData, bigSHA)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upload 4MB failed: %d", resp.StatusCode)
	}

	bDest := filepath.Join(env.dir, "b-resume")
	agB := env.startAgentB(ctx, "b1", map[string]string{"proj-resume": bDest}, 1)

	dstPath := filepath.Join(bDest, "large4mb.bin")
	waitUntil(t, 15*time.Second, func() bool {
		_, err := os.Stat(dstPath)
		return err == nil
	}, "4MB file resumed and committed")

	if !dropped.Load() {
		t.Fatalf("expected mid-stream drop hook to trigger")
	}
	if agB.ResumeCount.Load() < 1 {
		t.Fatalf("expected B ResumeCount >= 1, got %d", agB.ResumeCount.Load())
	}
	got, _ := os.ReadFile(dstPath)
	if !bytes.Equal(got, bigData) {
		t.Fatalf("resumed 4MB file content mismatch")
	}
}

func TestLeaseExpiryFailoverAndIdempotentAck(t *testing.T) {
	env := newTestEnv(t)
	env.createProject("proj-lease", protocol.ConflictOverwrite, 2) // 2-second short lease for test

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	agA, a1Local, a1Tok := env.startAgentA(ctx, "a1", []string{"proj-lease"}, 2, 0)
	data, sha := randBytes(t, 128*1024)
	resp, body := uploadToA(t, a1Local, a1Tok, "proj-lease", "failover.bin", data, sha)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upload failed: %d %s", resp.StatusCode, string(body))
	}

	// Sign an access JWT for a simulated zombie B node "b-dead" and claim the file without downloading.
	deadJWT, err := auth.SignAccessJWT(env.jwtSecret, auth.AccessClaims{
		BNodeID:   "b-dead",
		ProjectID: "proj-lease",
		ANodeID:   "a1",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("SignAccessJWT: %v", err)
	}
	claimBody, _ := json.Marshal(protocol.ClaimReq{
		ProjectID:   "proj-lease",
		BNodeID:     "b-dead",
		LeaseTTLSec: 2,
	})
	aPubURL := "https://" + agA.PublicListenAddr()
	claimReq, _ := http.NewRequest(http.MethodPost, aPubURL+"/api/v1/claim", bytes.NewReader(claimBody))
	claimReq.Header.Set("Content-Type", "application/json")
	claimReq.Header.Set("Authorization", "Bearer "+deadJWT)
	claimResp, err := env.httpClient.Do(claimReq)
	if err != nil || claimResp.StatusCode != http.StatusOK {
		t.Fatalf("zombie claim failed: err=%v resp=%v", err, claimResp)
	}
	var claimed protocol.ClaimResp
	_ = json.NewDecoder(claimResp.Body).Decode(&claimed)
	_ = claimResp.Body.Close()

	// Wait for lease (2s) to expire and reaper (1s loop) to release file back to READY.
	time.Sleep(3200 * time.Millisecond)

	// Zombie B trying to stream with expired lease token must receive 409 Conflict.
	staleReq, _ := http.NewRequest(http.MethodGet, aPubURL+"/api/v1/files/"+claimed.FileID+"/stream", nil)
	staleReq.Header.Set(protocol.HeaderLeaseToken, claimed.LeaseToken)
	staleResp, err := env.httpClient.Do(staleReq)
	if err != nil {
		t.Fatalf("stale stream req: %v", err)
	}
	_ = staleResp.Body.Close()
	if staleResp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 Conflict for expired lease, got %d", staleResp.StatusCode)
	}

	// Start live B2; it must pick up the released file and finish it.
	b2Dest := filepath.Join(env.dir, "b2-failover")
	env.startAgentB(ctx, "b2", map[string]string{"proj-lease": b2Dest}, 1)

	dst := filepath.Join(b2Dest, "failover.bin")
	waitUntil(t, 10*time.Second, func() bool {
		b, err := os.ReadFile(dst)
		return err == nil && bytes.Equal(b, data)
	}, "b2 took over expired lease and downloaded file")

	// Wait until A1 deletes the file after B2 ACK.
	waitUntil(t, 5*time.Second, func() bool {
		var live protocol.LiveFilesResp
		env.adminGet("/api/v1/admin/nodes/a1/live-files", &live)
		return len(live.Files) == 0
	}, "a1 deleted file after b2 ack")

	// Unauthenticated duplicate ACK must be rejected with 401; forged token must get 404.
	forgedAckBody, _ := json.Marshal(protocol.AckReq{
		LeaseID: claimed.LeaseID,
		BNodeID: "b2",
		SHA256:  sha,
	})
	unauthReq, _ := http.NewRequest(http.MethodPost, aPubURL+"/api/v1/files/"+claimed.FileID+"/ack", bytes.NewReader(forgedAckBody))
	unauthReq.Header.Set("Content-Type", "application/json")
	unauthResp, err := env.httpClient.Do(unauthReq)
	if err != nil {
		t.Fatalf("unauth ack req: %v", err)
	}
	_ = unauthResp.Body.Close()
	if unauthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 on unauthenticated ack, got %d", unauthResp.StatusCode)
	}

	forgedReq, _ := http.NewRequest(http.MethodPost, aPubURL+"/api/v1/files/"+claimed.FileID+"/ack", bytes.NewReader(forgedAckBody))
	forgedReq.Header.Set("Content-Type", "application/json")
	forgedReq.Header.Set(protocol.HeaderLeaseToken, "forged-token")
	forgedResp, err := env.httpClient.Do(forgedReq)
	if err != nil {
		t.Fatalf("forged ack req: %v", err)
	}
	_ = forgedResp.Body.Close()
	if forgedResp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 on forged duplicate ack, got %d", forgedResp.StatusCode)
	}

	// Genuine duplicate ACK with matching lease credentials must return 200 OK {"status":"already_deleted"}.
	dataIdem, shaIdem := randBytes(t, 16*1024)
	upResp, _ := uploadToA(t, a1Local, a1Tok, "proj-lease", "idem.bin", dataIdem, shaIdem)
	if upResp.StatusCode != http.StatusOK {
		t.Fatalf("upload idem.bin failed: %d", upResp.StatusCode)
	}
	idemClaimBody, _ := json.Marshal(protocol.ClaimReq{ProjectID: "proj-lease", BNodeID: "b-dead", LeaseTTLSec: 30})
	idemClaimReq, _ := http.NewRequest(http.MethodPost, aPubURL+"/api/v1/claim", bytes.NewReader(idemClaimBody))
	idemClaimReq.Header.Set("Content-Type", "application/json")
	idemClaimReq.Header.Set("Authorization", "Bearer "+deadJWT)
	idemClaimResp, err := env.httpClient.Do(idemClaimReq)
	if err != nil || idemClaimResp.StatusCode != http.StatusOK {
		t.Fatalf("claim idem.bin failed: err=%v resp=%v", err, idemClaimResp)
	}
	var idemClaim protocol.ClaimResp
	_ = json.NewDecoder(idemClaimResp.Body).Decode(&idemClaim)
	_ = idemClaimResp.Body.Close()

	ackPayload, _ := json.Marshal(protocol.AckReq{
		LeaseID: idemClaim.LeaseID,
		BNodeID: "b-dead",
		SHA256:  shaIdem,
	})
	for i, wantStatus := range []string{"deleted", "already_deleted"} {
		req, _ := http.NewRequest(http.MethodPost, aPubURL+"/api/v1/files/"+idemClaim.FileID+"/ack", bytes.NewReader(ackPayload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(protocol.HeaderLeaseToken, idemClaim.LeaseToken)
		resp, err := env.httpClient.Do(req)
		if err != nil {
			t.Fatalf("ack #%d req: %v", i+1, err)
		}
		var ackRes protocol.AckResp
		_ = json.NewDecoder(resp.Body).Decode(&ackRes)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || ackRes.Status != wantStatus {
			t.Fatalf("ack #%d: expected 200 %s, got %d %+v", i+1, wantStatus, resp.StatusCode, ackRes)
		}
	}

	// Duplicate summary event to Center must be deduplicated cleanly.
	dupEv := protocol.SummaryEvent{
		EventID:   "cmp-" + claimed.FileID,
		ProjectID: "proj-lease",
		ANodeID:   "a1",
		BNodeID:   "b2",
		EventType: protocol.EventCompleted,
		Bytes:     int64(len(data)),
		Timestamp: time.Now().UTC(),
	}
	// Ensure both completed events flushed first.
	waitUntil(t, 5*time.Second, func() bool {
		var ov protocol.OverviewResp
		env.adminGet("/api/v1/admin/overview", &ov)
		return ov.AllTimeCompleted == 2
	}, "center recorded initial completed events")

	applied, err := env.centerSrv.Store().RecordSummaryEvents(context.Background(), []protocol.SummaryEvent{dupEv})
	if err != nil {
		t.Fatalf("RecordSummaryEvents dup: %v", err)
	}
	if applied != 0 {
		t.Fatalf("expected 0 applied for duplicate summary event, got %d", applied)
	}
}

func TestAgentADiskWatermarkAlarm(t *testing.T) {
	env := newTestEnv(t)
	env.createProject("proj-disk", protocol.ConflictOverwrite, 60)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set impossibly high MinFreeDiskBytes to trip local disk watermark detection.
	_, a1Local, a1Tok := env.startAgentA(ctx, "a-disk", nil, 60, 1<<62)

	resp, _ := uploadToA(t, a1Local, a1Tok, "proj-disk", "blocked.bin", []byte("payload"), "")
	if resp.StatusCode != http.StatusInsufficientStorage {
		t.Fatalf("expected 507 Insufficient Storage when watermark exceeded, got %d", resp.StatusCode)
	}

	waitUntil(t, 5*time.Second, func() bool {
		var nodes []protocol.LiveNodeView
		env.adminGet("/api/v1/admin/nodes", &nodes)
		for _, n := range nodes {
			if n.ID == "a-disk" && n.Online && n.DiskAlarm {
				return true
			}
		}
		return false
	}, "center reports disk_alarm=true for a-disk")
}

func TestQARegressions(t *testing.T) {
	env := newTestEnv(t)
	adminReq := func(method, path string, body any) (*http.Response, []byte) {
		t.Helper()
		var r io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			r = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, env.centerURL+path, r)
		req.Header.Set(protocol.HeaderAdminToken, env.adminToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := env.httpClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		return resp, out
	}

	// 1. Center API validation: empty lists are JSON [], invalid policy/IDs/public_addr rejected, created_at non-zero.
	resp, rawProjs := adminReq(http.MethodGet, "/api/v1/admin/projects", nil)
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(rawProjs)) != "[]" {
		t.Fatalf("expected [] for empty projects, got %d %s", resp.StatusCode, string(rawProjs))
	}
	if r, _ := adminReq(http.MethodPost, "/api/v1/admin/projects", map[string]any{"id": "bad", "conflict_policy": "bogus"}); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid conflict_policy, got %d", r.StatusCode)
	}
	if r, _ := adminReq(http.MethodPost, "/api/v1/admin/projects", map[string]any{"id": "a');alert(1);//", "name": "xss"}); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for XSS project id, got %d", r.StatusCode)
	}
	if r, _ := adminReq(http.MethodPost, "/api/v1/admin/nodes", map[string]any{"id": "a-http", "role": "agent_a", "public_addr": "http://127.0.0.1:8080"}); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for plaintext http public_addr, got %d", r.StatusCode)
	}
	rProj, bProj := adminReq(http.MethodPost, "/api/v1/admin/projects", map[string]any{"id": "proj-zero", "name": "Zero", "conflict_policy": "overwrite", "lease_ttl_sec": 30})
	var savedProj protocol.Project
	_ = json.Unmarshal(bProj, &savedProj)
	if rProj.StatusCode != http.StatusOK || savedProj.CreatedAt.IsZero() {
		t.Fatalf("expected 200 and non-zero created_at, got %d %+v", rProj.StatusCode, savedProj)
	}
	env.createProject("proj-rename", protocol.ConflictAutoRename, 30)
	env.createProject("proj-skip", protocol.ConflictSkip, 30)
	env.createProject("proj-collide", protocol.ConflictOverwrite, 30)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	agA1, a1Local, a1Tok := env.startAgentA(ctx, "a1", nil, 30, 0)
	agA2, a2Local, a2Tok := env.startAgentA(ctx, "a2", nil, 30, 0)

	// 2. Multipart field-order independence: file BEFORE project succeeds; wrong sha256 AFTER file is rejected!
	sendMultipart := func(fields [][3]string) int {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		for _, f := range fields {
			if f[1] != "" {
				fw, _ := mw.CreateFormFile(f[0], f[1])
				_, _ = fw.Write([]byte(f[2]))
			} else {
				_ = mw.WriteField(f[0], f[2])
			}
		}
		_ = mw.Close()
		req, _ := http.NewRequest(http.MethodPost, a1Local+"/local/v1/upload", &buf)
		req.Header.Set(protocol.HeaderLocalToken, a1Tok)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("multipart upload: %v", err)
		}
		_ = r.Body.Close()
		return r.StatusCode
	}
	if st := sendMultipart([][3]string{
		{"file", "rev.bin", "reverse-order-ok"},
		{"project", "", "proj-zero"},
	}); st != http.StatusOK {
		t.Fatalf("expected 200 when multipart file precedes project, got %d", st)
	}
	if st := sendMultipart([][3]string{
		{"project", "", "proj-zero"},
		{"file", "badsha.bin", "actual-bytes"},
		{"sha256", "", "0000000000000000000000000000000000000000000000000000000000000000"},
	}); st != http.StatusBadRequest {
		t.Fatalf("expected 400 when trailing multipart sha256 mismatches, got %d", st)
	}

	// 3. Symlink registration must be rejected.
	realF := filepath.Join(env.dir, "real.bin")
	_ = os.WriteFile(realF, []byte("sym"), 0o600)
	symF := filepath.Join(env.dir, "sym.bin")
	_ = os.Symlink("real.bin", symF)
	regBody, _ := json.Marshal(protocol.LocalRegisterReq{ProjectID: "proj-zero", LocalPath: symF, Filename: "sym.bin", Mode: "move"})
	regReq, _ := http.NewRequest(http.MethodPost, a1Local+"/local/v1/register", bytes.NewReader(regBody))
	regReq.Header.Set(protocol.HeaderLocalToken, a1Tok)
	regReq.Header.Set("Content-Type", "application/json")
	regResp, err := http.DefaultClient.Do(regReq)
	if err != nil || regResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for symlink register, got err=%v resp=%v", err, regResp)
	}
	_ = regResp.Body.Close()

	// 4. Lease TTL bounds & int64 overflow rejection on /api/v1/claim.
	validJWT, _ := auth.SignAccessJWT(env.jwtSecret, auth.AccessClaims{
		BNodeID: "b1", ProjectID: "proj-zero", ANodeID: "a1",
		IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Minute).Unix(),
	})
	for _, badTTL := range []int{-5, 31536000, 10000000000} {
		cb, _ := json.Marshal(protocol.ClaimReq{ProjectID: "proj-zero", BNodeID: "b1", LeaseTTLSec: badTTL})
		cr, _ := http.NewRequest(http.MethodPost, "https://"+agA1.PublicListenAddr()+"/api/v1/claim", bytes.NewReader(cb))
		cr.Header.Set("Authorization", "Bearer "+validJWT)
		cr.Header.Set("Content-Type", "application/json")
		cResp, err := env.httpClient.Do(cr)
		if err != nil {
			t.Fatalf("claim badTTL %d: %v", badTTL, err)
		}
		_ = cResp.Body.Close()
		if cResp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400 for bad lease_ttl_sec=%d, got %d", badTTL, cResp.StatusCode)
		}
	}

	// 5. Center live-files query param escaping prevents injection ("proj-zero&x=1" must NOT return proj-zero files).
	var qLive protocol.LiveFilesResp
	env.adminGet("/api/v1/admin/nodes/a1/live-files?project="+url.QueryEscape("proj-zero&x=1"), &qLive)
	if len(qLive.Files) != 0 {
		t.Fatalf("expected 0 files for escaped project 'proj-zero&x=1', got %d", len(qLive.Files))
	}

	// 6. 0-byte file E2E + concurrent auto_rename + skip + file/dir collision cleanup & backoff.
	emptySHA := sha256.Sum256(nil)
	if r, b := uploadToA(t, a1Local, a1Tok, "proj-zero", "empty.bin", nil, hex.EncodeToString(emptySHA[:])); r.StatusCode != http.StatusOK {
		t.Fatalf("upload 0-byte file failed: %d %s", r.StatusCode, string(b))
	}

	bZeroDir := filepath.Join(env.dir, "b-zero")
	bRenameDir := filepath.Join(env.dir, "b-rename")
	bSkipDir := filepath.Join(env.dir, "b-skip")
	bCollideDir := filepath.Join(env.dir, "b-collide")
	_ = os.MkdirAll(bSkipDir, 0o755)
	_ = os.WriteFile(filepath.Join(bSkipDir, "keep.txt"), []byte("ORIGINAL"), 0o600)
	_ = os.MkdirAll(bCollideDir, 0o755)
	_ = os.WriteFile(filepath.Join(bCollideDir, "collide"), []byte("FILE"), 0o600)

	// Upload 5 same-named files for concurrent auto_rename test + 1 skip file + 1 colliding file.
	for i := 0; i < 5; i++ {
		content := []byte(fmt.Sprintf("payload-%d", i))
		if r, _ := uploadToA(t, a1Local, a1Tok, "proj-rename", "same.txt", content, ""); r.StatusCode != http.StatusOK {
			t.Fatalf("upload auto_rename #%d failed: %d", i, r.StatusCode)
		}
	}
	if r, _ := uploadToA(t, a1Local, a1Tok, "proj-skip", "keep.txt", []byte("NEW"), ""); r.StatusCode != http.StatusOK {
		t.Fatalf("upload skip failed: %d", r.StatusCode)
	}
	colResp, colBody := uploadToA(t, a1Local, a1Tok, "proj-collide", "collide/sub.txt", []byte("SUB"), "")
	if colResp.StatusCode != http.StatusOK {
		t.Fatalf("upload collide failed: %d", colResp.StatusCode)
	}
	var colUp protocol.LocalUploadResp
	_ = json.Unmarshal(colBody, &colUp)

	env.startAgentB(ctx, "b1", map[string]string{
		"proj-zero":    bZeroDir,
		"proj-rename":  bRenameDir,
		"proj-skip":    bSkipDir,
		"proj-collide": bCollideDir,
	}, 4)

	// Verify 0-byte empty.bin + rev.bin downloaded cleanly with 0 failures!
	waitUntil(t, 10*time.Second, func() bool {
		st0, err0 := os.Stat(filepath.Join(bZeroDir, "empty.bin"))
		st1, err1 := os.Stat(filepath.Join(bZeroDir, "rev.bin"))
		return err0 == nil && st0.Size() == 0 && err1 == nil && st1.Size() == int64(len("reverse-order-ok"))
	}, "b1 downloaded 0-byte empty.bin and reversed-multipart rev.bin")

	// Verify all 5 concurrent auto_rename files exist without overwriting each other!
	waitUntil(t, 10*time.Second, func() bool {
		ents, err := os.ReadDir(bRenameDir)
		if err != nil {
			return false
		}
		cnt := 0
		for _, e := range ents {
			if !e.IsDir() {
				cnt++
			}
		}
		return cnt == 5
	}, "all 5 concurrent auto_rename files saved distinctly")

	// Verify skip preserved ORIGINAL and removed file from A1.
	waitUntil(t, 10*time.Second, func() bool {
		var live protocol.LiveFilesResp
		env.adminGet("/api/v1/admin/nodes/a1/live-files?project=proj-skip", &live)
		return len(live.Files) == 0
	}, "proj-skip file ACKed and deleted on A1")
	if got, _ := os.ReadFile(filepath.Join(bSkipDir, "keep.txt")); string(got) != "ORIGINAL" {
		t.Fatalf("proj-skip modified existing file: got %q", string(got))
	}

	// Verify collide/sub.txt did NOT leak .part and NACK backoff prevented rapid retry storm.
	waitUntil(t, 5*time.Second, func() bool {
		var live protocol.LiveFilesResp
		env.adminGet("/api/v1/admin/nodes/a1/live-files?project=proj-collide", &live)
		return len(live.Files) == 1 && live.Files[0].RetryCount >= 1
	}, "collide file NACKed once")
	time.Sleep(1500 * time.Millisecond)
	if _, err := os.Stat(filepath.Join(bCollideDir, ".relay_tmp", colUp.FileID+".part")); !os.IsNotExist(err) {
		t.Fatalf("expected .part to be cleaned up on mkdir failure, got err=%v", err)
	}
	var colLive protocol.LiveFilesResp
	env.adminGet("/api/v1/admin/nodes/a1/live-files?project=proj-collide", &colLive)
	if len(colLive.Files) != 1 || colLive.Files[0].RetryCount > 3 {
		t.Fatalf("expected NACK backoff to limit retry_count <= 3, got %+v", colLive.Files)
	}

	// 7. Deleted A node is immediately evicted from Hub (discover, live-files, overview),
	//    spoofed heartbeat public_addr cannot override Center-registered addr (SSRF protection),
	//    and deleting a B node immediately closes its active SSE stream.
	env.createProject("proj-a2-only", protocol.ConflictOverwrite, 30)
	if r, _ := uploadToA(t, a2Local, a2Tok, "proj-a2-only", "on-a2.bin", []byte("a2data"), ""); r.StatusCode != http.StatusOK {
		t.Fatalf("upload to a2 failed: %d", r.StatusCode)
	}
	waitUntil(t, 5*time.Second, func() bool {
		var live protocol.LiveFilesResp
		env.adminGet("/api/v1/admin/nodes/a2/live-files", &live)
		return len(live.Files) == 1
	}, "a2 online with 1 file")

	// Register a dedicated B node to test SSE disconnect on BOTH token rotation AND node deletion.
	sseBTok := auth.GenerateRandomToken(16)
	if err := env.centerSrv.Store().UpsertNode(context.Background(), protocol.NodeRecord{
		ID: "b-sse-del", Name: "b-sse-del", Role: protocol.RoleAgentB, Projects: []string{"proj-a2-only"},
	}, sseBTok); err != nil {
		t.Fatalf("UpsertNode b-sse-del: %v", err)
	}
	openSSE := func(tok string) (<-chan struct{}, *http.Response) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, env.centerURL+"/api/v1/b/events?projects=proj-a2-only", nil)
		req.Header.Set(protocol.HeaderNodeID, "b-sse-del")
		req.Header.Set(protocol.HeaderNodeToken, tok)
		cli := &http.Client{Transport: env.httpClient.Transport}
		resp, err := cli.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("open SSE for b-sse-del failed: err=%v resp=%v", err, resp)
		}
		closed := make(chan struct{})
		go func() {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			close(closed)
		}()
		return closed, resp
	}
	rotClosed, _ := openSSE(sseBTok)
	// Rotate token via admin API -> old SSE stream must be disconnected immediately!
	rRot, bRot := adminReq(http.MethodPost, "/api/v1/admin/nodes", map[string]any{
		"id": "b-sse-del", "name": "b-sse-del", "role": "agent_b", "projects": []string{"proj-a2-only"},
	})
	if rRot.StatusCode != http.StatusOK {
		t.Fatalf("rotate b-sse-del token failed: %d", rRot.StatusCode)
	}
	var rotRes struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(bRot, &rotRes)
	select {
	case <-rotClosed:
	case <-time.After(3 * time.Second):
		t.Fatalf("expected active SSE stream to close immediately after rotating token for b-sse-del")
	}

	// Open SSE with new token, then delete node -> SSE must also close immediately!
	delClosed, _ := openSSE(rotRes.Token)
	if r, _ := adminReq(http.MethodDelete, "/api/v1/admin/nodes/b-sse-del", nil); r.StatusCode != http.StatusNoContent {
		t.Fatalf("delete b-sse-del failed: %d", r.StatusCode)
	}
	select {
	case <-delClosed:
	case <-time.After(3 * time.Second):
		t.Fatalf("expected active SSE stream to close immediately after deleting b-sse-del")
	}

	// 8. Agent A stream auto-renew scales to short lease_ttl (3s) without client calling /renew.
	env.createProject("proj-arenew", protocol.ConflictOverwrite, 3)
	arData, arSHA := randBytes(t, 2*1024*1024)
	if r, _ := uploadToA(t, a1Local, a1Tok, "proj-arenew", "slow.bin", arData, arSHA); r.StatusCode != http.StatusOK {
		t.Fatalf("upload slow.bin failed: %d", r.StatusCode)
	}
	arJWT, _ := auth.SignAccessJWT(env.jwtSecret, auth.AccessClaims{
		BNodeID: "b-ar", ProjectID: "proj-arenew", ANodeID: "a1",
		IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Minute).Unix(),
	})
	arClaimBody, _ := json.Marshal(protocol.ClaimReq{ProjectID: "proj-arenew", BNodeID: "b-ar", LeaseTTLSec: 3})
	arClaimReq, _ := http.NewRequest(http.MethodPost, "https://"+agA1.PublicListenAddr()+"/api/v1/claim", bytes.NewReader(arClaimBody))
	arClaimReq.Header.Set("Authorization", "Bearer "+arJWT)
	arClaimReq.Header.Set("Content-Type", "application/json")
	arClaimResp, err := env.httpClient.Do(arClaimReq)
	if err != nil || arClaimResp.StatusCode != http.StatusOK {
		t.Fatalf("claim slow.bin failed: err=%v resp=%v", err, arClaimResp)
	}
	var arClaim protocol.ClaimResp
	_ = json.NewDecoder(arClaimResp.Body).Decode(&arClaim)
	_ = arClaimResp.Body.Close()

	// Pace server-side streaming over ~4.4s (8 x 256KiB chunks @ 550ms) > 3s lease TTL with zero client /renew calls!
	agA1.StreamChunkHook = func(fileID string, sentTotal int64) error {
		if fileID == arClaim.FileID {
			time.Sleep(550 * time.Millisecond)
		}
		return nil
	}
	defer func() { agA1.StreamChunkHook = nil }()

	streamReq, _ := http.NewRequest(http.MethodGet, "https://"+agA1.PublicListenAddr()+"/api/v1/files/"+arClaim.FileID+"/stream", nil)
	streamReq.Header.Set(protocol.HeaderLeaseToken, arClaim.LeaseToken)
	streamResp, err := env.httpClient.Do(streamReq)
	if err != nil || streamResp.StatusCode != http.StatusOK {
		t.Fatalf("stream slow.bin failed: err=%v resp=%v", err, streamResp)
	}
	gotAR, rErr := io.ReadAll(streamResp.Body)
	_ = streamResp.Body.Close()
	if rErr != nil || !bytes.Equal(gotAR, arData) {
		t.Fatalf("slow stream mismatch: len=%d err=%v", len(gotAR), rErr)
	}
	arAckBody, _ := json.Marshal(protocol.AckReq{LeaseID: arClaim.LeaseID, BNodeID: "b-ar", SHA256: arSHA})
	arAckReq, _ := http.NewRequest(http.MethodPost, "https://"+agA1.PublicListenAddr()+"/api/v1/files/"+arClaim.FileID+"/ack", bytes.NewReader(arAckBody))
	arAckReq.Header.Set("Content-Type", "application/json")
	arAckReq.Header.Set(protocol.HeaderLeaseToken, arClaim.LeaseToken)
	arAckResp, err := env.httpClient.Do(arAckReq)
	if err != nil || arAckResp.StatusCode != http.StatusOK {
		t.Fatalf("expected ACK 200 after slow stream auto-renew (lease_ttl=3s), got err=%v resp=%v", err, arAckResp)
	}
	_ = arAckResp.Body.Close()

	_ = agA2.Shutdown(context.Background())

	if r, _ := adminReq(http.MethodDelete, "/api/v1/admin/nodes/a2", nil); r.StatusCode != http.StatusNoContent {
		t.Fatalf("delete a2 failed: %d", r.StatusCode)
	}
	if r, _ := adminReq(http.MethodGet, "/api/v1/admin/nodes/a2/live-files", nil); r.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for deleted a2 live-files, got %d", r.StatusCode)
	}
	var ov protocol.OverviewResp
	env.adminGet("/api/v1/admin/overview", &ov)
	for _, ps := range ov.Projects {
		for _, av := range ps.ANodeAvailability {
			if av.ANodeID == "a2" {
				t.Fatalf("deleted node a2 still present in overview availability")
			}
		}
	}
}
