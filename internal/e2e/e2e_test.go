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
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
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
	cfg := &center.Config{
		Listen:         fmt.Sprintf("127.0.0.1:%d", cPort),
		TLSCert:        cCert,
		TLSKey:         cKey,
		CACert:         caCert,
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

	// Duplicate ACK to A1 must return 200 OK {"status":"already_deleted"}.
	dupAckBody, _ := json.Marshal(protocol.AckReq{
		LeaseID: claimed.LeaseID,
		BNodeID: "b2",
		SHA256:  sha,
	})
	dupReq, _ := http.NewRequest(http.MethodPost, aPubURL+"/api/v1/files/"+claimed.FileID+"/ack", bytes.NewReader(dupAckBody))
	dupReq.Header.Set("Content-Type", "application/json")
	dupResp, err := env.httpClient.Do(dupReq)
	if err != nil {
		t.Fatalf("dup ack req: %v", err)
	}
	var ackRes protocol.AckResp
	_ = json.NewDecoder(dupResp.Body).Decode(&ackRes)
	_ = dupResp.Body.Close()
	if dupResp.StatusCode != http.StatusOK || ackRes.Status != "already_deleted" {
		t.Fatalf("expected 200 already_deleted on duplicate ack, got %d %+v", dupResp.StatusCode, ackRes)
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
	// Ensure first event flushed first.
	waitUntil(t, 5*time.Second, func() bool {
		var ov protocol.OverviewResp
		env.adminGet("/api/v1/admin/overview", &ov)
		return ov.AllTimeCompleted == 1
	}, "center recorded initial completed event")

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
