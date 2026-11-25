package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"relay-download/internal/agenta"
	"relay-download/internal/agentb"
	"relay-download/internal/auth"
	"relay-download/internal/pki"
	"relay-download/internal/protocol"
)

func TestHTTPPutBatchClaimBatchAckDelayedDeleteAndMultiDiskAffinity(t *testing.T) {
	env := newTestEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const (
		projMain   = "delivery-01a20649"
		projPaused = "paused-unlanded"
	)
	env.createProject(projMain, protocol.ConflictOverwrite, 60)
	env.createProject(projPaused, protocol.ConflictOverwrite, 60)

	// Issue TLS cert & register Agent A with 1s delayed batched spool cleanup enabled.
	certDir := filepath.Join(env.dir, "certs")
	aCert := filepath.Join(certDir, "a-fast.crt")
	aKey := filepath.Join(certDir, "a-fast.key")
	if err := pki.IssueCert(env.caCert, env.caKey, aCert, aKey, "a-fast", []string{"127.0.0.1"}, nil, 365); err != nil {
		t.Fatalf("IssueCert a-fast: %v", err)
	}
	localPort := freePort(t)
	pubPort := freePort(t)
	aPubURL := fmt.Sprintf("https://127.0.0.1:%d", pubPort)
	aLocalURL := fmt.Sprintf("http://127.0.0.1:%d", localPort)
	aTok := auth.GenerateRandomToken(16)
	if err := env.centerSrv.Store().UpsertNode(ctx, protocol.NodeRecord{
		ID:         "a-fast",
		Name:       "Fast A",
		Role:       protocol.RoleAgentA,
		PublicAddr: aPubURL,
	}, aTok); err != nil {
		t.Fatalf("UpsertNode a-fast: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	aCfg := &agenta.Config{
		NodeID:                 "a-fast",
		NodeName:               "Fast A",
		PublicAddr:             aPubURL,
		CenterURL:              env.centerURL,
		CenterToken:            aTok,
		JWTSecret:              env.jwtSecret,
		CenterSecret:           env.centerSecret,
		LocalListen:            fmt.Sprintf("127.0.0.1:%d", localPort),
		LocalToken:             "local-put-token",
		PublicListen:           fmt.Sprintf("127.0.0.1:%d", pubPort),
		TLSCert:                aCert,
		TLSKey:                 aKey,
		CACert:                 env.caCert,
		DataDir:                filepath.Join(env.dir, "data-a-fast"),
		MaxDiskUsagePct:        99.0,
		LeaseTTLSec:            60,
		MaxConcurrentStreams:   16,
		HeartbeatIntervalSec:   1,
		DeleteBatchIntervalSec: 1,
		DeleteBatchSize:        100,
	}
	agA, err := agenta.New(aCfg, logger)
	if err != nil {
		t.Fatalf("new agent-a: %v", err)
	}
	aDone := make(chan error, 1)
	go func() { aDone <- agA.Start(ctx) }()
	defer func() {
		cancel()
		<-aDone
	}()

	// Register and start Agent B with 2 simulated disks (/mnt/sda & /mnt/sdb), multi-conn HTTP/2 pool, and batched ACK.
	bTok := auth.GenerateRandomToken(16)
	if err := env.centerSrv.Store().UpsertNode(ctx, protocol.NodeRecord{
		ID:       "b-fast",
		Name:     "Fast B",
		Role:     protocol.RoleAgentB,
		Projects: []string{projMain},
	}, bTok); err != nil {
		t.Fatalf("UpsertNode b-fast: %v", err)
	}
	disk1 := filepath.Join(env.dir, "disk-sda", projMain)
	disk2 := filepath.Join(env.dir, "disk-sdb", projMain)
	bCfg := &agentb.Config{
		NodeID:               "b-fast",
		NodeName:             "Fast B",
		CenterURL:            env.centerURL,
		CenterToken:          bTok,
		CACert:               env.caCert,
		ProjectDirs:          map[string][]string{projMain: {disk1, disk2}},
		StateDir:             filepath.Join(env.dir, "state-b-fast"),
		MaxConcurrent:        8,
		StreamConns:          8,
		ChunkConcurrency:     4,
		ChunkSizeMB:          1,
		ChunkThresholdMB:     1,
		ClaimBatchSize:       8,
		AckBatchIntervalMs:   300,
		AckBatchSize:         10,
		PollIntervalSec:      1,
		HeartbeatIntervalSec: 1,
	}
	agB, err := agentb.New(bCfg, logger)
	if err != nil {
		t.Fatalf("new agent-b: %v", err)
	}
	bDone := make(chan error, 1)
	go func() { bDone <- agB.Start(ctx) }()
	defer func() {
		cancel()
		<-bDone
	}()

	// Wait for both A and B to come online.
	waitUntil(t, 8*time.Second, func() bool {
		req, _ := http.NewRequest(http.MethodGet, env.centerURL+"/api/v1/admin/overview", nil)
		req.Header.Set(protocol.HeaderAdminToken, env.adminToken)
		resp, err := env.httpClient.Do(req)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		var ov protocol.OverviewResp
		if err := json.NewDecoder(resp.Body).Decode(&ov); err != nil {
			return false
		}
		return ov.OnlineANodes >= 1 && ov.OnlineBNodes >= 1
	}, "a-fast and b-fast online")

	// 1. Push 12 paired video assets (24 files, including leading '---' YouTube IDs) via HTTP PUT!
	expected := make(map[string]string) // filename -> sha256
	videoIDs := []string{
		"---an6lH3gc", "--0_Hqq8260", "--29kZ5pPs4", "--2HSeR_gW8",
		"--5eLH0dCW8", "abc12345678", "def87654321", "ghi_0001112",
		"jkl-9998887", "mno_5554443", "pqr_2223334", "stu_7776665",
	}
	plainHTTP := &http.Client{Timeout: 10 * time.Second}
	for i, vid := range videoIDs {
		mediaExt := ".opus"
		if i%3 == 1 {
			mediaExt = ".m4a"
		} else if i%3 == 2 {
			mediaExt = ".webm"
		}
		files := map[string][]byte{
			vid + mediaExt:     bytes.Repeat([]byte(fmt.Sprintf("media-%02d-%s|", i, vid)), 65536),
			vid + ".info.json": []byte(fmt.Sprintf(`{"id":%q,"index":%d}`, vid, i)),
		}
		for fname, data := range files {
			sum := sha256.Sum256(data)
			sumHex := hex.EncodeToString(sum[:])
			expected[fname] = sumHex

			var req *http.Request
			if i == 0 && fname == vid+".info.json" {
				// Also exercise PUT /local/v1/upload with headers.
				req, err = http.NewRequest(http.MethodPut, aLocalURL+"/local/v1/upload", bytes.NewReader(data))
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set(protocol.HeaderProject, projMain)
				req.Header.Set(protocol.HeaderFilename, fname)
			} else {
				req, err = http.NewRequest(http.MethodPut, aLocalURL+"/local/v1/files/"+url.PathEscape(projMain)+"/"+url.PathEscape(fname), bytes.NewReader(data))
				if err != nil {
					t.Fatal(err)
				}
			}
			req.Header.Set(protocol.HeaderLocalToken, "local-put-token")
			req.Header.Set(protocol.HeaderExpectedSHA256, sumHex)
			resp, err := plainHTTP.Do(req)
			if err != nil {
				t.Fatalf("PUT %s failed: %v", fname, err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("PUT %s returned HTTP %d", fname, resp.StatusCode)
			}
		}
	}

	// 2. Also test POST /local/v1/register-batch with 4 local files.
	srcDir := filepath.Join(env.dir, "batch-src")
	_ = os.MkdirAll(srcDir, 0o755)
	var regItems []protocol.LocalRegisterReq
	for i := 0; i < 4; i++ {
		fname := fmt.Sprintf("batchreg_%02d.opus", i)
		data := bytes.Repeat([]byte(fmt.Sprintf("batch-reg-%d", i)), 1024)
		sum := sha256.Sum256(data)
		sumHex := hex.EncodeToString(sum[:])
		p := filepath.Join(srcDir, fname)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		expected[fname] = sumHex
		regItems = append(regItems, protocol.LocalRegisterReq{
			ProjectID:      projMain,
			LocalPath:      p,
			Filename:       fname,
			ExpectedSHA256: sumHex,
			Mode:           "move",
		})
	}
	regBody, _ := json.Marshal(protocol.LocalRegisterBatchReq{Items: regItems})
	regReq, _ := http.NewRequest(http.MethodPost, aLocalURL+"/local/v1/register-batch", bytes.NewReader(regBody))
	regReq.Header.Set(protocol.HeaderLocalToken, "local-put-token")
	regReq.Header.Set("Content-Type", "application/json")
	regResp, err := plainHTTP.Do(regReq)
	if err != nil || regResp.StatusCode != http.StatusOK {
		t.Fatalf("register-batch failed: err=%v resp=%v", err, regResp)
	}
	_ = regResp.Body.Close()

	// 3. Upload 1 file into projPaused (NO Agent B consuming it!) to verify "没落盘的不准删".
	unlandedData := []byte("must-never-be-deleted-before-landing-on-b")
	unlandedSum := sha256.Sum256(unlandedData)
	unlandedSHA := hex.EncodeToString(unlandedSum[:])
	putUnlanded, _ := http.NewRequest(http.MethodPut, aLocalURL+"/local/v1/files/"+projPaused+"/keep_safe.opus", bytes.NewReader(unlandedData))
	putUnlanded.Header.Set(protocol.HeaderLocalToken, "local-put-token")
	respU, err := plainHTTP.Do(putUnlanded)
	if err != nil || respU.StatusCode != http.StatusOK {
		t.Fatalf("PUT unlanded failed: err=%v resp=%v", err, respU)
	}
	var unlandedResp protocol.LocalUploadResp
	_ = json.NewDecoder(respU.Body).Decode(&unlandedResp)
	_ = respU.Body.Close()

	// Wait until all 28 files for projMain have landed across disk1 + disk2 AND Agent A's delayed deleter unlinked them.
	waitUntil(t, 15*time.Second, func() bool {
		found := 0
		for fname := range expected {
			if _, err := os.Stat(filepath.Join(disk1, fname)); err == nil {
				found++
				continue
			}
			if _, err := os.Stat(filepath.Join(disk2, fname)); err == nil {
				found++
			}
		}
		if found != len(expected) {
			return false
		}
		entries, _ := os.ReadDir(filepath.Join(env.dir, "data-a-fast", "ready"))
		return len(entries) == 1
	}, "all 28 files landed on dual disks and Agent A drained projMain spool")

	// Verify permissions on landed files are readable (0644) and SHA256 matches.
	disk1Count, disk2Count := 0, 0
	fileDisk := make(map[string]int)
	for fname, wantSHA := range expected {
		p1 := filepath.Join(disk1, fname)
		p2 := filepath.Join(disk2, fname)
		var path string
		if _, err := os.Stat(p1); err == nil {
			path = p1
			disk1Count++
			fileDisk[fname] = 1
		} else if _, err := os.Stat(p2); err == nil {
			path = p2
			disk2Count++
			fileDisk[fname] = 2
		} else {
			t.Fatalf("missing landed file %s on both disks", fname)
		}
		if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o044 != 0o044 {
			t.Fatalf("expected readable 0644 permissions on %s, got %o", path, fi.Mode().Perm())
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		got := sha256.Sum256(raw)
		if hex.EncodeToString(got[:]) != wantSHA {
			t.Fatalf("sha256 mismatch for %s", fname)
		}
	}
	if disk1Count == 0 || disk2Count == 0 {
		t.Fatalf("expected balanced multi-disk placement across both disks, got disk1=%d disk2=%d", disk1Count, disk2Count)
	}
	for i, vid := range videoIDs {
		mediaExt := ".opus"
		if i%3 == 1 {
			mediaExt = ".m4a"
		} else if i%3 == 2 {
			mediaExt = ".webm"
		}
		if fileDisk[vid+mediaExt] != fileDisk[vid+".info.json"] {
			t.Fatalf("pair affinity broken for %s: media on disk %d, info.json on disk %d",
				vid, fileDisk[vid+mediaExt], fileDisk[vid+".info.json"])
		}
	}

	// Verify /local/v1/status?summary=1 reports exactly 1 file (the unlanded one).
	stReq, _ := http.NewRequest(http.MethodGet, aLocalURL+"/local/v1/status?summary=1", nil)
	stReq.Header.Set(protocol.HeaderLocalToken, "local-put-token")
	stResp, err := plainHTTP.Do(stReq)
	if err != nil || stResp.StatusCode != http.StatusOK {
		t.Fatalf("status summary failed: err=%v resp=%v", err, stResp)
	}
	var stOut protocol.LiveFilesResp
	_ = json.NewDecoder(stResp.Body).Decode(&stOut)
	_ = stResp.Body.Close()
	if stOut.TotalFiles != 1 || stOut.ReadyCount != 1 {
		t.Fatalf("expected 1 unlanded READY file in summary, got %+v", stOut)
	}

	// Verify IRONCLAD "没落盘的不准删": forged / wrong-SHA256 batch-ack MUST NOT delete unlanded file!
	bFakeTok := auth.GenerateRandomToken(16)
	if err := env.centerSrv.Store().UpsertNode(ctx, protocol.NodeRecord{
		ID:       "b-paused",
		Name:     "Paused B",
		Role:     protocol.RoleAgentB,
		Projects: []string{projPaused},
	}, bFakeTok); err != nil {
		t.Fatalf("UpsertNode b-paused: %v", err)
	}
	discReq, _ := http.NewRequest(http.MethodGet, env.centerURL+"/api/v1/b/discover?project="+projPaused, nil)
	discReq.Header.Set(protocol.HeaderNodeID, "b-paused")
	discReq.Header.Set(protocol.HeaderNodeToken, bFakeTok)
	discResp, err := env.httpClient.Do(discReq)
	if err != nil || discResp.StatusCode != http.StatusOK {
		t.Fatalf("discover projPaused failed: err=%v resp=%v", err, discResp)
	}
	var disc protocol.DiscoverResp
	_ = json.NewDecoder(discResp.Body).Decode(&disc)
	_ = discResp.Body.Close()
	if len(disc.Candidates) != 1 {
		t.Fatalf("expected 1 candidate for projPaused, got %d", len(disc.Candidates))
	}

	cbBody, _ := json.Marshal(protocol.ClaimBatchReq{
		ProjectID: projPaused,
		BNodeID:   "b-paused",
		MaxCount:  4,
	})
	cbReq, _ := http.NewRequest(http.MethodPost, aPubURL+"/api/v1/claim-batch", bytes.NewReader(cbBody))
	cbReq.Header.Set("Content-Type", "application/json")
	cbReq.Header.Set("Authorization", "Bearer "+disc.Candidates[0].AccessJWT)
	cbResp, err := env.httpClient.Do(cbReq)
	if err != nil || cbResp.StatusCode != http.StatusOK {
		t.Fatalf("claim-batch projPaused failed: err=%v resp=%v", err, cbResp)
	}
	var cbOut protocol.ClaimBatchResp
	_ = json.NewDecoder(cbResp.Body).Decode(&cbOut)
	_ = cbResp.Body.Close()
	if len(cbOut.Items) != 1 || cbOut.Items[0].FileID != unlandedResp.FileID {
		t.Fatalf("unexpected claim-batch result: %+v", cbOut.Items)
	}

	// Send batch-ack with WRONG sha256 -> MUST reject and NEVER delete the file on disk!
	badAckBody, _ := json.Marshal(protocol.BatchAckReq{
		BNodeID: "b-paused",
		Items: []protocol.BatchAckItem{{
			FileID:     cbOut.Items[0].FileID,
			LeaseID:    cbOut.Items[0].LeaseID,
			LeaseToken: cbOut.Items[0].LeaseToken,
			SHA256:     "0000000000000000000000000000000000000000000000000000000000000000",
		}},
	})
	badAckReq, _ := http.NewRequest(http.MethodPost, aPubURL+"/api/v1/files/batch-ack", bytes.NewReader(badAckBody))
	badAckReq.Header.Set("Content-Type", "application/json")
	badAckResp, err := env.httpClient.Do(badAckReq)
	if err != nil || badAckResp.StatusCode != http.StatusOK {
		t.Fatalf("bad batch-ack HTTP error: err=%v resp=%v", err, badAckResp)
	}
	var badAckOut protocol.BatchAckResp
	_ = json.NewDecoder(badAckResp.Body).Decode(&badAckOut)
	_ = badAckResp.Body.Close()
	if len(badAckOut.Results) != 1 || badAckOut.Results[0].Status != "checksum_failed" {
		t.Fatalf("expected checksum_failed, got %+v", badAckOut.Results)
	}

	// Wait >1.5s past a full delete-batch tick and verify the unlanded .dat file STILL exists on Agent A disk!
	time.Sleep(1500 * time.Millisecond)
	unlandedPath := filepath.Join(env.dir, "data-a-fast", "ready", unlandedResp.FileID+".dat")
	if raw, err := os.ReadFile(unlandedPath); err != nil {
		t.Fatalf("SAFETY VIOLATION: unlanded file was deleted from Agent A! err=%v", err)
	} else {
		got := sha256.Sum256(raw)
		if hex.EncodeToString(got[:]) != unlandedSHA {
			t.Fatalf("unlanded file corrupted")
		}
	}
}

func Test10GbpsH1StreamProtocolAndPipelinedChunkedHash(t *testing.T) {
	env := newTestEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const proj = "ten-gbps-proj"
	env.createProject(proj, protocol.ConflictOverwrite, 60)

	agA, aLocalURL, aLocalTok := env.startAgentA(ctx, "a-10g", []string{proj}, 60, 0)
	_ = agA

	bTok := auth.GenerateRandomToken(16)
	if err := env.centerSrv.Store().UpsertNode(ctx, protocol.NodeRecord{
		ID:       "b-10g",
		Name:     "10G B",
		Role:     protocol.RoleAgentB,
		Projects: []string{proj},
	}, bTok); err != nil {
		t.Fatalf("UpsertNode b-10g: %v", err)
	}
	destDir := filepath.Join(env.dir, "dest-10g")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agB, err := agentb.New(&agentb.Config{
		NodeID:               "b-10g",
		NodeName:             "10G B",
		CenterURL:            env.centerURL,
		CenterToken:          bTok,
		CACert:               env.caCert,
		Projects:             map[string]string{proj: destDir},
		StateDir:             filepath.Join(env.dir, "state-10g"),
		MaxConcurrent:        4,
		StreamProtocol:       "h1",
		StreamConns:          16,
		MaxTotalStreams:      32,
		ChunkConcurrency:     6,
		ChunkSizeMB:          1,
		ChunkThresholdMB:     2,
		ClaimBatchSize:       8,
		AckBatchIntervalMs:   150,
		PollIntervalSec:      1,
		HeartbeatIntervalSec: 1,
	}, logger)
	if err != nil {
		t.Fatalf("new agent-b h1: %v", err)
	}
	bDone := make(chan error, 1)
	go func() { bDone <- agB.Start(ctx) }()
	defer func() {
		cancel()
		<-bDone
	}()

	// Upload a 6.5 MiB file via HTTP PUT (triggers 7 parallel 1 MiB range chunks + pipelined prefix SHA256 over TLS 1.3 H1!).
	payload, wantSHA := randBytes(t, (6<<20)+(512<<10))
	req, err := http.NewRequest(http.MethodPut, aLocalURL+"/local/v1/files/"+proj+"/large_asset.opus", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(protocol.HeaderLocalToken, aLocalTok)
	req.Header.Set(protocol.HeaderExpectedSHA256, wantSHA)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT large_asset.opus failed: err=%v resp=%v", err, resp)
	}
	_ = resp.Body.Close()

	target := filepath.Join(destDir, "large_asset.opus")
	waitUntil(t, 15*time.Second, func() bool {
		st, err := os.Stat(target)
		return err == nil && st.Size() == int64(len(payload))
	}, "6.5MiB chunked TLS 1.3 H1 file landed")

	gotBytes, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	gotSum := sha256.Sum256(gotBytes)
	if hex.EncodeToString(gotSum[:]) != wantSHA {
		t.Fatalf("SHA256 mismatch on pipelined H1 chunked download")
	}
	// Verify Agent A drained its ready dir cleanly after batch ACK.
	waitUntil(t, 10*time.Second, func() bool {
		entries, _ := os.ReadDir(filepath.Join(env.dir, "data-a-10g", "ready"))
		return len(entries) == 0
	}, "a-10g drained spool after H1 chunked ACK")
}
