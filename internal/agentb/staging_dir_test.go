package agentb

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
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"relay-download/internal/pki"
	"relay-download/internal/protocol"
)

func TestStagingDirRootLevelAndLegacyCompatibility(t *testing.T) {
	// 1. Storage pool mode: .relay_tmp must live at <storage_root>/.relay_tmp/<project_id>,
	// NOT inside <storage_root>/<project_id>/.relay_tmp, keeping projects isolated and unaffected
	// when a project directory is externally removed/moved.
	ag, poolRoot := newTestAgentBForIsolation(t)
	projA := "proj-alpha"
	projB := "proj-beta"
	projADir := filepath.Join(poolRoot, projA)
	projBDir := filepath.Join(poolRoot, projB)

	wantStagingA := filepath.Join(poolRoot, ".relay_tmp", projA)
	wantStagingB := filepath.Join(poolRoot, ".relay_tmp", projB)
	if got := ag.stagingDirFor(projADir, projA); got != wantStagingA {
		t.Fatalf("storage pool stagingDir(A) = %q, want %q", got, wantStagingA)
	}
	if got := ag.stagingDirFor(projBDir, projB); got != wantStagingB {
		t.Fatalf("storage pool stagingDir(B) = %q, want %q", got, wantStagingB)
	}
	if err := ag.ensureDestDirReady(projADir, projA); err != nil {
		t.Fatalf("ensureDestDirReady(A): %v", err)
	}
	if err := ag.ensureDestDirReady(projBDir, projB); err != nil {
		t.Fatalf("ensureDestDirReady(B): %v", err)
	}
	for _, want := range []string{wantStagingA, wantStagingB} {
		if st, err := os.Stat(want); err != nil || !st.IsDir() {
			t.Fatalf("expected per-project root .relay_tmp dir at %q, err=%v", want, err)
		}
	}
	if _, err := os.Stat(filepath.Join(projADir, ".relay_tmp")); !os.IsNotExist(err) {
		t.Fatalf("expected NO project-level .relay_tmp dir inside %q, err=%v", projADir, err)
	}

	// 2. Legacy static project-mapping mode (no storage_dirs): staging dir remains <proj_dir>/.relay_tmp.
	dir := t.TempDir()
	caCert := filepath.Join(dir, "ca.crt")
	caKey := filepath.Join(dir, "ca.key")
	if err := pki.InitCA(caCert, caKey, "agentb-legacy-ca", 365); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	legacyProjDir := filepath.Join(dir, "legacy-proj")
	legacyCfg := &Config{
		NodeID:          "b-legacy",
		CenterURL:       "https://127.0.0.1:1",
		CenterToken:     "tok-b",
		CACert:          caCert,
		StateDir:        filepath.Join(dir, "state"),
		Projects:        map[string]string{"p1": legacyProjDir},
		MaxConcurrent:   2,
		MaxDiskUsagePct: 99,
	}
	legacyAg, err := New(legacyCfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("legacy agentb.New: %v", err)
	}
	t.Cleanup(func() { _ = legacyAg.store.Close() })

	wantLegacy := filepath.Join(legacyProjDir, ".relay_tmp")
	if got := legacyAg.stagingDirFor(legacyProjDir, "p1"); got != wantLegacy {
		t.Fatalf("legacy stagingDir = %q, want %q", got, wantLegacy)
	}
	if st, err := os.Stat(wantLegacy); err != nil || !st.IsDir() {
		t.Fatalf("expected legacy .relay_tmp dir at %q, err=%v", wantLegacy, err)
	}
}

func TestMidDownloadProjectDirDeletionDoesNotFailCommit(t *testing.T) {
	ag, poolRoot := newTestAgentBForIsolation(t)

	// 256 KiB payload split into two halves across a synchronization gate.
	payload := bytes.Repeat([]byte("relay-root-staging-test-payload-0123456789ABCDEF"), 5*1024)
	sum := sha256.Sum256(payload)
	wantSHA := hex.EncodeToString(sum[:])

	half := len(payload) / 2
	firstHalfSent := make(chan struct{})
	resumeStream := make(chan struct{})

	var ackCount, nackCount atomic.Int32
	var ackedSHA atomic.Value

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/stream"):
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(payload)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(payload[:half])
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			close(firstHalfSent)
			<-resumeStream
			_, _ = w.Write(payload[half:])
		case strings.HasSuffix(r.URL.Path, "/ack"):
			var req protocol.AckReq
			_ = json.NewDecoder(r.Body).Decode(&req)
			ackedSHA.Store(req.SHA256)
			ackCount.Add(1)
			protocol.WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
		case strings.HasSuffix(r.URL.Path, "/nack"):
			nackCount.Add(1)
			protocol.WriteJSON(w, http.StatusOK, map[string]string{"status": "requeued"})
		case strings.HasSuffix(r.URL.Path, "/renew"):
			protocol.WriteJSON(w, http.StatusOK, protocol.RenewResp{LeaseExpiresAt: time.Now().Add(5 * time.Minute)})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	ag.streamClients = []*http.Client{srv.Client()}
	ag.apiClient = srv.Client()

	projID := "01a21a9e-341e-709e-9114-2a6db6ea93c0"
	projDir := filepath.Join(poolRoot, projID)
	// Simulate existing project directory with previously delivered files that customer will move/delete.
	if err := os.MkdirAll(projDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projDir, "earlier.mp4"), []byte("already-copied"), 0o644); err != nil {
		t.Fatal(err)
	}

	fileID := "f-mid-delete-1"
	partPath := filepath.Join(ag.stagingDirFor(projDir, projID), fileID+".part")
	dl := ActiveDownload{
		FileID:         fileID,
		ProjectID:      projID,
		ANodeID:        "a-test",
		PublicAddr:     srv.URL,
		Filename:       "big_video.mp4",
		Size:           int64(len(payload)),
		SHA256:         wantSHA,
		LeaseID:        "lease-1",
		LeaseToken:     "ltok-1",
		LeaseExpiresAt: time.Now().Add(5 * time.Minute),
		LeaseTTLSec:    300,
		ConflictPolicy: protocol.ConflictOverwrite,
		DestDir:        projDir,
		PartPath:       partPath,
	}
	if err := ag.store.PutActive(dl); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		ag.runDownload(context.Background(), dl)
	}()

	// Wait until the first half has been streamed and .part is actively written under <poolRoot>/.relay_tmp/.
	select {
	case <-firstHalfSent:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for stream start")
	}

	// Wait briefly for agent-b to create & write to the root-level .part file.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := os.Stat(partPath); err == nil && st.Size() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if st, err := os.Stat(partPath); err != nil || st.Size() == 0 {
		t.Fatalf("expected active .part file under root staging dir %q, err=%v", partPath, err)
	}

	// Simulate customer deleting/moving the entire project folder while download is still in flight!
	if err := os.RemoveAll(projDir); err != nil {
		t.Fatalf("RemoveAll(projDir): %v", err)
	}

	// Let the second half finish streaming and commit.
	close(resumeStream)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for download completion")
	}

	if nackCount.Load() != 0 {
		t.Fatalf("expected 0 NACKs when project dir is deleted mid-download, got %d", nackCount.Load())
	}
	if ackCount.Load() != 1 {
		t.Fatalf("expected 1 ACK, got %d", ackCount.Load())
	}
	if gotSHA, _ := ackedSHA.Load().(string); gotSHA != wantSHA {
		t.Fatalf("ACKed sha256 = %q, want %q", gotSHA, wantSHA)
	}

	// Project dir must be recreated with exact file contents, and no .relay_tmp inside project dir.
	gotData, err := os.ReadFile(filepath.Join(projDir, "big_video.mp4"))
	if err != nil {
		t.Fatalf("expected committed file after auto-recreating project dir: %v", err)
	}
	if !bytes.Equal(gotData, payload) {
		t.Fatalf("committed file content mismatch: got %d bytes, want %d", len(gotData), len(payload))
	}
	if _, err := os.Stat(partPath); !os.IsNotExist(err) {
		t.Fatalf("expected staged .part file %q to be renamed away, err=%v", partPath, err)
	}
	if _, err := os.Stat(filepath.Join(projDir, ".relay_tmp")); !os.IsNotExist(err) {
		t.Fatalf("expected no .relay_tmp directory inside project folder %q, err=%v", projDir, err)
	}
}

func TestAckFlushSurvivesProjectDirDeletionBeforeSyncFS(t *testing.T) {
	ag, poolRoot := newTestAgentBForIsolation(t)

	var acked atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req protocol.BatchAckReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		results := make([]protocol.BatchAckItemResult, len(req.Items))
		for i, it := range req.Items {
			results[i] = protocol.BatchAckItemResult{FileID: it.FileID, Status: "deleted"}
			acked.Add(1)
		}
		protocol.WriteJSON(w, http.StatusOK, protocol.BatchAckResp{Results: results})
	}))
	defer srv.Close()
	ag.apiClient = srv.Client()

	// Project directory has already been removed by the customer between rename and ACK flush,
	// while the underlying storage root (poolRoot) is healthy and mounted.
	deletedProjDir := filepath.Join(poolRoot, "proj-already-moved")
	if err := ag.store.CompleteActiveAndQueueAck("f-sync-fallback", PendingAck{
		FileID:     "f-sync-fallback",
		ANodeID:    "a-1",
		PublicAddr: srv.URL,
		LeaseID:    "lease-1",
		LeaseToken: "tok-1",
		SHA256:     "abc",
		DestDir:    deletedProjDir,
		CreatedAt:  time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	ag.flushPendingAcks(context.Background())

	if acked.Load() != 1 {
		t.Fatalf("expected pending ACK to flush via storage-root SyncFS fallback, got acked=%d", acked.Load())
	}
	if rem := ag.store.PendingAckCount(); rem != 0 {
		t.Fatalf("expected 0 remaining pending ACKs, got %d", rem)
	}
}
