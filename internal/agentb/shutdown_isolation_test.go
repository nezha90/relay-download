package agentb

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"relay-download/internal/pki"
	"relay-download/internal/protocol"
)

func newTestAgentBForIsolation(t *testing.T) (*Agent, string) {
	t.Helper()
	dir := t.TempDir()
	caCert := filepath.Join(dir, "ca.crt")
	caKey := filepath.Join(dir, "ca.key")
	if err := pki.InitCA(caCert, caKey, "agentb-iso-ca", 365); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	dest := filepath.Join(dir, "dest")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		NodeID:          "b-iso-1",
		CenterURL:       "https://127.0.0.1:1",
		CenterToken:     "tok-b",
		CACert:          caCert,
		StateDir:        filepath.Join(dir, "state"),
		StorageDirs:     []string{dest},
		MaxConcurrent:   4,
		MaxDiskUsagePct: 99,
	}
	ag, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("agentb.New: %v", err)
	}
	t.Cleanup(func() { _ = ag.store.Close() })
	return ag, dest
}

func TestAgentBReleasesSlotImmediatelyWhenDispatchDrainingOrDead(t *testing.T) {
	ag, dest := newTestAgentBForIsolation(t)

	// 1. Dispatch node signals graceful shutdown via X-Relay-Draining: 1 -> must exit immediately (<1s).
	drainingSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(protocol.HeaderDraining, "1")
		protocol.WriteError(w, http.StatusServiceUnavailable, "dispatch node is shutting down")
	}))
	defer drainingSrv.Close()
	ag.streamClients = []*http.Client{drainingSrv.Client()}
	ag.apiClient = drainingSrv.Client()

	partPath := filepath.Join(dest, "proj-1", ".relay_tmp", "f-drain.part")
	dl := ActiveDownload{
		FileID:         "f-drain",
		ProjectID:      "proj-1",
		ANodeID:        "a-draining",
		PublicAddr:     drainingSrv.URL,
		Filename:       "video.mp4",
		Size:           1024,
		SHA256:         "deadbeef",
		LeaseID:        "lease-1",
		LeaseToken:     "ltok-1",
		LeaseExpiresAt: time.Now().Add(5 * time.Minute),
		LeaseTTLSec:    300,
		DestDir:        filepath.Join(dest, "proj-1"),
		PartPath:       partPath,
	}
	_ = ag.store.PutActive(dl)

	start := time.Now()
	ag.runDownload(context.Background(), dl)
	elapsed := time.Since(start)
	if elapsed > 2*time.Second {
		t.Fatalf("draining dispatch node took too long to release worker slot: %v", elapsed)
	}
	if !ag.isPeerDead("a-draining") {
		t.Fatalf("expected a-draining to be placed on short cooldown")
	}
	if active, _ := ag.store.ListActive(); len(active) != 0 {
		t.Fatalf("expected active record cleaned up after draining abort, got %d", len(active))
	}

	// 2. Dispatch node hard-crashed (closed listener / connection refused) -> must NOT hang forever.
	deadSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := deadSrv.URL
	deadSrv.Close() // simulate abrupt power-off

	dl2 := dl
	dl2.FileID = "f-dead"
	dl2.ANodeID = "a-dead"
	dl2.PublicAddr = deadURL
	dl2.PartPath = filepath.Join(dest, "proj-1", ".relay_tmp", "f-dead.part")
	dl2.LeaseExpiresAt = time.Now().Add(2 * time.Second)
	_ = ag.store.PutActive(dl2)

	start2 := time.Now()
	ag.runDownload(context.Background(), dl2)
	if time.Since(start2) > 8*time.Second {
		t.Fatalf("dead dispatch node held worker slot too long: %v", time.Since(start2))
	}
	if !ag.isPeerDead("a-dead") {
		t.Fatalf("expected a-dead to be placed on cooldown")
	}
	if active, _ := ag.store.ListActive(); len(active) != 0 {
		t.Fatalf("expected active record cleaned up after dead-peer abort, got %d", len(active))
	}
}

func TestAgentBParallelAckFlushIsolatesDeadDispatchNode(t *testing.T) {
	ag, dest := newTestAgentBForIsolation(t)

	// Slow/hung dead dispatch node (sleeps until test cleanup) vs fast healthy dispatch node.
	stopHung := make(chan struct{})
	hungSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-stopHung:
		}
	}))
	defer func() {
		close(stopHung)
		hungSrv.Close()
	}()

	var healthyAcked atomic.Int32
	healthySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req protocol.BatchAckReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		results := make([]protocol.BatchAckItemResult, len(req.Items))
		for i, it := range req.Items {
			results[i] = protocol.BatchAckItemResult{FileID: it.FileID, Status: "deleted"}
			healthyAcked.Add(1)
		}
		protocol.WriteJSON(w, http.StatusOK, protocol.BatchAckResp{Results: results})
	}))
	defer healthySrv.Close()

	ag.apiClient = &http.Client{Timeout: 400 * time.Millisecond}

	now := time.Now().UTC()
	_ = ag.store.CompleteActiveAndQueueAck("f-hung", PendingAck{
		FileID: "f-hung", ANodeID: "a-hung", PublicAddr: hungSrv.URL,
		LeaseID: "l1", LeaseToken: "t1", SHA256: "abc", DestDir: dest, CreatedAt: now,
	})
	_ = ag.store.CompleteActiveAndQueueAck("f-ok", PendingAck{
		FileID: "f-ok", ANodeID: "a-ok", PublicAddr: healthySrv.URL,
		LeaseID: "l2", LeaseToken: "t2", SHA256: "def", DestDir: dest, CreatedAt: now,
	})

	ag.flushPendingAcks(context.Background())

	if healthyAcked.Load() != 1 {
		t.Fatalf("expected healthy dispatch node to be ACKed despite dead peer, got %d", healthyAcked.Load())
	}
	rem, _ := ag.store.ListPendingAcks()
	if len(rem) != 1 || rem[0].FileID != "f-hung" {
		t.Fatalf("expected only f-hung remaining in pending ACKs, got %+v", rem)
	}
	// Dead peer must now be in backoff so next immediate flush does not stall.
	if ag.shouldRetryAckPeer(hungSrv.URL, time.Now()) {
		t.Fatalf("expected dead peer %s to be in ACK retry backoff", hungSrv.URL)
	}
}
