package agenta

import (
	"path/filepath"
	"testing"
	"time"

	"relay-download/internal/protocol"
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

	// Missing local_token must fail.
	noLocalTok := baseValidConfig()
	noLocalTok.LocalToken = ""
	if err := noLocalTok.Validate(); err == nil {
		t.Fatalf("expected empty local_token to fail validation")
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
