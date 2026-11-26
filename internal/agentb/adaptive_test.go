package agentb

import (
	"context"
	"testing"
	"time"

	"relay-download/internal/protocol"
)

func TestDynamicGateResizeAndCancel(t *testing.T) {
	g := NewDynamicGate(2)
	if !g.TryAcquire() || !g.TryAcquire() {
		t.Fatalf("expected 2 initial acquires to succeed")
	}
	if g.TryAcquire() {
		t.Fatalf("expected 3rd TryAcquire to fail at limit 2")
	}

	// Raising limit immediately unblocks a waiting Acquire.
	done := make(chan error, 1)
	go func() {
		done <- g.Acquire(context.Background())
	}()
	time.Sleep(15 * time.Millisecond)
	g.SetLimit(3)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Acquire after SetLimit(3): %v", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for Acquire after SetLimit increase")
	}

	// Context cancellation aborts waiting Acquire cleanly.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := g.Acquire(ctx); err == nil {
		t.Fatalf("expected context deadline error when gate is full")
	}
	g.Release()
	g.Release()
	g.Release()
	if g.InFlight() != 0 {
		t.Fatalf("expected InFlight=0, got %d", g.InFlight())
	}
}

func TestAdaptiveControllerProbeCruiseBackoffAndManual(t *testing.T) {
	wg := NewDynamicGate(100)
	sg := NewDynamicGate(200)
	ac := NewAdaptiveController(protocol.ConcurrencyAuto, 100, 200, 50, wg, sg)

	initSnap := ac.Snapshot()
	if initSnap.EffectiveConcurrent != 60 || initSnap.State != "probing" {
		t.Fatalf("unexpected initial warm-start snap: %+v", initSnap)
	}

	// 1. Saturated + scaling throughput -> probes upward cleanly.
	ac.RecordBytes(100 * 1024 * 1024) // 10 MB/s over 10s
	ac.RecordCompleted()
	s1 := ac.Evaluate(10*time.Second, 58, 0)
	if s1.EffectiveConcurrent <= initSnap.EffectiveConcurrent || s1.State != "probing" {
		t.Fatalf("expected upward probe on baseline epoch, got %+v", s1)
	}

	ac.RecordBytes(160 * 1024 * 1024) // 16 MB/s (+60% raw, +27% EWMA gain!)
	ac.RecordCompleted()
	s2 := ac.Evaluate(10*time.Second, s1.EffectiveConcurrent, 0)
	if s2.EffectiveConcurrent <= s1.EffectiveConcurrent || s2.State != "probing" {
		t.Fatalf("expected continued upward probe on throughput gain, got %+v", s2)
	}

	// 2. Plateau (flat goodput despite higher concurrency) -> parks into cruising at sweetSpot!
	ac.RecordBytes(120 * 1024 * 1024) // pulls EWMA flat (~12.4 vs 12.7 MB/s -> plateau)
	ac.RecordCompleted()
	s3 := ac.Evaluate(10*time.Second, s2.EffectiveConcurrent, 0)
	if s3.State != "cruising" || s3.EffectiveConcurrent != s1.EffectiveConcurrent {
		t.Fatalf("expected plateau cruise at sweetSpot=%d, got %+v", s1.EffectiveConcurrent, s3)
	}

	// 3. HTTP 503 backpressure -> immediate AIMD multiplicative decrease (0.80x).
	ac.RecordBytes(120 * 1024 * 1024)
	ac.RecordBackpressure()
	s4 := ac.Evaluate(10*time.Second, s3.EffectiveConcurrent, 0)
	if s4.State != "backoff" || s4.EffectiveConcurrent >= s3.EffectiveConcurrent {
		t.Fatalf("expected AIMD backoff on 503, got %+v (prev=%d)", s4, s3.EffectiveConcurrent)
	}
	if wg.Limit() != s4.EffectiveConcurrent {
		t.Fatalf("workGate limit (%d) out of sync with adaptive controller (%d)", wg.Limit(), s4.EffectiveConcurrent)
	}

	// 4. Switching to manual mode via Center directive locks exact override cap.
	ac.Configure(protocol.ConcurrencyManual, 88, 120)
	s5 := ac.Snapshot()
	if s5.Mode != protocol.ConcurrencyManual || s5.EffectiveConcurrent != 88 || s5.EffectiveStreams != 120 {
		t.Fatalf("unexpected manual override snapshot: %+v", s5)
	}
}
