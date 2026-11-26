package agenta

import (
	"path/filepath"
	"testing"
	"time"

	"relay-download/internal/transfer"
)

func TestClaimBatchAtomicAssetGroupBundlingAndStickyAffinity(t *testing.T) {
	st, err := OpenStore(filepath.Join(t.TempDir(), "agent-a.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer st.Close()

	now := time.Now().UTC()
	// Upload 3 paired media+metadata assets (6 files total).
	files := []FileRecord{
		{FileID: "f1", ProjectID: "p1", Filename: "vidA.m4a", Size: 1000, SHA256: "a", UploadedAt: now.Add(-6 * time.Second)},
		{FileID: "f2", ProjectID: "p1", Filename: "vidA.info.json", Size: 200, SHA256: "b", UploadedAt: now.Add(-5 * time.Second)},
		{FileID: "f3", ProjectID: "p1", Filename: "vidB.opus", Size: 1000, SHA256: "c", UploadedAt: now.Add(-4 * time.Second)},
		{FileID: "f4", ProjectID: "p1", Filename: "vidB.info.json", Size: 200, SHA256: "d", UploadedAt: now.Add(-3 * time.Second)},
		{FileID: "f5", ProjectID: "p1", Filename: "vidC.m4a", Size: 1000, SHA256: "e", UploadedAt: now.Add(-2 * time.Second)},
		{FileID: "f6", ProjectID: "p1", Filename: "vidC.info.json", Size: 200, SHA256: "f", UploadedAt: now.Add(-1 * time.Second)},
	}
	for _, rec := range files {
		if err := st.PutReady(rec, nil); err != nil {
			t.Fatalf("PutReady %s: %v", rec.FileID, err)
		}
	}

	// 1. Atomic whole-group bundling: maxCount=3 must NOT split vidB across batches -> returns vidA pair (2 files) intact!
	batch, err := st.ClaimBatch("p1", "nas-01", 0, 5*time.Minute, 3)
	if err != nil {
		t.Fatalf("ClaimBatch nas-01: %v", err)
	}
	if len(batch) != 2 {
		t.Fatalf("expected atomic pair of 2 files (vidA.*), got %d: %+v", len(batch), batch)
	}
	for _, r := range batch {
		if transfer.MediaAffinityKey(r.Filename) != "vidA" {
			t.Fatalf("unexpected group in batch: %s", r.Filename)
		}
	}

	// 2. Staggered sibling upload: vidA.srt arrives AFTER nas-01 already claimed vidA.m4a + vidA.info.json.
	// nas-02 MUST skip vidA.srt (reserved for live owner nas-01) and take vidB.* instead!
	if err := st.PutReady(FileRecord{
		FileID: "f7", ProjectID: "p1", Filename: "vidA.srt", Size: 100, SHA256: "g", UploadedAt: now,
	}, nil); err != nil {
		t.Fatalf("PutReady f7: %v", err)
	}
	batch2, err := st.ClaimBatch("p1", "nas-02", 0, 5*time.Minute, 2)
	if err != nil {
		t.Fatalf("ClaimBatch nas-02: %v", err)
	}
	if len(batch2) != 2 {
		t.Fatalf("expected 2 files for nas-02, got %d", len(batch2))
	}
	for _, r := range batch2 {
		if transfer.MediaAffinityKey(r.Filename) != "vidB" {
			t.Fatalf("nas-02 should skip vidA.srt and claim vidB.*, got %s", r.Filename)
		}
	}

	// 3. nas-01 claims next -> gets its reserved sibling vidA.srt!
	batch3, err := st.ClaimBatch("p1", "nas-01", 0, 5*time.Minute, 1)
	if err != nil {
		t.Fatalf("ClaimBatch nas-01 sibling: %v", err)
	}
	if len(batch3) != 1 || batch3[0].FileID != "f7" {
		t.Fatalf("expected nas-01 to claim sibling f7 (vidA.srt), got %+v", batch3)
	}
}

func TestClaimBatchHRWRendezvousAndFailoverWorkStealing(t *testing.T) {
	st, err := OpenStore(filepath.Join(t.TempDir(), "agent-a-hrw.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer st.Close()

	receivers := []string{"nas-01", "nas-02"}
	st.SetRoutingState(map[string][]string{"p1": receivers}, map[string]bool{"p1": true})

	// Pick a video stem deterministically owned by nas-01 via HRW.
	var targetStem string
	for _, cand := range []string{"vid01", "vid02", "vid03", "vid04", "vid05", "vid06", "vid07", "vid08"} {
		if transfer.RendezvousOwner("p1", cand, receivers) == "nas-01" {
			targetStem = cand
			break
		}
	}
	if targetStem == "" {
		t.Fatalf("could not find HRW stem owned by nas-01")
	}

	now := time.Now().UTC()
	_ = st.PutReady(FileRecord{FileID: "h1", ProjectID: "p1", Filename: targetStem + ".opus", Size: 500, SHA256: "x", UploadedAt: now}, nil)
	_ = st.PutReady(FileRecord{FileID: "h2", ProjectID: "p1", Filename: targetStem + ".info.json", Size: 100, SHA256: "y", UploadedAt: now}, nil)

	// Within HRW grace window, nas-02 respects nas-01's ownership (ErrNoReadyFile).
	if _, err := st.ClaimBatch("p1", "nas-02", 0, 5*time.Minute, 10); err != ErrNoReadyFile {
		t.Fatalf("expected nas-02 to defer fresh HRW-owned group to nas-01, got err=%v", err)
	}

	// nas-01 claims the whole pair immediately.
	got, err := st.ClaimBatch("p1", "nas-01", 0, 5*time.Minute, 10)
	if err != nil || len(got) != 2 {
		t.Fatalf("expected nas-01 to claim both HRW-owned files, got len=%d err=%v", len(got), err)
	}

	// Past HRW grace window (old file while nas-01 is slow/idle), nas-02 work-steals the whole pair cleanly!
	oldTime := now.Add(-hrwGraceWindow - 5*time.Second)
	_ = st.PutReady(FileRecord{FileID: "h3", ProjectID: "p1", Filename: targetStem + "_old.opus", Size: 500, SHA256: "x2", UploadedAt: oldTime}, nil)
	_ = st.PutReady(FileRecord{FileID: "h4", ProjectID: "p1", Filename: targetStem + "_old.info.json", Size: 100, SHA256: "y2", UploadedAt: oldTime}, nil)

	stolen, err := st.ClaimBatch("p1", "nas-02", 0, 5*time.Minute, 10)
	if err != nil || len(stolen) != 2 {
		t.Fatalf("expected nas-02 to work-steal past-grace pair atomically, got len=%d err=%v", len(stolen), err)
	}
}
