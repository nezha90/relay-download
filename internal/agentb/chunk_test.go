package agentb

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEffectiveChunkSizeAcrossScales(t *testing.T) {
	if got := effectiveChunkSize(50<<20, 4); got != 4<<20 {
		t.Fatalf("50MiB file expected 4MiB chunk, got %d", got)
	}
	if got := effectiveChunkSize(512<<20, 4); got != 16<<20 {
		t.Fatalf("512MiB file expected 16MiB chunk, got %d", got)
	}
	if got := effectiveChunkSize(300<<30, 4); got != 32<<20 {
		t.Fatalf("300GiB file expected 32MiB chunk, got %d", got)
	}
}

func TestChunkBitmapPersistenceAndResume(t *testing.T) {
	dir := t.TempDir()
	partPath := filepath.Join(dir, "huge.part")
	bitmapPath := partPath + ".bitmap"
	const fileSize = int64(5 << 20)
	const chunkSize = int64(1 << 20)
	const numChunks = 5

	pf, bm, resumed, err := openOrInitChunkBitmap(partPath, bitmapPath, fileSize, chunkSize, numChunks)
	if err != nil {
		t.Fatalf("init bitmap: %v", err)
	}
	if resumed {
		t.Fatalf("expected fresh download, got resumed=true")
	}
	// Mark chunks 0, 2, 4 as completed and simulate restart.
	bm.markDone(0)
	bm.markDone(2)
	bm.markDone(4)
	bm.close()
	_ = pf.Close()

	pf2, bm2, resumed2, err := openOrInitChunkBitmap(partPath, bitmapPath, fileSize, chunkSize, numChunks)
	if err != nil {
		t.Fatalf("reopen bitmap: %v", err)
	}
	defer func() {
		bm2.close()
		_ = pf2.Close()
	}()
	if !resumed2 {
		t.Fatalf("expected resumed=true on reopen")
	}
	wantDone := []bool{true, false, true, false, true}
	for i, want := range wantDone {
		if bm2.isDone(i) != want {
			t.Fatalf("chunk %d done=%v want=%v", i, bm2.isDone(i), want)
		}
	}

	// Changing fileSize invalidates old bitmap cleanly instead of corrupting resume.
	bm2.close()
	_ = pf2.Close()
	pf3, bm3, resumed3, err := openOrInitChunkBitmap(partPath, bitmapPath, fileSize+1024, chunkSize, numChunks+1)
	if err != nil {
		t.Fatalf("reinit on size mismatch: %v", err)
	}
	bm3.close()
	_ = pf3.Close()
	if resumed3 {
		t.Fatalf("expected resumed=false when fileSize changed")
	}
	if _, err := os.Stat(bitmapPath); err != nil {
		t.Fatalf("expected bitmap file to exist: %v", err)
	}
}

func TestMediaAffinityKeyPairing(t *testing.T) {
	cases := [][2]string{
		{"---an6lH3gc.opus", "---an6lH3gc.info.json"},
		{"--0_Hqq8260.m4a", "--0_Hqq8260.info.json"},
		{"--5eLH0dCW8.webm", "--5eLH0dCW8.info.json"},
		{"sub/dir/abc123.opus", "sub/dir/abc123.info.json"},
	}
	for _, tc := range cases {
		k1 := mediaAffinityKey(tc[0])
		k2 := mediaAffinityKey(tc[1])
		if k1 != k2 || k1 == "" {
			t.Fatalf("affinity key mismatch for %q (%q) vs %q (%q)", tc[0], k1, tc[1], k2)
		}
	}
}
