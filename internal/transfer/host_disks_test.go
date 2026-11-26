package transfer

import "testing"

func TestMandatoryWatermarkFree(t *testing.T) {
	const GiB = 1 << 30
	const TiB = 1 << 40

	// Default (<=0) enforces 85% ceiling: 100 GiB disk reserves 15 GiB.
	usable, over := MandatoryWatermarkFree(100*GiB, 20*GiB, 0, 0)
	if over || usable != 5*GiB {
		t.Fatalf("expected default 85%% watermark to leave 5GiB usable on 100GiB disk with 20GiB free, got usable=%d over=%v", usable, over)
	}
	usable, over = MandatoryWatermarkFree(100*GiB, 14*GiB, 0, 0)
	if !over || usable != 0 {
		t.Fatalf("expected default 85%% watermark to trip at 86%% used, got usable=%d over=%v", usable, over)
	}

	// Custom minimum 1% watermark: 100 GiB disk reserves 99 GiB -> 2% used (98 GiB free) trips, 0.5% used passes.
	usable, over = MandatoryWatermarkFree(100*GiB, 98*GiB, 1.0, 0)
	if !over || usable != 0 {
		t.Fatalf("expected 1%% watermark to trip at 2%% used, got usable=%d over=%v", usable, over)
	}
	usable, over = MandatoryWatermarkFree(1000*GiB, 995*GiB, 1.0, 0)
	if over || usable != 5*GiB {
		t.Fatalf("expected 1%% watermark at 0.5%% used to leave 5GiB usable, got usable=%d over=%v", usable, over)
	}

	// Custom maximum 99% watermark: 100 GiB disk reserves 1 GiB -> 98% used (2 GiB free) passes, 99.5% used trips.
	usable, over = MandatoryWatermarkFree(100*GiB, 2*GiB, 99.0, 0)
	if over || usable != 1*GiB {
		t.Fatalf("expected 99%% watermark at 98%% used to leave 1GiB usable, got usable=%d over=%v", usable, over)
	}
	usable, over = MandatoryWatermarkFree(1000*GiB, 5*GiB, 99.0, 0)
	if !over || usable != 0 {
		t.Fatalf("expected 99%% watermark to trip at 99.5%% used, got usable=%d over=%v", usable, over)
	}

	// Values >99 are clamped to 99% (never allow 100%); values <1 (but >0) are clamped to 1%.
	usable, over = MandatoryWatermarkFree(1000*GiB, 5*GiB, 100.0, 0)
	if !over || usable != 0 {
		t.Fatalf("expected >99%% watermark clamped to 99%% to block 99.5%% full disk, got usable=%d over=%v", usable, over)
	}
	if got := NormalizeMaxDiskUsagePct(0.2); got != MinMaxDiskUsagePct {
		t.Fatalf("expected 0.2 clamped to %.1f, got %.1f", MinMaxDiskUsagePct, got)
	}

	// Explicit minFreeBytes reserve still overrides percentage reserve when larger.
	usable, over = MandatoryWatermarkFree(15*TiB, 11*TiB, 90.0, 0)
	if over || usable == 0 {
		t.Fatalf("expected healthy 15TiB disk, got usable=%d over=%v", usable, over)
	}
	usable, over = MandatoryWatermarkFree(100*GiB, 9*GiB, 99.0, 10*GiB)
	if !over || usable != 0 {
		t.Fatalf("expected explicit 10GiB minFreeBytes to trip when only 9GiB free, got usable=%d over=%v", usable, over)
	}
}

func TestIsSafeStorageDir(t *testing.T) {
	safe := []string{"/mnt/sda/relay-delivery", "/mnt/sdb/relay-cache", "/data/relay-delivery", "/data/relay-a", "/srv/disk1/relay"}
	for _, p := range safe {
		if !IsSafeStorageDir(p) {
			t.Fatalf("expected %q to be allowed", p)
		}
	}
	unsafe := []string{"", "/", "/etc", "/etc/cron.d", "/root/.ssh", "/usr/local/bin", "/bin", "/boot/efi", "/proc/self", "/sys", "/dev", "/mnt/sda/../etc/passwd", "/tmp", "/var", "/home"}
	for _, p := range unsafe {
		if IsSafeStorageDir(p) {
			t.Fatalf("expected sensitive/invalid path %q to be rejected", p)
		}
	}
}

func TestNaturalLess(t *testing.T) {
	cases := [][2]string{
		{"/mnt/disk1", "/mnt/disk2"},
		{"/mnt/disk2", "/mnt/disk10"},
		{"/mnt/disk9", "/mnt/disk10"},
		{"/mnt/disk10", "/mnt/disk100"},
		{"/mnt/sda", "/mnt/sdb"},
	}
	for _, tc := range cases {
		if !NaturalLess(tc[0], tc[1]) {
			t.Fatalf("expected NaturalLess(%q, %q) == true", tc[0], tc[1])
		}
		if NaturalLess(tc[1], tc[0]) {
			t.Fatalf("expected NaturalLess(%q, %q) == false", tc[1], tc[0])
		}
	}
}
