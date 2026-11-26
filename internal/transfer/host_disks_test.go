package transfer

import "testing"

func TestMandatoryWatermarkFree(t *testing.T) {
	const GiB = 1 << 30
	const TiB = 1 << 40

	// 15 TiB data disk with 11 TiB free @ 90% max usage -> reserve 1.5 TiB, usable = 9.5 TiB.
	usable, over := MandatoryWatermarkFree(15*TiB, 11*TiB, 90.0, 0)
	if over || usable == 0 {
		t.Fatalf("expected healthy 15TiB disk, got usable=%d over=%v", usable, over)
	}
	// 15 TiB data disk at 92% used (1.2 TiB free < 1.5 TiB reserve) -> MUST trip watermark!
	usable, over = MandatoryWatermarkFree(15*TiB, 1200*GiB, 90.0, 0)
	if !over || usable != 0 {
		t.Fatalf("expected 15TiB disk at 92%% used to trip mandatory 90%% watermark, got usable=%d over=%v", usable, over)
	}
	// 63 GiB system disk "/" with 9 GiB free -> even though 85.7% < 90%, mandatory >=10 GiB reserve trips!
	usable, over = MandatoryWatermarkFree(63*GiB, 9*GiB, 90.0, 0)
	if !over || usable != 0 {
		t.Fatalf("expected 63GiB system disk with 9GiB free to trip mandatory 10GiB reserve, got usable=%d over=%v", usable, over)
	}
	// 63 GiB system disk "/" with 25 GiB free -> usable = 15 GiB, healthy!
	usable, over = MandatoryWatermarkFree(63*GiB, 25*GiB, 90.0, 0)
	if over || usable != 15*GiB {
		t.Fatalf("expected 15GiB usable on 63GiB system disk, got usable=%d over=%v", usable, over)
	}
	// Caller trying to set maxUsedPct=100 is clamped to 95%.
	usable, over = MandatoryWatermarkFree(100*GiB, 4*GiB, 100.0, 0)
	if !over || usable != 0 {
		t.Fatalf("expected clamped watermark to block 96%% full disk, got usable=%d over=%v", usable, over)
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
