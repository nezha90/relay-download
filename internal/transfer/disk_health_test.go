package transfer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestParseMountInfoAndResolve(t *testing.T) {
	raw := `28 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw,errors=remount-ro
142 28 8:0 / /mnt/sda rw,relatime shared:88 - ext4 /dev/sda rw
143 28 8:16 / /mnt/sdb ro,relatime shared:89 - ext4 /dev/sdb rw
144 28 8:32 / /mnt/my\040disk rw,relatime - xfs /dev/sdc rw
`
	entries := ParseMountInfo(strings.NewReader(raw))
	if len(entries) != 4 {
		t.Fatalf("expected 4 mountinfo entries, got %d", len(entries))
	}
	ent, ok := ResolveMountForPath("/mnt/sda/relay-delivery/proj1", entries)
	if !ok || ent.MountPoint != "/mnt/sda" || ent.MountID != 142 || ent.ReadOnly {
		t.Fatalf("unexpected mount resolution for /mnt/sda: %+v ok=%v", ent, ok)
	}
	entRO, ok := ResolveMountForPath("/mnt/sdb/relay-delivery", entries)
	if !ok || !entRO.ReadOnly {
		t.Fatalf("expected /mnt/sdb to be flagged read-only, got %+v", entRO)
	}
	entSpace, ok := ResolveMountForPath("/mnt/my disk/relay-delivery", entries)
	if !ok || entSpace.MountPoint != "/mnt/my disk" || entSpace.FSType != "xfs" {
		t.Fatalf("expected escaped space mountpoint to resolve, got %+v", entSpace)
	}
	entUnmounted, ok := ResolveMountForPath("/mnt/sdd/relay-delivery", entries)
	if !ok || entUnmounted.MountPoint != "/" {
		t.Fatalf("expected unmounted /mnt/sdd to fall back to '/', got %+v", entUnmounted)
	}
	if !RequiresDedicatedMount("/mnt/sdd/relay-delivery") {
		t.Fatalf("expected /mnt/sdd/relay-delivery to require a dedicated mount")
	}
	if RequiresDedicatedMount("/data/relay-delivery") {
		t.Fatalf("expected /data/relay-delivery (system disk) NOT to require dedicated external mount")
	}
}

func TestDiskHealthUnplugLatchSwapAndSafeEject(t *testing.T) {
	tmp := t.TempDir()
	fakeDataDir := filepath.Join(tmp, "relay-delivery")
	// Simulate an external mount path /mnt/sda/relay-delivery backed by fake OS hooks.
	const (
		rootDev uint64 = 100
		sdaDev  uint64 = 200
		sdbDev  uint64 = 300
	)
	mounts := []MountEntry{
		{MountID: 28, Device: "/dev/nvme0n1p2", MountPoint: "/", FSType: "ext4"},
	}
	devs := map[string]uint64{
		"/":        rootDev,
		"/mnt/sda": rootDev, // initially unmounted -> sits on rootDev!
	}
	writable := true

	tr := NewDiskHealthTracker()
	tr.readMountsFn = func() ([]MountEntry, bool) { return append([]MountEntry(nil), mounts...), true }
	tr.statDevFn = func(p string) (uint64, error) {
		if d, ok := devs[p]; ok {
			return d, nil
		}
		return rootDev, nil
	}
	tr.diskUsageFn = func(p string) (uint64, uint64, float64, error) {
		return 1000 << 30, 800 << 30, 20.0, nil
	}
	tr.accessWriteFn = func(p string) bool { return writable }

	// 1. Cold start while /mnt/sda is NOT mounted: must detect root-fallthrough & REFUSE mkdir!
	p0 := tr.ProbeRoot("/mnt/sda/relay-delivery", true, 90, 0, 0)
	if !p0.Detached || p0.Mounted || !p0.UnplugLatched {
		t.Fatalf("expected unmounted /mnt/sda to be detached & latched, got %+v", p0)
	}
	if err := tr.SafeMkdirAll("/mnt/sda/relay-delivery", fakeDataDir, true); err == nil {
		t.Fatalf("expected SafeMkdirAll to refuse mkdir when /mnt/sda is unmounted")
	}
	if _, err := os.Stat(fakeDataDir); !os.IsNotExist(err) {
		t.Fatalf("SafeMkdirAll must NOT create directory on root fallback")
	}

	// 2. Mount /mnt/sda (mountID=142, dev=sdaDev) -> still latched at gen=0 until operator confirms!
	mounts = append(mounts, MountEntry{MountID: 142, Device: "/dev/sda", MountPoint: "/mnt/sda", FSType: "ext4"})
	devs["/mnt/sda"] = sdaDev
	pStillLocked := tr.ProbeRoot("/mnt/sda/relay-delivery", true, 90, 0, 0)
	if !pStillLocked.Mounted || !pStillLocked.UnplugLatched || pStillLocked.Writable {
		t.Fatalf("expected reinserted disk to stay latched until operator confirmation, got %+v", pStillLocked)
	}

	// 3. Operator confirms & enables in console -> disk_gen advances 0 -> 1 -> healthy & SafeMkdirAll succeeds!
	tr.ApplyConfig(nil, 1)
	pHealthy := tr.ProbeRoot("/mnt/sda/relay-delivery", true, 90, 0, 0)
	if pHealthy.Detached || pHealthy.UnplugLatched || !pHealthy.Mounted || !pHealthy.Writable {
		t.Fatalf("expected confirmed mounted disk to be healthy, got %+v", pHealthy)
	}
	if err := tr.SafeMkdirAll("/mnt/sda/relay-delivery", fakeDataDir, true); err != nil {
		t.Fatalf("expected SafeMkdirAll to succeed after confirmation: %v", err)
	}

	// 4. Sudden direct unplug (umount /mnt/sda -> falls back to /) -> immediate latch at gen=1!
	mounts = mounts[:1]
	devs["/mnt/sda"] = rootDev
	pUnplug := tr.ProbeRoot("/mnt/sda/relay-delivery", true, 90, 0, 0)
	if !pUnplug.Detached || !pUnplug.UnplugLatched || pUnplug.LatchedGen != 1 {
		t.Fatalf("expected direct unplug to latch at gen=1, got %+v", pUnplug)
	}

	// 5. Plug back in with new mountID=189 (no operator confirmation yet) -> STILL locked!
	mounts = append(mounts, MountEntry{MountID: 189, Device: "/dev/sda", MountPoint: "/mnt/sda", FSType: "ext4"})
	devs["/mnt/sda"] = sdaDev
	pReinsert := tr.ProbeRoot("/mnt/sda/relay-delivery", false, 90, 0, 0)
	if !pReinsert.Mounted || pReinsert.Detached || !pReinsert.UnplugLatched || pReinsert.Writable {
		t.Fatalf("expected remounted disk to remain locked pending manual confirmation, got %+v", pReinsert)
	}

	// 6. Operator confirms again (disk_gen 1 -> 2) -> healthy; then sub-second swap (mountID 189 -> 205) -> auto-locks!
	tr.ApplyConfig(nil, 2)
	pOk2 := tr.ProbeRoot("/mnt/sda/relay-delivery", true, 90, 0, 0)
	if pOk2.Detached || pOk2.UnplugLatched || !pOk2.Writable {
		t.Fatalf("expected disk healthy after gen=2 re-enable, got %+v", pOk2)
	}
	mounts[1].MountID = 205 // quick umount + mount of same device between heartbeats!
	pSwap := tr.ProbeRoot("/mnt/sda/relay-delivery", true, 90, 0, 0)
	if !pSwap.UnplugLatched || pSwap.LatchedGen != 2 || pSwap.Writable {
		t.Fatalf("expected sub-second mount_id swap to latch unplug at gen=2, got %+v", pSwap)
	}

	// 7. Confirm (gen=3), then simulate hard cable pull mid-write via ReportIOError(EIO) -> immediate latch!
	tr.ApplyConfig(nil, 3)
	_ = tr.ProbeRoot("/mnt/sda/relay-delivery", true, 90, 0, 0)
	if !tr.ReportIOError("/mnt/sda/relay-delivery", unix.EIO) {
		t.Fatalf("expected ReportIOError(EIO) to trip unplug latch")
	}
	if !tr.IsBlocked("/mnt/sda/relay-delivery") {
		t.Fatalf("expected disk to be blocked immediately after EIO")
	}

	// 8. Graceful safe-eject drain: confirm (gen=4), disable, verify InFlight transitions SafeToEject!
	tr.ApplyConfig(nil, 4)
	_ = tr.ProbeRoot("/mnt/sda/relay-delivery", true, 90, 0, 0)
	tr.ApplyConfig([]string{"/mnt/sda/relay-delivery"}, 5)
	tr.BeginIO("/mnt/sda/relay-delivery")
	pDrain := tr.ProbeRoot("/mnt/sda/relay-delivery", false, 90, 0, 0)
	if pDrain.SafeToEject || pDrain.InFlight != 1 {
		t.Fatalf("expected InFlight=1 and SafeToEject=false while draining, got %+v", pDrain)
	}
	tr.EndIO("/mnt/sda/relay-delivery")
	pSafe := tr.ProbeRoot("/mnt/sda/relay-delivery", false, 90, 0, 0)
	if !pSafe.SafeToEject || pSafe.InFlight != 0 {
		t.Fatalf("expected SafeToEject=true once InFlight reaches 0, got %+v", pSafe)
	}

	// 9. System disk "/" (/data/relay-delivery) works normally without false root-fallback alarm!
	pSys := tr.ProbeRoot("/data/relay-delivery", true, 90, 0, 0)
	if pSys.Detached || pSys.UnplugLatched || !pSys.Mounted || !pSys.Writable {
		t.Fatalf("expected explicit system disk /data/relay-delivery to be healthy, got %+v", pSys)
	}
}
