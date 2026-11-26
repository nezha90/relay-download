package transfer

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// MountEntry describes a single kernel mount entry parsed from /proc/self/mountinfo or /proc/mounts.
type MountEntry struct {
	MountID    int64
	Device     string
	MountPoint string
	FSType     string
	ReadOnly   bool
}

// ParseMountInfo parses Linux /proc/self/mountinfo content.
// Format:
//   mountID parentID major:minor root mountPoint mountOptions [optional...] - fsType mountSource superOptions
// Each remount of even the exact same block device at the same path gets a new monotonically increasing mountID,
// enabling sub-second hot-unplug + re-mount detection between heartbeats.
func ParseMountInfo(r io.Reader) []MountEntry {
	out := make([]MountEntry, 0, 16)
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		sepIdx := strings.Index(line, " - ")
		if sepIdx < 0 {
			continue
		}
		left := strings.Fields(line[:sepIdx])
		right := strings.Fields(line[sepIdx+3:])
		if len(left) < 6 || len(right) < 3 {
			continue
		}
		mid, _ := strconv.ParseInt(left[0], 10, 64)
		mnt := filepath.Clean(unescapeMountField(left[4]))
		mntOpts := left[5]
		fsType := strings.ToLower(right[0])
		dev := unescapeMountField(right[1])
		superOpts := right[2]

		ro := hasReadOnlyOpt(mntOpts) || hasReadOnlyOpt(superOpts)
		out = append(out, MountEntry{
			MountID:    mid,
			Device:     dev,
			MountPoint: mnt,
			FSType:     fsType,
			ReadOnly:   ro,
		})
	}
	return out
}

// ParseProcMounts parses Linux /proc/mounts as a fallback when /proc/self/mountinfo is unavailable.
func ParseProcMounts(r io.Reader) []MountEntry {
	out := make([]MountEntry, 0, 16)
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		out = append(out, MountEntry{
			Device:     unescapeMountField(fields[0]),
			MountPoint: filepath.Clean(unescapeMountField(fields[1])),
			FSType:     strings.ToLower(fields[2]),
			ReadOnly:   hasReadOnlyOpt(fields[3]),
		})
	}
	return out
}

func hasReadOnlyOpt(opts string) bool {
	for _, opt := range strings.Split(opts, ",") {
		if opt == "ro" {
			return true
		}
	}
	return false
}

// ReadMountTable reads Linux kernel mount entries from /proc/self/mountinfo (or /proc/mounts fallback).
// Returns (nil, false) on non-Linux systems where /proc is unavailable.
func ReadMountTable() ([]MountEntry, bool) {
	if f, err := os.Open("/proc/self/mountinfo"); err == nil {
		defer f.Close()
		entries := ParseMountInfo(f)
		if len(entries) > 0 {
			return entries, true
		}
	}
	if f, err := os.Open("/proc/mounts"); err == nil {
		defer f.Close()
		entries := ParseProcMounts(f)
		if len(entries) > 0 {
			return entries, true
		}
	}
	return nil, false
}

// ResolveMountForPath finds the deepest mount point covering path from mounts.
// If multiple mounts are stacked on the same mount point, the last entry wins (Linux mount-stack semantics).
func ResolveMountForPath(path string, mounts []MountEntry) (MountEntry, bool) {
	clean := filepath.Clean(strings.TrimSpace(path))
	var (
		best    MountEntry
		found   bool
		bestLen int
	)
	for _, m := range mounts {
		mp := filepath.Clean(m.MountPoint)
		matches := false
		if mp == "/" {
			matches = strings.HasPrefix(clean, "/")
		} else {
			matches = clean == mp || strings.HasPrefix(clean, mp+"/")
		}
		if matches && (!found || len(mp) >= bestLen) {
			best = m
			best.MountPoint = mp
			bestLen = len(mp)
			found = true
		}
	}
	return best, found
}

var dedicatedMountPrefixes = []string{
	"/mnt/", "/media/", "/run/media/", "/volumes/", "/disks/",
}

// RequiresDedicatedMount returns true if path sits under a standard external/data-disk mount
// directory (e.g. /mnt/sda/relay-delivery). Such paths MUST resolve to a dedicated non-root
// mount point and are NEVER allowed to silently fall back onto "/" if the drive is unmounted.
func RequiresDedicatedMount(path string) bool {
	clean := filepath.Clean(strings.TrimSpace(path))
	lower := strings.ToLower(clean)
	for _, pfx := range dedicatedMountPrefixes {
		if strings.HasPrefix(lower, pfx) {
			return true
		}
	}
	return false
}

// IsDiskIOError reports whether err indicates a hardware unplug, stale mount, read-only remount,
// or device-gone filesystem failure that must immediately fence the backing disk.
func IsDiskIOError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, unix.EIO) ||
		errors.Is(err, unix.ENODEV) ||
		errors.Is(err, unix.EROFS) ||
		errors.Is(err, unix.ESTALE) ||
		errors.Is(err, unix.ENXIO) ||
		errors.Is(err, unix.ESHUTDOWN)
}

type mountIdentity struct {
	mountPoint string
	mountID    int64
	devID      uint64
	hasDev     bool
}

// DiskProbeResult summarizes real-time mount, space, drain, and unplug-latch status for a storage root.
type DiskProbeResult struct {
	Root          string
	TotalBytes    uint64
	FreeBytes     uint64
	UsedPct       float64
	LowSpace      bool
	Writable      bool
	Mounted       bool
	Detached      bool
	UnplugLatched bool
	LatchedGen    int64
	InFlight      int
	SafeToEject   bool
	StatusReason  string
	DevID         uint64
	HasDev        bool
}

// DiskHealthTracker provides unified hot-plug/unplug detection, "/" root-fallthrough protection,
// manual re-confirm latching (by monotonic Center DiskGen), and per-disk in-flight drain tracking
// shared by both relay-agent-a (dispatch) and relay-agent-b (receiver).
type DiskHealthTracker struct {
	mu            sync.Mutex
	diskGen       int64
	knownMount    map[string]mountIdentity
	latchedGen    map[string]int64
	latchedReason map[string]string
	inFlight      map[string]int32
	disabled      map[string]bool

	// Injectable OS hooks for deterministic unit tests (default to real OS calls).
	readMountsFn  func() ([]MountEntry, bool)
	statDevFn     func(string) (uint64, error)
	diskUsageFn   func(string) (uint64, uint64, float64, error)
	accessWriteFn func(string) bool
}

func NewDiskHealthTracker() *DiskHealthTracker {
	return &DiskHealthTracker{
		knownMount:    make(map[string]mountIdentity),
		latchedGen:    make(map[string]int64),
		latchedReason: make(map[string]string),
		inFlight:      make(map[string]int32),
		disabled:      make(map[string]bool),
		readMountsFn:  ReadMountTable,
		statDevFn:     statDeviceID,
		diskUsageFn:   DiskUsage,
		accessWriteFn: func(p string) bool { return unix.Access(p, unix.W_OK) == nil },
	}
}

func statDeviceID(p string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(p, &st); err != nil {
		return 0, err
	}
	return uint64(st.Dev), nil
}

// ApplyConfig synchronizes Center's latest disabled-disk list and monotonic DiskGen.
// Whenever DiskGen advances (operator clicked Save / Re-enable in the console), any prior unplug
// latch for disks that are now enabled is cleared so the operator's confirmation takes effect,
// while still verifying live mount health before allowing any directory creation or writes.
func (t *DiskHealthTracker) ApplyConfig(disabledDisks []string, diskGen int64) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	disMap := make(map[string]bool, len(disabledDisks))
	for _, d := range disabledDisks {
		d = strings.TrimSpace(d)
		if d != "" {
			disMap[filepath.Clean(d)] = true
		}
	}
	prevDisabled := t.disabled
	prevGen := t.diskGen
	if diskGen > t.diskGen {
		t.diskGen = diskGen
	}
	t.disabled = disMap

	if t.diskGen > prevGen {
		for root, lGen := range t.latchedGen {
			if lGen < t.diskGen && !disMap[root] {
				delete(t.latchedGen, root)
				delete(t.latchedReason, root)
				delete(t.knownMount, root)
			}
		}
		// Any root explicitly re-enabled by operator adopts its current mount_id cleanly.
		for root := range prevDisabled {
			if !disMap[root] {
				delete(t.knownMount, root)
			}
		}
	}
}

// MatchRootForPath finds the configured storage root that equals or contains path (longest match wins).
func MatchRootForPath(path string, roots []string) string {
	clean := filepath.Clean(strings.TrimSpace(path))
	best := ""
	for _, r := range roots {
		rc := filepath.Clean(strings.TrimSpace(r))
		if rc == "" || rc == "." {
			continue
		}
		if clean == rc || strings.HasPrefix(clean, rc+string(filepath.Separator)) {
			if len(rc) > len(best) {
				best = rc
			}
		}
	}
	if best != "" {
		return best
	}
	return clean
}

// BeginIO increments the active I/O counter for root (used to report safe-to-eject drain status).
func (t *DiskHealthTracker) BeginIO(root string) {
	clean := filepath.Clean(strings.TrimSpace(root))
	if clean == "" || clean == "." {
		return
	}
	t.mu.Lock()
	t.inFlight[clean]++
	t.mu.Unlock()
}

// EndIO decrements the active I/O counter for root.
func (t *DiskHealthTracker) EndIO(root string) {
	clean := filepath.Clean(strings.TrimSpace(root))
	if clean == "" || clean == "." {
		return
	}
	t.mu.Lock()
	if cur := t.inFlight[clean]; cur > 1 {
		t.inFlight[clean] = cur - 1
	} else {
		delete(t.inFlight, clean)
	}
	t.mu.Unlock()
}

// InFlight returns the current number of active transfers/writes targeting root.
func (t *DiskHealthTracker) InFlight(root string) int {
	clean := filepath.Clean(strings.TrimSpace(root))
	t.mu.Lock()
	n := int(t.inFlight[clean])
	t.mu.Unlock()
	return n
}

// ReportIOError immediately latches a disk root as detached/faulted when a live file operation
// returns a hardware/mount I/O error (EIO, ENODEV, EROFS, ESTALE, ENXIO).
// Returns true if this newly tripped the unplug latch.
func (t *DiskHealthTracker) ReportIOError(root string, err error) bool {
	if !IsDiskIOError(err) {
		return false
	}
	clean := filepath.Clean(strings.TrimSpace(root))
	if clean == "" || clean == "." {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	reason := fmt.Sprintf("磁盘 I/O 异常 (%v)，已自动锁定", err)
	already := false
	if g, ok := t.latchedGen[clean]; ok && g == t.diskGen {
		already = true
	}
	t.latchedGen[clean] = t.diskGen
	t.latchedReason[clean] = reason
	return !already
}

// IsBlocked returns true if root is currently latched as unplugged/faulted OR disabled.
func (t *DiskHealthTracker) IsBlocked(root string) bool {
	if t == nil {
		return false
	}
	clean := filepath.Clean(strings.TrimSpace(root))
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.disabled[clean] {
		return true
	}
	if _, ok := t.latchedGen[clean]; ok {
		return true
	}
	return false
}

// ProbeRoot verifies whether root sits on a real, mounted, writable backing filesystem (never
// silently falling through onto "/" when an external drive is unmounted), detects unplug/swap
// via /proc/self/mountinfo mount_id + stat.Dev, enforces mandatory watermarks, and computes
// safe-to-eject drain status.
// extraQueued is optional pending queued files residing on this disk (used by dispatch agent-a).
func (t *DiskHealthTracker) ProbeRoot(root string, enabled bool, maxUsedPct float64, minFreeBytes uint64, extraQueued int) DiskProbeResult {
	clean := filepath.Clean(strings.TrimSpace(root))
	res := DiskProbeResult{
		Root: clean,
	}

	mounts, hasMounts := t.readMountsFn()
	var rootDev uint64
	hasRootDev := false
	if hasMounts {
		if rd, err := t.statDevFn("/"); err == nil {
			rootDev = rd
			hasRootDev = true
		}
	}

	t.mu.Lock()
	curGen := t.diskGen
	prevIdent, hadIdent := t.knownMount[clean]
	lGen, isLatched := t.latchedGen[clean]
	lReason := t.latchedReason[clean]
	inFlight := int(t.inFlight[clean])
	t.mu.Unlock()

	res.InFlight = inFlight

	// Step 1: Verify backing mount point via kernel mount table (Linux) to block "/" fallthrough.
	var (
		curIdent   mountIdentity
		hasIdent   bool
		mountOK    = true
		mountErr   string
		statTarget = clean
	)
	if hasMounts {
		ent, ok := ResolveMountForPath(clean, mounts)
		if !ok {
			mountOK = false
			mountErr = "磁盘已拔出/未挂载"
		} else {
			isRootFallback := ent.MountPoint == "/" && (RequiresDedicatedMount(clean) || (hadIdent && prevIdent.mountPoint != "/"))
			if isRootFallback {
				mountOK = false
				mountErr = "数据盘已拔出/未挂载（已拦截防写进系统盘）"
			} else if ent.ReadOnly {
				mountOK = false
				mountErr = "磁盘已变为只读状态"
			} else if ent.MountPoint != "/" && !allowedMountFSTypes[ent.FSType] {
				mountOK = false
				mountErr = fmt.Sprintf("无效挂载文件系统 (%s)", ent.FSType)
			} else {
				// Also verify stat.Dev on the mount point itself differs from "/" for dedicated mounts.
				mpDev, devErr := t.statDevFn(ent.MountPoint)
				if devErr != nil {
					mountOK = false
					mountErr = "磁盘挂载点不可访问"
				} else if ent.MountPoint != "/" && hasRootDev && mpDev == rootDev {
					mountOK = false
					mountErr = "数据盘设备号退化为系统盘（已拦截）"
				} else {
					curIdent = mountIdentity{
						mountPoint: ent.MountPoint,
						mountID:    ent.MountID,
						devID:      mpDev,
						hasDev:     true,
					}
					hasIdent = true
					statTarget = existingAncestorWithinMount(clean, ent.MountPoint)
				}
			}
		}
	} else {
		// Non-Linux fallback (macOS development/unit tests): resolve nearest existing directory.
		statTarget = existingAncestorWithinMount(clean, "/")
		if dev, err := t.statDevFn(statTarget); err == nil {
			curIdent = mountIdentity{mountPoint: "/", devID: dev, hasDev: true}
			hasIdent = true
		}
	}

	// Step 2: Check disk usage & writability ONLY when mount validation succeeded.
	if mountOK {
		total, free, pct, uErr := t.diskUsageFn(statTarget)
		if uErr != nil {
			mountOK = false
			if IsDiskIOError(uErr) {
				mountErr = "磁盘 I/O 异常（可能已热拔出）"
			} else {
				mountErr = "读取磁盘容量失败"
			}
		} else if total == 0 {
			mountOK = false
			mountErr = "磁盘容量为 0（疑似已卸载）"
		} else {
			res.TotalBytes = total
			res.FreeBytes = free
			res.UsedPct = pct
			_, overWM := MandatoryWatermarkFree(total, free, maxUsedPct, minFreeBytes)
			res.LowSpace = overWM
			res.Writable = t.accessWriteFn(statTarget)
			if !res.Writable {
				mountOK = false
				mountErr = "磁盘目录不可写或只读"
			}
		}
	}

	// Step 3: Detect hot-unplug, remount-ro, or sub-second hot-swap (mount_id / dev_id / mount_point changed).
	swapped := false
	if mountOK && hasIdent && hadIdent {
		if prevIdent.mountPoint != curIdent.mountPoint {
			swapped = true
		} else if prevIdent.mountID > 0 && curIdent.mountID > 0 && prevIdent.mountID != curIdent.mountID {
			swapped = true
		} else if prevIdent.hasDev && curIdent.hasDev && prevIdent.devID != curIdent.devID {
			swapped = true
		}
	}

	t.mu.Lock()
	// Re-read diskGen in case ApplyConfig ran concurrently.
	curGen = t.diskGen
	if !mountOK {
		res.Mounted = false
		res.Detached = true
		res.Writable = false
		if enabled || isLatched {
			// Latch unplug immediately whenever an enabled disk detaches (or stays latched).
			t.latchedGen[clean] = curGen
			t.latchedReason[clean] = mountErr
			isLatched = true
			lGen = curGen
			lReason = mountErr
		}
		res.UnplugLatched = isLatched
		res.LatchedGen = lGen
		if mountErr != "" {
			res.StatusReason = mountErr
		} else {
			res.StatusReason = "磁盘已拔出/未挂载"
		}
	} else {
		res.Mounted = true
		res.DevID = curIdent.devID
		res.HasDev = curIdent.hasDev
		if swapped && enabled {
			// Even a sub-second umount + remount (same or different disk) locks until operator re-confirms!
			t.latchedGen[clean] = curGen
			t.latchedReason[clean] = "检测到磁盘重新挂载，已自动锁定待人工确认"
			isLatched = true
			lGen = curGen
			lReason = t.latchedReason[clean]
		}
		if hasIdent && !isLatched && enabled {
			t.knownMount[clean] = curIdent
		}
		res.UnplugLatched = isLatched
		res.LatchedGen = lGen
		switch {
		case isLatched:
			res.Writable = false
			if strings.Contains(lReason, "I/O") {
				res.StatusReason = lReason
			} else {
				res.StatusReason = "已重插就绪 · 待人工确认启用"
			}
		case !enabled:
			if inFlight == 0 && extraQueued == 0 {
				res.SafeToEject = true
				res.StatusReason = "已排空（在途 0）· 可安全卸载拔盘"
			} else if inFlight > 0 {
				res.StatusReason = fmt.Sprintf("排空中（在途写入 %d）· 请勿拔盘", inFlight)
			} else {
				res.StatusReason = fmt.Sprintf("停用中（尚有 %d 个待分发缓存文件）", extraQueued)
			}
		case res.LowSpace:
			res.StatusReason = "触达强制安全水位"
		default:
			if lReason != "" && !isLatched {
				delete(t.latchedReason, clean)
			}
			res.StatusReason = "正常挂载"
		}
	}
	t.mu.Unlock()

	return res
}

// SafeMkdirAll creates targetDir (which must equal or sit inside root) ONLY after verifying that
// root is genuinely mounted, writable, and NOT unplug-latched or falling back onto "/".
// This guarantees we NEVER create directories inside an unmounted /mnt/* folder on "/".
func (t *DiskHealthTracker) SafeMkdirAll(root, targetDir string, enabled bool) error {
	probe := t.ProbeRoot(root, enabled, 95, 0, 0)
	if probe.Detached || !probe.Mounted {
		return fmt.Errorf("storage root %s is detached/unmounted (%s): refusing mkdir to protect root filesystem", root, probe.StatusReason)
	}
	if probe.UnplugLatched {
		return fmt.Errorf("storage root %s is locked after unplug (%s): awaiting manual confirmation", root, probe.StatusReason)
	}
	if !probe.Writable {
		return fmt.Errorf("storage root %s is not writable (%s)", root, probe.StatusReason)
	}
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		if IsDiskIOError(err) {
			t.ReportIOError(root, err)
		}
		return err
	}
	return nil
}

// existingAncestorWithinMount walks upward from path until an existing directory is found,
// stopping strictly at mountPoint so it never escapes a dedicated mount onto "/".
func existingAncestorWithinMount(path, mountPoint string) string {
	cur := filepath.Clean(path)
	mp := filepath.Clean(mountPoint)
	for {
		if _, err := os.Stat(cur); err == nil {
			return cur
		}
		if cur == mp || cur == "/" {
			return mp
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return mp
		}
		// Never cross above mountPoint.
		if mp != "/" && parent != mp && !strings.HasPrefix(parent, mp+"/") {
			return mp
		}
		cur = parent
	}
}
