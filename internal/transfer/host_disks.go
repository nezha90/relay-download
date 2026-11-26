package transfer

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/sys/unix"

	"relay-download/internal/protocol"
)

var validStoragePathRe = regexp.MustCompile(`^/[A-Za-z0-9/._-]{1,255}$`)

var forbiddenStoragePrefixes = []string{
	"/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/proc", "/root",
	"/run", "/sbin", "/sys", "/usr", "/var/lib/systemd", "/var/spool", "/var/run",
}

// IsSafeStorageDir validates that a Center-pushed storage_dir path is a clean absolute path
// outside sensitive OS system directories (preventing arbitrary system-file overwrite).
func IsSafeStorageDir(raw string) bool {
	p := strings.TrimSpace(raw)
	if !validStoragePathRe.MatchString(p) || strings.Contains(p, "..") {
		return false
	}
	clean := filepath.Clean(p)
	if clean == "/" || clean == "/tmp" || clean == "/var" || clean == "/home" {
		return false
	}
	for _, pfx := range forbiddenStoragePrefixes {
		if clean == pfx || strings.HasPrefix(clean, pfx+"/") {
			return false
		}
	}
	return true
}

// MandatoryWatermarkFree enforces a mandatory safety watermark on EVERY disk (both data disks
// and the system "/" disk) so no transfer can ever exhaust disk space or crash the host OS.
//   - Always enforces maxUsedPct (clamped to [50, 95], default 90 if <=0).
//   - On disks >= 50 GiB, always reserves at least 10 GiB free (in addition to configured minFreeBytes).
//   - On smaller disks (e.g., compact test disks), reserves at least (100 - maxUsedPct)% + minFreeBytes.
//
// Returns usable bytes available above the watermark and whether the disk has already hit/exceeded it.
func MandatoryWatermarkFree(total, free uint64, maxUsedPct float64, minFreeBytes uint64) (usable uint64, overWatermark bool) {
	if total == 0 {
		return 0, true
	}
	if maxUsedPct <= 0 {
		maxUsedPct = 90.0
	}
	if maxUsedPct > 95.0 {
		maxUsedPct = 95.0
	}
	if maxUsedPct < 50.0 {
		maxUsedPct = 50.0
	}
	pctReserve := uint64(float64(total) * (100.0 - maxUsedPct) / 100.0)
	reserve := pctReserve
	const fiftyGiB = 50 << 30
	const tenGiB = 10 << 30
	if total >= fiftyGiB && reserve < tenGiB {
		reserve = tenGiB
	}
	if minFreeBytes > reserve {
		reserve = minFreeBytes
	}
	if free <= reserve {
		return 0, true
	}
	return free - reserve, false
}

var allowedMountFSTypes = map[string]bool{
	"ext4": true, "ext3": true, "ext2": true, "xfs": true, "btrfs": true, "zfs": true,
	"f2fs": true, "jfs": true, "ntfs": true, "ntfs3": true, "exfat": true, "vfat": true,
	"fuseblk": true, "nfs": true, "nfs4": true, "cifs": true, "smb3": true,
	"ceph": true, "glusterfs": true, "lustre": true,
}

var ignoredMountPrefixes = []string{
	"/boot", "/snap", "/run", "/proc", "/sys", "/dev",
	"/var/lib/docker", "/var/lib/containerd", "/var/lib/kubelet",
}

func unescapeMountField(s string) string {
	r := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return r.Replace(s)
}

// DiscoverHostDisks scans /proc/mounts (Linux) for real mounted physical/network filesystems
// (filtering out pseudo/virtual/container/boot/ro/tiny partitions, allowing "/" system disk
// tagged with IsSystem=true so operators can safely choose it under mandatory disk watermarks).
// subdirName is appended to each data mount (e.g. "relay-delivery" for receivers, "relay-cache" for dispatchers).
func DiscoverHostDisks(subdirName string) []protocol.HostDisk {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return nil
	}
	defer f.Close()

	if subdirName == "" {
		subdirName = "relay-delivery"
	}
	const minDiskBytes = 4 << 30 // skip tiny < 4 GiB EFI/recovery partitions
	seenDev := make(map[uint64]struct{})
	seenMount := make(map[string]struct{})
	out := make([]protocol.HostDisk, 0, 8)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		dev := unescapeMountField(fields[0])
		mnt := filepath.Clean(unescapeMountField(fields[1]))
		fsType := strings.ToLower(fields[2])
		opts := fields[3]

		if !allowedMountFSTypes[fsType] || !strings.HasPrefix(mnt, "/") {
			continue
		}
		skip := false
		for _, pfx := range ignoredMountPrefixes {
			if mnt == pfx || strings.HasPrefix(mnt, pfx+"/") {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		if _, dup := seenMount[mnt]; dup {
			continue
		}

		readOnly := false
		for _, opt := range strings.Split(opts, ",") {
			if opt == "ro" {
				readOnly = true
				break
			}
		}
		if readOnly {
			continue
		}

		total, free, pct, uErr := DiskUsage(mnt)
		if uErr != nil || total < minDiskBytes {
			continue
		}

		var st unix.Stat_t
		if unix.Stat(mnt, &st) == nil {
			devID := uint64(st.Dev)
			if _, dup := seenDev[devID]; dup {
				continue
			}
			seenDev[devID] = struct{}{}
		}
		seenMount[mnt] = struct{}{}

		isSys := mnt == "/"
		suggested := filepath.Join(mnt, subdirName)
		if isSys {
			suggested = filepath.Join("/data", subdirName)
		}
		writable := unix.Access(mnt, unix.W_OK) == nil
		out = append(out, protocol.HostDisk{
			Device:       dev,
			MountPoint:   mnt,
			FSType:       fsType,
			TotalBytes:   total,
			FreeBytes:    free,
			UsedPct:      pct,
			Writable:     writable,
			SuggestedDir: suggested,
			IsSystem:     isSys,
		})
	}

	// Sort real data disks first (largest free space first), system "/" disk last.
	sort.Slice(out, func(i, j int) bool {
		if out[i].IsSystem != out[j].IsSystem {
			return !out[i].IsSystem
		}
		if out[i].FreeBytes != out[j].FreeBytes {
			return out[i].FreeBytes > out[j].FreeBytes
		}
		return out[i].MountPoint < out[j].MountPoint
	})
	return out
}
