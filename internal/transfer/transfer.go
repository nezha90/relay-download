package transfer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

const BufSize = 1024 * 1024 // 1 MiB fixed streaming buffer tuned for 10 Gbps WAN streams

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, BufSize)
		return &b
	},
}

func GetBuf() *[]byte {
	return bufPool.Get().(*[]byte)
}

func PutBuf(b *[]byte) {
	if b != nil && len(*b) == BufSize {
		bufPool.Put(b)
	}
}

// RateLimiter is a dynamic token-bucket byte rate limiter safe for concurrent use.
// A rate <= 0 disables throttling with a lock-free atomic fast path for 10Gbps streams.
type RateLimiter struct {
	rateAtomic  atomic.Int64
	mu          sync.Mutex
	bytesPerSec float64
	burst       float64
	tokens      float64
	last        time.Time
}

func NewRateLimiter(bytesPerSec int64) *RateLimiter {
	if bytesPerSec <= 0 {
		return nil
	}
	r := &RateLimiter{last: time.Now()}
	r.SetRate(bytesPerSec)
	return r
}

// NewDynamicRateLimiter always returns a non-nil limiter whose rate can be changed live via SetRate.
func NewDynamicRateLimiter(bytesPerSec int64) *RateLimiter {
	r := &RateLimiter{last: time.Now()}
	r.SetRate(bytesPerSec)
	return r
}

func (r *RateLimiter) SetRate(bytesPerSec int64) {
	if r == nil {
		return
	}
	if bytesPerSec < 0 {
		bytesPerSec = 0
	}
	r.mu.Lock()
	r.rateAtomic.Store(bytesPerSec)
	if bytesPerSec == 0 {
		r.bytesPerSec = 0
		r.burst = 0
		r.tokens = 0
		r.last = time.Now()
		r.mu.Unlock()
		return
	}
	burst := float64(bytesPerSec)
	if burst < float64(BufSize) {
		burst = float64(BufSize)
	}
	r.bytesPerSec = float64(bytesPerSec)
	r.burst = burst
	if r.tokens > burst || r.tokens <= 0 {
		r.tokens = burst
	}
	r.last = time.Now()
	r.mu.Unlock()
}

func (r *RateLimiter) Rate() int64 {
	if r == nil {
		return 0
	}
	return r.rateAtomic.Load()
}

func (r *RateLimiter) Wait(ctx context.Context, n int) error {
	if r == nil || n <= 0 {
		return nil
	}
	if r.rateAtomic.Load() <= 0 {
		return nil
	}
	for {
		r.mu.Lock()
		if r.bytesPerSec <= 0 {
			r.mu.Unlock()
			return nil
		}
		now := time.Now()
		elapsed := now.Sub(r.last).Seconds()
		r.last = now
		r.tokens += elapsed * r.bytesPerSec
		if r.tokens > r.burst {
			r.tokens = r.burst
		}
		if r.tokens >= float64(n) {
			r.tokens -= float64(n)
			r.mu.Unlock()
			return nil
		}
		deficit := float64(n) - r.tokens
		waitDur := time.Duration((deficit / r.bytesPerSec) * float64(time.Second))
		r.mu.Unlock()

		if waitDur < time.Millisecond {
			waitDur = time.Millisecond
		}
		if waitDur > 250*time.Millisecond {
			// Cap single sleep so hot rate increases take effect promptly.
			waitDur = 250 * time.Millisecond
		}
		timer := time.NewTimer(waitDur)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// MediaAffinityKey computes the canonical asset-group stem for a relative filename so paired
// media + metadata files (e.g. "<video_id>.opus" and "<video_id>.info.json") resolve to the
// same key on both dispatch nodes (multi-receiver grouping) and receiver nodes (multi-disk placement).
func MediaAffinityKey(filename string) string {
	norm := strings.ReplaceAll(strings.TrimSpace(filename), "\\", "/")
	dir := path.Dir(norm)
	base := path.Base(norm)
	lower := strings.ToLower(base)
	stem := base
	matchedCompound := false
	for _, suffix := range []string{".info.json", ".meta.json", ".tar.gz", ".tar.zst"} {
		if strings.HasSuffix(lower, suffix) && len(base) > len(suffix) {
			stem = base[:len(base)-len(suffix)]
			matchedCompound = true
			break
		}
	}
	if !matchedCompound {
		ext := path.Ext(base)
		if ext != "" && len(base) > len(ext) {
			stem = base[:len(base)-len(ext)]
		}
	}
	if dir != "" && dir != "." && dir != "/" {
		return dir + "/" + stem
	}
	return stem
}

// RendezvousOwner selects the deterministic HRW (Highest Random Weight) owner receiver node
// for (projectID, groupKey) among candidates. Adding or removing a receiver remaps only ~1/N keys.
func RendezvousOwner(projectID, groupKey string, candidates []string) string {
	if len(candidates) == 0 {
		return ""
	}
	if len(candidates) == 1 {
		return candidates[0]
	}
	var (
		bestNode  string
		bestScore uint64
	)
	for i, nodeID := range candidates {
		h := fnv.New64a()
		_, _ = h.Write([]byte(projectID))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(groupKey))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(nodeID))
		score := h.Sum64()
		// SplitMix64 finalizer improves avalanche across similar node IDs (e.g. nas-01, nas-02).
		score ^= score >> 30
		score *= 0xbf58476d1ce4e5b9
		score ^= score >> 27
		score *= 0x94d049bb133111eb
		score ^= score >> 31
		if i == 0 || score > bestScore || (score == bestScore && nodeID < bestNode) {
			bestScore = score
			bestNode = nodeID
		}
	}
	return bestNode
}

// CopyStream copies from src to dst using a pooled 256 KiB buffer, optionally updating a hasher,
// applying rate limiting, and invoking onChunk after each written chunk.
func CopyStream(ctx context.Context, dst io.Writer, src io.Reader, limiter *RateLimiter, onChunk func(n int64)) (int64, string, error) {
	bufPtr := GetBuf()
	defer PutBuf(bufPtr)
	buf := *bufPtr

	h := sha256.New()
	var total int64

	for {
		if err := ctx.Err(); err != nil {
			return total, "", err
		}
		nr, rErr := src.Read(buf)
		if nr > 0 {
			if limiter != nil {
				if err := limiter.Wait(ctx, nr); err != nil {
					return total, "", err
				}
			}
			chunk := buf[:nr]
			nw, wErr := dst.Write(chunk)
			if nw > 0 {
				_, _ = h.Write(chunk[:nw])
				total += int64(nw)
				if onChunk != nil {
					onChunk(int64(nw))
				}
			}
			if wErr != nil {
				return total, "", wErr
			}
			if nw != nr {
				return total, "", io.ErrShortWrite
			}
		}
		if rErr == io.EOF {
			return total, hex.EncodeToString(h.Sum(nil)), nil
		}
		if rErr != nil {
			return total, "", rErr
		}
	}
}

// HashFile computes the size and SHA256 hex digest of a file using a fixed 256 KiB buffer.
func HashFile(ctx context.Context, filePath string) (int64, string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()

	bufPtr := GetBuf()
	defer PutBuf(bufPtr)
	buf := *bufPtr

	h := sha256.New()
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, "", err
		}
		nr, rErr := f.Read(buf)
		if nr > 0 {
			_, _ = h.Write(buf[:nr])
			total += int64(nr)
		}
		if rErr == io.EOF {
			return total, hex.EncodeToString(h.Sum(nil)), nil
		}
		if rErr != nil {
			return total, "", rErr
		}
	}
}

// SanitizeRelativePath validates and normalizes a relative file path to prevent path traversal.
func SanitizeRelativePath(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("empty filename")
	}
	if strings.ContainsRune(raw, 0) {
		return "", errors.New("filename contains null byte")
	}
	// Normalize backslashes to forward slashes before validating.
	normalized := strings.ReplaceAll(raw, "\\", "/")
	if strings.HasPrefix(normalized, "/") {
		return "", fmt.Errorf("absolute path not allowed: %q", raw)
	}
	for _, seg := range strings.Split(normalized, "/") {
		if seg == ".." {
			return "", fmt.Errorf("path traversal not allowed: %q", raw)
		}
	}
	cleaned := path.Clean(normalized)
	if cleaned == "." || cleaned == "/" || cleaned == ".." || strings.HasPrefix(cleaned, "../") || strings.HasPrefix(cleaned, "/") {
		return "", fmt.Errorf("invalid filename: %q", raw)
	}
	return cleaned, nil
}

// SafeJoin joins baseDir and a sanitized relative path and guarantees the result stays inside baseDir.
func SafeJoin(baseDir, relPath string) (string, error) {
	cleanRel, err := SanitizeRelativePath(relPath)
	if err != nil {
		return "", err
	}
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return "", err
	}
	target := filepath.Join(absBase, filepath.FromSlash(cleanRel))
	rel, err := filepath.Rel(absBase, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("target path escapes base directory: %q", relPath)
	}
	return target, nil
}

// DiskUsage returns total bytes, available (free to unprivileged user) bytes, and used percentage.
func DiskUsage(dir string) (totalBytes uint64, freeBytes uint64, usedPct float64, err error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, 0, 0, err
	}
	bsize := uint64(st.Bsize)
	total := st.Blocks * bsize
	avail := st.Bavail * bsize
	var pct float64
	if total > 0 {
		used := total - avail
		pct = (float64(used) / float64(total)) * 100.0
	}
	return total, avail, pct, nil
}

// SyncDir fsyncs a directory entry so atomic renames inside it are durable against power loss.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	_ = d.Close()
	return err
}
