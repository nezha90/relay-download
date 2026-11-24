package transfer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const BufSize = 256 * 1024 // 256 KiB fixed streaming buffer

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

// RateLimiter is a simple token-bucket byte rate limiter safe for concurrent use.
type RateLimiter struct {
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
	burst := float64(bytesPerSec)
	if burst < float64(BufSize) {
		burst = float64(BufSize)
	}
	return &RateLimiter{
		bytesPerSec: float64(bytesPerSec),
		burst:       burst,
		tokens:      burst,
		last:        time.Now(),
	}
}

func (r *RateLimiter) Wait(ctx context.Context, n int) error {
	if r == nil || n <= 0 {
		return nil
	}
	for {
		r.mu.Lock()
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
		timer := time.NewTimer(waitDur)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
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
