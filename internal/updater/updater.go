package updater

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"relay-download/internal/protocol"
	"relay-download/internal/transfer"
	"relay-download/internal/version"
)

// Options configures a self-updating agent helper.
type Options struct {
	Component    string // "relay-agent-a" | "relay-agent-b"
	NodeID       string
	CenterURL    string
	CenterToken  string
	HTTPClient   *http.Client
	Logger       *slog.Logger
	ExePath      string               // optional override for tests; defaults to os.Executable()
	OnStatusSync func()               // optional callback to trigger immediate heartbeat
	OnRestart    func(targetVer string) // called after atomic binary replacement; triggers graceful exit
}

// Updater coordinates safe, SHA256-verified, self-checked atomic binary replacement.
type Updater struct {
	opts Options

	mu      sync.Mutex
	running bool
	status  string
	errMsg  string
	lastVer string
}

func New(opts Options) *Updater {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Updater{opts: opts}
}

func (u *Updater) Status() (attemptID, status, errMsg string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.lastVer, u.status, u.errMsg
}

func (u *Updater) setState(status, errMsg string) {
	u.mu.Lock()
	u.status = status
	u.errMsg = errMsg
	u.mu.Unlock()
	if u.opts.OnStatusSync != nil {
		u.opts.OnStatusSync()
	}
}

// HandleDirective inspects a heartbeat UpgradeDirective and launches an async self-upgrade if needed.
func (u *Updater) HandleDirective(ctx context.Context, d *protocol.UpgradeDirective) {
	if d == nil || d.Version == "" || d.DownloadURL == "" || d.SHA256 == "" {
		return
	}
	if d.Version == version.Version {
		return
	}
	u.mu.Lock()
	if u.running {
		u.mu.Unlock()
		return
	}
	// Do not loop infinitely if the exact same upgrade attempt already failed once; operator can re-trigger to retry.
	attemptKey := d.AttemptID
	if attemptKey == "" {
		attemptKey = d.ReleaseID
	}
	if u.status == "failed" && u.lastVer == attemptKey {
		u.mu.Unlock()
		return
	}
	u.running = true
	u.lastVer = attemptKey
	u.status = "downloading"
	u.errMsg = ""
	u.mu.Unlock()

	if u.opts.OnStatusSync != nil {
		u.opts.OnStatusSync()
	}

	go func() {
		err := u.apply(ctx, *d)
		if err != nil {
			u.opts.Logger.Error("self-upgrade failed", "target_version", d.Version, "err", err)
			u.mu.Lock()
			u.running = false
			u.status = "failed"
			u.errMsg = err.Error()
			u.mu.Unlock()
			if u.opts.OnStatusSync != nil {
				u.opts.OnStatusSync()
			}
			return
		}
		u.mu.Lock()
		u.status = "restarting"
		u.errMsg = ""
		u.mu.Unlock()
		if u.opts.OnStatusSync != nil {
			u.opts.OnStatusSync()
		}
		// Give the final status heartbeat a brief moment to flush before graceful exit.
		select {
		case <-ctx.Done():
		case <-time.After(400 * time.Millisecond):
		}
		if u.opts.OnRestart != nil {
			u.opts.OnRestart(d.Version)
		}
	}()
}

func (u *Updater) apply(ctx context.Context, d protocol.UpgradeDirective) error {
	exePath := u.opts.ExePath
	if exePath == "" {
		var err error
		exePath, err = os.Executable()
		if err != nil {
			return fmt.Errorf("resolve executable path: %w", err)
		}
		if resolved, err := filepath.EvalSymlinks(exePath); err == nil {
			exePath = resolved
		}
	}

	dlURL := strings.TrimSpace(d.DownloadURL)
	// Security invariant: only pull releases from a relative /api/v1/releases/... path on the configured CenterURL
	// to prevent SSRF or exfiltrating CenterToken to untrusted hosts.
	if !isSafeReleaseDownloadPath(dlURL) {
		return fmt.Errorf("refusing untrusted upgrade download_url %q", dlURL)
	}
	dlURL = strings.TrimRight(u.opts.CenterURL, "/") + dlURL

	dlCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(dlCtx, http.MethodGet, dlURL, nil)
	if err != nil {
		return fmt.Errorf("build download request: %w", err)
	}
	req.Header.Set(protocol.HeaderNodeID, u.opts.NodeID)
	req.Header.Set(protocol.HeaderNodeToken, u.opts.CenterToken)

	resp, err := u.opts.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("download release: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("download release returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	tmpPath := filepath.Join(filepath.Dir(exePath), fmt.Sprintf(".%s.upgrade.%d.tmp", u.opts.Component, os.Getpid()))
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("create staging binary: %w", err)
	}
	_, actualSHA, copyErr := transfer.CopyStream(dlCtx, f, resp.Body, nil, nil)
	syncErr := f.Sync()
	closeErr := f.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write staging binary: %v %v %v", copyErr, syncErr, closeErr)
	}

	if !strings.EqualFold(strings.TrimSpace(d.SHA256), actualSHA) {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("sha256 mismatch: expected %s got %s", d.SHA256, actualSHA)
	}
	if err := os.Chmod(tmpPath, 0o755); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("chmod staging binary: %w", err)
	}

	// Self-check new binary before atomic swap to guarantee arch/binary integrity and prevent bricking.
	checkCtx, checkCancel := context.WithTimeout(ctx, 10*time.Second)
	defer checkCancel()
	out, err := exec.CommandContext(checkCtx, tmpPath, "-version").CombinedOutput()
	if err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("new binary self-check (-version) failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	if u.opts.Component != "" && !strings.Contains(string(out), u.opts.Component) {
		_ = os.Remove(tmpPath)
		return errors.New("new binary self-check output does not match component " + u.opts.Component)
	}

	if err := os.Rename(tmpPath, exePath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("atomic replace binary %s: %w", exePath, err)
	}

	u.opts.Logger.Info("binary atomically upgraded, scheduling restart", "version", d.Version, "path", exePath)
	return nil
}

func isSafeReleaseDownloadPath(p string) bool {
	if !strings.HasPrefix(p, "/api/v1/releases/") || strings.HasPrefix(p, "//") {
		return false
	}
	if strings.Contains(p, "..") || strings.ContainsAny(p, "\\?#@ \t\r\n\x00") {
		return false
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return len(p) > len("/api/v1/releases/")
}
