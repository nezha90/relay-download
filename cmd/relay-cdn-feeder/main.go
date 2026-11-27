package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	bolt "go.etcd.io/bbolt"

	"relay-download/internal/agenta"
	"relay-download/internal/protocol"
	"relay-download/internal/version"
)

var bucketPushed = []byte("pushed_items")

type ManifestItem struct {
	Filename string `json:"filename"`
	URL      string `json:"url"`
	Size     int64  `json:"size,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
	ETag     string `json:"etag,omitempty"`
}

type checkpointStore struct {
	db *bolt.DB
}

func openCheckpoint(path string) (*checkpointStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucketPushed)
		return err
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &checkpointStore{db: db}, nil
}

func (c *checkpointStore) Close() error { return c.db.Close() }

func (c *checkpointStore) IsPushed(filename string, expectedSize int64) bool {
	var ok bool
	_ = c.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketPushed).Get([]byte(filename))
		if v == nil {
			return nil
		}
		if expectedSize <= 0 {
			ok = true
			return nil
		}
		parts := strings.SplitN(string(v), "|", 2)
		if len(parts) >= 1 && parts[0] == strconv.FormatInt(expectedSize, 10) {
			ok = true
		}
		return nil
	})
	return ok
}

func (c *checkpointStore) MarkPushed(filename string, size int64, shaHex string) error {
	val := fmt.Sprintf("%d|%s", size, shaHex)
	return c.db.Batch(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketPushed).Put([]byte(filename), []byte(val))
	})
}

func loadManifest(path string) ([]ManifestItem, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var items []ManifestItem
	seen := make(map[string]struct{})
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var it ManifestItem
		if err := json.Unmarshal([]byte(line), &it); err != nil {
			return nil, fmt.Errorf("manifest line %d: %w", lineNo, err)
		}
		it.Filename = strings.TrimLeft(strings.TrimSpace(it.Filename), "/")
		it.URL = strings.TrimSpace(it.URL)
		if it.Filename == "" || it.URL == "" {
			return nil, fmt.Errorf("manifest line %d: filename and url are required", lineNo)
		}
		if _, dup := seen[it.Filename]; dup {
			continue
		}
		seen[it.Filename] = struct{}{}
		items = append(items, it)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

// stallTimeoutConn refreshes per-read/write deadlines on every active I/O call so
// multi-GB transfers never time out while making progress, yet stalled TCP sockets
// fail fast and trigger seamless HTTP Range resume.
type stallTimeoutConn struct {
	net.Conn
	readTimeout  time.Duration
	writeTimeout time.Duration
}

func (c *stallTimeoutConn) Read(p []byte) (int, error) {
	if c.readTimeout > 0 {
		_ = c.Conn.SetReadDeadline(time.Now().Add(c.readTimeout))
	}
	return c.Conn.Read(p)
}

func (c *stallTimeoutConn) Write(p []byte) (int, error) {
	if c.writeTimeout > 0 {
		_ = c.Conn.SetWriteDeadline(time.Now().Add(c.writeTimeout))
	}
	return c.Conn.Write(p)
}

func newCDNHTTPClient(readIdleTimeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout:   20 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return &stallTimeoutConn{
				Conn:         conn,
				readTimeout:  readIdleTimeout,
				writeTimeout: 30 * time.Second,
			}, nil
		},
		ForceAttemptHTTP2:     false, // HTTP/1.1 avoids single-conn HTTP/2 HOL blocking across large parallel video streams
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   20 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ReadBufferSize:        1 << 20,
	}
	return &http.Client{Transport: tr}
}

func newLocalHTTPClient() *http.Client {
	tr := &http.Transport{
		Proxy:               nil, // strictly never route 127.0.0.1 through system http_proxy
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 64,
		IdleConnTimeout:     90 * time.Second,
		WriteBufferSize:     1 << 20,
	}
	return &http.Client{Transport: tr}
}

// resumableCDNReader streams a remote CDN object into an HTTP PUT request body,
// computing SHA-256 on the fly and seamlessly recovering from mid-stream CDN drops
// using HTTP Range + If-Match without restarting multi-GB downloads from byte 0.
type resumableCDNReader struct {
	ctx        context.Context
	client     *http.Client
	url        string
	logger     *slog.Logger
	expectedSz int64
	totalSize  int64
	etag       string
	maxResumes int

	body      io.ReadCloser
	offset    int64
	resumes   int
	hasher    hash.Hash
	done      bool
	closed    bool
	onBytesFn func(n int64)
}

func openResumableCDN(
	ctx context.Context,
	client *http.Client,
	rawURL string,
	expectedSize int64,
	maxResumes int,
	logger *slog.Logger,
	onBytes func(n int64),
) (*resumableCDNReader, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		_ = resp.Body.Close()
		return nil, fmt.Errorf("cdn GET HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	totalSize := expectedSize
	if resp.ContentLength > 0 {
		if expectedSize > 0 && resp.ContentLength != expectedSize {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("cdn content-length mismatch: expected %d got %d", expectedSize, resp.ContentLength)
		}
		if totalSize <= 0 {
			totalSize = resp.ContentLength
		}
	}
	if maxResumes <= 0 {
		maxResumes = 12
	}
	return &resumableCDNReader{
		ctx:        ctx,
		client:     client,
		url:        rawURL,
		logger:     logger,
		expectedSz: expectedSize,
		totalSize:  totalSize,
		etag:       strings.TrimSpace(resp.Header.Get("ETag")),
		maxResumes: maxResumes,
		body:       resp.Body,
		hasher:     sha256.New(),
		onBytesFn:  onBytes,
	}, nil
}

func (r *resumableCDNReader) TotalSize() int64 { return r.totalSize }
func (r *resumableCDNReader) BytesRead() int64 { return r.offset }
func (r *resumableCDNReader) SHA256() string   { return hex.EncodeToString(r.hasher.Sum(nil)) }

func (r *resumableCDNReader) Close() error {
	r.closed = true
	if r.body != nil {
		err := r.body.Close()
		r.body = nil
		return err
	}
	return nil
}

func (r *resumableCDNReader) reopenAtOffset() error {
	if r.body != nil {
		_ = r.body.Close()
		r.body = nil
	}
	backoff := 500 * time.Millisecond
	var lastErr error
	for r.resumes < r.maxResumes {
		if r.ctx.Err() != nil {
			return r.ctx.Err()
		}
		r.resumes++
		if r.logger != nil {
			r.logger.Warn("cdn stream interrupted, resuming with Range",
				"url", r.url, "offset", r.offset, "total", r.totalSize, "resume_attempt", r.resumes)
		}
		req, err := http.NewRequestWithContext(r.ctx, http.MethodGet, r.url, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", r.offset))
		if r.etag != "" {
			req.Header.Set("If-Match", r.etag)
		}
		resp, err := r.client.Do(req)
		if err == nil {
			if resp.StatusCode == http.StatusPartialContent {
				cr := strings.TrimSpace(resp.Header.Get("Content-Range"))
				wantPrefix := fmt.Sprintf("bytes %d-", r.offset)
				if strings.HasPrefix(cr, wantPrefix) {
					r.body = resp.Body
					return nil
				}
				_ = resp.Body.Close()
				return fmt.Errorf("cdn unexpected Content-Range %q (want prefix %q)", cr, wantPrefix)
			}
			snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusPreconditionFailed || resp.StatusCode == http.StatusRequestedRangeNotSatisfiable {
				return fmt.Errorf("cdn resume rejected HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
			}
			lastErr = fmt.Errorf("cdn Range GET HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
		} else {
			lastErr = err
		}

		t := time.NewTimer(backoff)
		select {
		case <-r.ctx.Done():
			t.Stop()
			return r.ctx.Err()
		case <-t.C:
		}
		backoff *= 2
		if backoff > 8*time.Second {
			backoff = 8 * time.Second
		}
	}
	if lastErr == nil {
		lastErr = io.ErrUnexpectedEOF
	}
	return fmt.Errorf("exhausted %d CDN range resumes at offset %d/%d: %w", r.maxResumes, r.offset, r.totalSize, lastErr)
}

func (r *resumableCDNReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	if r.closed {
		return 0, io.ErrClosedPipe
	}
	for {
		if r.ctx.Err() != nil {
			return 0, r.ctx.Err()
		}
		if r.body == nil {
			if err := r.reopenAtOffset(); err != nil {
				return 0, err
			}
		}
		n, err := r.body.Read(p)
		if n > 0 {
			if r.totalSize > 0 && r.offset+int64(n) > r.totalSize {
				return 0, fmt.Errorf("cdn returned more bytes than expected (%d > %d)", r.offset+int64(n), r.totalSize)
			}
			_, _ = r.hasher.Write(p[:n])
			r.offset += int64(n)
			if r.onBytesFn != nil {
				r.onBytesFn(int64(n))
			}
			if r.totalSize > 0 && r.offset == r.totalSize && (err == nil || errors.Is(err, io.EOF)) {
				r.done = true
				return n, nil
			}
			return n, nil
		}
		if errors.Is(err, io.EOF) {
			if r.totalSize <= 0 || r.offset == r.totalSize {
				r.done = true
				return 0, io.EOF
			}
			// Premature EOF before totalSize -> attempt Range resume!
			if rErr := r.reopenAtOffset(); rErr != nil {
				return 0, rErr
			}
			continue
		}
		if err != nil {
			if r.totalSize > 0 && r.offset > 0 && r.offset < r.totalSize {
				if rErr := r.reopenAtOffset(); rErr != nil {
					return 0, rErr
				}
				continue
			}
			return 0, err
		}
	}
}

type feeder struct {
	cdnClient     *http.Client
	localClient   *http.Client
	store         *checkpointStore
	logger        *slog.Logger
	project       string
	projectName   string
	customers     string
	agentAURL     string
	localToken    string
	concurrency   int
	maxQueueFiles int
	maxQueueBytes int64
	maxResumes    int
	maxAttempts   int

	pushedCount   atomic.Int64
	skippedCount  atomic.Int64
	failedCount   atomic.Int64
	pushedBytes   atomic.Int64
	streamedBytes atomic.Int64
	inFlightFiles atomic.Int64
	inFlightBytes atomic.Int64
	lastQueueF    atomic.Int64
	lastQueueB    atomic.Int64
}

func (f *feeder) queryAgentAStatus(ctx context.Context) (*protocol.LiveFilesResp, error) {
	u := strings.TrimRight(f.agentAURL, "/") + "/local/v1/status?summary=1"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if f.localToken != "" {
		req.Header.Set(protocol.HeaderLocalToken, f.localToken)
	}
	resp, err := f.localClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agent-a status HTTP %d", resp.StatusCode)
	}
	var out protocol.LiveFilesResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	f.lastQueueF.Store(int64(out.TotalFiles))
	f.lastQueueB.Store(out.ReadyBytes + out.ClaimedBytes)
	return &out, nil
}

func (f *feeder) waitForBackpressure(ctx context.Context, nextSize int64) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		st, err := f.queryAgentAStatus(ctx)
		if err != nil {
			f.logger.Warn("agent-a status check failed, retrying", "err", err)
		} else {
			curFiles := int64(st.TotalFiles) + f.inFlightFiles.Load()
			curBytes := st.ReadyBytes + st.ClaimedBytes + f.inFlightBytes.Load()
			filesOK := f.maxQueueFiles <= 0 || curFiles < int64(f.maxQueueFiles)
			// Always allow at least 1 file in flight if agent-a itself has no disk alarm and queue is below cap,
			// even if a single video is very large.
			bytesOK := f.maxQueueBytes <= 0 ||
				(curBytes+nextSize <= f.maxQueueBytes) ||
				(f.inFlightFiles.Load() == 0 && (st.ReadyBytes+st.ClaimedBytes) < f.maxQueueBytes)
			if !st.DiskAlarm && filesOK && bytesOK {
				return nil
			}
		}
		t := time.NewTimer(1 * time.Second)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

func encodeRelativePath(rel string) string {
	segs := strings.Split(rel, "/")
	for i, seg := range segs {
		segs[i] = url.PathEscape(seg)
	}
	return strings.Join(segs, "/")
}

func (f *feeder) buildTargetURL(filename string) string {
	u := fmt.Sprintf("%s/local/v1/files/%s/%s",
		strings.TrimRight(f.agentAURL, "/"),
		url.PathEscape(f.project),
		encodeRelativePath(filename),
	)
	if f.projectName != "" {
		u += "?project_name=" + url.QueryEscape(f.projectName)
	}
	return u
}

func (f *feeder) pushItem(ctx context.Context, item ManifestItem) error {
	if f.store.IsPushed(item.Filename, item.Size) {
		f.skippedCount.Add(1)
		return nil
	}

	targetURL := f.buildTargetURL(item.Filename)
	maxAttempts := f.maxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 6
	}
	backoff := 2 * time.Second
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := f.waitForBackpressure(ctx, item.Size); err != nil {
			return err
		}

		f.inFlightFiles.Add(1)
		f.inFlightBytes.Add(item.Size)

		reader, openErr := openResumableCDN(ctx, f.cdnClient, item.URL, item.Size, f.maxResumes, f.logger, func(n int64) {
			f.streamedBytes.Add(n)
		})
		if openErr != nil {
			f.inFlightFiles.Add(-1)
			f.inFlightBytes.Add(-item.Size)
			f.logger.Warn("open CDN stream failed, retrying", "filename", item.Filename, "attempt", attempt, "err", openErr)
		} else {
			putReq, reqErr := http.NewRequestWithContext(ctx, http.MethodPut, targetURL, reader)
			if reqErr != nil {
				_ = reader.Close()
				f.inFlightFiles.Add(-1)
				f.inFlightBytes.Add(-item.Size)
				return reqErr
			}
			if reader.TotalSize() > 0 {
				putReq.ContentLength = reader.TotalSize()
			}
			putReq.Header.Set("Content-Type", "application/octet-stream")
			if f.localToken != "" {
				putReq.Header.Set(protocol.HeaderLocalToken, f.localToken)
			}
			if f.customers != "" {
				putReq.Header.Set(protocol.HeaderCustomer, f.customers)
			}
			if item.SHA256 != "" {
				putReq.Header.Set(protocol.HeaderExpectedSHA256, item.SHA256)
			}

			putResp, putErr := f.localClient.Do(putReq)
			_ = reader.Close()
			f.inFlightFiles.Add(-1)
			f.inFlightBytes.Add(-item.Size)

			if putErr != nil {
				f.logger.Warn("PUT to agent-a failed, retrying", "filename", item.Filename, "attempt", attempt, "bytes_sent", reader.BytesRead(), "err", putErr)
			} else {
				respBody, _ := io.ReadAll(io.LimitReader(putResp.Body, 4096))
				_ = putResp.Body.Close()

				if putResp.StatusCode == http.StatusOK {
					var upResp protocol.LocalUploadResp
					if err := json.Unmarshal(respBody, &upResp); err != nil {
						f.logger.Warn("invalid JSON response from agent-a, retrying", "filename", item.Filename, "err", err)
					} else {
						wantSize := item.Size
						if wantSize <= 0 {
							wantSize = reader.BytesRead()
						}
						streamSHA := reader.SHA256()
						if upResp.Size != wantSize || upResp.Size != reader.BytesRead() {
							f.logger.Error("size mismatch after PUT, retrying", "filename", item.Filename, "want", wantSize, "streamed", reader.BytesRead(), "got", upResp.Size)
						} else if !strings.EqualFold(upResp.SHA256, streamSHA) {
							f.logger.Error("sha256 mismatch after PUT, retrying", "filename", item.Filename, "stream_sha", streamSHA, "agent_sha", upResp.SHA256)
						} else if item.SHA256 != "" && !strings.EqualFold(upResp.SHA256, item.SHA256) {
							f.logger.Error("manifest sha256 mismatch, retrying", "filename", item.Filename, "manifest_sha", item.SHA256, "got", upResp.SHA256)
						} else {
							if err := f.store.MarkPushed(item.Filename, upResp.Size, upResp.SHA256); err != nil {
								return fmt.Errorf("save checkpoint %s: %w", item.Filename, err)
							}
							f.pushedCount.Add(1)
							f.pushedBytes.Add(upResp.Size)
							f.logger.Info("file transferred CDN -> agent-a READY",
								"filename", item.Filename,
								"size_MB", fmt.Sprintf("%.2f", float64(upResp.Size)/(1024*1024)),
								"sha256", upResp.SHA256[:12],
								"customers", upResp.CustomerIDs,
							)
							return nil
						}
					}
				} else if putResp.StatusCode == http.StatusInsufficientStorage || putResp.StatusCode == http.StatusServiceUnavailable {
					f.logger.Warn("agent-a backpressure, pausing before retry", "filename", item.Filename, "status", putResp.StatusCode, "body", strings.TrimSpace(string(respBody)))
					if err := f.waitForBackpressure(ctx, item.Size); err != nil {
						return err
					}
					if attempt > 1 {
						attempt--
					}
					continue
				} else {
					f.logger.Warn("agent-a PUT non-200, retrying", "filename", item.Filename, "status", putResp.StatusCode, "body", strings.TrimSpace(string(respBody)), "attempt", attempt)
				}
			}
		}

		t := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
		backoff *= 2
		if backoff > 20*time.Second {
			backoff = 20 * time.Second
		}
	}
	f.failedCount.Add(1)
	return fmt.Errorf("exhausted %d retries for %s", maxAttempts, item.Filename)
}

func (f *feeder) run(ctx context.Context, items []ManifestItem) error {
	var totalBytes int64
	for _, it := range items {
		totalBytes += it.Size
	}

	jobs := make(chan ManifestItem, f.concurrency*2)
	var wg sync.WaitGroup
	for i := 0; i < f.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range jobs {
				if ctx.Err() != nil {
					return
				}
				if err := f.pushItem(ctx, it); err != nil && !errors.Is(err, context.Canceled) {
					f.logger.Error("cdn feed item failed", "filename", it.Filename, "err", err)
				}
			}
		}()
	}

	stopLog := make(chan struct{})
	startAt := time.Now()
	var prevStreamed int64
	prevAt := startAt
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopLog:
				return
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				curStreamed := f.streamedBytes.Load()
				dt := now.Sub(prevAt).Seconds()
				mbps := 0.0
				if dt > 0 {
					mbps = float64(curStreamed-prevStreamed) / (1024 * 1024) / dt
				}
				prevStreamed = curStreamed
				prevAt = now
				_, _ = f.queryAgentAStatus(ctx)
				f.logger.Info("cdn feeder progress",
					"pushed", f.pushedCount.Load(),
					"skipped", f.skippedCount.Load(),
					"failed", f.failedCount.Load(),
					"total", len(items),
					"pushed_GB", fmt.Sprintf("%.2f", float64(f.pushedBytes.Load())/(1024*1024*1024)),
					"target_GB", fmt.Sprintf("%.2f", float64(totalBytes)/(1024*1024*1024)),
					"cdn_rate_MBps", fmt.Sprintf("%.1f", mbps),
					"in_flight", f.inFlightFiles.Load(),
					"agent_a_queue_files", f.lastQueueF.Load(),
					"agent_a_queue_GB", fmt.Sprintf("%.2f", float64(f.lastQueueB.Load())/(1024*1024*1024)),
				)
			}
		}
	}()

feedLoop:
	for _, it := range items {
		if ctx.Err() != nil {
			break
		}
		if f.store.IsPushed(it.Filename, it.Size) {
			f.skippedCount.Add(1)
			continue
		}
		select {
		case jobs <- it:
		case <-ctx.Done():
			break feedLoop
		}
	}

	close(jobs)
	wg.Wait()
	close(stopLog)

	f.logger.Info("cdn feeder pass complete",
		"pushed", f.pushedCount.Load(),
		"skipped", f.skippedCount.Load(),
		"failed", f.failedCount.Load(),
		"total", len(items),
		"pushed_GB", fmt.Sprintf("%.2f", float64(f.pushedBytes.Load())/(1024*1024*1024)),
		"elapsed", time.Since(startAt).Round(time.Second).String(),
	)
	if f.failedCount.Load() > 0 {
		return fmt.Errorf("%d files failed transfer", f.failedCount.Load())
	}
	return nil
}

func main() {
	var (
		showVersion     = flag.Bool("version", false, "print version and exit")
		manifestPath    = flag.String("manifest", "", "path to JSONL manifest ({filename, url, size})")
		projectID       = flag.String("project", "", "Relay project ID")
		projectName     = flag.String("project-name", "", "optional initial project display name on first auto-creation")
		customers       = flag.String("customers", "", "optional comma-separated customer account IDs for first auto-creation")
		agentAURL       = flag.String("agent-a-url", "", "Agent A local HTTP base URL (e.g. http://127.0.0.1:18445)")
		localToken      = flag.String("local-token", "", "optional Agent A X-Local-Token (only needed if require_local_token is enabled)")
		agentAConfig    = flag.String("agent-a-config", "", "path to agent-a.yaml to auto-load local_listen and local_token")
		stateDB         = flag.String("state-db", "./cdn-feeder-state.db", "BoltDB checkpoint file path")
		concurrency     = flag.Int("concurrency", 6, "concurrent CDN -> Agent-A PUT workers")
		maxQueueFiles   = flag.Int("max-queue-files", 30, "pause feeding when Agent A spool + in-flight reaches this many files")
		maxQueueGB      = flag.Float64("max-queue-gb", 80.0, "pause feeding when Agent A spool + in-flight reaches this many GB")
		cdnReadIdleSec  = flag.Int("cdn-read-idle-sec", 45, "per-read stall timeout (seconds) before triggering HTTP Range resume")
		maxRangeResumes = flag.Int("max-range-resumes", 12, "max mid-stream HTTP Range resume attempts per file attempt")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version.String("relay-cdn-feeder"))
		return
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	aURL, tok := *agentAURL, *localToken
	if *agentAConfig != "" {
		aCfg, err := agenta.LoadConfig(*agentAConfig)
		if err != nil {
			logger.Error("load agent-a config failed", "err", err)
			os.Exit(1)
		}
		if aURL == "" {
			aURL = "http://" + aCfg.LocalListen
		}
		if tok == "" && aCfg.RequireLocalToken {
			tok = aCfg.LocalToken
		}
	}

	if *manifestPath == "" || *projectID == "" || aURL == "" {
		logger.Error("required flags missing: -manifest, -project, and (-agent-a-config or -agent-a-url)")
		os.Exit(2)
	}
	if *concurrency <= 0 {
		*concurrency = 6
	}
	if *cdnReadIdleSec <= 0 {
		*cdnReadIdleSec = 45
	}

	items, err := loadManifest(*manifestPath)
	if err != nil {
		logger.Error("load manifest failed", "path", *manifestPath, "err", err)
		os.Exit(1)
	}
	st, err := openCheckpoint(*stateDB)
	if err != nil {
		logger.Error("open checkpoint db failed", "path", *stateDB, "err", err)
		os.Exit(1)
	}
	defer st.Close()

	f := &feeder{
		cdnClient:     newCDNHTTPClient(time.Duration(*cdnReadIdleSec) * time.Second),
		localClient:   newLocalHTTPClient(),
		store:         st,
		logger:        logger,
		project:       strings.TrimSpace(*projectID),
		projectName:   strings.TrimSpace(*projectName),
		customers:     strings.TrimSpace(*customers),
		agentAURL:     aURL,
		localToken:    tok,
		concurrency:   *concurrency,
		maxQueueFiles: *maxQueueFiles,
		maxQueueBytes: int64(*maxQueueGB * 1024 * 1024 * 1024),
		maxResumes:    *maxRangeResumes,
		maxAttempts:   6,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger.Info("starting read-only CDN -> Agent-A HTTP PUT feeder",
		"manifest", *manifestPath,
		"items", len(items),
		"project", f.project,
		"project_name", f.projectName,
		"customers", f.customers,
		"agent_a", aURL,
		"concurrency", *concurrency,
		"max_queue_files", *maxQueueFiles,
		"max_queue_gb", *maxQueueGB,
	)

	if err := f.run(ctx, items); err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(0)
		}
		logger.Error("cdn feeder finished with errors", "err", err)
		os.Exit(1)
	}
}
