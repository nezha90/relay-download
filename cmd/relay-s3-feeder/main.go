package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	bolt "go.etcd.io/bbolt"

	"relay-download/internal/agenta"
	"relay-download/internal/protocol"
	"relay-download/internal/s3client"
	"relay-download/internal/version"
)

var bucketPushed = []byte("pushed_keys")

type seaweedS3Config struct {
	Identities []struct {
		Name        string `json:"name"`
		Credentials []struct {
			AccessKey string `json:"accessKey"`
			SecretKey string `json:"secretKey"`
		} `json:"credentials"`
	} `json:"identities"`
}

func loadSeaweedCreds(path, identity string) (string, string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
	}
	var cfg seaweedS3Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return "", "", fmt.Errorf("parse s3.json: %w", err)
	}
	for _, id := range cfg.Identities {
		if id.Name == identity && len(id.Credentials) > 0 {
			return id.Credentials[0].AccessKey, id.Credentials[0].SecretKey, nil
		}
	}
	return "", "", fmt.Errorf("identity %q with credentials not found in %s", identity, path)
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

func objStamp(obj s3client.ObjectInfo) string {
	return fmt.Sprintf("%d|%s", obj.Size, obj.ETag)
}

func (c *checkpointStore) IsPushed(key, stamp string) bool {
	var ok bool
	_ = c.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketPushed).Get([]byte(key))
		if v != nil && string(v) == stamp {
			ok = true
		}
		return nil
	})
	return ok
}

func (c *checkpointStore) MarkPushed(key, stamp string) error {
	return c.db.Batch(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketPushed).Put([]byte(key), []byte(stamp))
	})
}

// ResumeStartAfter returns a safe S3 start-after cursor by seeking to the lexicographically
// last pushed key matching prefix in BoltDB and stepping back overlap keys so in-flight
// out-of-order workers from a prior run can never be skipped.
func (c *checkpointStore) ResumeStartAfter(prefix string, overlap int) string {
	var startAfter string
	_ = c.db.View(func(tx *bolt.Tx) error {
		cur := tx.Bucket(bucketPushed).Cursor()
		k, _ := cur.Last()
		for k != nil && !strings.HasPrefix(string(k), prefix) {
			k, _ = cur.Prev()
		}
		if k == nil {
			return nil
		}
		for i := 0; i < overlap; i++ {
			prevK, _ := cur.Prev()
			if prevK == nil || !strings.HasPrefix(string(prevK), prefix) {
				return nil // fewer than overlap keys pushed -> scan from beginning
			}
			k = prevK
		}
		startAfter = string(k)
		return nil
	})
	return startAfter
}

type feeder struct {
	s3             *s3client.ReadOnlyClient
	httpClient     *http.Client
	store          *checkpointStore
	logger         *slog.Logger
	bucket         string
	prefix         string
	project        string
	agentAURL      string
	localToken     string
	concurrency    int
	maxQueueFiles  int
	maxQueueBytes  int64
	minAge         time.Duration
	limit          int64

	pushedCount  atomic.Int64
	skippedCount atomic.Int64
	failedCount  atomic.Int64
	pushedBytes  atomic.Int64
	inFlight     atomic.Int64
	lastQueueF   atomic.Int64
	lastQueueB   atomic.Int64
}

func (f *feeder) queryAgentAStatus(ctx context.Context) (*protocol.LiveFilesResp, error) {
	u := strings.TrimRight(f.agentAURL, "/") + "/local/v1/status?summary=1"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(protocol.HeaderLocalToken, f.localToken)
	resp, err := f.httpClient.Do(req)
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

func (f *feeder) waitForBackpressure(ctx context.Context) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		st, err := f.queryAgentAStatus(ctx)
		if err != nil {
			f.logger.Warn("agent-a status check failed, retrying", "err", err)
		} else {
			curFiles := st.TotalFiles + int(f.inFlight.Load())
			curBytes := st.ReadyBytes + st.ClaimedBytes
			if !st.DiskAlarm &&
				(f.maxQueueFiles <= 0 || curFiles < f.maxQueueFiles) &&
				(f.maxQueueBytes <= 0 || curBytes < f.maxQueueBytes) {
				return nil
			}
		}
		t := time.NewTimer(500 * time.Millisecond)
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

func (f *feeder) pushObject(ctx context.Context, obj s3client.ObjectInfo) error {
	relPath := strings.TrimPrefix(obj.Key, f.prefix)
	relPath = strings.TrimLeft(relPath, "/")
	if relPath == "" || strings.HasSuffix(obj.Key, "/") {
		return nil
	}

	stamp := objStamp(obj)
	if f.store.IsPushed(obj.Key, stamp) {
		f.skippedCount.Add(1)
		return nil
	}

	targetURL := fmt.Sprintf("%s/local/v1/files/%s/%s",
		strings.TrimRight(f.agentAURL, "/"),
		url.PathEscape(f.project),
		encodeRelativePath(relPath),
	)

	backoff := 500 * time.Millisecond
	for attempt := 1; attempt <= 6; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s3Resp, err := f.s3.GetObject(ctx, f.bucket, obj.Key)
		if err != nil {
			f.logger.Warn("s3 GetObject failed, retrying", "key", obj.Key, "attempt", attempt, "err", err)
		} else {
			putReq, reqErr := http.NewRequestWithContext(ctx, http.MethodPut, targetURL, s3Resp.Body)
			if reqErr != nil {
				_ = s3Resp.Body.Close()
				return reqErr
			}
			if obj.Size >= 0 {
				putReq.ContentLength = obj.Size
			}
			putReq.Header.Set(protocol.HeaderLocalToken, f.localToken)
			putReq.Header.Set("Content-Type", "application/octet-stream")

			putResp, putErr := f.httpClient.Do(putReq)
			_ = s3Resp.Body.Close()
			if putErr != nil {
				f.logger.Warn("PUT to agent-a failed, retrying", "key", obj.Key, "attempt", attempt, "err", putErr)
			} else {
				bodySnippet, _ := io.ReadAll(io.LimitReader(putResp.Body, 2048))
				_ = putResp.Body.Close()
				if putResp.StatusCode == http.StatusOK {
					if err := f.store.MarkPushed(obj.Key, stamp); err != nil {
						return fmt.Errorf("checkpoint save %s: %w", obj.Key, err)
					}
					f.pushedCount.Add(1)
					f.pushedBytes.Add(obj.Size)
					return nil
				}
				if putResp.StatusCode == http.StatusInsufficientStorage {
					// Spool watermark reached: pause until drained and retry without counting down hard.
					if err := f.waitForBackpressure(ctx); err != nil {
						return err
					}
					if attempt > 1 {
						attempt--
					}
					continue
				}
				f.logger.Warn("agent-a PUT non-200, retrying", "key", obj.Key, "status", putResp.StatusCode, "body", strings.TrimSpace(string(bodySnippet)), "attempt", attempt)
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
		if backoff > 10*time.Second {
			backoff = 10 * time.Second
		}
	}
	f.failedCount.Add(1)
	return fmt.Errorf("exhausted retries for key %s", obj.Key)
}

func (f *feeder) runPass(ctx context.Context) error {
	jobs := make(chan s3client.ObjectInfo, f.concurrency*2)
	var wg sync.WaitGroup
	for i := 0; i < f.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for obj := range jobs {
				if ctx.Err() != nil {
					return
				}
				f.inFlight.Add(1)
				if err := f.pushObject(ctx, obj); err != nil && !errors.Is(err, context.Canceled) {
					f.logger.Error("object feed failed", "key", obj.Key, "err", err)
				}
				f.inFlight.Add(-1)
			}
		}()
	}

	// Progress reporter.
	stopLog := make(chan struct{})
	startAt := time.Now()
	var prevBytes int64
	prevAt := startAt
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopLog:
				return
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				curBytes := f.pushedBytes.Load()
				dt := now.Sub(prevAt).Seconds()
				mbps := 0.0
				if dt > 0 {
					mbps = float64(curBytes-prevBytes) / (1024 * 1024) / dt
				}
				prevBytes = curBytes
				prevAt = now
				f.logger.Info("feeder progress",
					"pushed", f.pushedCount.Load(),
					"skipped", f.skippedCount.Load(),
					"failed", f.failedCount.Load(),
					"pushed_GB", fmt.Sprintf("%.2f", float64(curBytes)/(1024*1024*1024)),
					"rate_MBps", fmt.Sprintf("%.1f", mbps),
					"agent_a_queue_files", f.lastQueueF.Load(),
					"agent_a_queue_GB", fmt.Sprintf("%.2f", float64(f.lastQueueB.Load())/(1024*1024*1024)),
				)
			}
		}
	}()

	var (
		token      string
		startAfter = f.store.ResumeStartAfter(f.prefix, 128)
		dispatched int64
		listErr    error
	)
	if startAfter != "" {
		f.logger.Info("resuming S3 listing via start-after cursor", "start_after", startAfter)
	}
	checkEvery := 0
listLoop:
	for {
		if ctx.Err() != nil {
			break
		}
		page, err := f.s3.ListObjectsV2From(ctx, f.bucket, f.prefix, token, startAfter, 1000)
		if err != nil {
			listErr = err
			break
		}
		startAfter = "" // only used on first page; subsequent pages use continuation-token
		for _, obj := range page.Objects {
			if ctx.Err() != nil {
				break listLoop
			}
			if strings.HasSuffix(obj.Key, "/") {
				continue
			}
			if f.minAge > 0 && !obj.LastModified.IsZero() && time.Since(obj.LastModified) < f.minAge {
				continue
			}
			if f.store.IsPushed(obj.Key, objStamp(obj)) {
				f.skippedCount.Add(1)
				continue
			}
			if f.limit > 0 && dispatched >= f.limit {
				break listLoop
			}

			// Enforce spool backpressure periodically (every 8 new items or when approaching cap).
			checkEvery++
			if checkEvery >= 8 || f.lastQueueF.Load()+f.inFlight.Load() >= int64(f.maxQueueFiles)-8 {
				checkEvery = 0
				if err := f.waitForBackpressure(ctx); err != nil {
					break listLoop
				}
			}

			select {
			case jobs <- obj:
				dispatched++
			case <-ctx.Done():
				break listLoop
			}
		}
		if !page.IsTruncated || page.NextContinuationToken == "" {
			break
		}
		token = page.NextContinuationToken
	}

	close(jobs)
	wg.Wait()
	close(stopLog)

	f.logger.Info("feeder pass complete",
		"pushed", f.pushedCount.Load(),
		"skipped", f.skippedCount.Load(),
		"failed", f.failedCount.Load(),
		"pushed_GB", fmt.Sprintf("%.2f", float64(f.pushedBytes.Load())/(1024*1024*1024)),
		"elapsed", time.Since(startAt).Round(time.Second).String(),
	)
	return listErr
}

func main() {
	var (
		showVersion    = flag.Bool("version", false, "print version and exit")
		s3Endpoint     = flag.String("s3-endpoint", "http://127.0.0.1:8333", "SeaweedFS / S3 endpoint URL")
		s3Region       = flag.String("s3-region", "us-east-1", "S3 region for SigV4")
		s3Bucket       = flag.String("s3-bucket", "", "S3 bucket name")
		s3Prefix       = flag.String("s3-prefix", "", "S3 key prefix")
		s3AccessKey    = flag.String("s3-access-key", "", "S3 access key (or use -s3-config)")
		s3SecretKey    = flag.String("s3-secret-key", "", "S3 secret key (or use -s3-config)")
		s3ConfigPath   = flag.String("s3-config", "", "path to SeaweedFS s3.json to load credentials safely without CLI exposure")
		s3Identity     = flag.String("s3-identity", "developer", "identity name in SeaweedFS s3.json")
		agentAURL      = flag.String("agent-a-url", "", "Agent A local HTTP base URL (e.g. http://127.0.0.1:18445)")
		localToken     = flag.String("local-token", "", "Agent A X-Local-Token (or use -agent-a-config)")
		agentAConfig   = flag.String("agent-a-config", "", "path to agent-a.yaml to auto-load local_listen and local_token")
		projectID      = flag.String("project", "", "Relay project ID")
		stateDB        = flag.String("state-db", "./feeder-state.db", "BoltDB checkpoint file path")
		concurrency    = flag.Int("concurrency", 8, "concurrent S3->Agent-A PUT workers")
		maxQueueFiles  = flag.Int("max-queue-files", 400, "pause feeding when Agent A spool reaches this many files")
		maxQueueGB     = flag.Float64("max-queue-gb", 15.0, "pause feeding when Agent A spool reaches this many GB")
		minAgeSec      = flag.Int("min-age-sec", 0, "skip objects newer than N seconds")
		limit          = flag.Int64("limit", 0, "optional cap on number of newly pushed objects (0 = unlimited)")
		pollInterval   = flag.Int("poll-interval-sec", 0, "if >0, re-scan S3 every N seconds after pass finishes")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version.String("relay-s3-feeder"))
		return
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	ak, sk := *s3AccessKey, *s3SecretKey
	if *s3ConfigPath != "" && (ak == "" || sk == "") {
		var err error
		ak, sk, err = loadSeaweedCreds(*s3ConfigPath, *s3Identity)
		if err != nil {
			logger.Error("load s3 config failed", "err", err)
			os.Exit(1)
		}
	}

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
		if tok == "" {
			tok = aCfg.LocalToken
		}
	}

	if *s3Bucket == "" || *projectID == "" || aURL == "" || tok == "" {
		logger.Error("required flags missing: -s3-bucket, -project, and (-agent-a-config or -agent-a-url + -local-token)")
		os.Exit(2)
	}
	if *concurrency <= 0 {
		*concurrency = 8
	}

	s3c, err := s3client.NewReadOnly(*s3Endpoint, *s3Region, ak, sk)
	if err != nil {
		logger.Error("init s3 client failed", "err", err)
		os.Exit(1)
	}
	st, err := openCheckpoint(*stateDB)
	if err != nil {
		logger.Error("open checkpoint db failed", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	f := &feeder{
		s3:            s3c,
		httpClient:    &http.Client{Transport: &http.Transport{MaxIdleConns: 64, MaxIdleConnsPerHost: 64, IdleConnTimeout: 90 * time.Second, WriteBufferSize: 1 << 20}},
		store:         st,
		logger:        logger,
		bucket:        *s3Bucket,
		prefix:        *s3Prefix,
		project:       *projectID,
		agentAURL:     aURL,
		localToken:    tok,
		concurrency:   *concurrency,
		maxQueueFiles: *maxQueueFiles,
		maxQueueBytes: int64(*maxQueueGB * 1024 * 1024 * 1024),
		minAge:        time.Duration(*minAgeSec) * time.Second,
		limit:         *limit,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger.Info("starting read-only S3 -> Agent-A HTTP PUT feeder",
		"s3_endpoint", *s3Endpoint,
		"bucket", *s3Bucket,
		"prefix", *s3Prefix,
		"agent_a", aURL,
		"project", *projectID,
		"concurrency", *concurrency,
		"max_queue_files", *maxQueueFiles,
		"max_queue_gb", *maxQueueGB,
		"limit", *limit,
	)

	for {
		if err := f.runPass(ctx); err != nil && !errors.Is(err, context.Canceled) {
			logger.Error("feeder pass error", "err", err)
			if *pollInterval <= 0 {
				os.Exit(1)
			}
		}
		if *pollInterval <= 0 || ctx.Err() != nil {
			break
		}
		t := time.NewTimer(time.Duration(*pollInterval) * time.Second)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}
