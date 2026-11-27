package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"relay-download/internal/protocol"
)

func TestCDNFeederRangeResumeAndIdempotentCheckpoint(t *testing.T) {
	payloadA := bytes.Repeat([]byte("0123456789abcdef"), 16*1024) // 256 KiB
	payloadB := bytes.Repeat([]byte("HELLO-CDN-VIDEO!"), 8*1024)  // 128 KiB
	sumA := sha256.Sum256(payloadA)
	sumB := sha256.Sum256(payloadB)
	shaA := hex.EncodeToString(sumA[:])
	shaB := hex.EncodeToString(sumB[:])

	var dropOnceA atomic.Bool
	var rangeHits atomic.Int32
	cdnSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data []byte
		var etag string
		switch r.URL.Path {
		case "/a.mp4":
			data = payloadA
			etag = `"etag-a"`
		case "/b.mp4":
			data = payloadB
			etag = `"etag-b"`
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("ETag", etag)
		if rng := r.Header.Get("Range"); rng != "" {
			if r.Header.Get("If-Match") != etag {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			startStr := strings.TrimSuffix(strings.TrimPrefix(rng, "bytes="), "-")
			start, err := strconv.Atoi(startStr)
			if err != nil || start < 0 || start >= len(data) {
				w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
				return
			}
			rangeHits.Add(1)
			rem := data[start:]
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, len(data)-1, len(data)))
			w.Header().Set("Content-Length", strconv.Itoa(len(rem)))
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(rem)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.WriteHeader(http.StatusOK)
		if r.URL.Path == "/a.mp4" && dropOnceA.CompareAndSwap(false, true) {
			// Simulate abrupt mid-stream CDN disconnect after 64 KiB!
			_, _ = w.Write(data[:64*1024])
			if fl, ok := w.(http.Flusher); ok {
				fl.Flush()
			}
			if hj, ok := w.(http.Hijacker); ok {
				if conn, _, err := hj.Hijack(); err == nil {
					_ = conn.Close()
				}
			}
			return
		}
		_, _ = w.Write(data)
	}))
	defer cdnSrv.Close()

	var (
		mu          sync.Mutex
		putCount    int
		received    = map[string][]byte{}
		gotCustomer string
		gotProjName string
		inject507   atomic.Bool
	)
	inject507.Store(true)

	agentASrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/local/v1/status" {
			protocol.WriteJSON(w, http.StatusOK, protocol.LiveFilesResp{
				TotalFiles: 0,
				ReadyBytes: 0,
				DiskAlarm:  false,
			})
			return
		}
		if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/local/v1/files/") {
			if inject507.CompareAndSwap(true, false) {
				_, _ = io.Copy(io.Discard, r.Body)
				protocol.WriteError(w, http.StatusInsufficientStorage, "disk watermark exceeded")
				return
			}
			b, err := io.ReadAll(r.Body)
			if err != nil {
				protocol.WriteError(w, http.StatusInternalServerError, err.Error())
				return
			}
			s := sha256.Sum256(b)
			name := strings.TrimPrefix(r.URL.Path, "/local/v1/files/proj-test/")
			mu.Lock()
			putCount++
			received[name] = b
			gotCustomer = r.Header.Get(protocol.HeaderCustomer)
			gotProjName = r.URL.Query().Get("project_name")
			mu.Unlock()
			protocol.WriteJSON(w, http.StatusOK, protocol.LocalUploadResp{
				FileID:      "fid-" + name,
				ProjectID:   "proj-test",
				Filename:    name,
				Size:        int64(len(b)),
				SHA256:      hex.EncodeToString(s[:]),
				Status:      protocol.FileStatusReady,
				CustomerIDs: []string{r.Header.Get(protocol.HeaderCustomer)},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer agentASrv.Close()

	tmpDir := t.TempDir()
	manifestFile := filepath.Join(tmpDir, "manifest.jsonl")
	lines := []string{
		fmt.Sprintf(`{"filename":"a.mp4","url":"%s/a.mp4","size":%d}`, cdnSrv.URL, len(payloadA)),
		fmt.Sprintf(`{"filename":"b.mp4","url":"%s/b.mp4","size":%d}`, cdnSrv.URL, len(payloadB)),
	}
	if err := os.WriteFile(manifestFile, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	items, err := loadManifest(manifestFile)
	if err != nil || len(items) != 2 {
		t.Fatalf("loadManifest failed: len=%d err=%v", len(items), err)
	}

	st, err := openCheckpoint(filepath.Join(tmpDir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	f := &feeder{
		cdnClient:     cdnSrv.Client(),
		localClient:   agentASrv.Client(),
		store:         st,
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		project:       "proj-test",
		projectName:   "测试视频项目",
		customers:     "cust-receiver-01",
		agentAURL:     agentASrv.URL,
		concurrency:   2,
		maxQueueFiles: 10,
		maxQueueBytes: 100 << 20,
		maxResumes:    5,
		maxAttempts:   4,
	}

	if err := f.run(context.Background(), items); err != nil {
		t.Fatalf("first run failed: %v", err)
	}
	if f.pushedCount.Load() != 2 || f.failedCount.Load() != 0 {
		t.Fatalf("unexpected counts: pushed=%d failed=%d", f.pushedCount.Load(), f.failedCount.Load())
	}
	if rangeHits.Load() < 1 {
		t.Fatalf("expected Range resume hit after mid-stream CDN disconnect, got %d", rangeHits.Load())
	}
	if gotCustomer != "cust-receiver-01" || gotProjName != "测试视频项目" {
		t.Fatalf("unexpected hints: customer=%q project_name=%q", gotCustomer, gotProjName)
	}
	gotA := sha256.Sum256(received["a.mp4"])
	gotB := sha256.Sum256(received["b.mp4"])
	if hex.EncodeToString(gotA[:]) != shaA || hex.EncodeToString(gotB[:]) != shaB {
		t.Fatalf("transferred payload corrupted")
	}

	// Second pass with same checkpoint DB must skip all items without issuing any PUT!
	prevPuts := putCount
	f2 := &feeder{
		cdnClient:     cdnSrv.Client(),
		localClient:   agentASrv.Client(),
		store:         st,
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		project:       "proj-test",
		projectName:   "测试视频项目",
		customers:     "cust-receiver-01",
		agentAURL:     agentASrv.URL,
		concurrency:   2,
		maxQueueFiles: 10,
		maxQueueBytes: 100 << 20,
	}
	if err := f2.run(context.Background(), items); err != nil {
		t.Fatalf("second run failed: %v", err)
	}
	if f2.skippedCount.Load() != 2 || f2.pushedCount.Load() != 0 || putCount != prevPuts {
		t.Fatalf("second pass should skip all already-pushed items: skipped=%d pushed=%d puts=%d->%d",
			f2.skippedCount.Load(), f2.pushedCount.Load(), prevPuts, putCount)
	}
	_ = json.Valid([]byte("{}"))
}
