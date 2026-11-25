package s3client

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadOnlyS3ListAndGetWithSigV4(t *testing.T) {
	objects := map[string]string{
		"delivery/proj/---an6lH3gc.opus":      "opus-binary-payload-1",
		"delivery/proj/---an6lH3gc.info.json": `{"id":"---an6lH3gc"}`,
		"delivery/proj/--0_Hqq8260.m4a":       "m4a-payload-2",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected strictly read-only GET, got %s", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		authHdr := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHdr, "AWS4-HMAC-SHA256 Credential=ak-test/") {
			t.Errorf("missing/invalid SigV4 header: %q", authHdr)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.Header.Get("x-amz-date") == "" || r.Header.Get("x-amz-content-sha256") != emptyPayloadSHA256 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if r.URL.Path == "/media" && r.URL.Query().Get("list-type") == "2" {
			tok := r.URL.Query().Get("continuation-token")
			w.Header().Set("Content-Type", "application/xml")
			if tok == "" {
				fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
  <IsTruncated>true</IsTruncated>
  <NextContinuationToken>page2</NextContinuationToken>
  <Contents>
    <Key>delivery/proj/---an6lH3gc.opus</Key>
    <LastModified>2026-11-23T05:40:40Z</LastModified>
    <ETag>"etag1"</ETag>
    <Size>21</Size>
  </Contents>
  <Contents>
    <Key>delivery/proj/---an6lH3gc.info.json</Key>
    <LastModified>2026-11-23T05:40:40Z</LastModified>
    <ETag>"etag2"</ETag>
    <Size>20</Size>
  </Contents>
</ListBucketResult>`)
				return
			}
			fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>delivery/proj/--0_Hqq8260.m4a</Key>
    <LastModified>2026-11-23T06:08:20Z</LastModified>
    <ETag>"etag3"</ETag>
    <Size>13</Size>
  </Contents>
</ListBucketResult>`)
			return
		}

		key := strings.TrimPrefix(r.URL.Path, "/media/")
		payload, ok := objects[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	cli, err := NewReadOnly(srv.URL, "us-east-1", "ak-test", "sk-secret")
	if err != nil {
		t.Fatalf("NewReadOnly: %v", err)
	}

	ctx := context.Background()
	p1, err := cli.ListObjectsV2(ctx, "media", "delivery/proj/", "", 2)
	if err != nil {
		t.Fatalf("ListObjectsV2 page1: %v", err)
	}
	if !p1.IsTruncated || p1.NextContinuationToken != "page2" || len(p1.Objects) != 2 {
		t.Fatalf("unexpected page1: %+v", p1)
	}
	if p1.Objects[0].ETag != "etag1" {
		t.Fatalf("expected stripped ETag etag1, got %q", p1.Objects[0].ETag)
	}

	p2, err := cli.ListObjectsV2(ctx, "media", "delivery/proj/", p1.NextContinuationToken, 2)
	if err != nil {
		t.Fatalf("ListObjectsV2 page2: %v", err)
	}
	if p2.IsTruncated || len(p2.Objects) != 1 {
		t.Fatalf("unexpected page2: %+v", p2)
	}

	for _, obj := range append(p1.Objects, p2.Objects...) {
		resp, err := cli.GetObject(ctx, "media", obj.Key)
		if err != nil {
			t.Fatalf("GetObject %s: %v", obj.Key, err)
		}
		got, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if string(got) != objects[obj.Key] {
			t.Fatalf("payload mismatch for %s: got %q want %q", obj.Key, string(got), objects[obj.Key])
		}
	}
}
