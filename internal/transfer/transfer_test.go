package transfer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"
)

func TestSanitizeAndSafeJoin(t *testing.T) {
	valid := []struct {
		in   string
		want string
	}{
		{"a.bin", "a.bin"},
		{"dir/sub/file.tar.gz", "dir/sub/file.tar.gz"},
		{`dir\sub\file.bin`, "dir/sub/file.bin"},
	}
	for _, tc := range valid {
		got, err := SanitizeRelativePath(tc.in)
		if err != nil || got != tc.want {
			t.Fatalf("SanitizeRelativePath(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}

	invalid := []string{"", "/etc/passwd", "../secret", "a/../../b", "a/\x00b", "."}
	for _, in := range invalid {
		if _, err := SanitizeRelativePath(in); err == nil {
			t.Fatalf("expected error for invalid path %q", in)
		}
	}

	base := t.TempDir()
	joined, err := SafeJoin(base, "sub/file.bin")
	if err != nil {
		t.Fatalf("SafeJoin valid: %v", err)
	}
	want := filepath.Join(base, "sub", "file.bin")
	if joined != want {
		t.Fatalf("SafeJoin = %q, want %q", joined, want)
	}
}

func TestCopyStreamAndHash(t *testing.T) {
	src := bytes.Repeat([]byte("relay-stream-chunk-"), 20000)
	var dst bytes.Buffer
	n, gotSHA, err := CopyStream(context.Background(), &dst, bytes.NewReader(src), nil, nil)
	if err != nil {
		t.Fatalf("CopyStream: %v", err)
	}
	if int(n) != len(src) || !bytes.Equal(dst.Bytes(), src) {
		t.Fatalf("copied bytes mismatch: got %d want %d", n, len(src))
	}
	exp := sha256.Sum256(src)
	if gotSHA != hex.EncodeToString(exp[:]) {
		t.Fatalf("sha mismatch: got %s", gotSHA)
	}
}
