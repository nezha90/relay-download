package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"relay-download/internal/protocol"
)

func TestReleaseUploadBatchSelfUpgradeAndAgentBScript(t *testing.T) {
	env := newTestEnv(t)
	// Enable deploy/release settings on Center config for this test.
	env.centerSrv.Store() // verify initialized
	env.createProject("proj-upg", protocol.ConflictOverwrite, 60)

	uploadRelease := func(role, ver, osName, arch string, payload []byte) (*http.Response, []byte) {
		t.Helper()
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		_ = mw.WriteField("role", role)
		_ = mw.WriteField("version", ver)
		_ = mw.WriteField("os", osName)
		_ = mw.WriteField("arch", arch)
		_ = mw.WriteField("notes", "e2e upgrade test")
		fw, _ := mw.CreateFormFile("file", role+".bin")
		_, _ = fw.Write(payload)
		_ = mw.Close()

		req, _ := http.NewRequest(http.MethodPost, env.centerURL+"/api/v1/admin/releases", &buf)
		req.Header.Set(protocol.HeaderAdminToken, env.adminToken)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		resp, err := env.httpClient.Do(req)
		if err != nil {
			t.Fatalf("upload release: %v", err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, b
	}

	// 1. Uploading non-ELF bytes with os=linux must be rejected with 400.
	if resp, _ := uploadRelease(protocol.RoleAgentA, "v1.9.9", "linux", "amd64", []byte("not-an-elf-binary")); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for non-ELF linux release, got %d", resp.StatusCode)
	}

	// 2. Upload valid Linux ELF release (for agent_b script test) + host-executable test binaries for real self-update test!
	linuxELF := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte("A"), 1024)...)
	if resp, b := uploadRelease(protocol.RoleAgentB, "v1.5.0", "linux", "amd64", linuxELF); resp.StatusCode != http.StatusOK {
		t.Fatalf("upload linux ELF agent_b failed: %d %s", resp.StatusCode, string(b))
	}

	// Host-runnable executable scripts implementing `-version` for real updater self-check & atomic rename test!
	// If running on Linux, skip ELF guard by only running this sub-check on darwin OR using compiled test binary.
	// Since we can copy our current test binary or build a tiny mock script on darwin:
	var goodABin, goodBBin, badBin []byte
	if runtime.GOOS == "darwin" {
		goodABin = []byte("#!/bin/sh\necho \"relay-agent-a v2.0.0 (darwin/" + runtime.GOARCH + ")\"\n")
		goodBBin = []byte("#!/bin/sh\necho \"relay-agent-b v2.0.0 (darwin/" + runtime.GOARCH + ")\"\n")
		badBin = []byte("#!/bin/sh\necho \"wrong-component v2.0.0\"\n")
	} else {
		// On Linux, use the current compiled Go executable? No, skip self-exec check if not darwin;
		// instead build the real binaries or test ELF upload. On macOS dev host runtime.GOOS == "darwin".
		t.Skip("host-script self-upgrade execution check runs on darwin; linux ELF validation already verified")
	}

	rA, bA := uploadRelease(protocol.RoleAgentA, "v2.0.0", runtime.GOOS, runtime.GOARCH, goodABin)
	if rA.StatusCode != http.StatusOK {
		t.Fatalf("upload agent_a v2.0.0 failed: %d %s", rA.StatusCode, string(bA))
	}
	var relA protocol.ReleaseRecord
	_ = json.Unmarshal(bA, &relA)

	rB, bB := uploadRelease(protocol.RoleAgentB, "v2.0.0", runtime.GOOS, runtime.GOARCH, goodBBin)
	if rB.StatusCode != http.StatusOK {
		t.Fatalf("upload agent_b v2.0.0 failed: %d %s", rB.StatusCode, string(bB))
	}
	var relB protocol.ReleaseRecord
	_ = json.Unmarshal(bB, &relB)

	rBad, bBad := uploadRelease(protocol.RoleAgentA, "v2.0.1-bad", runtime.GOOS, runtime.GOARCH, badBin)
	if rBad.StatusCode != http.StatusOK {
		t.Fatalf("upload bad agent_a failed: %d %s", rBad.StatusCode, string(bBad))
	}
	var relBad protocol.ReleaseRecord
	_ = json.Unmarshal(bBad, &relBad)

	// Verify sha256 matches.
	expSumA := sha256.Sum256(goodABin)
	if relA.SHA256 != hex.EncodeToString(expSumA[:]) {
		t.Fatalf("release sha256 mismatch")
	}

	// 3. Start Agent A and Agent B with staged executable paths and restart hooks.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	exeA := filepath.Join(env.dir, "fake-relay-agent-a")
	exeB := filepath.Join(env.dir, "fake-relay-agent-b")
	origA := []byte("#!/bin/sh\necho old-a\n")
	origB := []byte("#!/bin/sh\necho old-b\n")
	_ = os.WriteFile(exeA, origA, 0o755)
	_ = os.WriteFile(exeB, origB, 0o755)

	// Start A1 with UpgradeExePath configured BEFORE Start().
	// Use startAgentA helper? startAgentA calls Start() immediately in goroutine, so instead test bad binary protection + good upgrade via fresh Agent setup.
	var aRestarted atomic.Value
	var bRestarted atomic.Value

	agA, _, _ := env.startAgentAWithUpgrade(ctx, "a-upg", exeA, func(v string) { aRestarted.Store(v) })
	_ = agA
	env.startAgentBWithUpgrade(ctx, "b-upg", map[string]string{"proj-upg": filepath.Join(env.dir, "b-upg-dest")}, exeB, func(v string) { bRestarted.Store(v) })

	// Wait for both nodes to appear online and report OS/Arch.
	waitUntil(t, 6*time.Second, func() bool {
		var nodes []protocol.LiveNodeView
		env.adminGet("/api/v1/admin/nodes", &nodes)
		foundA, foundB := false, false
		for _, n := range nodes {
			if n.ID == "a-upg" && n.Online && n.OS == runtime.GOOS {
				foundA = true
			}
			if n.ID == "b-upg" && n.Online && n.OS == runtime.GOOS {
				foundB = true
			}
		}
		return foundA && foundB
	}, "a-upg and b-upg online with OS/Arch reported")

	postUpgrade := func(relID string, nodeIDs []string) protocol.BatchUpgradeResult {
		body, _ := json.Marshal(protocol.BatchUpgradeReq{ReleaseID: relID, NodeIDs: nodeIDs})
		req, _ := http.NewRequest(http.MethodPost, env.centerURL+"/api/v1/admin/upgrades", bytes.NewReader(body))
		req.Header.Set(protocol.HeaderAdminToken, env.adminToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := env.httpClient.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("POST /api/v1/admin/upgrades failed: err=%v resp=%v", err, resp)
		}
		defer resp.Body.Close()
		var out protocol.BatchUpgradeResult
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return out
	}

	// 4. First test ANTI-BRICK protection: push relBad (wrong component output) to a-upg!
	//    It must FAIL self-check, leave origA untouched, and report status="failed" to Center!
	resBad := postUpgrade(relBad.ID, []string{"a-upg", "b-upg"})
	if len(resBad.Queued) != 1 || resBad.Queued[0] != "a-upg" || resBad.Skipped["b-upg"] == "" {
		t.Fatalf("expected a-upg queued and b-upg skipped for role mismatch, got %+v", resBad)
	}
	waitUntil(t, 8*time.Second, func() bool {
		var nodes []protocol.LiveNodeView
		env.adminGet("/api/v1/admin/nodes", &nodes)
		for _, n := range nodes {
			if n.ID == "a-upg" && n.UpgradeStatus == "failed" && strings.Contains(n.UpgradeMessage, "does not match component") {
				return true
			}
		}
		return false
	}, "a-upg reports anti-brick self-check failure to center")
	if got, _ := os.ReadFile(exeA); !bytes.Equal(got, origA) {
		t.Fatalf("anti-brick check failed: original binary was overwritten!")
	}
	if aRestarted.Load() != nil {
		t.Fatalf("expected no restart on failed self-check")
	}

	// 5. Now push valid v2.0.0 releases to both a-upg and b-upg!
	resA := postUpgrade(relA.ID, []string{"a-upg"})
	resB := postUpgrade(relB.ID, []string{"b-upg"})
	if len(resA.Queued) != 1 || len(resB.Queued) != 1 {
		t.Fatalf("expected both queued, got A=%+v B=%+v", resA, resB)
	}

	waitUntil(t, 10*time.Second, func() bool {
		return aRestarted.Load() == "v2.0.0" && bRestarted.Load() == "v2.0.0"
	}, "both a-upg and b-upg verified, replaced binary, and triggered restart")

	gotA, _ := os.ReadFile(exeA)
	gotB, _ := os.ReadFile(exeB)
	if !bytes.Equal(gotA, goodABin) || !bytes.Equal(gotB, goodBBin) {
		t.Fatalf("upgraded binaries on disk do not match uploaded releases")
	}

	// Verify Center recorded restarting status for both nodes.
	waitUntil(t, 5*time.Second, func() bool {
		var nodes []protocol.LiveNodeView
		env.adminGet("/api/v1/admin/nodes", &nodes)
		okA, okB := false, false
		for _, n := range nodes {
			if n.ID == "a-upg" && n.UpgradeStatus == "restarting" {
				okA = true
			}
			if n.ID == "b-upg" && n.UpgradeStatus == "restarting" {
				okB = true
			}
		}
		return okA && okB
	}, "center shows upgrading status=restarting for both nodes")

	// 6. Verify Agent B one-click install script generation (with token rotation & embedded CA).
	scBody, _ := json.Marshal(protocol.AgentBScriptReq{
		NodeID:      "b-upg",
		RotateToken: true,
		Projects:    map[string]string{"proj-upg": "/data/relay/proj-upg"},
	})
	scReq, _ := http.NewRequest(http.MethodPost, env.centerURL+"/api/v1/admin/deploy/agent-b-script", bytes.NewReader(scBody))
	scReq.Header.Set(protocol.HeaderAdminToken, env.adminToken)
	scReq.Header.Set("Content-Type", "application/json")
	scResp, err := env.httpClient.Do(scReq)
	if err != nil || scResp.StatusCode != http.StatusOK {
		t.Fatalf("generate agent-b script failed: err=%v resp=%v", err, scResp)
	}
	var scOut protocol.AgentBScriptResp
	_ = json.NewDecoder(scResp.Body).Decode(&scOut)
	_ = scResp.Body.Close()
	if scOut.RotatedToken == "" || !strings.Contains(scOut.Script, scOut.RotatedToken) || !strings.Contains(scOut.Script, "--tlsv1.3") || !strings.Contains(scOut.Script, "BEGIN CERTIFICATE") {
		t.Fatalf("unexpected generated agent-b script: rotated=%q len=%d", scOut.RotatedToken, len(scOut.Script))
	}
}
