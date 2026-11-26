package deployer

import (
	"strings"
	"testing"

	"relay-download/internal/protocol"
)

func TestRenderAgentBInstallScriptBlocksInjection(t *testing.T) {
	validRel := protocol.ReleaseRecord{
		ID:      "rel-123",
		Role:    protocol.RoleAgentB,
		Version: "v1.9.0",
		OS:      "linux",
		Arch:    "amd64",
		SHA256:  strings.Repeat("a", 64),
	}
	validNode := protocol.NodeRecord{
		ID:   "nas-01",
		Name: "Target NAS",
		Role: protocol.RoleAgentB,
	}
	caPEM := []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")

	// 1. Heredoc breakout attempt via newline in node name MUST be rejected.
	badNode := validNode
	badNode.Name = "ok\nRELAY_CFG_EOF\nrm -rf /\n"
	if _, err := RenderAgentBInstallScript("https://1.2.3.4:8440", caPEM, badNode, "tok", validRel, protocol.AgentBScriptReq{}); err == nil {
		t.Fatalf("expected newline/heredoc breakout in node.Name to be rejected")
	}

	// 2. Shell command injection in projects map path MUST be rejected.
	if _, err := RenderAgentBInstallScript("https://1.2.3.4:8440", caPEM, validNode, "tok", validRel, protocol.AgentBScriptReq{
		Projects: map[string]string{"p1": "/data/$(id)"},
	}); err == nil {
		t.Fatalf("expected shell command substitution in projects path to be rejected")
	}

	// 3. Path traversal in projects map or storage_dirs MUST be rejected.
	if _, err := RenderAgentBInstallScript("https://1.2.3.4:8440", caPEM, validNode, "tok", validRel, protocol.AgentBScriptReq{
		StorageDirs: []string{"/mnt/sda/../../etc"},
	}); err == nil {
		t.Fatalf("expected path traversal in storage_dirs to be rejected")
	}

	// 4. Shell injection in release version MUST be rejected.
	badRel := validRel
	badRel.Version = `v1.0"$(whoami)"`
	if _, err := RenderAgentBInstallScript("https://1.2.3.4:8440", caPEM, validNode, "tok", badRel, protocol.AgentBScriptReq{}); err == nil {
		t.Fatalf("expected shell injection in release version to be rejected")
	}

	// 5. Valid script must use unique randomized heredoc markers (never static RELAY_CFG_EOF).
	s1, err := RenderAgentBInstallScript("https://1.2.3.4:8440", caPEM, validNode, "tok", validRel, protocol.AgentBScriptReq{
		StorageDirs: []string{"/mnt/sda/relay-delivery"},
	})
	if err != nil {
		t.Fatalf("valid RenderAgentBInstallScript failed: %v", err)
	}
	s2, err := RenderAgentBInstallScript("https://1.2.3.4:8440", caPEM, validNode, "tok", validRel, protocol.AgentBScriptReq{
		StorageDirs: []string{"/mnt/sda/relay-delivery"},
	})
	if err != nil {
		t.Fatalf("second RenderAgentBInstallScript failed: %v", err)
	}
	if strings.Contains(s1, "<<'RELAY_CFG_EOF'\n") {
		t.Fatalf("script should use randomized heredoc delimiter, not static RELAY_CFG_EOF")
	}
	if s1 == s2 {
		t.Fatalf("expected randomized heredoc delimiters to differ across invocations")
	}

	// 6. Systemd unit renderer must strip newlines so ExecStartPost injection is impossible.
	unit := RenderSystemdUnit("Desc\nExecStartPost=/bin/sh -c evil", "/opt/a/bin", "/opt/a/cfg.yaml", "/opt/a")
	if strings.Contains(unit, "\nExecStartPost=") {
		t.Fatalf("systemd unit allowed newline directive injection:\n%s", unit)
	}
}
