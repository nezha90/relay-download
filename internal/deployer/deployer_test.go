package deployer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"

	"relay-download/internal/agenta"
	"relay-download/internal/pki"
	"relay-download/internal/protocol"
)

type mockSSHServer struct {
	addr       string
	privKeyPEM string
	ln         net.Listener

	mu           sync.Mutex
	probeOut     string
	uploaded     map[string][]byte
	execCommands []string
}

func startMockSSH(t *testing.T, probeOut string) *mockSSHServer {
	t.Helper()
	// Host key
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	// Client authorized key
	cliPub, cliPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cliSSHPub, err := ssh.NewPublicKey(cliPub)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(cliPriv)
	if err != nil {
		t.Fatal(err)
	}
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))

	srvCfg := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if string(pubKey.Marshal()) == string(cliSSHPub.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("unauthorized key")
		},
	}
	srvCfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	m := &mockSSHServer{
		addr:       ln.Addr().String(),
		privKeyPEM: privPEM,
		ln:         ln,
		probeOut:   probeOut,
		uploaded:   make(map[string][]byte),
	}

	go func() {
		for {
			nConn, err := ln.Accept()
			if err != nil {
				return
			}
			go m.handleConn(nConn, srvCfg)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return m
}

func (m *mockSSHServer) handleConn(nConn net.Conn, cfg *ssh.ServerConfig) {
	sConn, chans, reqs, err := ssh.NewServerConn(nConn, cfg)
	if err != nil {
		return
	}
	defer sConn.Close()
	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			_ = newChan.Reject(ssh.UnknownChannelType, "unknown")
			continue
		}
		ch, requests, err := newChan.Accept()
		if err != nil {
			continue
		}
		go func(ch ssh.Channel, in <-chan *ssh.Request) {
			defer ch.Close()
			for req := range in {
				if req.Type != "exec" {
					_ = req.Reply(false, nil)
					continue
				}
				var payload struct{ Cmd string }
				_ = ssh.Unmarshal(req.Payload, &payload)
				_ = req.Reply(true, nil)

				exitCode := uint32(0)
				cmd := payload.Cmd
				m.mu.Lock()
				m.execCommands = append(m.execCommands, cmd)
				probe := m.probeOut
				m.mu.Unlock()

				switch {
				case strings.Contains(cmd, "echo \"UID=$(id -u)\""):
					_, _ = io.WriteString(ch, probe+"\n")
				case strings.HasPrefix(cmd, "umask 077 && cat > "):
					data, _ := io.ReadAll(ch)
					// Extract final destination path from `... mv -f '<tmp>' '<final>'`
					idx := strings.LastIndex(cmd, " '")
					dst := strings.Trim(cmd[idx+1:], "'")
					m.mu.Lock()
					m.uploaded[dst] = data
					m.mu.Unlock()
				case strings.HasPrefix(cmd, "sha256sum "):
					m.mu.Lock()
					var targetBytes []byte
					for path, b := range m.uploaded {
						if strings.Contains(cmd, path) {
							targetBytes = b
							break
						}
					}
					m.mu.Unlock()
					sum := sha256.Sum256(targetBytes)
					_, _ = io.WriteString(ch, hex.EncodeToString(sum[:])+"\n")
				case strings.HasSuffix(cmd, " -version"):
					_, _ = io.WriteString(ch, "relay-agent-a v1.2.0 (linux/amd64)\n")
				case strings.Contains(cmd, "systemctl is-active relay-agent-a"):
					_, _ = io.WriteString(ch, "active\n")
				}
				_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{exitCode}))
				return
			}
		}(ch, requests)
	}
}

func (m *mockSSHServer) port() int {
	_, p, _ := net.SplitHostPort(m.addr)
	var n int
	_, _ = fmt.Sscanf(p, "%d", &n)
	return n
}

func TestValidationSecurity(t *testing.T) {
	for _, badHost := range []string{"", "1.2.3.4; rm -rf /", "-oProxyCommand=evil", "host with space"} {
		if err := ValidateHost(badHost); err == nil {
			t.Fatalf("expected invalid host %q to fail", badHost)
		}
	}
	for _, badDir := range []string{"", "relative/dir", "/", "/etc", "/usr", "/opt/../etc", "/opt/a;id"} {
		if err := ValidateAbsDir(badDir); err == nil {
			t.Fatalf("expected unsafe dir %q to fail", badDir)
		}
	}
	if err := ValidateAbsDir("/opt/relay-agent-a"); err != nil {
		t.Fatalf("expected valid dir to pass, got %v", err)
	}
}

func TestPrecheckPassWarnFail(t *testing.T) {
	dir := t.TempDir()
	caCrt, caKey := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if err := pki.InitCA(caCrt, caKey, "Test CA", 365); err != nil {
		t.Fatal(err)
	}
	d := New(Config{
		CACertPath:      caCrt,
		CAKeyPath:       caKey,
		CenterPublicURL: "https://5.6.7.8:8440",
		JWTSecret:       "jwt-s",
		CenterSecret:    "center-s",
	})
	rel := &protocol.ReleaseRecord{ID: "rel-1", Role: protocol.RoleAgentA, Version: "v1.2.0", OS: "linux", Arch: "amd64", SHA256: "abcdef0123456789"}
	finder := func(osName, arch string) (*protocol.ReleaseRecord, error) {
		if osName == "linux" && arch == "amd64" {
			return rel, nil
		}
		return nil, fmt.Errorf("not found")
	}

	// 1. Clean machine -> OK=true, CanForce=true
	srvOK := startMockSSH(t, `UID=0
HOSTNAME=pub-a1
OS=Linux
ARCH=x86_64
DISTRO=Ubuntu 24.04 LTS
SYSTEMD=yes
PORT_PUB=free
PORT_LOC=free
DIR_INSTALL=missing
DIR_DATA=missing
DISK_TOTAL_KB=104857600
DISK_AVAIL_KB=83886080
EXISTING_SVC=none`)

	resOK, err := d.Precheck(context.Background(), protocol.DeployPrecheckReq{
		Host:          "127.0.0.1",
		SSHPort:       srvOK.port(),
		SSHUser:       "root",
		SSHPrivateKey: srvOK.privKeyPEM,
	}, finder)
	if err != nil {
		t.Fatalf("Precheck clean: %v", err)
	}
	if !resOK.OK || !resOK.CanForce || resOK.HostInfo.Arch != "amd64" || resOK.HostInfo.HostFingerprint == "" || resOK.MatchedRelease == nil {
		t.Fatalf("expected clean precheck OK=true, got %+v", resOK)
	}

	// 2. Non-empty dir + existing service -> OK=false, CanForce=true
	srvWarn := startMockSSH(t, `UID=0
HOSTNAME=pub-a1
OS=Linux
ARCH=x86_64
DISTRO=Ubuntu 24.04 LTS
SYSTEMD=yes
PORT_PUB=busy:0.0.0.0:8443 users:(("relay-agent-a",pid=99,fd=3))
PORT_LOC=free
DIR_INSTALL=nonempty:4
DIR_DATA=nonempty:2
DISK_TOTAL_KB=104857600
DISK_AVAIL_KB=83886080
EXISTING_SVC=active
EXISTING_VER=relay-agent-a v1.0.0 (linux/amd64)`)

	resWarn, err := d.Precheck(context.Background(), protocol.DeployPrecheckReq{
		Host:          "127.0.0.1",
		SSHPort:       srvWarn.port(),
		SSHUser:       "root",
		SSHPrivateKey: srvWarn.privKeyPEM,
	}, finder)
	if err != nil {
		t.Fatalf("Precheck warn: %v", err)
	}
	if resWarn.OK || !resWarn.CanForce {
		t.Fatalf("expected warn precheck OK=false CanForce=true, got OK=%v CanForce=%v checks=%+v", resWarn.OK, resWarn.CanForce, resWarn.Checks)
	}

	// 3. Port busy by nginx & non-root -> OK=false, CanForce=false
	srvFail := startMockSSH(t, `UID=1000
HOSTNAME=pub-a1
OS=Linux
ARCH=x86_64
DISTRO=Ubuntu 24.04 LTS
SYSTEMD=no
PORT_PUB=busy:0.0.0.0:8443 users:(("nginx",pid=10,fd=5))
PORT_LOC=free
DIR_INSTALL=notdir
DIR_DATA=missing
DISK_TOTAL_KB=104857600
DISK_AVAIL_KB=83886080
EXISTING_SVC=none`)

	resFail, err := d.Precheck(context.Background(), protocol.DeployPrecheckReq{
		Host:          "127.0.0.1",
		SSHPort:       srvFail.port(),
		SSHUser:       "ubuntu",
		SSHPrivateKey: srvFail.privKeyPEM,
	}, finder)
	if err != nil {
		t.Fatalf("Precheck fail: %v", err)
	}
	if resFail.OK || resFail.CanForce {
		t.Fatalf("expected hard-fail precheck OK=false CanForce=false, got %+v", resFail)
	}
}

func TestInstallAgentAOverMockSSH(t *testing.T) {
	dir := t.TempDir()
	caCrt, caKey := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if err := pki.InitCA(caCrt, caKey, "Deploy Test CA", 365); err != nil {
		t.Fatal(err)
	}
	fakeBin := []byte("\x7fELF-mock-relay-agent-a-binary-payload-v1.2.0")
	binPath := filepath.Join(dir, "relay-agent-a.bin")
	if err := os.WriteFile(binPath, fakeBin, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(fakeBin)
	rel := protocol.ReleaseRecord{
		ID:      "rel-a",
		Role:    protocol.RoleAgentA,
		Version: "v1.2.0",
		OS:      "linux",
		Arch:    "amd64",
		SHA256:  hex.EncodeToString(sum[:]),
		Size:    int64(len(fakeBin)),
	}

	srv := startMockSSH(t, "")
	d := New(Config{
		CACertPath:      caCrt,
		CAKeyPath:       caKey,
		CenterPublicURL: "https://5.6.7.8:8440",
		JWTSecret:       "shared-jwt-secret",
		CenterSecret:    "shared-center-secret",
	})

	var logs []string
	err := d.InstallAgentA(context.Background(), InstallAgentAParams{
		Req: protocol.DeployAgentAReq{
			Host:          "127.0.0.1",
			SSHPort:       srv.port(),
			SSHUser:       "root",
			SSHPrivateKey: srv.privKeyPEM,
			NodeID:        "a1",
			NodeName:      "Node A1",
			Projects:      []string{"proj-alpha"},
			PublicPort:    8443,
			LocalPort:     18081,
			InstallDir:    "/opt/relay-agent-a",
			DataDir:       "/data/relay-a",
		},
		BinaryPath:  binPath,
		Release:     rel,
		CenterToken: "tok-center-123",
		LocalToken:  "tok-local-456",
		Log:         func(step, msg string) { logs = append(logs, step+": "+msg) },
	})
	if err != nil {
		t.Fatalf("InstallAgentA failed: %v\nlogs=%v", err, logs)
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()
	if string(srv.uploaded["/opt/relay-agent-a/relay-agent-a"]) != string(fakeBin) {
		t.Fatalf("uploaded binary mismatch")
	}
	cfgBytes := srv.uploaded["/opt/relay-agent-a/agent-a.yaml"]
	if len(cfgBytes) == 0 {
		t.Fatalf("agent-a.yaml was not uploaded")
	}
	var parsed agenta.Config
	if err := yaml.Unmarshal(cfgBytes, &parsed); err != nil {
		t.Fatalf("unmarshal uploaded agent-a.yaml: %v", err)
	}
	if err := parsed.Validate(); err != nil {
		t.Fatalf("generated agent-a.yaml failed Validate(): %v", err)
	}
	if parsed.NodeID != "a1" || parsed.LocalToken != "tok-local-456" || parsed.CenterToken != "tok-center-123" || parsed.PublicAddr != "https://127.0.0.1:8443" {
		t.Fatalf("unexpected generated config: %+v", parsed)
	}
	unit := string(srv.uploaded["/etc/systemd/system/relay-agent-a.service"])
	if !strings.Contains(unit, "Restart=always") || !strings.Contains(unit, "/opt/relay-agent-a/relay-agent-a -config /opt/relay-agent-a/agent-a.yaml") {
		t.Fatalf("unexpected systemd unit: %s", unit)
	}
	// Verify uploaded leaf cert is valid PEM and carries IP SAN 127.0.0.1.
	blk, _ := pem.Decode(srv.uploaded["/opt/relay-agent-a/certs/a1.crt"])
	if blk == nil {
		t.Fatalf("uploaded a1.crt is not valid PEM")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil || len(cert.IPAddresses) == 0 || cert.IPAddresses[0].String() != "127.0.0.1" {
		t.Fatalf("unexpected issued cert: err=%v ips=%v", err, cert.IPAddresses)
	}
}

func TestRenderAgentBInstallScript(t *testing.T) {
	script, err := RenderAgentBInstallScript(
		"https://5.6.7.8:8440",
		[]byte("-----BEGIN CERTIFICATE-----\nTESTCA\n-----END CERTIFICATE-----\n"),
		protocol.NodeRecord{ID: "b1", Name: "B1", Role: protocol.RoleAgentB, Projects: []string{"proj-alpha"}},
		"secret-b-tok",
		protocol.ReleaseRecord{ID: "rel-b", Role: protocol.RoleAgentB, Version: "v1.2.0", OS: "linux", Arch: "amd64", SHA256: "deadbeef"},
		protocol.AgentBScriptReq{NodeID: "b1"},
	)
	if err != nil {
		t.Fatalf("RenderAgentBInstallScript: %v", err)
	}
	for _, must := range []string{"--tlsv1.3", "--cacert", "TESTCA", "sha256sum", "-version", "relay-agent-b.service", "secret-b-tok"} {
		if !strings.Contains(script, must) {
			t.Fatalf("expected script to contain %q", must)
		}
	}
	if strings.Contains(script, " -k ") || strings.Contains(script, "--insecure") {
		t.Fatalf("script must not skip TLS verification")
	}
}
