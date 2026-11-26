package deployer

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"

	"relay-download/internal/agenta"
	"relay-download/internal/agentb"
	"relay-download/internal/pki"
	"relay-download/internal/protocol"
)

var (
	validHostRe    = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,253}$`)
	validUserRe    = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	validIDRe      = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	validVersionRe = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}$`)
	validHexRe     = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	validModeRe    = regexp.MustCompile(`^0?[0-7]{3,4}$`)
	validPathRe    = regexp.MustCompile(`^/[A-Za-z0-9/._-]{1,255}$`)
)

var forbiddenDirs = map[string]bool{
	"/": true, "/bin": true, "/boot": true, "/dev": true, "/etc": true,
	"/home": true, "/lib": true, "/lib64": true, "/proc": true, "/root": true,
	"/run": true, "/sbin": true, "/sys": true, "/tmp": true, "/usr": true, "/var": true,
}

// Config holds Center-side settings required by the SSH deployer.
type Config struct {
	DefaultSSHKeyPath string
	CACertPath        string
	CAKeyPath         string
	CenterPublicURL   string
	JWTSecret         string
	CenterSecret      string
}

type Deployer struct {
	cfg Config
}

func New(cfg Config) *Deployer {
	return &Deployer{cfg: cfg}
}

func ValidateHost(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return errors.New("host is required")
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	if !validHostRe.MatchString(host) || strings.HasPrefix(host, "-") {
		return fmt.Errorf("invalid host %q", host)
	}
	return nil
}

func ValidateAbsDir(dir string) error {
	dir = strings.TrimSpace(dir)
	if !validPathRe.MatchString(dir) || strings.Contains(dir, "..") {
		return fmt.Errorf("invalid absolute directory path %q", dir)
	}
	cleaned := filepath.Clean(dir)
	if forbiddenDirs[cleaned] {
		return fmt.Errorf("refusing unsafe system directory %q", cleaned)
	}
	return nil
}

func ValidateID(id string) error {
	if !validIDRe.MatchString(strings.TrimSpace(id)) {
		return fmt.Errorf("invalid identifier %q: only [A-Za-z0-9._-] (1-64 chars) allowed", id)
	}
	return nil
}

func ValidateSafeSingleLine(s string, maxLen int) error {
	if len(s) > maxLen {
		return fmt.Errorf("value exceeds max length %d", maxLen)
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return errors.New("control characters and newlines are not allowed")
		}
	}
	return nil
}

func randomHeredocDelim(prefix string) string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return prefix + "_" + strings.ToUpper(hex.EncodeToString(b[:]))
}

func ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func normalizeArch(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "x86_64", "amd64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	default:
		return strings.ToLower(strings.TrimSpace(raw))
	}
}

func (d *Deployer) buildSSHConfig(user, password, privateKeyPEM string, fpOut *string) (*ssh.ClientConfig, error) {
	user = strings.TrimSpace(user)
	if user == "" {
		user = "root"
	}
	if !validUserRe.MatchString(user) {
		return nil, fmt.Errorf("invalid ssh_user %q", user)
	}

	var authMethods []ssh.AuthMethod
	var signers []ssh.Signer

	if strings.TrimSpace(privateKeyPEM) != "" {
		s, err := ssh.ParsePrivateKey([]byte(privateKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("parse ssh_private_key: %w", err)
		}
		signers = append(signers, s)
	} else {
		for _, kp := range d.candidateKeyPaths() {
			b, err := os.ReadFile(kp)
			if err != nil {
				continue
			}
			if s, err := ssh.ParsePrivateKey(b); err == nil {
				signers = append(signers, s)
			}
		}
	}
	if len(signers) > 0 {
		authMethods = append(authMethods, ssh.PublicKeys(signers...))
	}
	if password != "" {
		authMethods = append(authMethods, ssh.Password(password))
	}
	if len(authMethods) == 0 {
		return nil, errors.New("no SSH authentication available: configure ssh_key_path / ~/.ssh/id_ed25519 or provide ssh_password / ssh_private_key")
	}

	return &ssh.ClientConfig{
		User: user,
		Auth: authMethods,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			if fpOut != nil && key != nil {
				*fpOut = ssh.FingerprintSHA256(key)
			}
			return nil
		},
		Timeout: 10 * time.Second,
	}, nil
}

func (d *Deployer) candidateKeyPaths() []string {
	var paths []string
	if d.cfg.DefaultSSHKeyPath != "" {
		paths = append(paths, d.cfg.DefaultSSHKeyPath)
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		paths = append(paths,
			filepath.Join(home, ".ssh", "id_ed25519"),
			filepath.Join(home, ".ssh", "id_rsa"),
			filepath.Join(home, ".ssh", "id_ecdsa"),
		)
	}
	return paths
}

func (d *Deployer) dialSSH(ctx context.Context, host string, port int, user, password, keyPEM string) (*ssh.Client, string, error) {
	if port <= 0 {
		port = 22
	}
	var fp string
	cfg, err := d.buildSSHConfig(user, password, keyPEM, &fp)
	if err != nil {
		return nil, "", err
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, "", fmt.Errorf("tcp connect %s: %w", addr, err)
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, "", fmt.Errorf("ssh handshake %s: %w", addr, err)
	}
	return ssh.NewClient(c, chans, reqs), fp, nil
}

func runRemoteCmd(ctx context.Context, client *ssh.Client, cmd string) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()

	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr

	done := make(chan error, 1)
	go func() {
		done <- sess.Run(cmd)
	}()

	select {
	case <-ctx.Done():
		_ = sess.Close()
		return "", ctx.Err()
	case err := <-done:
		out := strings.TrimSpace(stdout.String())
		if err != nil {
			errTxt := strings.TrimSpace(stderr.String())
			if errTxt == "" {
				errTxt = out
			}
			return out, fmt.Errorf("%w: %s", err, errTxt)
		}
		return out, nil
	}
}

func uploadFile(ctx context.Context, client *ssh.Client, r io.Reader, remotePath string, mode string) error {
	if err := ValidateAbsDir(filepath.Dir(remotePath)); err != nil {
		return err
	}
	if !validModeRe.MatchString(mode) {
		return fmt.Errorf("invalid file mode %q", mode)
	}
	if strings.ContainsAny(remotePath, "\r\n\x00") || strings.Contains(remotePath, "..") {
		return fmt.Errorf("invalid remote path %q", remotePath)
	}
	tmpPath := remotePath + ".relaytmp"
	cmd := fmt.Sprintf("umask 077 && cat > %s && chmod %s %s && mv -f %s %s",
		ShellQuote(tmpPath), mode, ShellQuote(tmpPath), ShellQuote(tmpPath), ShellQuote(remotePath))

	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()

	var stderr bytes.Buffer
	sess.Stdin = r
	sess.Stderr = &stderr

	done := make(chan error, 1)
	go func() {
		done <- sess.Run(cmd)
	}()
	select {
	case <-ctx.Done():
		_ = sess.Close()
		return ctx.Err()
	case err := <-done:
		if err != nil {
			return fmt.Errorf("upload %s: %w (%s)", remotePath, err, strings.TrimSpace(stderr.String()))
		}
		return nil
	}
}

// ReleaseFinder looks up a matching agent_a release for the probed remote OS/Arch.
type ReleaseFinder func(osName, arch string) (*protocol.ReleaseRecord, error)

// Precheck connects to the target server over SSH and validates root access, ports, directories,
// disk capacity, systemd availability, and Center-side deployment prerequisites.
func (d *Deployer) Precheck(ctx context.Context, req protocol.DeployPrecheckReq, findRelease ReleaseFinder) (*protocol.DeployPrecheckResp, error) {
	if err := ValidateHost(req.Host); err != nil {
		return nil, err
	}
	if req.SSHPort <= 0 {
		req.SSHPort = 22
	}
	if req.SSHUser == "" {
		req.SSHUser = "root"
	}
	if req.PublicPort <= 0 {
		req.PublicPort = 8443
	}
	if req.LocalPort <= 0 {
		req.LocalPort = 18081
	}
	if req.PublicPort < 1 || req.PublicPort > 65535 || req.LocalPort < 1 || req.LocalPort > 65535 || req.PublicPort == req.LocalPort {
		return nil, errors.New("public_port and local_port must be valid distinct ports (1-65535)")
	}
	if req.InstallDir == "" {
		req.InstallDir = "/opt/relay-agent-a"
	}
	if req.DataDir == "" {
		req.DataDir = "/data/relay-a"
	}
	if err := ValidateAbsDir(req.InstallDir); err != nil {
		return nil, fmt.Errorf("install_dir: %w", err)
	}
	if err := ValidateAbsDir(req.DataDir); err != nil {
		return nil, fmt.Errorf("data_dir: %w", err)
	}

	resp := &protocol.DeployPrecheckResp{
		Checks: make([]protocol.PrecheckItem, 0, 10),
	}
	addCheck := func(key, label, status, detail string) {
		resp.Checks = append(resp.Checks, protocol.PrecheckItem{
			Key: key, Label: label, Status: status, Detail: detail,
		})
	}

	// 1. Center prerequisites (CA key + public_url)
	centerMissing := []string{}
	if d.cfg.CACertPath == "" || d.cfg.CAKeyPath == "" {
		centerMissing = append(centerMissing, "ca_cert/ca_key")
	} else {
		if _, err := os.Stat(d.cfg.CAKeyPath); err != nil {
			centerMissing = append(centerMissing, "ca_key("+err.Error()+")")
		}
	}
	if strings.TrimSpace(d.cfg.CenterPublicURL) == "" {
		centerMissing = append(centerMissing, "public_url")
	}
	if len(centerMissing) > 0 {
		addCheck("center_prereq", "中心部署配置 (CA 签名密钥 / public_url)", "fail", "缺失配置: "+strings.Join(centerMissing, ", "))
	} else {
		addCheck("center_prereq", "中心部署配置 (CA 签名密钥 / public_url)", "pass", fmt.Sprintf("CA 签发就绪，中心地址 %s", d.cfg.CenterPublicURL))
	}

	// 2. Dial SSH
	pCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	client, fp, err := d.dialSSH(pCtx, req.Host, req.SSHPort, req.SSHUser, req.SSHPassword, req.SSHPrivateKey)
	if err != nil {
		addCheck("ssh_connect", "SSH 连通性检测", "fail", err.Error())
		return resp, nil
	}
	defer client.Close()
	resp.HostInfo.HostFingerprint = fp
	addCheck("ssh_connect", "SSH 连通性检测", "pass", fmt.Sprintf("连接 %s@%s:%d 成功 (指纹 %s)", req.SSHUser, req.Host, req.SSHPort, fp))

	// 3. Single POSIX shell probe script
	probeScript := buildPrecheckScript(req.PublicPort, req.LocalPort, req.InstallDir, req.DataDir)
	out, err := runRemoteCmd(pCtx, client, probeScript)
	if err != nil {
		addCheck("remote_probe", "远端环境探测", "fail", err.Error())
		return resp, nil
	}

	kv := parseKV(out)
	uid := kv["UID"]
	resp.HostInfo.IsRoot = uid == "0"
	resp.HostInfo.Hostname = kv["HOSTNAME"]
	resp.HostInfo.OS = strings.ToLower(kv["OS"])
	resp.HostInfo.Arch = normalizeArch(kv["ARCH"])
	resp.HostInfo.Distro = kv["DISTRO"]
	resp.HostInfo.HasSystemd = kv["SYSTEMD"] == "yes"
	resp.HostInfo.ExistingService = kv["EXISTING_SVC"]
	resp.HostInfo.ExistingVersion = kv["EXISTING_VER"]

	if resp.HostInfo.IsRoot {
		addCheck("root_perm", "Root 权限校验", "pass", fmt.Sprintf("uid=0 (%s · %s %s/%s)", resp.HostInfo.Hostname, resp.HostInfo.Distro, resp.HostInfo.OS, resp.HostInfo.Arch))
	} else {
		addCheck("root_perm", "Root 权限校验", "fail", fmt.Sprintf("当前登录用户 uid=%s，需要 root (uid=0) 权限", uid))
	}

	if resp.HostInfo.OS == "linux" && (resp.HostInfo.Arch == "amd64" || resp.HostInfo.Arch == "arm64") {
		addCheck("os_arch", "操作系统与架构", "pass", fmt.Sprintf("%s/%s (%s)", resp.HostInfo.OS, resp.HostInfo.Arch, resp.HostInfo.Distro))
	} else {
		addCheck("os_arch", "操作系统与架构", "fail", fmt.Sprintf("不支持的目标平台: %s/%s", resp.HostInfo.OS, resp.HostInfo.Arch))
	}

	if resp.HostInfo.HasSystemd {
		addCheck("systemd", "Systemd 服务管理", "pass", "systemctl 可用")
	} else {
		addCheck("systemd", "Systemd 服务管理", "fail", "目标主机未检测到运行中的 systemd")
	}

	// Port checks
	checkPort := func(key, label string, port int, raw string) {
		if raw == "free" || raw == "" {
			addCheck(key, label, "pass", fmt.Sprintf("端口 %d 空闲可用", port))
			return
		}
		detail := strings.TrimPrefix(raw, "busy:")
		// If occupied specifically by our own existing relay-agent-a service, mark as warn (overwritable) instead of hard fail.
		if strings.Contains(detail, "relay-agent-a") {
			addCheck(key, label, "warn", fmt.Sprintf("端口 %d 当前被已有 relay-agent-a 占用（覆盖重装时将自动重启）: %s", port, detail))
		} else {
			addCheck(key, label, "fail", fmt.Sprintf("端口 %d 已被其他进程占用: %s", port, detail))
		}
	}
	checkPort("port_public", fmt.Sprintf("公网传输端口 (%d)", req.PublicPort), req.PublicPort, kv["PORT_PUB"])
	checkPort("port_local", fmt.Sprintf("本机上传端口 (127.0.0.1:%d)", req.LocalPort), req.LocalPort, kv["PORT_LOC"])

	// Directory checks
	checkDir := func(key, label, path, raw string) {
		switch {
		case raw == "missing":
			addCheck(key, label, "pass", fmt.Sprintf("目录 %s 不存在，部署时将自动创建", path))
		case raw == "empty":
			addCheck(key, label, "pass", fmt.Sprintf("目录 %s 存在且为空", path))
		case strings.HasPrefix(raw, "nonempty:"):
			cnt := strings.TrimPrefix(raw, "nonempty:")
			addCheck(key, label, "warn", fmt.Sprintf("目录 %s 已存在且非空（含 %s 项），需确认覆盖", path, cnt))
		case raw == "notdir":
			addCheck(key, label, "fail", fmt.Sprintf("路径 %s 已被普通文件占用，无法作为目录", path))
		default:
			addCheck(key, label, "warn", fmt.Sprintf("目录 %s 状态: %s", path, raw))
		}
	}
	checkDir("dir_install", "安装目录检测", req.InstallDir, kv["DIR_INSTALL"])
	checkDir("dir_data", "数据目录检测", req.DataDir, kv["DIR_DATA"])

	// Disk check
	if totalKB, err1 := strconv.ParseUint(kv["DISK_TOTAL_KB"], 10, 64); err1 == nil && totalKB > 0 {
		availKB, _ := strconv.ParseUint(kv["DISK_AVAIL_KB"], 10, 64)
		resp.HostInfo.DiskTotalBytes = totalKB * 1024
		resp.HostInfo.DiskFreeBytes = availKB * 1024
		usedBytes := resp.HostInfo.DiskTotalBytes - resp.HostInfo.DiskFreeBytes
		if resp.HostInfo.DiskFreeBytes > resp.HostInfo.DiskTotalBytes {
			usedBytes = 0
		}
		resp.HostInfo.DiskUsedPct = (float64(usedBytes) / float64(resp.HostInfo.DiskTotalBytes)) * 100.0
		freeGB := float64(resp.HostInfo.DiskFreeBytes) / (1024 * 1024 * 1024)
		if resp.HostInfo.DiskUsedPct >= 85.0 {
			addCheck("disk_space", "目标磁盘水位", "warn", fmt.Sprintf("磁盘已用 %.1f%% (剩余 %.2f GB)，接近或超过默认 85%% 水位阈值", resp.HostInfo.DiskUsedPct, freeGB))
		} else {
			addCheck("disk_space", "目标磁盘水位", "pass", fmt.Sprintf("磁盘已用 %.1f%%，可用 %.2f GB", resp.HostInfo.DiskUsedPct, freeGB))
		}
	}

	// Existing service check
	if resp.HostInfo.ExistingService != "" && resp.HostInfo.ExistingService != "none" {
		detail := fmt.Sprintf("检测到已有服务 relay-agent-a (%s)", resp.HostInfo.ExistingService)
		if resp.HostInfo.ExistingVersion != "" {
			detail += " · 当前版本: " + resp.HostInfo.ExistingVersion
		}
		addCheck("existing_svc", "已有服务检查", "warn", detail+"（确认覆盖部署将平滑替换重启）")
	} else {
		addCheck("existing_svc", "已有服务检查", "pass", "未安装同名 relay-agent-a 服务（全新环境）")
	}

	// Matching release binary on Center
	if findRelease != nil && resp.HostInfo.OS != "" && resp.HostInfo.Arch != "" {
		rel, err := findRelease(resp.HostInfo.OS, resp.HostInfo.Arch)
		if err != nil || rel == nil {
			addCheck("release_bin", "中心发布包就绪", "fail", fmt.Sprintf("中心未上传匹配的分发节点 (%s/%s) 二进制包，请先在「部署与版本」中上传", resp.HostInfo.OS, resp.HostInfo.Arch))
		} else {
			resp.MatchedRelease = rel
			addCheck("release_bin", "中心发布包就绪", "pass", fmt.Sprintf("已匹配 %s (%s/%s, SHA256 %s…)", rel.Version, rel.OS, rel.Arch, rel.SHA256[:12]))
		}
	}

	hasFail := false
	hasWarn := false
	for _, c := range resp.Checks {
		if c.Status == "fail" {
			hasFail = true
		} else if c.Status == "warn" {
			hasWarn = true
		}
	}
	resp.OK = !hasFail && !hasWarn
	resp.CanForce = !hasFail
	return resp, nil
}

func buildPrecheckScript(pubPort, locPort int, installDir, dataDir string) string {
	return fmt.Sprintf(`sh -c '
echo "UID=$(id -u)"
echo "HOSTNAME=$(hostname 2>/dev/null || echo unknown)"
echo "OS=$(uname -s 2>/dev/null || echo unknown)"
echo "ARCH=$(uname -m 2>/dev/null || echo unknown)"
DISTRO="Linux"
if [ -f /etc/os-release ]; then
  DISTRO=$(grep -m1 "^PRETTY_NAME=" /etc/os-release | cut -d= -f2- | tr -d "\"")
fi
echo "DISTRO=$DISTRO"
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  echo "SYSTEMD=yes"
else
  echo "SYSTEMD=no"
fi

check_port() {
  P="$1"
  if command -v ss >/dev/null 2>&1; then
    HIT=$(ss -ltnp 2>/dev/null | awk -v p=":$P" "$4 ~ p\"$\" {print \$4, \$6; exit}")
    if [ -n "$HIT" ]; then echo "busy:$HIT"; return; fi
  elif command -v netstat >/dev/null 2>&1; then
    HIT=$(netstat -ltnp 2>/dev/null | awk -v p=":$P" "$4 ~ p\"$\" {print \$4, \$7; exit}")
    if [ -n "$HIT" ]; then echo "busy:$HIT"; return; fi
  fi
  echo "free"
}
echo "PORT_PUB=$(check_port %d)"
echo "PORT_LOC=$(check_port %d)"

check_dir() {
  D="$1"
  if [ -d "$D" ]; then
    CNT=$(ls -A "$D" 2>/dev/null | wc -l | tr -d " ")
    if [ "$CNT" = "0" ]; then echo "empty"; else echo "nonempty:$CNT"; fi
  elif [ -e "$D" ]; then
    echo "notdir"
  else
    echo "missing"
  fi
}
echo "DIR_INSTALL=$(check_dir %s)"
echo "DIR_DATA=$(check_dir %s)"

DISK_TARGET=%s
while [ ! -e "$DISK_TARGET" ] && [ "$DISK_TARGET" != "/" ]; do
  DISK_TARGET=$(dirname "$DISK_TARGET")
done
DF_LINE=$(df -Pk "$DISK_TARGET" 2>/dev/null | tail -n 1)
echo "DISK_TOTAL_KB=$(echo "$DF_LINE" | awk "{print \$2}")"
echo "DISK_AVAIL_KB=$(echo "$DF_LINE" | awk "{print \$4}")"

if [ -f /etc/systemd/system/relay-agent-a.service ]; then
  ST=$(systemctl is-active relay-agent-a 2>/dev/null || echo inactive)
  echo "EXISTING_SVC=$ST"
else
  echo "EXISTING_SVC=none"
fi
if [ -x %s/relay-agent-a ]; then
  VER=$(%s/relay-agent-a -version 2>/dev/null | head -n 1 || true)
  echo "EXISTING_VER=$VER"
fi
'`, pubPort, locPort, ShellQuote(installDir), ShellQuote(dataDir), ShellQuote(dataDir), ShellQuote(installDir), ShellQuote(installDir))
}

func parseKV(out string) map[string]string {
	m := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if ok {
			m[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return m
}

// InstallAgentAParams carries everything needed to push and activate Agent A over SSH.
type InstallAgentAParams struct {
	Req         protocol.DeployAgentAReq
	BinaryPath  string
	Release     protocol.ReleaseRecord
	CenterToken string
	LocalToken  string
	Log         func(step, msg string)
}

// InstallAgentA issues a node TLS cert, uploads binary/certs/config/systemd unit over SSH,
// verifies remote SHA256 + self-check, and enables & starts the systemd service.
func (d *Deployer) InstallAgentA(ctx context.Context, p InstallAgentAParams) error {
	logf := p.Log
	if logf == nil {
		logf = func(string, string) {}
	}
	req := p.Req
	if req.SSHPort <= 0 {
		req.SSHPort = 22
	}
	if req.SSHUser == "" {
		req.SSHUser = "root"
	}
	if req.PublicPort <= 0 {
		req.PublicPort = 8443
	}
	if req.LocalPort <= 0 {
		req.LocalPort = 18081
	}
	if req.InstallDir == "" {
		req.InstallDir = "/opt/relay-agent-a"
	}
	if req.DataDir == "" {
		req.DataDir = "/data/relay-a"
	}
	if req.MaxDiskUsagePct <= 0 {
		req.MaxDiskUsagePct = 85.0
	}
	if req.LeaseTTLSec <= 0 {
		req.LeaseTTLSec = 300
	}
	if req.MaxConcurrentStreams <= 0 {
		req.MaxConcurrentStreams = 16
	}
	if req.NodeName == "" {
		req.NodeName = req.NodeID
	}
	if err := ValidateHost(req.Host); err != nil {
		return err
	}
	if err := ValidateID(req.NodeID); err != nil {
		return fmt.Errorf("node_id: %w", err)
	}
	if err := ValidateSafeSingleLine(req.NodeName, 128); err != nil {
		return fmt.Errorf("node_name: %w", err)
	}
	if req.SSHPort < 1 || req.SSHPort > 65535 || req.PublicPort < 1 || req.PublicPort > 65535 || req.LocalPort < 1 || req.LocalPort > 65535 || req.PublicPort == req.LocalPort {
		return errors.New("invalid SSH / public / local port range")
	}
	if err := ValidateAbsDir(req.InstallDir); err != nil {
		return fmt.Errorf("install_dir: %w", err)
	}
	if err := ValidateAbsDir(req.DataDir); err != nil {
		return fmt.Errorf("data_dir: %w", err)
	}
	for _, pid := range req.Projects {
		if err := ValidateID(pid); err != nil {
			return fmt.Errorf("project %q: %w", pid, err)
		}
	}

	// Step 1: Issue TLS cert for target host IP/DNS using Center CA.
	logf("issue_cert", fmt.Sprintf("正在为节点 %s (%s) 签发专属 TLS 1.3 IP-SAN 证书...", req.NodeID, req.Host))
	tmpCertDir, err := os.MkdirTemp("", "relay-deploy-cert-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpCertDir)

	var ips, dnsNames []string
	if ip := net.ParseIP(req.Host); ip != nil {
		ips = []string{req.Host, "127.0.0.1"}
	} else {
		ips = []string{"127.0.0.1"}
		dnsNames = []string{req.Host}
	}
	leafCert := filepath.Join(tmpCertDir, req.NodeID+".crt")
	leafKey := filepath.Join(tmpCertDir, req.NodeID+".key")
	if err := pki.IssueCert(d.cfg.CACertPath, d.cfg.CAKeyPath, leafCert, leafKey, req.NodeID, ips, dnsNames, 825); err != nil {
		return fmt.Errorf("issue node TLS cert: %w", err)
	}
	caBytes, err := os.ReadFile(d.cfg.CACertPath)
	if err != nil {
		return fmt.Errorf("read ca cert: %w", err)
	}
	certBytes, err := os.ReadFile(leafCert)
	if err != nil {
		return err
	}
	keyBytes, err := os.ReadFile(leafKey)
	if err != nil {
		return err
	}

	// Step 2: Connect SSH
	logf("ssh_connect", fmt.Sprintf("连接目标主机 %s@%s:%d ...", req.SSHUser, req.Host, req.SSHPort))
	client, fp, err := d.dialSSH(ctx, req.Host, req.SSHPort, req.SSHUser, req.SSHPassword, req.SSHPrivateKey)
	if err != nil {
		return err
	}
	defer client.Close()
	logf("ssh_connect", fmt.Sprintf("SSH 连接已建立 (主机指纹: %s)", fp))

	// Step 3: Prepare directories & stop existing service if present
	logf("prepare_dirs", fmt.Sprintf("创建目录 %s 与 %s ...", req.InstallDir, req.DataDir))
	prepCmd := fmt.Sprintf("mkdir -p %s %s/certs %s && chmod 700 %s/certs && (systemctl stop relay-agent-a 2>/dev/null || true)",
		ShellQuote(req.InstallDir), ShellQuote(req.InstallDir), ShellQuote(req.DataDir), ShellQuote(req.InstallDir))
	if _, err := runRemoteCmd(ctx, client, prepCmd); err != nil {
		return fmt.Errorf("prepare remote directories: %w", err)
	}

	// Step 4: Upload binary & verify remote SHA256 + -version
	binRemote := filepath.Join(req.InstallDir, "relay-agent-a")
	logf("upload_binary", fmt.Sprintf("上传 relay-agent-a (%s, %.2f MB)...", p.Release.Version, float64(p.Release.Size)/(1024*1024)))
	binFile, err := os.Open(p.BinaryPath)
	if err != nil {
		return fmt.Errorf("open release binary: %w", err)
	}
	upErr := uploadFile(ctx, client, binFile, binRemote, "0755")
	_ = binFile.Close()
	if upErr != nil {
		return upErr
	}

	verifyCmd := fmt.Sprintf("sha256sum %s | awk '{print $1}'", ShellQuote(binRemote))
	remoteSHA, err := runRemoteCmd(ctx, client, verifyCmd)
	if err != nil {
		return fmt.Errorf("verify remote sha256: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(remoteSHA), p.Release.SHA256) {
		return fmt.Errorf("remote binary sha256 mismatch: expected %s got %s", p.Release.SHA256, remoteSHA)
	}
	verOut, err := runRemoteCmd(ctx, client, ShellQuote(binRemote)+" -version")
	if err != nil {
		return fmt.Errorf("remote binary self-check (-version) failed: %w", err)
	}
	logf("upload_binary", fmt.Sprintf("二进制校验与自检通过: %s", verOut))

	// Step 5: Upload certs & generated agent-a.yaml
	logf("upload_config", "推送 TLS 证书与 agent-a.yaml 配置文件...")
	caRemote := filepath.Join(req.InstallDir, "certs", "ca.crt")
	crtRemote := filepath.Join(req.InstallDir, "certs", req.NodeID+".crt")
	keyRemote := filepath.Join(req.InstallDir, "certs", req.NodeID+".key")
	if err := uploadFile(ctx, client, bytes.NewReader(caBytes), caRemote, "0644"); err != nil {
		return err
	}
	if err := uploadFile(ctx, client, bytes.NewReader(certBytes), crtRemote, "0644"); err != nil {
		return err
	}
	if err := uploadFile(ctx, client, bytes.NewReader(keyBytes), keyRemote, "0600"); err != nil {
		return err
	}

	pubHost := req.Host
	if ip := net.ParseIP(req.Host); ip != nil && ip.To4() == nil {
		pubHost = "[" + req.Host + "]"
	}
	aCfg := agenta.Config{
		NodeID:               req.NodeID,
		NodeName:             req.NodeName,
		PublicAddr:           fmt.Sprintf("https://%s:%d", pubHost, req.PublicPort),
		CenterURL:            d.cfg.CenterPublicURL,
		CenterToken:          p.CenterToken,
		JWTSecret:            d.cfg.JWTSecret,
		CenterSecret:         d.cfg.CenterSecret,
		Projects:             req.Projects,
		LocalListen:          fmt.Sprintf("127.0.0.1:%d", req.LocalPort),
		LocalToken:           p.LocalToken,
		PublicListen:         fmt.Sprintf("0.0.0.0:%d", req.PublicPort),
		TLSCert:              crtRemote,
		TLSKey:               keyRemote,
		CACert:               caRemote,
		DataDir:              req.DataDir,
		MaxDiskUsagePct:      req.MaxDiskUsagePct,
		MinFreeDiskBytes:     req.MinFreeDiskBytes,
		LeaseTTLSec:            req.LeaseTTLSec,
		MaxConcurrentStreams:   req.MaxConcurrentStreams,
		RateLimitMBps:          req.RateLimitMBps,
		DeleteBatchIntervalSec: req.DeleteBatchIntervalSec,
		HeartbeatIntervalSec:   5,
	}
	cfgYAML, err := yaml.Marshal(&aCfg)
	if err != nil {
		return fmt.Errorf("marshal agent-a.yaml: %w", err)
	}
	cfgRemote := filepath.Join(req.InstallDir, "agent-a.yaml")
	if err := uploadFile(ctx, client, bytes.NewReader(cfgYAML), cfgRemote, "0600"); err != nil {
		return err
	}

	// Step 6: Install systemd unit & start service
	logf("start_service", "写入 systemd 服务单元并启动 relay-agent-a ...")
	unit := RenderSystemdUnit("Relay Download Public Agent A", binRemote, cfgRemote, req.InstallDir)
	if err := uploadFile(ctx, client, strings.NewReader(unit), "/etc/systemd/system/relay-agent-a.service", "0644"); err != nil {
		return err
	}
	startCmd := "systemctl daemon-reload && systemctl enable relay-agent-a && systemctl restart relay-agent-a && sleep 1 && systemctl is-active relay-agent-a"
	svcStatus, err := runRemoteCmd(ctx, client, startCmd)
	if err != nil {
		journal, _ := runRemoteCmd(ctx, client, "journalctl -u relay-agent-a -n 20 --no-pager 2>/dev/null || true")
		return fmt.Errorf("start relay-agent-a failed: %w\n%s", err, journal)
	}
	logf("start_service", fmt.Sprintf("systemd 服务已启动 (状态: %s)", svcStatus))
	return nil
}

func sanitizeUnitField(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

func RenderSystemdUnit(desc, binPath, cfgPath, workDir string) string {
	return fmt.Sprintf(`[Unit]
Description=%s
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=%s
ExecStart=%s -config %s
Restart=always
RestartSec=2
LimitNOFILE=65536
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
`, sanitizeUnitField(desc), sanitizeUnitField(workDir), sanitizeUnitField(binPath), sanitizeUnitField(cfgPath))
}

// RenderAgentBInstallScript generates a self-contained bash installer for intranet receiver nodes
// with embedded ca.crt so binary download enforces strict TLS 1.3 verification without -k/--insecure.
// All inputs are strictly validated and heredocs use cryptographically random delimiters to prevent script injection.
func RenderAgentBInstallScript(centerPublicURL string, caCertPEM []byte, node protocol.NodeRecord, rawToken string, rel protocol.ReleaseRecord, req protocol.AgentBScriptReq) (string, error) {
	if err := ValidateID(node.ID); err != nil {
		return "", fmt.Errorf("node_id: %w", err)
	}
	if err := ValidateSafeSingleLine(node.Name, 128); err != nil {
		return "", fmt.Errorf("node_name: %w", err)
	}
	if u, err := url.Parse(strings.TrimSpace(centerPublicURL)); err != nil || u.Scheme != "https" || u.Host == "" {
		return "", errors.New("centerPublicURL must be a valid https:// URL")
	}
	if err := ValidateSafeSingleLine(centerPublicURL, 512); err != nil {
		return "", fmt.Errorf("center_url: %w", err)
	}
	if !validVersionRe.MatchString(rel.Version) || (rel.OS != "linux" && rel.OS != "darwin") || (rel.Arch != "amd64" && rel.Arch != "arm64") {
		return "", errors.New("invalid release metadata")
	}
	if !validHexRe.MatchString(rel.SHA256) {
		return "", errors.New("invalid release sha256")
	}
	if !validIDRe.MatchString(rel.ID) {
		return "", errors.New("invalid release id")
	}
	if rawToken != "" {
		if err := ValidateSafeSingleLine(rawToken, 256); err != nil {
			return "", fmt.Errorf("node_token: %w", err)
		}
	}

	installDir := req.InstallDir
	if installDir == "" {
		installDir = "/opt/relay-agent-b"
	}
	stateDir := req.StateDir
	if stateDir == "" {
		stateDir = "/data/relay-b/state"
	}
	if err := ValidateAbsDir(installDir); err != nil {
		return "", err
	}
	if err := ValidateAbsDir(stateDir); err != nil {
		return "", err
	}
	onlyProject := strings.TrimSpace(req.OnlyProject)
	if onlyProject != "" {
		if err := ValidateID(onlyProject); err != nil {
			return "", fmt.Errorf("only_project: %w", err)
		}
	}
	storageDirs := make([]string, 0, len(req.StorageDirs))
	for _, d := range req.StorageDirs {
		d = strings.TrimSpace(d)
		if d != "" {
			if err := ValidateAbsDir(d); err != nil {
				return "", fmt.Errorf("storage_dir: %w", err)
			}
			storageDirs = append(storageDirs, d)
		}
	}
	destDirs := make([]string, 0, len(req.DestDirs))
	for _, d := range req.DestDirs {
		d = strings.TrimSpace(d)
		if d != "" {
			if err := ValidateAbsDir(d); err != nil {
				return "", fmt.Errorf("dest_dir: %w", err)
			}
			destDirs = append(destDirs, d)
		}
	}

	var projects map[string]string
	if len(req.Projects) > 0 {
		projects = make(map[string]string, len(req.Projects))
		for k, v := range req.Projects {
			k = strings.TrimSpace(k)
			v = strings.TrimSpace(v)
			if err := ValidateID(k); err != nil {
				return "", fmt.Errorf("projects key %q: %w", k, err)
			}
			if err := ValidateAbsDir(v); err != nil {
				return "", fmt.Errorf("projects[%s] dir: %w", k, err)
			}
			projects[k] = v
		}
	}
	var projectDirs map[string][]string
	if len(req.ProjectDirs) > 0 {
		projectDirs = make(map[string][]string, len(req.ProjectDirs))
		for k, dirs := range req.ProjectDirs {
			k = strings.TrimSpace(k)
			if err := ValidateID(k); err != nil {
				return "", fmt.Errorf("project_dirs key %q: %w", k, err)
			}
			clean := make([]string, 0, len(dirs))
			for _, d := range dirs {
				d = strings.TrimSpace(d)
				if d == "" {
					continue
				}
				if err := ValidateAbsDir(d); err != nil {
					return "", fmt.Errorf("project_dirs[%s]: %w", k, err)
				}
				clean = append(clean, d)
			}
			if len(clean) > 0 {
				projectDirs[k] = clean
			}
		}
	}

	var destDir string
	awaitDisk := req.AwaitDiskSelection
	if awaitDisk {
		// Activate-first mode: node comes online, scans physical host disks, and stays standby until user selects disks in Console.
		storageDirs = nil
		projects = nil
		projectDirs = nil
		destDirs = nil
		onlyProject = ""
	} else if len(storageDirs) > 0 && onlyProject == "" {
		// Managed disk-pool mode (recommended): Center controls projects, scheduling, and disk toggles dynamically.
		projects = nil
		projectDirs = nil
		destDirs = nil
	} else if onlyProject != "" {
		// Single-project receiver mode: strictly pin only_project locally with storage_dirs or dest_dir(s).
		projects = nil
		projectDirs = nil
		if len(storageDirs) == 0 {
			if len(destDirs) == 0 {
				destDir = filepath.Join("/data/relay-b/files", onlyProject)
			} else if len(destDirs) == 1 {
				destDir = destDirs[0]
				destDirs = nil
			}
		} else {
			destDirs = nil
		}
	} else if len(projects) == 0 && len(projectDirs) == 0 {
		// Default fallback: wait for disk selection in Console so we never guess paths or write to "/" unintentionally.
		awaitDisk = true
	}
	maxConc := req.MaxConcurrent
	if maxConc <= 0 {
		maxConc = 3
	}
	if maxConc > 1024 {
		maxConc = 1024
	}
	tokVal := rawToken
	if tokVal == "" {
		tokVal = "<REPLACE_WITH_RECEIVER_NODE_TOKEN>"
	}

	bCfg := agentb.Config{
		NodeID:               node.ID,
		NodeName:             node.Name,
		CenterURL:            centerPublicURL,
		CenterToken:          tokVal,
		CACert:               filepath.Join(installDir, "certs", "ca.crt"),
		StorageDirs:          storageDirs,
		AwaitDiskSelection:   awaitDisk,
		OnlyProject:          onlyProject,
		DestDir:              destDir,
		DestDirs:             destDirs,
		Projects:             projects,
		ProjectDirs:          projectDirs,
		StateDir:             stateDir,
		MaxConcurrent:        maxConc,
		AckBatchIntervalMs:   req.AckBatchIntervalMs,
		MaxDiskUsagePct:      90.0,
		MinFreeDiskBytes:     req.MinFreeDiskBytes,
		PollIntervalSec:      10,
		HeartbeatIntervalSec: 2,
	}
	cfgYAML, err := yaml.Marshal(&bCfg)
	if err != nil {
		return "", err
	}

	binPath := filepath.Join(installDir, "relay-agent-b")
	cfgPath := filepath.Join(installDir, "agent-b.yaml")
	unit := RenderSystemdUnit("Relay Download Intranet Receiver", binPath, cfgPath, installDir)
	dlURL := strings.TrimRight(centerPublicURL, "/") + "/api/v1/releases/" + rel.ID + "/download"

	caEOF := randomHeredocDelim("RELAY_CA_EOF")
	cfgEOF := randomHeredocDelim("RELAY_CFG_EOF")
	svcEOF := randomHeredocDelim("RELAY_SVC_EOF")
	if bytes.Contains(caCertPEM, []byte(caEOF)) || bytes.Contains(cfgYAML, []byte(cfgEOF)) || strings.Contains(unit, svcEOF) {
		return "", errors.New("heredoc delimiter collision")
	}

	verBanner := fmt.Sprintf("[1/4] 从中心服务器下载 relay-agent-b (%s %s/%s)...", rel.Version, rel.OS, rel.Arch)

	var sb strings.Builder
	sb.WriteString("#!/usr/bin/env bash\nset -euo pipefail\n\n")
	sb.WriteString("if [ \"$(id -u)\" -ne 0 ]; then echo '请使用 root 或 sudo 运行此安装脚本'; exit 1; fi\n\n")
	sb.WriteString(fmt.Sprintf("INSTALL_DIR=%s\nSTATE_DIR=%s\nNODE_ID=%s\nNODE_TOKEN=%s\nEXPECTED_SHA=%s\nDOWNLOAD_URL=%s\n\n",
		ShellQuote(installDir), ShellQuote(stateDir), ShellQuote(node.ID), ShellQuote(tokVal), ShellQuote(rel.SHA256), ShellQuote(dlURL)))
	sb.WriteString("mkdir -p \"$INSTALL_DIR/certs\" \"$STATE_DIR\"\n")
	sb.WriteString("cat > \"$INSTALL_DIR/certs/ca.crt\" <<'" + caEOF + "'\n")
	sb.Write(caCertPEM)
	if len(caCertPEM) > 0 && caCertPEM[len(caCertPEM)-1] != '\n' {
		sb.WriteByte('\n')
	}
	sb.WriteString(caEOF + "\nchmod 644 \"$INSTALL_DIR/certs/ca.crt\"\n\n")
	sb.WriteString("echo " + ShellQuote(verBanner) + "\n")
	sb.WriteString("curl -fsSL --tlsv1.3 --cacert \"$INSTALL_DIR/certs/ca.crt\" \\\n")
	sb.WriteString("  -H \"X-Node-ID: $NODE_ID\" -H \"X-Node-Token: $NODE_TOKEN\" \\\n")
	sb.WriteString("  \"$DOWNLOAD_URL\" -o \"$INSTALL_DIR/relay-agent-b.tmp\"\n")
	sb.WriteString("ACTUAL_SHA=$(sha256sum \"$INSTALL_DIR/relay-agent-b.tmp\" | awk '{print $1}')\n")
	sb.WriteString("if [ \"$ACTUAL_SHA\" != \"$EXPECTED_SHA\" ]; then echo \"SHA256 校验失败: $ACTUAL_SHA\"; rm -f \"$INSTALL_DIR/relay-agent-b.tmp\"; exit 1; fi\n")
	sb.WriteString("chmod 755 \"$INSTALL_DIR/relay-agent-b.tmp\"\n")
	sb.WriteString("\"$INSTALL_DIR/relay-agent-b.tmp\" -version\n")
	sb.WriteString("systemctl stop relay-agent-b 2>/dev/null || true\n")
	sb.WriteString("mv -f \"$INSTALL_DIR/relay-agent-b.tmp\" \"$INSTALL_DIR/relay-agent-b\"\n\n")
	sb.WriteString("echo '[2/4] 写入 agent-b.yaml ...'\n")
	sb.WriteString("cat > \"$INSTALL_DIR/agent-b.yaml\" <<'" + cfgEOF + "'\n")
	sb.Write(cfgYAML)
	if len(cfgYAML) > 0 && cfgYAML[len(cfgYAML)-1] != '\n' {
		sb.WriteByte('\n')
	}
	sb.WriteString(cfgEOF + "\nchmod 600 \"$INSTALL_DIR/agent-b.yaml\"\n\n")
	sb.WriteString("echo '[3/4] 写入 systemd 服务 ...'\n")
	sb.WriteString("cat > /etc/systemd/system/relay-agent-b.service <<'" + svcEOF + "'\n")
	sb.WriteString(unit)
	sb.WriteString(svcEOF + "\nchmod 644 /etc/systemd/system/relay-agent-b.service\n\n")
	sb.WriteString("echo '[4/4] 启动并设置开机自启 ...'\n")
	sb.WriteString("systemctl daemon-reload\nsystemctl enable --now relay-agent-b\nsystemctl status relay-agent-b --no-pager\n")
	return sb.String(), nil
}

// RenderAgentAInstallScript generates a self-contained bash installer for dispatch (agent_a) nodes,
// embedding CA cert + freshly issued IP/DNS-SAN leaf cert/key, pulling the verified binary over TLS 1.3,
// writing agent-a.yaml, and enabling systemd. Suitable when direct SSH from Center is unavailable or NAT/FRP is used.
func RenderAgentAInstallScript(
	centerPublicURL string,
	caCertPEM, leafCertPEM, leafKeyPEM []byte,
	jwtSecret, centerSecret string,
	node protocol.NodeRecord,
	rawToken, localToken string,
	rel protocol.ReleaseRecord,
	req protocol.AgentAScriptReq,
) (string, error) {
	if err := ValidateID(node.ID); err != nil {
		return "", fmt.Errorf("node_id: %w", err)
	}
	if err := ValidateSafeSingleLine(node.Name, 128); err != nil {
		return "", fmt.Errorf("node_name: %w", err)
	}
	if u, err := url.Parse(strings.TrimSpace(centerPublicURL)); err != nil || u.Scheme != "https" || u.Host == "" {
		return "", errors.New("centerPublicURL must be a valid https:// URL")
	}
	if err := ValidateSafeSingleLine(centerPublicURL, 512); err != nil {
		return "", fmt.Errorf("center_url: %w", err)
	}
	pubAddr := strings.TrimSpace(req.PublicAddr)
	if pubAddr == "" {
		pubAddr = strings.TrimSpace(node.PublicAddr)
	}
	pubU, err := url.Parse(pubAddr)
	if err != nil || pubU.Scheme != "https" || pubU.Host == "" {
		return "", errors.New("public_addr must be a valid https://host:port URL")
	}
	if err := ValidateSafeSingleLine(pubAddr, 512); err != nil {
		return "", fmt.Errorf("public_addr: %w", err)
	}
	if !validVersionRe.MatchString(rel.Version) || (rel.OS != "linux" && rel.OS != "darwin") || (rel.Arch != "amd64" && rel.Arch != "arm64") {
		return "", errors.New("invalid release metadata")
	}
	if !validHexRe.MatchString(rel.SHA256) {
		return "", errors.New("invalid release sha256")
	}
	if !validIDRe.MatchString(rel.ID) {
		return "", errors.New("invalid release id")
	}
	if rawToken != "" {
		if err := ValidateSafeSingleLine(rawToken, 256); err != nil {
			return "", fmt.Errorf("node_token: %w", err)
		}
	}
	if err := ValidateSafeSingleLine(localToken, 256); err != nil || localToken == "" {
		return "", errors.New("invalid local_token")
	}

	installDir := strings.TrimSpace(req.InstallDir)
	if installDir == "" {
		installDir = "/opt/relay-agent-a"
	}
	dataDir := strings.TrimSpace(req.DataDir)
	awaitDisk := req.AwaitDiskSelection
	if awaitDisk {
		dataDir = filepath.Join(installDir, "state")
	} else if dataDir == "" {
		dataDir = "/data/relay-a"
	}
	if err := ValidateAbsDir(installDir); err != nil {
		return "", fmt.Errorf("install_dir: %w", err)
	}
	if err := ValidateAbsDir(dataDir); err != nil {
		return "", fmt.Errorf("data_dir: %w", err)
	}

	pubPort := req.PublicPort
	if pubPort <= 0 {
		if pStr := pubU.Port(); pStr != "" {
			if p, pErr := strconv.Atoi(pStr); pErr == nil && p > 0 {
				pubPort = p
			}
		}
		if pubPort <= 0 {
			pubPort = 8443
		}
	}
	locPort := req.LocalPort
	if locPort <= 0 {
		locPort = 18081
	}
	if pubPort < 1 || pubPort > 65535 || locPort < 1 || locPort > 65535 || pubPort == locPort {
		return "", errors.New("invalid public_port / local_port")
	}
	maxDiskPct := req.MaxDiskUsagePct
	if maxDiskPct <= 0 {
		maxDiskPct = 85.0
	}
	leaseTTL := req.LeaseTTLSec
	if leaseTTL <= 0 {
		leaseTTL = 300
	}
	maxStreams := req.MaxConcurrentStreams
	if maxStreams <= 0 {
		maxStreams = 16
	}
	tokVal := rawToken
	if tokVal == "" {
		tokVal = "<REPLACE_WITH_DISPATCH_NODE_TOKEN>"
	}

	certPath := filepath.Join(installDir, "certs", node.ID+".crt")
	keyPath := filepath.Join(installDir, "certs", node.ID+".key")
	aCfg := agenta.Config{
		NodeID:                 node.ID,
		NodeName:               node.Name,
		CenterURL:              centerPublicURL,
		CenterToken:            tokVal,
		JWTSecret:              jwtSecret,
		CenterSecret:           centerSecret,
		LocalToken:             localToken,
		LocalListen:            fmt.Sprintf("127.0.0.1:%d", locPort),
		PublicListen:           fmt.Sprintf("0.0.0.0:%d", pubPort),
		PublicAddr:             pubAddr,
		TLSCert:                certPath,
		TLSKey:                 keyPath,
		CACert:                 filepath.Join(installDir, "certs", "ca.crt"),
		DataDir:                dataDir,
		AwaitDiskSelection:     awaitDisk,
		Projects:               append([]string(nil), node.Projects...),
		MaxDiskUsagePct:        maxDiskPct,
		LeaseTTLSec:            leaseTTL,
		MaxConcurrentStreams:   maxStreams,
		RateLimitMBps:          req.RateLimitMBps,
		HeartbeatIntervalSec:   2,
		DeleteBatchIntervalSec: 0,
	}
	cfgYAML, err := yaml.Marshal(&aCfg)
	if err != nil {
		return "", err
	}

	binPath := filepath.Join(installDir, "relay-agent-a")
	cfgPath := filepath.Join(installDir, "agent-a.yaml")
	unit := RenderSystemdUnit("Relay Download Public Dispatch Node", binPath, cfgPath, installDir)
	dlURL := strings.TrimRight(centerPublicURL, "/") + "/api/v1/releases/" + rel.ID + "/download"

	caEOF := randomHeredocDelim("RELAY_CA_EOF")
	certEOF := randomHeredocDelim("RELAY_CERT_EOF")
	keyEOF := randomHeredocDelim("RELAY_KEY_EOF")
	cfgEOF := randomHeredocDelim("RELAY_CFG_EOF")
	svcEOF := randomHeredocDelim("RELAY_SVC_EOF")
	if bytes.Contains(caCertPEM, []byte(caEOF)) ||
		bytes.Contains(leafCertPEM, []byte(certEOF)) ||
		bytes.Contains(leafKeyPEM, []byte(keyEOF)) ||
		bytes.Contains(cfgYAML, []byte(cfgEOF)) ||
		strings.Contains(unit, svcEOF) {
		return "", errors.New("heredoc delimiter collision")
	}

	verBanner := fmt.Sprintf("[1/5] 从中心服务器下载 relay-agent-a (%s %s/%s)...", rel.Version, rel.OS, rel.Arch)
	writePEMBlock := func(sb *strings.Builder, destExpr string, data []byte, delim, mode string) {
		sb.WriteString("cat > " + destExpr + " <<'" + delim + "'\n")
		sb.Write(data)
		if len(data) > 0 && data[len(data)-1] != '\n' {
			sb.WriteByte('\n')
		}
		sb.WriteString(delim + "\nchmod " + mode + " " + destExpr + "\n")
	}

	var sb strings.Builder
	sb.WriteString("#!/usr/bin/env bash\nset -euo pipefail\n\n")
	sb.WriteString("if [ \"$(id -u)\" -ne 0 ]; then echo '请使用 root 或 sudo 运行此安装脚本'; exit 1; fi\n\n")
	sb.WriteString(fmt.Sprintf("INSTALL_DIR=%s\nDATA_DIR=%s\nNODE_ID=%s\nNODE_TOKEN=%s\nEXPECTED_SHA=%s\nDOWNLOAD_URL=%s\n\n",
		ShellQuote(installDir), ShellQuote(dataDir), ShellQuote(node.ID), ShellQuote(tokVal), ShellQuote(rel.SHA256), ShellQuote(dlURL)))
	sb.WriteString("mkdir -p \"$INSTALL_DIR/certs\" \"$DATA_DIR\"\n")
	writePEMBlock(&sb, "\"$INSTALL_DIR/certs/ca.crt\"", caCertPEM, caEOF, "644")
	sb.WriteString("\necho " + ShellQuote(verBanner) + "\n")
	sb.WriteString("curl -fsSL --tlsv1.3 --cacert \"$INSTALL_DIR/certs/ca.crt\" \\\n")
	sb.WriteString("  -H \"X-Node-ID: $NODE_ID\" -H \"X-Node-Token: $NODE_TOKEN\" \\\n")
	sb.WriteString("  \"$DOWNLOAD_URL\" -o \"$INSTALL_DIR/relay-agent-a.tmp\"\n")
	sb.WriteString("ACTUAL_SHA=$(sha256sum \"$INSTALL_DIR/relay-agent-a.tmp\" | awk '{print $1}')\n")
	sb.WriteString("if [ \"$ACTUAL_SHA\" != \"$EXPECTED_SHA\" ]; then echo \"SHA256 校验失败: $ACTUAL_SHA\"; rm -f \"$INSTALL_DIR/relay-agent-a.tmp\"; exit 1; fi\n")
	sb.WriteString("chmod 755 \"$INSTALL_DIR/relay-agent-a.tmp\"\n")
	sb.WriteString("\"$INSTALL_DIR/relay-agent-a.tmp\" -version\n")
	sb.WriteString("systemctl stop relay-agent-a 2>/dev/null || true\n")
	sb.WriteString("mv -f \"$INSTALL_DIR/relay-agent-a.tmp\" \"$INSTALL_DIR/relay-agent-a\"\n\n")
	sb.WriteString("echo '[2/5] 写入 TLS 节点证书与私钥 ...'\n")
	writePEMBlock(&sb, ShellQuote(certPath), leafCertPEM, certEOF, "644")
	writePEMBlock(&sb, ShellQuote(keyPath), leafKeyPEM, keyEOF, "600")
	sb.WriteString("\necho '[3/5] 写入 agent-a.yaml ...'\n")
	writePEMBlock(&sb, "\"$INSTALL_DIR/agent-a.yaml\"", cfgYAML, cfgEOF, "600")
	sb.WriteString("\necho '[4/5] 写入 systemd 服务 ...'\n")
	sb.WriteString("cat > /etc/systemd/system/relay-agent-a.service <<'" + svcEOF + "'\n")
	sb.WriteString(unit)
	sb.WriteString(svcEOF + "\nchmod 644 /etc/systemd/system/relay-agent-a.service\n\n")
	sb.WriteString("echo '[5/5] 启动并设置开机自启 ...'\n")
	sb.WriteString("systemctl daemon-reload\nsystemctl enable --now relay-agent-a\nsystemctl status relay-agent-a --no-pager\n")
	return sb.String(), nil
}
