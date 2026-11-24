# Relay Download — A/B 多节点去中心化流式文件传输系统

纯 Go（零 CGO、单二进制）实现的去云存储、多公网 A 节点与多内网 B 节点直传系统。

## 核心特性
- **去中心化文件队列 + 汇总留痕**：文件清单仅存在 `A1/A2/A3` 本地，下载校验确认后 **即用即删**；中心服务器仅知道“哪台 A 有多少可下载文件”并持久化按项目/日期的汇总统计，同时支持在 Web 控制台实时穿透查看单台 A 的在途队列。
- **上传完校验完才开放下载**：A 节点提供仅监听 `127.0.0.1` 的本机流式上传接口与本地路径零拷贝注册接口，强制完成落盘与 SHA256 校验后才转为 `READY`。
- **多台 B 抢占式消费**：抢占锁原子落在各自 A 节点（BoltDB 事务），支持租约自动续期与宕机超时接管。
- **大文件稳定直传**：全链路 TLS 1.3 + HTTP/2 流式读写（固定 256 KiB 缓冲池控内存）、`Range` 断点续传、断线自动重连、SHA256 端到端校验、项目内原子覆盖、持久化幂等 ACK。
- **裸 IPv4 开箱加密**：内置轻量 Root CA 与 IP-SAN 证书签发命令，无需域名即可完成严格 TLS 证书校验。

## 快速开始

### 1. 构建二进制
```bash
# 当前平台构建
make build

# 交叉编译 Linux amd64 / arm64 静态二进制（支持通过 VERSION 注入版本号）
make build-linux VERSION=v1.0.0
make build-linux-arm64 VERSION=v1.0.0
```

### 2. 一键签发裸 IPv4 TLS 证书
```bash
# 1) 生成自建 Root CA
./bin/relay-center pki init-ca -out ./certs

# 2) 为中心服务器签发证书（填入中心公网 IPv4）
./bin/relay-center pki issue -ca ./certs/ca.crt -ca-key ./certs/ca.key -out ./certs -name center -ip 5.6.7.8,127.0.0.1

# 3) 为每个公网节点 A1 / A2 / A3 签发证书
./bin/relay-center pki issue -ca ./certs/ca.crt -ca-key ./certs/ca.key -out ./certs -name a1 -ip 1.2.3.4,127.0.0.1
```
将 `ca.crt` 分发至中心、所有 A 节点与所有 B 节点；将各节点对应的 `.crt`/`.key` 放到对应机器。

### 3. 启动三端服务
参考 `deploy/*.example.yaml` 准备配置文件后分别启动：
```bash
# 中心服务器（访问 https://<center_ip>:8440 打开 Web 控制台，创建项目并注册 A/B 节点获取 Token）
./bin/relay-center serve -config center.yaml

# 公网节点 A1
./bin/relay-agent-a -config agent-a.yaml

# 内网节点 B1 / B2（无需公网 IP，零入站端口）
./bin/relay-agent-b -config agent-b.yaml
```

### 4. 在 A 节点提交待下载文件（本机调用）

**方式一：流式 HTTP 上传（原始二进制流）**
```bash
SHA=$(shasum -a 256 /tmp/big.tar.gz | awk '{print $1}')
curl -X POST http://127.0.0.1:18081/local/v1/upload \
  -H "X-Local-Token: <local_token>" \
  -H "X-Project: proj-alpha" \
  -H "X-Filename: releases/big.tar.gz" \
  -H "X-Expected-SHA256: $SHA" \
  --data-binary @/tmp/big.tar.gz
```

**方式二：Multipart 表单流式上传**
```bash
curl -X POST http://127.0.0.1:18081/local/v1/upload \
  -H "X-Local-Token: <local_token>" \
  -F "project=proj-alpha" \
  -F "filename=big.tar.gz" \
  -F "file=@/tmp/big.tar.gz"
```

**方式三：本地路径零拷贝注册（推荐大文件已在 A 磁盘时使用）**
```bash
curl -X POST http://127.0.0.1:18081/local/v1/register \
  -H "X-Local-Token: <local_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "project_id": "proj-alpha",
    "local_path": "/data/staging/big.tar.gz",
    "filename": "big.tar.gz",
    "mode": "move"
  }'
```

### 5. Web 控制台一键部署与批量更新

在 `center.yaml` 中配置好 `ca_key`、`public_url` 与 `releases_dir`（参考 [deploy/center.example.yaml](deploy/center.example.yaml)），即可在控制台 **「部署与版本」** 中完成全生命周期运维：

1. **上传发布包**：在「部署与版本」页签上传 `bin/linux-amd64/relay-agent-a` 与 `relay-agent-b` 静态二进制（自动校验 Linux ELF 头与 SHA256）。
2. **公网 A 节点一键 SSH 部署**：点击 **「一键部署公网 A 节点 (SSH)」**，填入目标公网 IP（默认使用中心本机 SSH 私钥免密以 `root` 登录，亦支持临时密码）：
   - **步骤 1（环境预检）**：自动检测 `root` 权限、系统/架构、`systemd`、公网/本机端口占用、安装与数据目录占用及磁盘水位、已有服务及中心 CA/发布包就绪状态；
   - **步骤 2（确认一键部署）**：自动用内置 PKI 为目标 IP 签发 IP-SAN 证书、流式推送二进制并校验远端 `sha256sum` 与 `-version`、写入 `agent-a.yaml` 与 `systemd` 服务并拉起验证上线，同时展示一次性 `X-Local-Token`。
3. **内网 B 节点一键安装脚本**：在「B 节点」页签点击 **「安装脚本」**（或在新建 B 节点后直接点击生成），导出内嵌 `ca.crt`、走严格 TLS 1.3 拉取二进制与 `systemd` 启动的自包含 `bash` 脚本，在内网 B 主机以 `root` 执行即可。
4. **全集群批量更新（A + B）**：上传新版本二进制后，在「A 节点」或「B 节点」页签勾选多台目标节点并选择目标版本点击 **「批量更新」**；各节点通过心跳收到升级指令后主动 HTTPS 拉取、校验 SHA256、执行 `-version` 防砖自检、原子替换二进制并优雅退出交由 `systemd` 自动拉起新版本。
