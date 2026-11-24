# Relay Download — 需求定稿、架构决策与新会话交接指南

> 本文档完整记录本项目从需求讨论、架构审核到当前实现与验收的全量上下文。在新对话窗口中直接让助手阅读本文件即可无缝接续开发。

---

## 一、最终确认的核心需求与业务边界

### 1. 业务目标
替代“公网 A → 云存储中转 → 内网 B”的传统链路，实现 **无云存储中转、多公网 A 节点与多内网 B 节点直连的大文件流式传输系统**。

### 2. 已拍板的硬性规则（不可随意变更）
| 维度 | 最终确认方案 |
|---|---|
| **技术栈** | 纯 Go（`CGO_ENABLED=0`，单二进制零依赖可交叉编译 Linux amd64）+ SQLite（中心）+ BoltDB（A/B 本地状态）+ 中心内嵌 Web 控制台 |
| **文件来源（模块 2 / A 节点）** | **仅支持 A 本机接口上传 / 本机路径零拷贝注册**（不做第三方 HTTP 源站拉取边下边传） |
| **可下载时机** | **必须上传完成且 SHA256 校验通过后**，才转为 `READY` 开放给 B 下载 |
| **文件清单存储位置** | **绝不在中心服务器持久化全量文件列表**；文件清单仅存在于各自 `A1/A2/A3` 本地，B 校验确认后 **即用即删** |
| **中心服务器职责（模块 1）** | 部署在公网 IP；仅保存项目/节点配置、**内存实时可用性索引（知道哪台 A 有多少可下载文件）**、**历史汇总统计数据**；Web UI 查单台 A 在途明细时，由中心**实时穿透查询** A 节点（2s 超时，不落中心库） |
| **多台 B 消费模式（模块 3）** | **多台 B 抢占式消费**（每个文件仅由 1 台 B 消费）；B 位于内网无公网 IP、零入站端口，全连接由 B 主动对外发起 |
| **A 节点磁盘保护** | **不做未下载文件自动过期删除**；由 A 本地做 **磁盘水位检测**（默认使用率 ≥ 85% 或低于最小剩余空间阈值时拒收新上传返回 `507` 并向中心告警） |
| **B 端同名冲突策略** | 按项目目录隔离，**项目内部采用原子覆盖原则（`overwrite`）**（支持按项目配置 `auto_rename` / `skip`） |
| **网络与加密（裸 IPv4）** | `A1/A2/A3` 与中心均为 **裸公网 IPv4**；使用内置轻量 **自建 Root CA + IP-SAN 证书签发工具**，全链路严格 TLS 1.3 + HTTP/2 加密校验（不跳过证书验证） |

---

## 二、已通过审核的 9 项关键架构决策

新会话在后续扩展或修改代码时请保留以下已验证的设计：

1. **双端口物理隔离（模块 2 / Agent A）**：
   - 本地上传/注册端口强制仅绑定 `127.0.0.1:18081` + `X-Local-Token`，防止公网攻击者向 A 灌垃圾文件；
   - 公网传输端口监听 `0.0.0.0:8443`（TLS 1.3 + HTTP/2），仅暴露 B 抢占/流式下载与中心穿透查询接口。
2. **原子抢占锁落在 A 本地 BoltDB**：
   - 每个文件仅属于一台 A，直接由 A 本地 BoltDB 事务执行 `READY -> CLAIMED` 原子加锁，零中心分布式锁复杂度，天然保证多 B 并发抢占零重复。
3. **两层凭证解决大文件续传 JWT 过期问题**：
   - 中心签发短效 `access_jwt`（默认 15 min）用于 B 调用 `/api/v1/claim`；
   - 抢占成功后由 A 签发绑定该文件的 `lease_token`，随租约自动续期持续有效，长耗时大文件断点续传不会因 JWT 过期报 `401`。
4. **租约自动续期 + 宕机超时接管**：
   - 默认 `lease_ttl_sec = 300`（项目级可配）；传输流活跃期 A 每 15s 自动续租，B 端后台协程亦定期 `/renew`；
   - 若 B 真宕机超 TTL，A 的 `reapLoop` 自动把任务释放回 `READY` 由其他 B 接管；僵尸 B 再带过期 `lease_token` 请求时返回 `409 Conflict` 并自动清理本地过期 `.part`。
5. **物理删除先于 BoltDB 记录移除（原子即用即删）**：
   - `Store.AckAndRemove` 在 BoltDB 写事务内校验 `lease_id`、`lease_token`、`b_node_id` 与 `SHA256` 后，先执行 `os.Remove` 删除物理文件再提交删除 BoltDB 记录，消除“记录已空但物理文件残留”的竞态窗口；
   - A 维护短期已删 `file_id` 内存 LRU，重复 ACK 幂等返回 `200 OK {"status":"already_deleted"}`。
6. **中心汇总数据幂等精准去重**：
   - A 端持久化 `pending_events` 队列保证上报不丢；每条事件携带唯一 `event_id`；
   - 中心使用 24 小时滚动清理的 `event_dedup` 表做幂等去重，既不保留文件明细，又保证汇总统计不重不漏。
7. **防惊群 SSE 精准唤醒**：
   - B 与中心维持出站 SSE 长连接（配低频轮询兜底）；中心按 `ready_count + 1` 优先唤醒空闲 B，B 端叠加 20~100ms 抖动并打散候选 A 节点顺序。
8. **恒定低内存流式 IO**：
   - 全链路（A 上传落盘、A 流式推送、B 流式落盘、SHA256 重算）统一使用 `sync.Pool` 复用固定 `256 KiB` 缓冲区，配并发信号量与可选令牌桶限速。
9. **路径穿越防护与原子落盘**：
   - `transfer.SanitizeRelativePath` + `transfer.SafeJoin` 拒绝 `..`、绝对路径与空字节；
   - B 端下载写入 `.relay_tmp/<file_id>.part`，校验整文件 SHA256 一致后 `fsync` + 原子 `os.Rename` 落盘，再持久化 `pending_acks` 重试至 A 确认。

---

## 三、当前代码结构与模块清单

项目路径：`/Users/nezha/Worker/Worker/titan/relay-download`

```text
relay-download/
├── cmd/
│   ├── relay-center/main.go      # 模块 1 入口（serve + pki init-ca / pki issue）
│   ├── relay-agent-a/main.go     # 模块 2 入口
│   └── relay-agent-b/main.go     # 模块 3 入口
├── internal/
│   ├── protocol/                 # 共享请求/响应结构与 JSON HTTP 辅助函数
│   ├── auth/                     # HS256 JWT 签发验签、常量时间比对、Token 哈希
│   ├── pki/                      # 自建 ECDSA P-256 Root CA 与 IP-SAN 证书签发及 TLS 配置
│   ├── transfer/                 # 256KiB 缓冲池流式复制、SHA256、限速、路径净化、statfs 磁盘检测
│   ├── center/                   # 模块 1：config / SQLite store / 内存 Hub / HTTP+SSE+穿透代理 / 内嵌 web/
│   ├── agenta/                   # 模块 2：config / BoltDB store / 双端口服务与水位检测
│   ├── agentb/                   # 模块 3：config / BoltDB store / SSE+抢占工作池+断点续传+ACK 重试
│   └── e2e/e2e_test.go           # 全链路端到端集成与故障演练测试
├── deploy/                       # center / agent-a / agent-b 示例 YAML 配置
├── docs/DESIGN_AND_HANDOFF.md    # 本文档
├── bin/                          # 已构建产物（macOS 本机 + bin/linux-amd64/ 静态二进制）
├── Makefile
└── README.md
```

---

## 四、当前已完成的验收状态

截至交接时，以下检查全部通过（`exit 0`）：
- `go vet ./...` 通过；
- `go test -v -race ./...` 全部通过（无数据竞争）：
  - `internal/auth`: `TestJWTSignVerifyAndExpiry`
  - `internal/pki`: `TestInitCAAndIssueIPCert`
  - `internal/transfer`: `TestSanitizeAndSafeJoin`、`TestCopyStreamAndHash`
  - `internal/e2e`:
    - `TestEndToEndFullFlowAndSummaryOnly`（路径穿越拦截、错误 SHA256 拦截、上传/注册、穿透查询、即用即删、中心无文件表校验、汇总精准、项目内原子覆盖）
    - `TestMultiBCompetingPreemptiveClaim`（2 台 A + 3 台 B 并发抢占 30 文件，零重复零遗漏）
    - `TestResumableDownloadAfterMidStreamDrop`（4 MiB 文件传输至 1.5 MiB 强制断流后 `Range` 自动续传校验通过）
    - `TestLeaseExpiryFailoverAndIdempotentAck`（租约过期故障接管、过期租约 409 拒绝、重复 ACK 幂等、中心汇总去重）
    - `TestAgentADiskWatermarkAlarm`（A 端磁盘水位超限返回 507 并在中心触发告警）
- `make build` 与 `make build-linux` 均已生成零依赖静态二进制（`bin/` 与 `bin/linux-amd64/`）。

---

## 五、新窗口快速接续提示词（直接复制发送即可）

在打开 `/Users/nezha/Worker/Worker/titan/relay-download` 的新对话窗口中，复制发送下面这段话即可直接衔接：

```text
请先阅读 docs/DESIGN_AND_HANDOFF.md 和 README.md 了解本项目已完成的需求定稿、架构决策和当前实现状态。后续我们在此基础上继续推进。
```
