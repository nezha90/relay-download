# HTTP PUT 本地接入说明文档

> 适用版本：`v1.14.1+`（支持通过 `X-Customer` / `X-Project-Name` 首次建项自动归属客户，默认本机免 Token 接入）

本文档面向业务方与数据生产脚本开发者，介绍如何通过本机 HTTP 接口将文件写入 **分发节点**，由系统自动完成持久化、完整性校验、公网 TLS 1.3 传输、内网接收节点落盘与客户归属分发。

---

## 1. 工作流程与核心特性

```text
业务脚本 / 采集程序 (同机)
   │  HTTP PUT http://127.0.0.1:<local_port>/local/v1/files/<项目ID>/<相对路径>
   │  Header: X-Customer / X-Project-Name / X-Expected-SHA256 (均可选)
   ▼
分发节点 (本机回环监听，零公网暴露)
   │  1. 流式写入临时文件 + 实时计算 SHA-256 + fsync 落盘
   │  2. 校验预期 SHA-256 & 强制磁盘水位保护
   │  3. 原子重命名入队 (ready) + 提交本地 SQLite + 返回 200 OK
   ▼
中心服务 (自动建项 & 首次绑定客户账号，不覆盖已有项目权限)
   ▼
内网接收节点 (严格 TLS 1.3 拉取 → 校验 SHA-256 + fsync 落盘 → ACK 后分发节点安全清理缓存)
```

- **数据零丢失**：返回 `200 OK` 前已完成临时文件 `fsync`、SHA-256 校验与原子入队；下游接收节点未完成 SHA-256 校验落盘并 ACK 前，分发节点绝不删除缓存副本。
- **自动建项与直达客户**：上传一个尚未存在的 `<项目ID>` 时，中心会自动创建该项目；搭配 `X-Customer` 可在首次建项时直接授权给指定客户账号，无需后台二次分配。
- **本机直连免密 + 5 层防线**：默认仅监听本机回环地址（`127.0.0.1` / `::1`），同机脚本无需配置 Token；同时强制拦截非回环来源、DNS Rebinding、跨源请求与反向代理转发。
- **内置水位反压**：当分发节点缓存盘达到强制水位上限（默认 `85%`，控制台可按 `1% ~ 99%` 自定义）时返回 `507 Insufficient Storage`，上游按退避策略等待即可自动恢复。

---

## 2. 接入地址与安全限制

### 2.1 监听地址

- 默认监听：`http://127.0.0.1:18081`
- 实际端口以分发节点配置文件中的 `local_listen` 为准（不同节点可能自定义为其他端口，如 `127.0.0.1:18445`）。
- 本机快速确认监听端口：

```bash
grep local_listen /opt/relay-agent-a/agent-a.yaml
```

### 2.2 强制安全策略（必须遵守）

分发节点本地上传接口强制执行以下校验，违反任意一条将返回 **`403 Forbidden`**：

| 校验项 | 要求 | 说明 |
| :--- | :--- | :--- |
| 来源地址 (`RemoteAddr`) | 必须是本机回环 (`127.0.0.1` / `::1`) | **仅允许同机调用**，不可跨机访问 |
| `Host` 请求头 | 必须是 `127.0.0.1`、`[::1]` 或 `localhost`（可带端口） | 防止 DNS Rebinding 攻击 |
| `Origin` 请求头 | 不得携带非回环来源 | 防止浏览器跨源 CSRF |
| 代理转发头 | 禁止携带 `X-Forwarded-For`、`Forwarded`、`X-Real-IP` | **严禁在本地端口前套用 Nginx/Caddy 等反向代理** |
| Token 鉴权（可选） | 默认关闭（免 Token） | 仅当节点显式开启 `require_local_token: true` 时，需携带 `X-Local-Token: <token>`，否则返回 `401` |

---

## 3. 主接口：`HTTP PUT` 流式上传（推荐）

最简单、零内存膨胀、适合从小文件到数十 GB 大文件的标准接入方式。

### 3.1 请求定义

```http
PUT /local/v1/files/{project}/{filename...} HTTP/1.1
Host: 127.0.0.1:18081
Content-Length: <文件字节数，强烈建议携带>
X-Customer: <客户账号ID，多个用英文逗号分隔，可选>
X-Project-Name: <项目显示名，可选>
X-Expected-SHA256: <64位十六进制SHA-256，可选>

<原始文件二进制内容>
```

### 3.2 路径参数说明

| 参数 | 必填 | 格式与限制 | 说明 |
| :--- | :--- | :--- | :--- |
| `{project}` | 是 | 仅允许 `[A-Za-z0-9._-]`，长度 `1 ~ 64`，禁止 `.`、`..` 及包含 `..` | 项目 ID。若不存在则由中心自动创建；若节点配置了静态项目白名单，未在白名单内会返回 `403` |
| `{filename...}` | 是 | 相对路径，支持多级子目录（如 `2026/11/vid001.mp4`） | 落盘相对路径。接收节点最终保存至 `<存储盘>/<project>/<filename>`。禁止以 `/` 开头、禁止 `..` 路径穿越、禁止空字节 `\x00`；反斜杠 `\` 会自动规范化为 `/` |

> **URL 编码提示**：如果 `{filename...}` 包含空格、`#`、`?`、`%` 或中文字符，请对路径分段进行 URL Percent-Encoding（保留斜杠 `/`），例如 Python 中使用 `urllib.parse.quote(rel_path, safe="/")`。服务端会自动解码并校验。

### 3.3 请求头与查询参数

| 请求头 | 等价 Query 参数 | 必填 | 说明 |
| :--- | :--- | :--- | :--- |
| `X-Customer`（兼容 `X-Account`） | `?customer=`（兼容 `?account=`） | 否 | 首次自动创建项目时，直接将该新项目授权给指定客户账号 ID。多个客户用英文逗号 `,` 分隔（最多 16 个，如 `cust-a,cust-b`） |
| `X-Project-Name` | `?project_name=` | 否 | 首次自动创建项目时的展示名称（自动去除换行，最长 128 字符；不传则默认等于 `{project}`） |
| `X-Expected-SHA256` | 无 | 否 | 64 位十六进制 SHA-256（不区分大小写）。服务端写完后校验不通过会立即删除临时文件并返回 `400` |
| `Content-Length` | 无 | 建议 | 携带后服务端会在落盘前预检磁盘水位，并将 `≥ 64 MiB` 的大文件优先路由到剩余可用空间最大的缓存盘 |
| `X-Local-Token` | 无 | 仅开启鉴权时 | 默认无需传递；仅当节点显式开启 `require_local_token: true` 时必填 |

> **中文项目显示名兼容性提示**：部分 HTTP 客户端库（如 Python `urllib` / `requests`、Java `HttpClient`）要求 HTTP Header 值必须为 Latin-1 编码，直接传中文 `X-Project-Name` 可能在客户端报错。若项目显示名含中文，推荐使用 URL 编码后的 Query 参数：`?project_name=%E5%AE%A2%E6%88%B7A%E9%A1%B9%E7%9B%AE`。

### 3.4 `X-Customer` / `X-Project-Name` 归属生效规则（重要）

1. **仅首次建项生效（原子保障）**：
   - 仅当 `{project}` 在中心数据库中**尚不存在**、由本次上传首次自动创建时，中心会在同一个 SQLite 事务内原子写入初始项目名并绑定目标客户账号。
   - **已存在项目绝不覆盖**：无论该项目是管理员在后台预创建的，还是此前上传已创建过的，后续请求携带的任何 `X-Customer` 或 `X-Project-Name` 都会被安全忽略，**不会覆盖或重新授予管理员已调整/回收的客户权限**。
2. **建议每次请求都携带**：
   - 并发上传新项目时，无法预知哪一个文件最先到达中心；持续在脚本中携带 `X-Customer` 可以确保最先触发建项的请求必定带有归属信息，后续请求自动空操作，完全幂等且安全。
3. **非法客户 ID 自动降级**：
   - 若传入不存在的账号 ID 或非 `customer` 角色的账号 ID（如管理员 ID），中心仅记录告警日志并跳过该 ID，**不会导致上传失败**，也不会产生越权风险。
4. **接收节点自动发现**：
   - 若目标客户名下的接收节点配置为“跟随账号全部授权项目”（项目列表为空），新项目一旦在中心创建并绑定到该客户，接收节点通常在 **2 秒内** 自动发现并开始拉取，全程无需人工介入。
5. **新项目默认配置**：
   - 自动创建的项目默认采用：`conflict_policy = overwrite`、`lease_ttl_sec = 300`、`group_affinity = true`、`description = "上传自动发现创建"`。如需定制（例如改为 `skip` / `auto_rename` 或配置项目限速），可在控制台项目管理中修改。

### 3.5 响应格式

#### 成功响应：`200 OK`

```json
{
  "file_id": "550e8400-e29b-41d4-a716-446655440000",
  "project_id": "proj-customer-a",
  "filename": "2026/11/video_001.mp4",
  "size": 104857600,
  "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
  "status": "ready",
  "customer_ids": ["cust-acme"]
}
```

| 字段 | 类型 | 说明 |
| :--- | :--- | :--- |
| `file_id` | string (UUID) | 本次文件在分发队列中的唯一 ID |
| `project_id` | string | 所属项目 ID |
| `filename` | string | 规范化后的相对路径 |
| `size` | int64 | 实际落盘字节数 |
| `sha256` | string | 服务端流式计算得到的 SHA-256（小写 64 位十六进制） |
| `status` | string | 固定为 `"ready"`，表示已持久化并等待下游拉取 |
| `customer_ids` | string[] | 回显本次请求解析到的合法格式客户 ID 列表（未传时省略该字段） |

#### 错误响应：`4xx` / `5xx`

```json
{
  "error": "disk watermark exceeded on agent-a"
}
```

---

## 4. 状态码与重试策略

| HTTP 状态码 | 典型 `error` 信息 | 原因 | 推荐客户端处理策略 |
| :--- | :--- | :--- | :--- |
| **`200 OK`** | — | 文件已校验、落盘并进入分发队列 | 视为上传成功；如需清理源文件，**必须在收到 200 后执行** |
| **`400 Bad Request`** | `invalid project id...` / `path traversal not allowed` / `empty filename` | 项目 ID 或路径非法 | **不要重试**，修正参数并告警 |
| **`400 Bad Request`** | `sha256 mismatch: expected ... got ...` | 传输内容与 `X-Expected-SHA256` 不一致 | 校验本地文件是否仍在被写入；可最多重试 1~2 次 |
| **`401 Unauthorized`** | `invalid local token` | 节点启用了 `require_local_token: true` 且 Token 不匹配 | 检查 `X-Local-Token` 配置，不要盲目重试 |
| **`403 Forbidden`** | `local endpoint only accepts localhost...` / `proxied requests...` / `project not allowed on this node` | 非本机调用、经由代理转发、或项目不在节点白名单 | 检查是否直连 `127.0.0.1`、是否误走系统代理（`http_proxy`）、以及节点项目白名单 |
| **`503 Service Unavailable`** | `dispatch node awaiting data disk selection in console` | 分发节点尚未在控制台勾选缓存数据盘 | 退避重试（每 `10 ~ 30s`），并通知运维在控制台选盘 |
| **`507 Insufficient Storage`** | `disk watermark exceeded on agent-a` / `disk watermark exceeded after upload` | 缓存盘触及强制水位上限（默认 85%），保护磁盘不被写爆 | **正常反压信号！** 暂停写入并指数退避（如 `5s → 10s → 30s`），或轮询 `GET /local/v1/status?summary=1` 直到 `disk_alarm == false` 后继续 |
| **`500 Internal Server Error`** | `upload write failed...` / `disk check failed...` / `commit file...` | 磁盘 I/O 异常、写入中断或本地元数据写入失败 | 有限次数退避重试（如 3 次，间隔 `2s / 5s / 10s`），仍失败则告警 |

> **代理环境变量避坑**：如果服务器配置了全局 `http_proxy` / `ALL_PROXY`，某些客户端可能会把 `http://127.0.0.1:...` 错误转发到代理并触发 `403`！建议：
> - `curl` 加上 `--noproxy '*'`
> - Python `requests` 设置 `session.trust_env = False` 或 `proxies={"http": None, "https": None}`
> - Go `http.Transport` 设置 `Proxy: nil`

---

## 5. 多语言接入示例

### 5.1 `curl`（命令行 / Shell 脚本）

> **大文件务必使用 `-T`（流式上传）**，不要用 `--data-binary @file`（部分版本 `curl` 会把大文件整个读入内存）。

```bash
LOCAL_PORT=18081   # 请替换为本机实际 local_listen 端口
PROJECT="proj-customer-a"
CUSTOMER="cust-acme"
REL_PATH="2026/11/video_001.mp4"
LOCAL_FILE="/data/raw/video_001.mp4"

# 1. 基础 PUT（流式上传 + 首次建项自动归属客户）
curl -fS --noproxy '*' \
  -X PUT \
  -H "X-Customer: ${CUSTOMER}" \
  -T "${LOCAL_FILE}" \
  "http://127.0.0.1:${LOCAL_PORT}/local/v1/files/${PROJECT}/${REL_PATH}"

# 2. 带端到端 SHA-256 强校验 + 指定中文项目显示名（推荐生产使用）
SHA=$(sha256sum "${LOCAL_FILE}" | awk '{print $1}')
ENC_NAME=$(python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))' "客户A音视频项目")
curl -fS --noproxy '*' \
  -X PUT \
  -H "X-Customer: ${CUSTOMER}" \
  -H "X-Expected-SHA256: ${SHA}" \
  -T "${LOCAL_FILE}" \
  "http://127.0.0.1:${LOCAL_PORT}/local/v1/files/${PROJECT}/${REL_PATH}?project_name=${ENC_NAME}"
```

### 5.2 Python（流式上传 + SHA-256 校验 + 507 反压重试）

```python
import hashlib
import os
import time
import urllib.parse
import requests

LOCAL_BASE = "http://127.0.0.1:18081"  # 请替换为本机实际 local_listen 地址

# 复用连接池，并禁用系统代理环境变量，防止 localhost 请求误走 http_proxy
session = requests.Session()
session.trust_env = False


def sha256_file(path: str, chunk_size: int = 4 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def put_file(
    local_path: str,
    project_id: str,
    rel_filename: str,
    customers: list[str] | None = None,
    project_name: str | None = None,
    verify_sha256: bool = True,
    max_retries: int = 8,
) -> dict:
    encoded_rel = urllib.parse.quote(rel_filename.lstrip("/"), safe="/")
    url = f"{LOCAL_BASE}/local/v1/files/{urllib.parse.quote(project_id, safe='')}/{encoded_rel}"

    params = {}
    if project_name:
        # 放 Query 参数可安全传递中文，避免 HTTP Header Latin-1 编码限制
        params["project_name"] = project_name

    headers = {
        "Content-Length": str(os.path.getsize(local_path)),
    }
    if customers:
        headers["X-Customer"] = ",".join(customers)
    if verify_sha256:
        headers["X-Expected-SHA256"] = sha256_file(local_path)

    backoff = 2.0
    for attempt in range(1, max_retries + 1):
        try:
            with open(local_path, "rb") as f:
                # connect 超时 10s；read 超时设为 None（或足够大）以支持数十 GB 大文件
                resp = session.put(url, params=params, headers=headers, data=f, timeout=(10, None))
        except requests.RequestException as exc:
            if attempt == max_retries:
                raise
            print(f"[retry {attempt}] network error: {exc}, sleep {backoff:.0f}s")
            time.sleep(backoff)
            backoff = min(backoff * 2, 30.0)
            continue

        if resp.status_code == 200:
            return resp.json()

        if resp.status_code in (503, 507):
            # 507 = 缓存盘触发水位保护；503 = 节点待选盘；均为可恢复反压信号
            wait_s = min(5.0 * attempt, 30.0)
            print(f"[backpressure {resp.status_code}] {resp.text.strip()}, sleep {wait_s:.0f}s")
            time.sleep(wait_s)
            continue

        if resp.status_code >= 500 and attempt < max_retries:
            print(f"[retry {attempt}] server {resp.status_code}: {resp.text.strip()}, sleep {backoff:.0f}s")
            time.sleep(backoff)
            backoff = min(backoff * 2, 30.0)
            continue

        # 400 / 401 / 403 等客户端错误直接抛出，不盲目重试
        raise RuntimeError(f"PUT failed ({resp.status_code}): {resp.text.strip()}")

    raise RuntimeError(f"PUT failed after {max_retries} attempts: {local_path}")


if __name__ == "__main__":
    res = put_file(
        local_path="/data/raw/video_001.mp4",
        project_id="proj-customer-a",
        rel_filename="2026/11/video_001.mp4",
        customers=["cust-acme"],
        project_name="客户A音视频项目",
    )
    print("Uploaded:", res)
```

### 5.3 Go（标准库零依赖流式上传）

```go
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type UploadResp struct {
	FileID      string   `json:"file_id"`
	ProjectID   string   `json:"project_id"`
	Filename    string   `json:"filename"`
	Size        int64    `json:"size"`
	SHA256      string   `json:"sha256"`
	Status      string   `json:"status"`
	CustomerIDs []string `json:"customer_ids,omitempty"`
}

func escapeRelPath(rel string) string {
	parts := strings.Split(strings.TrimLeft(rel, "/"), "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}

func PutFile(ctx context.Context, localBase, localPath, projectID, relPath string, customers []string, projectName string) (*UploadResp, error) {
	f, err := os.Open(localPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	expectedSHA := hex.EncodeToString(h.Sum(nil))
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	u := fmt.Sprintf("%s/local/v1/files/%s/%s", strings.TrimRight(localBase, "/"), url.PathEscape(projectID), escapeRelPath(relPath))
	if projectName != "" {
		u += "?project_name=" + url.QueryEscape(projectName)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u, f)
	if err != nil {
		return nil, err
	}
	req.ContentLength = st.Size()
	req.Header.Set("X-Expected-SHA256", expectedSHA)
	if len(customers) > 0 {
		req.Header.Set("X-Customer", strings.Join(customers, ","))
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:               nil, // 禁止系统代理拦截 127.0.0.1
			MaxIdleConnsPerHost: 16,
			IdleConnTimeout:     60 * time.Second,
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out UploadResp
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
```

---

## 6. 其他可选本地接口（按需使用）

除主推的 `PUT /local/v1/files/{project}/{filename...}` 外，分发节点还提供以下本机接口（均适用相同的回环安全限制与 `X-Customer` / `X-Project-Name` 首次建项归属规则）：

### 6.1 `POST / PUT /local/v1/upload`（Header 元数据 / Multipart 表单上传）

适合传统表单上传或不便将路径拼进 URL 的场景：

- **Multipart 模式**（`Content-Type: multipart/form-data`）：
  - 表单字段：`project`（或 `project_id`）、`filename`（可选，默认取上传文件名）、`sha256`（可选）、`customer`（可选，支持逗号分隔）、`project_name`（可选）、`file`（单文件）。
  ```bash
  curl -fS --noproxy '*' -X POST \
    -F "project=proj-customer-a" \
    -F "customer=cust-acme" \
    -F "project_name=客户A音视频项目" \
    -F "filename=2026/11/video_001.mp4" \
    -F "file=@/data/raw/video_001.mp4" \
    "http://127.0.0.1:18081/local/v1/upload"
  ```
- **Raw Body 模式**（非 `multipart/form-data`）：
  - 通过请求头 `X-Project`、`X-Filename`、`X-Customer`、`X-Project-Name`、`X-Expected-SHA256` 传参，请求体为原始字节流。

### 6.2 `POST /local/v1/register` 与 `/local/v1/register-batch`（同机零拷贝登记）

当源文件已经落盘在分发节点同一台机器、且与缓存目录位于**同一文件系统**时，可直接登记入队，省去一次完整数据拷贝：

```bash
# 单文件零拷贝登记
curl -fS --noproxy '*' -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "project_id": "proj-customer-a",
    "project_name": "客户A音视频项目",
    "customer": "cust-acme",
    "local_path": "/data/staging/video_001.mp4",
    "filename": "2026/11/video_001.mp4",
    "mode": "move"
  }' \
  "http://127.0.0.1:18081/local/v1/register"
```

- `mode`：
  - `"move"`（默认）：同文件系统内 `O(1)` 原子 `rename` 移入队列；跨文件系统时自动降级为校验复制后删除源文件。
  - `"hardlink"`：同文件系统内创建硬链接（不删除源路径；跨盘不支持硬链接会报错）。
- `customers`：除逗号分隔字符串 `customer` 外，也可传数组 `"customers": ["cust-a", "cust-b"]`。
- 不允许软链接（`local_path` 必须是普通文件）。
- 批量接口 `POST /local/v1/register-batch` 接收 `{"items": [...]}`，单次支持 **1 ~ 256** 条，逐条返回结果（部分失败不影响同批成功条目）。

### 6.3 `GET /local/v1/status`（查询本机积压与磁盘水位）

可用于上游主动限流、监控告警或判断 `507` 水位是否已解除：

```bash
# 轻量汇总模式（推荐高频轮询，不拉取全量文件列表）
curl -s --noproxy '*' "http://127.0.0.1:18081/local/v1/status?summary=1"

# 按项目过滤并查看前 50 个在途/待拉文件
curl -s --noproxy '*' "http://127.0.0.1:18081/local/v1/status?project=proj-customer-a&limit=50"
```

返回示例（`summary=1`）：

```json
{
  "a_node_id": "dispatch-01",
  "a_name": "主分发节点",
  "public_addr": "https://203.0.113.10:8443",
  "files": [],
  "total_files": 124,
  "ready_count": 108,
  "claimed_count": 16,
  "ready_bytes": 5368709120,
  "claimed_bytes": 1073741824,
  "disk_total_bytes": 2000398934016,
  "disk_free_bytes": 1200239360409,
  "disk_used_pct": 40.0,
  "disk_alarm": false
}
```

---

## 7. 生产最佳实践

1. **务必携带 `Content-Length`**：让分发节点能在落盘前精准检查可用水位，并将 `≥ 64 MiB` 大文件优先写入剩余空间最大的缓存盘，小文件在多块缓存盘间轮询分摊 IOPS。
2. **先写完再上传，切勿上传正在追加写入的文件**：上游下载/转码任务应先写入 `.part` 临时文件，完成关闭后再发起 `PUT`，避免传出半截文件或触发 `sha256 mismatch`。
3. **优雅处理 `507` 反压**：当源端生产速率高于公网出口速率时，缓存盘触及水位并返回 `507` 是正常保护机制。建议将 `507` 纳入标准等待重试队列，或根据 `GET /local/v1/status?summary=1` 中的 `disk_alarm` / `ready_bytes` 动态调节并发。
4. **配套文件保持同目录同词干命名（自动亲和落盘）**：
   - 系统默认开启同源亲和，会自动识别同一目录、同一主干名的音视频与伴随文件（如 `abc123.m4a`、`abc123.opus`、`abc123.info.json`、`abc123.meta.json`、`abc123.live_chat.json`、`abc123.zh.vtt`、`abc123.en.srt`），确保成对文件在多接收节点和多块数据盘场景下始终落到**同一台接收节点、同一块物理磁盘**。
5. **合理控制并发与连接复用**：
   - 保持 HTTP Keep-Alive 连接复用，单机并发建议 `4 ~ 16` 个协程/线程（视本机缓存盘 NVMe/HDD 性能调整）。
   - 对 GB 级大文件，不要设置过短的请求总超时（`read timeout` 建议设为 `None` 或 `≥ 3600s`）。
6. **源文件安全清理时机**：
   - 仅当 `PUT` 明确返回 `HTTP 200` 且返回体中的 `status == "ready"`（可选再核对返回的 `sha256`）后，业务方才可删除本地源文件。
