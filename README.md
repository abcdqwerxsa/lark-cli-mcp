# lark-mcp

把[官方飞书 CLI](https://github.com/larksuite/cli)（`@larksuite/cli` / `lark-cli`）封装成 MCP server，面向公网部署。

- **协议**：MCP Streamable HTTP（2025-06-18），无状态（无会话亲和，重启不掉线）
- **鉴权**：OAuth 2.1 授权服务器——授权码 + PKCE(S256) + refresh_token（浏览器客户端，如 Gemini）**和** client_credentials（脚本/pi）双支持，RFC 9728 / RFC 8414 发现文档
- **防护**：Host 头校验（DNS rebinding）、timing-safe 凭据比较、按 IP 失败锁定、Caddy 自动 TLS
- **省 token**：2 个工具、紧凑 schema；成功时只返回 `data`（解包官方 envelope）；`jq` 透传（自动在 `.data` 上下文求值，`.name` 即可，不必写 `.data.name`）；输出按字节上限截断

## 工具

| 工具 | 说明 |
|---|---|
| `lark_api` | 调用任意飞书 Open API：`method` + `path`（`/open-apis` 前缀可省）+ `params`/`data`/`jq`/`page_all`/`page_limit` |
| `lark_auth_status` | 查询服务器端 lark-cli 登录状态（用户身份、token 是否有效） |

## 运行

```bash
npm install
LARK_MCP_CLIENTS="my-client:my-long-secret" npm start   # 默认 127.0.0.1:3333
```

环境变量（完整清单见 `deploy/lark-mcp.env.example`）：

| 变量 | 默认 | 说明 |
|---|---|---|
| `LARK_MCP_CLIENTS` | 必填 | `id:secret` 逗号分隔；轮换任意 secret 会吊销所有已发 token（JWT key 由 secrets 派生） || `LARK_MCP_PUBLIC_URL` | 空 | 公网 HTTPS 地址（Caddy 站点名）；设置后启用 OAuth 发现文档 + Host 校验 + trust proxy |
| `LARK_MCP_TOKEN_TTL` | 3600 | access token 有效期（秒） |
| `LARK_MCP_REFRESH_TTL` | 2592000 | refresh token 有效期（秒），仅授权码流程签发 |
| `LARK_MCP_MAX_OUTPUT` | 65536 | 单次工具输出字节上限，超出截断并提示用 `jq` 收窄 |
| `LARK_MCP_TIMEOUT_MS` | 120000 | lark-cli 子进程超时 |
| `HOST` / `PORT` | 127.0.0.1 / 3333 | 监听地址（公网由 Caddy 反代） |

## 部署（oci-arm2，k3s）

实际部署不用自建镜像：源码（约 17 KB）放在宿主机 `/opt/lark-mcp/app`，Pod 用官方 `node:24-bookworm-slim` 镜像，initContainer 负责 `npm ci` + 从 GitHub release 下载 lark-cli 的 arm64 二进制（sha256 校验）+ 安装 CA 证书。清单：`deploy/k8s.yaml`，apply 即可。

```bash
tar czf src.tgz package.json package-lock.json src
scp src.tgz oci-arm2:/tmp/ && ssh oci-arm2 'sudo tar xzf /tmp/src.tgz -C /opt/lark-mcp/app && sudo chown -R 1000:1000 /opt/lark-mcp/app'
ssh oci-arm2 'sudo kubectl apply -f deploy/k8s.yaml && sudo kubectl rollout restart deploy/lark-mcp'
```

关键点（都是踩过的坑）：
- **`LARKSUITE_CLI_CONFIG_DIR` 和 `LARKSUITE_CLI_DATA_DIR` 都要指向 `/data`**：lark-cli 把 app secret / 用户 token / DPoP 密钥放在"keychain"里，由 `DATA_DIR` 控制，默认在 `~/.local/share`——容器 home 是临时的，不固定就每次重启丢登录。
- 飞书登录要用 `setpriv --reuid=1000` 以 node 用户身份跑（`kubectl exec` 默认 root，写出来的文件主进程读不了）。
- `/healthz` 挂在 Host 校验之前，否则 kubelet 探针（Host 是 Pod IP）永远 403。
- traefik 对"创建时还没有 endpoint"的 ingress 不会自动重试：Pod 就绪后要删掉 ingress 重建。
- 域名走 Cloudflare 代理（Flexible，回源 HTTP/80），所以 ingress 不加 `certresolver: le`（LE HTTP-01 被 CF 挡住签不下来，而且边缘证书由 CF 提供）。

### 重新登录飞书（token 失效时）

```bash
ssh oci-arm2
sudo kubectl exec deploy/lark-mcp -c lark-mcp -- setpriv --reuid=1000 --regid=1000 --clear-groups \
  env HOME=/data LARKSUITE_CLI_CONFIG_DIR=/data LARKSUITE_CLI_DATA_DIR=/data \
  /tools/lark-cli auth login --no-wait --recommend --json      # 打开 verification_url
# 用户确认后，用返回的 device_code 完成：
sudo kubectl exec deploy/lark-mcp -c lark-mcp -- setpriv --reuid=1000 --regid=1000 --clear-groups \
  env HOME=/data LARKSUITE_CLI_CONFIG_DIR=/data LARKSUITE_CLI_DATA_DIR=/data \
  /tools/lark-cli auth login --device-code <code>
```

## 客户端接入

### Gemini / Google Connected Apps（你截图里的对话框）

Gemini 走的是**浏览器授权码 + PKCE** 流程，不是 client_credentials：

| 对话框字段 | 填什么 |
|---|---|
| MCP Server URL | `https://<域名>/mcp` |
| Client ID | `LARK_MCP_CLIENTS` 里的 id（如 `gemini`） |
| Client secret | 对应的 secret |
| Copy redirect URI | **不用填**——服务器已 allowlist `https://oauth-redirect{,-sandbox,-test}.googleusercontent.com/{r,a}/*` |

点 Next 后 Gemini 会弹一个浏览器窗口到 `/oauth/authorize`，我们的同意页会要求输入**该 client 的 secret**（服务器无用户库，这是验证"只有持有凭据的人能完成登录"的最小方案）。输入后 302 跳回 Google 完成。token 1h 过期后 Gemini 用 refresh token 自动续（30 天）。

### 脚本 / pi / curl（client_credentials）

```bash
# 拿 token（Basic 或 form 两种方式均可）
curl -s -u my-client:my-long-secret -d grant_type=client_credentials \
  https://<域名>/oauth/token
# {"access_token":"...","token_type":"Bearer","expires_in":3600}
```

- **pi**：`/mcp install https://<域名>/mcp`，auth profile 配静态头 `Authorization: Bearer <token>`（把 `LARK_MCP_TOKEN_TTL` 调大即可长期用，或到期换新）
- **原生 OAuth 客户端**：授权服务器地址 `https://<域名>`，元数据在 `/.well-known/oauth-authorization-server`（含 `authorization_endpoint`、`token_endpoint`、`code_challenge_methods_supported: ["S256"]`）
- 手动调用：`POST /mcp`，头 `Authorization: Bearer <token>`、`Accept: application/json, text/event-stream`、`Content-Type: application/json`，标准 JSON-RPC

## 测试

```bash
npm test        # 单元自检（JWT、锁死、截断、envelope 解包）
```

## 安全说明

- JWT 签名 key = 所有 client secrets 的哈希：改任一 secret 即吊销全部存量 token（特性，不是缺陷）
- 登录态是**服务器上单一的飞书用户身份**，任何持有效 client 凭据的 MCP 客户端都以该身份调用 API——凭据分发要谨慎
- 同意页用 client secret 代替用户登录：secret 泄露 = 可完成授权（但泄露本身已意味着能直接换 token，所以不额外扩大攻击面）
- 授权码一次性、60 秒有效；refresh token 一次性轮换（重放拒绝）；code/refresh 状态在进程内存，重启后客户端需重新授权
- 失败锁定是进程内存态，重启清零；公网暴露务必走 TLS（Caddy 自动证书）
