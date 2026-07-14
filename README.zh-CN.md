# AERO 协议服务端（Edge）v1.0.0 — 冻结版

> 本目录为**服务端代码冻结副本**，便于独立维护与部署。  
> 路径：`grok/aero/server` · 版本 **1.0.0** · API 级别 **1**

English: [README.en.md](./README.en.md)

---

## 1. 这是什么

**AERO Edge** 是 AERO 独立隧道协议的**服务端节点**：

- 主路径：TLS 1.3 + **HTTP/2 CONNECT** + TypedMessage 中继  
- **不兼容** VMess / VLESS / Trojan / Shadowsocks 等协议超市  
- 面向 **多用户 / 小 VPS**：连接数上限、每用户限速、空闲超时、Token 持久化  
- 运维：订阅 `/sub/{secret}`、Cover 伪装站、Admin API、metrics  

契约冻结文档：[`docs/edge-server-v1.md`](./docs/edge-server-v1.md)

---

## 2. 目录结构

```
server/
├── README.md / README.zh-CN.md / README.en.md
├── FROZEN.md                 # 冻结元信息
├── VERSION                   # 1.0.0
├── go.work                   # 本地模块聚合
├── aero-edge/                # 服务端源码（主程序）
│   ├── cmd/aero-edge/        # 入口
│   └── internal/             # auth, subscribe, cover, connlimit...
├── proto/                    # 共享 Protobuf
├── deploy/                   # install / systemd / docker
└── docs/                     # 契约与说明
```

---

## 3. 编译

要求：Go **1.22+**（推荐 1.25）

```bash
cd grok/aero/server/aero-edge
go build -o aero-edge ./cmd/aero-edge

# 版本
./aero-edge -version
# aero-edge 1.0.0 protocol=aero/2.0 api_level=1
```

Windows:

```powershell
cd D:\Jacky\grok\aero\server\aero-edge
go build -o aero-edge.exe .\cmd\aero-edge
.\aero-edge.exe -version
```

---

## 4. 用法（CLI）

### 4.1 最简（开发 / 自签）

```bash
./aero-edge -token my-secret -profile small
# 默认监听 :8443，自签证书，数据目录 ./aero_data 或 AERO_DATA_DIR
```

### 4.2 生产推荐

```bash
./aero-edge \
  -token BOOTSTRAP_TOKEN \
  -listen :443 \
  -domain edge.example.com \
  -profile small \
  -admin-key "$(openssl rand -hex 16)" \
  -data-dir /var/lib/aero
```

已有证书：

```bash
./aero-edge -token SECRET -listen :443 -domain edge.example.com \
  -cert /path/fullchain.pem -key /path/privkey.pem -profile small
```

Let's Encrypt：

```bash
./aero-edge -token SECRET -listen :443 -domain edge.example.com \
  -autocert edge.example.com -profile small
```

### 4.3 档位 `-profile`

| 档位 | 适用 | 全局连接 | 每用户连接 | 每用户带宽 | 空闲超时 | 最大寿命 |
|------|------|----------|------------|------------|----------|----------|
| `tiny` | 1 核 1G | 256 | 16 | 2 MiB/s | 10 分钟 | 12 小时 |
| `small` | 2 核 2G | 1024 | 32 | 5 MiB/s | 15 分钟 | 24 小时 |
| `medium` | 4G+ | 4096 | 64 | 不限 | 20 分钟 | 不限 |

可用 flag 覆盖：`-max-conn` `-max-conn-user` `-bw-user` `-idle-sec` `-max-life-sec` `-max-dial` `-rate-ip` `-q`

### 4.4 常用参数

| 参数 | 说明 |
|------|------|
| `-token` | 启动引导 Token（写入 tokens.json 的 default） |
| `-listen` | 监听端口，如 `:443` |
| `-domain` | 公网域名 / SNI（订阅里也会用） |
| `-data-dir` | 数据目录（token、订阅 meta） |
| `-admin-key` | 远程 Admin 密钥（本机 127.0.0.1 免密钥） |
| `-profile` | `tiny` / `small` / `medium` |
| `-q` | 减少每连接日志 |
| `-version` | 打印版本 |

---

## 5. 客户端如何连

启动成功后日志会打印，例如：

```text
import: aero-ech -sub https://edge.example.com/sub/<secret>
# 自签：
aero-ech -sub /var/lib/aero/client-sub.json -insecure
```

订阅 JSON 含 `signature` 与可选 `pin_spki`，客户端需校验。

---

## 6. 多用户 Token（Admin）

Token 持久化：`{data-dir}/tokens.json`  
热重载：`POST /admin/reload` 或 Linux `SIGHUP`

**本机示例**（默认端口 8443 时）：

```bash
# 版本 / 状态
curl -s http://127.0.0.1:8443/admin/version
curl -s http://127.0.0.1:8443/admin/status

# 列出 / 新增 / 吊销
curl -s http://127.0.0.1:8443/admin/tokens
curl -s -X POST http://127.0.0.1:8443/admin/tokens -d '{"label":"user2","ttl_hours":8760}'
curl -s -X DELETE "http://127.0.0.1:8443/admin/tokens?token=THE_TOKEN"

# 从磁盘重载
curl -s -X POST http://127.0.0.1:8443/admin/reload
```

远程需带密钥：

```bash
curl -s -H "X-Aero-Admin-Key: YOUR_KEY" https://edge.example.com/admin/status
```

> 说明：公网 HTTPS 上 Admin 与 Cover 同端口；**务必设置 `-admin-key`**，且仅受信网络调用。

---

## 7. 路由优先级

1. ACME `/.well-known/...`  
2. **CONNECT** → 隧道  
3. **`/admin/*`**（需鉴权）  
4. **`/sub/{secret}`** 订阅  
5. 本机 `/health` `/metrics`  
6. Cover 伪装站  

---

## 8. 运维

| 端点 | 访问 | 说明 |
|------|------|------|
| `/health` | 仅本机 | 健康检查 |
| `/metrics` | 仅本机 | Prometheus 文本 |
| `/sub/{secret}` | 公网 | 订阅 |
| `/admin/*` | 本机或 admin-key | 运维 API |

优雅退出：`SIGINT` / `SIGTERM` → 先 drain 拒绝新连接 → 再关闭。

---

## 9. 部署脚本

见 `deploy/`：

- `install.sh` — Linux 安装示例  
- `aero-edge.service` — systemd  
- `Dockerfile` / `docker-compose.yml`  

安装后请仍用本目录编译出的 **1.0.0** 二进制，或按脚本路径替换。

---

## 10. 升级策略（冻结后）

| 变更 | 版本 |
|------|------|
| 修 bug、性能 | **1.0.x** |
| 只增 Admin/metrics 字段 | **1.x.0** |
| 破坏 CONNECT/帧/签名 | **2.0.0** |

客户端与中台应识别 `api_level`；**v1 字段只增不改**。

---

## 11. 相关文档

| 文档 | 内容 |
|------|------|
| [docs/edge-server-v1.md](./docs/edge-server-v1.md) | 运维契约（冻结） |
| [docs/SERVER-V1-COMPLETE.md](./docs/SERVER-V1-COMPLETE.md) | 完成定义 |
| [docs/SERVER-MULTIUSER.md](./docs/SERVER-MULTIUSER.md) | 多用户说明 |
| [docs/protocol-v1.md](./docs/protocol-v1.md) | 协议规范摘要 |
| [FROZEN.md](./FROZEN.md) | 本快照元数据 |

---

## 12. 许可

与上游 AERO Protocol 一致（Apache License 2.0）。
