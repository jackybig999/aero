# AERO Edge Server 契约 v1（冻结）

> 版本：`aero-edge 1.0.0` · `api_level=1` · 日期 2026-07-14  
> **原则：已发布字段/路径只增不改；破坏性变更升 major（2.0）。**

本文件是服务端运维与客户端/中台对接的**唯一真源摘要**。实现以 `aero-edge` 为准。

---

## 1. 协议主路径（L0，已实现）

| 项 | 契约 |
|----|------|
| 传输 | TLS 1.3 + HTTP/2，ALPN `h2` |
| 隧道 | `CONNECT` + `Proxy-Authorization: Bearer <token>` |
| 成功 | `:status 200` 后 TypedMessage 中继 |
| 握手帧 | `ConnectRequest` / `ConnectResponse`（Protobuf） |
| 防重放 | token + timestamp(±30s) + nonce |
| 数据帧 | TcpFrame / Heartbeat / HeartbeatAck / UdpFrame … |
| 默认推荐 | `RecommendedProtocol=tcp_h2`（QUIC 数据面未开放） |

### 错误码（CONNECT 层）

| HTTP | 含义 |
|------|------|
| 407 | 鉴权失败 |
| 429 | IP 新建限速 |
| 503 | 容量满 / draining |
| 502 | 上游目标拨号失败 |
| 400 | 缺少目标 |

---

## 2. 订阅（Edge 真源）

| 项 | 契约 |
|----|------|
| 路径 | `GET /sub/{secret}` |
| 文档 | JSON：`version`, `servers[]`, `signature`, 可选 `pin_spki` |
| 签名 | HMAC-SHA256(token) over 固定字段，与客户端 `sub.Verify` 一致 |
| 限速 | 与 CONNECT 同系 IP 限速（前缀隔离） |

中台只分发同 schema；不得私自改签名算法。

---

## 3. 多用户 Token

| 项 | 契约 |
|----|------|
| 存储 | `{data-dir}/tokens.json`（schema version=1） |
| 启动 | `-token` 写入 `default`；已有文件则合并 |
| 校验 | 任一有效 token 可 CONNECT |
| 热更 | `POST /admin/reload` 或 `SIGHUP` 重载文件 |

字段：`token`, `label`, `created_at`, `expires_at`。

---

## 4. Admin API（api_level=1）

鉴权：**loopback 免密**，或 `X-Aero-Admin-Key` / `?key=`（需 `-admin-key`）。

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/admin/version` | version / protocol / api_level |
| GET | `/admin/status` | 容量、metrics、超时、uptime |
| GET | `/admin/tokens` | 列表 |
| POST | `/admin/tokens` | body: `{token?,label?,ttl_hours?}` |
| DELETE | `/admin/tokens?token=` | 吊销 |
| POST | `/admin/reload` | 重载 tokens.json |

后续版本只允许**新增**路径/字段。

---

## 5. 容量与公平（小 VPS）

| 参数 | 含义 | 默认（无 profile） |
|------|------|-------------------|
| max-conn | 全局隧道 | 4096 |
| max-conn-user | 每 token | 128 |
| rate-ip | CONNECT/s/IP | 20 |
| bw-user | 每 token B/s，0=不限 | 0 |
| idle-sec | 无流量断开 | 900 |
| max-life-sec | 单隧道最长，0=不限 | 86400 |
| max-dial | 同时拨号 | 256 |

### Profile 冻结名

| 名 | 场景 |
|----|------|
| `tiny` | 1c1g |
| `small` | 2c2g |
| `medium` | 2–4c4g+ |

---

## 6. 运维端点（仅 loopback）

`/health` · `/metrics` · `/ech-config`

---

## 7. Cover

未鉴权 HTTP → 伪装站；**不得**影响 CONNECT / `/sub` / Admin 优先级。

---

## 8. 明确不在 v1 默认路径

- QUIC 数据面全量转发  
- Reality / 多协议 outbounds  
- 默认开启 padding 混淆  
- 完整机场计费面板（中台职责）  

---

## 9. 升级规则（后期只做微小调整）

1. **补丁**（1.0.x）：修 bug、性能，契约不变  
2. **次版本**（1.x.0）：只增 Admin/metrics/配置字段，旧客户端仍可用  
3. **主版本**（2.0.0）：才允许破坏 CONNECT/帧/签名语义  

客户端与中台应对 **api_level** 做兼容判断。

---

## 10. 推荐生产启动

```bash
aero-edge -token BOOTSTRAP -listen :443 -domain edge.example.com \
  -profile small -admin-key "$(openssl rand -hex 16)" -data-dir /var/lib/aero
```
