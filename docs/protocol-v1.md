# AERO Protocol Specification v1.0

> 目标：未参与代码的工程师，读完本文档后能用自己喜欢的语言独立实现 AERO 客户端或服务端，并与官方实现互通。  
> **服务端运维契约（冻结）：** [contracts/edge-server-v1.md](./contracts/edge-server-v1.md) · 实现版本 `aero-edge 1.0.0`

### 实现状态（与官方 Edge 对齐，2026-07）

| 能力 | 状态 |
|------|------|
| TLS1.3 + H2 CONNECT + Bearer + TypedMessage 中继 | **已实现（主路径）** |
| Token + 时间窗 + nonce 防重放 | **已实现** |
| 订阅 JSON + HMAC + pin_spki | **已实现** |
| Cover 同端口伪装 | **已实现** |
| 多 token / Admin / 容量档位 / 带宽与空闲 | **已实现** |
| ALPN `aero/1`、QUIC 数据面全量、多流 QoS 调度 | **vNext**（默认不启用） |
| ECH | **可选增强**（服务端可生成，部署条件依赖） |

---

## 1. 概述

### 1.1 设计目标

AERO 是面向 AI 时代的自适应传输协议。核心特征：

- **传输层**：HTTP/2 CONNECT 隧道 + TypedMessage + Protobuf
- **QoS 模型**：5 类 Stream（Control/AI/UDP/Browser/General）分级调度
- **安全层**：TLS 1.3 + ECH + Token + Nonce + Timestamp 防重放
- **AI 原生**：首 Token 延迟追踪、断线续传、SSE Keepalive

### 1.2 非目标

AERO 从不兼容且永远不会兼容：

- VMess / VLESS / Trojan / Reality / Shadowsocks
- SOCKS5 over TLS 或其他代理聚合
- 配置文件中的 `outbounds` 概念

### 1.3 术语表

| 术语 | 含义 |
|------|------|
| Edge | AERO 服务端节点 |
| Stream | QUIC/HTTP/2 双向流 |
| TypedMessage | [1B 类型][4B 长度][Protobuf] 帧格式 |
| Context ID | AI Stream 断线续传标识 |
| FTL | First Token Latency（首 Token 延迟） |

---

## 2. 传输层

### 2.1 TLS 握手

- TLS 版本：1.3（必填）
- ALPN：`"h2"`, `"aero/1"`
- SNI：客户端 `public_name`（伪 SNI 或 ECH outer SNI）
- ECH：TLS 1.3 Encrypted Client Hello 扩展（推荐）

### 2.2 QUIC 传输

- QUIC 版本：RFC 9000
- ALPN：`"h3"`, `"aero/1"`
- 默认端口：443/UDP
- 支持 Connection Migration

### 2.3 HTTP/2 CONNECT 语义

```
Client → Edge:
  :method = CONNECT
  :authority = 目标地址（提示，服务端可按需忽略）
  proxy-authorization: Bearer <token>

Edge → Client:
  :status = 200（隧道建立）
  :status = 407（认证失败）
```

隧道建立后，HTTP/2 DATA 帧承载 AERO TypedMessage。

---

## 3. 连接生命周期

### 3.1 握手流程

```
Client                              Edge Server
  |                                      |
  |--- TCP/TLS 握手 + ECH ------------->|
  |                                      |
  |--- HTTP/2 CONNECT + Token --------->|
  |                                      |
  |<-- :status 200 ---------------------|
  |                                      |
  |--- ConnectRequest (Protobuf) ------>|
  |<-- ConnectResponse (Protobuf) ------|
  |                                      |
  |--- Heartbeat (周期) --------------->|
  |<-- HeartbeatAck ---------------------|
  |                                      |
  |=== TypedMessage 数据阶段 ===========>|
```

### 3.2 ConnectRequest

```protobuf
message ConnectRequest {
  string version = 1;           // "aero/2.0"
  string token = 2;             // Bearer token
  bytes nonce = 3;              // 32 字节随机数
  uint64 timestamp = 4;         // Unix 毫秒
  repeated StreamSpec streams = 5;
  string isp_hint = 6;
  repeated uint32 tested_ports = 7;
  bool udp_available = 8;
}
```

### 3.3 ConnectResponse

```protobuf
message ConnectResponse {
  bool accepted = 1;
  string session_id = 2;
  uint32 heartbeat_interval = 3;  // 秒，默认 30
  string message = 4;
  map<string, string> server_params = 5;
  string recommended_protocol = 6;
  uint32 recommended_port = 7;
}
```

### 3.4 心跳与超时

- 心跳间隔：服务端通过 `heartbeat_interval` 通告，默认 30s
- 超时判定：3 × heartbeat_interval 无 ack → 关闭连接
- Heartbeat 帧序列号 `uint32`，单连接单调递增

---

## 4. 消息编码

### 4.1 TypedMessage 格式

```
[1 byte: msg_type][4 bytes: length (big-endian)][length bytes: Protobuf payload]

最大消息长度：16MB
```

### 4.2 消息类型定义

| msg_type | 名称 | Protobuf 消息 |
|----------|------|--------------|
| 0x01 | TcpFrame | `aero.TcpFrame` |
| 0x02 | UdpFrame | `aero.UdpFrame` |
| 0x03 | Heartbeat | `aero.Heartbeat` |
| 0x04 | HeartbeatAck | `aero.HeartbeatAck` |
| 0x05 | AiStreamHeader | `aero.AiStreamHeader` |
| 0x06 | AiStreamFrame | `aero.AiStreamFrame` |
| 0x07 | MetricsReport | `aero.MetricsReport` |
| 0x08 | SchedulerCommand | `aero.SchedulerCommand` |

未知 msg_type → 关闭连接（不允许静默忽略）。

### 4.3 Stream 类型

| 类型 | proto 值 | 优先级 | 用途 |
|------|---------|--------|------|
| CONTROL | 0 | 255（最高） | 心跳、Metrics、调度指令 |
| GENERAL | 1 | 100 | 通用 HTTP/HTTPS |
| UDP | 2 | 200 | DNS、游戏、实时音视频 |
| AI | 3 | 200 | SSE、Token Stream |
| BROWSER | 4 | 150 | 指纹隔离浏览器流量 |

---

## 5. 认证与安全

### 5.1 Token 认证

- Token 格式：任意字符串，推荐 32 字节 hex
- 传输方式：`proxy-authorization: Bearer <token>`（HTTP 头）
- ConnectRequest 中再次携带 token 供 Protobuf 层二次验证

### 5.2 防重放

- `nonce` 最小长度：16 字节，推荐 32 字节
- `timestamp` 容差：±30 秒
- 服务端维护 nonce LRU 缓存（5 分钟窗口），拒绝重复 nonce

### 5.3 CA 证书

- 生产环境必须验证服务端证书
- Self-signed 仅用于测试

---

## 6. AI QoS

### 6.1 首 Token 延迟分级

| 等级 | 延迟范围 | 动作 |
|------|---------|------|
| Excellent | < 200ms | 无操作 |
| Good | 200-500ms | 无操作 |
| Fair | 500-1000ms | 告警 |
| Poor | > 1000ms | 建议切换节点 |

### 6.2 断线续传

```
连接断开前：
  Client → AiStreamHeader { context_id: "abc123", resume: false }
  Edge 保存 context_id → (last_sequence, bytes_transferred) 到存储

重连后：
  Client → AiStreamHeader { context_id: "abc123", resume: true }
  Edge 查存储 → 恢复状态 → 日志输出恢复信息
  Client 从上次断点继续接收
```

### 6.3 SSE Keepalive

Edge 周期发送注释行（`:keepalive\n\n`）维持 NAT/防火墙会话，间隔 15s。

---

## 7. 错误处理

| 场景 | 行为 |
|------|------|
| Token 无效 | HTTP 407 + ConnectResponse.accepted=false |
| Timestamp 超出容差 | ConnectResponse.accepted=false |
| Nonce 重复 | ConnectResponse.accepted=false |
| 未知 msg_type | 关闭 HTTP/2 Stream + 关闭连接 |
| 心跳超时 | 关闭连接 |

---

## 8. 扩展性

### 8.1 新增 msg_type

- 0x00-0x7F：官方注册表保留
- 0x80-0xFF：私有扩展（无需申请）

### 8.2 新增 StreamType

需通过 `aero-protocol/assignments` 仓库提交申请，2 位 maintainer 批准后分配。

---

## 附录 A：Protobuf 完整定义

参见：`proto/aero.proto`

## 附录 B：参考实现

- Go 客户端：`aero-ech`
- Go 服务端：`aero-edge`
- Rust 核心：`aero-core`
- 一致性测试：`tests/conformance/`
