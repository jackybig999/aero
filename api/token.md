# C3 用户 token（draft）

状态：`final`（2026-11-10，用户确认）。变更须按 L0 §4.6 进行。flag `auth_signed_token` 默认 `OFF`，实现通过 §4.3 校验后方可 `ON`。依据：ADR-0002。

## 1. 线上格式

```
aero1.<payload>.<signature>
```

- `payload`：UTF-8 JSON 对象的 base64url（RFC 4648 §5，无填充）。字段见 `api/token.schema.json`。
- `signature`：Ed25519（RFC 8032）对 **`aero1.` + payload 的 ASCII 字节** 的签名，base64url 无填充，解码后必须为 64 字节。
- 签名覆盖的是编码后的原始字节，签发方与校验方 **不需要** 对 JSON 做规范化；校验方 **MUST** 先验签，再解析 JSON。
- 整个 token 长度上限 2048 字节；超出直接拒绝。
- 传输：`Authorization: Bearer <token>`。`Aero-Timestamp`、`Aero-Nonce` 废弃，服务端忽略（TLS 已提供防重放；原全局 nonce 表可被单个用户耗尽，审查 P0-8）。

## 2. 签发方与密钥

| `iss` | 私钥持有方 | 公钥位置 | 用途 |
|---|---|---|---|
| `sub` | 只有 sub | edge 配置 `token_issuers`（`kid` → 32 字节公钥 base64） | 商业订阅用户 |
| `edge` | 只有该 edge 节点（首次启动生成，0600 存于数据目录） | 该 edge 自身 | 节点控制台创建的用户；没有 sub 时 edge 独立可用 |

- 一个 `kid` 只对应一把公钥；轮换时先在 edge 配置中加入新 `kid`，sub 改用新私钥签发，旧 token 全部过期后再删除旧 `kid`。
- `iss=edge` 的 token 只在签发它的节点有效。
- 私钥 **MUST NOT** 出现在订阅、日志、管理接口响应中。

## 3. 校验规则（edge）

按顺序执行，任一步失败即拒绝，返回对应错误码（`api/errors.yaml`）：

| 步骤 | 条件 | 错误码 |
|---|---|---|
| 1 | 前缀为 `aero1.`，三段，长度 ≤ 2048，base64url 合法 | `EDGE_AUTH_INVALID_TOKEN` |
| 2 | `kid` 已配置且属于 `iss`；Ed25519 验签通过 | `EDGE_AUTH_INVALID_TOKEN` |
| 3 | 载荷符合 schema；`exp - iat` ≤ 604800 | `EDGE_AUTH_INVALID_TOKEN` |
| 4 | `iat` ≤ 当前时间 + 300 秒；当前时间 < `exp` + 0（不放宽过期） | `EDGE_AUTH_TOKEN_EXPIRED` |
| 5 | `jti` 不在吊销列表（C4） | `EDGE_AUTH_TOKEN_REVOKED` |
| 6 | 请求的场景在 `classes` 内 | `EDGE_CLASS_NOT_ALLOWED` |
| 7 | 该 `uid` 在本节点的 QUIC 连接数 < `max_devices`（服务端原子计数，L0 §7.5） | `EDGE_DEVICE_LIMIT` |

- 校验通过的 token 绑定到该 QUIC 连接；连接存续期间 token 过期或被吊销时，edge 在 10 秒内断开该连接（已由 M1-4a 的执行器实现）。
- 时钟容差只用于 `iat`（容忍签发方时钟略快），不用于 `exp`。
- 日志只记录 `jti` 的前 8 个字符与 `uid`，不记录完整 token。

## 4. 推荐取值（估算，M3 实测后替换）

| 项 | 值 |
|---|---|
| token 有效期 | 24 小时；client 在剩余 25% 时刷新 |
| 最长有效期 | 7 天（硬上限） |
| 吊销列表拉取间隔 | 60 秒 |

## 5. 迁移

1. 本契约定稿后实现校验与 `iss=edge` 签发；flag `auth_signed_token` 默认 `OFF`。
2. `OFF` 时继续接受旧的不透明 token（`aero_<hex>`），同时 **立即** 停止要求与记录 `Aero-Timestamp`/`Aero-Nonce`（不改变客户端行为，属于兼容变更）。
3. `ON` 后同时接受新旧两种 token 30 天（§8），过渡期结束后删除旧 token 路径与 `tokens.json`。

## 6. 档位与执行参数（用户决定，2026-11-10）

- 档位（`tier`）由中台定义和命名，edge **不解析**、不保存档位表；`tier` 仅用于展示与日志。
- 中台签发 token 时把执行所需的全部参数写入载荷：`classes`、`max_devices`、`quota_bytes`、`bw_bps`。edge 只执行这些数字。
- 中台修改档位参数后：新参数随用户下一次 token 刷新（≤ 24 小时）生效；需立即生效时，中台吊销旧 token（C4）。
- 新增限制项 = 在载荷中新增字段（兼容变更，L0 §4.6）；edge 不认识的字段忽略。

## 7. 多节点下的限制执行

| 限制 | 单节点（立即，硬限制） | 跨节点（延迟一个拉取周期，软限制） |
|---|---|---|
| 设备数 `max_devices` | 本节点同一 `uid` 并发 QUIC 连接原子计数 | sub 汇总各节点 `/v1/status` 的每用户在线会话数，超限则吊销最早签发的 `jti` |
| 流量 `quota_bytes` | 本节点累计计量达到即断开 | sub 汇总 `/v1/usage`，跨节点合计超限即吊销 |
| 带宽 `bw_bps` | 本节点按 `uid` 令牌桶 | 不做跨节点合计 |

节点之间不互相通信（ADR-0001）；跨节点一致性只经 sub 的只读拉取与吊销列表实现。

## 8. 过渡期

`auth_signed_token` 打开后，新旧 token 并存 **30 天**，之后删除旧 token 路径与 `tokens.json`。
