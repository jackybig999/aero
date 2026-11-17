# C5 订阅文档（edge、sub → client）

状态：draft（2026-11-17 起草）。机器可读定义：`api/subscription.schema.json`；示例：`api/testdata/subscription-*.json`。

## 1. 获取
- 客户端只通过 `https://` 获取订阅，并按系统根证书严格校验服务端证书（节点为真实域名 + Let's Encrypt）。
  完整性与来源由 TLS 保证；客户端不得为获取订阅跳过证书校验。
- 订阅 URL 不得指向私网、回环、链路本地地址（防 SSRF）。
- 响应体为 JSON（UTF-8）；为兼容旧客户端，生产方也可返回整个 JSON 的标准 Base64 编码。

## 2. 文档（version = `aero/3.0`）
字段名以下表为准（顶层 camelCase、节点 snake_case 是历史线上格式，保持不变以免影响已部署客户端）。

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `version` | string | 是 | 固定 `aero/3.0` |
| `userId` | string | 否 | 订阅所属用户（管理员订阅为 `admin`） |
| `expireAt` | int | 否 | 到期，Unix 秒；0 或缺省为不限期 |
| `trafficLimitBytes` | int | 否 | 流量上限；0 或缺省为不限 |
| `trafficUsedBytes` | int | 否 | 已用流量（展示用） |
| `createdAt` | int | 否 | 文档生成时间，Unix 秒 |
| `servers` | array | 是 | 至少 1 个节点（见 §3） |
| `switchStatus` | string | 否 | `on` / `off`；`off` 表示订阅被停用，客户端视为失效 |
| `optimization` | object | 否 | 场景节点提示（`aiNodes`、`gameNodes` 等），客户端可忽略 |
| `signature` | string | 否 | **已废弃**：生产方不再输出；客户端忽略（见 §5） |

## 3. 节点（servers[]）
| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `name` | string | 是 | 显示名 |
| `host` | string | 是 | 节点域名（或 IP），客户端据此拨号 |
| `address` | string | 否 | `host:port`；缺省端口为 443 |
| `ip` | string | 否 | 节点 IP（域名解析失败时的备选） |
| `token` | string | 是 | 用户 token（C3：`aero1.` 签名 token 或过渡期的不透明 token） |
| `sni` | string | 是 | TLS SNI 与证书校验名，通常等于节点域名 |
| `protocol` | string | 是 | `connect-ip`（HTTP/3 MASQUE；不降级到 TCP） |
| `alt_ports` | int[] | 否 | 主端口不可用时的候选端口（ADR-0005） |
| `pin_spki` | string[] | 否 | 证书公钥固定（base64 SHA-256）；空表示只做常规校验 |
| `line_type`、`isp_affinity` | string | 否 | 线路类型与运营商亲和，用于排序 |
| `ech` | string | 否 | ECH 配置（base64）；`ech_config` 为同义旧名 |
| `country`、`purityScore`、`aiBlocked`、`warp_active`、`tags` | | 否 | 展示与排序用元数据 |

## 4. 兼容（只读）
客户端在过渡期接受下列旧名，生产方不得再输出：
`serverName`（= `sni`）、`echConfig`/`ech_config`（= `ech`）、`ispAffinity`、`lineType`、`altPorts`、`purity_score`、`ai_blocked`、
`warpActive`/`warp`/`is_warp_egress`/`isWarpEgress`、`countryCode`/`country_code`、`tag`、顶层 `traffic_limit_bytes`、`traffic_used_bytes`、`expire_at`。
过渡期结束（与 C3 相同，2026-12-10）后删除。

## 5. 为什么去掉 `signature`
旧格式用第一个节点的 token 作 HMAC 密钥签名整个节点列表：
- 不防伪：持有 token（即订阅本身）的任何人都能重新签名；
- 极易误判：签名覆盖 Go 序列化后的节点结构，edge、sub、client 三处必须维护完全相同的字段集合与顺序，任何一处增减字段，
  客户端即报 `ERR_SUB_TAMPERED` 并拒绝订阅（用户断连）。
完整性由 HTTPS 严格证书校验保证。若将来需要离线或经第三方分发订阅，改为由签发方密钥（Ed25519，同 C3 的 `kid` 机制）签名，
届时新增字段而不复用 `signature`。

## 6. 待清理（中台，之后处理）
sub 目前还输出 `slug`、`sub_url`、`subUrl`、顶层 `token`、`subTicketSeed`、`expire_at`、`protocolPriority`、`role`、`unrestricted`、
`riskWarning`、节点的 `serverName`、`ech_config`；客户端不使用它们。sub 收敛到本契约后再启用 sub 侧的一致性测试。

## 7. 一致性
- edge 的测试校验其输出符合 `subscription.schema.json`（只含已定义字段、必填齐全）；sub 见 §6。
- client 的测试解析 `api/testdata/subscription-*.json` 并核对结果。
