# C1 数据面与 C2 DoH（edge ↔ client）

状态：draft（2026-11-17，按当前实现成文）。验证：`tests/e2e`（真实 cmd/edge + cmd/client，CI 必跑）。

## 1. 传输
- 只用 HTTP/3（QUIC，ALPN `h3`，启用 HTTP Datagrams 与扩展 CONNECT）。**不降级到 TCP**：edge 的 TCP 端口只提供伪装站与控制台，对 CONNECT 返回 405。
- 节点地址与端口来自订阅（C5 §3）：先连主端口，失败时按 `alt_ports` 依次尝试；证书按 `sni` 严格校验（系统根证书，可选 `pin_spki`）。
- 一条 QUIC 连接承载一个会话；连接上的各请求共用同一个 token（C3）。

## 2. 认证（所有请求）
- `Authorization: Bearer <token>`（C3：`aero1.` 签名 token，或过渡期的不透明 token）。
- 同一 QUIC 连接上出现不同的 token：401（`details="token differs from the one bound to this connection"`）。
- 过渡期（至 2026-12-10）客户端仍在连接的第一个请求上发送 `Aero-Timestamp`、`Aero-Nonce`；edge 忽略它们。

## 3. 请求
| 用途 | 方法与路径 | 说明 |
|---|---|---|
| TCP | 标准 `CONNECT host:port`（无 `:protocol`） | RFC 9114 §4.4；半关闭：客户端关闭写端后 edge 只关闭目标写端，继续回传 |
| UDP | 扩展 CONNECT `connect-udp`，`/.well-known/masque/udp/{target_host}/{target_port}/` | RFC 9298；单个超过数据报上限的报文丢弃，会话继续 |
| 全局隧道 | 扩展 CONNECT `connect-ip`，`/.well-known/masque/ip/*/*/` | RFC 9484，见 §4 |
| DNS | `POST /dns-query`，`Content-Type: application/dns-message` | C2，见 §6 |

## 4. CONNECT-IP（全局隧道）
- 地址分配：IPv4 `/32`，取自 `10.88.0.0/16`（`10.88.0.1` 为 edge 网关）；签名 token 按 uid 保持同一地址（token 轮换后隧道地址不变，C3）。
  节点有公网 IPv6 前缀时另分配 IPv6；否则只有 IPv4。
- 路由通告：`0.0.0.0/0` 与 `::/0`。
- MTU：edge TUN 1360；客户端 TUN 1280（IPv6 最小值），IPv4 路由 MTU 1224。超过 1360 的内层 IPv6 报文由 edge 回 ICMPv6 Packet Too Big。
- 源地址校验：客户端只能以分配给自己的地址发包，伪造源地址的报文丢弃。
- 节点配置 `connect_ip=false` 时返回 503 `connect_ip_disabled`（该节点只提供 TCP/UDP 与 DoH）。

## 5. 目的地址策略（TCP、UDP、CONNECT-IP 三条路径相同）
拒绝（TCP/UDP 返回 403 `destination_ip_prohibited`，CONNECT-IP 静默丢包）：
- IPv4：`0.0.0.0/8`、`10.0.0.0/8`、`100.64.0.0/10`、`127.0.0.0/8`、`169.254.0.0/16`、`172.16.0.0/12`、`192.0.0.0/24`、`192.0.2.0/24`、
  `192.88.99.0/24`、`192.168.0.0/16`、`198.18.0.0/15`、`198.51.100.0/24`、`203.0.113.0/24`、`224.0.0.0/4`、`240.0.0.0/4`；
- IPv6：`::/128`、`::1/128`、`64:ff9b:1::/48`、`100::/64`、`2001:db8::/32`、`fc00::/7`、`fe80::/10`、`fec0::/10`、`ff00::/8`；
  NAT64（`64:ff9b::/96`）与 6to4（`2002::/16`）按内嵌 IPv4 判定；
- edge 本机的任何地址；
- 出站 TCP 25（SMTP）。

## 6. DoH（C2）
- 只接受 `POST /dns-query`，`Content-Type: application/dns-message`，请求体为单问题 DNS 报文（RFC 8484），上限 4096 字节；
  响应 `application/dns-message`。不记录查询内容。
- edge 把报文**原样**转发给宿主 `/etc/resolv.conf` 的上游（没有时用 1.1.1.1、8.8.8.8），先 UDP，应答截断时改 TCP；
  只接受 ID 与问题段一致的应答，并原样返回。因此所有记录类型与应答码（NOERROR、NXDOMAIN…）保持不变。
- 所有上游失败：SERVFAIL（rcode 2），不伪造“无记录”。
- 节点没有公网 IPv6 出口时，AAAA 返回空的 NOERROR 应答（不查上游），应用直接用 IPv4。
- 限流：每个 token 每秒 50 次，超出返回 HTTP 429。

## 7. 拒绝与客户端处理
edge 以 HTTP 状态 + `Proxy-Status`（RFC 9209，`aero; error=<token>; details="<文本>"`）说明拒绝原因；`details` 只含固定文本或 `EDGE_*` 错误码，不含内部地址：

| 状态 | `error` | 含义 | 客户端处理 |
|---|---|---|---|
| 401 | `proxy_authorization_required` | token 无效、被吊销或过期（`details="EDGE_AUTH_TOKEN_EXPIRED"`） | 重新拉取订阅换 token；同一会话不再向 edge 发请求；两次尝试至少间隔 15 秒 |
| 429 | —（带 `Retry-After`） | 来源 IP 因认证失败过多被暂时封禁（5 次/分钟 → 15 分钟） | 至少等待 `Retry-After` |
| 503 | `connect_ip_disabled`、`address_pool_exhausted`、`connection_limit_exceeded`、`udp_slot_limit_exceeded` | 本节点暂不能提供该服务 | 该节点记入 10 分钟冷却名单，换到其他可达节点并立即重连；没有可换节点时至少 60 秒后重试 |
| 403 | `destination_ip_prohibited` | 目的地址被 §5 拒绝 | 只影响该次请求，不影响会话 |
| 502 | `connection_refused`、`destination_ip_unroutable` | 目标不可达 | 只影响该次请求 |
| 400 | `http_request_error`（`details="EDGE_BAD_REQUEST"`） | 请求格式错误：缺少目标、端口不是 1-65535 的数字、URI 无法解析 | 只影响该次请求；属于客户端缺陷，不重试 |

客户端把拒绝原因反映到状态的 `error_code`（取 `details` 中的 `EDGE_*` 错误码，或按上表映射，见 `api/errors.yaml`）。

## 8. 未定稿
- 场景参数（`class=ai|browser|game`）与场景授权（C3 第 6 步）尚未实现。
- 多跳转发（edge `role=ingress|egress`、`Aero-Hop-Token`）存在于实现中但没有契约与测试，定稿前需决定保留或删除。
- token 吊销（C3 第 5 步，`EDGE_AUTH_TOKEN_REVOKED`）、按 uid 的配额 `quota_bytes` 与带宽 `bw_bps` 尚未在 edge 执行：依赖中台下发吊销名单（C4），随中台对接实现。在此之前，被吊销的 token 在过期（最长 7 天）前仍被接受。
