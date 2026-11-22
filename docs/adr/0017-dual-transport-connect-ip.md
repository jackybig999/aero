# ADR-0017 双传输 CONNECT-IP：数据报会话 D 与 DATAGRAM capsule 稳定会话 R

状态：proposed（2026-11-22）；用户确认方向：保持标准 MASQUE、永久不用用户态 TCP/IP 栈、一次设计到位；2026-11-22 用户授权其余细节由主会话按建议决定（见决定 8、9、P7，已按建议写定）
关系：细化 ADR-0003（会话与地址池）；遵守 ADR-0012 第 1 条（禁止用户态协议栈）；与 ADR-0006（出口模块）衔接；取代 aisys `final.md` 中的 `reliable-ip-v1` 私有扩展（不采用）

## 背景
目标：同一条 HTTP/3 连接内，AI 与网页的 TCP 流量要稳（丢包不拖垮长连接），游戏与 UDP 要快（低延迟、不被大流量挤占）。

已核对的事实（RFC 为 2026-11-22 抓取原文）：
- RFC 9484 §6：IP 包以 HTTP Datagram 承载，Context ID 为 0。§10：隧道内至少两层嵌套拥塞控制；IP 代理**应当**跑在 HTTP/3 上以利用 QUIC DATAGRAM 帧。
- RFC 9297 §3.5：DATAGRAM capsule（类型 0x00）允许在请求流上承载 HTTP Datagram，即流上的可靠承载。§3.2：capsule 数据占用底层流控，可能死锁。
- RFC 9484 §4.6：代理可给两个 IP 代理请求分配同一地址；多请求共用一条 HTTP 连接，标准无明文规定也无禁止。
- `connect-ip-go v0.4.0`：IP 包只经 `SendDatagram` 发出（`conn.go:607`）；`readFromStream` 对类型 0x00 走 `default: Discard()`；`ParseProxyRequest` 对带变量的模板直接报错（`request.go:74`），即 `target`/`ipproto` 不可用。
- edge 会话表限制“每个 QUIC 连接 1 个 CONNECT-IP 会话”（`edge/quic.go:2241,2258`），且 `maxDevices` 以会话数计。
- edge NAT 与地址池写死 `10.88.0.0/16`（`edge/nat_linux.go:33,112`、`serve.go:473`）。
- quic-go v0.63.0 数据报发送队列 32 帧，满后阻塞调用方（`datagram_queue.go:13,38`）；全部包共用一个 FIFO。
- 客户端 TUN 数据泵只依赖 `IPPacketConn{ReadPacket,WritePacket,Close}`（`tunnel_pump.go:23`）；edge 路由表按地址登记、reader 按会话建下行队列，均已支持多会话。

## 备选
1. 维持现状：单会话，全部数据报。
2. 在 TUN 内终结 TCP，转成 CONNECT 流：违反 ADR-0012 第 1 条，排除。
3. 私有 capsule（`reliable-ip-v1`，Type 0x41455230）：非标准、需双端私有实现、更易被识别，排除。
4. 双会话：D（QUIC DATAGRAM）与 R（标准 DATAGRAM capsule，走请求流），按 `class` 区分。

## 决定
选 4。

1. **会话与承载**。同一 QUIC 连接上最多两条 CONNECT-IP 请求：
   - D：`class=default`，IP 包走 QUIC DATAGRAM（RFC 9484 默认方式）。
   - R：`class=ai`，IP 包走 DATAGRAM capsule（RFC 9297 §3.5，Payload = Context ID 0 + IP 包），由 QUIC 流保证不丢。
   `browser`、`game` 为保留类别：token 可携带，v1 服务端对其返回 400 `unsupported_class`，不静默映射。
   类别授权取**本次请求验签得到的载荷**（不透明 token 与出口跳间凭证没有载荷，视为授权全部已实现类别），不读取连接绑定表：绑定发生在验签之后的另一步，其间并发请求会读到尚未写完的状态（P2b 审核发现，fail-open）。
2. **类别信号用请求头，不用 URI 模板**。头 `Aero-Class: default|ai`；服务端在响应里回 `Aero-Transport: datagram|capsule`，客户端核对一致，不一致即失败（`CLIENT_TRANSPORT_MISMATCH`），不得静默当作数据报使用。原因：库不支持模板变量；模板保持标准字面量 `ip/*/*/`。订阅 C5 增加能力字段 `transports`，旧节点不含则客户端不开 R。
3. **地址与源地址改写**。每条会话从自己的类别子网取一个地址。**两个子网都切自现有的 10.88.0.0/16**：`default` 用 10.88.0.0/17，`ai` 用 10.88.128.0/17（取代 ADR-0003 示例里的 10.89/16，2026-11-22 修订）。好处：服务端 NAT 规则、TUN 地址、`ConfigureGlobalTunnelDevice`、客户端 `tunPool` 都不变，没有新增宿主修改（ADR-0012）；按源子网做策略路由（ADR-0006）同样成立。每个子网容量约 3.2 万个地址，不足时再扩展，不影响本契约。TUN 网卡只配 D 的地址。客户端复用层（`ipmux`）在上行把 R 会话的包源地址改写为 R 地址，下行把目的地址改回 TUN 地址，增量更新 IP、TCP、UDP 校验和，并改写 ICMP 差错报文内嵌的原包头。服务端沿用 `ValidateSource` 按会话校验源地址。v1 只处理 IPv4（客户端 TUN 对 IPv6 已黑洞，`stack.go` `SetIPv6Blackhole(true)`）。
4. **客户端分类（按流，建立时确定，不迁移）**。
   - UDP、ICMP → D。
   - TCP：目的 IP 在 AI 集合内 → R，否则 D。
   - AI 集合由 DNS 处理器在应答 AI 域名（`builtinAIDomains` 与规则）时登记（缓存命中也续期）：IP → 过期时间（取应答 TTL 与 5 分钟的较大值，估算，待实测）。同一 IP 一旦登记为 AI，在过期前不因其他域名的应答而撤销。
   - 流表容量有上限并按最近使用淘汰、空闲 15 分钟删除（L0 §9.2；数值估算，待实测）。
   - **只有纯 SYN 才能开始一条 ai 流**；流表里没有项的中途包、分片、RST 一律走 default 且不记录。这样用户中途打开通道、条目过期或被淘汰时，已经在 default 上的连接不会因源地址突变而断流。
   - 分类错误只影响传输方式，不改变出口与安全属性（两类会话出口策略在 v1 相同）。
   - 是否让“非 AI 的普通 TCP”也进 R：由 P5 的丢包测量决定；在数据出来之前不进 R。
5. **客户端发送调度（针对 D）**。写入 `WritePacket` 之前分两级队列：小 UDP 包与 ICMP 优先，大流量限长度，满时尾部丢弃。目的：避免大流量占满 quic-go 的 32 帧数据报队列而阻塞游戏包。阈值与队列长度估算，待实测。
6. **库**。fork `connect-ip-go v0.4.0` 到 `third_party/connect-ip-go`，用 `replace` 引入，保留 MIT 许可证与版权声明。改动限于：(a) 构造选项选择“数据走 capsule”；(b) 写路径发 DATAGRAM capsule；(c) `readFromStream` 解析 0x00 并交给 `ReadPacket`（有界队列，满时停止读流，借 QUIC 流控反压；控制类 capsule 与数据共用一条流，实现时必须验证不因此死锁，RFC 9297 §3.2）；(d) D 会话收到 0x00 capsule、R 会话收到 QUIC 数据报，均丢弃并计数。服务端与客户端使用同一补丁版。改动提交上游 PR 为可选项，不作为前提。
7. **服务端会话表**。登记键由“连接”改为“连接 + 类别”：每个 QUIC 连接每个类别最多 1 条，共 2 条；`maxDevices` 按不同 QUIC 连接数计，而不是会话数；全局上限按会话数计；地址租约键：`default` 沿用原键，`ai` 为原键加 `/ai` 后缀（默认池从 /16 缩为 /17，哈希起点随之变化，升级重启后部分用户的 default 地址会变；租约本来就不持久化，客户端重连时只替换 TUN 地址，不受影响）；带宽令牌桶仍按 token 共用（两条会话合计）。两个子网都在原 /16 内，NAT、TUN、nftables/iptables 规则与宿主还原逻辑均不改。
8. **严禁降级**。
   - 任何情况下不回落到 TCP/TLS/h2；R 是 H3 请求流，不属于降级。
   - 未协商出 QUIC DATAGRAM 时，D 与 R 都失败，不自动改用 capsule 顶替。
   - 节点在订阅里**没有声明 capsule**（旧节点、中台订阅没有该字段）：不开 R 会话，客户端不包装连接，AI 流量走原来的 default 路径，行为与引入本 ADR 之前完全一致，界面状态为 `unsupported`。这不是降级：该节点本来就不提供稳定通道。
   - 节点**声明了 capsule** 但 R 会话建立不了（被拒、超限、传输方式不符、断线重拨中）：新建的 AI TCP 流 fail-closed（丢弃并回 ICMP 不可达），界面显示原因，不静默改走 D；已建立的流不受影响。这与 ADR-0006“ai 出口失效 fail-closed”一致；可由用户明确改为“允许改走 D”，默认关闭。（2026-11-22 定：采用 fail-closed。）
9. **质量回传的范围**。不是只有中台接口，分四段，每段可单独关闭：
   - L1 本机自适应：客户端对每个会话测量 RTT、丢包、队列丢弃，只用于本机决策，不出本机，始终开启。
   - L2 客户端 → edge：约每 60 秒一次 H3 请求 `POST /v1/qos`，Bearer token，载荷只含数值（类别、RTT 分位、丢包率、队列丢弃数、PMTU、网络类型粗分、客户端版本）。
   - L3 edge → 中台：并入 C6/C13，按“节点 × 小时 × 运营商粗分”聚合分位数，不含 uid 与目的地。
   - L4 用户主动发送诊断：用户点击后才上传，可含 uid，含当次会话的 L2 明细。
   - 永不采集：访问的域名与目的 IP、DNS 查询内容、流量内容、设备指纹、浏览历史。
   - 默认值（2026-11-22 定）：L1 始终开启；L2、L3 默认开启，首次启动时明示说明采集内容与不采集内容，设置里一键可关；关闭后 L1 仍生效，不影响连接。L4 永远由用户主动触发。工程剖面 `pii: true`，隐私声明与合规核对由项目所有者负责。
   - 对应契约（`api/qos.yaml`、C6/C13 增量）随 P6 提出，现在不改。
10. **契约变更草案（不在本步生效）**。C1：请求头 `Aero-Class`、响应头 `Aero-Transport`、`Proxy-Status` 错误 `unsupported_class`（400，`details="EDGE_UNSUPPORTED_CLASS"`）、复用 `errors.yaml` 已登记的 `EDGE_CLASS_NOT_ALLOWED`（403，token 未授权该类别）、客户端侧 `CLIENT_TRANSPORT_MISMATCH`；不透明 token（过渡期）视为授权全部类别；C5：`transports` 字段；C11：连接状态增加“AI 稳定通道”状态与错误码。随 P2 一并提出，经用户确认后修改 `api/` 文件（§4.1）。

## 后果
- R 会话内所有 TCP 流共用一条请求流，一个包丢失会让同会话的流短暂等待（队头阻塞）；内层 TCP 也可能误判超时，与外层重传叠加。RFC 9484 §10 也说明标准更偏好数据报。因此 R 的收益必须由 P5 测量证明，否则只保留 R 的能力、不扩大使用范围。
- 新增维护面：库 fork（升级 quic-go 时要跟随）、客户端校验和改写（需与完整重算对拍的测试）、服务端多池 NAT。
- 数据泵、TUN 宿主、DNS 处理器、数据路由表不需要重写：复用层实现 `IPPacketConn`，对泵透明。
- 客户端断线重连（`engine_reconnect.go`）要同时恢复两条会话：D 失败视为整体断线；仅 R 失败时只重建 R，AI 新流按第 8 条处理。
- 这套结构是 ADR-0006 的前置：`ai` 池有了独立源地址，才能让 AI 的 TUN 流量也走 egress（WARP 或干净出口）。

## 实施步骤（每步 ≤3 个非生成文件；高风险步 reviewer 必审，§14.9 第 5 条）
| 步 | 内容 | 主要文件 |
|---|---|---|
| P0 | 本 ADR；ADR-0003 注明被细化 | docs/adr |
| P1 | fork 库，加 capsule 数据模式、解析 0x00、单元与模糊测试；`go.mod` replace；依赖说明（§7.6） | third_party/connect-ip-go、go.mod |
| P2 | 服务端：P2a 契约与 errors.yaml；P2b `Aero-Class`、两个类别子网、会话表改键、`Aero-Transport`、类别授权；P2c 订阅 `transports` 字段。不改 NAT/TUN/命令行入口 | api/、internal/edge（quic.go、新增 connectip_class.go、sub.go） |
| P3 | 客户端复用层与源地址改写；`dialIPFn` 返回复用层；重连支持双会话 | internal/client（ipmux.go、ipnat.go、engine*.go） |
| P4 | 分类器（DNS 登记 AI 集合、流表）与 D 的两级发送队列 | internal/client（dns.go、flowclass.go、tunnel_pump.go） |
| P5 | 丢包测量：`unshare` + `tc netem`，丢包 0/1/3/5%、往返 50/150ms；AI 式流式响应、大文件、并行游戏式 UDP；指标：数据块到达延迟 p50/p95/p99、吞吐、卡顿、游戏 UDP 抖动；据此定“普通 TCP 是否进 R”。阈值先在 0% 基线标定，不预设数字 | tools/、tests/ |
| P6 | 质量回传 L2–L4：契约、endpoint、客户端设置项 | api/qos.yaml、internal/edge、internal/client |
| P7 | 界面（含把状态字段 `ai_channel`、`ai_channel_reason`、`ai_channel_enabled` 写进 C11 契约；`api/client-ui.yaml` 目前不存在）：一个“AI 稳定通道”开关（默认开）与状态，放在线路页（与链式代理详细配置同页，不增加主页模式按钮，不放设置页）；游戏不设开关（UDP 一律走 D）；C11 错误码 | cmd/client/ui、cmd/desk/ui |

门禁：每步 `bash tmp/gate.sh` 输出 `GATE PASS`；P1、P2、P3 另需 reviewer（Opus，只读，仅看本次 diff）审核；网络相关测试只在 `unshare` 命名空间内做，不动宿主。

## 不做
- 不在 TUN 内终结 TCP；不引入任何用户态 TCP/IP 栈（ADR-0012）。
- 不使用私有 capsule 类型；不新增服务端 DPI/SNI 嗅探。
- v1 不处理 IPv6、不启用 `browser`/`game` 类别、不做流的跨会话迁移。

## 实现说明（P3，2026-11-22）
- 复用层 `ipMux`（`internal/client/ipmux.go`）实现 `IPPacketConn`，数据泵、TUN、DNS 不改。节点声明了 capsule 才创建；用户关闭通道时复用层仍在，只是不拨 ai 会话、分类器让一切走 default（运行中可开关，无需重连）。
- ai 上行有独立队列（128 包）和独立写协程，满则丢尾：数据泵是单协程，ai 的流控反压不能阻塞 default 的上行。ai 的任何读写错误只让 ai 降级并按退避重拨（永久性拒绝如 `class_not_allowed` 不重拨），不让泵报错。
- 源地址改写只处理 IPv4：IP、TCP、UDP 校验和增量更新；ICMP 差错报文改写内嵌头（分片的 ICMP 不改内嵌头，系统会忽略这类差错）。
- 已知限制：数据泵重启后，旧泵里还卡在 TUN 读上的协程会吃掉重连后的第一个包（已有行为，TCP 重传）；用户中途关闭通道时，已建立在 ai 上的连接因源地址改变会中断（显式操作）。
