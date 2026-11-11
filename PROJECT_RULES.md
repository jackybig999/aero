# PROJECT_RULES

继承：GLOBAL_ENGINEERING_RULES.md（v1.1.1）
language: go

> 草稿状态：draft（M0）。数值标注“实测”的沿用旧版 PROJECT_RULES 的测量；标注“估算”的须在 M2/M4 用 §13.4 的测量替换，替换前不得在发布说明中写“已按实测设定”（L0 §9.1）。

## 职责
AERO：基于标准 HTTP/3 MASQUE（RFC 9298 / RFC 9484）的多用户加密隧道系统，按 AI、浏览器、游戏、其他四类流量场景分流，绝不降级到 TCP 承载数据面。

## 版本来源
根目录 `VERSION` 文件，构建时以 `-ldflags -X` 注入各二进制；代码中 **MUST NOT** 硬编码版本号（§15.4）。发布性协议或契约变更前 **MUST** 递增版本。

## 组件与边界（ADR-0001）

| 组件 | 目录 | 权威范围 | 禁止 |
|---|---|---|---|
| edge | `internal/edge`、`cmd/edge` | 数据面、token 校验、计量、端口选择、证书、geo 分发、自身配置 | 调用 sub；执行 shell；安装或卸载系统软件 |
| egress | `internal/egress`、`cmd/egress`（M5 新建） | 出口（direct / warp / relay）、出口健康分 | 鉴权用户；读写 edge 存储 |
| client | `internal/client`、`cmd/client` | 本地分类、本地 DNS、隧道、防泄漏 | 持有业务事实（配额、档位判定以 edge 为准） |
| sub | `internal/sub`、`cmd/sub` | 用户、计费、token 签发、吊销列表签发 | 写 edge；运行时调用 edge 的写接口 |
| desk | `internal/desk`、`cmd/desk` | 浏览器环境与指纹，每个环境的状态持久保留 | 直接操作隧道或路由 |
| 安装脚本 | `deploy/` | 放置二进制与 systemd unit、启动服务 | 读写任何组件配置文件；修改防火墙、路由；生成密钥 |

### 目录布局（ADR-0009）
- 最多两级：`cmd/<组件>/`、`internal/<组件>/`；契约统一在 `api/`，ADR 在 `docs/adr/`，部署在 `deploy/`，测试工具在 `tools/`，跨组件测试在 `tests/`。
- **MUST NOT** 新建 `common/`、`utils/` 等无业务语义目录（L0 §2.3）。
- `internal/<A>` **MUST NOT** import `internal/<B>`；`cmd/<A>` 只能 import `internal/<A>`。由 `tools/check-imports.sh` 在 CI 中强制，违反即阻断。
- 契约类型由 `api/` 生成到各消费方自己的包内，**MUST NOT** 建共享类型包（避免组件通过共享包穿插）。

- 组件之间只通过 `api/` 中的契约通信（§3.2、§4.1）。
- 运维 CLI（`deploy/aero`）**MUST** 通过 edge 本地管理接口（unix socket）操作，**MUST NOT** 用 `sed` 等方式改配置。

## 业务专有规则

### 出口与 WARP（ADR-0006）
- WARP **MUST** 使用 Cloudflare 官方客户端（`cloudflare-warp` 软件包，`warp-cli`/`warp-svc`）及其官方运行模式，**MUST NOT** 使用第三方生成的 WireGuard 配置（如 wgcf）。
- 官方客户端由运维按 Cloudflare 官方文档安装；edge 与安装脚本 **MUST NOT** 安装或配置 WARP。
- 接入方式（官方 warp 模式运行在独立网络命名空间，或官方 proxy 模式）在 M5 前以 spike 验证后由新 ADR 定稿。

### 流量场景（ADR-0003）
- 场景枚举（契约权威枚举，§4.2）：`ai`、`browser`、`game`、`default`；另有不进隧道的 `direct`。
- 每个场景使用独立的 CONNECT-IP 会话与独立地址池；edge 按源地址池打 fwmark 交给内核策略路由。
- `ai`、`browser`：出口不可用时 fail-closed，**MUST NOT** 回落直连。`game`：不加填充、不混淆，出口 IP 在会话内不变。`browser`：按环境 ID 粘性绑定出口，变更出口前 **MUST** 通知 desk。
- 游戏判定：桌面端按进程 + 规则，移动端按规则。

### 隐蔽分层（ADR-0004）
- 默认：标准 HTTP/3 + 真实域名 + Let's Encrypt 通配符证书（DNS-01，Cloudflare）+ 随机子域名；节点 DNS 记录 **MUST** 为灰云。
- ECH：计划默认开启，edge 自生成 HPKE 密钥，配置仅由 edge 写入订阅；flag `ech_enabled` 默认 `OFF`，quic-go 路径抓包验证与国内网络实测通过后方可 `ON`（§4.4）。
- ECH 握手失败：**MUST** fail-closed 并切换到混淆节点组；**MUST NOT** 回退明文 SNI。
- 混淆档位：非标准协议，**MUST** 使用独立节点或独立端口组，**MUST NOT** 与标准档位共用监听。

### 端口（ADR-0005）
- 候选端口列表是契约：`443` + `2083, 2087, 8443, 2053, 2096, 10443, 24443, 34443, 44443`，edge 与 client 各一份，一致性测试守护。
- TCP（订阅、伪装站）与 UDP（数据面）**MUST** 分开选择端口。
- edge 只在启动时按列表顺序选端口，选定后持久化，下次优先沿用；被自身旧进程占用时先等待重试；**MUST** 用独占锁文件，**MUST NOT** 启用 `SO_REUSEPORT`。
- client 依次尝试候选端口（TCP 与 HTTP/3），成功端口 **MUST** 落盘缓存。
- 会话中途端口跳变：edge 在进程内同时监听多个候选 UDP 端口（不使用 DNAT，ADR-0012）。

### 鉴权（ADR-0002）
- 用户 token：sub 以 Ed25519 签发，字段 `{uid, tier, classes, max_devices, exp, kid}`；edge 以配置中的公钥离线验签。
- 吊销：edge 定期拉取 sub 签名的吊销列表；拉取失败不影响已有会话判定，以 token 的 `exp` 兜底。
- 吊销、过期、超配额、超设备数：edge **MUST** 在 10 秒内断开该 token 的全部会话（估算，M3 实测）。
- 管理员订阅：配额不限，但 **MUST** 鉴权（§7.2），**MUST NOT** 存在匿名可取的订阅路径。

### IPv6（ADR-0007）
- 外层 IPv6：client 并行竞速 A/AAAA。
- 内层 IPv6：ULA 地址池 + NAT66；edge 启动自检通过才在订阅中声明，否则 client 走 IPv6 黑洞。
- `ai`、`browser` 场景：IPv6 出口地理位置与 IPv4 不一致时，该场景只走 IPv4 并对 AAAA 返回空应答。
- IPv6 流量 **MUST** 只有两种去向：进隧道或黑洞，**MUST NOT** 漏到物理网卡。

## 对 L0 的收紧项
- 客户端 TUN MTU 固定 1224，**MUST NOT** 运行中修改网卡 MTU；路径 MTU 交给 ICMP/PTB 处理。
- 数据面 **MUST NOT** 降级为 TCP 承载；UDP 整体不通时返回 `CLIENT_UDP_BLOCKED`。
- 未鉴权请求在 TCP 与 HTTP/3 上 **MUST** 只看到伪装站；鉴权失败的响应与伪装站在状态码、头部、长度分布上一致。`/healthz` 仅监听本机或需鉴权。
- edge **MUST NOT** 记录用户访问的目的地址。
- 测试代码与测试开关 **MUST NOT** 改变生产代码分支；测试使用测试 CA（§7.4）。
- CONNECT-IP 写入 TUN 之前 **MUST** 做目的地址 ACL；默认拒绝：私网、链路本地、回环、组播、CGNAT、元数据地址、本机地址、其他用户地址池、出站 25 端口。
- 任何破坏性删除或清理 **MUST** 先归档并提供清单和回滚脚本（沿用旧规则）。
- 客户端不修改宿主防火墙、注册表与系统 DNS（ADR-0012）。

## 剖面参数（§0.7）

### 核心业务包（§13.1）
`internal/edge`、`internal/client`、`internal/egress`（M5 新建）。

### 超时（§8.1）
| 调用 | 值 | 来源 |
|---|---|---|
| QUIC 建连 | 8 秒 | 实测（旧版） |
| HTTP/TLS 外部调用 | 10 秒 | 实测（旧版） |
| 健康探测 | 3 秒 | 实测（旧版） |
| 订阅候选端口 | 单端口 2.5 秒，总计 6 秒 | 实测（旧版） |
| DoH 上游 | 2.5 秒 | 估算 |
| 吊销列表拉取 | 10 秒，间隔 60 秒 | 估算 |
| ACME（DNS-01 传播等待） | 120 秒 | 估算 |

### 入站与安全（§7.3、§7.5、§5.3）
- 请求体上限：管理 API 1 MiB；DoH 4096 字节；订阅请求无请求体；CONNECT-IP 单帧 65535 字节（实测）。
- 限流：每 IP 新建 QUIC 连接 20 个/秒（估算）；鉴权失败按 token 指纹加延迟，不按 IP 封禁（避免 CGNAT 连坐）；控制台每 IP 60 req/min（实测）；DoH 每 token 100 QPS（估算）。
- 每 token 并发设备数：由 token 的 `max_devices` 决定，服务端原子计数。
- Cookie：`Secure; HttpOnly; SameSite=Strict`；值为服务端会话 ID，**MUST NOT** 存原始管理密钥。

### 持久化（§6.10、§8.8）
- edge SQLite：WAL 模式；单写连接 `SetMaxOpenConns(1)` + 读连接池 4；`busy_timeout=5000`；`foreign_keys=ON` 写入 DSN。
- 配置、证书、geo 文件：同目录临时文件 → `Sync` → `Close` → `Rename` → 目录 `fsync`；失败保留旧文件。Windows 客户端使用 `ReplaceFile`，附失败注入测试记录（M2 补）。

### 服务生命周期与预算（§8.6、§9.1、§15.5、§17.2）
- 停止信号：Unix 为 `SIGINT`、`SIGTERM`；Windows 为服务控制管理器停止事件。排空上限配置项 `drain_timeout`，默认 15 秒。
- `/readyz` 与 `/healthz` 分离，仅监听本机 unix socket 或 loopback。
- 资源预算（估算，M2 实测替换）：edge 内存 limit 512MB（`GOMEMLIMIT=460MiB`）；egress 128MB；桌面 client 256MB；**移动端 Go 侧 40MB**（iOS NetworkExtension 上限约 50MB）。
- 回滚阈值：metrics 落地前，由发布人在发布后 15 分钟内人工核对 §15.5 四项；metrics 落地后改为“5 分钟内 CONNECT-IP 建连失败率比基线高 5 个百分点自动回滚”。
- 值班：无 24/7 值班。

### 错误码（§4.5）
- 注册表：`api/errors.yaml`。
- 前缀：`EDGE_`、`EGRESS_`、`CLIENT_`、`SUB_`、`DESK_`。

### 个人信息（§6.11）
| 数据 | 保留期限 |
|---|---|
| 计量明细（按小时聚合，不含目的地址） | 90 天，之后只保留按月汇总 |
| 连接元数据（token 指纹、建连时间、来源 IP） | 7 天 |
| 环境 ↔ 出口绑定 | 环境删除后 7 天 |
| 测试运行数据 | 不超过 7 天 |
| 删除请求时限 | 30 天内完成主存储删除，审计留痕 |

## 宿主全局状态（§8.10，ADR-0012）

铁律：服务端不改 VPS 系统与配置，客户端不改宿主（注册表、NRPT、系统或其他网卡 DNS、配置文件、持久防火墙规则、物理网卡路由均禁止）；**MUST NOT** 使用 gVisor 或任何用户态协议栈。只允许“随进程或自有网卡自动消失”的状态（ADR-0014）；无法自动消失的项（仅服务端）**MUST** 同时具备退出回滚、崩溃应急回滚、启动自检回滚。

| 所有者 | 修改内容 | 标记 | 自动消失 | 退出 / 崩溃 / 启动 | 手动清理命令 |
|---|---|---|---|---|---|
| edge | TUN 设备 `aero-tun0` | 设备名 | 进程退出即消失 | — | — |
| edge | iptables 规则（转发放行、NAT、MSS 钳制，仅限 TUN；原 `ip_forward` 为 0 时追加“非本 TUN 转发一律丢弃”，保持宿主原语义） | 注释标签 `aero_edge_default` | 否 | 删除 / `ExecStopPost` / 启动先删 | `aero-edge cleanup-host` |
| edge | `ip_forward` | 数据目录 `host-state.json` 记录修改前原值（崩溃后重启不覆盖） | 否 | 还原原值 / `ExecStopPost` / 启动先还原 | 同上 |
| client | TUN 网卡 `aero0` 及其地址、路由、MTU、该网卡自身 DNS | 设备（Windows 固定 GUID） | 网卡销毁即消失 | — | — |
| client（Windows） | WFP 动态会话过滤规则（放行本进程与本网卡，屏蔽其余 53 端口） | 动态会话 | 进程退出即由内核删除 | — | — |
| client（macOS） | SCDynamicStore 会话键（本服务 DNS） | 会话 | 进程退出即删除 | — | — |
| client（Linux） | systemd-resolved 中 aero0 的链路 DNS 与 `~.` 路由域 | 设备 | 网卡销毁即消失 | — | — |

每项 **MUST** 附一次“强杀后残留”记录（M4 补）。
