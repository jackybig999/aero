# AERO 项目研发与执行准则 (PROJECT_RULES.md)

> **Version**: 2.2.0-hardened (Aligned with GLOBAL MASTER RULES v1.0.0 & Universal Pre-Flight Protocol)  
> **Last-Updated**: 2026-10-02  
> **Maintainer**: Jacky  
> **Language-Stack**: Go 1.24+ (Solidified, per GLOBAL MASTER RULES §1.3)  
> **Repository-Module**: `module github.com/aero-protocol/aero`  

---

## 语言选型固化 (Solidified Tech Stack) `[REVIEW]`
- **核心语言**: Go 1.24+ 标准工程，单模块单一代码树。
- **选型锁定状态**: 已固化锁定为 **Go**（Go 1.24+），后续会话自动继承，禁止反复询问，不可擅自切换至 Rust 或其他语言。

---

## 第一部分：全局底座准则继承说明
本项目无条件继承 `GLOBAL MASTER RULES v1.0.0` 的全部规范（涵盖 §0 规范性约定、§1 技术栈准入与前端零信任、§2 目录结构、§3 构建产物隔离与三路径模型、§4 跨进程与跨子系统解耦契约、§5 API 兼容性、§6 数据所有权与数据库加固、§7 契约驱动前后端联动、§8 研发流程闭环、§9 测试规范、§10 CI/CD 卡点、§11 依赖管理、§12 日志与可观测性、§13 错误处理与异步安全、§14 运行时验证、§15 发布回滚、§16 稳定性工程、§17 资源效率预算、§18 豁免与审核）。

---

## 第二部分：AERO 核心架构、契约设计与系统隔离铁律

### C1. 全系统单一模块与三层平铺目录结构 (Single Module & Flat Layout) `[CI]`
* **单一模块 (MUST)**：全仓仅使用唯一模块 `module github.com/aero-protocol/aero`，彻底废除多模块与 `go.work`。
* **三层平铺封顶 (MUST)**：
  - 第一层：仓库根目录；
  - 第二层：`cmd/`、`internal/`、`deploy/`；
  - 第三层：各子包具体源码文件（如 `internal/client/engine.go`、`cmd/client/main.go`）；
  - **绝对禁令 (MUST NOT)**：全仓严禁设立 `public/`、`protocol/`、`domain/`、`infra/`、`service/`、`win/`、`mac/`、`common/`、`util/`、`helper/`、`pkg/` 等任何中间层或无业务语义容器目录。
* **跨平台文件命名 (MUST)**：平台特异性逻辑使用 Go 标准文件后缀实现（`stack_windows.go`、`stack_linux.go`、`stack_darwin.go`、`stack_android.go`、`stack_ios.go`、`window_windows.go`、`window_darwin.go`、`window_other.go`）。

### C2. 核心契约设计与严禁跨子系统穿插铁律 (Decoupled Contracts & Zero Cross-Import) `[CI]`
* **绝对隔离铁律 (MUST NOT)**：
  - `internal/client`、`internal/edge`、`internal/mid`、`internal/desk` 四大核心业务包在 Go 源码层面**严禁发生任何交叉 `import`**！
  - 任何试图在 `client` 中引用 `mid`、在 `desk` 中引用 `client`、或在 `mid` 中引用 `edge` 内部实现的编译行为均属于违规阻断项。
* **显式契约边界 (Contract Boundaries) (MUST)**：
  1. **Proto 协议契约**：`internal/proto` 仅存放由 `aero.proto` 生成的静态 Go 结构代码（`aero.pb.go`）。该包为 `client` 与 `edge` 之间数据面的**唯二共享源码依赖**。
  2. **边缘节点管控契约**：中台与边缘节点仅通过标准 HTTP REST 接口交互（`POST /admin/subs` 注册下发 Token、`GET /health` 探活），使用 JSON 通信，严禁跨进程读写对方数据库或共享内部包。
  3. **订阅发布契约**：中台向用户和节点颁发原生 `aero/3.0` 标准 JSON 订阅。客户端单向通过标准 HTTPS 443 接口拉取并解析。
  4. **桌面沙箱交接契约**：桌面指纹沙箱（`internal/desk`）与客户端网络数据面仅通过本地 `127.0.0.1:19877` HTTP 状态端点和本地 SOCKS5 端口通信；严禁代码级绑定。

### C3. 前端零信任与轻量嵌入标准 (Frontend Zero-Trust & Embedded Assets) `[CI]`
* **零信任红线 (MUST NOT)**：前端静态代码严禁包含任何明文密钥、Token、内部连接串或业务判决逻辑。
* **零运行时依赖 (MUST)**：控制台与界面一律采用原生 HTML5 + CSS + Vanilla JS 编写，严禁引入重量级前端框架，严禁提交 `node_modules/`。
* **资源体积预算 (MUST)**：单个页面 JS gzip 后体积必须 < 150 KB。
* **单二进制嵌入 (MUST)**：所有 Web 资源统一通过 Go 标准库 `//go:embed` 嵌入可执行二进制文件交付。

---

## 第三部分：AERO 数据面关键工程与容灾加固规范

### D1. 客户端网络栈与 MTU/ICMP 反压门禁 (Client MTU & ICMP Backpressure) `[CI]`
1. **虚拟网卡初始 MTU**：虚拟网卡（Wintun / utun / tun）初始 MTU 设为 1224（对应最大数据报 1200 + 24 字节开销），严禁写死 1280 或 1500。
2. **栈入口 IPv4 DF 检查与 ICMP 回写 (MUST)**：
   - 数据包进入 gVisor 虚拟网络栈入口时，从刚注入的 IPv4 首部读取 DF（Don't Fragment）标志；
   - 若包长超过当前数据报允许上限（`len(packet) > currentMaxDatagramSize + 24`）：
     - **若 DF == 1**：在栈内生成 `ICMP Type 3 Code 4 (Fragmentation Needed)` 报文，Next-MTU 字段设为当时的 `currentMaxDatagramSize + 24`（初始 1224）；源 IP 为虚拟网卡网关地址，目的 IP 为原数据包源 IP，载荷包含原 IPv4 首部及前 8 字节；**该报文仅向本地虚拟网卡回写，绝对不进入 QUIC，绝对不发往 VPS**；
     - **若 DF == 0**：直接静默丢弃；
3. **动态 MTU 自适应与路由同步 (MUST)**：
   - QUIC 传输层捕获到 `*quic.DatagramTooLargeError` 异常时，立即动态下调 `currentMaxDatagramSize`；
   - 立即联动调用虚拟网卡动态 MTU 重设接口（`SetInterfaceMTU`），将网卡 MTU 同步更新为新的 `currentMaxDatagramSize + 24`；后续会话与 ICMP 反压均以新数值为准。
4. **数据报超限预检与直接丢弃 (MUST)**：
   - 客户端在向底层发送数据报前，若 `4 + len(payload) > currentMaxDatagramSize`，必须立即直接丢弃；**严禁调用 SendDatagram、严禁回退到 QUIC Stream、严禁组包**。
5. **移除游戏特征与端口盲判 (MUST)**：彻底移除 `IsGameTraffic`，流量调度严格以 IP 首部协议号为准。

### D2. DNS 零泄露两级漏斗 (Two-Stage DNS Funnel) `[CI]`
1. **第一级漏斗**：`.cn` 域名及内网/局域网保留域名直连宿主机物理 DNS 解析，主动剥离丢弃 AAAA 记录防止 IPv6 泄露。
2. **第二级漏斗**：非 `.cn` 域名全量通过隧道内部短流（`StreamType_CONTROL`）由海外边缘节点解析；解析失败或尚未建连时回传 198.18 假 IP；Type AAAA 一律回空应答。
3. **严禁 53 端口兜底泄露 (MUST NOT)**：gVisor 虚拟栈内 DNS 处理返回 nil 时，直接栈内丢弃（`DecRef()`），严禁调用 `DialUDP` 穿透宿主机物理网络！

### D3. 客户端会话弹性与防死锁 (Client Session Resiliency) `[CI]`
1. **故障隔离**：单流超时或失败绝对不可调用 `GlobalSessionPool.Remove` 销毁整条物理 QUIC 连接。
2. **重试约束**：单流向外出站拨号最多重试 1 次，严禁在重试循环中执行 `time.Sleep`。
3. **换线与订阅刷新幂等**：`switchActiveNode` 仅比对目标 `host:port`，目标未变时短路返回，严禁调用 `Reset()` 引起网络颠簸；`loadAndApplySubscription` 挂载 `singleflight.Group` 阻断并发重入。

### D4. 边缘节点商业多租户与防雪崩门禁 (Edge Server Multi-Tenant & Anti-Avalanche) `[CI]`
1. **连接级鉴权与 Nonce 消耗 (MUST)**：
   - 每个 QUIC 连接建立唯一的 `handleQUICConn` 上下文；
   - 仅该连接上的第 1 条握手流执行 `ValidateFull` 校验并消耗 Nonce，通过后将 Token 绑定到连接对象；
   - 同一连接上的后续流与 UDP 登记流严格校验 `req.Token == conn.Token`，免除 Nonce 重复校验。
2. **TCP 业务流流控门禁 (CRITICAL GATE) (MUST)**：
   - **仅对 TCP 业务流**在 `AcceptStream` 成功后调用 `ConnLimiter.TryAcquire(token)`；
   - 仅当返回 `true` 时，才执行 `defer ConnLimiter.Release(token)` 并调用 `DialGuard.DialTimeout` 向外拨号；
   - 若返回 `false`（超限），向流写入拒绝响应并优雅关闭该流，**底层 QUIC 会话严禁断开**。
3. **短流 DNS 与 Context 登记流豁免门禁 (MUST)**：
   - **DNS 短流与 UDP Context 登记流绝对免占 `ConnLimiter` 连接槽位、绝对不调用 `TryAcquire`、绝对不进入 `DialGuard` 拨号闸门**！
4. **单连接唯一数据报接收循环与 Context 调度 (MUST)**：
   - 单连接仅运行一个 `ReceiveDatagram` 读取循环，解析出 4 字节大端 `ContextID`，分发至本连接关联的 Context；
   - 每个 UDP Context 独占非阻塞 `net.UDPConn`，单 Token 限制最多 64 个 Context，全局总帽防护，45 秒空闲自动注销归还资源；
   - 双向流量（出站与入站）必须严格扣减 `BandwidthLimiter.Take(token, len)`。
5. **日志安全脱敏 (MUST)**：边缘节点日志绝对严禁明文输出 Token。

---

## 第四部分：子系统边界与运维交付准则

### O1. 移动端轻量占位标准 (Mobile Adapters Honesty) `[REVIEW]`
- 桌面全功能交付期间，移动端适配器（`stack_android.go`、`stack_ios.go`）中的 `SetupRoutes` 明确返回 `fmt.Errorf("TUN not supported on this platform")`；
- 客户端启动时若检测到 TUN 不支持则优雅失败并在界面明确提示；
- 严禁提前引入 `gomobile bind`、严禁生成 `.aar` / `.xcframework`、严禁添加 `StartTunnelWithFD`。

### O2. 宿主机零污染与系统代理禁令 (Host Cleanliness & Zero Proxy Tampering) `[CI]`
- **严禁篡改系统代理**：物理彻底删除 `sys_proxy_windows.go` 与 `sys_proxy_darwin.go`，任何模块均不得修改操作系统级全局代理设置。
- **严禁侵入防火墙**：物理删除客户端调用 `netsh advfirewall` 添加规则的代码。
- **清理自愈闭环**：Windows 守卫进程（`aero-guard.exe`）通过 `//go:build windows` 编译，仅监控主进程 PID，退出时仅清理属于 `aero0` 的 `0.0.0.0/1` 与 `128.0.0.0/1` 路由并关闭接口。

### O3. 唯一官方订阅格式与无端口发布 (Native AERO Sub & Zero-Port URL) `[REVIEW]`
- 全系统严格仅支持以下两种标准原生订阅：
  1. 系统管理员：`https://domain.com/sub/superadmin`
  2. 普通用户：`https://domain.com/sub/username{六位随机码}`
- **【绝对红线：严禁输出或伪造本地宿主机订阅】**：
  - 本地商业中台（`127.0.0.1:18080` / `localhost:18080`）**仅作为后台运维管理控制台（Admin Dashboard）及内部 API 处理机**，自身绝非用户消费订阅的端点；
  - 任何 AI 助手、代码、日志、提示信息、交互界面中，**绝对严禁输出形如 `http://localhost:18080/sub/...`、`http://127.0.0.1:18080/sub/...` 或携带任何非 443 端口的订阅链接！**
  - 订阅链接必须且只能通过已配置 SSL 证书的公网标准 443 HTTPS 域名发布；
  - 向用户展示中台自测与服务状态时，**严格仅允许输出管理控制台 `http://localhost:18080/` 与健康检查 `http://localhost:18080/healthz`，严禁向用户提示或输出任何本地订阅链接！**
- 严禁在订阅链接中携带 `:18080`、`:8080` 等非标端口；必须通过标准 443 HTTPS 域名发布；
- 严禁生成或兼容任何第三方异构代理订阅（Clash、v2rayN、sing-box 等）。

### O4. 生产独立交付与自动化脚本 (Independent Deployment & Scripts) `[REVIEW]`
- 客户端与边缘节点支持完全独立发布，不依赖中台与工作台；
- 边缘安装脚本（`deploy/edge-install.sh`）闭合 iptables 语法（补齐 `fi`）；
- 所有二进制产物由标准 `go build` 原生编译生成。

---

## 第五部分：通用工程交付防错、Git 预检与仓库防御准则 (Universal Delivery & Anti-Error Protocol)

> 本部分沉淀自本项目多轮严格工程审计与实战复盘，适用于 AERO 全仓及任何追求工业级高可靠交付的工程项目。所有开发人员与自动代理必须无条件遵循。

### U1. 交付预检与 Git 索引对齐准则 (Pre-Flight Git Alignment Gate) `[CI/RELEASE]`
* **根因警示**：本地工作区物理文件的存在极易造成“本地测试通过 = 可以发布”的虚假安全感。若新增源码、单元测试或 `//go:embed` 静态资产未纳入 Git 追踪（处于 `??` 状态），一旦推送到远端或由 CI/VPS 克隆构建，将立即引发严重的 `undefined symbol` 或 `pattern no matching files` 编译崩溃事故。
* **执行红线 (MUST)**：
  1. **零未跟踪红线 (Zero Untracked Files)**：
     - 在任何代码提交（commit）、合并（PR）或推送（push）前，`git status --porcelain` 输出中未跟踪项（`??`）必须严格为 **0**；
     - 严禁留存任何游离的核心源码、测试脚本或配置资产；新文件必须明确执行 `git add` 纳入版本追踪。
  2. **删除显式暂存 (Explicit Deletion Staging)**：
     - 工作区物理删除的文件必须显式通过 `git add -u` 或 `git rm` 纳入暂存区，严禁遗留 `Changes not staged for commit: deleted: ...` 悬空状态导致远端残余过时文件。
  3. **暂存区对齐终审 (Staging Validation)**：
     - 严禁盲目依赖 `git commit -a`（该命令无法追踪新增文件）；
     - 提交前必须执行 `git diff --cached --stat` 逐一核验待提交清单，确保修改、新增、删除与交付目标 100% 吻合。
  4. **干净克隆模拟验证 (Clean Clone Simulation)**：
     - 在重大发布或里程碑交付前，必须在隔离临时目录中通过 `git clone` 模拟全新环境构建：`go build ./...` 与 `go test ./...`，证明仓库绝无依赖本地宿主机未追踪文件的隐式隐患。

### U2. 物理资产卫生与轻量隔离模型 (Physical Hygiene & Strict 3-Path Model) `[CI]`
* **根因警示**：大体积可执行文件、构建中间件与高分辨率设计源文件若随意堆放于代码根目录，不仅会导致仓库体积爆炸式膨胀（几 MB 源码膨胀至近百 MB），还会永久污染 Git 历史对象库，拖垮拉取与构建带宽。
* **执行红线 (MUST)**：
  1. **二进制产物绝对零入库 (No Binaries in Git Tree)**：
     - 所有平台构建可执行文件（`*.exe`, `client`, `edge`, `*.dll`, `*.so`, `*.dylib`，除极少数强绑定的核心驱动白名单如 `wintun.dll` 外）严禁出现在 Git 树中；
     - 本地 `go build` 产生的调试二进制必须在测试完成后即刻物理清理；生产发布二进制严格仅推送到 GitHub Release Assets。
  2. **设计原始素材与运行时代码解耦 (Design Asset Decoupling)**：
     - 高清设计切图、全尺寸图标套件（如包含 Mac `.icns`、iOS 1024、Android 多分辨率 mipmap 等）属于设计中间件，严禁直接堆放于业务代码根目录；
     - 嵌入可执行文件的静态资源必须经过极端轻量化压缩（单图标 < 150KB，全静态集合 < 500KB），存放于专属 `assets/` 或 `ui/` 目录并明确声明 `//go:embed`。
  3. **运行态数据与数据库全量忽略 (Runtime & DB Exclusion)**：
     - 本地测试/开发生成的数据库文件（`*.db`, `*.db-shm`, `*.db-wal`）与运行时目录（`data/`, `tmp/`, `logs/`）必须 100% 纳入 `.gitignore`，杜绝任何运行时状态数据与敏感测试数据泄露入库。
  4. **临时目录沙箱隔离与源码零污染铁律 (Tmp Sandbox & Zero-Pollution Mandate)**：
     - 仓库根目录下的 `tmp/` 目录为全工程唯一合法的本地临时工作空间；
     - **测试零污染**：所有本地测试、基准测试产生的文件、临时套接字、Mock 数据库必须强制重定向至 `tmp/` 目录完成（通过 `GOTMPDIR` 或 `t.TempDir()`），严禁在源码树、包目录或根目录下生成任何临时测试文件；
     - **构建零污染**：本地开发、调试编译产生的所有临时可执行文件，必须显式重定向至 `tmp/` 输出（如 `go build -o tmp/client.exe ./cmd/client`），严禁直接裸输出至源码根目录；
     - **缓存与运行时零污染**：开发态和调试态的临时缓存文件（如 `.last-sub-body`、动态规则临时文件、临时日志）一律强制限制在 `tmp/` 内部生成；
     - **源码神圣不可侵犯**：源码目录与根目录除升级、维护、修复 bug 显式修改源码与必要工程配置文件外，严禁写入、衍生或残留任何垃圾文件，违者视为严重工程违规。

### U3. 可逆操作与安全备份契约 (Non-Destructive Operations & Rollback Contract) `[OPS]`
* **根因警示**：在环境整治、垃圾清理或重构瘦身时，直接使用不可逆的硬删除（如 `rm -rf` / `Remove-Item`）极其容易导致误删有用文件且无法自证与恢复。
* **执行红线 (MUST)**：
  1. **备份优先，严禁直接硬删除 (Archive Before Clean)**：
     - 在清理工作区非源码文件或大体积垃圾时，必须将所有移出文件完整保存在受 `.gitignore` 保护的 `backup/` 目录中，同时同步至外部独立目录（如 `../backup`）作为灾备镜像。
  2. **清单与脚本双闭环 (Manifest & Rollback Automation)**：
     - 每次执行备份与清理必须生成清单文档（`BACKUP_MANIFEST.md`），详尽记录每个文件的原路径、大小、时间戳与清理原因；
     - 必须配套提供开箱即用的自动化一键回滚脚本（如 `rollback.ps1` / `rollback.sh`），确保任何误清理均可在 3 秒内完全无损还原。
  3. **依赖白名单前置排查 (Preservation Whitelist)**：
     - 执行清理前必须对全仓代码进行静态扫描（检索 `//go:embed` 路径、驱动文件、配置文件等），凡被代码显式引用的文件绝对列入保护白名单，严禁过度清理。

### U4. 高可靠网络与数据面对抗工程模式 (Advanced Data-Plane & Network Defense Patterns) `[ARCH]`
* **架构模式萃取 (MUST)**：
  1. **反 DPI 包长密码学动态抖动 (Anti-DPI Cryptographic Jitter)**：
     - 传输层（QUIC/TLS）握手包长严禁硬编码固定数值（如固定 1350 会暴露极其明显的静态流量指纹）；
     - 必须通过密码学安全随机源（`crypto/rand`）引入动态随机扰动（如在 `[1280, 1380]` 区间内离散分布），既打破 DPI 静态统计特征，又严格满足 RFC 9000 规范下限（≥ 1200）。
  2. **WebRTC 两阶段原子状态机 (Two-Stage WebRTC Guard)**：
     - 防止 UDP 打洞导致物理真实 IP 泄露，必须依托原子状态机（`atomic.Bool`）实现两阶段精准门控；
     - **阶段一（未握手 / 切换中）**：网络栈直接静默丢弃发往 3478、19302、5349 端口的 UDP 报文；
     - **阶段二（会话就绪）**：仅在底层 QUIC 物理会话预热成功后方可原子置为 `true` 放行；
     - 发生网络跃点变动（Roaming/WiFi切移动网）或主动切换节点时，必须先将状态下线置 `false`，待新通道验证就绪后再原子激活。
  3. **哨兵探测专用短路与零 DNS 消耗 (Sentinel Probe & Zero-DNS Short Circuit)**：
     - 节点活跃与 RTT 探针必须基于 HTTP/3 原生轻量探活端点（`GET /healthz`）；
     - 边缘节点接收到探活端点请求时，必须在协议分发层直接专用短路：**严禁发起上游公网 DNS 解析，严禁消耗用户单 Token QPS 限速令牌**，直接返回 200 OK 及 `ok` 正文，实现端到端纯网络往返延迟的高频、零成本度量。
  4. **配置与分流规则原子落地保障 (Atomic Configuration File Sync)**：
     - 客户端或服务端在线同步分流规则（GeoData）、路由表或证书时，严禁使用直接覆写或预删除模式；
     - 必须遵循**同目录原子写入链路**：`os.CreateTemp` -> `Sync()` -> `Close()` -> `os.Rename` 覆盖替换；若底层（如 Windows 文件独占锁）报错，必须走 `.bak` 备份并包含双向自动回滚防护，杜绝断电或崩溃产生半写文件。
  5. **并发锁解耦与无睡眠可测性 (Fine-Grained Concurrency & Decoupled Reaping)**：
     - 扫描和清理闲置网络连接（如 UDP 上下文回收）时，严禁在全局互斥锁或读写锁内执行阻塞的网络套接字关闭（`conn.Close()`）；
     - 必须遵循“读锁快照收集待清理项 -> 释放锁 -> 锁外安全关闭连接”原则，套接字关闭自身必须通过 CAS（`CompareAndSwap`）保证幂等；
     - 清理逻辑必须解耦为纯函数（如 `reapIdleContexts(maxIdle)`），严禁使用 `time.Sleep` 进行单元测试同步，保证单测在微秒级内确定性执行完毕。
  6. **生命周期 Context 全链路穿透 (Context Lifecycle Penetration)**：
     - 所有守护协程、监听器接收循环（如 `ServeListener`）、流中继（`relayTCP`）必须显式接受并穿透 `ctx context.Context`；
     - 监听和阻塞操作必须与 `ctx.Done()` 绑定联动退出，杜绝孤儿协程挂死；入参若为 `nil` 必须防御性自动降级为 `context.Background()`。
  7. **生产环境强证书阻断 (Production Zero Self-Signed Cert)**：
     - 边缘节点生产模式严禁降级使用自签名 TLS 证书（防止中间人探测与审查嗅探）；自签证书逻辑仅允许在单元测试配置中显式声明开启（`AllowSelfSignedCertForTest: true`），生产启动若缺少合法证书必须硬拒绝启动。



### U5. 反假大空与真实交付铁律 (Zero-Hype & Reality-First Protocol) `[CORE]`
* **准则背景**：杜绝盲目自信与浮躁心态，禁止以局部单元测试全绿掩盖跨系统、跨网络真实运行态缺陷。
* **执行红线 (MUST)**：
  1. **绝对词汇禁令 (Banned Vocabulary)**：严禁在思考、汇报、总结、提交信息中使用“完美”、“工业级终极”、“无可挑剔”、“彻底搞定”等任何夸大、浮躁、情绪化的词汇。所有技术汇报只能陈述：输入参数、输出结果、真实网络用例、具体缺陷、修改行数。
  2. **禁止以 Mock 全绿替代真实可用 (Ban on Mock-Only Confidence)**：单元测试通过仅证明局部函数语法无崩溃，绝不等于工程在真实环境中可用。任何涉及网络传输、操作系统交互、第三方共存的功能，必须提供跨系统真实数据流闭环验证。
  3. **数据链路必须逐行 5 步穿透追踪 (Mandatory 5-Step Traceability)**：修改或审查任何配置或字段，必须严格走完完整数据链路：`生成端构造 -> 网络 JSON 序列化 -> 接收端结构体反序列化 -> 业务引擎字段提取 -> 最终系统调用`，严禁只在单个文件中确认函数存在就妄下结论。
  4. **每次执行前置审视自省 (Mandatory Pre-Execution Check)**：每次对话和每次执行前，主代理必须强制自检本条铁律，确保杜绝假大空。

### U6. 权威线缆契约与零遗漏零空值工程防线 (Wire-Contract-First & Zero-Omission Protocol) `[CORE/CI]`
* **准则背景**：汲取 Google gRPC、Tailscale、Cloudflare 工业级系统实践，消除 Go `encoding/json` 默认静默丢弃未匹配 key 和空字符零值漂移的顽疾。
* **执行红线 (MUST)**：
  1. **防线一：真实线路字节串优先测试 (Wire-Contract-First Testing)**：
     - 跨系统（客户端、边缘服务端、商业中台、桌面工作台）交互的结构体测试，严禁直接在内存中构造 Go 结构体字面量作为验证依据；
     - 必须使用真实原始 JSON 报文字符串（Raw Wire JSON）通过真实的 `Unmarshal` 流转，断言反序列化后物理 IP、跳频端口、运营商标签、鉴权凭据等关键字段非零值且类型严格匹配（如 `TestWireContract_Strict`）。
  2. **防线二：反序列化前置校验与安全归一化流水线 (Validate & Normalize Pipeline)**：
     - 任何接收外部输入或订阅数据的结构体，反序列化后必须强制立即调用 `ValidateAndNormalize()` 契约流水线；
     - 具备安全回填与防御能力：若核心物理字段（如 `IP`）缺失，自动从 `Host` 或 `Address` 提取物理 IPv4，杜绝空字符串流入运行时；若备用端口 `AltPorts` 为空，自动注入标准备用端口池 `[2083, 8443, 2087]`；发现格式非法必须直接抛错拒收，严禁将半空或残缺对象传入下游业务引擎。
  3. **防线三：跨系统双驼峰/下划线兼容与单一事实大纲 (Dual-Case Unmarshaling & Schema Alignment)**：
     - 在禁止跨包引用的物理隔离架构下，所有公用 JSON 契约结构体必须实现自定义 `UnmarshalJSON`，同时匹配 `snake_case`（如 `alt_ports`、`isp_affinity`、`line_type`）与 `camelCase`（如 `altPorts`、`ispAffinity`、`lineType`），彻底消除两端手写字段大小写漂移引发的静默丢弃。
  4. **防线四：二进制 PE 子系统与平台级交付门禁 (PE Subsystem & Binary Gate)**：
     - 针对 Windows GUI 客户端交付产物，所有 CI 编译与自动化构建脚本必须强制注入 `-ldflags="-H windowsgui -s -w"`；
     - 必须通过自动化单测（使用标准库 `debug/pe` 读取 OptionalHeader）断言 `Subsystem == 2`（`IMAGE_SUBSYSTEM_WINDOWS_GUI`），任何带有控制台黑框（Subsystem 3）的二进制产物在构建测试阶段直接熔断拦截。

### U7. 零静默吞咽与强输入校验门禁 (Zero-Silent-Failure & Strict Input Validation Gate) `[CORE/CI]`
* **准则背景**：彻底消灭由于 `_ = json.NewDecoder(r.Body).Decode(&req)` 或 `_ = json.Unmarshal` 导致畸形或空请求体被静默吞咽、底层携带空值盲目执行的高危隐患。
* **执行红线 (MUST)**：
  1. **输入反序列化必须捕获错误**：全仓 HTTP 处理函数凡涉及 JSON 解码，必须做显式 `err != nil` 校验；发生错误立即阻断并响应 `http.StatusBadRequest` (400) 及详细 JSON 错误提示，严禁进入业务逻辑。
  2. **数值类型严格防御**：跨系统时延、计数、时间戳字段必须使用有符号整数（如 `int64`），绝对严禁声明为 `uint32`，防止网络断开时返回 `-1` 导致 Go 反序列化崩溃。
  3. **显式错误链路追踪**：内部函数所有错误向上返回时必须使用 `fmt.Errorf("context: %w", err)`，保证错误链条完整，杜绝裸错误返回或直接置空。

### U8. 路由探活与健康检查双向对齐 (Bi-Directional API Routing & Healthcheck Alignment) `[CORE]`
* **准则背景**：彻底解决跨组件探活因路径细微差异（如 `/health` 与 `/healthz`）引发的 404 误判及启动假死。
* **执行红线 (MUST)**：
  1. **服务端双路由兼容**：所有后台进程（客户端守护进程、边缘节点、商业中台）必须同时挂载 `/healthz`（云原生探活标准）与 `/health`（桌面与第三方适配别名）。
  2. **调用端双向容错回退**：桌面工作台或健康探测器发起探活时，优先请求 `/healthz`，若遇异常自动回退探测 `/health`，杜绝单点路径阻断。

### U9. 跨 VPN/TUN 冲突物理隔离与真实网卡回退 (Cross-VPN Anti-Conflict & Physical Egress) `[CORE]`
* **准则背景**：解决多代理（如用户同时开启 Clash TUN 模式）并存时的网络路由抢占、DNS 污染与回环死锁灾难。
* **执行红线 (MUST)**：
  1. **宿主 DNS 策略隔离 (NRPT)**：Windows 平台绝对禁止直接篡改宿主物理网卡的系统 DNS，统一采用带有专属标识（`AERO_aero0`）的 Windows NRPT 专用策略；客户端退出时精准清理，不干扰其他 TUN 软件。
  2. **底层探活与订阅拉取物理逃逸**：客户端向中台拉取订阅或进行边缘节点探活时，拨号器必须绑定宿主机物理网卡真实出站 IP/接口，跳过虚拟 TUN 回环，确保在任何第三方 VPN 开启时均能正常拉取订阅和测速。

### U10. 生产级单写者架构与无锁资源回收 (Single-Writer SQLite & Lock-Free Reaping) `[CORE]`
* **准则背景**：彻底消除高并发写导致的 `database is locked (5)` 崩溃及锁内关闭套接字引发的死锁。
* **执行红线 (MUST)**：
  1. **SQLite 单写者连接池固化**：所有单机 Pure-Go SQLite 数据库启动时必须显式调用 `db.SetMaxOpenConns(1)`。
  2. **连接回收无锁解耦**：清理闲置网络会话（如 UDP 上下文、过期 Session）必须严格遵循“读锁快照收集 -> 释放锁 -> 锁外安全异步关闭”的标准流水线，严禁在临界区内执行阻塞式 I/O。

### U11. 遗漏字段、空值、隐藏边界与盲区深层防范机制 (Deep Defense against Missing Fields, Nil/Zero Values & Boundary Blindspots) `[CORE/CI]`
* **准则背景**：系统性攻克“序列化未知字段静默丢弃”、“必填字段与零值二义性混淆”、“命名风格漂移致空”、“孤儿协程泄漏死锁”以及“宿主网络状态残留”五大深水区盲疾，实现全链路纵深防御。
* **执行红线 (MUST)**：
  1. **未知字段严苛拦截 (DisallowUnknownFields Gate)**：
     - 在关键内部管控接口（如 `/admin/subs`、`/admin/metering` 等）的反序列化逻辑中，显式启用 `decoder.DisallowUnknownFields()`；
     - 凡出现任何拼写笔误（如 `alt_port` 漏写 `s`）或冗余非法 key，必须直接阻断并返回 HTTP 400，杜绝配置静默失效。
  2. **必填不变量断言与指针可空区分 (Required Invariants & Pointer-Nullable Distinction)**：
     - 凡跨进程或跨子系统 DTO，必须在 `ValidateAndNormalize()` 中对必填字段进行硬性校验（如 `Token == ""`、`Address == ""` 直接抛错）；
     - 可选布尔或数值字段一律采用指针（`*bool`、`*int64`）声明，彻底区分“未传递该字段 (nil)”与“显式传递零值 (false / 0)”，消灭零值二义性。
  3. **双向回转与双命名风格自愈 (Round-Trip Wire Contract & Dual-Case Unmarshaling)**：
     - 跨系统公共结构体必须实现自定义 `UnmarshalJSON`，同时匹配 `snake_case` 与 `camelCase`；
     - 单元测试严禁依赖内存结构体字面量，必须以真实原始 JSON 报文字符流执行 `Unmarshal -> ValidateAndNormalize -> 行为断言 -> Re-marshal -> 对比` 闭环。
  4. **协程生命周期闭环与滑动超时看门狗 (Goroutine Lifecycle & Sliding Deadline Hygiene)**：
     - 启动任何 Goroutine 之前，必须在代码中明确其退出触发条件；
     - 数据流读写协程必须受 `ctx.Done()` 或滑动 `SetDeadline`（UDP 45 秒、STUN 15 秒）看门狗保护，超时主动关闭连接解除阻塞；
     - 后台常驻任务必须经由 `safeGo` 包装，内置 `recover()` 隔离 panic；排空会话队列限制最大深度（`maxDrainingSessions = 2`），防止快速切线堆积泄露。
  5. **宿主网络状态零残留与独立守护进程 (Host State Zero-Leak & Guard Watchdog)**：
     - Windows 客户端编译固化 `-ldflags="-H windowsgui -s -w"` 并由 CI 通过标准库 `debug/pe` 机器断言 `Subsystem == 2`，从物理上杜绝控制台 CMD 窗口弹出；
     - 独立看门狗守护进程（`guard.exe`）以客户端 PID 为锚点进行操作系统级监听，无论客户端正常退出或被系统强杀，均自动执行精准清理专属标识（`AERO_aero0`）的 NRPT 策略与路由，彻底保障宿主网络自愈。

### U12. 零本地宿主订阅与标准 443 协议发布死线 (Zero-Localhost Subscription & Standard 443 HTTPS Mandate) `[CORE/DELIVERY]`
* **准则背景**：彻底杜绝 AI 助手与开发人员混淆“本地管理平面”与“线上订阅分发平面”，坚决消灭将本地宿主机端口（如 `:18080`、`:8080`）当作订阅链接向外暴露的严重违规行为。
* **执行红线 (MUST)**：
  1. **本地商业中台定位绝对锁死**：本地启动的商业中台（`127.0.0.1:18080` / `localhost:18080`）严格仅作为运维管理面板（Dashboard）与本地服务编排器，只提供后台管理、健康检查（`/healthz`）与内部 API 处理，自身绝非用户消费订阅的端点。
  2. **严禁输出本地带端口订阅**：任何 AI 助手在思考、汇报、提示信息、文档或代码输出中，**绝对严禁输出任何形如 `http://localhost:18080/sub/...`、`http://127.0.0.1:18080/sub/...` 或带有任何非 443 端口的订阅链接！** 违者直接判定为最高严重度工程违规。
  3. **标准 443 唯一合法性**：生产与测试订阅链接必须且只能通过已配置有效证书的公网标准 443 HTTPS 域名进行下发（`https://<domain>/sub/superadmin` 或 `https://<domain>/sub/<username><6位随机码>`）。
  4. **前置回复自查过滤**：在每次向用户输出测试地址或接口列表时，必须前置过滤，严禁把中台本地地址与订阅链接拼装在一起；若要提供订阅测试指南，必须明确指引用户通过生产绑定的公网标准 HTTPS 443 域名进行测试。

