# AERO 项目研发与执行准则 (PROJECT_RULES.md)

> **Version**: 2.1.0-unified (Aligned with GLOBAL MASTER RULES v1.0.0 & newplan.md)  
> **Last-Updated**: 2026-09-30  
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
  3. **订阅发布契约**：中台向用户和节点颁发原生 `aero/2.0` 标准 JSON 订阅。客户端单向通过标准 HTTPS 443 接口拉取并解析。
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
- 严禁在订阅链接中携带 `:18080`、`:8080` 等非标端口；必须通过标准 443 HTTPS 域名发布；
- 严禁生成或兼容任何第三方异构代理订阅（Clash、v2rayN、sing-box 等）。

### O4. 生产独立交付与自动化脚本 (Independent Deployment & Scripts) `[REVIEW]`
- 客户端与边缘节点支持完全独立发布，不依赖中台与工作台；
- 边缘安装脚本（`deploy/edge-install.sh`）闭合 iptables 语法（补齐 `fi`）；
- 所有二进制产物由标准 `go build` 原生编译生成。
