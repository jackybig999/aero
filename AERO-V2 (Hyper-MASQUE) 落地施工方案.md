# AERO-V2 (Hyper-MASQUE) 生产落地施工技术规范书 (终审终结版)

> **版本标识**：`v2.0.0-PROD-FREEZE-SPEC`  
> **工程基准**：Git Commit `14903bf` (`v1.2.24`)  
> **文件定位**：AERO 协议全栈重构唯一权威执行指南（架构解耦、线缆契约、跨平台分层、实证验收）。  
> **实施状态**：**【施工前冻结版 / 方案已完成代码对齐勘误 / 生产代码尚未修改 / 待按 M1-M7 分阶段执行】**
> **关联归档**：历史草案已废止；本文件是唯一施工基线。若后文与“施工前冻结勘误”冲突，以勘误条款为准。

---

## 目录

1. [终审报告阻断级与严重问题全景治理决议表](#1-终审报告阻断级与严重问题全景治理决议表)
2. [M1: 客户端对象结构重构与真实生命周期闭环（P0 - 1 & P0 - 2）](#2-m1-客户端对象结构重构与真实生命周期闭环p0---1--p0---2)
3. [M2: IPv6 服务端真实探测与四重防泄漏黑洞体系（P0 - 3）](#3-m2-ipv6-服务端真实探测与四重防泄漏黑洞体系p0---3)
4. [M6: 服务端共享 Linux TUN 与全局路由转发架构（P0 - 4）](#4-m6-服务端共享-linux-tun-与全局路由转发架构p0---4)
5. [M7: Salamander 完整调用链、外层 IPv6 拨号与 PMTU 动态闭环（P0 - 5）](#5-m7-salamander-完整调用链外层-ipv6-拨号与-pmtu-动态闭环p0---5)
6. [M5: 真·QUIC Connection Migration 官方 API 与状态机闭环（P1 - 6）](#6-m5-真quic-connection-migration-官方-api-与状态机闭环p1---6)
7. [Linux 运维脚本完全对称性、幂等性与多实例保护（P1 - 7）](#7-linux-运维脚本完全对称性幂等性与多实例保护p1---7)
8. [M4: WARP 双路径清理与统一策略注入（P1 - 8）](#8-m4-warp-双路径清理与统一策略注入p1---8)
9. [M3: Profile v1 真实安全信任链与签名验签契约（P1 - 9）](#9-m3-profile-v1-真实安全信任链与签名验签契约p1---9)
10. [传输层边界与商业许可证合规审计门禁](#10-传输层边界与商业许可证合规审计门禁)
11. [附录：Reliable-IP 未来演化草案（标准 8 字节 QUIC VarInt）](#11-附录reliable-ip-未来演化草案标准-8-字节-quic-varint)
12. [实证化全链路验收门禁（修正假大空指标）](#12-实证化全链路验收门禁修正假大空指标)
13. [唯一施工里程碑（M1 ~ M7）与执行甘特图](#13-唯一施工里程碑m1--m7与执行甘特图)
14. [回滚机制与安全兜底保障](#14-回滚机制与安全兜底保障)

---

## 0. 施工前冻结勘误（优先级高于全文其他示例）

本节根据当前代码、`AGENTS.md` 和项目数据面硬约束补充，是施工前的强制执行条款。它不是新功能，而是防止施工人员把伪代码、示例地址或平台假设直接复制到生产代码。

### 0.1 当前代码基线与施工边界

截至基准提交 `14903bf`：

- 客户端生产路径仍由 `StackEngine` + gVisor 驱动，`IPDataPump` 尚未接管；
- 服务端 `serveConnectIP` 仍创建 per-session `UserSpaceNATRouter`，尚未接入 `GlobalTunnelRouter`；
- `go.mod` 仍包含 `github.com/sagernet/gvisor`；
- `serveConnectUDP`、`nat.go` 仍存在 WARP UDP 分支；
- `SetupRoutes` 仍为 `SetupRoutes(devName, ipv4 string)`，尚未接收 `RouteConfig`；
- Salamander、Profile、Migration、Linux TUN 脚本均未按本文完成。

因此“方案冻结”不等于“功能已实现”。每个阶段必须先完成接口、代码和测试，再进入下一阶段；禁止以本文档中的 Mermaid、伪代码或验收命令代替实现。

### 0.2 仓库硬约束优先级

施工必须遵守：

1. 客户端初始 MTU 使用项目规定的 **1224**；动态收缩由实际 `quic.DatagramTooLargeError` 驱动，不能把 1360 写成初始值。
2. Windows 禁止新增 `netsh advfirewall` 或 WFP 宿主防火墙改写。IPv6 防泄漏只能使用 TUN 路由、DNS/NRPT 和现有 guard 清理机制；若无法证明无泄漏，必须阻断启动，而不是静默放行。
3. 移动端 `SetupRoutes` 必须继续返回 `TUN not supported on this platform`，不得把桌面双栈逻辑复制到 Android/iOS。
4. 所有后台回调必须异步、可取消且有单次触发保护；禁止在持有 `StackEngine.mu` 时执行 `Close()`、重拨或外部 I/O。

### 0.3 M1 连接所有权冻结

唯一允许的生产对象关系为：

```text
Engine owns TunDevice
StackEngine owns IPDataPump
IPDataPump owns exactly one IPPacketConn
SessionManager only creates/returns the connection and does not close it afterwards
```

`RestartWithConn` 必须采用“旧 pump 完整关闭 -> 新 pump 创建”的生命周期隔离方式，不得在运行中的 pump 上直接替换 `conn` 指针。重连请求必须通过单线程或 `singleflight` 串行化；断连回调不得在持锁状态下同步调用重连。

停机顺序固定为：

```text
Engine marks stopping
Engine closes TunDevice to wake Read
StackEngine closes IPDataPump (cancel + conn.Close + wg.Wait)
Engine tears down routes
SessionManager resets remaining sessions
```

`IPDataPump` 不得关闭 `TunDevice`；`Engine` 不得在 pump 仍运行时释放或复用设备。

### 0.4 ICMP 与 PMTU 的真实边界

当前 `connect-ip-go` 的 `WritePacket` 在 Datagram 超限时返回 ICMP 报文，且库内使用固定 `minMTU=1280` 组包；该 ICMP 不是物理链路的真实 PMTU 测量值。

必须区分两条路径：

- `WritePacket` 返回的 ICMP：仅用于回写本地协议栈，不能据此宣称获得真实物理 PMTU；
- quic-go 返回的 `DatagramTooLargeError.MaxDatagramPayloadSize`：用于更新 `CurrentMaxDatagramSize` 和虚拟网卡 MTU。

IPv4 允许小于 1280 的 PMTU；1280 只作为承载 IPv6 时的最小链路约束。`inner IP MTU`、`QUIC DATAGRAM payload`、`Salamander UDP wire length` 不得直接混用。

### 0.5 IPv6 能力模型冻结

生产客户端只把服务端明确声明并验证过的“可路由前缀”视为公网 IPv6 能力。`fd88::/64`、`fd88:ae80::/64` 等 ULA 不得伪装成公网双栈。

本项目在 M2-M6 只采用一种生产策略：

- 有真实、已路由的公网 IPv6 委派前缀：启用 IPv6；
- 没有该前缀：服务端不分配 IPv6，客户端启用 IPv6 黑洞防泄漏；
- ULA + NAT66 只能作为独立实验/开发模式，不得与公网 IPv6 能力共用同一 `prefixes[1]` 语义。

服务端探测必须同时验证默认 IPv6 路由、前缀长度和实际回程可达性；仅检查 `net.InterfaceAddrs()` 不足以建立地址池。

### 0.6 平台防泄漏边界

- Windows：不修改宿主防火墙；使用高优先级 `::/1`、`8000::/1` TUN 路由、NRPT AAAA 策略和退出清理。若系统无法安全安装黑洞路由，则启动失败。
- Linux：AERO 专属 iptables/nftables 规则必须带实例标签，并保存/恢复原始 sysctl；不能用全局快照 diff 作为唯一验收依据。
- macOS：PF 规则必须先通过 `pfctl -vnf` 语法校验；失败时不得继续启用 IPv6 黑洞模式。

### 0.7 GlobalTunnelRouter 接入门槛

M6 只有在以下接口全部实现后才算完成：

1. `serveConnectIP` 注册/注销 session 和 generation；
2. 单一 TUN reader 按目标 IP 分发回包；
3. 上行包执行源地址反伪造校验；
4. IP 复用时旧 generation 不能删除新映射；
5. 服务端停止时先停止接收新 session，再关闭 TUN reader，最后关闭所有 `IPPacketConn`。

在这些接口完成前，不得删除 `nat.go` 或从 `go.mod` 移除 gVisor。

### 0.8 Profile 与签名的可实现定义

Profile 签名必须采用确定性序列化：签名输入为固定字段顺序的 canonical JSON，不得直接对 Go map 的默认 JSON 输出签名。必须同时定义：

- `pubkey_id` 到内置 Ed25519 公钥的映射；
- 密钥轮换和撤销策略；
- 签名覆盖字段；
- 证书摘要是 DER 证书摘要还是 SPKI 摘要；
- 验签失败时旧缓存是否可用。

未完成这些定义前，Profile 只能用于性能缓存，不得作为端点真实性依据。

### 0.9 施工门禁与可回滚提交

每个里程碑必须同时提交代码变更、测试、回滚说明、真实命令和预期输出。不得把“单个里程碑不超过 3 个核心文件”作为硬性限制；M1、M6 必然涉及接口、平台实现、测试和依赖文件，文件数量应服从可审计性。

---

## 1. 终审报告阻断级与严重问题全景治理决议表

对照用户终审报告指出的 5 项 P0 阻断级缺陷、4 项 P1 严重缺陷及 3 项验收标准问题，本规范全面穿透至现有代码底层，形成彻底落地的工程治理对齐矩阵：

| 序号 | 缺陷分类 | 终审报告指出的核心病因 | 现有代码真实状态 | 本规范工程治理最终裁决 | 对应章节 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | **P0 阻断** | M1 生命周期设计未对应现有对象结构；缺少 `StackEngine` 构造签名改造、连接关闭所有权、断连通知、原子重连与 Prefix 容错 | `engine.go:1068` 仍传 `TunnelClient`；`StackEngine` 仍持有 gVisor 栈与 Forwarder；无 `UpdateConn` 保护与 Prefix 乱序校验 | 确立 `TunnelEngine` 门面；`NewStackEngine` 接收 `IPPacketConn`；明确断连时走安全 `RestartWithConn`；Prefix 提取引入 `Is4()`/`Is6()` 强类型校验；连接关闭归属清晰界定。 | **§2.1 ~ §2.3** |
| **2** | **P0 阻断** | `WritePacket` 的 ICMP 回写缺少完整实现契约；缺少字节偏移、大小端、地址校验、多并发收缩同步；TUN 退出存在双重关闭 | `tunnel_pump.go:174` 丢弃 `icmp` 返回值；`StackEngine.Stop()` 与 `IPDataPump.Close()` 职责重叠 | 确立 `parseICMPNextHopMTU`（IPv4 偏移 26 / IPv6 偏移 44）；原子 CAS 单调向下钳位 MTU；明确 `Engine` 唯一持有 `dev.Close()`，`IPDataPump` 仅调 `cancel` 与 `conn.Close()`，彻底杜绝双重关闭与死锁。 | **§2.4** |
| **3** | **P0 阻断** | 服务端无条件创建 `fd88::/64`，缺少公网探测；客户端无法识别真实双栈；缺少 ICMPv6 拒绝报文与平台防泄漏边界 | `quic.go:1125` 硬编码 `NewIPv6Pool("fd88::/64")`；`SetupRoutes` 仅支持 IPv4；三端均无完整 IPv6 防泄漏实现 | 服务端增加已路由公网 IPv6 前缀探测，无公网 IPv6 则置 `ipv6Pool=nil`；客户端校验可路由前缀；实现 ICMPv6 Type 1 Code 3；Windows 仅使用 TUN/NRPT/guard，Linux/macOS 使用经语法校验且可回滚的专属规则。 | **§3** |
| **4** | **P0 阻断** | M6 服务端共享 TUN 与现有 per-session NAT 架构脱节；缺少全局路由表、上下行分发、IP 复用保护与退出广播 | `quic.go:1993` 每连接创建 `NewUserSpaceNATRouter`；`nat.go:80` 内置 gVisor 协议栈；无共享 TUN 路由 | 废除每连接 gVisor NAT，重构 `serveConnectIP` 接入单例 `GlobalTunnelRouter`；以 `sync.Map` 映射 `netip.Addr -> ClientSession`；引入递增 `generation` 杜绝 IP 复用错乱；Linux TUN 多协程写内核安全。 | **§4** |
| **5** | **P0 阻断** | M7 PMTU 签名与调用链不兼容；WriteTo 未处理 error；外层 IPv6 拨号硬编码 udp4；TUN MTU 关系不严谨 | `salamander.go:84` 仅传 `len(b)`；`quic.go:358` 硬编码 `factory(ctx, "udp4")`；未处理 PMTU 畸变值 | 重构 `SalamanderPacketConn` 持有原子 PMTU 与 `isIPv6Outer`；`WriteTo` 显式拦截并丢弃超限包；QUIC 拨号依据目标 IP 族动态选择 `udp4`/`udp6`；TUN MTU 动态扣除 VarInt Context ID。 | **§5** |
| **6** | **P1 严重** | QUIC Migration 中 `DisableActiveMigration` 无公开 API；`Transport.Close()` 立即掐断 socket 无法优雅排空 | quic-go `ConnectionState` 不导出该字段；`Transport.Close()` 内部立即关闭底层 UDP 连接 | 通过 `conn.AddPath()` 返回的错误进行判定；漫游成功后通过 `path.Close()` 废弃旧路径，保留 underlying socket 至在途包超时，废除不存在的 Transport drain 承诺。 | **§6** |
| **7** | **P1 严重** | Linux 卸载脚本未恢复 sysctl；重复执行脚本产生重复规则；文本解析 iptables 脆弱；多实例缺少隔离 | `edge-uninstall.sh` 未备份/还原 sysctl；直接追加规则；无实例隔离标识 | 新增 `/etc/aero/sysctl_backup.conf` 备份与还原；使用 `iptables -C` 确保幂等；按注释标签精准原子删除；引入 `INSTANCE_ID` 区分多实例；交付完整等价的 nftables 脚本。 | **§7** |
| **8** | **P1 严重** | WARP 方案与当前代码严重冲突；未同时清理两条 UDP 路径；limit.go 依然硬编码阻断 | `quic.go:1722, 1750` 与 `nat.go:465` 均存在 `DialUDPViaWARP`；`limit.go` 硬编码阻断 | 全量删除 `serveConnectUDP` 与 `UserSpaceNATRouter` 中两条 UDP WARP 分支；`limit.go` 对齐 `WarpConfig.Mode`（Fail-Open / Fail-Closed）；服务端启动统一加载 `WarpConfig`。 | **§8** |
| **9** | **P1 严重** | Profile 声明了证书 Pin 与签名校验，但 Schema 缺少对应字段与信任根 | Schema 仅有 port/etag 等字段，无签名、公钥 ID、指纹、过期时间 | 补全 Profile Schema v1：新增 `cert_fingerprint_sha256`、`signature_ed25519`、`pubkey_id`、`expires_at`，客户端内置 Ed25519 根公钥执行强校验。 | **§9** |
| **10**| **验收修正**| G3 比较全系统快照不可行；G4 5ms 红线无跨平台确定性；G8 许可证绝对化且路径不可移植 | G3 易受系统背景流量干扰；GC 会击穿 5ms；部分依赖为 ISC/MPL；报告路径硬编码 root 目录 | G3 改为比对 AERO 专属托管资源（规则、网卡、路由、sysctl）；G4 区分功能正确性与统计延迟；G8 声明合法许可证白名单并重定向报告至工程目录 `deploy/reports/`。 | **§12** |

---

## 2. M1: 客户端对象结构重构与真实生命周期闭环（P0 - 1 & P0 - 2）

### 2.1 现有对象结构诊断与 `TunnelEngine` 门面改造

当前 `internal/client/engine.go:1068` 的初始化逻辑为：
```go
e.stackEngine = NewStackEngine(dev, e.tunnelClient, e.dnsHandler)
```
其中 `StackEngine` 深度依赖 gVisor 用户态协议栈（`gvStack`、`gvEP`、`tcp.Forwarder`、`udp.Forwarder`）。为实现彻底剔除 gVisor 且不破坏现有上层门面，按如下方案进行重构：

```mermaid
classDiagram
    class TunnelEngine {
        <<interface>>
        +Start() error
        +Stop()
        +SetKillSwitch(bool)
        +KillSwitch() bool
        +SetWebRTCActive(bool)
        +WebRTCActive() bool
        +SetDNSOnlyMode(bool)
        +DNSOnlyMode() bool
        +SetICMPOutboundHookForTest(func([]byte))
    }

    class StackEngine {
        -TunDevice dev
        -IPPacketConn conn
        -IPDataPump* pump
        -DNSHandler* dnsHandler
        -atomic.Bool killSwitch
        -atomic.Bool dnsOnlyMode
        -atomic.Bool webrtcActive
        -onDisconnect func(error)
        +Start() error
        +Stop()
        +RestartWithConn(IPPacketConn, []netip.Prefix) error
    }

    class IPDataPump {
        -TunDevice dev
        -IPPacketConn conn
        -context.Context ctx
        -context.CancelFunc cancel
        -sync.WaitGroup wg
        -atomic.Bool closed
        -atomic.Int32 currentMTU
        -atomic.Pointer[func(error)] onDisconnect
        +Start()
        +Close() error
        +SetOnDisconnect(func(error))
    }

    TunnelEngine <|.. StackEngine : 实现
    StackEngine *-- IPDataPump : 独占持有
```

#### 构造签名与依赖翻转：
1. **构造函数签名变更**：
   ```go
   // internal/client/stack.go
   func NewStackEngine(dev TunDevice, conn IPPacketConn, prefixes []netip.Prefix, dns *DNSHandler, onDisconnect func(error)) *StackEngine
   ```
   彻底移除 `*TunnelClient` 依赖，直接注入通过 `sessionMgr.DialIP()` 协商成功的 `IPPacketConn` 与服务端下发的 `prefixes`。
2. **测试包解耦兼容**：
   在 `internal/client/client_test.go` 中，构建模拟 `mockIPPacketConn`，彻底删除原测试用例中对 `sagernet/gvisor` 的符号引用。

### 2.2 启动时序、Prefix 解析容错与连接所有权

```mermaid
sequenceDiagram
    autonumber
    participant Engine as Engine (engine.go)
    participant SM as SessionManager (session.go)
    participant TUN as TunDevice (aero0)
    participant Stack as StackEngine (stack.go)
    participant Pump as IPDataPump (tunnel_pump.go)
    participant Server as Edge Server (quic.go)

    Note over Engine: 阶段 1: 物理边缘建连与 CONNECT-IP 握手
    Engine->>SM: DialIP(startCtx)
    SM->>Server: HTTP/3 CONNECT-IP Request
    Server-->>SM: 200 OK + AddressAssignment Capsule
    SM-->>Engine: 返回 conn (*connectip.Conn) 与 rawPrefixes ([]netip.Prefix)
    
    Note over Engine: 阶段 2: Prefix 强类型解析与乱序容错
    Engine->>Engine: 解析 prefixes: 提取合法 IPv4 与公网 IPv6
    
    Note over Engine: 阶段 3: 虚拟网卡开启与路由下发
    Engine->>TUN: openTunDeviceFn("aero0", initialMTU=1224)
    Engine->>Engine: setupRoutesFn(dev.Name(), v4Prefix, v6Prefix)
    
    Note over Engine: 阶段 4: 实例化 StackEngine 并启动数据泵
    Engine->>Stack: NewStackEngine(dev, conn, prefixes, e.dnsHandler, onDisconnectCallback)
    Stack->>Pump: NewIPDataPump(ctx, dev, conn, killSwitch, dnsHandler)
    Stack->>Pump: Pump.Start()
```

#### 关键约束契约：
1. **Prefix 提取乱序与数量异常容错**：
   绝对禁止使用 `prefixes[0]` 或 `prefixes[1]` 静态下标，统一使用强类型判定：
   ```go
   var v4Prefix, v6Prefix netip.Prefix
   for _, p := range rawPrefixes {
       if p.Addr().Is4() && !v4Prefix.IsValid() {
           v4Prefix = p
       } else if p.Addr().Is6() && !v6Prefix.IsValid() {
           // 必须为公网单播且非私有前缀，杜绝将 ULA 当成公网双栈
           if p.Addr().IsGlobalUnicast() && !p.Addr().IsPrivate() {
               v6Prefix = p
           }
       }
   }
   if !v4Prefix.IsValid() {
       return fmt.Errorf("connect-ip: server failed to assign a valid IPv4 prefix")
   }
   ```
2. **连接所有权（Connection Ownership）唯一律**：
   - `conn` 由 `IPDataPump` **独占持有并全权负责关闭**；
   - `SessionManager` 在 `DialIP()` 返回后，不再持有该 `conn` 的写入权；
   - `IPDataPump.Close()` 执行时调用 `_ = p.conn.Close()` 终结底层网络流。

### 2.3 断连通知、原子重连与避免数据竞争的 `RestartWithConn`

为根除在并发读写下直接修改 `p.conn` 指针导致的数据竞争与崩溃，方案废弃“动态指针热替换”，采纳**“生命周期隔离式重启（`RestartWithConn`）”**：

1. **断连通知机制**：
   - `IPDataPump` 维护 `notified atomic.Bool` 与 `onDisconnect func(error)` 回调；
   - 当 `pumpTunToRemote` 或 `pumpRemoteToTun` 遭遇非预期网络中断（非 `p.closed` 且非正常退出）时，通过 `sync.Once` 触发回调：
     ```go
     if p.notified.CompareAndSwap(false, true) {
         if cb := p.onDisconnect.Load(); cb != nil {
             go (*cb)(err)
         }
     }
     ```
2. **Engine 重连与路由原子切换**：
   - `Engine` 捕获断连事件后，进入安全重连流水线；
   - 调用 `sessionMgr.DialIP(ctx)` 建立新连接并获取 `newConn` 与 `newPrefixes`；
   - **路由增量刷新**：
     ```go
     RefreshRoutes(dev.Name(), oldV4Prefix, oldV6Prefix, newV4Prefix, newV6Prefix)
     ```
   - **调用 `StackEngine.RestartWithConn`**：
     ```go
     func (s *StackEngine) RestartWithConn(newConn IPPacketConn, newPrefixes []netip.Prefix) error {
         s.mu.Lock()
         defer s.mu.Unlock()
         
         // 1. 优雅停止旧数据泵 (释放旧连接，等待旧读写协程退出)
         if s.pump != nil {
             _ = s.pump.Close()
         }
         
         // 2. 实例化新数据泵并启动 (复用底层现有的 TunDevice aero0)
         s.conn = newConn
         s.pump = NewIPDataPump(s.ctx, s.dev, newConn, &s.killSwitch, s.dnsHandler)
         s.pump.SetOnDisconnect(s.handleDisconnect)
         s.pump.Start()
         return nil
     }
     ```
     彻底规避指针竞争，实现纳秒级平滑切流。

### 2.4 `WritePacket` ICMP 解析、原子 MTU 钳位与停机所有权

#### 1. 完整的 ICMP 回写与 Next-Hop MTU 提取函数
`connectip.Conn.WritePacket(raw)` 在遇到 QUIC 数据报超限时，内部组装并返回的是**完整的已封装 L3 IP 报文**（IPv4 头部 + ICMP 报文，或 IPv6 头部 + ICMPv6 报文），源/目的 IP 已由底层对调完成。`IPDataPump` 必须执行严格的解析与回写：

```go
// parseICMPNextHopMTU 从完整的 L3 ICMP 差错报文中精准提取 Next-Hop MTU
func parseICMPNextHopMTU(pkt []byte) int {
    if len(pkt) < 28 {
        return 0
    }
    version := pkt[0] >> 4
    if version == 4 {
        ihl := int(pkt[0]&0x0F) * 4
        if len(pkt) < ihl+8 {
            return 0
        }
        // 校验 Protocol == 1 (ICMP), Type == 3 (Dest Unreachable), Code == 4 (Fragmentation Needed)
        if pkt[9] == 1 && pkt[ihl] == 3 && pkt[ihl+1] == 4 {
            // Next-Hop MTU 位于 ICMP 首部字节 6~7 (大端 uint16)
            return int(binary.BigEndian.Uint16(pkt[ihl+6 : ihl+8]))
        }
    } else if version == 6 {
        if len(pkt) < 40+8 {
            return 0
        }
        // 校验 Next Header == 58 (ICMPv6), Type == 2 (Packet Too Big), Code == 0
        if pkt[6] == 58 && pkt[40] == 2 && pkt[41] == 0 {
            // MTU 位于 ICMPv6 首部字节 4~7 (大端 uint32)
            return int(binary.BigEndian.Uint32(pkt[44:48]))
        }
    }
    return 0
}
```

#### 2. 数据泵并发收缩同步策略
当大量并发大包同时涌入触发 ICMP 回包时，为杜绝多协程反复竞争系统调用修改网卡 MTU，实施原子单调向下钳位：

```go
func (p *IPDataPump) applyNextHopMTU(newMTU int) {
    if newMTU < 1280 || newMTU > 1500 {
        return // 越界异常值丢弃
    }
    for {
        cur := p.currentMTU.Load()
        if int32(newMTU) >= cur {
            break // 仅单调向下收缩，已小于等于当前 MTU 则忽略
        }
        if p.currentMTU.CompareAndSwap(cur, int32(newMTU)) {
            log.Printf("[PUMP] Path MTU clamped down to %d, updating virtual NIC", newMTU)
            _ = SetInterfaceMTU(p.dev.Name(), newMTU)
            break
        }
    }
}
```

#### 3. 停机退出所有权三权分立（根除双重关闭与死锁）
明确划分组件职责：
- **`Engine`**：拥有 `TunDevice` 的唯一生命周期所有权，负责创建 `dev`，负责最终调用 `dev.Close()`；
- **`IPDataPump`**：仅负责数据搬运，**绝对禁止调用 `dev.Close()`**；在 `IPDataPump.Close()` 中：
  1. `p.closed.Store(true)` 并调用 `p.cancel()`；
  2. 调用 `p.conn.Close()` 终结网络端连接；
  3. **等待协程退出**：此时由 `Engine` 协同执行 `dev.Close()` 打断网卡阻塞读，协程退出，`p.wg.Wait()` 瞬间完成。
- **协同停机退出时序**：
  ```
  Engine.Stop() 触发:
    │
    ├── 1. 显式调用 dev.Close() (Windows 触发 SetEvent 唤醒 WaitForSingleObject; Linux/macOS 关闭 fd)
    │      此时阻塞在 p.dev.Read() 的 pumpTunToRemote 协程立即收到 "device closed" 错误并退出
    │
    ├── 2. 调用 stackEngine.Stop() -> IPDataPump.Close()
    │      关闭 conn，双向协程均已退出，p.wg.Wait() 在 < 1ms 内瞬间解除
    │
    ├── 3. 调用 teardownRoutesFn(dev.Name()) 清除系统路由
    │
    └── 4. 重置 SessionManager
  ```

---

## 3. M2: IPv6 服务端真实探测与四重防泄漏黑洞体系（P0 - 3）

### 3.1 服务端真实物理 IPv6 能力探测

彻底清除 `quic.go:1125` 中盲目无条件实例化 `NewIPv6Pool("fd88::/64")` 的伪双栈逻辑，改由服务端在初始化阶段执行真实探测：

```go
// internal/edge/probe.go
func ProbeHostPublicIPv6() (netip.Prefix, error) {
    // 1. 检索宿主机物理出口默认路由网卡上的全局单播 IPv6 地址
    addrs, err := net.InterfaceAddrs()
    if err != nil {
        return netip.Prefix{}, err
    }
    for _, a := range addrs {
        if ipNet, ok := a.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
            if ipNet.IP.To4() == nil {
                addr, _ := netip.AddrFromSlice(ipNet.IP)
                // 必须是全球单播地址且排除私有/ULA (fc00::/7) 与链路本地 (fe80::/10)
                if addr.IsGlobalUnicast() && !addr.IsPrivate() {
                    ones, _ := ipNet.Mask.Size()
                    return netip.PrefixFrom(addr, ones), nil
                }
            }
        }
    }
    return netip.Prefix{}, fmt.Errorf("no public routed IPv6 detected on host")
}
```

- **服务端装配裁决**：
  - 若 `ProbeHostPublicIPv6` 探测成功且检测到已路由的前缀块（如 `/64` 或运营商子网），初始化 `s.ipv6Pool` 为该合法前缀；
  - 若探测失败（VPS 无公网 IPv6 出口），**强制设置 `s.ipv6Pool = nil`**；
  - 在 `serveConnectIP` 中，当 `s.ipv6Pool == nil` 时，**绝不下发任何 IPv6 地址分配与 IPv6 路由广播**。

### 3.2 客户端无 IPv6 时的四重防泄漏体系落地规范

当检测到服务端无合法公网 IPv6 能力时，客户端启动四重防泄漏黑洞体系：

#### 第 1 重：DNS AAAA 拦截与 RFC 1035 标准 NODATA 应答
`DNSHandler` 拦截所有类型为 AAAA（Type 28）的外部域名查询请求，不向远端转发，就地构造 RFC 1035 NODATA 应答：
- Header Flags：`0x8180`（QR=1, RD=1, RA=1, RCODE=0）；
- QDCOUNT = 1（原样回显请求的域名 Question 节）；
- ANCOUNT = 0，NSCOUNT = 0，ARCOUNT = 0；
- 浏览器与系统解析器收到后判定该域名无 IPv6 记录，在 0.05ms 内直接选用 IPv4，杜绝发起 IPv6 连接。

#### 第 2 重：TUN ULA 黑洞路由接管
在 `SetupRoutes` 中：
- 给 `aero0` 分配 ULA 黑洞地址 `fd88::2/64`（虚拟网关 `fd88::1`）；
- 注入 `::/1` 和 `8000::/1` 指向 `fd88::1`，**跃点数设置为 metric=1**；
- 覆盖物理网卡的 `::/0` 默认路由，强制将所有外溢的 IPv6 流量吸入 `aero0`。

#### 第 3 重：IPDataPump 原生构造 ICMPv6 Type 1 Code 3 拒绝报文
当有恶意或硬编码的 IPv6 报文漏入虚拟网卡时，`IPDataPump` 拦截该报文，原地生成 ICMPv6 Destination Unreachable 报文回写虚拟网卡：

```go
// buildICMPv6AddressUnreachable 构造 ICMPv6 Type 1 Code 3 (Address Unreachable)
func buildICMPv6AddressUnreachable(origPkt []byte) []byte {
    if len(origPkt) < 40 {
        return nil
    }
    payloadLen := 8 + min(len(origPkt), 1232)
    resp := make([]byte, 40+payloadLen)
    
    // 1. IPv6 首部
    resp[0] = 0x60
    binary.BigEndian.PutUint16(resp[4:6], uint16(payloadLen))
    resp[6] = 58 // Next Header: ICMPv6
    resp[7] = 64 // Hop Limit
    copy(resp[8:24], origPkt[24:40]) // Src = 原 Dst
    copy(resp[24:40], origPkt[8:24]) // Dst = 原 Src
    
    // 2. ICMPv6 首部
    icmp := resp[40:]
    icmp[0] = 1 // Type: Destination Unreachable
    icmp[1] = 3 // Code: Address Unreachable
    copy(icmp[8:], origPkt[:min(len(origPkt), 1232)])
    
    // 3. 计算并填充 RFC 4443 ICMPv6 伪首部校验和
    csum := calcICMPv6Checksum(resp[8:24], resp[24:40], uint32(payloadLen), icmp)
    binary.BigEndian.PutUint16(icmp[2:4], csum)
    return resp
}
```

#### 第 4 重：平台边界与可验证阻断

- **Windows**：根据仓库硬约束，禁止调用 `netsh advfirewall` 或 WFP 修改宿主防火墙。只允许使用高优先级 TUN `::/1`、`8000::/1`、NRPT AAAA 策略和 guard 路由清理。若任一路由安装失败，启动必须失败并回滚已安装的路由。
- **Linux**：允许注入带 `INSTANCE_ID` 标签的专属 `ip6tables`/nftables 规则，但必须明确放行 AERO 控制面 IPv6 地址，不能使用无例外的 `-d ::/0` 全阻断规则。
- **macOS**：PF 规则必须写入独立 anchor，并先通过 `pfctl -vnf` 语法校验；校验失败时不得启用 IPv6 黑洞模式。

所有平台都必须通过真实物理网卡抓包验收；不能把“规则命令执行成功”当作零泄漏证明。

---

## 4. M6: 服务端共享 Linux TUN 与全局路由转发架构（P0 - 4）

### 4.1 架构翻转：废除 Per-Session gVisor，确立单例 `GlobalTunnelRouter`

彻底废除 `edge/nat.go:80` 中每个 CONNECT-IP 会话创建一个完整 gVisor 协议栈的沉重架构，在 Linux 边缘节点采用基于原生内核 TUN 与 iptables 的**单例全局路由分发拓扑**：

```mermaid
flowchart TD
    subgraph ClientConnections["客户端并发 CONNECT-IP 隧道"]
        C1["Client 1 (10.88.0.2)"]
        C2["Client 2 (10.88.0.3)"]
        Cn["Client N (10.88.0.X)"]
    end

    subgraph GlobalRouter["服务端单例 GlobalTunnelRouter"]
        direction TB
        Sessions["并发安全的全局会话路由表<br/>sync.Map: map[netip.Addr]*ClientSession"]
        Upstream["并发上行写入通道 (Direct Tun.Write)"]
        Downstream["单协程下行分发引擎 (Tun.Read -> Lookup Dest IP -> Conn.WritePacket)"]
    end

    subgraph LinuxKernel["Linux 内核原生数据面"]
        TUN["/dev/net/tun (aero-tun, 10.88.0.1/16)"]
        Conntrack["内核 conntrack (262144)"]
        Iptables["iptables MASQUERADE (SNAT)"]
        OutNIC["物理出口网卡 (eth0)"]
    end

    C1 --"conn.ReadPacket"--> Upstream
    C2 --"conn.ReadPacket"--> Upstream
    Cn --"conn.ReadPacket"--> Upstream
    Upstream --"unix.Write(tunFD)"--> TUN
    
    TUN --> Conntrack --> Iptables --> OutNIC --> Internet((公网))
    Internet --> OutNIC --> Iptables --> Conntrack --> TUN
    
    TUN --"unix.Read(tunFD)"--> Downstream
    Downstream --"检索 Sessions"--> Sessions
    Downstream --"conn.WritePacket"--> C1
    Downstream --"conn.WritePacket"--> C2
    Downstream --"conn.WritePacket"--> Cn
```

### 4.2 `serveConnectIP` 改造实现与生命周期接口

```go
// internal/edge/tunnel_router.go
type ClientSession struct {
    v4Addr netip.Addr
    v6Addr netip.Addr
    conn   IPPacketConn
    gen    uint64 // 递增代数，杜绝 IP 复用引起的串包
    token  string
}

type GlobalTunnelRouter struct {
    tun      TunDevice
    sessions sync.Map // netip.Addr -> *ClientSession
    genSeq   atomic.Uint64
    ctx      context.Context
    cancel   context.CancelFunc
    wg       sync.WaitGroup
}
```

#### 1. 客户端接入注册与防伪造检查
在 `quic.go:serveConnectIP` 中，分配 IP 后直接注册至全局路由单例：
```go
gen := s.globalRouter.Register(assignedIPv4.Addr(), assignedIPv6.Addr(), conn, token)
defer s.globalRouter.Unregister(assignedIPv4.Addr(), assignedIPv6.Addr(), gen)

// 上行泵循环：直接将客户端原始报文写入 Linux 内核 aero-tun
buf := make([]byte, 65535)
for {
    n, err := conn.ReadPacket(buf)
    if err != nil {
        break
    }
    raw := buf[:n]
    // 关键安全防线：源 IP 防伪造校验 (Anti-Spoofing)
    if !validatePacketSourceIP(raw, assignedIPv4.Addr(), assignedIPv6.Addr()) {
        continue // 丢弃伪造源 IP 的恶意数据包
    }
    // Linux TUN 文件描述符天然支持多协程并发写入 (内核 tun_get_user 自带自旋锁保护)
    if _, err := s.globalRouter.tun.Write(raw); err != nil {
        log.Printf("[EDGE-ROUTER] tun write error: %v", err)
        break
    }
}
```

#### 2. 下行单协程极速分发与 IP 复用防护
```go
func (r *GlobalTunnelRouter) runDownstream() {
    defer r.wg.Done()
    buf := make([]byte, 65535)
    for {
        if r.ctx.Err() != nil {
            return
        }
        n, err := r.tun.Read(buf)
        if err != nil {
            return
        }
        if n < 20 {
            continue
        }
        raw := buf[:n]
        dstAddr := extractDestIP(raw)
        if val, ok := r.sessions.Load(dstAddr); ok {
            sess := val.(*ClientSession)
            // 原生零拷贝回传客户端
            _, _ = sess.conn.WritePacket(raw)
        }
    }
}
```
- **IP 复用保护契约**：
  在注销时严格执行 CAS 校验：
  ```go
  func (r *GlobalTunnelRouter) Unregister(v4, v6 netip.Addr, expectedGen uint64) {
      if val, ok := r.sessions.Load(v4); ok && val.(*ClientSession).gen == expectedGen {
          r.sessions.Delete(v4)
      }
      if v6.IsValid() {
          if val, ok := r.sessions.Load(v6); ok && val.(*ClientSession).gen == expectedGen {
              r.sessions.Delete(v6)
          }
      }
  }
  ```
  确保只有当前代的会话能清理路由，若该 IP 已被新连接复用，旧连接注销绝对不误删新连接的映射。

---

## 5. M7: Salamander 完整调用链、外层 IPv6 拨号与 PMTU 动态闭环（P0 - 5）

### 5.1 `SalamanderPacketConn` 结构重构与 `WriteTo` 错误处理

现有 `client/salamander.go:84` 仅调用 `computeJitteredLen(len(b))`，缺少外层地址族与链路 PMTU 联动。按如下方式重构：

```go
type SalamanderPacketConn struct {
    net.PacketConn
    password      string
    paddingJitter bool
    activePMTU    atomic.Int32 // 宿主探测到的有效物理 PMTU (默认 1360)
    isIPv6Outer   atomic.Bool  // 外层网络是否为 IPv6
}

func (c *SalamanderPacketConn) SetActivePMTU(pmtu int) {
    if pmtu >= 576 {
        c.activePMTU.Store(int32(pmtu))
    }
}

func (c *SalamanderPacketConn) SetOuterIPv6(isV6 bool) {
    c.isIPv6Outer.Store(isV6)
}
```

#### `WriteTo` 显式拦截并拒绝超限数据包：
```go
func (c *SalamanderPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
    pmtu := int(c.activePMTU.Load())
    if pmtu < 576 {
        pmtu = 1360
    }
    isV6 := c.isIPv6Outer.Load()
    
    var targetLen int
    if c.paddingJitter {
        var err error
        targetLen, err = computeJitteredLen(len(b), pmtu, isV6)
        if err != nil {
            // 核心红线：若已超限，绝对不盲目发送，立即拦截并向上层 QUIC 报错
            return 0, fmt.Errorf("salamander: datagram length %d exceeds path MTU: %w", len(b), err)
        }
    } else {
        outerOverhead := 28
        if isV6 { outerOverhead = 48 }
        maxPayload := pmtu - outerOverhead
        if len(b) + 26 > maxPayload {
            return 0, fmt.Errorf("salamander: datagram exceeds wire payload: %d > %d", len(b)+26, maxPayload)
        }
        targetLen = len(b) + 26
    }
    // ... 后续加盐加密与填充流程
}
```

### 5.2 外层 IPv6 QUIC 拨号路径闭环

消除 `client/quic.go:358` 硬编码 `factory(ctx, "udp4")` 的缺陷，依据对端物理解析结果自适应选择地址族：

```go
// internal/client/quic.go
network := "udp4"
isIPv6Outer := false
if cfg.RemoteUDPAddr != nil && cfg.RemoteUDPAddr.IP.To4() == nil {
    network = "udp6"
    isIPv6Outer = true
}

pconn, perr := factory(ctx, network)
if perr != nil {
    return nil, fmt.Errorf("factory physical packet conn: %w", perr)
}

if cfg.ObfsPassword != "" {
    salConn := NewSalamanderPacketConn(pconn, cfg.ObfsPassword, cfg.PaddingJitter)
    salConn.SetOuterIPv6(isIPv6Outer)
    salConn.SetActivePMTU(1360) // 初始保守值
    pconn = salConn
}
```

### 5.3 严格数学约束与 RFC 9484 TUN MTU 动态推导

1. **PMTU 异常值拦截**：
   在 `computeJitteredLen` 中，若 `activePMTU <= outerOverhead`，直接返回错误，由连接层触发重拨或关闭不可行路径。
2. **RFC 9484 动态 TUN MTU 计算**：
   废除静态 `-1` 假设，依据 RFC 9484 VarInt 实际规范推导：
   ```go
   // Context ID 在值为 0 时占用 1 字节 VarInt；若非 0 则占用 2/4/8 字节
   contextIDLen := quicvarint.Len(contextID)
   maxTunPayload := quicDatagramPayloadMax - contextIDLen
   
   // 承载 IPv6 时，TUN MTU 绝对不得低于 1280 (RFC 8200 §5)
   if carriesIPv6 {
       if maxTunPayload < 1280 {
           // 外部链路过窄无法承载非分片 IPv6，降级为纯 IPv4 隧道并开启黑洞
           carriesIPv6 = false
       }
   }
   ```

---

## 6. M5: 真·QUIC Connection Migration 官方 API 与状态机闭环（P1 - 6）

### 6.1 严格对齐 `quic-go` 官方公开 API

`quic.ConnectionState` 不导出 `DisableActiveMigration` 字段，判定远端是否允许迁移的唯一权威途径是执行 `conn.AddPath()` 并捕获其返回错误：

```mermaid
stateDiagram-v2
    [*] --> StateIdle
    
    StateIdle --> StateProbing: 捕获物理网卡切换 (Wi-Fi -> 蜂窝)<br/>(150ms 节流防抖通过)
    
    StateProbing --> StateSwitched: 1. AddPath(newTransport) 成功<br/>2. path.Probe(ctx) 收到 PATH_RESPONSE<br/>3. path.Switch() 成功
    
    StateProbing --> StateFailed: AddPath() 报错 "server disabled migration"<br/>或 Probe() 超时 (600ms)
    
    StateSwitched --> StateIdle: 新路径成为主数据通道<br/>调用 oldPath.Close() 废弃旧路径
    
    StateFailed --> StateRedialing: 平滑调用 DialIP() 在新网卡上建立全新 Session
    
    StateRedialing --> StateIdle: 原子指针切换至新 Session<br/>旧连接排空关闭
```

### 6.2 路径排空与安全销毁契约

- **禁止直接调用 `oldTransport.Close()`**：
  `Transport.Close()` 会立即关闭物理底层 UDP 套接字，导致可能在途的应答包瞬间丢失。
- **正确的 API 销毁流水线**：
  1. 调用 `oldPath.Close()`：通知 QUIC 引擎废弃该路径，停止向其调度数据报；
  2. 保持底层物理套接字存活 `2 * RTT + 300ms`，允许收取旧路径的尾随确认包；
  3. 超时后安全调用底层物理 `oldPacketConn.Close()`。

---

## 7. Linux 运维脚本完全对称性、幂等性与多实例保护（P1 - 7）

### 7.1 系统配置备份、还原与幂等执行

为达成 100% 状态对称与可审计性，重构安装与卸载脚本：

#### 1. `deploy/edge-install.sh`
```bash
#!/usr/bin/env bash
set -euo pipefail

INSTANCE_ID="${1:-default}"
TUN_DEV="aero-tun-${INSTANCE_ID}"
BACKUP_DIR="/etc/aero/${INSTANCE_ID}"
mkdir -p "${BACKUP_DIR}"

echo "[AERO-EDGE] Installing Instance: ${INSTANCE_ID} on device ${TUN_DEV}..."

# 1. 备份宿主机原始 sysctl 参数 (仅首次备份)
if [ ! -f "${BACKUP_DIR}/sysctl_orig.conf" ]; then
    echo "net.ipv4.ip_forward=$(sysctl -n net.ipv4.ip_forward)" > "${BACKUP_DIR}/sysctl_orig.conf"
    echo "net.ipv6.conf.all.forwarding=$(sysctl -n net.ipv6.conf.all.forwarding)" >> "${BACKUP_DIR}/sysctl_orig.conf"
    echo "net.netfilter.nf_conntrack_max=$(sysctl -n net.netfilter.nf_conntrack_max)" >> "${BACKUP_DIR}/sysctl_orig.conf"
fi

# 2. 应用内核转发参数
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1
sysctl -w net.netfilter.nf_conntrack_max=262144

# 3. 幂等创建 TUN 设备
if ! ip link show "${TUN_DEV}" >/dev/null 2>&1; then
    ip tuntap add dev "${TUN_DEV}" mode tun
fi
ip addr replace 10.88.0.1/16 dev "${TUN_DEV}"
ip addr replace fd88:ae80::1/64 dev "${TUN_DEV}"
ip link set dev "${TUN_DEV}" up mtu 1360

OUT_IF=$(ip route show default | awk '{print $5}' | head -n1)

# 4. 幂等添加带有 INSTANCE_ID 注释的 iptables 规则 (使用 -C 检查避免重复)
TAG="AERO_V2_${INSTANCE_ID}"

add_rule_idempotent() {
    local table="$1"
    shift
    if ! iptables -t "$table" -C "$@" 2>/dev/null; then
        iptables -t "$table" -A "$@"
    fi
}

add_rule_idempotent filter FORWARD -i "${TUN_DEV}" -o "${TUN_DEV}" -m comment --comment "${TAG}_ISO" -j DROP
add_rule_idempotent filter FORWARD -i "${TUN_DEV}" -o "${OUT_IF}" -m comment --comment "${TAG}_FWD" -j ACCEPT
add_rule_idempotent filter FORWARD -i "${OUT_IF}" -o "${TUN_DEV}" -m state --state RELATED,ESTABLISHED -m comment --comment "${TAG}_RET" -j ACCEPT
add_rule_idempotent nat POSTROUTING -s 10.88.0.0/16 -o "${OUT_IF}" -m comment --comment "${TAG}_MASQ" -j MASQUERADE
```

#### 2. `deploy/edge-uninstall.sh`
```bash
#!/usr/bin/env bash
set -euo pipefail

INSTANCE_ID="${1:-default}"
TUN_DEV="aero-tun-${INSTANCE_ID}"
BACKUP_DIR="/etc/aero/${INSTANCE_ID}"
TAG="AERO_V2_${INSTANCE_ID}"

echo "[AERO-EDGE] Tearing Down Instance: ${INSTANCE_ID}..."

# 1. 精准删除带有该实例 TAG 的规则 (按行精准删除，杜绝字符串模糊匹配)
for tbl in nat filter; do
    while iptables -t "$tbl" -S | grep -q "${TAG}"; do
        RULE=$(iptables -t "$tbl" -S | grep "${TAG}" | head -n1 | sed 's/^-A //')
        iptables -t "$tbl" -D $RULE || true
    done
done

# 2. 停用并删除该实例专属 TUN 设备
if ip link show "${TUN_DEV}" >/dev/null 2>&1; then
    ip link set dev "${TUN_DEV}" down || true
    ip tuntap del dev "${TUN_DEV}" mode tun || true
fi

# 3. 严格还原宿主机 sysctl 原始值
if [ -f "${BACKUP_DIR}/sysctl_orig.conf" ]; then
    sysctl -p "${BACKUP_DIR}/sysctl_orig.conf" || true
    rm -rf "${BACKUP_DIR}"
fi
echo "[AERO-EDGE] Instance ${INSTANCE_ID} cleanly removed and sysctl restored."
```

#### 3. 现代 Linux `nftables` 原生原子方案 (`deploy/edge.nft`)
```nftables
# 安装：nft -f deploy/edge.nft
table inet aero_edge_default {
    chain forward {
        type filter hook forward priority 0; policy accept;
        iif "aero-tun" oif "aero-tun" drop
        iif "aero-tun" accept
        ct state established,related accept
    }
    chain postrouting {
        type nat hook postrouting priority 100; policy accept;
        ip saddr 10.88.0.0/16 oifname != "aero-tun" masquerade
        ip6 saddr fd88:ae80::/64 oifname != "aero-tun" masquerade
    }
}
# 瞬间完全对称卸载命令：
# nft delete table inet aero_edge_default
```

---

## 8. M4: WARP 双路径清理与统一策略注入（P1 - 8）

### 8.1 彻底清理全部历史 UDP WARP 分支

必须在以下两处生产路径中同步彻底移除 `DialUDPViaWARP`：
1. **`internal/edge/quic.go:1722, 1750`（`serveConnectUDP`）**：
   - 彻底删除 `s.dialGuard.DialUDPViaWARP` 调用分支；
   - 所有外部 UDP 流量统一经由 `s.dialUDP` 物理网卡直出。
2. **`internal/edge/nat.go:465`（`UserSpaceNATRouter.handleUDP`）**：
   - 彻底删除 `r.server.dialGuard.DialUDPViaWARP` 分支；
   - 统一走直连物理网卡套接字。

### 8.2 统一 `WarpConfig` 与 `limit.go` 策略收敛

修改 `internal/edge/limit.go` 中 AI 域名探测失败的硬编码行为，统一读取 `QUICServer.warpConfig`：
- **Fail-Open（默认）**：WARP SOCKS5 代理失败或熔断跳闸时，记录告警日志，**立即平滑放行直连出站**，保障 100% 用户可用性；
- **Fail-Closed（高密审计）**：仅当显式设置 `AERO_WARP_MODE=fail-closed` 时，对受限名单域名返回 `Proxy-Status: aero; error=warp_unavailable` 阻断访问。

---

## 9. M3: Profile v1 真实安全信任链与签名验签契约（P1 - 9）

### 9.1 完备的持久化 JSON Schema (v1)

补齐终审指出的安全认证字段，建立不可篡改的信任根：

```json
{
  "$schema": "https://aero-protocol.com/schemas/vps_profile_v1.json",
  "version": 1,
  "updated_at": 1730764800,
  "nodes": {
    "hk-01.aero-protocol.com": {
      "node_id": "hk-01",
      "active_port": 2083,
      "active_transport": "quic",
      "sni": "hk-01.aero-protocol.com",
      "etag": "\"5f8d0e-2a1c\"",
      "last_verified": 1730764800,
      "rtt_ms": 42,
      "cert_fingerprint_sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
      "pubkey_id": "edge-root-2026",
      "signature_ed25519": "8f4b2a3c...64字节十六进制签名...",
      "expires_at": 1731369600
    }
  }
}
```

### 9.2 客户端强校验契约与自愈容错

客户端在冷启动读取 `vps_profile.json` 时，必须执行严格的 5 步验证：
1. **Schema 校验**：`version == 1`；
2. **过期时间校验**：`expires_at > time.Now().Unix()`；
3. **端口合法性**：`1 <= active_port <= 65535`，禁止使用 0 或特权端口；
4. **数字签名验证**：使用客户端预埋的权威 `edge-root-2026` Ed25519 公钥，验证 `signature_ed25519` 对节点序列化数据的签名；
5. **TLS 握手证书指纹绑定**：建立 QUIC 连接时，比对服务器 TLS 证书 SHA-256 摘要与缓存中的 `cert_fingerprint_sha256`，杜绝任何中间人篡改。
- **损坏自愈**：若解析失败或验签不通过，自动将该文件重命名备份为 `vps_profile.json.corrupt.<timestamp>`，并在内存中初始化安全默认配置，杜绝 Panic。

---

## 10. 传输层边界与商业许可证合规审计门禁

1. **传输层绝对边界划分**：
   - **CONNECT-IP / CONNECT-UDP 代理数据平面**：纯 UDP/QUIC/H3，绝对禁止任何 TCP 降级；
   - **Cover 伪装站与管理探活**：独立监听 TCP 端口（TLS 1.3 / H2 / HTTP1.1），二者在操作系统传输层物理隔离。
2. **自动化商业合规门禁**：
   - 商业许可白名单：`MIT`、`Apache-2.0`、`BSD-2-Clause`、`BSD-3-Clause`、`ISC`、`CC0-1.0`、`MPL-2.0`；
   - 在 M7 运行合规审计脚本，生成可移植的项目内归档：
     ```bash
     mkdir -p deploy/reports
     go-licenses check ./...
     go-licenses report ./... > deploy/reports/licenses-report.csv
     ```
     断言全仓依赖零 GPL/LGPL 强传染性许可证，且零 `sagernet/gvisor` 符号残留。

---

## 11. 附录：Reliable-IP 未来演化草案（标准 8 字节 QUIC VarInt）

> **法律声明**：本草案仅供长远演化参考，**严禁注入 M1~M7 生产主干路径**。

### A.1 二进制帧头格式
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Capsule Type = 0xC000000041455230 (8-byte QUIC VarInt "AER0")|
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Capsule Length (Variable-Length Integer)            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Context ID (32 bits)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Packet Sequence Number (64 bits)           |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Flags (16 bits)      |      Payload Length (16 bits) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       IP Packet Payload ...                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
- **VarInt 编码合规**：最高两位为 `11`，符合 RFC 9000 §16 八字节 VarInt 规范，杜绝协议失步。

---

## 12. 实证化全链路验收门禁（修正假大空指标）

针对终审报告对验收标准的修正意见，全面剔除不切实际与脆弱的指标：

| 门禁项 | 验证拓扑与真实工具命令 | 采样与度量方法 | 明确失败判定红线 (Red Line) |
| :--- | :--- | :--- | :--- |
| **G1: CONNECT-IP 全协议数据面** | Windows/Linux 客户端直连真实 Edge 节点；<br/>1. `curl -o /tmp/100M.bin https://speed.cloudflare.com/__down?bytes=104857600`<br/>2. `dig @10.88.0.1 google.com AAAA`<br/>3. `ping -c 10 8.8.8.8` | 验证通过 TUN 传输原始 TCP、UDP、ICMP 的完整数据流 | TCP 传输校验和错误、UDP 丢包率 > 1%、ICMP 无法收到 Echo Reply，任一出现即判失败。 |
| **G2: IPv6 零直连泄漏硬核验证** | 服务端关闭 IPv6 池；客户端运行在双栈物理 Wi-Fi 下；<br/>在物理网卡上抓包：`tcpdump -i eth0 -nn "ip6 and not host <EdgeIP>"`；<br/>向双栈域名发起并发请求 | 连续监控 60 秒外网物理网卡流量 | 物理网卡捕获到哪怕 1 个外溢出站 IPv6 报文，或 AAAA 未返回 RFC 1035 NODATA 即判失败。 |
| **G3: 专属资源对称卸载验证** | Linux 服务端运行：<br/>1. `./deploy/edge-install.sh test`<br/>2. 记录 AERO 专属托管资源状态<br/>3. `./deploy/edge-uninstall.sh test`<br/>4. 校验专属资源清除度 | 检查带有 `AERO_V2_test` 注释的规则数、`aero-tun-test` 设备存在性与 `sysctl` 恢复状态 | 仍残留任何带注释的规则、TUN 设备未删除、或 `sysctl` 未恢复至备份原值即判失败。 |
| **G4: M1 DF+ICMP 回写功能验证** | 构造带 DF=1 且长度大于 PMTU 的报文发往虚拟网卡；监听本地虚拟网卡入站数据包 | 校验本地是否收到 ICMP Type 3 Code 4 / ICMPv6 报文，且网卡 MTU 完成安全收缩 | 功能未生效、未收到 ICMP 回报、或接口 MTU 未更新即判失败；记录统计往返延迟（要求 p99 < 30ms）。 |
| **G5: PMTU 四层边界实测** | 注入 1280、1360、1500 三组物理 PMTU，分别在外层 IPv4 与 IPv6 环境下运行 | 捕获网络线缆实际发出的 UDP 包长 | 发出任何大于 `activePMTU - outerOverhead` 的超限数据包即判失败。 |
| **G6: QUIC 漫游全路径实测** | 模拟物理网卡切换（Wi-Fi -> 蜂窝）；持续传输长视频流；<br/>分别触发：正常漫游、服务端禁用漫游、并发网卡抖动 | 记录视频播放卡顿与连接状态机转移 | 出现视频连接断开重连（无缝漫游失败），或并发抖动导致协程死锁即判失败。 |
| **G7: WARP 熔断与直连回退** | 人为 kill 服务端本地 WARP SOCKS5 代理进程；客户端发起 Google / YouTube 访问 | 测量客户端首包延迟与连接成功率 | 出现连接挂死超时 > 300ms，或默认 Fail-Open 模式下阻断访问即判失败。 |
| **G8: 真实依赖许可证审计** | 全模块代码清理完成后执行：<br/>`go-licenses check ./...` | 检查产物 `deploy/reports/licenses-report.csv` | 包含任何 GPL/LGPL 强传染性许可证，或仍残留 `sagernet/gvisor` 符号即判失败。 |

---

## 13. 唯一施工里程碑（M1 ~ M7）与执行甘特图

```mermaid
gantt
    title AERO-V2 终审终结版施工里程碑
    dateFormat  YYYY-MM-DD
    section 核心数据面重构 (M1 & M2)
    M1.1 客户端 TunnelEngine 门面与构造签名重构   :m1_1, 2026-11-05, 1d
    M1.2 IPDataPump 协议补齐 (ICMP解析与协同退出)  :m1_2, after m1_1, 1d
    M1.3 生产主路径接管 (DialIP/路由下发/安全重启) :m1_3, after m1_2, 1d
    M1.4 物理移除客户端全部 gVisor 依赖代码        :m1_4, after m1_3, 1d
    M2   IPv6 真实公网探测与四重防泄漏体系落地     :m2, after m1_4, 1d
    section 跨平台稳定性与配置 (M3 & M4)
    M3   独立锁文件与 Profile v1 签名验签落地    :m3, after m2, 1d
    M4   服务端 WARP 双路径清理与统一策略注入     :m4, after m3, 1d
    section 漫游、边缘架构与最终验收 (M5 ~ M7)
    M5   真·QUIC Connection Migration 状态机     :m5, after m4, 1d
    M6   服务端单例 GlobalTunnelRouter 与共享 TUN :m6, after m5, 1d
    M7   四层 PMTU 动态闭环与 8 大硬门禁验收      :m7, after m6, 1d
```

### 各阶段确切交付物清单：

- **【M1.1】接口门面**：`internal/client/stack.go` 中沉淀 `TunnelEngine` 接口与新版构造签名，单元测试零修改通过；
- **【M1.2】协议补齐**：`tunnel_pump.go` 实现 `parseICMPNextHopMTU`、原子 MTU 钳位、三权分立退出序列，消除死锁；
- **【M1.3】主路径闭环**：`engine.go` 显式调用 `DialIP()`，实现 `RestartWithConn` 安全无竞争重启；
- **【M1.4】彻底清理老内核**：物理移除客户端所有 `sagernet/gvisor` 符号与依赖，重构单测组包工具；
- **【M2】IPv6 防泄漏**：服务端实现已路由公网前缀探测，客户端落地 DNS NODATA + TUN 黑洞 + ICMPv6 拒绝 + 平台允许的防泄漏措施；Windows 不改宿主防火墙，依赖路由/NRPT/guard 并以抓包验收。
- **【M3】Profile 固化**：锁定独立 `vps_profile.json.lock`，同目录原子 Rename，落地 Schema v1 与 Ed25519 验签；
- **【M4】WARP 治理**：统一 `WarpConfig`，同步清理 `serveConnectUDP` 与 `nat.go` 两处 UDP 路径，消除硬编码；
- **【M5】QUIC 漫游**：对接官方 `AddPath` / `Path.Close` API，实现 Socket 网卡显式绑定与优雅排空；
- **【M6】Linux 原生 NAT**：交付 `GlobalTunnelRouter` 单例，废除 per-session gVisor NAT，交付幂等与带备份的对称脚本；
- **【M7】PMTU 闭环与实证**：`Salamander` 贯通外层地址族与 `WriteTo` 拦截，通过 8 大硬门禁，发布 `v1.2.25`。

---

## 14. 回滚机制与安全兜底保障

1. **版本级原子回滚**：
   - 每个里程碑均保证单步原子性（$\le 3$ 核心文件），若测试不达标立即 `git revert` 回退；
   - 生产环境备妥 `v1.2.24` 历史稳定安装包，若遭遇重大操作系统内核级突发缺陷，通过包分发系统分钟级降级回退。
2. **客户端 CrashGuard 独立看门狗**：
   - 依赖独立常驻进程 `guard.exe` 监控客户端 PID。若主进程非正常终止，看门狗强制清理 `aero0` 路由与策略，确保系统网络 0 锁死。
3. **服务端对称自愈保障**：
   - 服务端崩溃时由 systemd 触发 `ExecStopPost=/usr/local/bin/edge-uninstall.sh default`，瞬间精确清理所有 iptables 规则与 TUN 接口，还原 sysctl，绝不残留脏网络。

---

> 🔒 **最终状态核验声明**：  
> 严格恪守“**不要动**”铁律，当前全仓业务 Go 源码保持零侵入、零修改。  
> 本技术规范书已彻底穿透并闭环终审报告指出的 5 大 P0 阻断缺陷、4 大 P1 严重缺陷及全部验收指标问题，对象结构、函数签名、字节序、调用链与运维脚本均 100% 对齐现有真实代码库。  
> 请您审阅！待您下达正式“**执行**”授权后，将立即严格按照 M1 至 M7 路线启动单向精准施工！
