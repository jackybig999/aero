# AERO 协议“标准 MASQUE (RFC 9484) + 自主拟态护城河”下一代 VPN 实施方案 (final.md)

> **版本**：v2.0.0-production-ready  
> **更新时间**：2026-10-16  
> **状态**：审核闭环修订版（已消除全部 4 个严重错误、3 个中级瑕疵与 2 个设计缺口）  
> **工程基线**：标准 L3 IP 隧道内核 (RFC 9484 CONNECT-IP) + 自主密码学拟态护城河 (Salamander v2) + 四重绝对零泄露防线 + APNIC 极速前置分流  
> **代码冻结原则**：本方案为最终指导纲领，实施阶段按 Phase 0 至 Phase 4 严格推进，所有改动须有单元测试断言覆盖。

---

## 目录

1. [项目背景与全链路故障真实病灶再定性](#一项目背景与全链路故障真实病灶再定性)
2. [总体技术架构：洋葱复合模型与两级数据平面蓝图](#二总体技术架构洋葱复合模型与两级数据平面蓝图)
3. [六大核心技术专案完善实施细则](#三六大核心技术专案完善实施细则)
   - [专案 A：标准 MASQUE CONNECT-IP (RFC 9484) 数据面平滑重构与 HTTP/3 假死根治](#专案-a标准-masque-connect-ip-rfc-9484-数据面平滑重构与-http3-假死根治)
   - [专案 B：Wintun 驱动读写与内核级 SetEvent 三段式优雅销毁管道（根治重连闪退）](#专案-bwintun-驱动读写与内核级-setevent-三段式优雅销毁管道根治重连闪退)
   - [专案 C：Win32 Message-Only 纯消息窗口托盘与套接字退避重试（根治代理切换闪退）](#专案-cwin32-message-only-纯消息窗口托盘与套接字退避重试根治代理切换闪退)
   - [专案 D：三级确定性 DNS 判决漏斗与 APNIC 10ns 极速前置分流（根治国内网站走代理）](#专案-d三级确定性-dns-判决漏斗与-apnic-10ns-极速前置分流根治国内网站走代理)
   - [专案 E：四重绝对零泄露工程防线（NRPT 根域锚定 + WebRTC DPI + IPv6 黑洞 + KillSwitch）](#专案-e四重绝对零泄露工程防线nrpt-根域锚定--webrtc-dpi--ipv6-黑洞--killswitch)
   - [专案 F：自主领先护城河工程落地（Salamander v2 拟态混淆 + 动态跳频 + 蜜罐入狱）](#专案-f自主领先护城河工程落地salamander-v2-拟态混淆--动态跳频--蜜罐入狱)
4. [全模块代码改造清单与精密外科手术指引](#四全模块代码改造清单与精密外科手术指引)
5. [分阶段落地实施排期、测试桩设计与验收判定门禁](#五分阶段落地实施排期测试桩设计与验收判定门禁)
6. [权威协议对照与合规性指标](#六权威协议对照与合规性指标)

---

## 一、项目背景与全链路故障真实病灶再定性

结合实测现象与代码逐行穿透审计，对原系统中暴露的五大阻断性故障进行**彻底去伪存真**的真实病灶定性：

| 故障现象 | 表面现象假象 | 真实代码病灶与底层机理（穿透审计） | 涉及核心文件与代码行 |
| :--- | :--- | :--- | :--- |
| **浏览器直接不可用 / 假死转圈** | 误判为“ICMP 函数恒返回 nil” | **应用层强行干预 QUIC 协商产生丢包黑洞**：`stack.go:438` 拦截 UDP 443 并向本地写回 ICMP Port Unreachable (Type 3 Code 3)。根据 RFC 792/9000，Chromium 收到端口不可达后**不会**线性降级到 TCP，而是启动 QUIC 备用端口重试或等待 Alt-Svc 预热；叠加 gVisor 吞咽原生 QUIC 数据包，造成 Chromium 产生 30~60 秒的连接退避挂死。 | `aeroprot/internal/client/stack.go:436–457`<br>`aeroprot/internal/client/stack.go:746–798` |
| **AI 能对话，体验良好** | 误判为“AI 具备独立专网” | **数据链路物理旁路**：桌面端 AI 工具使用 `127.0.0.1:55555` HTTP CONNECT 代理，以纯 TCP 字节流穿透隧道，根本没有经过 Wintun 驱动与 gVisor 协议栈，避开了客户端数据平面所有的结构性缺陷。 | `aeroos/internal/desk/aitools.go:93`<br>`aeroprot/internal/client/engine.go:1665` |
| **中断之后，重连闪退** | 误判为“单纯缺少 WaitGroup” | **Windows 内核对象悬挂与跨环内存访问异常 (0xC0000005)**：`tun_windows.go:250` 的 `Close()` 在未通知且未唤醒阻塞在 `windows.WaitForSingleObject(ev, 1000)` 的读循环时，直接调用 `d.session.End()` 销毁了 Wintun 环形缓冲区；处于内核态的读线程被唤醒后在已被释放的 Handle 上调用 `ReceivePacket()`，直接触发 C 运行时非法内存访问。 | `aeroprot/internal/client/tun_windows.go:186–220`<br>`aeroprot/internal/client/tun_windows.go:250–264` |
| **系统代理模式，直接闪退** | 误判为“单纯端口冲突” | **Win32 跨线程同步 SendMessage 死锁 + 监听器销毁时序竞态**：`gui_windows.go:447` 强行子类化 WebView2 主窗口，后台网络 Goroutine 通过同步阻塞的 `SendMessageW(..., WM_SETICON)` 向 UI 线程灌发消息；同时 `:55555` 端口在切换时未等 Windows 内核释放连接即重新监听，两相叠加触发窗口消息死锁与进程 Panic。 | `aeroprot/cmd/client/gui_windows.go:387`<br>`aeroprot/cmd/client/gui_windows.go:447–458`<br>`aeroprot/internal/client/engine.go:1679` |
| **TUN 连上了显示一直连接中** | 误判为“探活超时” | **接口状态跳变重置与 UI 状态机竞态**：配置路由激活 Wintun 时触发 Windows `NotifyIpInterfaceChange`，底层会话被意外重置；同时 UI 前端的 `busy` 锁在未收到预期 WebSocket/API 心跳回调前陷入锁死。 | `aeroprot/internal/client/engine.go:1060`<br>`aeroprot/cmd/client/ui/app.js:422` |
| **国内网站（B站等）走代理** | 误判为“完全没有国内分流” | **分流漏斗颠倒且 Fake-IP 投毒前置**：现行 `dns.go:381` 仅放行 `.cn` 顶级域及静态名单，对 `bilibili.com`、`163.com` 等大量未在硬编码规则内的未知国内站点全部落入 Fallthrough，下发 `198.18.x.x` Fake-IP；这直接破坏了目的 IP 的真实地理属性，导致后置的 8000+ 网段 APNIC `ChinaIPMatcher` 匹配库被彻底架空！ | `aeroprot/internal/client/dns.go:381–410`<br>`aeroprot/internal/client/split.go:62–138` |

---

## 二、总体技术架构：洋葱复合模型与两级数据平面蓝图

方案摒弃“gVisor 用户态协议栈深度篡改 L4 流量”的重型旧架构，向**标准 L3 原生 IP 隧道架构（MASQUE CONNECT-IP）**全面升级，形成内层纯净标准、外层自主拟态的“洋葱模型”：

```text
                  ┌────────────────────────────────────────────────────────┐
                  │          应用程序 / 浏览器 / 4K流媒体 / 联机游戏          │
                  └───────────────────────────┬────────────────────────────┘
                                              │ (操作系统原生 L3 IP 数据包)
                                              ▼
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│ AERO 客户端核心数据平面 (Client Data Plane Core)                                          │
│  ├── 驱动与生命周期层：Wintun 适配器 (内核级 SetEvent 显式唤醒 + sync.WaitGroup 零崩销毁)  │
│  ├── 智能分流决策层：三级确定性判决漏斗                                                   │
│  │    ├── Level 1: AI 专线 / 明确境外名单 ──> Fake-IP (198.18.0.0/15)                     │
│  │    ├── Level 2: 明确国内白名单 / .cn 顶级域 ──> 物理 DNS 极速直连                       │
│  │    └── Level 3: 未知域名 Fallthrough ──> 物理 DNS 并发解析 ──> APNIC 10ns 真实 IP 校验    │
│  │                                          ├── 属于中国大陆 ──> 返回真实 IP (直连)        │
│  │                                          └── 属于海外 ────> 走隧道安全解析 (走代理)     │
│  ├── 四重安全防线：NRPT 根域策略 + WebRTC DPI (RFC 5389) 丢弃 + IPv6 黑洞 + Fail-Closed  │
│  └── L3 双向流转泵 (Dual-Directional IP Pump)：                                          │
│       ├── 出站泵 (Wintun -> CONNECT-IP): 校验 IP 报头，直灌 connectip.Conn.WritePacket   │
│       └── 入站泵 (CONNECT-IP -> Wintun): 接收下行报文，直灌 Wintun.Write (免 L4 解包)      │
└─────────────────────────────────────────────┬────────────────────────────────────────────┘
                                              │
                                              ▼
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│ 自主技术护城河外壳 (Autonomous Moat Layer - Salamander v2)                               │
│  ├── 密码学高熵白噪声：Blake2b 密钥衍生 + ChaCha20-Poly1305 AEAD                          │
│  ├── 统计特征消除：动态随机包长抖动拟态 [1280, 1380 字节] 瓦解 DPI 机器学习包长直方图      │
│  ├── 物理接入绑定：作为 PacketConn 装饰器透明挂载于 QUIC Transport 底层套接字              │
│  └── 传输信道韧性：单机多端口动态跳频 + QUIC Connection Migration 零 RTT 漫游            │
└─────────────────────────────────────────────┬────────────────────────────────────────────┘
                                              │ (外网线路上表现为完全无特征的随机高熵 UDP 流)
                                              ▼
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│ Linux VPS 边缘服务器 (AERO Edge Server)                                                  │
│  ├── 边界拟态诱捕：未授权扫描呈现真实企业官网 (Cover Web) + 暴力探测自动压入黑名单 (Jail)   │
│  ├── 拟态外壳剥离：Salamander 解密校验 Poly1305 MAC 标签，还原标准 QUIC 数据报             │
│  ├── 标准 MASQUE 终止：HTTP/3 CONNECT-IP Proxy 接收 IP 数据报并分配会话前缀               │
│  └── 真实物理出站：纯内存轻量 NAT + iptables / 内核路由直出公网                            │
└──────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 三、六大核心技术专案完善实施细则

### 专案 A：标准 MASQUE CONNECT-IP (RFC 9484) 数据面平滑重构与 HTTP/3 假死根治

#### 1. 彻底纠治应用层劫持病灶
- **清除伪降级代码**：彻底从 `aeroprot/internal/client/stack.go` 中删除 `id.LocalPort == 443` 的分支判断（L436–L457），同时安全移除已经失效的 `buildICMPPortUnreachable` 函数。
- **技术原理**：客户端协议栈不应在应用层主观假设浏览器协议偏好。浏览器的 QUIC Initial (UDP/443) 报文应被视为最纯粹的 L3 原生数据包，由隧道完整透传至服务端直出，使 Chrome / Edge 能在 **0 毫秒内秒级原生协商出 HTTP/3 (`h3`)**。

#### 2. L3 原生 IP 双向泵（The L3 IP Pump）架构过渡路线
当前系统存在 `StackEngine`（基于 gVisor 的 L4 用户态网络协议栈），而 RFC 9484 要求的是 L3 原生 IP 报文透传。必须通过明确的 **4 步过渡管道** 替换底层传输核心：

```go
// 数据面核心：双向无锁 IP 数据泵
type IPDataPump struct {
    wintunDev  TunDevice
    ipConn     *connectip.Conn
    ctx        context.Context
    cancel     context.CancelFunc
    wg         sync.WaitGroup
    killSwitch *atomic.Bool
}
```

- **Step 1（出站流转：Wintun → CONNECT-IP）**：
  启动独立的 `pumpWintunToRemote` Goroutine：
  - 从 Wintun 驱动调用 `Read()` 获取原生 IP 报文（IPv4/IPv6）；
  - 检查 Kill-Switch 状态：若激活则直接放弃；
  - 校验 IP 报头有效性，执行 WebRTC 防泄漏过滤；
  - 直接调用 `d.ipConn.WritePacket(pkt)` 写入标准 CONNECT-IP 管道（走底层 QUIC Datagram，零队头阻塞）。
- **Step 2（入站流转：CONNECT-IP → Wintun）**：
  启动独立的 `pumpRemoteToWintun` Goroutine：
  - 从 `d.ipConn.ReadPacket()` 接收 VPS 边缘节点回传的下行 IP 数据报；
  - 直接调用 `d.wintunDev.Write(pkt)` 回灌至 Windows 虚拟网卡，由操作系统内核协议栈负责分发至具体套接字。
- **Step 3（gVisor 降级与角色剥离）**：
  - `StackEngine` 不再处理全局的 TCP/UDP `ForwarderRequest`；
  - 仅保留一个极轻量的局部虚拟端点负责监听 `10.88.0.1:53` 进行本地 DNS 捕获，彻底解除单进程 64 UDP Context 上限与 L4 转换损耗。
- **Step 4（启动编排与会话对接）**：
  在 `engine.go` 启动时，调用 `session.DialIP(ctx)`，握手成功获取 VPS 分配的客户端虚拟 IP 路由后，将创建的 `ipConn` 绑定至 `IPDataPump` 并启动。

#### 3. 关于 `reliable-ip-v1` 的确切定位与演进规范
- **明确边界**：经代码全面审计，`reliable-ip-v1` 在当前代码库中不存在任何代码资产。方案正式将其确认为**自主研发扩展特性（New Extension Feature）**，排入 Phase 4，绝不阻断 Phase 1 标准 CONNECT-IP 的基线打通。
- **协议规范定义**：
  - 针对恶劣高丢包网络下的 AI 长文本流式传输（SSE）与超大文件传输，当底层 UDP 数据报丢包率高于阈值时，客户端与服务端通过协商自定义 Capsule：`CAPSULE_RELIABLE_IP_FRAME (Type=0x41455230)`；
  - 在 QUIC Stream 上传输带 4 字节大端长度前缀的 IP 报文，提供可靠重传机制，与基于 Datagram 的标准低延迟 `connect-ip` 互为补充。

---

### 专案 B：Wintun 驱动读写与内核级 SetEvent 三段式优雅销毁管道（根治重连闪退）

#### 1. 深度病灶根除机理
Wintun 的读取操作通过 Windows 内核事件对象同步。若仅仅使用 Go 的 `context.CancelFunc`，读 Goroutine 依然会阻塞在 `windows.WaitForSingleObject(ev, 1000)` 最长达 1 秒；若此时外层主线程直接调用 `d.session.End()` 与 `d.adapter.Close()`，内核句柄被注销，唤醒后的线程调用 `ReceivePacket()` 必将触发内存访问越界（0xC0000005）。

#### 2. 三段式优雅销毁管道标准设计

```go
type windowsDevice struct {
    name       string
    mtu        int
    adapter    *wintun.Adapter
    session    wintun.Session
    sessionOK  atomic.Bool
    closed     atomic.Bool
    ctx        context.Context
    cancel     context.CancelFunc
    readWg     sync.WaitGroup
    writeMu    sync.Mutex
}
```

```go
// Close 遵循严格的内核对象三段式安全销毁时序
func (d *windowsDevice) Close() error {
    stopCrashGuard()
    
    // Step 0: 状态原子保护，防止重复并发调用
    if !d.closed.CompareAndSwap(false, true) {
        return nil
    }
    d.sessionOK.Store(false)

    // Step 1: 内核级显式唤醒与上下文级联取消
    if d.cancel != nil {
        d.cancel()
    }
    // 关键细节：显式触发 Wintun 的 ReadWaitEvent，瞬间击破 WaitForSingleObject 阻塞！
    if d.session != 0 {
        if ev := d.session.ReadWaitEvent(); ev != 0 {
            _ = windows.SetEvent(ev)
        }
    }

    // Step 2: 严格阻塞等待读/写 Goroutine 全部脱离 Wintun 环形缓冲区
    d.readWg.Wait()

    // Step 3: 在确保无任何活跃内存访问后，安全关闭 Wintun 句柄
    d.writeMu.Lock()
    defer d.writeMu.Unlock()
    
    d.session.End()
    if d.adapter != nil {
        _ = d.adapter.Close()
        d.adapter = nil
    }
    log.Printf("[TUN] Windows adapter safely destroyed: %s", d.name)
    return nil
}
```

#### 3. `Read()` 循环适配
在 `Read(p []byte)` 的循环中：
- 每次等待前将 `d.readWg.Add(1)`，退出时 `d.readWg.Done()`；
- `WaitForSingleObject` 唤醒后，第一时间检查 `d.ctx.Err() != nil` 或 `d.closed.Load()`，若成立立即退出，绝不二次调用 `ReceivePacket()`！

---

### 专案 C：Win32 Message-Only 纯消息窗口托盘与套接字退避重试（根治代理切换闪退）

#### 1. 彻底解耦 WebView2 消息循环
- **删除侵入式子类化钩子**：
  从 `aeroprot/cmd/client/gui_windows.go` 中彻底剔除 `SetWindowLongPtrW(..., GWLP_WNDPROC)` 与 `origWndProc`，让 WebView2 引擎完全掌控其内部渲染与 Chromium 消息调度。
- **构建独立的 Message-Only 托盘消息窗口**：
  使用 Win32 API `CreateWindowExW` 创建不可见的系统消息原生窗口（HWND_MESSAGE），将 `Shell_NotifyIconW` 的回调消息（`WM_TRAY_MSG`）路由至该独立窗口的过程函数（`trayWndProc`）。
- **异步消息解耦**：
  托盘状态变更改用纯异步非阻塞的 `PostMessageW(trayHWND, ...)`，彻底禁止在后台网络 Goroutine 中调用同步阻塞的 `SendMessageW`，杜绝任何 UI 跨线程死锁。

#### 2. 本地代理端口（55555）优雅退避与复用重试
Windows 内核在套接字关闭到端口完全可用之间存在微小的时间窗口。优化 `startMixedProxy` 逻辑：
- 在关闭原监听器后，加入显式的 **100ms 优雅退避缓冲**；
- 引入最多 3 次、间隔 100ms 的自旋重试机制，若因瞬时 `WSAEADDRINUSE` 冲突则自动退避；
- 对已接入的连接池（`activeConns`）实施级联断开通知，保障在 TUN 模式与系统代理模式间任意高频切换 0 报错、0 闪退。

---

### 专案 D：三级确定性 DNS 判决漏斗与 APNIC 10ns 极速前置分流（根治国内网站走代理）

#### 1. 现状纠偏与深度病灶剖析
系统当前已具备针对 `.cn` 的直连逻辑，但**对所有未在硬编码域名规则内的未知国内站点（如 bilibili.com, 163.com 等），全部盲目下发 Fake-IP（198.18.x.x）**，使得这部分流量全部被强制裹挟进海外代理，引发国内服务严重的异地风控与延迟。

#### 2. 三级确定性智能判决漏斗（Three-Stage Funnel）

```text
[DNS 查询请求] ──> [提取 QNAME & QTYPE]
                      │
                      ├── [Level 1: 绝对专线 / 白名单匹配]
                      │     ├── 命中 AI 服务 / 明确境外名单 ──> 下发 Fake-IP (198.18.x.x) ──> 走代理隧道
                      │     └── 命中明确直连规则 / .cn 顶级域 ──> 走本地物理 DNS 解析 ──> 100% 物理直连
                      │
                      └── [Level 2: 未知域名 Fallthrough 决策]
                            │
                            ▼
                      [向本地物理 DNS 并发极速查询真实 IP (超时 800ms)]
                            │
                            ▼
                      [提取应答中的 IPv4 地址] ──> 调用 ChinaIPMatcher.Contains(ip)
                            │
                            ├── 命中中国大陆 IP (APNIC 8000+ 网段, 10ns 二分匹配)
                            │     └── 返回真实 A 记录 + 写入 DIRECT 缓存 ──> 100% 物理直连 (免代理免风控)
                            │
                            └── 属于境外 IP / 解析失败 / 遭到运营商污染
                                  └── 立即丢弃 ──> 下发 Fake-IP / 隧道 DoH 解析 ──> 走代理隧道
```

#### 3. 盘活现有高价值资产
- 完整重用 `split.go` 中的 `ChinaIPMatcher`，其底层基于紧凑闭区间数组和二分查找，单次匹配仅耗时 ~10ns，且零堆内存分配。
- 此机制将从根本上保障：**无论国内网站是否带有 .cn 后缀，只要其服务器位于中国大陆境内，解析结果全部直连物理网卡，彻底消除验证码与风控！**

---

### 专案 E：四重绝对零泄露工程防线（NRPT 根域锚定 + WebRTC DPI + IPv6 黑洞 + KillSwitch）

#### 1. Windows NRPT 根域策略绝对锁定
在调用 `SetupRoutes` 建立虚拟网卡路由时，通过 PowerShell / Windows NetAPI 执行：
```powershell
Add-DnsClientNrptRule -Namespace "." -NameServers "10.88.0.1" -Comment "AERO_aero0"
```
强制将全局根命名空间 `.` 的 DNS 递归解析权锁定至本地虚拟 DNS，彻底封杀 Windows **SMHNR（Smart Multi-Homed Name Resolution）** 并行向物理网卡泄露明文查询的漏洞。进程退出时由守护进程精准撤销。

#### 2. WebRTC STUN 深度报文过滤（RFC 5389）
在 L3 IP 出站管道首端部署报文检测，精准匹配 STUN 报文格式：
```go
// RFC 5389 STUN 规范深度特征：前2位为00，Magic Cookie 必须精确匹配 0x2112A442
if len(udpPayload) >= 20 && (udpPayload[0]&0xC0 == 0) && binary.BigEndian.Uint32(udpPayload[4:8]) == 0x2112A442 {
    // 强制阻止直接泄露：在 WebRTC 专线未就绪时立即原地丢弃！
    return true
}
```
结合针对常用 STUN 端口 `3478, 19302, 5349` 的物理丢弃机制，杜绝前端 JavaScript 通过 `RTCPeerConnection` 探查宿主真实物理公网 IP。

#### 3. IPv6 空间抑制黑洞
在 Windows 虚拟网卡上配置全覆盖的黑洞路由：
- `route add ::/1 10.88.0.2 metric 1`
- `route add 8000::/1 10.88.0.2 metric 1`  
配合未配置 IPv6 时的纯内存丢包，杜绝双栈网络下流量绕过 IPv4 隧道发生走私。

#### 4. 内核级 Fail-Closed Kill-Switch
当网络波动或 QUIC 底层断开时，原子变量 `killSwitch` 即刻置为 `true`。L3 IP 数据泵在读取到任何出站数据报时直接原地 Drop，**0 字节流量逃逸至物理网卡**。

---

### 专案 F：自主领先护城河工程落地（Salamander v2 拟态混淆 + 动态跳频 + 蜜罐入狱）

#### 1. 密码学高熵拟态外壳（Salamander v2）的透明挂载
- **确认代码资产就绪性**：
  `aeroprot/internal/client/salamander.go` 已完整具备 Blake2b 密钥推导、ChaCha20-Poly1305 AEAD 加密、8 字节强随机盐和 `[1280, 1380]` 字节动态随机抖动。
- **固化挂载接入点**：
  在 `quic.go` 的底层拨号器中，不再直接将原始 UDP 套接字传给 QUIC Transport，而是透明套上一层装饰器：
  ```go
  // 透明挂载 Salamander v2 混淆外壳
  obfsConn := NewSalamanderPacketConn(rawPacketConn, cfg.ObfsPassword, cfg.PaddingJitter)
  tr := &quic.Transport{
      Conn: obfsConn,
  }
  ```
  在线路上，所有出站的数据包均表现为完全高熵的白噪声随机比特流，完全破坏基于数据报长度直方图与特征码的 DPI 机器学习识别。

#### 2. 服务端主动诱捕与扫描入狱（Cover Web & Jail）
- 服务端 `edge/quic.go` 在接收到未携带正确认证握手的 HTTP/3 请求时，原汁原味返回内置的高仿真企业科技官网（`cover.html` / `cover.css`），不暴露任何代理服务指征；
- `jail.go` 的 `AuthFailureJail` 自动对高频探测 IP 实施封锁，并在内核连接表中实施阻断。

---

## 四、全模块代码改造清单与精密外科手术指引

严格遵守 Go 单模块体系，杜绝大规模盲目重写，执行精确的外科手术式改造：

| 模块类别 | 目标文件路径 | 操作性质 | 精密改造内容与行号指引 |
| :--- | :--- | :---: | :--- |
| **协议栈净化** | `aeroprot/internal/client/stack.go` | **精简/剥除** | 彻底删除 L436–L457 的 UDP 443 拦截代码块；删除 L746–L798 的 `buildICMPPortUnreachable` 函数；保留 L53 DNS 劫持与 STUN 检测。 |
| **L3 数据面泵** | `aeroprot/internal/client/tunnel.go` | **新增/重构** | 实现 `IPDataPump`，构建 `pumpWintunToRemote` 与 `pumpRemoteToWintun` 双向高并发数据管道。 |
| **驱动生命周期** | `aeroprot/internal/client/tun_windows.go` | **加固重构** | 在 `windowsDevice` 引入 `ctx`, `cancel`, `readWg`；重构 `Close()`，在 `cancel()` 后显式调用 `windows.SetEvent(session.ReadWaitEvent())` 唤醒内核，阻塞等待 `readWg.Wait()` 后再注销 session 与 adapter。 |
| **GUI 与托盘** | `aeroprot/cmd/client/gui_windows.go` | **解耦重构** | 彻底删除 `SetWindowLongPtrW` 子类化调用及 `origWndProc`；创建独立 Message-Only 纯消息窗口；`UpdateTrayIcon` 改用异步 `PostMessageW`。 |
| **DNS 漏斗时序** | `aeroprot/internal/client/dns.go` | **时序重排** | 在 `HandleQuery` 的阶段三引入并发物理 DNS 探测与 `ChinaIPMatcher.Contains()` 判决，国内 IP 直连，海外才走隧道/Fake-IP。 |
| **传输层外壳** | `aeroprot/internal/client/quic.go` | **挂载装配** | 在客户端 QUIC Transport 构建处，将底层 UDP 套接字包装为 `NewSalamanderPacketConn`。 |
| **中台主引擎** | `aeroprot/internal/client/engine.go` | **编排更新** | 恢复调用 `session.DialIP`，将握手返回的 `connectip.Conn` 注入 `IPDataPump`；`startMixedProxy` 引入端口退避重试机制。 |

---

## 五、分阶段落地实施排期、测试桩设计与验收判定门禁

```text
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│     Phase 0     │ ──> │     Phase 1     │ ──> │     Phase 2     │ ──> │     Phase 3     │ ──> │     Phase 4     │
│ 线缆测试桩与前置门禁 │     │ CONNECT-IP 数据面 │     │ 驱动生命与GUI解耦 │     │ DNS漏斗与零泄露  │     │ 护城河合体与终验 │
└─────────────────┘     └─────────────────┘     └─────────────────┘     └─────────────────┘     └─────────────────┘
```

### Phase 0：线缆测试桩设计与前置单测门禁
- **构建测试桩沙箱（`tmp/` 隔离）**：
  - 构建基于内存通道的 `MockPacketConn` 与 `MockConnectIPConn`；
  - 构造包含真实 IPv4 首部与 UDP/443 净荷的原始字节流测试用例，断言数据面在处理原生 IP 报文时的无损性；
  - 构造 Wintun 销毁竞态模拟用例，验证并发 `Close()` 与 `Read()` 时 0 内存越界。
- **门禁标准**：`go test -race -shuffle=on ./...` 全绿通过。

### Phase 1：MASQUE CONNECT-IP 数据面打通（治愈浏览器 HTTP/3 假死）
- **改造内容**：剥除 `stack.go` 中 UDP 443 拦截；在 `tunnel.go` 建立 `IPDataPump` 并在 `engine.go` 对接 `session.DialIP`。
- **门禁标准**：
  - 宿主机 Chrome 访问 Google / Cloudflare 测试站，DevTools 网络面板显示**直接协商为 `h3` 协议**；
  - 首次内容渲染（FCP）耗时降低 80% 以上，无任何超时假死。

### Phase 2：驱动内核级优雅销毁与 GUI 消息泵解耦（治愈双重闪退）
- **改造内容**：在 `tun_windows.go` 实现带有 `SetEvent` 的三段式销毁；在 `gui_windows.go` 创建独立 Message-Only 窗口并改用 `PostMessage`。
- **门禁标准**：
  - 自动化脚本执行连续 50 次“连接 → 中断 → 立即重连”，进程保持平稳，崩溃次数为 0；
  - 在 GUI 界面中快速切换 TUN 模式与本地代理模式 20 次，无卡顿无闪退。

### Phase 3：DNS 漏斗重排与四重零泄露部署（治愈国内走代理与泄露）
- **改造内容**：重排 `dns.go` 时序，接入 `ChinaIPMatcher` 极速判决；配置 NRPT 策略与 WebRTC 丢弃规则。
- **门禁标准**：
  - 访问 Bilibili、网易云等国内非 .cn 域名，直接命中直连网卡，无异地风控；
  - 在 browserleaks.com 扫描，**DNS 泄露数 = 0，WebRTC 泄露数 = 0，IPv6 泄露数 = 0**。

### Phase 4：自主护城河全面合体与整体验收
- **改造内容**：在 `quic.go` 挂载 `SalamanderPacketConn`；验证服务端 `Cover Web` 与 `Jail` 机制；评估 `reliable-ip-v1` 协议扩展。
- **门禁标准**：
  - Wireshark 抓包确认出站 UDP 报文呈现完全高熵随机白噪声特征，无任何明文特征；
  - 浏览器直接访问 VPS 端口呈现逼真企业官网，系统整体运行如行云流水。

---

## 六、权威协议对照与合规性指标

| 协议 / 标准规范 | 官方核心定义 | AERO 系统严格落地对齐方式 |
| :--- | :--- | :--- |
| **RFC 9484** | The CONNECT-IP HTTP Method | 标准 URI 模板协商，传输端到端原生 IP 数据报 |
| **RFC 9298** | Proxying UDP in HTTP | MASQUE CONNECT-UDP 原生 UDP 数据流代理 |
| **RFC 9221** | An Unreliable Datagram Extension to QUIC | 底层基于 QUIC Datagram 实现 0 队头阻塞的高速低延迟转发 |
| **RFC 9000** | QUIC Transport Protocol | 核心传输基石，天然支持 0-RTT 与 Connection Migration 无感漫游 |
| **RFC 9114** | HTTP/3 Protocol | 控制面交互与 MASQUE Capsule 协议交换通道 |
| **RFC 5389** | STUN Protocol Specification | 精准检测 Magic Cookie (`0x2112A442`)，前置丢弃阻断 WebRTC 泄露 |
| **RFC 8484** | DNS Queries over HTTPS (DoH) | 隧道内部安全递归解析，彻底杜绝中间人劫持与探测 |
| **RFC 8305** | Happy Eyeballs v2 | 客户端多节点、多端口阶梯式健康并发竞速探活 |
| **RFC 1191** | Path MTU Discovery | 虚拟网卡 MTU 对齐 1360，动态适应底层封装开销 |

---
*(本文档为审核修订后的终极实施纲领，已在工作目录下固化并对齐代码库现状)*
