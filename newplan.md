# AERO 全系统大一统架构与数据面施工总纲（newplan.md）

> **状态**：终极工程基准定稿（Ready for Implementation & Migration）  
> **版本**：v2.1.0-unified  
> **核心原则**：四系统一模块一棵树、严格三层平铺封顶、四大业务包互不 Import、阶段一在现有路径完成数据面逻辑闭环、阶段二至四纯机械平移（只改路径与 import 零行为变更）、服务端与客户端支持绝对独立发布与部署。

---

## 目录
1. [大一统系统架构与工程树规范](#一-大一统系统架构与工程树规范)
2. [四大子系统文件职责与行数预算表](#二-四大子系统文件职责与行数预算表)
3. [阶段一：客户端单一管道与数据面重构规格（旧树靶点）](#三-阶段一客户端单一管道与数据面重构规格旧树靶点)
4. [阶段一：边缘商业多租户与容量防雪崩规格（旧树靶点）](#四-阶段一边缘商业多租户与容量防雪崩规格旧树靶点)
5. [协议 Proto 冻结与 StreamSpec 映射规约](#五-协议-proto-冻结与-streamspec-映射规约)
6. [宿主机零污染与适配器诚实准则](#六-宿主机零污染与适配器诚实准则)
7. [纯进程内全真 7 项自动化验收矩阵](#七-纯进程内全真-7-项自动化验收矩阵)
8. [五阶段平滑移植与独立交付路线图](#八-五阶段平滑移植与独立交付路线图)

---

## 一、 大一统系统架构与工程树规范

### 1.1 单模块收敛（Single Module）
彻底废除历史上分散的 5 份模块（`aero-ech`、`aero-edge`、`aero-webui`、`proto`、`aisys/connect/os`）及顶层 `go.work`。新仓库严格仅保留唯一的一份模块定义：
```go
module github.com/aero-protocol/aero
```

### 1.2 最终纯净工程目录树（三层平铺封顶）
全仓严禁设立 `public`、`protocol`、`domain`、`infra`、`service`、`win`、`mac` 等模糊或过度嵌套的目录，到具体文件为止只有三层：

```text
aero/
├── go.mod                                # 全系统唯一模块描述
├── cmd/                                  # 唯一薄入口层（只做参数解析、配置读取与启动）
│   ├── client/                           # 客户端入口
│   │   ├── main.go                       # 约 150 行，嵌入 UI
│   │   └── ui/                           # 客户端原生嵌入网页资源
│   ├── edge/                             # 边缘服务端入口
│   │   └── main.go                       # 约 120 行，读配置调用 internal/edge
│   ├── guard/                            # Windows 守卫守护进程
│   │   └── main.go                       # 约 150 行，//go:build windows，PID 监控与 aero0 路由自愈
│   ├── panel/                            # 边缘 8090 管理面板
│   │   └── main.go                       # 约 400 行，管理密钥中间件鉴权
│   ├── mid/                              # 生产中台控制面入口
│   │   ├── main.go                       # 约 150 行，启动 18080 服务
│   │   └── web/                          # admin 与 user 前端嵌入页面
│   └── desk/                             # 桌面指纹沙箱工作台入口
│       ├── main.go                       # 约 150 行，按系统编译启动窗口
│       ├── ui/                           # 工作台嵌入静态资源
│       ├── window_windows.go             # 200–400 行，Windows 窗口/托盘实现
│       ├── window_darwin.go              # 150–400 行，macOS 窗口实现
│       └── window_other.go               # 约 20 行，//go:build !windows && !darwin 无头占位
├── deploy/                               # 生产部署与配置资产
│   ├── edge-install.sh                   # VPS 边缘一键安装脚本（含补齐的 fi）
│   ├── mid-install.sh                    # 中台部署脚本与 systemd 服务定义
│   └── sni_matrix.json                   # 中台使用的伪装 SNI 矩阵初始配置
└── internal/                             # 核心私有业务包（编译器强制可见性保护）
    ├── proto/                            # 唯一共享协议：仅放生成的 aero.pb.go
    ├── client/                           # 客户端核心：包名 client
    ├── edge/                             # 边缘节点核心：包名 edge
    ├── mid/                              # 生产中台核心：包名 mid
    └── desk/                             # 桌面沙箱核心：包名 desk
```

### 1.3 核心依赖隔离原则（四大业务包互不 Import）
- **四大业务包严格互不引用**：`internal/client`、`internal/edge`、`internal/mid`、`internal/desk` 在 Go 源码层面严禁发生任何交叉 `import`；
- **共享契约的唯一边界**：
  - `client` 与 `edge` 仅共享 `internal/proto`（纯 Protobuf 生成代码）；
  - `mid` 与其他模块仅通过标准 HTTP REST 接口交互（`POST /admin/subs` 及原生订阅 JSON）；
  - `desk` 与客户端通信边界：两边控制面交互仅通过本地 `127.0.0.1:19877` 通信；阶段四平移时工作台原样带走现有代理参数，阶段五去掉 `--proxy-server` 之后两边只通过 `127.0.0.1:19877` 通信，浏览器流量全量走 TUN；
- **严禁无意义容器目录**：全仓严禁设立 `common/`、`util/`、`helper/`、`pkg/`。

### 1.4 构建与交付标准命令（单行无外部脚本依赖）
全仓各端交付二进制直接由标准原生 Go 命令输出：
```bash
# 1. 客户端与守卫（桌面网络数据面）
go build -o aero-client.exe ./cmd/client
go build -o aero-guard.exe  ./cmd/guard

# 2. 边缘节点与面板（VPS 部署面）
go build -o aero-edge       ./cmd/edge
go build -o aero-panel      ./cmd/panel

# 3. 生产中台与桌面工作台
go build -o aero-mid        ./cmd/mid
go build -o aero-desk.exe   ./cmd/desk
```

### 1.5 排除代码清单（彻底切除平行冗余与侵入实现）
旧树中的以下文件属于废弃、重复或侵入宿主机实现，**严禁搬入新仓库**：
- `protocol/client/internal/clienttunnel/`
- 客户端根目录的 `split.go`、`sub.go`、`sticky_pool.go`
- `internal/runtime/runtime.go`
- `internal/transport/ech.go`
- `internal/gameqos/`（数据面严格按 IP 报头协议号分流，不再按端口猜协议）
- 边缘服务端的 `connect.go`、`connect_udp.go`、`masque_handler.go`
- **宿主机系统代理篡改代码**：`win/sys_proxy_windows.go` 与 `mac/sys_proxy_darwin.go` 坚决物理剔除，绝不进 `window_windows.go` 或 `window_darwin.go`；
- 运行时生成的 `*.db`、`*.exe`、临时日志、浏览器内核压缩包（必须通过启动参数 `-data-dir` 挂载外部路径）。

---

## 二、 四大子系统文件职责与行数预算表

遵守“一个文件放一条会一起修改的职责；不到约 150 行且无独立变更理由的并入调用方；超过约 800 行且能按职责切开时才拆分”的原则。平台差异统一使用 Go 原生文件名后缀。

### 2.1 客户端与边缘服务端（`internal/client` 与 `internal/edge`）

| 新文件路径 | 行数预算 | 收进来的现有文件与核心职责 |
|---|---|---|
| `internal/client/engine.go` | 400–700 | `engine.go`、`engine_dialer.go`：会话管理、`switchActiveNode`（地址不变不 Reset）、`loadAndApplySubscription` 与 `singleflight` |
| `internal/client/tunnel.go` | 400–800 | `tunnel.go`、`tunnel_relay.go`：TCP 业务流调度、数据报发送、发送前 MTU 严格预检（移除 IsGameTraffic） |
| `internal/client/quic.go` | 200–400 | `internal/transport/quic.go`：底层 QUIC 拨号、方案 A 物理域名 SNI 锁死、捕获 `*quic.DatagramTooLargeError` |
| `internal/client/dns.go` | 200–400 | `internal/tun/dns.go`：两级 DNS 漏斗实现（.cn 直连、隧道短流解析、未建连假 IP、AAAA 空应答） |
| `internal/client/split.go` | 200–400 | `internal/split/split.go` 与 APNIC 大陆 IPv4 地址库 `internal/split/china_ip.go` 及其嵌入的 `china_ip.txt`（删除纯真字样） |
| `internal/client/sub.go` | 150–300 | `internal/sub/`：原生订阅 JSON 解析，完整保留 `isp` 参数与 `Optimization` |
| `internal/client/stack.go` | 500–900 | `gvisor.go`：虚拟网络栈转发、端口 53 封死兜底、IPv4+DF 超限包在栈入口回传 ICMP、Context 队列调度 |
| `internal/client/stack_windows.go` | 200–500 | `tun.go`、`route_windows.go`：Wintun 驱动调用、IP Helper 路由注入、虚拟网卡动态 MTU 重设接口 |
| `internal/client/stack_linux.go` | 150–400 | `route_linux.go`：Linux tun 原生设备与路由管理，暴露动态修改 MTU 接口 |
| `internal/client/stack_darwin.go` | 150–400 | `route_darwin.go`：macOS utun 原生设备与路由管理，暴露动态修改 MTU 接口 |
| `internal/client/stack_android.go` | 约 40 | `SetupRoutes` 明确返回 `fmt.Errorf("TUN not supported on this platform")` |
| `internal/client/stack_ios.go` | 约 40 | `SetupRoutes` 明确返回 `fmt.Errorf("TUN not supported on this platform")` |
| `internal/edge/quic.go` | 700–1000 | `listener.go` 的注入与 `quic.go` 的连接级对象、TCP/UDP 流调度、单连接数据报接收循环、短流 DNS |
| `internal/edge/limit.go` | 200–400 | `connlimit.go`、`dialguard.go`、`bandwidth.go`：`ConnLimiter`（仅 TCP 流 TryAcquire 成功才 defer Release）、`BandwidthLimiter`、`DialGuard` |
| `internal/edge/auth.go` | 200–400 | `validator.go`、`tokenstore.go`：首帧 `ValidateFull` 绑定 Token，同一连接后续流免 Nonce 验证；Token 本地存储与校验 |
| `internal/edge/serve.go` | 200–400 | `server.go`：服务启动收口、停止明文打印 Token、保留 `tokens.json` 持久化及 SIGHUP 重载 |
| `internal/edge/admin.go` | 200–400 | `admin.go`：提供中台调用的 `POST /admin/subs` 及边缘管理鉴权端点 |
| `internal/edge/sub.go`   | 200–400 | `bootstrap_sub.go` 与 `internal/subscribe/` 包：管理节点订阅自举与生成写出 `client-sub.json` |
| `cmd/panel/main.go` | 300–500 | `webui/cmd/panel/main.go`：8090 面板，增加 `X-Aero-Admin-Key` 鉴权中间件，彻底停止返回 `token_full` |
| `cmd/guard/main.go` | 100–200 | `win/guard/main.go`：增加 `//go:build windows`，仅 Windows 平台编译，监听 PID 退出，仅清理属于 `aero0` 的 `0.0.0.0/1` 与 `128.0.0.0/1` |
| `deploy/edge-install.sh` | 原脚本 | `protocol/server/vps/install.sh`：第 339 行补齐缺失的 `fi`，闭合 iptables 判断 |

### 2.2 生产中台（`internal/mid`，阶段三机械平移现有行为）

| 新文件路径 | 行数预算 | 收进来的现有文件与核心职责（零新增行为） |
|---|---|---|
| `internal/mid/http.go` | 300–600 | `middleware.go`、`web_handler.go`、`aero_handler.go`：中台 HTTP 路由分发与中间件 |
| `internal/mid/user.go` | 400–800 | `user_handler.go`、`user_model.go`、`user_service.go`、`user_store.go`：用户生命周期、权限控制与 Slug 检索 |
| `internal/mid/sub.go` | 400–800 | `sub_builder.go`、`edge_sync.go`、`sni_matrix.go`：两种原生订阅生成（`/sub/superadmin` 与 `/sub/{slug}`）；`sni_matrix` 只随中台原样搬家，客户端的 `ServerName` 始终等于节点域名（不引入新的纯净度调度） |
| `internal/mid/db.go` | 500–900 | `aero_db.go`：`aero.db` 纯 Go SQLite（`modernc.org/sqlite`）底层库表与连接池 |
| `internal/mid/pay.go` | 400–800 | `aeropay_db.go`、`billing.go`、`pay_in.go`、`pay_out.go`、`pay_ledger.go`：财务记账与流水审计 |
| `internal/mid/node.go` | 400–800 | `node.go`、`vps_model.go`、`vps_store.go`、`vps_file_store.go`、`vps_service.go`、`vps_handler.go`：节点拓扑与状态同步 |
| `internal/mid/probe.go` | 300–700 | `vps_probe.go`、`vps_diag.go`、`vps_install.go`、`geoip.go`、`aero_task.go`：节点探活、纯净度打分、任务状态与远程安装支持 |
| `cmd/mid/main.go` | 约 150 | 原 `sub/vpn/main.go`：启动 18080 端口，嵌入 Web 页面 |
| `cmd/mid/web/` | 静态文件 | `sub/vpn/web/admin` 与 `sub/vpn/web/user` 的页面 |
| `deploy/mid-install.sh` | 原脚本 | `scripts/install.sh`、`subvps.service` |

### 2.3 桌面指纹沙箱工作台（`internal/desk`，阶段四机械平移现有行为）

| 新文件路径 | 行数预算 | 收进来的现有文件与核心职责（零新增行为） |
|---|---|---|
| `internal/desk/browser.go` | 500–900 | `kernel/chrome.go`、`firefox.go`、`safari.go`、`types.go`、`validate.go`、`clean.go`：浏览器内核启动与管理 |
| `internal/desk/browser_windows.go`| 150–400 | `process_windows.go`、`chrome_locale.go` 的 Windows 原生进程实现 |
| `internal/desk/browser_darwin.go` | 150–400 | `process_other.go` 与 macOS 启动实现 |
| `internal/desk/fetch.go` | 200–500 | `download.go`、`download_url.go`、`archive.go`、`kernel_check.go`、`detect.go`：内核下载、校验与解压 |
| `internal/desk/profile.go` | 400–800 | `service/launcher.go`、`profile.go`、`profile_ops.go`、`batch.go`：环境配置与会话生命周期 |
| `internal/desk/fingerprint.go` | 200–400 | `domain/fingerprint/`：指纹参数建模 |
| `internal/desk/proxy.go` | 150–300 | `domain/proxy/`：原样保留现有代理配置参数（不提前改动代理模型） |
| `internal/desk/store.go` | 300–600 | `infra/db/`、`infra/storage/`、`domain/user/`：原样平移本地存储（不提前强制启用未调用的 EncryptField） |
| `internal/desk/ipc.go` | 400–800 | `ipc/` 下各 handler：本地 IPC 命令分发与状态响应 |
| `internal/desk/bridge.go` | 200–400 | `netcore/client_bridge.go`、`client_daemon.go`：与本机客户端网络端口（127.0.0.1:19877）的状态探测与桥接 |
| `internal/desk/aitools.go` | 200–400 | `aitools/`：AI 辅助开发工具箱集成 |
| `internal/desk/audit.go` | 150–300 | `audit/`：操作审计日志追加写入 |
| `internal/desk/apicheck.go` | 150–300 | `apimatrix/`：第三方 API 矩阵与健康检查 |
| `cmd/desk/main.go` | 约 150 | 桌面端薄入口，跨系统调用窗口实现 |
| `cmd/desk/ui/` | 静态文件 | 工作台前端 HTML/JS 资产 |
| `cmd/desk/window_windows.go`| 200–400 | 仅 Windows 窗口、托盘、图标（绝对不包含 sys_proxy） |
| `cmd/desk/window_darwin.go` | 150–400 | 仅 macOS 窗口（绝对不包含 sys_proxy） |
| `cmd/desk/window_other.go`  | 约 20 | `//go:build !windows && !darwin`，非桌面平台占位报错 |

---

## 三、 阶段一：客户端单一管道与数据面重构规格（旧树靶点）

> **特别铁律**：阶段一的所有修改，严格发生在当前旧工作区（`D:\jacky\gemini\aisys`）的现有路径内，**绝不提前变动目录结构或重命名模块**！

```
                         [ 客户端 Client: 宿主机零污染，单一 TUN 管道 ]
                                │
                                │ 唯一复用 QUIC 连接 (ServerName=节点域名，无伪装，底层 Ping 保活)
                                ▼
         ┌─────────────────────────────────────────────────────────────┐
         │ 边缘节点: listener/quic.go: handleQUICConn (连接级唯一对象)   │
         │ (由 listener.go 注入 ConnLimiter, BandwidthLimiter, DialGuard)│
         ├─────────────────────────────────────────────────────────────┤
         │ 1. 唯一鉴权与 Nonce 保护:                                   │
         │    └── 连接上第 1 条 ConnectRequest 走 ValidateFull 消耗 Nonce │
         │    └── 校验通过后 Token 绑定到当前连接对象                  │
         │    └── 后续流与 Context 登记严格比对 req.Token == conn.Token │
         │ 2. 单连接唯一 ReceiveDatagram 读循环: 读出大端 4 字节 ContextID│
         │    └── 查本连接 Context 表分发，未知 ContextID 直接丢弃       │
         └──────────────┬───────────────────────────────┬──────────────┘
                        │                               │
         [ TCP 业务流 ]  │                               │ [ UDP 数据报 Context ]
 ┌──────────────────────▼───────┐        ┌──────────────▼──────────────────────────────┐
 │ • Token 比对通过             │        │ • 登记流 (StreamType_UDP): StreamId=ContextID│
 │ • 仅 TCP 调用:               │        │   过 IsBlockedTarget，免连接槽、不进DialGuard│
 │   ConnLimiter.TryAcquire(tok)│        │ • 进程级 UDP 计数: 单 Token<=64，全局计数器独立│
 │   ├── false: 拒绝本流,不拆连接│        │ • 单 Context 独占非阻塞 UDPConn，单 Read 循环│
 │   └── true : defer Release() │        │ • 双向记账: Ingress 写入与 Egress 发回均扣减  │
 │ • 调用 DialGuard.DialTimeout │        │   BandwidthLimiter.Take(token, len)          │
 │   向目标服务器发起出站 TCP 拨号│        │ • 45s 空闲关闭套接字并归还进程级槽位         │
 └──────────────────────────────┘        └─────────────────────────────────────────────┘
                        │
                        ▼ [ 隧道内 DNS 短流 (StreamType_CONTROL) ]
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │ • TargetHost 为域名；免 ConnLimiter 连接槽，免进入 DialGuard 拨号闸门        │
 │ • 单 Token 50 QPS 限制，节点侧 singleflight，成功缓存 300s，负缓存 30s，1.0s超时│
 │ • 成功回传 4 字节真实 IPv4 载荷；超时/失败回传空载荷，客户端发 198.18 假 IP │
 └─────────────────────────────────────────────────────────────────────────────┘
```

### 3.1 客户端旧树修改文件清单
1. `protocol/client/public/tunnel.go`：彻底移除单流超时调用 `GlobalSessionPool.Remove`；对齐握手超时与单流最多重试 1 次（不睡眠）；首包发送预检与 MTU 判定；
2. `protocol/client/public/tunnel_relay.go`：第 310 行彻底移除 `gameqos.IsGameTraffic` 调用，流量严格按 IP 报头为准；
3. `protocol/client/public/engine.go`：物理删除 `healLeftoverAeroDNS()` 函数定义；`switchActiveNode` 仅比对 `host:port`（相同则短路返回，严禁 `Reset()`）；`loadAndApplySubscription` 挂载 `singleflight.Group`；
4. `protocol/client/public/engine_dialer.go`：收口单管道统一拨号逻辑；
5. `protocol/client/public/tun.go`：物理删除调用 `netsh advfirewall` 添加 `AERO-NoIPv6` 和 `AERO-WebRTC-Shield` 的代码；
6. `protocol/client/public/app.go` 第 42 行、`public/cli.go` 第 28 行：彻底删除 `healLeftoverAeroDNS()` 调用代码；
7. `protocol/client/public/ui/app.js`：导入逻辑增加 `isImporting` 防抖单飞锁，阻断前端初始化与点击重入；
8. `protocol/client/internal/tun/gvisor.go`：
   - channel MTU 维持 1280+；
   - 彻底删除端口 53 返回 nil 后的 `DialUDP` 兜底（直接栈内 `DecRef()` 丢弃）；
   - 阶段一静默丢弃 3478/19302/5349，数据报验收通过后放行；
   - 第一包登记 Context 并建端点，同一四元组后续包直接排队写入此 Context；
   - **在栈入口从刚注入的 IPv4 头读取 DF 标志**：超限且带 DF 构造 ICMP Type 3 Code 4 回写本地虚拟网卡（源 IP 为虚拟网卡网关地址，目的 IP 为原包源 IP，Next-MTU 动态等于当时的 `currentMaxDatagramSize + 24`，初始 1224，绝不写死 1280；ICMP 载荷附带原 IPv4 头与前 8 字节；这帧只写回本地虚拟网卡，绝不发给 VPS），不带 DF 的超限包纯静默丢弃；
9. `protocol/client/internal/tun/dns.go`：两级漏斗实现（.cn 直连、隧道短流解析、未建连假 IP、AAAA 空应答）；
10. `protocol/client/internal/tun/route_windows.go`：
    - 初始虚拟网卡 MTU 设为 1224（1200+24），暴露动态重设接口；
    - 收到 `DatagramTooLargeError` 立刻调用此接口同步更新网卡 MTU 为新的 `currentMaxDatagramSize + 24`；
    - 物理删除第 49-58 行 `fd88::2`、第 57 行 IPv6 `mtu=1380`、第 75-80 行 `::/1` 和 `8000::/1` 捕获路由；
11. `protocol/client/internal/tun/route_darwin.go`、`route_linux.go`：IPv6 传空，暴露动态修改 MTU 接口；
12. `protocol/client/internal/tun/route_android.go`、`route_ios.go`：`SetupRoutes` 明确返回 `fmt.Errorf("TUN not supported on this platform")`；
13. `protocol/client/internal/transport/quic.go`：方案 A 物理域名 SNI 锁死，SPKI pin 空列表回退系统 CA，捕获 `DatagramTooLargeError` 并持久化；
14. `protocol/client/win/guard/main.go`：仅监听主进程 PID，退出时仅删除属于 `aero0` 的 `0.0.0.0/1` 和 `128.0.0.0/1`。

---

## 四、 阶段一：边缘商业多租户与容量防雪崩规格（旧树靶点）

### 4.1 服务端旧树修改文件清单
1. `protocol/server/public/internal/listener/listener.go`：
   - `NewManager` 接收现成的 `cl`、`bl`、`dg`（`traffic.DialGuard`）；
   - `StartQUIC` 将它们传给 `NewQUICHandler`；
2. `protocol/server/public/internal/listener/quic.go`：
   - `handleQUICConn` 作为连接级唯一对象；
   - 首帧 `ValidateFull` 绑定 Token，后续流免 Nonce 验证；
   - **关键流控门禁**：**仅对 TCP 业务流在 `AcceptStream` 成功后调用 `ConnLimiter.TryAcquire(token)`，返回 true 时才执行 `defer ConnLimiter.Release(token)`；若超限优雅拒绝本流，底层 QUIC 会话保持**；
   - **DNS 短流与 Context 登记流**：**绝对免占 ConnLimiter 槽位，绝对不调用 TryAcquire，绝对不进 DialGuard**；
   - 单连接唯一 `ReceiveDatagram` 读循环，按 4 字节 ContextID 分发；
   - Context 独占非阻塞 `net.UDPConn`，单 Token 上限 64，进程级全局 UDP 总帽，45 秒超时归还，双向扣减 `BandwidthLimiter.Take`；
3. `protocol/server/public/server.go`：
   - 彻底停止在第 175、178、299 行将 Token 明文打入日志；
   - 调用 `listener.NewManager` 时传入已建好的 `cl`、`bl`、`dg`；
   - **完整保留 `tokens.json` 与 `client-sub.json` 磁盘持久化及 SIGHUP 重载**；
4. `protocol/server/public/webui/cmd/panel/main.go`：
   - 增加 `X-Aero-Admin-Key` 鉴权中间件，彻底停止返回 `token_full`；`GET /health` 维持无需鉴权；
5. `protocol/server/vps/install.sh`：
   - **第 339 行补齐缺失的 `fi`**，闭合 iptables 判断。

---

## 五、 协议 Proto 冻结与 StreamSpec 映射规约

不新增 `.proto` 文件，现有字段完全满足新架构：
- **TCP 业务流**：
  - `StreamType`: `StreamType_GENERAL` 或 `StreamType_AI`；`TargetHost` 和 `TargetPort` 为目标地址；
  - 校验 Token 通过后，调用 `ConnLimiter.TryAcquire(token)`，返回 true 时才执行 `defer ConnLimiter.Release(token)`；
  - 随后调用 `DialGuard.DialTimeout` 向目标建连；拨号失败依靠该 defer 正常归还槽位；
- **Context 登记流**：
  - `StreamType`: `StreamType_UDP`；`StreamId` 即为 `ContextID`；`TargetHost` 和 `TargetPort` 为目标地址；
  - 校验 Token 通过后，过 `traffic.IsBlockedTarget`，**免占 ConnLimiter 槽位，不进 DialGuard**；
  - 若当前连接上该 `StreamId` 已存在，直接丢弃该登记；
- **隧道内 DNS 短流**：
  - `StreamType`: `StreamType_CONTROL`；`TargetHost` 为要解析的域名；
  - **免占 ConnLimiter 槽位，不进 DialGuard**；
  - 节点受单 Token 50 QPS 限制，经 `singleflight.Group` 共享解析，成功回传 4 字节 A 记录载荷；失败或 1.0 秒超时回传空载荷；
- **数据报帧**：
  - 纯二进制帧（非 protobuf）：`[ContextID (4 字节大端 uint32)][UDP Payload]`。

---

## 六、 宿主机零污染与适配器诚实准则

### 6.1 物理移除宿主机侵入代码
- 移除客户端调用 `netsh advfirewall` 添加 `AERO-NoIPv6` 和 `AERO-WebRTC-Shield` 的代码；
- 在 `route_windows.go` 中删掉 `fd88::2` 地址分配、删掉 IPv6 `mtu=1380`，以及 `::/1` 和 `8000::/1` 路由的添加与删除命令；macOS 与 Linux 传入空 IPv6 字符串；
- 物理删除 `healLeftoverAeroDNS` 函数定义及所有调用处，用户物理 DNS 列表保持原样。

### 6.2 WebRTC 两阶段进程内控制
- **第一阶段（数据报验收通过前）**：
  - gVisor 在虚拟栈内静默丢弃发往 UDP 3478、19302、5349 的包；
  - 进程内 DNS 对所有 Type AAAA 查询直接响应纯净的 `RCODE=0, NOERROR, Answers=0` 空应答，系统不为虚拟网卡安装 IPv6 默认路由；
- **第二阶段（数据报验收通过后）**：
  - gVisor 停止丢弃，这些 UDP 进入同一套 Context 数据报通道发往海外节点，由 VPS 产生反射地址；
  - 流量严格以 IP 报头的协议号为准，严禁按端口改写协议。

### 6.3 守护进程对齐与路由自愈
- 守卫进程产物与查找路径严格统一为 **`aero-guard.exe`**；
- 彻底剔除改写注册表、WinHTTP reset、防火墙删除与 `flushdns`；
- **唯一职责**：监听主进程 PID，退出时仅删除下一跳或接口索引属于本进程创建之 `aero0` 的 `0.0.0.0/1` 和 `128.0.0.0/1`，关闭 `aero0`；**彻底移除 `10.88.` 前缀强依赖**；
- macOS / Linux 的清理直接写在各自适配器的 Context Done / SIGTERM 退出路径中，无独立守卫进程。

### 6.4 移动端适配器诚实性（本工单范围彻底锁定桌面三端）
- Android 和 iOS 的 `SetupRoutes` 维持返回 `fmt.Errorf("TUN not supported on this platform")`，客户端 `Start()` 失败并在界面明确标红提示该平台 TUN 不可用；
- 本工单绝不生成 `.aar`、绝不生成 `.xcframework`、绝不添加 `StartTunnelWithFD`。

---

## 七、 纯进程内全真 7 项自动化验收矩阵

本工单全部验收均采用**无需管理员权限、不修改宿主机环境、纯 Go 进程内测试**：

| 序号 | 验证场景 | 核心动作与断言（必须 100% 机械化通过） |
|---|---|---|
| **1** | **单流故障隔离** | 注入 Mock 拨号器挂死其中一个流，同一 QUIC 连接上的其他流持续高频读写；**断言：底层物理 QUIC 连接未断开，会话对象指针未变**。 |
| **2** | **DNS 零泄露与断言** | • `*.cn` 查询只打到 Mock 物理解析器；<br>• **核心断言：`google.com` 绝对不进入 `queryFastUDP`**；<br>• **核心断言：端口 53 返回 nil 绝对不触发 `DialUDP`**；<br>• 境外站仅通过隧道解析 Stub 获取。 |
| **3** | **节点 DNS 单飞** | 模拟 10 个并发 Goroutine 同时查询同一个冷门域名；**断言：节点上游 Mock 解析器接收到的实际查询次数严格为 1**。 |
| **4** | **多租户连接限额** | 使用经 `/admin/subs` 注册的两枚不同 Token（Token A 与 Token B）：将 Token A 压满至 `MaxConnUser`；**断言：Token A 新流被优雅拒绝且底层 QUIC 连接保持；Token B 仍能正常获取槽位向外出站拨号**。 |
| **5** | **UDP 绝对不串包** | 两个 Token 对同一个 `IP:443` 各自建立独立的 UDP Context；注入回包；**断言：回包 100% 严格落入各自独占的套接字并回到对应 ContextID，零交叉、零串包**。 |
| **6** | **速率与 Context 上限** | 配置非 0 的 BandwidthLimiter 桶；**断言：数据报发送按字节成功调用并扣减了 `Take`**；注入第 65 个 Context 的数据报被静默丢弃，已有 64 个 Context 和底层会话正常传输。 |
| **7** | **换线与刷新幂等** | 对同一个 `host:port` 连续 3 次调用订阅应用逻辑；**断言：会话池的 `Reset()` 调用次数严格为 0**。 |

---

## 八、 五阶段平滑移植与独立交付路线图

### 8.1 阶段一：当前工作区数据面逻辑闭环（旧树不动目录）
- 在 `D:\jacky\gemini\aisys` 现有热路径文件内，按第三、四、五、六部分完成所有改动；
- 运行并通过全量 7 项纯进程内自动化测试，形成功能闭环基准。

### 8.2 阶段二：平移 `proto`、`client`、`edge` 并实现双端独立发布上线
- 新建空工程目录，初始化单一模块 `github.com/aero-protocol/aero`；
- 仅平移 `internal/proto`、`internal/client`、`internal/edge` 以及 `cmd/client`、`cmd/edge`、`cmd/guard`（带 build 标签）、`cmd/panel`；
- **本次提交仅允许路径与 import 变更，业务逻辑零改动**；
- 再次运行并通过完全相同的 7 项自动化测试；
- **【双端独立交付确认】**：
  - 此时新仓库无 `mid` 与 `desk` 依赖；
  - 即可直接执行 `git commit` 并推送远程，通过 GitHub Release 上传 `aero-client` 与 `aero-edge`，海外 VPS 即可直接通过 `edge-install.sh` 独立上线，业务完全可用！

### 8.3 阶段三：平移生产中台（`internal/mid`，机械平移零新增行为）
- 将中台按职责归并为 `internal/mid` 下的 7 个文件及 `cmd/mid`；
- 保持现行订阅 JSON 的字段形状不变，现有中台逻辑原样带走；
- 运行中台既有测试，确保与边缘服务端的鉴权 Token 保持完全互通。

### 8.4 阶段四：平移桌面工作台（`internal/desk`，机械平移零新增行为）
- 将深层目录按职责并入 `internal/desk` 对应文件；
- 保持现有代理配置参数与本地存储代码原样平移，不提前改动代理模型与强制加密；
- 保持通过本机 `127.0.0.1:19877` 或 SOCKS5 端口与客户端解耦交互，严禁跨包 import。

### 8.5 阶段五：清理收官与独立专项演进
- 旧的五份 `go.mod` 与 `go.work` 正式退役；
- 在新仓库统一基准下，独立推进后续三项专项工单：
  1. **中台安全与财务加固**：封堵提权漏洞、卡号 AES-256 加密、真实安装诊断与卸载状态；
  2. **工作台指纹注入**：移除 `--proxy-server`，接入 CDP 首帧注入指纹参数；
  3. **移动端跨平台 SDK 专项**：
     - 单独封装轻量内核，严禁将带 UI/Wintun 的代码拿去 `gomobile bind`；
     - Android 传虚拟网卡 FD，iOS 传 `packetFlow` 读写接口；
     - 手机网卡 MTU 由系统 API 设为 `currentMaxDatagramSize + 24`，Go 核心做预检并向通道回写 ICMP，手机外壳不执行桌面命令；
     - 数据面 100% 沿用同一套 ContextID、MTU 与两级 DNS 漏斗规则。
