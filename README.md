# AIsys — 全平台网络协议与 AI 连接中台系统

> **项目根目录（唯一主仓）**：`D:\jacky\gemini\aisys`  
> **定位**：面向生产环境的高性能自主加密隧道协议、订阅中台单端口运营系统与 AI 研发工具连接管理器。

[![Go Version](https://img.shields.io/badge/Go-1.24%2B-00ADD8?style=flat&logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Architecture](https://img.shields.io/badge/Arch-Decoupled%20Subtrees-brightgreen.svg)]()

---

## 一、 系统架构全景

系统严格划分为三大物理隔离、逻辑解耦的子树。各子树拥有独立的 `go.mod` 模块，**禁止互相跨树源码 import**，仅通过 HTTP REST API、本地网络端口、二进制交付物与标准数据契约交互。

```text
AIsys/
├── assets/                         # 全系统统一品牌视觉资产真源 (icon.ico, icon.png 等)
├── sync-assets.ps1                 # 品牌资产统一分发同步流水线
│
├── protocol/                       # 【子树 1】自主隧道协议与跨端客户端套件
│   ├── client/                     # 客户端模块 (github.com/aero-protocol/aero-ech)
│   │   ├── config/                 # 客户端默认配置文件 (config.yaml)
│   │   ├── public/                 # PC 桌面端核心引擎实现与内嵌 WebUI
│   │   │   ├── app.go              # GUI 桌面生命周期控制 (WebView2 / 托盘)
│   │   │   ├── engine.go           # 客户端混合代理核心 (HTTP/SOCKS5 127.0.0.1:55555)
│   │   │   ├── tun.go              # Wintun 虚拟网卡与网络路由接管
│   │   │   ├── proxy_http.go       # HTTP / HTTPS CONNECT 代理服务
│   │   │   ├── proxy_socks5.go     # SOCKS5 代理服务
│   │   │   └── ui/                 # 客户端内嵌轻量前端界面 (HTML/CSS/JS)
│   │   ├── internal/               # 跨端共享领域内核 (解耦支持全平台复用)
│   │   │   ├── clienttunnel/       # gVisor 用户态网络栈与隧道数据流调度
│   │   │   ├── tun/                # 虚拟网卡设备抽象与跨平台驱动对接
│   │   │   ├── sub/                # 订阅拉取、签名防伪校验与节点解析
│   │   │   ├── split/              # 智能分流决策器 (AI 专线 / 直连 / 代理)
│   │   │   ├── h2pool/             # HTTP/2 多路复用连接池
│   │   │   └── api/                # 本地控制 API (端口 19877)
│   │   ├── win/                    # Windows 桌面入口 (main.go -> aerowin)
│   │   │   ├── guard/              # 崩溃守护进程入口 (main.go -> aero-guard)
│   │   │   └── scripts/            # 辅助运维脚本 (recover-network.ps1, connect.ps1)
│   │   ├── cli/                    # 跨平台命令行客户端入口 (main.go -> aerocli)
│   │   ├── android/                # Android 移动端 SDK 桥接 (bridge.go -> VpnService)
│   │   ├── ios/                    # iOS 移动端 SDK 桥接 (ios.go -> NetworkExtension)
│   │   ├── mac/                    # macOS 桌面端入口 (main.go)
│   │   └── linux/                  # Linux 桌面端入口 (main.go)
│   │
│   └── server/                     # Edge 边缘服务端模块 (github.com/aero-protocol/aero-edge)
│       ├── config/                 # 服务端默认配置 (config.yaml)
│       ├── public/                 # 服务端核心协议引擎实现
│       │   ├── server.go           # 服务端主控启动、TLS 加载与端口监听
│       │   ├── handler.go          # HTTP/2 CONNECT 握手与会话调度
│       │   ├── connect.go          # 数据流隧道转发与双向透传
│       │   ├── admin.go            # 边缘节点管理与动态凭证接口
│       │   ├── internal/           # 服务端 10 大核心内部组件
│       │   │   ├── auth/           # Bearer Token 与客户端身份鉴权
│       │   │   ├── trafficguard/   # SSRF 防护、私网 IP 拦截与访问控制
│       │   │   ├── subscribe/      # 动态订阅生成与 HMAC 签名引擎
│       │   │   ├── flow/           # 流量统计与 QoS 限速控制
│       │   │   ├── replay/         # Nonce 防重放攻击防御
│       │   │   ├── cert/           # 自动化证书管理与加载
│       │   │   └── acme/           # Let's Encrypt ACME 自动化证书签发
│       │   └── webui/              # 边缘服务端可视化监控控制台
│       ├── vps/                    # Linux VPS 生产部署入口 (main.go, install.sh)
│       └── cli/                    # 命令行轻量测试服务端入口 (main.go)
│
├── sub/                            # 【子树 2】订阅与资产运维中台 (github.com/vpn-platform/vpsserver)
│   ├── config/                     # 中台统一配置文件 (config.yaml)
│   └── vpn/                        # 中台主程序源码 (生产常驻 Linux VPS，端口 18080)
│       ├── main.go                 # 中台服务总入口
│       ├── data/                   # 核心持久化数据 (aero_endpoints.json, vps.json 密文)
│       ├── internal/
│       │   ├── middleware/         # 安全网关、JWT/HMAC 鉴权、审计日志、跨域控制
│       │   └── modules/            # Clean Architecture 业务模块
│       │       ├── subscription/   # 订阅管理、配置下发 (/api/v1/subscriptions/config/)
│       │       ├── node/           # 节点状态上报、健康检查与探针编排
│       │       ├── vps/            # VPS SSH 自动化部署与 Edge 节点装机
│       │       ├── user/           # 用户管理、权限划分与身份认证
│       │       ├── billing/        # 计费方案、套餐配额与流量周期
│       │       └── pay/            # 支付收单、账本记录与对账结算
│       ├── web/                    # 中台前端界面 (/login, /admin)
│       └── scripts/                # VPS 一键安装脚本 (install.sh)
│
└── connect/                        # 【子树 3】AI 开发者工具代理连接器
    ├── cli/                        # 零依赖极速命令行启动器 (main.go -> connect-cli)
    └── desktop/                    # 跨平台桌面连接器 (github.com/AIsys/connect/desktop)
        ├── config/                 # 连接器配置
        ├── public/                 # 代理多端口并发扫描探测、环境注入与 WebUI
        └── win/                    # Windows 桌面客户端入口 (main.go -> desktop.exe)
```

---

## 二、 三大子系统职责与边界纪律

| 子系统 | 核心职责 | 运行环境 | 边界与纪律（严守） |
| :--- | :--- | :--- | :--- |
| **protocol** | 自主 HTTP/2 CONNECT 隧道、TLS 1.3 / ECH 混淆、Wintun 全局网络接管、跨平台客户端 | 客户端：Windows/macOS/Linux/Android/iOS<br>服务端：Linux VPS（端口 443） | **协议与数据面真源**。仅暴露标准网络代理与订阅拉取，严禁侵入上层业务逻辑。 |
| **sub** | 账号鉴权、节点编排、VPS 自动化安装 Edge、单端口分发订阅配置 | 生产环境：常驻 Linux VPS（端口 18080） | **运营与控制中台**。常驻运行，严禁在开发客户端时随意修改生产 `data/` 目录密文与密钥。 |
| **connect** | 自动发现本地可用代理端口（默认探测 `55555` 等），为 AI 工具一键注入网络环境 | 本地开发机（Windows / macOS） | **纯代理消费者**。零侵入，完全通过网络端口消费代理，与中台源码完全解耦。 |

---

## 三、 核心技术契约与安全机制

### 1. 隧道传输协议
- **加密传输**：底层采用 TLS 1.3 / ECH 加密，结合 uTLS 模拟浏览器客户端指纹（Chrome/Firefox JA3/JA4）；
- **协议握手**：通过 HTTP/2 CONNECT 发起双向流式多路复用通道，在 HTTP 头携带 `Proxy-Authorization: Bearer <token>`；
- **参数协商**：隧道建立后立即执行二进制 Protobuf 握手协商（会话 ID、流量加密套件、流控窗口）；
- **主动伪装**：遭遇未授权探测或非协议流量，服务端无缝反向代理至配置的伪装站点（Cover Site）；
- **SSRF 拦截**：服务端内核配备 `TrafficGuard`，自动解析目标地址并严格封锁回环（`127.0.0.0/8`）与私网（`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`）拨号。

### 2. 订阅签发与防伪验签契约
- **服务端接口**：`GET /sub/{secret}`（单节点直连订阅）或 `/api/v1/subscriptions/config/?uuid=...`（中台集中订阅）；
- **数字签名**：服务端根据节点配置采用 `HMAC-SHA256(token)` 实时对节点列表和有效期进行加签；
- **客户端防篡改**：客户端拉取配置后强制执行 `sub.Verify()`，数据一旦被第三方劫持修改，立即触发签名校验失败并熔断。

### 3. 端口契约对照表
| 默认端口 | 协议类型 | 所属模块 | 用途说明 |
| :--- | :--- | :--- | :--- |
| **443** | TCP (TLS+H2) | `protocol/server` | AERO Edge 边缘隧道监听端口与 HTTPS 服务 |
| **80** | TCP (HTTP) | `protocol/server` | Let's Encrypt ACME 自动化证书申请验证端口 |
| **55555** | TCP (HTTP/SOCKS5) | `protocol/client` | 客户端本地混合代理入口（同时支持 HTTP CONNECT 与 SOCKS5） |
| **19877** | TCP (HTTP) | `protocol/client` | 客户端本地控制 RPC API 端口 |
| **18080** | TCP (HTTP) | `sub/vpn` | 订阅中台生产单端口（集成用户登录、API 与管理后台） |

---

## 四、 极速编译指南

仓库已在根目录配置了完善的 `.gitignore`，不含任何预编译的二进制文件。拉取仓库后，可按需完成单文件编译：

### 1. 编译协议客户端（`protocol/client`）

```powershell
# 1. 编译 Windows 桌面图形客户端 (aerowin.exe)
cd protocol\client\win
go build -o aerowin.exe .

# 2. 编译 Windows 崩溃与防断网守护进程 (aero-guard.exe，与 aerowin 放置同目录)
cd guard
go build -o ..\aero-guard.exe .
cd ..

# 3. 编译 跨平台命令行客户端 (aerocli.exe)
cd ..\cli
go build -o aerocli.exe .

# 4. 交叉编译 macOS / Linux 客户端
cd ..\mac
$env:GOOS='darwin'; go build -o aeromac .; $env:GOOS=''
cd ..\linux
$env:GOOS='linux'; go build -o aerolix .; $env:GOOS=''
```

> **移动端说明**：Android 与 iOS 核心位于 `android/bridge.go` 与 `ios/ios.go`，直接复用 `protocol/client/internal/` 领域内核，可通过 `gomobile bind` 生成原生 AAR 与 XCFramework。

### 2. 编译协议服务端（`protocol/server`）

```bash
# 编译 Linux VPS 生产主程序 (amd64 / x86_64)
cd protocol/server/vps
GOOS=linux GOARCH=amd64 go build -o aero-edge-linux-amd64 .

# 编译 ARM64 VPS 生产主程序 (甲骨文云 / AWS Graviton)
GOOS=linux GOARCH=arm64 go build -o aero-edge-linux-arm64 .

# 编译 命令行调试服务端 (aero-edge-cli)
cd ../cli
go build -o aero-edge-cli.exe .
```

### 3. 编译订阅中台（`sub`）

```bash
# 编译 Linux VPS 生产主程序 (subvps)
cd sub/vpn
GOOS=linux GOARCH=amd64 go build -o subvps .
```

### 4. 编译 AI 工具连接器（`connect`）

```powershell
# 编译 Windows 桌面端 (desktop.exe)
cd connect\desktop\win
go build -o desktop.exe .

# 编译 极速命令行版启动器 (connect-cli.exe)
cd ..\..\cli
go build -o connect-cli.exe .
```

---

## 五、 部署与生产运行指南

### 1. 部署协议服务端（AERO Edge）至 Linux VPS

将编译产物 `aero-edge-linux-amd64` 与脚本复制到目标 VPS：
```bash
# 赋予权限并执行一键安装（自动配置公网证书、生成安全凭证、注册 systemd 服务）
chmod +x install.sh
sudo bash install.sh -d YOUR_DOMAIN -b ./aero-edge-linux-amd64
```
- **服务状态**：`systemctl status aero-edge`
- **查看日志**：`journalctl -u aero-edge -f`
- **存储路径**：`/var/lib/aero/`（存储私钥、证书与 `sub_meta.json` 动态凭证）

### 2. 部署订阅中台（Subplatform）至 Linux VPS

```bash
cd sub/vpn
chmod +x subvps
sudo bash scripts/install.sh
```
- **前台入口**：`http://YOUR_SERVER_IP:18080/login`（用户登录与订阅提取）
- **管理后台**：`http://YOUR_SERVER_IP:18080/admin/`（用户、套餐、财务对账）
- **运维控制台**：`http://YOUR_SERVER_IP:18080/aero-ui/`（可视化 Edge 节点运维）

### 3. 运行协议客户端（用户侧）

- **GUI 客户端**：运行 `aerowin.exe`，托盘常驻，一键开启系统代理或 Wintun 虚拟网卡；
- **CLI 命令行**：
  ```powershell
  .\aerocli.exe -sub "https://YOUR_DOMAIN/sub/SECRET"
  ```
- **辅助脚本一键连**：在 `protocol/client/win/scripts/` 下执行：
  ```powershell
  .\connect.ps1 -Sub "https://YOUR_DOMAIN/sub/SECRET"
  ```

### 4. 启动 AI 工具连接器

- **命令行启动**：运行 `connect-cli.exe`，自动探测本地 `55555` 等代理端口，一键拉起配置好网络环境的 `claude` 或 `codex`；
- **图形桌面版**：运行 `desktop.exe`，提供托盘化图形界面与状态监控。

---

## 六、 自动化全链路模拟回测

系统包含多套经过严格验证的真实模拟回测测试集，运行指令如下：

```powershell
# 1. 协议服务端 TLS + H2 真实握手、Token 拦截与 SSRF 阻断测试
cd protocol\server\public
go test -v -run TestLiveServerHandshake .

# 2. 订阅中台服务启动、登录、节点拉取全链路实测
cd ..\..\..\sub\vpn
go test -v -run TestLiveSubPlatform .

# 3. 客户端订阅解析、防篡改签名与 HTTP 拉取测试
cd ..\..\protocol\client\internal\sub
go test -v -run TestSubscriptionLifecycleAndVerification .

# 4. AI 桌面连接器 55555 代理端口自动发现测试
cd ..\..\..\..\connect\desktop\public
go test -v -run TestDetectProxies .
```

---

## 七、 运维排障与应急恢复

### 1. VPS 节点一键彻底干净卸载指令
如果在测试过程中需要从 VPS 上彻底清除 Edge 服务端环境，在 VPS 终端执行：
```bash
systemctl stop aero-edge 2>/dev/null; systemctl disable aero-edge 2>/dev/null
pkill -9 -x aero-edge 2>/dev/null
rm -f /etc/systemd/system/aero-edge.service
systemctl daemon-reload
rm -rf /opt/aero /var/lib/aero /etc/aero /usr/local/bin/aero-edge /var/log/aero-edge.log
```

### 2. Windows 本地网络与代理异常应急恢复
若异常终止导致系统代理未关闭，在 PowerShell 执行：
```powershell
powershell -ExecutionPolicy Bypass -File protocol\client\win\scripts\recover-network.ps1
```
自动刷新并清除注册表 WinINET 系统代理、清空 PAC 地址并重置网络路由。
