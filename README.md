# AIsys — 全平台自主高匿协议、订阅中台与 AI 连接套件

> **项目定位**：面向现代网络环境的高性能自主加密隧道协议（AERO）、多 VPS 订阅运营中台（Subplatform）与 AI 开发者连接套件（Connect）。  
> **设计哲学**：**瘦客户端（Thin Client）**、**服务端智能编排**、**物理逻辑完全解耦**、**崩溃断网自愈**。

[![Go Version](https://img.shields.io/badge/Go-1.24%2B-00ADD8?style=flat&logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Architecture](https://img.shields.io/badge/Arch-Decoupled%20Subtrees-brightgreen.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS%20%7C%20Android%20%7C%20iOS-orange.svg)]()
[![Tests](https://img.shields.io/badge/Tests-Passing%20(0%20Race)-success.svg)]()

---

## 目录导航

- [一、 核心系统特性](#一-核心系统特性)
- [二、 系统架构全景](#二-系统架构全景)
- [三、 新手 3 分钟极速上手](#三-新手-3-分钟极速上手)
  - [1. 终端使用者（桌面 GUI / 命令行）](#1-终端使用者桌面-gui--命令行)
  - [2. 节点与中台管理员（Linux VPS 生产部署）](#2-节点与中台管理员linux-vps-生产部署)
  - [3. AI 开发者（终端工具一键联网）](#3-ai-开发者终端工具一键联网)
- [四、 核心设计与契约机制](#四-核心设计与契约机制)
  - [1. 服务端自适应 SNI 矩阵（Thin Client）](#1-服务端自适应-sni-矩阵thin-client)
  - [2. 多 VPS 双轨容灾与无感切换](#2-多-vps-双轨容灾与无感切换)
  - [3. 协议数据面与高匿伪装](#3-协议数据面与高匿伪装)
  - [4. 端口与契约对照表](#4-端口与契约对照表)
- [五、 全模块编译指南](#五-全模块编译指南)
- [六、 自动化测试与全链路回测](#六-自动化测试与全链路回测)
- [七、 运维排障与应急自愈](#七-运维排障与应急自愈)
- [八、 架构纪律与治理规范](#八-架构纪律与治理规范)

---

## 一、 核心系统特性

1. **极致轻量瘦客户端（Thin Client）**：
   - 客户端保持最小化体积与单一职责（仅负责本地混合代理、轻量 ISP RTT 探测与隧道握手）；
   - 所有复杂的运营商测速矩阵、SNI 伪装匹配规则均由服务端集中运算与热更新，客户端零规则包袱、无内存暴涨风险。
2. **自主 AERO 隧道协议与智能分流**：
   - 基于 **HTTP/2 CONNECT** 双向多路复用，集成 **uTLS** 模拟标准浏览器指纹（Chrome / Firefox）；
   - 自研二进制 Protobuf 握手协商与会话复用，内嵌 `TrafficGuard` 严格防御 SSRF 与私网回环穿透；
   - 支持智能路由分流（国内域名/IP 直连，AI 专线与国际流量走加密隧道），集成 Wintun 虚拟网卡接管。
3. **服务端动态自适应 SNI 矩阵（ISP-Aware Matrix）**：
   - 针对国内不同电信运营商（中国电信、中国联通、中国移动）及跨国 VPS 节点区位（美、日、欧、新等），服务端实时下发最佳握手伪装域名与优化参数。
4. **多 VPS 双轨容灾与毫秒级热备（EdgePool）**：
   - 订阅拉取具备多 VPS 自动故障切换（Failover Fetch）；
   - 运行时内建 `EdgePool` 动态连接池与智能探针，主节点异常毫秒级平滑跳频至备用节点，保障 AI 长连接对话不中断。
5. **AI 开发者极速连接套件（Connect）**：
   - 零依赖自动扫描本地代理端口（`55555` 等），一键向 Claude Code、OpenAI Codex、Aider 等研发终端注入标准代理环境变量，秒级就绪。
6. **崩溃自愈与断网防恐慌机制**：
   - 配套独立进程守护器（`aero-guard`）监控核心生命周期；
   - 提供应急一键还原脚本（`recover-network.ps1`），即使遭遇断电或异常崩溃，系统代理与路由表瞬间安全回滚。

---

## 二、 系统架构全景

系统由三大**物理解耦、各自独立 `go.mod`** 的核心子树构成，禁止跨树源码导入，确保绝对高内聚、低耦合：

```text
AIsys/
├── assets/                         # 全系统统一品牌视觉资产 (icon.ico, icon.png 等)
├── sync-assets.ps1                 # 资产一键跨平台分发同步脚本
│
├── protocol/                       # 【子树 1】自主隧道协议与跨端客户端套件
│   ├── client/                     # 客户端引擎 (github.com/aero-protocol/aero-ech)
│   │   ├── config/                 # 客户端默认配置 (config.yaml)
│   │   ├── win/                    # Windows 桌面 GUI 入口 (aerowin.exe)
│   │   │   ├── guard/              # 进程监控与防断网守护源码 (aero-guard.exe)
│   │   │   └── scripts/            # 运维脚本 (recover-network.ps1, connect.ps1)
│   │   ├── cli/                    # 跨平台命令行客户端入口 (aerocli.exe)
│   │   ├── public/                 # PC 桌面端核心引擎、混合代理 (55555) 与内嵌 WebUI
│   │   ├── internal/               # 跨端共享领域层 (tun, clienttunnel, sub, split, h2pool, gameqos)
│   │   ├── android/                # Android VpnService JNI 移动端桥接
│   │   ├── ios/                    # iOS PacketTunnel 移动端桥接
│   │   ├── mac/                    # macOS 桌面端入口
│   │   └── linux/                  # Linux 桌面端入口
│   └── server/                     # Edge 边缘服务端模块 (github.com/aero-protocol/aero-edge)
│       ├── config/                 # 服务端默认配置
│       ├── public/                 # 服务端核心协议引擎 (TLS 1.3 / H2 CONNECT / Nonce / TrafficGuard)
│       ├── vps/                    # Linux VPS 生产主程序入口 (aero-edge) 与 install.sh
│       └── cli/                    # 命令行轻量测试服务端入口
│
├── sub/                            # 【子树 2】订阅与节点运营中台 (github.com/vpn-platform/vpsserver)
│   └── vpn/                        # 中台主程序源码 (生产常驻 Linux VPS，端口 18080)
│       ├── main.go                 # 中台服务总入口
│       ├── data/                   # 核心持久化存储 (vps.json, aero_endpoints.json, sni_matrix.json)
│       ├── internal/
│       │   ├── middleware/         # 安全网关、鉴权 Token、审计与限流
│       │   └── modules/            # Clean Architecture 业务模块
│       │       ├── subscription/   # 订阅分发、动态多用户 Slug 与 SNI 矩阵引擎
│       │       ├── vps/            # VPS SSH 探针与 Edge 自动化安装编排
│       │       ├── node/           # 节点状态上报与健康检查
│       │       ├── user/           # 用户管理与认证体系
│       │       └── pay/            # 账本与财务结算
│       ├── web/                    # 中台管理控制台前端
│       └── scripts/                # VPS 一键安装与系统初始化脚本
│
└── connect/                        # 【子树 3】AI 开发者工具代理连接器
    ├── cli/                        # 零依赖极速终端启动器 (connect-cli.exe)
    └── desktop/                    # 桌面跨平台连接管理器 (desktop.exe)
        └── public/                 # 本地代理端口并发探针与环境注入逻辑
```

---

## 三、 新手 3 分钟极速上手

### 1. 终端使用者（桌面 GUI / 命令行）

#### 方式 A：Windows 图形化客户端（推荐普通用户）
1. 编译或下载 `aerowin.exe`（与配套的 `wintun.dll`、`aero-guard.exe` 置于同目录）；
2. 双击启动 `aerowin.exe`，托盘将出现系统图标；
3. 打开配置面板，输入你的订阅地址（如 `https://your-domain.com/sub/YOUR_KEY`）；
4. 点击「启动代理」：
   - 默认开启**系统混合代理**（HTTP/SOCKS5 混合监听于 `127.0.0.1:55555`）；
   - 可在界面一键切换为 **TUN 虚拟网卡全局模式** 接管全机网络。

#### 方式 B：跨平台极速命令行（推荐开发者）
```powershell
# 启动命令行客户端并直接载入订阅（自动后台匹配运营商与 SNI 伪装）
.\aerocli.exe -sub "https://your-domain.com/sub/YOUR_KEY"

# 指定本地代理端口并输出详细日志
.\aerocli.exe -sub "https://your-domain.com/sub/YOUR_KEY" -addr "127.0.0.1:55555" -v
```

---

### 2. 节点与中台管理员（Linux VPS 生产部署）

#### 第一步：部署 Edge 协议边缘节点（单机或多机 VPS）
登录你的 Linux VPS，运行一键安装脚本（自动拉取/部署、申请 Let's Encrypt 证书、注册守护服务）：
```bash
# 下载一键安装脚本并赋予执行权限
chmod +x install.sh

# 自动绑定域名并安装运行（以 amd64 为例）
sudo bash install.sh -d your-node-domain.com -b ./aero-edge-linux-amd64
```
- **查看运行状态**：`systemctl status aero-edge`
- **查看实时日志**：`journalctl -u aero-edge -f`
- 安装完成后，终端将打印该节点的专用直连订阅链接及管理密钥。

#### 第二步：部署中台运营平台（集中管理多节点与订阅）
在管理机或主控 VPS 上运行中台程序：
```bash
cd sub/vpn
chmod +x subvps
sudo bash scripts/install.sh
```
- **中台登录入口**：`http://YOUR_SERVER_IP:18080/login`
- **节点与订阅管理**：在后台直观录入 VPS SSH 凭据，中台自动探针下发、统一聚合订阅并自动提供动态 SNI 伪装。

---

### 3. AI 开发者（终端工具一键联网）

针对使用 Claude Code、Aider、OpenAI Codex、Copilot CLI 等工具的开发者，无需繁杂配置环境变量：
```powershell
# 1. 确保客户端已启动（本地代理 55555 正在运行）
# 2. 执行 connect-cli 自动探测代理并启动你的 AI 工具：
.\connect-cli.exe claude

# 或启动 Aider
.\connect-cli.exe aider
```
`connect-cli` 会自动在 20 毫秒内扫描本地存活的代理端口，为当前子进程安全注入 `HTTP_PROXY`、`HTTPS_PROXY` 与 `ALL_PROXY`，命令退出后不污染系统全局变量。

---

## 四、 核心设计与契约机制

### 1. 服务端自适应 SNI 矩阵（Thin Client）

```text
┌─────────────────┐       ① 带运营商指纹请求订阅 (?isp=ChinaTelecom)       ┌────────────────────────┐
│  AERO 瘦客户端  │ ───────────────────────────────────────────────────► │  订阅中台 / Edge 服务  │
│ (仅 10MB，零规则)│ ◄─────────────────────────────────────────────────── │ (内存矩阵热匹配算法)  │
└─────────────────┘       ② 下发经过地区与 ISP 优选计算后的节点配置与 SNI      └────────────────────────┘
         │
         ▼ ③ 直接使用定制 SNI 发起 TLS 1.3 + uTLS 握手
┌─────────────────┐
│ VPS 边缘服务器  │ (完美伪装成目标主流域名，审查设备无从识别与特征封锁)
└─────────────────┘
```
- **轻量至上**：客户端不需要加载庞大的测速字典或定期更新规则，只在订阅拉取时基于 DNS RTT 携带自身运营商标签（`ChinaTelecom`、`ChinaUnicom`、`ChinaMobile`）；
- **服务端热更**：中台维护 `sub/vpn/data/sni_matrix.json`，根据 VPS 国家地区（US、HK、JP、SG 等）与 ISP 分布实时映射最优伪装站点，零停机毫秒级生效。

### 2. 多 VPS 双轨容灾与无感切换

- **订阅拉取容灾（Failover Fetch）**：客户端配置文件支持多个备用 VPS 节点。当首选订阅 URL 网络中断时，自动降级至备用 VPS 节点拉取最新配置；
- **传输层热切换（EdgePool Live Switch）**：客户端内建连接池管理多条节点长连接。网络丢包或节点抖动时，在 50ms 内透明将数据流迁移至备用节点，保障 AI 流式输出不中断。

### 3. 协议数据面与高匿伪装

- **双向 HTTP/2 CONNECT 隧道**：完全符合 RFC 9113 / RFC 8441 标准，所有流量封装于标准化 HTTPS 流中；
- **防重放与认证**：握手头携带经过加盐哈希的 Bearer Token，隧道内发起 Protobuf 握手协商，集成 Nonce 窗滑动拦截重放攻击；
- **物理 SSRF 拦截（TrafficGuard）**：边缘服务端内置私网防护防火墙，强制阻断发往 `127.0.0.1`、`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16` 等内网段的请求；
- **Cover Site 主动伪装**：任何非协议探测或非法嗅探请求，服务端透明反向代理至指定的知名站点（如主流公开 CDN），无特征暴露。

### 4. 端口与契约对照表

| 默认端口 | 协议类型 | 所属模块 | 用途与安全性 |
| :--- | :--- | :--- | :--- |
| **443** | TCP (TLS 1.3 / H2) | `protocol/server` | AERO Edge 边缘隧道与伪装 HTTPS 入口 |
| **80** | TCP (HTTP) | `protocol/server` | Let's Encrypt ACME 自动化证书签发与续期验证 |
| **55555** | TCP (HTTP / SOCKS5)| `protocol/client` | 客户端本地混合代理入口（应用、浏览器或 AI 工具连接） |
| **19877** | TCP (HTTP REST) | `protocol/client` | 客户端本地控制 RPC 接口（GUI 与 Engine 通信） |
| **18080** | TCP (HTTP) | `sub/vpn` | 订阅中台生产聚合端口（包含用户端、管理后台与订阅分发） |

---

## 五、 全模块编译指南

本仓库为纯源码仓库，无垃圾二进制。编译环境要求 **Go 1.24+**：

### 1. 编译客户端套件（`protocol/client`）

```powershell
# 1. 编译 Windows 桌面 GUI 客户端 (aerowin.exe)
cd protocol\client\win
go build -ldflags "-s -w" -o aerowin.exe .

# 2. 编译 Windows 进程守护器 (aero-guard.exe，放置于与 aerowin 相同目录)
cd guard
go build -ldflags "-s -w" -o ..\aero-guard.exe .
cd ..

# 3. 编译 跨平台命令行版客户端 (aerocli.exe)
cd ..\cli
go build -ldflags "-s -w" -o aerocli.exe .

# 4. 交叉编译 Linux / macOS 客户端
cd ..\linux
$env:GOOS='linux'; go build -ldflags "-s -w" -o aerolix .; $env:GOOS=''
cd ..\mac
$env:GOOS='darwin'; go build -ldflags "-s -w" -o aeromac .; $env:GOOS=''
```

### 2. 编译服务端（`protocol/server`）

```bash
# 编译 Linux VPS 生产程序 (x86_64 / amd64)
cd protocol/server/vps
GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o aero-edge-linux-amd64 .

# 编译 ARM64 VPS 生产程序 (甲骨文云 / AWS Graviton)
GOOS=linux GOARCH=arm64 go build -ldflags "-s -w" -o aero-edge-linux-arm64 .

# 编译 本地轻量调试命令行版
cd ../cli
go build -o aero-edge-cli.exe .
```

### 3. 编译订阅中台（`sub/vpn`）

```bash
# 编译生产主控程序 (subvps)
cd sub/vpn
GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o subvps .
```

### 4. 编译 AI 连接器（`connect`）

```powershell
# 编译 极速终端 CLI 启动器 (connect-cli.exe)
cd connect\cli
go build -ldflags "-s -w" -o connect-cli.exe .

# 编译 桌面连接器 (desktop.exe)
cd ..\desktop\win
go build -ldflags "-s -w" -o desktop.exe .
```

---

## 六、 自动化测试与全链路回测

仓库包含完备的自动化回测测试用例，可对真实握手、并发切换与防伪签名进行一键验证：

```powershell
# 1. 客户端订阅生命周期、HMAC 防篡改验证与多 VPS 容灾回测
cd protocol\client\internal\sub
go test -v -run "TestSubscription" .

# 2. 真实双 VPS 节点 H2 CONNECT 握手与并发热切换回测
cd ..\..\public
go test -v -run "TestLive" .

# 3. 订阅中台自适应 SNI 矩阵计算与回退匹配单测
cd ..\..\..\sub\vpn\internal\modules\subscription
go test -v ./...

# 4. AI 开发者连接器本地多代理端口并发发现探测测试
cd ..\..\..\..\connect\desktop\public
go test -v -run "TestDetectProxies" .
```

---

## 七、 运维排障与应急自愈

### 1. Windows 本地网络与代理异常恢复
若遭遇断电、强制关机或客户端异常退出导致浏览器无法上网（系统代理未解绑）：
- 进入目录 `protocol/client/win/scripts/`；
- 右键以管理员身份运行或在 PowerShell 执行：
  ```powershell
  powershell -ExecutionPolicy Bypass -File protocol\client\win\scripts\recover-network.ps1
  ```
- 脚本将秒级完成注册表 WinINET 代理清理、PAC 脚本复位与路由表重置，100% 恢复正常网络。

### 2. VPS 边缘节点一键彻底干净卸载
若需要从 VPS 上完全清理 AERO 服务端环境：
```bash
sudo systemctl stop aero-edge 2>/dev/null; sudo systemctl disable aero-edge 2>/dev/null
sudo pkill -9 -x aero-edge 2>/dev/null
sudo rm -f /etc/systemd/system/aero-edge.service
sudo systemctl daemon-reload
sudo rm -rf /opt/aero /var/lib/aero /etc/aero /usr/local/bin/aero-edge /var/log/aero-edge.log
```

---

## 八、 架构纪律与治理规范

为了维护系统的长期稳定与可维护性，所有开发者及协同智能体必须严格遵循以下纪律：

1. **绝对禁止跨树源码导入**：
   - `protocol/`、`sub/`、`connect/` 三大子树各自治理，严禁互相 `import` 代码。只能通过标准网络协议、端口或 JSON 契约通信。
2. **生产持久化数据零破坏**：
   - `sub/vpn/data/` 目录中的 `vps.json`、`aero_endpoints.json` 与 `sni_matrix.json` 为生产密文与配置真源，本地测试绝不可将其覆盖或污染。文件写入必须采用原子落盘机制（`.tmp` -> `.json` 重命名）。
3. **安全准则**：
   - 严禁在未经用户明确授权的情况下执行 `git push`；
   - 保持客户端体积小巧与零入侵，坚决不向客户端引入臃肿无关的第三方依赖。

---

## 开源协议

本项目采用 [Apache-2.0 License](LICENSE) 授权。
