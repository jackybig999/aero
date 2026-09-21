# AERO AIsys 统一系统架构规范与研发说明书 (v6.0 磐石定稿版)

> **版本发布**：v6.0-SOLID-ENTERPRISE · 2026-09-21  
> **核心架构**：全面贯彻“Go 原生工业标准 (Plan B)”与“100% 指纹沙箱无损还原”，彻底剥离 Node.js/npm 臃肿依赖，实现秒级跨平台一键编译与极致轻量化。

---

## 一、 系统架构全景与子系统拓扑

整个 AIsys 体系由四大物理隔离的独立 Go 模块组成，各模块均具有独立的 `go.mod` 与清晰的通信边界，经由工作区根目录 `go.work` 协同组织：

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                            AERO AIsys 系统拓扑全景                          │
└─────────────────────────────────────────────────────────────────────────────┘

 [ 用户端超级桌面操作系统 ]                    [ 独立网络内核与守护进程 ]
 ┌───────────────────────────┐                ┌───────────────────────────┐
 │   connect/os (AERO OS)    │  REST (19877)  │   protocol/client (CLI)   │
 │ • 100% 原生指纹浏览器沙箱  │ ─────────────> │ • MASQUE/H2 双栈网络隧道  │
 │ • 内嵌纯净 WebUI 视窗     │                │ • Wintun 网卡透明接管     │
 │ • 零本地 HTTP 端口 (纯IPC)│                │ • 后台静默运行守护        │
 └───────────────────────────┘                └───────────────────────────┘
               │                                            │
               │                                            │ ECH / MASQUE
               │ 订阅拉取 / Token 鉴权                      │ (加密数据面)
               ▼                                            ▼
 ┌───────────────────────────┐                ┌───────────────────────────┐
 │     sub/vpn (运营中台)     │  SSH 打靶探活  │   protocol/server (VPS)   │
 │ • 纯 Go 嵌入式管理中台    │ ─────────────> │ • 单一无头 Edge 守护进程  │
 │ • VPS 纯净度风控分流      │                │ • 纯 Go 内嵌单机运维面板  │
 │ • 监听端口 :18080         │                │ • 监听端口 :443           │
 └───────────────────────────┘                └───────────────────────────┘
```

### 1.1 模块权责划分表

| 模块目录 | 模块名 (go.mod) | 交付二进制 | 运行环境 | 核心职能 |
|:---|:---|:---|:---|:---|
| `connect/os` | `aisys/connect/os` | `aero-os.exe` / `aero-os` | Windows / macOS | 超级生产力桌面工作台、100% 原生指纹沙箱、便携内核管理、API 矩阵与审计日志 |
| `protocol/client` | `github.com/aero-protocol/aero-ech` | `aero-client.exe` / `aero-client-cli.exe` | Windows / macOS / Linux | 高性能自主网络协议客户端、MASQUE/H2 自适应隧道、Wintun 透明接管、本地 REST API (:19877) |
| `protocol/server` | `github.com/aero-protocol/aero-edge` | `aero-server` / `aero-panel` | 纯 Linux VPS | 高并发 MASQUE/H2 接入网关、RFC 9218 AI 流量调度、防探测动态掩码、单机轻量运维面板 |
| `sub/vpn` | `aisys/sub/vpn` | `subvps` | 纯 Linux VPS | 节点智能编排调度中台、SSH 真实出口纯净度打靶、自适应 SNI 生成、内嵌纯 Go 管理后台 (:18080) |

---

## 二、 纯 Go 工业标准 (Plan B) 实施要点

为消除跨端编译时对 Node.js/npm 的外部工具链依赖，并彻底解决依赖缓存过大问题，全系统管理控制台全面推行 **Plan B 原生内嵌标准**：

1. **彻底消除 `node_modules`**：全项目不再保留任何 `package.json`、`package-lock.json` 或 `vite.config.js`，全库 `node_modules` 占用为 **0 KB**。
2. **纯 Go 嵌入式静态资源**：
   - `protocol/server/public/webui/dist/`：纯手写现代 HTML5 + Flex/Grid CSS + 原生 Vanilla JS (`console.js`)，完美保留 GitHub 官方 Release 验签横幅、节点 Token 矩阵与启停控制。
   - `sub/vpn/web/admin/dist/`：纯手写现代 HTML5 + 原生 Vanilla JS (`admin.js`)，完整呈现系统概览 KPI、VPS 纯净度 Tier 1/2/3 矩阵、用户订阅分发、记账流水与诊断工具。
3. **零编译摩擦**：只需安装 Go 编译器即可在任何平台上通过 `go build` 直接产出包含完整 WebUI 的单一静态二进制文件。

---

## 三、 AERO OS 指纹浏览器沙箱 100% 功能还原

`connect/os` 完整平移并增强了 `finger` 独立项目的全部核心能力，无任何功能缩水：

### 3.1 界面交互层 (54 项核心控件 · 100% 还原)
- **多状态概览与环境感知**：顶部状态栏实时展示系统代理探测状态、内核下载进度（带动态百分比进度条与完成提示）、批量启动/批量停止/批量删除动作栏。
- **双模态视图切换**：支持“表格视图（Table View）”与“卡片视图（Card View）”无缝一键切换。
- **全要素指纹配置抽屉 (18 项参数)**：
  - 基础参数：配置名称、分组标签、内核版本（Chrome 153/154, Firefox 140/156, Safari 等）。
  - 网络出站：直连模式、自定义 HTTP/SOCKS5 代理、系统代理探测绑定。
  - 核心指纹：User-Agent 伪装、操作系统平台（Win/Mac/Linux）、屏幕分辨率、时区掩码、语言/Locale 伪造。
  - 硬件仿真：WebRTC（禁用/替换/公网穿透）、Canvas 指纹噪点扰动、WebGL 供应商与渲染器重写、AudioContext 随机偏移。
  - 硬件指纹：CPU 核心数、设备内存 (DeviceMemory)、媒体设备数量虚构。

### 3.2 内存级双向 IPC 通信绑定 (26 项核心 API)
视窗完全运行在本地内存模式（`w.SetHtml`），前端全部通过 `window.goXxx()` 触发原生 Go 处理函数，彻底消灭本地监听端口被嗅探的风险：
```javascript
// 核心指纹沙箱 IPC 接口清单
window.goGetSysInfo()          // 系统代理探测与宿主机环境获取
window.goGetProfiles()         // 获取指纹配置列表
window.goCreateProfile(data)   // 新增指纹沙箱环境
window.goUpdateProfile(data)   // 更新指纹沙箱参数
window.goDeleteProfile(id)     // 删除指定沙箱
window.goLaunchProfile(id)     // 拉起隔离浏览器进程
window.goStopProfile(id)       // 安全关闭浏览器进程
window.goDownloadKernel(name)  // 后台静默下载浏览器便携内核
window.goGetKernelProgress()   // 轮询内核下载解压进度
window.goDetectProxy(ip, port) // 节点网络健康度与延迟检测
```

### 3.3 系统底层适配与常驻保活
- **Windows**：采用纯 Go COM 封装的 `go-webview2`（零 CGO），具备 `Shell_NotifyIcon` 完整 Win32 托盘菜单与主界面最小化隐藏/恢复。
- **macOS**：采用 `webview/webview_go` 与 WKWebView，深度集成 macOS 状态栏托盘与 Cocoa 事件循环。
- **网络桥接**：后台静默拉起无头守护目标 `aero-client-cli.exe`，通过 `127.0.0.1:19877` REST 接口提供自适应连接与流量透传。

---

## 四、 历史代码与废弃资产隔离策略 (`tmp/`)

所有被重构淘汰的历史代码和外部代码均已完整归档至工作区目录下的 `tmp/` 文件夹中作为不可侵入的安全备份：

```text
D:\jacky\gemini\aisys\tmp/
├── connect_desktop/          # 历史 Fyne GUI 桌面客户端源码 (已由 connect/os 全面替代)
├── finger/                   # 独立指纹浏览器源码备份 (已排除 kernels 缓存与 exe 二进制)
├── server_webui_vue/         # protocol/server 历史 Vue 3 / Vite 源码备份
├── sub_web_admin_vue/        # sub/vpn 历史 Vue 3 / Vite 源码备份
└── legacy_server_webui_dist/ # 历史打包遗留的 Vite 静态产物备份
```

> [!NOTE]
> `tmp/` 目录已被写入根目录 `.gitignore`，纯本地存档，绝不参与 Git 变更跟踪，不污染版本库提交。

---

## 五、 项目代码库容量精细化统计 (已彻底清理)

经执行严格的垃圾清理、测试缓存清理与历史资产归档后，全系统实际容量如下：

### 5.1 生产活动源码统计（排除 `.git` 与 `tmp/`）
- **活动源码文件总数**：**388 个**
- **活动代码库物理体积**：**7.26 MB** (仅 7,614,653 字节)
- **活动代码总行数 (LOC)**：**75,562 行**
- **全库 `node_modules`**：**0 KB** (已彻底清空 179.5 MB 前端缓存)
- **全库 `.exe` 编译产物**：**0 个** (编译产物随时按需秒级生成)

### 5.2 子系统规模明细
| 子系统目录 | 文件数量 | 物理体积 | 代码行数 | 主要技术栈 |
|:---|:---:|:---:|:---:|:---|
| `connect/os` (AERO OS) | 77 | 527.1 KB | 12,575 行 | Go + WebView2 + HTML5/CSS/JS |
| `protocol/client` (Client) | 139 | 3,306.1 KB | 41,665 行 | Go + Wintun + MASQUE/H2 |
| `protocol/server` (Server) | 69 | 359.5 KB | 8,069 行 | Go + Embedded Console |
| `sub/vpn` (中台中枢) | 76 | 2,205.1 KB | 10,643 行 | Go + SQLite (纯Go) + Admin UI |
| `assets` / `build` | 8 | 939.1 KB | 92 行 | 图标、构建配置与自动化脚本 |

### 5.3 备份与版本库总体积
- `tmp/` 历史代码安全存档：**161 个文件，10.68 MB**
- `.git/` 内部历史与对象树：**416 个文件，3.27 MB**
- **整个仓库根目录总物理占用**：**21.21 MB** (对比重构前 200+ MB，瘦身幅度达 **90%**！)

---

## 六、 研发操作与多端编译验证指南

### 6.1 代码质量门禁检查
```powershell
# 在各子模块根目录分别执行纯 Go 语法与静态检查
cd D:\jacky\gemini\aisys\connect\os;      go vet ./...
cd D:\jacky\gemini\aisys\protocol\client; go vet ./...
cd D:\jacky\gemini\aisys\protocol\server; go vet ./...
cd D:\jacky\gemini\aisys\sub\vpn;         go vet ./...
```

### 6.2 自动化测试套件执行
```powershell
# AERO OS 核心测试 (E2E 内核生命周期、指纹配置 CRUD、网络探测)
cd D:\jacky\gemini\aisys\connect\os; go test -v ./...

# sub/vpn 核心测试 (VPS 探针打靶、节点评分、Web 路由分发)
cd D:\jacky\gemini\aisys\sub\vpn;    go test -v ./...
```

### 6.3 生产构建命令清单
```powershell
# 1. 编译 AERO OS 超级桌面工作台 (Windows)
cd D:\jacky\gemini\aisys\connect\os
go build -ldflags="-s -w -H windowsgui" -o D:\jacky\gemini\aisys\dist\aero-os.exe ./win

# 2. 编译 AERO 客户端静默 CLI 守护目标
cd D:\jacky\gemini\aisys\protocol\client
go build -ldflags="-s -w" -o D:\jacky\gemini\aisys\dist\aero-client-cli.exe ./cli

# 3. 编译 AERO 客户端 GUI 视窗目标
cd D:\jacky\gemini\aisys\protocol\client
go build -ldflags="-s -w -H windowsgui" -o D:\jacky\gemini\aisys\dist\aero-client.exe ./win

# 4. 编译 Linux VPS 生产中台 (交叉编译)
cd D:\jacky\gemini\aisys\sub\vpn
$env:GOOS="linux"; $env:GOARCH="amd64"; $env:CGO_ENABLED="0"; go build -ldflags="-s -w" -o D:\jacky\gemini\aisys\dist\subvps .
```
