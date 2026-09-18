# AIsys Workspace Architecture & Agent Disciplines

**工作根目录（唯一主仓）：** `D:\jacky\gemini\aisys`

| 子树 | 职责定位 | 核心交付物 |
| :--- | :--- | :--- |
| `protocol/` | 自主隧道协议、跨平台客户端引擎与 VPS Edge 服务端 | `protocol/client` (aerowin, aerocli, aero-guard)<br>`protocol/server` (aero-edge, webui) |
| `sub/` | 订阅运营中台与 VPS 节点运维（单端口多模块，生产常驻 Linux VPS） | `sub/vpn` (`subvps` 生产程序，端口 18080) |
| `connect/` | AI 桌面/终端开发者代理自动发现与环境注入 | `connect/desktop` (desktop.exe)<br>`connect/cli` (connect-cli.exe) |

---

## 跨树边界与架构契约

- **绝对禁止源码跨树 Import**：三大子树（`protocol`、`sub`、`connect`）必须保持物理和逻辑解耦，各自拥有独立 `go.mod`。
- **允许的交互途径**：标准 HTTP REST / JSON API、标准本地网络端口（如 AERO 混合代理 `127.0.0.1:55555`）、二进制交付物、进程隔离执行。
- **协议真源 (`protocol`)**：核心协议数据面、TLS/ECH 伪装、Protobuf 协商与分流引擎在此闭环。客户端秉持“瘦客户端（Thin Client）”设计，只执行轻量 DNS RTT 测速并向服务端传递 `?isp=` 参数，绝不在客户端维护臃肿规则。
- **订阅运营 (`sub`)**：账号、节点编排、VPS 自动化安装、自适应 SNI 矩阵计算与单端口订阅分发。
- **连接管理 (`connect`)**：纯代理消费者，扫描本地可用代理并启动 Claude Code / Codex / Aider 等 AI 开发工具。

---

## 常用路径与关键代码真源

```text
# 1. 协议服务端 (protocol/server)
protocol/server/public/server.go              # 服务端核心初始化与监听入口
protocol/server/public/handler.go             # HTTP/2 CONNECT 握手与请求分发
protocol/server/public/internal/              # 服务端内部模块 (auth, trafficguard, subscribe 等)
protocol/server/vps/main.go                   # Linux VPS 生产主程序入口
protocol/server/vps/install.sh                # Edge 服务端 Linux VPS 一键部署脚本
protocol/server/cli/main.go                   # 命令行轻量测试服务端入口

# 2. 协议客户端 (protocol/client)
protocol/client/win/main.go                   # Windows 桌面 GUI 客户端入口 (aerowin)
protocol/client/win/guard/main.go             # Windows 崩溃与防断网守护进程 (aero-guard)
protocol/client/win/scripts/recover-network.ps1 # Windows 紧急网络与代理恢复脚本
protocol/client/cli/main.go                   # 跨平台命令行客户端入口 (aerocli)
protocol/client/public/                       # PC 桌面端核心引擎与 WebUI 界面
protocol/client/internal/                     # 跨端共享领域层 (clienttunnel, tun, sub, split 等)
protocol/client/android/bridge.go             # Android VpnService JNI 桥接
protocol/client/ios/ios.go                    # iOS PacketTunnel 框架桥接

# 3. 订阅中台 (sub/vpn)
sub/vpn/main.go                               # 中台生产源码入口 (端口 18080)
sub/vpn/config/config.yaml                    # 中台默认配置
sub/vpn/internal/modules/subscription/        # 订阅生成、配置拉取与节点映射
sub/vpn/internal/modules/subscription/snimatrix/ # 运营商与地区自适应 SNI 矩阵计算引擎
sub/vpn/internal/modules/vps/                 # VPS SSH 探针与 Edge 自动化安装
sub/vpn/internal/middleware/                  # 安全网关、鉴权 Token、审计中间件
sub/vpn/data/                                 # 生产持久化存储 (vps.json, aero_endpoints.json, sni_matrix.json)
sub/vpn/scripts/install.sh                    # 中台 Linux VPS 一键部署脚本

# 4. AI 连接器 (connect)
connect/desktop/win/main.go                   # Windows AI Desktop 客户端入口
connect/desktop/public/proxy.go               # 本地多端口代理自动扫描发现
connect/cli/main.go                           # AI 终端极速代理启动器 CLI

# 5. 公共视觉资产
assets/                                       # 全系统统一品牌资产真源 (icon.ico, icon.png 等)
sync-assets.ps1                               # 品牌资产一键分发同步脚本
```

---

## 启动与维护纪律（严守）

| 模块 | 常驻属性 | 维护纪律 |
| :--- | :--- | :--- |
| **sub/vpn** (`subvps`) | **常驻生产**（Linux VPS 守护） | **严禁** 改动生产 `data/` 目录中的密钥持久化文件；本地测试严禁破坏生产库。所有数据持久化需使用原子落盘（`.tmp` -> `.json`）。 |
| **protocol/server** (`aero-edge`) | **常驻生产**（Linux VPS systemd 守护） | **严禁** 因客户端改动随意重装 VPS 边缘节点。 |
| **protocol/client** | 用户按需启动 | 修改客户端仅允许改动 `protocol/client` 内部；严禁侵入 `sub` 进程与数据。保持 Thin Client，不引入臃肿依赖。 |
| **connect** | 用户按需启动 | 纯代理消费方，完全不依赖 `sub` 源码。 |
| **Git 纪律** | 全局准则 | **未经用户明确授权，绝对禁止执行 `git push`**。保持本地提交原子性与代码卫生。 |
