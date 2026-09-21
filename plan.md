# AERO AIsys 全系统重构实施总纲【磐石终极定稿版】

> **版本标识**：v6.0-SOLID-ENTERPRISE · **最后更新**：2026-09-20  
> **核心纪律**：**未经用户明确授权，绝对禁止执行 `git push`**；三树隔离、单目录单 main、生产数据绝对冻结。

---

## 一、 架构全景与系统拓扑

### 1.1 跨树物理与逻辑隔离契约
三大子树保持绝对解耦，各自拥有独立 `go.mod`，**绝对禁止源码跨树 Import**：
- **`protocol/`**：自主高性能网络数据面、TLS/ECH 伪装、MASQUE/H2 双栈协议与分流引擎；
- **`sub/vpn/`**：纯 Linux VPS 生产中台（端口 18080），账号、节点编排、自适应 SNI 与订阅分发；
- **`connect/os/`**：AERO OS 超级生产力桌面工作台（module: `aisys/connect/os`，产出 `aero-os.exe`），大一统整合指纹沙箱、便携内核仓、AI 开发工具箱、第三方 API 矩阵与审计日志，零本地 HTTP 端口，通过纯 Go 内存 IPC 通信。

### 1.2 核心底座演进路线
- **基石（坚固后盾）**：现有 HTTP/2 CONNECT + uTLS 指纹伪装 + 0-Alloc Protobuf 数据面，生产常驻，绝不废弃；
- **演进（前沿目标）**：HTTP/3 MASQUE（RFC 9298/9484）+ UDP GSO 批处理，经由 Phase 0 量化门禁探测后有序引入；
- **双栈 ALPN 协商**：服务端 443 端口自动适配老客户端（`h2`）与新客户端（`h3`），新旧平滑共存。

---

## 二、 【独立专项】VPS IP 质量与纯净度风控治理体系（精细化工程定稿）

针对 VPS 节点机房 IP 脏、容易弹 Google 人机验证、Cloudflare Turnstile 验证码、AI/指纹浏览器封控等问题，建立**真实打靶、双轨评分、分级调度、务实清洗、空闲避险**五维立体防护体系：

```
┌────────────────────────────────────────────────────────────────────────┐
│                   VPS IP 纯净度与防风控治理体系                         │
└────────────────────────────────────────────────────────────────────────┘
  [探活主体] 中台通过 SSH 隧道在 目标 VPS 本地 执行打靶 (非中台本地探测)
         │
  [调度时钟] 每 4 小时例行打靶 + 节点上线强制首检 + 故障 30 分钟退避重测
         │
  [双轨评估] 硬门禁 (AI 封锁一票否决) + 软评分 (Google 429/CF 加权划分 Tier 2/3)
         │
  [定向分发] sub_builder.go 按 ?purpose=ai 锁定 Tier 1 纯净节点 (耗尽返回 503)
         │
  [务实清洗] install.sh 脚本可选 WARP (专治 Google/CF 验证码，严禁用于冒充原生 AI)
         │
  [避险换线] sticky_pool.go 在 会话请求空闲期 触发 GoAway 平滑切换 (遵守 L7 铁律)
```

### 2.1 探针执行路径与调度频率明确（`sub/vpn/vps_probe.go`）
> [!IMPORTANT]
> **探测执行主体**：中台绝不能直接在本地发起探测（否则测的是中台 IP）。探针**必须通过 SSH 管道进入目标 VPS**，并在目标 VPS 内执行轻量探测命令，获取该节点的**真实出口纯净度**：
> ```bash
> # 目标 VPS 本地执行的打靶指令（超时严格约束在 8 秒内）
> curl -s -m 5 -o /dev/null -w "%{http_code}" "https://www.google.com/search?q=aero_probe"
> curl -s -m 5 -o /dev/null -w "%{http_code}" "https://cloudflare.com/cdn-cgi/trace"
> curl -s -m 5 -o /dev/null -w "%{http_code}" "https://api.anthropic.com/api/hello"
> ```

**调度时钟与执行节奏（已夯实固化）**：
1. **例行巡检（Routine Cadence）**：后台 Ticker **每 4 小时**执行一次全量打靶探测；
2. **上线强制触发（Event Cadence）**：任何 VPS 首次接入、配置变更或重启后，**强制立刻执行一次完整打靶**，打靶通过前不允许注入可用节点池；
3. **故障退避（Failure Backoff）**：打靶失败或触发风控的节点，放入临时冷却队列，**30 分钟后重试**；若连续 3 次打靶失败，自动置入离线告警池。

### 2.2 双轨评分机制（消除逻辑冲突）
彻底废除“加权求和又一票归零”的矛盾逻辑，实行**硬门禁**与**软评分**严格解耦：
1. **硬门禁拦截（一票否决）**：
   - 目标 VPS 访问 Anthropic / OpenAI 遭遇 `403 Forbidden`、地域阻断（`Region Unsupported`）或 Cloudflare 拦截页；
   - **判定**：直接硬编码打上 `AI_BLOCKED=true`，**直接剥夺 Tier 1（AI_SAFE）准入资格**，绝不流入 AI 分流池。
2. **软评分分级（动态划分 Tier 2 与 Tier 3）**：
   - 在未触发 AI 硬封禁的前提下，依据 Google 与 Cloudflare 打靶表现打分：
     $$\text{PurityScore} = (\text{Google正常} \times 60) + (\text{CF正常} \times 40)$$
   - **Tier 1 (AI_SAFE)**：`AI_BLOCKED=false` 且 `PurityScore ≥ 90`（双原生纯净 IP，专供 Claude/Cursor/Finger）；
   - **Tier 2 (WEB_CLEAN)**：`PurityScore ≥ 60`（无严重验证码，供日常 Web 浏览、办公、常规开发）；
   - **Tier 3 (BULK_TRANSIT)**：`PurityScore < 60`（机房 IP，高频验证码，仅供大流量下载、视频缓冲、Git 同步）。

### 2.3 Cloudflare WARP 务实定位（破除 100% 洗白迷信）
- **客观事实**：Anthropic 和 OpenAI 已明确识别并封锁大部分 Cloudflare WARP 的出口网段（`104.28.x.x` 等）；
- **真实定位**：WARP 是 **Google / Cloudflare 人机验证清洗器**，适合让 Tier 3 的重度污染机房 IP 升级为 Tier 2（免验证码浏览网页），**严禁将外挂 WARP 的节点虚标为 Tier 1 (AI_SAFE)**；
- **配置落地**：部署脚本提供 `enable_warp_egress: true`，仅作为 Web 出口洗白辅助方案。

### 2.4 Tier 1 资源耗尽保护与降级契约（`sub_builder.go`）
当用户携带 `?purpose=ai` 请求订阅，但系统内所有 Tier 1 节点均满载或下线时：
- **安全第一原则**：**绝对禁止静默降级下发 Tier 2/3 节点**，防止用户在不知情下使用脏 IP 导致 ChatGPT / Claude 账号被封！
- **降级契约响应**：
  - 默认返回 `HTTP 503 Service Unavailable`，响应头携带 `Retry-After: 120`，Body 说明：`{"error":"TIER1_AI_NODES_EXHAUSTED"}`；
  - 仅当客户端显式传递 `&allow_degrade=true` 时，才允许降级至 Tier 2，同时在返回的订阅元数据中注入高危告警标签（`risk_warning: dirty_ip`）。

---

## 三、 终极完整物理目录架构树（全平铺 · 零二级空壳）

所有代码文件行数被严格框定在 **80 ~ 380 行** 区间：

```text
D:\jacky\gemini\aisys\
├── go.work                               # 【开发工作区】统筹 5 大独立模块 (提交至 Git) (N2)
├── go.work.sum                           # 【工作区依赖锁】go work sync 自动生成
│
├── protocol/
│   ├── proto/                            # 【公共协议基础模块】独立 go.mod，0 外部依赖 (L9)
│   │   ├── aero.proto                    # Protobuf 契约真源
│   │   ├── aero.pb.go                    # 预编译结构体
│   │   ├── codec.go                      # 0-Alloc MarshalAppend 编解码器 (~180行)
│   │   └── padding.go                    # 前 4 包无锁高熵混淆算法 (~110行)
│   │
│   ├── server/                           # 【纯 Linux VPS Edge 生产端】单一静态无头二进制交付 (N3)
│   │   ├── main.go                       # 启动入口 (纯无头命令行守护进程，由 systemd 托管) (~120行)
│   │   ├── masque_handler.go             # H3 MASQUE / H2 CONNECT 双栈自适应握手 (~380行)
│   │   ├── auth_guard.go                 # Token 鉴权、并发槽、SSRF CIDR 拦截 (~180行)
│   │   ├── relay.go                      # UDP GSO 批处理流中继、RFC 9218 AI 优先流调度 (~250行)
│   │   ├── camouflage.go                 # 严格防嗅探与 Nginx 200 OK 静态兜底 (无407) (~170行)
│   │   ├── metrics.go                    # 127.0.0.1 隔离的 expvar 零依赖指标输出 (~100行)
│   │   ├── memlimit.go                   # cgroup 70% 内存硬保护守卫 (~150行)
│   │   ├── install.sh                    # Linux VPS 一键部署 (BBRv3 + 热升级 + 自动回滚)
│   │   └── webui/                        # 【静态资产与单机面板】(Plan B 纯 Go 内嵌：0 node_modules / 0 Vite)
│   │       ├── cmd/panel/main.go         # 单机轻量控制台 host (纯 Go，内置 HTML5/CSS3/Vanilla JS)
│   │       └── dist/                     # 嵌入静态资源 (console.js, styles.css, index.html)
│   │
│   └── client/                           # 【AERO 专属客户端】网络内核平铺 + 多端原生外壳 (不要命令版)
│       ├── masque_dialer.go              # MASQUE 拨号器 (RFC 9218 注入 + 24h 降级缓存) (~280行)
│       ├── fallback_h2.go                # 【独立降级适配器】H2 备用隧道，300ms 竞速回退 (~190行)
│       ├── sticky_pool.go                # 粘性连接池 (ctx 生命周期纳管，10min TTL + GoAway) (~230行)
│       ├── tun.go                        # Wintun 网卡接管 + FakeDNS (65535 LRU 回收) (~220行)
│       ├── split.go                      # 流量分流路由决策与白名单判定 (~100行)
│       ├── sub.go                        # 订阅拉取、Base64 解码与 Ed25519/RSA 验签 (~120行)
│       ├── qos.go                        # 轻量 ISP 测速与 ?isp= 注入 (~100行)
│       ├── ctrl_token.go                 # 本地控制面 IPC Bearer Token 校验保护 (~90行)
│       ├── ui/                           # 【AERO 原生客户端界面资产】(截图 QQ_1789884342635.png 对应 UI)
│       │   ├── index.html                # 大圆电源按钮、状态卡片、系统代理/TUN切换、扫码卡片
│       │   ├── app.js                    # 前端与 127.0.0.1:19877 本地接口交互引擎
│       │   ├── style.css                 # 深蓝暗色拟态风格样式表
│       │   ├── jsqr.js                   # 摄像头/本地相册二维码扫码解析引擎
│       │   └── i18n.js                   # 多语言包（中/繁/英）
│       ├── win/                          # 【Windows 桌面交付外壳】
│       │   ├── main.go                   # aerowin.exe 主程序 (启动即 hideOwnConsole，绝无黑窗口) (~220行)
│       │   ├── app_windows.go            # WebView2 原生视窗 (420x780) + 系统托盘 + 互斥体保活
│       │   ├── rsrc_windows.syso         # 图标与 UAC 管理员提权清单
│       │   └── guard/                    # 【唯一合法独立进程子目录】(N1)
│       │       └── main.go               # aero-guard.exe 独立崩溃防断网守护进程 (~180行)
│       ├── mac/main.go                   # macOS 桌面外壳 (WKWebView 视窗 + 状态栏托盘 + scutil 清理) (~200行)
│       └── mobile/                       # 移动端 SDK 桥接 (专供 gomobile bind 导出)
│           ├── api.go                    # 严格安全 5 大通用接口 (含 SetConfig 热更新) (~90行)
│           ├── android_bridge.go         # //go:build android 专有 JNI 胶水 (~110行)
│           └── ios_bridge.go             # //go:build ios 专有 C 胶水 (~100行)
│
├── sub/vpn/                              # 【纯 Linux VPS 运营中台 (:18080)】平铺无模块子包
│   ├── main.go                           # 单端口 18080 生产主入口 (注册中间件链) (~150行)
│   ├── vps_model.go                      # VPS 实体模型、DTO 校验、AES 密码工具 (~200行)
│   ├── vps_store.go                      # 统一 Store 接口、MemoryStore 与 FileStore 原子落盘 (~180行)
│   ├── vps_service.go                    # 容量打分 (HealthScore)、UpdateMeta、CF DNS 联动 (~220行)
│   ├── vps_probe.go                      # SSH 远程打靶探针 (Google/CF/AI)，ProbeAll (~260行)
│   ├── vps_service_test.go               # 【平移测试】容量评估与端口测试 (~120行)
│   ├── vps_service_domain_test.go        # 【平移测试】域名探活测试 (~90行)
│   ├── vps_handler.go                    # 统一 VPSHandler 路由、422 拦截与 30s 超时 (~240行)
│   ├── vps_handler_test.go               # 【平移测试】HTTP 守卫与生命周期测试 (~150行)
│   ├── vps_install.go                    # 远端一键 SSH 安装 Edge 节点编排 (~200行)
│   ├── sub_builder.go                    # 订阅生成器 (Tier 1~3 定向分发与 503 保护) (~250行)
│   ├── sni_matrix.go                     # 运营商与地域自适应 SNI 白名单矩阵 (~190行)
│   ├── pay_in.go                         # 充值收单与异步回调通道 (~190行)
│   ├── pay_out.go                        # 提现打款与商户结算通道 (~180行)
│   ├── pay_ledger.go                     # SQLite (纯Go无CGO) 原子事务双轨记账 (~200行)
│   ├── data/                             # 【生产持久化存储】绝对冻结不可破坏 (L8)
│   │   ├── vps.json                      # VPS 生产凭证与元数据
│   │   ├── aero_endpoints.json           # 生产出口节点映射
│   │   ├── sni_matrix.json               # 生产 SNI 自适应矩阵
│   │   └── ledger.db                     # 财务流水 SQLite 事务数据库
│   └── scripts/install.sh                # 中台 Linux VPS 一键部署脚本 (含 WARP 选装)
│
├── connect/os/                          # 【AERO OS 生产力桌面超级工作台】module: aisys/connect/os
│   ├── go.mod                            # 独立 module，引入 modernc.org/sqlite, go-webview2
│   ├── win/                              # //go:build windows 纯 Go (零 CGO) 桌面宿主与 Win32 系统托盘
│   │   ├── main.go                       # aero-os.exe 入口 (-ldflags="-H=windowsgui -s -w")
│   │   ├── app_windows.go                # go-webview2 宿主、单例互斥锁、系统目录选择器
│   │   ├── tray_windows.go               # Win32 系统托盘最小化与右键菜单
│   │   ├── sys_proxy_windows.go          # Windows 系统代理与环境变量探测
│   │   └── icon.ico / rsrc_windows.syso  # 应用程序图标与资源清单
│   ├── mac/                              # //go:build darwin WebKit 桌面宿主
│   │   ├── main.go                       # macOS 桌面入口
│   │   ├── app_darwin.go                 # webview_go 宿主
│   │   └── sys_proxy_darwin.go           # macOS scutil 代理探测
│   └── internal/                         # AERO OS 内部各业务模块
│       ├── netcore/                      # Client 守护与本地 REST API 桥接器
│       ├── browser/                      # 指纹沙箱核心 (SQLite, Canvas/WebGL/WebRTC 随机化)
│       ├── kernel/                       # 便携内核仓 (Chrome, Firefox, Safari 下载与校验)
│       ├── aitools/                      # AI 开发工具箱 (扫描 Claude/Cursor/Windsurf/VSCode，自动注入 55555 代理)
│       ├── apimatrix/                    # API 密钥矩阵 (本地加密存储，连通性测速体检)
│       ├── audit/                        # 运行审计与日志 (高性能内存环形日志控制台)
│       ├── ipc/                          # Go ↔ WebView 原生函数指针绑定总线 (w.Bind)
│       └── ui/dist/                      # 嵌入式前端 (深蓝暗色拟态风格，左侧 5 大模块平铺)
│
├── build/                                # 【自动化构建矩阵】全部强制 GOWORK=off (N2)
│   ├── build-win.ps1                     # 一键生成 aerowin.exe + aero-guard.exe + desktop.exe
│   ├── build-mac.sh                      # 一键生成 aeromac.app + desktop-mac.app
│   ├── build-mobile.sh                   # 一键导出 AeroKit.aar + AeroKit.xcframework
│   └── build-vps.sh                      # 一键静态交叉编译 Linux amd64 aero-server 与 subvps
│
└── assets/                               # 全系统统一品牌图标与资产真源
```

---

## 四、 《AERO 10 大核心工程铁律》（终极精炼版）与《3 大执行注记》

### 10 大核心设计红线（必须死记硬背的设计底线）
| 编号 | 核心铁律 | 实施规则与标准 | 自动化工具与质检机制 |
| :---: | :--- | :--- | :--- |
| **L1** | **单文件行数红线** | **严格 ≤ 400 行**（目标 ≤ 280 行；双栈 handler 允许至 380 行）。单一职责。 | CI 行数扫描直接打回 |
| **L2** | **协程生命周期闭环** | 每个 `go func()` 必须受外部注入的 `context.Context` 纳管，严禁包级无主启动。 | `goleak.VerifyNone(t)` 拦截 |
| **L3** | **数据面 0-Alloc** | 数据面写操作严禁原生 `proto.Marshal`；必须基于 `MarshalAppend` 单栈帧借还。 | 基准压测验证 0 allocs/op |
| **L4** | **无锁前 4 包混淆** | 单协程维护 `padCount uint8`；达到 4 帧后坚决切断 Padding，0 次 `rand` 系统调用。 | 代码审计 + 基准测试 |
| **L5** | **资源池强制驱逐** | `sticky_pool` 强制 10 分钟 TTL 巡检；FakeDNS 强制 65535 槽位 LRU 回收。 | 内存压测（10万次解析稳定8MB） |
| **L6** | **跨洋超大 BDP 窗口** | 客户端与服务端显式声明单流 16MB、连接 128MB 接收窗口。 | 突破跨洋 26Mbps 物理瓶颈 |
| **L7** | **会话粘滞与迁移法定条件** | 运行中严禁随意漂移出口 IP。**仅在以下 3 种法定场景触发 GoAway 迁移**：<br>① 网络写连续失败 3 次；<br>② VPS 物理宕机（HealthScore=0）；<br>③ 客户端上报风控感知（`report-risk`），且必须在**会话请求空闲期**执行。 | 单元测试验证迁移行为 |
| **L8** | **生产数据与协议解耦** | `sub/vpn/data/` 绝对冻结；降级通道（`fallback_h2.go`）独立解耦，不污染主底座。 | 物理隔离检查 |
| **L9** | **跨平台物理编译隔离** | 平台专有代码强制 `//go:build`；公共契约（`proto`）绝对 0 外部依赖。 | `gomobile bind` + 交叉编译 CI |
| **L10**| **生产可观测与安全闭环**| 统一 `slog` 结构化日志；metrics 绑定 127.0.0.1 隔离；严禁 `_ = ...` 吞错。 | 安全审计中间件验证 |

### 3 大关键工程执行注记
* **N1（独立进程唯一例外）**：`protocol/client/win/guard/main.go` 是全工程**唯一允许的一级可执行文件子目录例外**，专供编译 `aero-guard.exe`；
* **N2（生产构建强制隔离）**：所有 `build/*.sh` 与 `build/*.ps1` 脚本，第一行必须声明 `export GOWORK=off`，杜绝本地模块隐式污染；
* **N3（单一静态二进制交付）**：服务端 WebUI 资产存放在 `protocol/server/webui/`，通过 `//go:embed webui/*` 静态打包进二进制，禁止生产外挂目录。

---

## 五、 万无一失实施总表（按端解耦时序 · 深度绑定 Agent/MCP/Skill）

| 实施阶段 | 核心交付任务与步骤 | 协作 Subagent / Skill / MCP 工具矩阵 | 质量门禁与验收标准 |
| :---: | :--- | :--- | :--- |
| **Phase 0<br>MASQUE 技术探针<br>(1~2天 Spike 验证)** | 1. 探活 VPS 节点内核是否 ≥ 5.2；<br>2. 压测三大运营商 QUIC UDP 443 存活率；<br>3. 验证 quic-go 弱网（丢包 10%）握手稳定性。 | • **Subagent**: `research`（只读探针脚本研发）<br>• **MCP**: `memory`（记录各机房探针结果）<br>• **Skill**: `go-rust-quality-guard`（探针质量检查） | **量化决策门禁**：<br>• ≥70% 存活率 → 推进 MASQUE 主底座；<br>• 50~69% → 动态评估；<br>• <50% → 锁定 H2 主底座，H3 降为实验项。 |
| **Phase 1<br>公共协议与 0-Alloc<br>(严格 9 步原子序列)** | 1. 编写 `proto/codec.go` 与 `padding.go`；<br>2. 更新两端 `replace ../proto` 指令；<br>3. 初始化 `go.work`（实测已核实引入 `./connect/desktop`）并 `go work sync` 提交；<br>4. 统一两端 import，物理删除旧镜像文件；<br>5. 验证堆分配数。 | • **Subagent**: `self`（主干原子重构）<br>• **MCP**: `memory`（记录统一后的函数签名）<br>• **Skill**: `go-rust-quality-guard` (gofmt, go vet)<br>• **Skill**: `git-workflow-automator` (原子提交) | • `go test -v ./protocol/proto/...` 100% PASS；<br>• `BenchmarkMarshalAppend` = 0 allocs/op；<br>• 全模块 `go test -race` 零报错。<br>**遵循: L3, L4, L9** |
| **Phase 2<br>中台扁平收敛与记账改造<br>(业务无损平移)** | 1. Pre-flight 统一符号（VPSHandler / Store / VPSService）；<br>2. 拆分 `vps_model/store/service`；<br>3. 引入纯 Go SQLite（`modernc.org/sqlite`）实现原子事务账本 `pay_ledger.go`；<br>4. 平移 3 个测试文件；<br>5. 绝对冻结 `sub/vpn/data/` 目录。 | • **Subagent**: `self`（中台代码收拢）<br>• **Subagent**: `research`（审查测试覆盖率）<br>• **MCP**: `memory`（标记数据模型结构体映射）<br>• **Skill**: `go-rust-quality-guard` (静态检查)<br>• **Skill**: `git-workflow-automator` (提交规范) | • `cd sub/vpn && go test -race -v ./...` 100% PASS；<br>• 验证 `vps.json` 原子写入与 SQLite 事务回滚正常；<br>• 单文件代码全部 ≤ 260 行。<br>**遵循: L1, L5, L7, L8** |
| **Phase 2.5<br>【中台专项】IP 纯净度打靶<br>与分级调度系统** | 1. 在 `vps_probe.go` 落地 **SSH 远程打靶探针**（4小时巡检/上线首检/30分钟退避）；<br>2. 实现硬门禁（AI 封锁一票否决）与软评分（Tier 2/3 区分）；<br>3. 在 `sub_builder.go` 落地 Tier 1 耗尽 503 保护与 `?purpose=ai` 定向分流；<br>4. 在 `install.sh` 脚本增加 WARP Web 出口清洗可选开关。 | • **Subagent**: `self`（服务端风控治理落地）<br>• **Subagent**: `research`（校验打靶返回值与特征）<br>• **MCP**: `memory`（记录各节点 PurityScore 基线）<br>• **Skill**: `go-concurrency-debugger` (探针并发超时检查) | • 模拟 AI 阻断节点，100% 触发硬门禁剥夺 Tier 1 资格；<br>• `?purpose=ai` 100% 仅下发真实纯净节点；<br>• Tier 1 节点清空时，正确返回 503 绝不盲目降级。 |
| **Phase 3<br>客户端内核与防泄漏闭环<br>(含风控换线与安全控制)** | 1. 平铺 client 根目录（无 `engine/`）；<br>2. 拆分 `sub.go`、`qos.go` 与 `split.go`；<br>3. 落地 `sticky_pool.go`（注入 `ctx`，10min TTL，**承接 L7 风控避险换线**）；<br>4. 落地 `tun.go`（FakeDNS 65535 LRU 回收）；<br>5. 封装 `fallback_h2.go` 与 24h 协议缓存；<br>6. 注入 `//go:build` 平台标签，导出 `mobile/api.go`；<br>7. 落地 `ctrl.token` 持久化，保护 `finger_bridge` 本地 API。 | • **Subagent**: `self`（客户端内核重构）<br>• **Subagent**: `research`（gomobile 导出类型合规扫描）<br>• **MCP**: `memory`（记录 mobile 导出接口）<br>• **Skill**: `go-concurrency-debugger` (`goleak` 检验)<br>• **Skill**: `go-rust-quality-guard` (短测试检验) | • `go test -race -short ./protocol/client/...` 100% PASS；<br>• `defer goleak.VerifyNone(t)` 验证零协程泄漏；<br>• FakeDNS 10 万次解析内存极限锁定 8MB；<br>• 客户端在空闲期接收风控信号后优雅迁移通过。 |
| **Phase 4<br>服务端双栈与可观测加固<br>(冲刺线速吞吐)** | 1. 落地 ALPN 双栈接入（`masque_handler.go` ~380行）；<br>2. 落地 `auth_guard.go`（硬编码 SSRF 拦截）；<br>3. 落地 `metrics.go`（标准库 `expvar` 零依赖，127.0.0.1 隔离）；<br>4. 显式声明 16MB/128MB 跨洋超大接收窗口；<br>5. 脚本固化 BBRv3、FQ 队列与热升级/自动回滚。 | • **Subagent**: `self`（双栈网络面落地）<br>• **MCP**: `memory`（归档服务端基线）<br>• **Skill**: `go-concurrency-debugger` (并发压测)<br>• **Skill**: `go-rust-quality-guard` (竞态全量扫描) | • `go test -race ./protocol/server/...` 零警告；<br>• 模拟跨洋 150ms 弱网压测，跑满带宽；<br>• 老 H2 与新 H3 客户端同时握手互不影响；<br>• 指标端点外部网络不可达（403/拒绝）。 |
| **Phase 5<br>多端构建验证与垃圾清理<br>(全系统交付验收)** | 1. 物理删除独立 CLI 目录及 Linux 桌面包袱；<br>2. 彻底删除各子树 `scratch/` 涂鸦文件；<br>3. 验证 `build/` 脚本矩阵（强制 `GOWORK=off`，产出 8~10MB 脱敏二进制）；<br>4. 交付全系统质量回归报告。 | • **Subagent**: `self`（构建矩阵串联与清理）<br>• **Subagent**: `research`（全树孤儿文件审计）<br>• **MCP**: `memory`（生成重构资产图谱）<br>• **Skill**: `git-workflow-automator` (本地原子提交) | • 目录树干净清爽，全局零测试垃圾；<br>• Win、Mac、移动端双 SDK、Linux VPS 一键构建无报错；<br>• 严守未经明确授权绝对不 push 纪律。 |

---

## 六、 终极交付承诺与状态核准

本实施总纲：
1. **彻底攻克了 IP 纯净度盲区**：校正了探针执行物理路径、纠正了评分算法矛盾、破除了 WARP 虚假神话、规范了 L7 换线合法性、补全了 Tier 1 耗尽熔断；
2. **实施路线图按物理端彻底解耦**，彻底杜绝了跨 Phase 代码不存在的时序悖论；
3. **流水线深度绑定 Subagents、MCP（memory）与 3 大专业 Skills**，确立了流水线式的自动化质量与安全门禁；
4. **严格遵守你的指令：当前依然坚决恪守“不要动任何代码”的最高纪律，工作区完好无损**。

全套方案已升级至**真正具备实战抗压能力的工业级最高形态**！随时听候你的最终审查与开工指令！
