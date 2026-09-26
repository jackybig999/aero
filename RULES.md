# AERO 核心系统研发与执行准则 (RULES.md)

> **Version**: 1.0.0 (Aligned with GLOBAL MASTER RULES v1.0.0)  
> **Last-Updated**: 2026-09-22  
> **Maintainer**: Jacky  
> **Primary File**: [PROJECT_RULES.md](file:///D:/jacky/gemini/aisys/PROJECT_RULES.md)

本文档是 AERO 项目不可逾越的最高工程纪律与架构红线。本项目严格遵循两级治理体系：**【第一部分：全局通用底座准则 (L1)】** 完整继承全局母准则（v1.0.0），**【第二部分：AERO 专属衍生规则 (L2)】** 规范本项目的垂直业务约束。任何 AI 智能体、开发者及自动化脚本在执行设计、编码、测试与部署交付时必须 100% 严格遵守。

---

## 语言选型固化 (Solidified Tech Stack) `[REVIEW]`
- **核心语言**: Go 1.24+ 标准工程，平铺单包单二进制交付。
- **选型锁定状态**: 已固化锁定为 **Go**，后续会话自动继承，禁止反复询问，不可擅自切换至 Rust 或其他语言。

---

## 第一部分：全局通用底座准则 (L1 Global Baseline)
> 本部分继承自全局规则库（GLOBAL MASTER RULES v2.2.0），为跨项目绝对红线，不可抵触、不可削弱。

### 1. 技术栈准入与纯正性门禁 (Language Stack Gate)
* **生产代码边界 (MUST)**：严格以 **Go 官方标准设计框架**作为系统研发唯一准则。生产服务边界内严禁使用 Python 等动态脚本语言。
* **前端规范 (MUST)**：前端控制台与管理面板严格采用现代标准原生 HTML5 + CSS (Flex/Grid) + 原生 Vanilla JS（或纯构建期零运行时 TypeScript），单页 gzip 必须 < 150KB，运行时第三方依赖数为 0。通过 Go 官方 `//go:embed` 静态编译嵌入单二进制中。严禁在仓库中提交 `node_modules/`。

### 2. 工程目录结构规范 (Project Layout)
* **标准语义 (MUST)**：使用 `internal/` 承载私有包，多 entry 项目入口置于 `cmd/<bin>/main.go`。业务逻辑严禁写在 `cmd/` 内。
* **反模式禁令 (MUST NOT)**：严禁创建无业务语义的容器目录（如 `common/`、`utils/`、`helper/`、`base/`、`core/` 等）；严禁单子目录中间层包裹；严禁仓库遗留废弃、孤儿文件。

### 3. 构建产物隔离与三路径模型 (Artifact Isolation)
* **三路径模型 (MUST)**：
  - `tmp/`：开发期与 CI 的一切中间产物（编译二进制、`*.test`、`*.out`、`*.log`、`*.pprof`、`coverage/`）— 任务结束即清理，严禁入 Git；
  - `dist/`：**仅**存放嵌入用的轻量静态前端资源（HTML / CSS / JS / 字体 / 图标），随源码入 Git；
  - `Release Asset`：正式发布二进制上传至 GitHub Release Asset，**严禁**通过 git commit 提交入版本库。
* **物理防线 (MUST)**：`.gitignore` 必须全量屏蔽 `tmp/`、`*.exe`、`*.dll`、`*.so`、`*.test`、`*.out`、`*.log`、`coverage/`、`node_modules/`、`*.key`、`*.pem` 等敏感及二进制文件。

### 4. 分层与接口契约 (Decoupled Contracts)
* **跨进程 / 跨服务 (MUST)**：严格通过标准 HTTP REST+JSON 或 gRPC+Protobuf 解耦；严禁跨服务引用对方私有结构体；严禁跨系统直接读写对方数据库文件（SQLite / JSON 等）。
* **同进程跨模块 (MUST)**：严格通过 Go `interface` 抽象隔离；接口定义在消费方包内；模块间依赖方向单向，严禁循环依赖。

### 5. API 兼容性与版本演进 (API Compatibility)
* **兼容性红线 (MUST NOT)**：已发布的对外 API 严禁引入破坏性变更；Protobuf 启用 `buf breaking`，已删除字段记入 `reserved`；对外 HTTP API 携带 `/v1/...` 路径前缀。

### 6. 数据所有权与 Schema 迁移 (Data Ownership & Migration)
* **所有权与三段式迁移 (MUST)**：每张表有且仅有一个写入方服务；Schema 变更必须以版本化迁移脚本入库并配对 rollback 脚本；破坏性变更严格遵循 Expand-Migrate-Contract 三段式。

### 7. 研发全流程工程闭环 (Development Lifecycle)
* **六步闭环**：【设计】→【审查】→【编码】→【回测】→【验证】→【交叉排他性验证与交付】。
* **单人 / AI 结对模式（Trunk-Based 豁免）**：在确认单人/AI 结对独立项目时，允许直接维护主干 `main`，但必须满足：① 本地 pre-commit 全量通过快速卡点（格式 + 静态分析 + 测试）；② 输出结构化自检报告；③ Commit message 遵循 Conventional Commits 且包含自检摘要；④ 保持单向可回滚性。

### 8. 测试规范 (Testing Standards)
* **硬性要求 (MUST)**：核心业务包语句覆盖率 ≥ 70%；严禁 flaky 测试；严禁使用 `time.Sleep` 做并发同步（必须使用 channel、`sync.WaitGroup` 或条件变量）；启用随机化执行 `go test -shuffle=on`。

### 9. CI/CD 流水线门禁 (Pipeline Gate)
* **快速卡点 (< 60s)**：`gofmt` 零偏差、`go vet ./...` 零告警、`errcheck` 通过、快速测试通过。
* **完整卡点**：`go test -race -shuffle=on ./...` 全量通过、覆盖率达标、构建产物写入 `tmp/build/`、`govulncheck` 零高危、`gitleaks` 密钥扫描全绿、前端产物 0 依赖且 gzip < 150KB。
* **流水线安全**：第三方 GitHub Action 按完整 commit SHA 锁定，默认最小权限 `permissions: contents: read`。

### 10. 安全规范 (Security)
* **凭证安全 (MUST NOT)**：严禁在代码、配置或 git 历史中硬编码凭证，一律通过环境变量注入。
* **鉴权与传输 (MUST)**：对外暴露接口强制实现鉴权；管理接口严禁裸露；凭证比较必须使用 `subtle.ConstantTimeCompare`；输入进入业务前强制类型与边界校验（防路径穿越）。

### 11. 依赖管理规范 (Dependency Management)
* **锁文件入库 (MUST)**：`go.sum` 必须提交入库，CI 以 `go mod verify` 模式构建。
* **准入审查 (MUST)**：License 允许 MIT/Apache-2.0/BSD/ISC，严禁 GPL/AGPL 进入闭源服务；严禁引入存在未修复已知 CVE 或对安全问题无响应的依赖；坚持最小依赖原则。

### 12. 日志与可观测性 (Logging & Observability)
* **结构化日志 (MUST)**：生产服务代码统一使用 `log/slog` 输出 JSON 格式日志，严禁裸 `fmt.Println`。
* **CLI 渲染豁免**：命令行工具的界面提示渲染允许使用 `fmt.Println`，但业务错误路径仍必须使用 `slog.Error` 记录结构化日志。
* **可观测性基线 (MUST)**：核心服务暴露 `/metrics`（Prometheus 格式）与 `/healthz`（区分 liveness/readiness）。

### 13. 错误处理规范 (Error Handling)
* **严禁隐式忽略 (MUST NOT)**：函数返回的 error 严禁隐式丢弃；确需忽略时必须写作 `_ = f()` 并在同/上行注释显式说明原因；
* **包装错误链 (MUST)**：统一使用 `fmt.Errorf("...: %w", err)` 包裹错误链；使用 `errors.Is` / `errors.As` 断言。
* **Panic 边界**：仅在不可恢复逻辑错误 panic；HTTP Handler 层必须配置统一 `recover` 中间件兜底并记录 ERROR 日志与堆栈。

### 14. 运行时健康验证 (Runtime Verification)
* **真实身份验证 (MUST)**：服务存活判定必须基于真实进程身份（PID/进程名/二进制路径），严禁凭端口响应做假阳性推断；健康检查必须穿透至关键下游依赖；安装/卸载操作必须具备幂等性。

### 15. 发布与回滚 (Release & Rollback)
* **SemVer 与可溯源 (MUST)**：遵循 SemVer 2.0.0；CI 从 tag 自动构建发布包；二进制通过 `-ldflags -X` 内嵌版本号、commit hash 与构建时间；每次发布必须具备回滚路径。

### 16. 时效性检索机制 (Currency of Technical Decisions)
* **5 大触发阈值 (MUST)**：设计网络协议/加密方案、引入核心基础依赖、跨大版本升级、安全机制设计、架构重构时，必须强制联网检索近两年最新规范（Release Notes > RFC > 官方文档）；检索结论记录在 PR/设计文档中。

### 17. 规则层叠与豁免机制 (Hierarchy & Waiver)
* **底线原则**：本全局规则为最高底座，项目规则只能细化增强，严禁削弱。
* **豁免登记 (MUST)**：对 MUST 级条款的任何偏离，必须在项目 [WAIVERS.md](file:///D:/jacky/gemini/aisys/WAIVERS.md) 中登记，明确偏离描述、理由、缓解措施及有效期截止日；CI 监控过期告警。

---

## 第二部分：AERO 项目垂直场景专属衍生规则 (L2 Project Specifics)

### P1. GitHub 仓库单一 main 分支铁律 (Strict Single Branch) `[CI]`
* **绝对规则 (MUST)**：GitHub 远程仓库（`jackybig999/aero`）与本地开发环境**严格仅保留唯一的 `main` 主分支**。
* **严格禁令 (MUST NOT)**：**严禁创建或推送任何特性分支、修复分支或中间临时分支（如 `dev`、`feature/*`、`fix/*` 等）**。
* **单人/AI 结对 Trunk-Based 交付 (MUST)**：
  - 遵循全局规则 §7.3，本地提交前必须通过格式、静态检查与单元测试（§9.1），全量竞态测试与扫描由 CI 或提交前验证；
  - Commit message 必须遵循 Conventional Commits 并附带自检摘要；
  - 保持单向可回滚性与提交历史纯净，杜绝无意义的脏提交。

### P2. 100% 远端官方公开源部署双轨流水线 (100% Remote Public Source Dual Pipeline) `[REVIEW]`
* **绝对规则 (MUST)**：所有远端 VPS 节点的部署与安装，**必须 100% 且只能通过 GitHub 官方公开源（`jackybig999/aero`）直接拉取并就地部署**：
  1. **Release 优先轨**：检测到官方 Release 产物时，直接拉取官方发布包；
  2. **Repo 源码备用轨**：当 Release 尚未发布或为空时，远端 VPS 直接 `git clone --depth 1 https://github.com/jackybig999/aero.git` 并编译生成 `/usr/local/bin/aero-edge`。
* **严格禁令 (MUST NOT)**：**永久删除并绝对严禁任何本地二进制私拷、本地上传或流式传输逻辑**。

### P3. 运行时排他性存活与卸载验证标准 (Exclusive Runtime Probing & Teardown) `[REVIEW]`
* **探针防假阳性 (MUST)**：
  - 严禁单凭端口（443/80）响应推断自身服务存活；
  - 必须实施三维联合校验：**端口监听 + 真实进程身份（`pgrep aero-edge`） + 中台端点注册状态（`ep.Installed == true`）**；
  - 必须有效排除第三方进程（如 nginx、sui 等）占端口导致的误判。
* **卸载彻底闭环 (MUST)**：
  - 卸载执行必须确认目标进程被强制终结（`pkill -9 aero-edge`）；
  - 清理 `/usr/local/bin/aero-edge` 及运行环境配置；
  - 同步将中台管控状态更新为 `UNINSTALLED` 并持久化。
* **前端交互态 (MUST)**：控制台所有诊断、安装与卸载操作必须提供明确的 Loading 交互态，杜绝界面静默。

### P4. 用户授权边界铁律 (User Authority Boundary) `[REVIEW]`
* **绝对禁令 (MUST NOT)**：在未经用户明确下达安装/卸载指令前，**严禁 AI 智能体或任何自动化后台向远端真实 VPS 派发安装任务**。中台仅允许进行公开源探测与连通性检查。

### P5. 前端轻量与单二进制嵌入标准 (Frontend Budget & Embedding) `[CI]`
* **绝对规则 (MUST)**：
  - 严格遵循全局规则 §1.2，前端控制台以原生 HTML5 + CSS + 原生 Vanilla JS（或构建期零运行时 TypeScript）构建；
  - 严禁提交 `node_modules/`，运行时第三方依赖数必须为 0；
  - 单页 JS gzip 后体积必须 < 150 KB；
  - 静态资源统一放置于 `protocol/server/webui/dist`，通过 Go 标准库 `//go:embed` 嵌入到单一可执行二进制中交付。

### P6. 可观测性与服务基线 (Observability & API Security) `[CI]`
* **探针与指标 (MUST)**：
  - 中台服务（`sub/vpn`）与边缘服务（`protocol/server`）必须暴露 `GET /healthz`（区分 liveness/readiness）与 `GET /metrics`（Prometheus 格式）；
  - `web_handler.go` 必须放行 `/health`、`/healthz`、`/metrics` 直通路由，严禁 SPA 拦截。
* **安全鉴权 (MUST)**：
  - 业务接口全面启用基于 Token 的鉴权中间件（`Gate`）；
  - 鉴权凭证比对必须使用 `crypto/subtle.ConstantTimeCompare`。

### P7. 错误处理与规范约定 (Error Handling & Conventions) `[CI]`
* **严格遵守全局 §13.1**：
  - 严禁隐式忽略 error；显式忽略必须采用 `_ = f()` 并在同/上行注释明确说明原因；
  - 错误必须使用 `fmt.Errorf("...: %w", err)` 保留完整错误链；
  - 禁止对 `err.Error()` 进行字符串硬匹配，统一使用 `errors.Is` / `errors.As`。

### P8. 四大子系统自治解耦架构 (Subsystem Decoupling & Autonomous Architecture) `[REVIEW]`
* **中台控制面 (`sub/vpn`) (MUST)**：管理用户、套餐、订阅、订单与收支；物理双库 `aero.db` + `aeropay.db` 仅凭 `user_id` 单向关联；严禁侵入海外边缘节点的底层 SNI、反代或协议特征表；订阅停用返回 403，注销返回 404。
* **边缘服务端 (`protocol/server` / `aero-edge`) (MUST)**：单二进制独立运行在海外 VPS，100% 离线自治；专属加密库 `edge.db`（AES-256-GCM 密文存储，纯 Go SQLite 零 CGO）管理本地 Token 盲索引、证书私钥与反探测伪装路由。
* **跨平台客户端 (`protocol/client`) (MUST)**：纯 Go 多平台支持（Windows / macOS / Linux），零中台内部代码依赖，仅通过标准 HTTPS 订阅接口通信，遇 403/404 立即清理本地缓存防僵尸连接。
* **指纹沙箱内核 (`connect/os` / `finger`) (MUST)**：应用层多开沙箱，支持 Windows 与 macOS 双平台独立编译；数据库 `app.db` 字段级加密加固；与 VPN 仅通过本地标准 SOCKS5 代理端口交接流量。
