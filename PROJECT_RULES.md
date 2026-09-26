# AERO 项目研发与执行准则 (PROJECT_RULES.md)

> **Version**: 1.0.0 (Aligned with GLOBAL MASTER RULES v1.0.0)  
> **Last-Updated**: 2026-09-22  
> **Maintainer**: Jacky  
> **Language-Stack**: Go 1.24+ (Solidified, per GLOBAL MASTER RULES §1.3)  

---

## 语言选型固化 (Solidified Tech Stack) `[REVIEW]`
- **核心语言**: Go 1.24+ 标准工程，平铺单包单二进制交付。
- **选型锁定状态**: 已固化锁定为 **Go**（Go 1.24+），后续会话自动继承，禁止反复询问，不可擅自切换至 Rust 或其他语言。

---

## 第一部分：全局底座准则继承说明
本项目无条件继承 `GLOBAL MASTER RULES v1.0.0` 的全部规范（涵盖 §0 规范性约定、§1 技术栈准入与前端零信任、§2 目录结构、§3 构建产物隔离与三路径模型、§4 接口解耦、§5 API 兼容性、§6 数据所有权与数据库加固、§7 闭环流程、§8 测试规范、§9 CI/CD 卡点、§10 安全规范与容器加固、§11 依赖管理、§12 日志与可观测性、§13 错误处理与异步安全、§14 运行时验证、§15 发布回滚、§16 时效检索、§17 规则层叠与豁免、§18 稳定性工程规范、§19 资源效率与性能预算）。

---

## 第二部分：AERO 项目垂直场景专属衍生规则 (AERO Vertical Rules)

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
  - 严格遵循全局规则 §1.2 与 §1.4，前端控制台以原生 HTML5 + CSS + 原生 Vanilla JS（或构建期零运行时 TypeScript）构建；
  - 严禁提交 `node_modules/`，运行时第三方依赖数必须为 0；
  - 单页 JS gzip 后体积必须 < 150 KB；
  - 静态资源统一通过 Go 标准库 `//go:embed` 嵌入到单一可执行二进制中交付。

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
* **中台运营与订阅控制面 (`sub/vpn`) (MUST)**：
  - 纯控制面大脑，管理用户、套餐、订阅生命周期、订单与收支；
  - 双数据库物理隔离：`aero.db`（母库）与 `aeropay.db`（资金库），仅凭数字 `user_id` 单向关联；
  - 严禁在中台数据库中侵入海外边缘节点的底层 SNI、反代或协议特征表；
  - 订阅总开关关闭（`switch_status: "off"`）或到期时，`/sub/{slug}` 必须返回 403 Forbidden；注销删除返回 404。
* **边缘节点协议服务端 (`protocol/server` / `aero-edge`) (MUST)**：
  - 单二进制独立运行在海外 VPS，具备 100% 离线自治能力；
  - 使用专属加密数据库 `data/edge.db`（AES-256-GCM 密文存储，纯 Go SQLite 零 CGO），管理本地 Token 盲索引、证书私钥与 Cover Site 反探测伪装路由；
  - 严禁与中台共用数据库。
* **跨平台客户端 (`protocol/client`) (MUST)**：
  - 纯 Go 多平台支持（Windows / macOS / Linux），零中台内部包依赖；
  - 单向通过标准 HTTPS 订阅接口同步；遇 403/404 立即清空本地缓存，阻断连接并友好提示。
* **指纹沙箱内核 (`connect/os` / `finger`) (MUST)**：
  - AERO OS 应用层多开沙箱，支持 Windows 与 macOS 双平台独立编译；
  - 数据库 `app.db` 关键字段强制 AES-256-GCM 加密加固；
  - 与 VPN 仅通过本地标准 SOCKS5 代理端口（如 10808）进行网络流量交接，绝不耦合协议内部实现。

### P9. 专属原生 AERO 订阅格式与严禁端口铁律 (Strict Native AERO Sub & Zero-Port URL Mandate) `[REVIEW]`
* **绝对规则 (MUST)**：全系统严格仅允许存在以下**两种且唯二的标准原生订阅格式**，写死固化，严禁任何形式的擅自更改：
  1. **格式一（系统管理员订阅）**：`https://domain.com/sub/superadmin`
  2. **格式二（普通用户专属订阅）**：`https://domain.com/sub/username{六位随机码}`（如 `https://domain.com/sub/jacky123456`）
* **绝对禁令：严禁携带非标端口 (MUST NOT)**：
  - **严禁在订阅链接中携带任何显式非标端口号（绝对严禁出现 `:18080`、`:8080` 或任何其他端口后缀）**！订阅一律通过标准 443 HTTPS 域名发布与获取；
  - **客户端建立连接仅凭合法域名与 Token 即可完成通信，严禁在外部链接中暴露底层技术端口**；
  - **绝对严禁生成、转换或兼容任何第三方异构代理订阅格式（严禁 Clash, v2rayN, sing-box, Surge 等）**。全系统只认、只用、只输出自研的 AERO 原生标准规范。


