# 项目研发最高准则（GLOBAL MASTER RULES）

> **Version**: 1.1.1
> **Last-Updated**: 2026-11-03
> **Maintainer**: Jacky
>
> 本文件是 Go / Rust 仓库的工程底座（L0），小项目与大项目共用同一份。检查强度由项目剖面（§0.6）决定；项目只需在 `PROJECT_RULES.md` 里补充少量参数（§0.7）。项目规则只能细化或收紧，**MUST NOT** 削弱（§18.1）。
>
> 本文件同时是 AI 编码代理（Claude Code、Codex、Gemini CLI、Cursor、Copilot 等）的统一执行标准。各工具的接入方式与常驻速查卡见附录 F，代理行为约束见 §14.6–§14.8。
>
> **本文件做不到的事**：
> - 规则不能消灭全部缺陷。没被测试跑到的路径、没被探针看到的故障，规则发现不了。
> - 附录 C 只说明条款参照了哪份公开文档。没有逐条实现并留下证据的，**MUST NOT** 写成“已符合该标准”。
> - 正文示例与受支持语言版本的官方文档冲突时，以官方文档为准，并修订本文件。禁止照抄已废止的示例。

---

## §0 约定、层级与剖面

### 0.1 效力分级（RFC 2119 / RFC 8174）

| 标记 | 含义 | 违反后果 |
|---|---|---|
| **MUST** / **MUST NOT** | 绝对要求 / 绝对禁止 | 阻断合并或发布，须走 §18.2 豁免登记方可放行 |
| **SHOULD** / **SHOULD NOT** | 强烈建议，偏离须在 PR 描述中说明理由 | 不阻断，Reviewer 有权要求补充理由 |
| **MAY** | 可选项，由项目自行裁量 | 无 |

未在本节定义的标记无效。不可豁免的例外见 §0.8。

### 0.2 执行方式标注（Enforcement Tag）

| 标记 | 含义 |
|---|---|
| `[CI]` | 流水线自动校验，失败即阻断，人无法绕过 |
| `[LOCAL]` | pre-commit hook / Makefile target 本地校验 |
| `[REVIEW]` | 人工 Review，依 §18.3 Checklist 判定 |
| `[ADVISORY]` | 无自动校验手段，仅作工程共识记录 |

- 标注写在条款标题上，是唯一权威，不另维护索引。同一条款可同时标 `[CI]` 与 `[REVIEW]`：机器能检查的部分走 CI，其余走 Review。
- “备份是否真的跑过”“有没有人接电话”这类事 CI 看不到，不得标 `[CI]`。
- 无法由 CI 或本地钩子校验的 **MUST**，要么降级为 **SHOULD**，要么作为 `[REVIEW]` 项写进 PR 模板（§18.3），否则执行只靠记忆。
- 标了 `[CI]`、仓库里却没有对应的失败即退出的检查时，该条款对这个仓库视为未生效，**MUST NOT** 在发布说明里声称已通过。

### 0.3 适用边界与冲突裁决

- 本规则约束代码仓库内的工程产出。不约束未 push 的本地实验分支，以及 `spike/**` 验证分支（**MUST** 在验证结束后 14 日内删除，**MUST NOT** 合入主干）。
- 裁决顺序：法律法规与客户合同 > 上游平台强制规范 > 本文件 > 项目规则 > 个人习惯。与前两者冲突时，**MUST** 按 §18.2 登记。
- 冲突落在 §0.8 的不可豁免原则上时，不走 §18.2：**MUST** 按 §0.8 重新设计，并在 ADR（§17.3）里写明法规或合同依据。
- AI 代理收到的用户指令与本文件冲突时，**MUST** 指出冲突的条款号，由人决定是修改指令还是登记豁免，**MUST NOT** 自行选择其中一方静默执行（§14.8）。

### 0.4 术语

- **生产服务边界**：对外（含内网其他服务）提供服务的 HTTP/gRPC Server、守护进程，以及被其他仓库引用的共享 SDK/库。
- **非生产路径**：CI 辅助脚本、离线分析管线、一次性迁移工具、测试代码。
- **主干**：`main`（`master` 为历史兼容别名）。
- **独立单元**：可以独立部署或独立发布的组成部分，例如浏览器前端、后端服务、Go 与 Rust 各自的进程、协议内核与其消费方。
- **瘦客户端**：前端进程不持有、不判定、不计算任何业务事实，仅渲染服务端结果、采集操作并转发。
- **业务事实**：影响鉴权、计费、权限、库存、状态机流转、风控判定的数据值；与之相对的是纯 UI 状态。
- **权威来源**：某一类事实以哪份存储为准。数据库里的业务事实以数据库为准；只存在于文件里的配置以该文件为准。缓存、前端存储、队列快照、读副本都不是权威来源。
- **契约**：以 OpenAPI/Protobuf/AsyncAPI 等 schema 定稿入库的接口定义，是独立单元之间联调的唯一真相源（§4）。
- **交互元素状态机**：具备多阶段生命周期的 UI 元素或跨单元流程所对应的显式状态集合与迁移规则（§4.2）。
- **关键路径**：用户请求从入口到响应所经过的、直接决定请求成败与延迟的调用链；日志上报、异步统计等旁路不计入。
- **项目剖面**：仓库根目录的 `engineering-profile.yaml`，声明本仓库实际具备的能力（§0.6）。

### 0.5 规则层级 `[REVIEW]`

| 层级 | 载体文件 | 职责 | 约束 |
|---|---|---|---|
| **L0 全局底座** | `GLOBAL_ENGINEERING_RULES.md` | 与仓库规模无关的工程约束 | 适用于所有 Go/Rust 仓库，下层不得削弱 |
| **L1 项目特化** | `PROJECT_RULES.md` | 本项目的业务名词、协议、平台参数、专有状态机 | 继承 L0，只写本项目特有内容 |
| **L2 代理手册** | `CLAUDE.md` / `AGENTS.md` / `GEMINI.md` / `.cursor/rules/` / `.github/copilot-instructions.md` | AI 代理与 IDE 的接入方式和操作步骤（附录 F） | 只引用 L0/L1，不得另写一套冲突规则，不得复制改写 L0 正文 |
| **剖面** | `engineering-profile.yaml` | 本仓库实际开启了哪些能力 | CI 只启用剖面中的门禁（§0.6） |

低层级条款 **MUST** 能指向高层级的某一条，冲突时高层级胜出。宿主防火墙、应用商店文案、订阅计费规则写在 L1，不写进 L0。

### 0.6 项目剖面 `[CI]`

同一份 L0 覆盖单文件程序和多服务系统。差别在剖面，不在再抄一份“精简规则”。

仓库根目录 **MUST** 有 `engineering-profile.yaml`。新增能力时 **MUST** 先改剖面，再改代码。口头说“项目还小”不能跳过已引入能力对应的条款。

```yaml
language: go            # go | rust | go+rust
kind: cli               # cli | library | service
persistence: none       # none | file | sqlite | server-db
network: none           # none | outbound | inbound
concurrency: none       # none | in-process
frontend: none          # none | embedded | web | mobile（web：独立部署的浏览器前端）
components: single      # single | multi，独立单元是否多于一个
tenancy: single         # single | multi
replicas: 1             # 生产副本数
ai: none                # none | llm
pii: false              # 是否处理个人信息
```

任何仓库都执行：§0、§1、§2、§3.1、§7.1、§7.3、§7.4 中随机数一条、§7.6、§9.2 中外部输入分配一条、§9.4、§10、§11/§12 中与所用语言及代码有关的项、§13、§14、§15.1–§15.4、§15.5 第一条（回滚路径）、§17.3、§18。有测试之后才执行 §13.1 的覆盖率数字。

| 剖面取值 | 额外执行 |
|---|---|
| `language: go` / `rust` / `go+rust` | §1.2 与 §11 / §1.3 与 §12 / 两者，加 §1.4 |
| `kind: library` | §4.6 的公开 API 兼容检查、§7.6 的 SBOM、§7.8 |
| `kind: service` | §8.6、§8.7、§9.1、§9.5、§10.6、§15.5 全条、§17.1、§7.8；§7.7（容器化时）；§17.2（仅当 L1 写明有人值班） |
| `persistence: file` | §8.8 |
| `persistence: sqlite` | §6.2、§6.3、§6.10、§6.11（含个人信息时） |
| `persistence: server-db` | §6 全章（§6.9 仅 Go） |
| `network: outbound` | §7.3、§7.4、§8.1–§8.3、§8.9、§9.3 |
| `network: inbound` | 上一行，加 §3.2、§7.2、§7.5、§8.4–§8.7、§10.4 |
| `concurrency: in-process` | §8.9、§9.2、§11.4（Go）/ §12.2（Rust） |
| `frontend: embedded` / `web` | §5.1–§5.7 |
| `frontend: mobile` | §5.1–§5.5、§5.6 的轮询一条、§5.7、§5.8 |
| `components: multi`，或 `frontend` 非 `none`，或 `network: inbound` | §3.2、§4 全章 |
| `tenancy: multi` | §6.1 的租户边界 |
| `replicas` 大于 1 | §7.5 的共享计数、§8.4 |
| `ai: llm` | §16 |
| `pii: true` | §6.5、§6.11、§7.8 |

下列条款按事实触发，与剖面取值无关：§7.8（任何对外分发的产物，含 CLI）；§8.8（服务把配置、证书、规则写到磁盘）；§8.10（程序修改宿主的防火墙、路由或网络配置）；§6.11（存在用户账号数据）；§16（调用任何 AI/LLM 服务，此时剖面 **MUST** 写 `ai: llm`）。

CI 检查导入与剖面是否矛盾。常见矛盾如下，标准库和框架会自己启动线程或监听端口，只搜字面量不够：

| 剖面声明 | 与之矛盾的导入（示例） |
|---|---|
| `persistence: none` | `database/sql`、数据库驱动、`rusqlite`、`sqlx`、`diesel` |
| `network: none` | `net`、`net/http`、`hyper`、`reqwest`、`tonic`、`axum` |
| `concurrency: none` | `go` 语句、`sync`、`std::thread`、`tokio`；`net/http` 的服务端与客户端 `Transport`、`database/sql` 都会自己启动 goroutine，使用它们时不得写 `none` |
| `frontend: none` | 指向 Web 资源的 `//go:embed`、`rust-embed`；仓库里的 `package.json` |

CI 第一版只验证三件事：剖面文件存在、字段值落在上表枚举内、导入与声明没有明显矛盾。检查脚本不存在时，本条视为未生效。选定 `language` 后，**MUST NOT** 在每次任务里重新询问。

### 0.7 项目规则的最小内容

`PROJECT_RULES.md` 以两行开头：继承本文件；`language` 与剖面取值相同，两处不一致时 CI 失败。其后写：

- 职责：一句话。
- 版本来源：`VERSION` 文件、`Cargo.toml` 的 `version`、构建时从 tag 注入，三选一（§15.4）。
- 业务专有规则：协议、状态机、业务名词。没有就写“没有”。
- 对 L0 的收紧项。没有就不写。
- 剖面开启某项能力时，**MUST** 写明下表里的参数。L0 不替项目发明这些数值。

| 剖面取值 | 需要写明的参数 |
|---|---|
| 已有测试 | 核心业务包清单，覆盖率门槛按它计算（§13.1） |
| `kind: library` 且 `language` 含 `rust` | MSRV（§1.3） |
| `network` 非 `none` | 各类外部调用的超时值，以及它来自测量还是估算（§8.1） |
| `persistence: file` | 崩溃原子替换所用的 API 与测试记录（§8.8） |
| `persistence: sqlite` | 日志模式与连接数（§6.10） |
| `persistence: server-db` | 备份周期、恢复演练记录位置（§6.7） |
| `network: inbound` | 请求体上限（§7.3）、限流阈值（§7.5）、有会话时的 Cookie 属性（§5.3） |
| `kind: service` | 停止信号类型与排空上限的配置项（§8.6）、CPU 与内存预算（§9.1）、回滚阈值（§15.5）、是否有人值班（§17.2） |
| `frontend` 非 `none` | 公开变量前缀（§5.5） |
| `frontend: web` | 单页 JS gzip 预算（§5.6） |
| `components: multi` | 子系统前缀与错误码注册表位置（§4.5） |
| `pii: true` | 各类数据的保留期限与删除时限（§6.11） |
| `ai: llm` | 供应商、数据出境评估、成本上限（§16） |

### 0.8 不可豁免的核心原则

下列原则 **MUST NOT** 走 §18.2 豁免。唯一允许的调整路径是重新设计，让被约束的对象不再落入该条款，而不是登记豁免。具体实现细节仍可裁量。

- §4.1 契约先行（含跨子系统）
- §4.4 未就绪能力门禁
- §5.1 前端零信任
- §6.1 已持久化业务事实的权威来源
- §16.3 AI 输出的可信边界

其余 **MUST** 条款均可依 §18.2 登记豁免。

---

## §1 技术栈与版本时效

### 1.1 语言与受支持版本 `[CI]`

- 生产服务边界内的代码、核心协议、网络数据面与后台守护进程，**MUST** 使用 **Go** 或 **Rust**，或两者组合（§1.4）。
- **不落后原则**：任何仓库 **MUST NOT** 使用上游已停止安全修复的语言版本、协议版本、标准版本或依赖主版本。是否仍受支持以官方发布页为准。规则正文不写死“当前应使用哪个版本”，核对日期的快照见附录 C。为说明行为差异而写“`go` 行 ≥ X 时”“自某版本起”是允许的，且 **MUST** 写清楚低于该版本时怎么办。
- 语言选型写入剖面的 `language`。变更 **MUST** 走 §18.2，附迁移方案与 ADR（§17.3）。

### 1.2 Go 工具链 `[CI]`

- Go 官方同时只维护最近两个大版本。`go.mod` 的 `go` 行 **MUST NOT** 低于当前仍受维护的较旧那个大版本。`toolchain` 行或 CI 镜像 **MUST** 固定具体补丁号，**MUST NOT** 使用浮动的 `latest`。
- 服务与应用 **SHOULD** 在新大版本发布后 90 日内升到最新大版本；**MUST** 在所用大版本停止维护之前完成升级。
- 开发期工具（linter、代码生成器）**SHOULD** 用 `go.mod` 的 `tool` 指令固定版本。CI 里 **MUST NOT** 使用未固定版本的 `go install pkg@latest`。
- 升级大版本 **MUST** 先读 Release Notes 里的不兼容项（§1.6），升级后运行 `go fix` 并审阅差异。`stdversion` 检查 **MUST** 启用：`go vet` 的默认集合已包含它；`go` 行 ≥ 1.27 时 `go test` 也默认运行它。

### 1.3 Rust 工具链 `[CI]`

- Rust 没有长期支持分支，只有最新稳定版得到修复。`rust-toolchain.toml` **MUST** 固定具体稳定版本。某个稳定版发布满 90 日时，固定的版本 **MUST** 已不低于它。
- `Cargo.toml` **MUST** 使用已稳定的最新 `edition`。edition 迁移（`cargo fix --edition`）单独提交，不与功能改动混在一起。
- `kind: library` **MUST** 声明 `rust-version`（MSRV），CI **MUST** 同时在 MSRV 与最新稳定版上构建。MSRV 变更写入发布说明。MSRV 不能低于所用 edition 稳定时的 Rust 版本；库确需支持更旧的编译器、因此不能使用最新 edition 时，走 §18.2 登记。

### 1.4 多语言与跨语言边界 `[CI]` / `[REVIEW]`

- Go 与 Rust 可以在同一系统里分工（`language: go+rust`）。独立进程之间 **MUST** 走 §4 的契约（gRPC、HTTP 或 IPC），优先进程隔离。
- 同进程 FFI 只在性能或既有库复用确有必要时使用，**MUST** 在 ADR 记录理由，**MUST** 走 C ABI（Rust `extern "C"` 与 `#[repr(C)]`，Go `cgo`）。分配内存的一方负责释放。Go 指针传给 C 时 **MUST** 遵守 cgo 的指针传递规则，调用期间保持可达。panic **MUST NOT** 越过 FFI 边界。
- 绑定与头文件 **MUST** 由工具生成（如 `bindgen`、`cbindgen`）并纳入 §4.3 的一致性检查。
- 双语言仓库的 CI **MUST** 分别运行两套工具链对应的 §15.1、§15.2 检查，并在 `PROJECT_RULES.md` 标明各模块所属语言。

### 1.5 发布物的语言与脚本边界 `[CI]`

- 生产运行时和发布镜像中 **MUST NOT** 包含 Python 解释器或 `*.py`。CI **MUST** 检查发布产物里 `*.py` 的数量为 0。
- 开发期脚本放在 `tools/`，**MUST** 列入打包排除清单，**MUST NOT** 被服务进程加载。Rust crate 内用于对照测试的 Python **MUST** 放在 `tests/fixtures/` 并用 `uv` 锁定依赖。这不构成生产豁免。

### 1.6 时效性检索 `[REVIEW]`

- 下列变更 **MUST** 查阅该主题的当前官方文档：协议或加密方案、核心依赖的大版本升级、安全机制、存储引擎、语言或工具链大版本。PR 或 ADR **MUST** 留下文档 URL 和查阅日期，没有链接的“已经查过”不能复核。
- 信源优先级：官方 Release Notes > IETF RFC 与标准组织文本 > 官方文档 > 权威社区文章。**MUST NOT** 仅凭预训练知识或旧示例作决策。AI 代理引用某个 API 之前，**MUST** 对照所用版本的官方文档。
- 实验性特性（语言、标准库、协议草案）**MUST NOT** 进入生产，除非 ADR 论证并已登记豁免。

### 1.7 抽象与泛型边界 `[REVIEW]`

- 泛型（Go 的泛型函数与泛型方法、Rust 的 trait 泛型）只用于与业务领域无关的通用结构与算法：并发安全集合、环形缓冲区、对象池、通用缓存容器。
- 业务实体、HTTP 处理器、业务 Service 与持久层 **MUST NOT** 为了抽象而泛型化。**MUST NOT** 创建多层嵌套的泛型业务类型，避免代码晦涩、编译产物膨胀与调试堆栈断裂。

---

## §2 目录结构与仓库纯净

### 2.1 Go 项目布局 `[REVIEW]`

- 存在 `main` 以外的包时，不对外的包 **MUST** 放在 `internal/` 下（编译器强制的可见性边界）。只有一个 `main.go` 的 CLI 不需要建 `internal/`。
- 多 binary **MUST** 把入口放在 `cmd/<binname>/main.go` 并保持薄入口。`kind: cli` 允许根目录单个 `main.go`，不要求先建 `cmd/` 目录树。
- **SHOULD NOT** 使用 `pkg/`，仅确需对外导出时 **MAY** 使用。`api/`（契约，受 §4 约束）、`web/`（受 §5 约束）、`tools/` 为可选一级目录。

### 2.2 Rust 项目布局 `[REVIEW]`

- **MUST** 使用 Cargo Workspace 组织多 crate。每个 crate 的错误类型 **MUST** 放在自己的错误模块（通常是 `error.rs`），**MUST NOT** 被迫共用根目录上的一个 `error.rs`。
- 共享依赖版本 **SHOULD** 用 `[workspace.dependencies]` 统一，lint 配置 **SHOULD** 用 `[workspace.lints]` 统一。

### 2.3 反模式禁令 `[REVIEW]` / `[CI]`

- **MUST NOT** 创建无业务语义的容器目录（`common/`、`utils/`、`helper/`、`base/`、`core/`、`misc/`、`manager/`）。`[REVIEW]`
- **MUST NOT** 创建仅含单个子目录的中间层，**MUST NOT** 遗留废弃或孤儿文件。`[CI]` 由语言或工具约定的目录不算中间层：`internal/`、`cmd/`、`crates/`、`api/`、`docs/adr/`、`tests/fixtures/`，即使下面暂时只有一个子目录。

### 2.4 构建产物三路径 `[CI]`

| 路径 | 用途 | 入 Git | 生命周期 |
|---|---|---|---|
| `tmp/` | 一切中间产物 | **MUST NOT** | 任务结束即清理 |
| `dist/` | 仅嵌入用的轻量静态前端资源（受 §5 内容边界约束） | **MAY** | 随源码或由 CI 生成 |
| Release Asset | 正式二进制、安装包、校验和、SBOM | **MUST NOT** 入 Git 树 | 与 tag 一起归档 |

- CI 产物 **MUST** 写入 `tmp/build/`。对外发布的二进制从 tag 的 CI 上传到 Release，不进 Git 树。可执行二进制 **MUST NOT** `git commit`。
- `dist/` 若入库，CI **MUST** 从源码重建并比对，比对失败即阻断。禁止只提交手改过的生成物。
- 发布说明若写“静态单二进制”，构建 **MUST** 显式 `CGO_ENABLED=0`（或 Rust 的等价静态链接参数）并在 CI 日志里保留该命令。需要 CGO 时，发布说明 **MUST** 写明动态库，不得仍称静态单二进制。

### 2.5 `.gitignore` 基线 `[CI]`

```gitignore
tmp/
*.exe
*.dll
*.so
*.dylib
*.test
*.out
*.log
*.pprof
coverage/
node_modules/
target/
.env
.env.*
!.env.example
*.key
*.p12
*.pfx
```

- **MUST NOT** 使用 `*secret*`、`*credential*` 这类子串通配，它们会把 `secret.go` 之类的源码排除出版本库。密钥扫描用 §7.1 的扫描器，不用 `.gitignore` 代替。
- `.env.example` **MUST** 能被提交，上面的 `!.env.example` 就是为此。
- `*.pem` 不进入基线。私钥用 `*.key`、`*.p12`、`*.pfx`。公钥或 CA 包需要入库时，放在单独目录并在 `PROJECT_RULES.md` 列出文件名。
- `vendor/` 不进入基线。需要把依赖 vendor 进仓库时，在 `PROJECT_RULES.md` 说明理由，并仍然提交 `go.sum` / `Cargo.lock`。
- Linux 与 macOS 上 `go build` 产出的二进制没有扩展名，上面的模式拦不住。二进制入库由 §15.2 的仓库纯净性检查按文件内容（ELF、Mach-O、PE 头）拦截，不靠 `.gitignore`。

### 2.6 收尾清洁 `[LOCAL]`

- 验证完毕 **MUST** 清理本次任务在 `tmp/` 下产生的文件，范围不得扩大到未提交的源码。
- 交付前 `git status --porcelain` **MUST** 为空。空表示没有已修改、已暂存、未跟踪的文件。只检查 `??` 的数量不够，已修改未提交的文件仍会被漏掉。

---

## §3 分层与解耦

> 本章约束进程、服务、模块之间的**技术**解耦方式。契约的**内容治理**（谁来定、何时定、如何随功能演进）见 §4。

### 3.1 同进程 `[REVIEW]` / `[CI]`

- **MUST** 通过 `interface`（Go）或 `trait`（Rust）隔离模块。接口 **MUST** 定义在消费方。**MUST NOT** 引用他人 `internal/` 的实现细节。依赖方向 **MUST** 单向，循环依赖 **MUST** 由工具保证不存在。`[CI]`
- Go 中某个类型要满足别处定义的接口时，**MUST** 有编译期断言 `var _ consumer.Store = (*impl.PGStore)(nil)`，接口签名一变，编译器当场报错。断言 **MUST** 放在已经同时依赖两边的地方：组装层（`main` 或 wiring 包），或消费方包的测试文件。实现方包 **MUST NOT** 为了写断言去导入消费方包，那会把依赖方向倒过来，甚至形成循环。接口与实现在同一个包时，断言放在实现文件底部。`[REVIEW]`

### 3.2 跨进程与跨服务 `[REVIEW]`

- **MUST** 通过 HTTP REST+JSON 或 gRPC+Protobuf 解耦。**MUST NOT** 跨服务引用私有结构体，**MUST NOT** 直接读写对方存储，**MUST NOT** 以共享数据库表充当服务间通信。
- 一件业务事实要让另一个进程知道时，**MUST** 把业务写入和待投递事件放进同一事务（transactional outbox），再由投递器发送。禁止“数据库写成功后再顺便发一条消息”，那一次失败会让两边状态不同。
- 消费方 **MUST** 按幂等键去重。队列是至少一次投递，不是恰好一次。
- 反复失败的消息 **MUST** 进入死信或隔离位置，并有次数上限。禁止毒消息无限重试占满 worker。
- 定时任务默认 **MUST NOT** 重叠运行。允许重叠时写在 `PROJECT_RULES.md`，并写明共享状态如何避免并发写坏。

---

## §4 契约治理（Contract Governance）

> 适用：`components: multi`、`frontend` 非 `none`，或 `network: inbound`。
>
> **本章解决的问题**：前端与后端、或两个服务之间，一方进度快、另一方跟不上，造成“可点但点了报错”“字段对不上”“状态显示与实际不符”这类小缺陷反复出现、修好一个又冒出新的。根源不是代码质量，而是缺少一份先于代码存在、有强制力的契约，以及“完成”的标准过于主观。§5 与 §6.1 管“数据权威在哪”，§3 管“用什么技术解耦”，本章管“契约何时定、谁不能越过它、如何证明双方真的对齐”。

### 4.1 契约先行（Contract-First）`[CI]` / `[REVIEW]` — 不可豁免

- 任意两个独立单元之间的新交互（浏览器前端与后端、两个服务、Go 与 Rust 组件、协议内核与其消费方），**MUST** 先产出契约并定稿入库。**MUST NOT** 一方先实现、另一方“照着猜”。功能性代码 **MUST NOT** 早于契约定稿开工（`spike/**` 不受此限，仍受 §0.3 约束）。开工顺序 CI 看不到，由 Review 核对提交历史 `[REVIEW]`；契约文件存在、类型由契约生成，由 CI 核对 `[CI]`。
- 契约载体：同步 HTTP 用 OpenAPI，gRPC 用 Protobuf，WebSocket、SSE、消息队列等异步通道用 AsyncAPI 或等价 schema。**MUST NOT** 以“实时性”或“异步性”为由跳过，这类通道恰恰是状态不一致的高发区。OpenAPI 与 AsyncAPI 取当前稳定版（附录 C）。
- 契约文件 **MUST** 是类型与 mock 的唯一来源（`oapi-codegen`、`openapi-generator`、`buf generate`、`prost`、`tonic` 等）。消费方 **MUST NOT** 手写与契约重复的类型，**MUST NOT** 手写与契约不同步的 mock。契约字段一变，编译期即报错，而不是运行时才暴露。
- 未定稿的契约 **MUST** 显式标为 `draft`。`draft` 契约 **MUST NOT** 用于生产构建，**MUST NOT** 作为 feature flag 开启的依据（§4.4）。
- 契约变更遵守 §4.6。契约定稿后，AI 代理 **MUST NOT** 在实现其他任务时顺带修改契约；发现契约有问题，作为独立变更重新评审（§14.6）。

### 4.2 状态机与状态枚举同源 `[REVIEW]`

- 具备多阶段生命周期的交互元素（连接类按钮、提交类表单、任务流程、异步轮询任务），以及跨单元共享的状态迁移（连接建立与断开等），**MUST** 有显式状态机。状态机 **MUST** 覆盖初始态、进行态、成功态，以及按错误类别细分的失败态，**MUST NOT** 只有一个笼统的“失败”。**SHOULD** 覆盖取消态、超时态、重复触发态。
- 状态机定义 **MUST** 与契约同批评审、同批入库，**MUST NOT** 事后补充。事后补状态机是漏测边界的最主要成因。
- 所有消费方（前端，或作为消费方的另一个后端服务）的状态取值集合，**MUST** 从契约定义的权威枚举派生，**MUST NOT** 独立定义“等价但不完全一致”的集合。新增状态值 **MUST** 同步进契约并遵守 §4.6。
- 消费方 **MUST NOT** 自行推断契约未定义的中间状态。契约未覆盖的迁移视为契约缺陷，**MUST** 回到 §4.1 重新评审，**MUST NOT** 由消费方单方面“合理猜测”后绕过。

### 4.3 契约一致性校验 `[CI]`

- CI **MUST** 检查调用方与契约是否一致，不一致即阻断合并。前后端边界与服务间边界同等适用，**MUST NOT** 只校验浏览器那一条边。
- 这项检查做得到的前提，是调用方使用由契约生成的客户端，或有一份生成的调用清单。调用方手写 URL 和字段名时，静态扫描不完整，报告里 **MUST** 写“未覆盖手写调用”，**MUST NOT** 写“已逐字段证明一致”。
- CI 或测试 **MUST** 用契约校验后端的实际响应（schema 测试）。只检查“调用方有没有按契约调用”，会漏掉“后端没有按契约实现”。
- 契约测试 **MUST** 覆盖多出来的字段与缺失的字段。生产代码是否拒绝未知字段由 §4.6 的兼容策略决定：生产反序列化 **MUST NOT** 默认拒绝未知字段（Go 的 `DisallowUnknownFields`、Rust 的 `serde(deny_unknown_fields)` 同理）。新增字段属于兼容变更，旧服务若拒绝它，新客户端一发出新字段就会失败。
- 未通过本检查的接口，其对应的 feature flag **MUST NOT** 处于 `ON`。

### 4.4 未就绪能力门禁与 Feature Flag `[CI]` — 不可豁免

- UI 组件的可交互态（按钮可点、表单可提交、菜单项可见）**MUST** 与其依赖的后端接口就绪状态一一对应，通过 feature flag 统一管理，flag 默认 `OFF`。
- flag 是否放行 **MUST** 由服务端判定。打进前端包的布尔常量只能影响文案，不能当作放行依据，使用者可以改包里的值。
- `frontend: embedded` 的前端与后端在同一个二进制里原子发布时，flag **MAY** 是服务端的启动配置或编译期常量，不要求运行时开关服务；但放行判断仍在服务端，未就绪接口仍 **MUST** 拒绝请求，UI 仍按下一条呈现禁用态。
- 接口 **MUST** 通过 §4.3 的校验与最小可用测试后，flag 方可置 `ON`。**MUST NOT** 把“UI 可交互但依赖接口未实现或未验收”的中间态合入主干：未就绪的功能，UI **MUST** 呈现为禁用态或骨架屏，**MUST NOT** 伪造可交互外观。
- 项目 **MUST** 维护接口就绪矩阵（模板见附录 D），功能立项时创建，作为 §4.7 完成定义的前置依据。
- flag 的生命周期 `[REVIEW]`：每个 flag 创建时 **MUST** 记录创建日期、对应的契约点、预期下线日期。对应接口在 §4.3 中稳定通过 30 日后，**SHOULD** 清理判断分支，**MUST NOT** 无限期保留恒为 `ON` 却仍在分支判断的 flag。CI **SHOULD** 定期扫描创建超过 90 日仍未移除判断代码的 flag 并出报告，超过 180 日的 **MUST** 在 CI 中显式告警。单一功能模块里相互嵌套的活跃 flag **SHOULD** 不超过 5 个，否则状态组合数无法穷举，附录 D 的验收清单实际失效。

### 4.5 错误模型与错误码注册表 `[CI]` / `[REVIEW]`

- 跨单元边界（HTTP 响应、RPC 状态、分布式消息）传递的错误，**MUST** 是带稳定 Code、Message 与机器可读 Detail 的结构化类型。HTTP API **SHOULD** 使用 RFC 9457 的 `application/problem+json`；gRPC 使用 status 加等价的结构化详情。**MUST NOT** 传输裸字符串或未分类的通用异常。`[REVIEW]`
- 内部基础设施错误（数据库连接失败、文件 I/O 错误、内网 IP）在向外暴露前 **MUST** 脱敏并转换为对外错误码，**MUST NOT** 把内部堆栈或敏感配置泄露给消费端。`[REVIEW]`
- 项目 **MUST** 维护仓库级或组织级的错误码注册表（如 `errors/registry.yaml`）。新增错误码 **MUST** 先登记再进契约。错误码 **MUST** 带子系统前缀（如订阅中台 `SUB_QUOTA_EXCEEDED`、协议内核 `KERN_NODE_UNAVAILABLE`），**MUST NOT** 跨子系统复用同一错误码表示不同含义。没有前缀的 `QUOTA_EXCEEDED` 不合格。CI **MUST** 校验新增错误码已登记且前缀与所属子系统一致，未登记即阻断。`[CI]`
- 消费方对每个错误码 **MUST** 有对应的处理与用户文案。“未知错误”只作兜底，**MUST NOT** 用它承载本应处理的已知错误码。

### 4.6 兼容性与版本演进 `[CI]` / `[REVIEW]`

- 已发布 API **MUST NOT** 破坏性变更。Protobuf **MUST** 过 `buf breaking`，已删字段的编号与名称 **MUST** `reserved`。OpenAPI **MUST** 过 `oasdiff breaking`，并带 `--fail-on ERR`（不带时发现破坏性变更也返回 0）。`kind: library` 的公开 API，Go 用 `gorelease`，Rust 用 `cargo semver-checks` 检查。破坏性变更 **MUST** 升主版本。`[CI]`
- HTTP API **MUST** 使用路径版本前缀（`/v1/...`）。gRPC **MUST** 把版本放在 protobuf package 名里，不套用 HTTP 路径规则。`[REVIEW]`
- 废弃 **MUST** 在响应头（`Deprecation`，RFC 9745；下线时间用 `Sunset`，RFC 8594）或服务声明中标明，文档写明替代项。并行期 **SHOULD** 不少于 90 日，下线前确认调用方已归零。安全修复若不能等满 90 日，走 §18.2 并写明受影响的调用方。`[REVIEW]`

### 4.7 完成定义与验收颗粒度 `[REVIEW]`

- 联动类任务的拆分粒度 **MUST** 对应到“一个契约点”（一个接口的一条状态迁移路径），**MUST NOT** 以“实现 XX 功能”这种粗粒度描述单独下发或验收。
- 每个任务 **MUST** 附可自动核验的完成定义（类型检查通过、契约 diff 一致、对应测试通过），**MUST NOT** 用“体验良好”“基本能用”充当完成定义。
- 交互元素级验收 **MUST** 覆盖附录 D.2 的清单：契约字段一致性、错误码到 UI 文案的映射完整性、状态机每条迁移边的测试、防重复触发与 loading 态与超时处理三项均已实现。

---

## §5 前端瘦客户端与零信任

> 适用：`frontend` 非 `none`（§5.8 仅 `mobile`；§5.6 的产物与体积条款仅 `embedded` 与 `web`）。
>
> 本章是架构级红线。前端持有业务事实或硬编码密钥，是安全与数据完整性事故的直接成因。零信任客户端模型指：任何离开服务端可信边界的代码都 **MUST** 被当作运行在攻击者机器上，服务端 **MUST** 对其输入重新验证，这与 OWASP ASVS 的“不信任客户端输入”同源（附录 C）。本章约束前端“能装什么”，§5.6 约束“用什么造、占多少资源”，§4 约束“何时能对用户暴露”，三者独立生效。

### 5.1 核心原则 — 不可豁免

- 前端代码 **MUST NOT** 包含任何明文形式的密钥、Token、连接串、内部服务地址、业务规则常量（价格、折扣率、权限阈值、风控分数线）。
- 混淆（minify、obfuscate）**MUST NOT** 被视为满足本条。开发者工具几秒内即可还原字符串常量，混淆只增加阅读成本，不构成安全边界。
- 前端 **MUST NOT** 硬编码随业务运营变化的数据，此类数据 **MUST** 在运行时通过鉴权 API 获取。
- 前端 **MUST NOT** 承担业务事实的最终判定（金额计算、权限判断、库存扣减、状态机流转、风控决策）。前端侧的同类计算只可作乐观 UI 反馈，**MUST** 以服务端结果为准。
- 判定公式：**“如果攻击者篡改前端返回的这个值，后端是否会照单全收？”** 答案是“会”，该值 **MUST** 移入服务端权威判定。
- 只读的内部展示页，可以不在浏览器里把服务端已经算过的展示结果再算一遍。服务端鉴权、对象级授权和业务校验不得省略，明文密钥、连接串和 §5.3 的存储边界仍然适用。这不是 §18.2 豁免，也不因为“只在内网”而成立。

### 5.2 数据流向的唯一路径 `[REVIEW]`

- 前端所需的业务数据 **MUST** 经认证后的运行时 API 获取，**MUST NOT** 以构建期注入常量、静态 JSON、打包内嵌配置的形式存在。
- 例外（**MAY**）：纯展示性的公开文案；非对称加密的公钥本身（**MUST NOT** 以此为由内嵌私钥或对称密钥）；不含业务敏感信息的版本号与构建时间戳。
- 判定含糊时 **MUST** 按敏感数据处理。不能证明泄露无影响的常量，不得打进前端产物。

### 5.3 前端本地存储的边界 `[REVIEW]`

- `localStorage`、`sessionStorage`、`IndexedDB`、Cookie **MUST NOT** 持久化业务事实（余额、权限列表、订单状态、库存数量），**MUST** 每次以服务端为准重新拉取。
- **MAY** 用于会话令牌、纯 UI 偏好、未提交的草稿。会话令牌 **SHOULD** 放在设置了 `HttpOnly`、`Secure`、`SameSite` 的 Cookie 里，放在 `localStorage` 时一段 XSS 就能读走。使用 Cookie 承载会话时，状态变更请求 **MUST** 有 CSRF 防护。具体 Cookie 属性写在 `PROJECT_RULES.md`。
- **MUST NOT** 在缺乏服务端重新校验的情况下，把本地存储的数据当作鉴权或计费依据。

### 5.4 服务端的对应义务 `[CI]`

- 服务端 **MUST** 对所有写请求重新执行完整的鉴权与业务规则校验，**MUST NOT** 信任前端传入的价格、折扣、权限标志、未验证的身份声明。
- API 响应体 **MUST NOT** 返回超出当前用户权限范围的字段。**MUST NOT** 依赖前端“不显示”来实现权限隔离。

### 5.5 CI 强制扫描 `[CI]`

- 前端构建产物（含 sourcemap 还原后）**MUST** 经密钥模式扫描，命中即阻断发布。
- **MUST** 维护“禁止内嵌关键词”清单（`SECRET`、`PRIVATE_KEY`、`DB_PASSWORD` 等），对最终产物做静态字符串扫描。
- 前端构建 **MUST** 用显式的“公开变量前缀”白名单（如 `PUBLIC_*`），未加前缀的环境变量 **MUST NOT** 被内联进产物。

### 5.6 前端技术栈与资源预算 `[CI]`

- `frontend: embedded`（控制台、管理面板）**MUST** 零运行时依赖交付，通过 `//go:embed` 或 `rust-embed` 嵌入单二进制。**MUST NOT** 引入运行时前端框架。**MAY** 使用 TypeScript、`esbuild` 等纯构建期工具，产出 **MUST** 运行时依赖数为 0、单页 JS gzip 小于 150 KB。
- `frontend: web`（独立部署的浏览器前端）**MAY** 使用运行时框架。锁文件 **MUST** 入库，CI **MUST** 以锁定模式安装（如 `npm ci`），依赖纳入 §7.6 的漏洞扫描与准入审查。单页 JS gzip 预算写在 `PROJECT_RULES.md`，超出即阻断。
- 两者都 **MUST NOT** 提交 `node_modules/`。首屏可交互时间 **SHOULD** 小于 2 秒。
- 所有前端（含 `mobile`）**MUST NOT** 把轮询作为获取业务数据的默认手段，**SHOULD** 优先按需请求或服务端推送（SSE、WebSocket）。确需轮询时 **MUST** 设置最小间隔，非实时场景 **MUST NOT** 小于 1 秒。

### 5.7 派生状态与单一数据源 `[REVIEW]`

前端 **MUST NOT** 为已由后端持有的业务事实（权限、额度、订单状态等）在客户端维护第二份可变状态，并据此独立做渲染决策。展示态 **MUST** 以最近一次后端响应为准。判定所需的数据过期时 **MUST** 重新拉取，**MUST NOT** 沿用本地缓存推断出的值继续驱动交互判断。

### 5.8 移动端 `[REVIEW]`

- 涉及 iOS/Android 客户端的项目 **MUST** 遵循对应商店的审核指南与隐私声明要求（App Store 审核指南与隐私清单、Google Play 政策与数据安全声明，以当前官方版本为准）。VPN 类应用的权限声明与用途说明尤其严格。变更权限使用范围 **MUST** 提前评估审核风险。
- **MUST NOT** 使用非官方 API 或规避系统限制的方式维持后台存活。后台常驻能力 **MUST** 通过系统提供的合法机制实现（如 iOS 的 Network Extension、Android 前台服务）。
- §5.3 的本地存储边界同等适用于移动端。系统安全存储（Keychain、Keystore）**MAY** 用于凭证加密存储，但同样 **MUST NOT** 作为业务事实的最终判定依据，敏感状态仍 **MUST** 以服务端为准重新校验。

---

## §6 数据所有权、持久化与数据库加固

> 适用：`persistence` 非 `none`（范围见 §0.6）。**§6.1 不可通过 §18.2 豁免。** 已持久化的业务事实只能有一个权威来源：在数据库中的以数据库为准，只存在于文件中的配置以该文件为准。前端存储、缓存、队列快照、读副本都不是权威来源。具体引擎与表结构由项目决定。

### 6.1 数据所有权 `[REVIEW]` — 不可豁免

- 每张表或命名空间 **MUST** 只有一个写入方。其他进程要读时 **MUST** 走 API 或 §3.2 的 outbox，不得直接写对方的表。
- 存在数据库里的业务事实，判定时 **MUST** 以主库当前已提交的数据为准。缓存、前端本地存储、队列快照、读副本都是副本，不一致时以主库为准。
- 写后立刻要读的路径 **MUST** 读主库。读副本有延迟，不能用来判断“刚才那次写入是否生效”。
- `tenancy: multi` 时，查询和写入 **MUST** 带租户条件。禁止先取出多个租户的行，再在内存里挑出当前租户。

### 6.2 Schema 设计与完整性约束 `[CI]` / `[REVIEW]`

- 关键字段 **MUST** 在数据库层有约束（`NOT NULL`、外键、`CHECK`、唯一索引）。只在应用层校验，挡不住误跑的脚本和旁路写入。
- 金额 **MUST** 使用整数最小货币单位或定点数，**MUST NOT** 使用浮点。加减 **MUST** 检查溢出，溢出时返回错误，不得回绕后继续记账（CWE-190）。舍入规则写在 `PROJECT_RULES.md`。
- 会被并发更新的行 **MUST** 使用版本列、`UPDATE ... WHERE version = ?`，或由唯一约束拒绝重复写入。禁止读进进程、在内存里改完、再无条件写回。
- 状态机字段 **SHOULD** 用 `CHECK` 限制合法取值。
- 时间字段 **MUST** 存 UTC。字段含义是时间点时，类型 **MUST** 带时区（如 PostgreSQL 的 `timestamptz`），不得用无时区的本地时间字符串。SQLite 没有带时区的时间类型，**MUST** 存 RFC 3339 的 UTC 文本（以 `Z` 结尾），或存带单位的整数（列名写单位，如 `created_at_ms`），同一库内统一一种。
- SQL 里 `NULL` 与空串不是一回事，`WHERE col != 'x'` 选不中 `NULL`。每一列在注释里规定用 `NULL` 还是空串表示“没有”，不得混用。
- SQLite 的外键默认关闭，使用 SQLite 时 **MUST** 同时遵守 §6.10。

### 6.3 迁移 `[CI]`

- Schema 变更 **MUST** 以版本化迁移脚本入库，**MUST NOT** 手工在生产执行 DDL。每个迁移 **MUST** 提供回滚脚本。
- 破坏性变更 **MUST** 采用 expand-contract 三段式，单次迁移 **MUST NOT** 同时 expand 与 contract。
- contract 阶段（删列、删表）的数据无法靠回滚脚本找回。这类迁移的回滚脚本 **MUST** 在开头注明“不可逆”，并写明恢复所依赖的备份（§6.7）；按 §15.5 单独发布。
- CI **MUST** 校验每个迁移都有回滚部分，并在临时库里依次执行 up、down、up。回滚部分的形式跟随所用工具：成对的 `.up.sql` 与 `.down.sql`，或单文件内的 Up/Down 段（如 goose）。

### 6.4 访问控制与最小权限 `[REVIEW]`

各服务 **MUST** 使用独立的数据库账号，**MUST NOT** 共用管理员账号。业务账号 **MUST NOT** 拥有 `DROP`、`ALTER`、`GRANT`。迁移专用账号与运行时账号 **MUST** 分离。数据库管理端口 **MUST NOT** 暴露公网。

### 6.5 敏感数据加密 `[REVIEW]`

- 密码 **MUST** 用慢哈希（`argon2id`，或兼容旧数据时的 `bcrypt`），**MUST NOT** 明文或可逆加密存储（参数见 §7.4）。
- PII **MUST** 做字段级加密，**SHOULD** 优先应用层加密。密钥 **MUST** 由 Secret Manager 管理，**MUST NOT** 与数据库凭证同库。
- 数据库连接 **MUST** 使用 TLS，**MUST NOT** 用明文协议连生产库。

### 6.6 审计日志 `[REVIEW]`

关键表的写操作 **MUST** 有审计追踪（谁、何时、旧值到新值）。审计记录 **MUST** 追加写入，业务账号 **MUST NOT** 能删改。**SHOULD** 用触发器或 CDC，而不是只靠应用层。

### 6.7 备份与灾备 `[REVIEW]`

- `persistence: server-db` 的生产库 **MUST** 有定期备份，并有时间点恢复或等价的恢复窗口。备份存放 **MUST** 与生产库的磁盘分开。
- 恢复步骤 **MUST** 写在仓库或运维手册里。CI 只能检查这份文档在不在，生产任务有没有按计划跑、备份能不能打开，CI 看不到。
- **SHOULD** 至少每季度做一次恢复演练，并留下日期和结果。没有演练记录的备份只能称为“有备份脚本”，不能称为“已验证可恢复”。

### 6.8 连接治理 `[REVIEW]`

**MUST** 使用连接池并设置上限。慢查询 **MUST** 有监控告警。高频只读 **SHOULD** 走读副本，**MUST NOT** 与核心事务链路共享没有隔离的连接池。资源预算见 §9.3。

### 6.9 SQL 游标与事务回滚（Go）`[CI]`

- `for rows.Next()` 结束后、函数返回前，**MUST** 检查 `rows.Err()`。中途断连时，只靠 `Next` 会得到一份不完整的结果。
- `rows.Close()` **MUST** 在成功拿到 `rows` 之后立刻 `defer`，禁止写在 `for` 循环里（§11.2）。

```go
rows, err := tx.QueryContext(ctx, query, args...)
if err != nil {
    return fmt.Errorf("query orders: %w", err)
}
defer rows.Close()
for rows.Next() {
    // 扫描当前行
}
if err := rows.Err(); err != nil {
    return fmt.Errorf("iterate orders: %w", err)
}
```

- 开启事务后 **MUST** 无条件 `defer Rollback`。`Commit` 成功后再 `Rollback`，`database/sql` 返回 `sql.ErrTxDone`，该错误可以忽略，其他回滚错误 **MUST** 记入日志。
- **禁止**写成 `defer func() { if err != nil { tx.Rollback() } }()`。`defer` 看到的是变量 `err`，不是函数返回值。`return fmt.Errorf(...)` 不一定给这个变量赋值，事务就不会回滚，锁会留到连接被回收。

```go
tx, err := db.BeginTx(ctx, nil)
if err != nil {
    return fmt.Errorf("begin: %w", err)
}
defer func() {
    if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
        slog.Error("rollback", "err", rbErr)
    }
}()
// 读写。失败直接 return，defer 会回滚。
if err := tx.Commit(); err != nil {
    return fmt.Errorf("commit: %w", err)
}
return nil
```

Rust 侧使用的数据库库若在事务对象被丢弃时回滚（如 `sqlx`），**MUST** 在代码里明确事务边界，**MUST NOT** 依赖“忘记提交也没关系”。

### 6.10 SQLite `[CI]`

仅 `persistence: sqlite` 时生效。

- 每个连接 **MUST** 执行 `PRAGMA foreign_keys = ON`。SQLite 默认关闭外键，建表语句里写了 `REFERENCES` 也不会生效。Go 的 `database/sql` 有连接池，只在打开后执行一次 `Exec` 只作用于其中一个连接，**MUST** 写进 DSN 参数或驱动的连接钩子。
- 写者同时只能有一个。可以用单独的写句柄并 `SetMaxOpenConns(1)`，或用单写者队列。
- 多个读连接 **MUST** 配合 WAL（`PRAGMA journal_mode = WAL`）。回滚日志模式下多个连接容易出现 `database is locked`。
- `SetMaxOpenConns(1)` 会把读也串行化，它不是所有 SQLite 程序的必选项。实际采用的日志模式和连接数 **MUST** 写进 `PROJECT_RULES.md`。
- `busy_timeout` **MUST** 显式设置为非零且有限的值（同样写进 DSN 或连接钩子）。默认值为 0，遇到锁立即返回 `database is locked`；数值写进 `PROJECT_RULES.md`。

### 6.11 数据保留与删除 `[REVIEW]`

- 适用：`pii: true`，或存在用户账号数据。项目 **MUST** 在 `PROJECT_RULES.md` 明确各类用户数据（账号信息、使用与连接日志、计费记录、AI 交互记录等）的保留期限，**SHOULD** 遵循“非必要不长期保留”。`[REVIEW]`
- 用户请求删除账号或数据时，**MUST** 在承诺时限内完成主存储删除，时限 **SHOULD** 不超过 30 日，具体日期写在 `PROJECT_RULES.md`。备份里的残留 **MUST** 说明处理方式：不要求立刻从所有备份介质擦除，但备份过期之后不得再被恢复成可用数据。删除是否按时完成 CI 看不到，由删除工单与审计日志核对。`[REVIEW]`
- 法律或合同要求保留期间，暂停删除，在 `WAIVERS.md` 或删除工单里写下依据和到期日，到期再删。不得为满足 30 日条款而删除依法应保留的数据（§0.3 法律优先）。
- 删除操作 **MUST** 审计留痕（§6.6），**MUST NOT** 是无留痕、不可追溯的静默物理删除脚本。

---

## §7 安全基线

### 7.1 密钥与凭证 `[CI]`

- **MUST NOT** 把密钥、Token、密码、私钥硬编码在代码、配置或提交历史里。前端从严执行（§5，混淆不豁免）。
- 凭证 **MUST** 经环境变量或 Secret Manager 注入。已泄露的凭证 **MUST** 立即轮换。**SHOULD** 建立定期轮换周期（一般凭证不超过 90 日，高敏感凭证不超过 30 日）。
- CI 到云平台等外部系统的访问 **SHOULD** 使用短期凭证（OIDC 联合身份），而不是长期静态密钥放进 CI 的 Secret。
- 密钥扫描 **MUST** 覆盖全部提交历史与前端产物（§15.2）。

### 7.2 鉴权与授权 `[REVIEW]`

- `network: inbound` 的对外接口 **MUST** 鉴权（JWT、API Key、mTLS 或 OIDC）。管理接口 **MUST NOT** 无鉴权暴露在公网。凭证比较 **MUST** 使用恒定时间比较。
- 鉴权通过只说明“这个调用者是谁”。按 ID 读写对象时 **MUST** 再核对对象属于该调用者或该租户，缺少这一层就是对象级越权（OWASP API1:2023）。返回字段同样 **MUST** 按调用者权限裁剪（§5.4）。
- 服务之间的调用 **MUST** 验证调用方。来源 IP 属于内网不是验证。
- 使用 JWT 时 **MUST** 固定算法白名单，`none` **MUST NOT** 被接受，密钥类型 **MUST** 与算法匹配，**MUST** 校验 `iss`、`aud`、`exp`（RFC 8725）。
- OAuth 2.0 / OIDC **MUST** 使用授权码加 PKCE，**MUST NOT** 使用 implicit 与资源所有者密码授权，并遵循 OAuth 2.0 安全最佳实践（RFC 9700）。

### 7.3 输入验证与外部数据 `[REVIEW]`

- 外部输入（含前端传入的字段，无论前端是否已校验）**MUST** 做类型与边界检查。请求体 **MUST** 有大小上限。SQL **MUST** 参数化。具体的空值与格式校验位置见 §11.6。
- 文件路径 **MUST** 做穿越检查。Go 访问由外部输入决定的路径时 **SHOULD** 使用 `os.Root` 把访问限定在根目录之内。
- 服务端代为请求用户提供的 URL 时，**MUST** 限制协议、目标地址（含内网与元数据地址）和重定向次数，禁止把该 URL 直接交给默认 HTTP 客户端（CWE-918）。
- 解压或解码外部数据 **MUST** 限制解压后的大小。用户输入 **MUST NOT** 直接编译成正则表达式，确需如此时限制长度并设置匹配时限。
- 启动外部程序 **MUST** 使用参数切片，**MUST NOT** 经 shell 拼接外部字符串。

### 7.4 传输与密码学 `[CI]` / `[REVIEW]`

- 传输 **MUST** 使用 TLS 1.2 或更高，**MUST** 支持 TLS 1.3，**MUST NOT** 启用 TLS 1.0、1.1 与 SSL。生产 TLS 配置 **MUST NOT** 关闭证书校验（Go 的 `InsecureSkipVerify: true` 及各语言的等价项，CWE-295），测试使用测试 CA。`[CI]`
- 混合后量子密钥交换 **SHOULD** 保持启用。Go 标准库 `crypto/tls` 默认已启用，没有 ADR 不得手动关闭；Rust 侧以所用 TLS 库的文档为准。
- 令牌、会话标识、幂等键、密码重置凭证 **MUST** 使用操作系统的密码学随机源（Go 的 `crypto/rand`，Rust 的 OS RNG 或 `getrandom`），**MUST NOT** 使用 `math/rand`（CWE-338）。`[CI]`
- 密码哈希 **MUST** 使用 `argon2id`（RFC 9106），参数按 OWASP Password Storage Cheat Sheet 的当前推荐设置。对称加密 **MUST** 使用 AEAD（AES-GCM 或 ChaCha20-Poly1305），**MUST NOT** 使用 ECB 或无认证的 CBC。`[REVIEW]`
- **MUST NOT** 自研密码算法或协议，**MUST** 使用标准库或经过审计的库。`[REVIEW]`

### 7.5 限流与滥用防护 `[CI]` / `[REVIEW]`

> 本章约束对外接口的请求速率与失败次数。业务上什么行为算滥用，写在 `PROJECT_RULES.md`。§7.2 管身份，§8 管下游故障，本节管一个调用方能不能把进程的 CPU、内存或连接数打满。

- 对外接口 **MUST** 分级限流：按来源 IP、按账号或 API Key、按接口敏感等级（认证类接口 **MUST** 比普通读接口更严）。阈值 **MUST** 配置化，**MUST NOT** 硬编码在业务逻辑里。超限响应 **MUST** 返回标准化错误码与 `Retry-After`。`[REVIEW]`
- 认证类接口（登录、注册、密码重置、Token 刷新、连接鉴权）**MUST** 对连续失败加延迟并设次数上限，无限次尝试等于允许在线猜凭证。直接锁定账号会被用来锁住受害者，若采用锁定，**MUST** 有解锁条件并记入日志，优先使用延迟与告警。**MUST** 有测试覆盖“第 N+1 次失败被延迟或拒绝”。`[REVIEW]`
- `replicas` 大于 1 时，计数 **MUST NOT** 只放在进程内存里，否则限流阈值会被副本数乘大。`[REVIEW]`
- 需要限制并发会话数时，计数 **MUST** 由服务端在一个原子操作里增减（同一事务、唯一约束或数据库原子语句）。禁止读出 N、在进程里加一、再写回 N+1，两个请求会同时读到 N。前端 **MUST NOT** 自己计算“还允许几个会话”并当作放行依据。`[REVIEW]`
- 核心服务 **SHOULD** 对账号级异常行为（同一凭证短时间内来自大量不同 IP、异常高频建连与断连）做基础检测与告警，检测规则 **MUST** 与业务逻辑解耦、可独立调整，**MUST NOT** 需要重新发版才能改阈值。`[REVIEW]`
- 新增对外写接口 **MUST** 声明限流策略。CI **MUST** 检查是否存在未声明限流策略的新增公开写接口，未声明即阻断。`[CI]`

### 7.6 依赖与供应链 `[CI]` / `[REVIEW]`

- `go.sum`、`Cargo.lock` **MUST** 入库。CI **MUST** 以锁定模式构建（Go 的 `-mod=readonly`，Rust 的 `--locked`），**MUST NOT** 自动升级依赖。`[CI]`
- CI **MUST** 做漏洞扫描（`govulncheck`、`cargo audit` 或 `cargo deny` 的 advisories 检查），高危零容忍。Rust 项目 **MUST** 用 `cargo deny` 约束许可证、禁用清单与允许的依赖来源。基础镜像同在扫描范围内。`[CI]`
- 依赖 **SHOULD** 由 Dependabot 或 Renovate 之类的工具自动提更新 PR。安全更新 **SHOULD** 在高危漏洞公布后 7 日内、其余 30 日内合入。无法按期时走 §18.2 并写明缓解措施。`[REVIEW]`
- 准入审查 `[REVIEW]`：
  1. 许可证白名单 **MUST** 写成机器可读配置并由 CI 检查（Rust 用 `deny.toml`，Go 用 `go-licenses` 等工具的配置）。常见可直接接受：MIT、Apache-2.0、BSD-2-Clause、BSD-3-Clause、ISC、Zlib、BSL-1.0、CC0-1.0、Unicode-3.0（Rust 几乎所有项目都经 `unicode-ident` 间接依赖它）。MPL-2.0、LGPL 等弱 copyleft **SHOULD** 逐个评审后加入。GPL、AGPL 默认 **MUST NOT** 进入闭源产物，例外走 §18.2。
  2. **MUST NOT** 引入存在未修复漏洞、已被官方标记为不再维护（如 RustSec 的 unmaintained 公告）或对安全问题无响应的依赖。
  3. 新增传递依赖超过 10 个 **MUST** 说明理由。
  4. **SHOULD** 优先标准库，引入外部依赖 **MUST** 注明理由与替代方案评估。
- `kind: library` 与 `kind: service` 的 Release **MUST** 附 SBOM（CycloneDX 或 SPDX）与校验和，**SHOULD** 附构建来源证明（SLSA provenance，Build L2 起）并用 Sigstore 签名。没有签名就 **MUST NOT** 写成已签名（§15.4）。`[CI]`

### 7.7 容器与运行时加固 `[CI]`

> 对齐 CIS Docker/Kubernetes Benchmark 与 NIST SP 800-190，同时是 §9 资源效率的执行载体：容器层的资源限制与安全边界是一体两面。

- 生产镜像 **MUST** 使用最小基础镜像（distroless、`scratch` 或精简变体），**MUST NOT** 用完整发行版镜像作生产运行时。基础镜像 **MUST NOT** 使用 `:latest` 标签，**MUST** 固定摘要（digest）或明确版本号。
- 容器进程 **MUST** 以非 root 运行，**MUST NOT** 使用 `--privileged`，**SHOULD** 丢弃全部 capabilities 并禁止提权，seccomp 使用运行时默认配置。
- 容器文件系统 **MUST** 只读挂载（`readOnlyRootFilesystem`），需要写入的路径 **MUST** 显式声明为独立 volume。
- 容器 **MUST** 设置显式的 CPU 与内存 `requests` 和 `limits`（§9.1）。
- 最终镜像 **MUST** 多阶段构建，**MUST NOT** 包含构建期工具链。

### 7.8 漏洞披露与响应 `[REVIEW]`

- `kind: library`、`kind: service` 以及任何对外分发的产物，仓库根目录 **MUST** 有 `SECURITY.md`：报告渠道、受理与响应时限、受支持的版本。
- 已知被利用的漏洞与严重安全事件，**MUST** 按适用的法规与合同上报。面向欧盟市场的含数字元素产品，欧盟 Cyber Resilience Act 的漏洞与事件报告义务自 2026-09-11 起适用，其余义务自 2027-12-11 起适用。具体流程写在 L1，L0 不替项目发明。
- 处理个人数据的项目，数据泄露的通知时限按适用的隐私法规执行（`pii: true`）。
- 漏洞修复发布后 **SHOULD** 公开披露，写明受影响版本与修复版本。

---

## §8 稳定性工程

> 对齐 Google SRE 的核心工程模式：超时、重试、熔断降级、幂等、优雅关闭、错误预算。目标是让单点故障不传导为级联故障。来源对照见附录 C。

### 8.1 超时控制 `[CI]` / `[REVIEW]`

- 一切跨进程 I/O（HTTP 客户端、数据库查询、RPC、消息队列）**MUST** 设置显式超时，**MUST NOT** 使用语言或库的无限等待默认值。`[CI]`
- 有 §13.4 测量数据时，超时值 **MUST** 以实测延迟分位数为依据（**SHOULD** 取 p99 的 2 到 3 倍为起点）。没有测量（例如 CLI 调用第三方 API）时，**MAY** 使用估算值，但 **MUST** 在 `PROJECT_RULES.md` 或代码注释里标“估算”，**MUST NOT** 写成“已按实测设定”。`[REVIEW]`
- 请求链路跨多层服务时，下游超时 **MUST** 严格小于上游超时，**SHOULD** 预留不少于 20% 的余量。
- Go **MUST** 用 `context.Context` 传播截止时间与取消信号（§8.9）。Rust **MUST** 使用带超时的异步原语（如 `tokio::time::timeout`）。

### 8.2 HTTP 客户端 `[CI]`

仅 `network` 为 `outbound` 或 `inbound` 且进程自己会向外请求时生效。

- Go **MUST NOT** 使用 `http.DefaultClient`，**MUST NOT** 裸调用 `http.Get`、`http.Post`，它们的 `Timeout` 是 0，对端不返回时 goroutine 会一直停着。Rust 的 HTTP 客户端（如 `reqwest`）默认也没有总超时，**MUST** 显式设置总超时与连接超时。
- Go 的每个客户端 **MUST** 设置 `http.Client.Timeout`；它覆盖连接、重定向以及读取响应体的全过程。改用 `Transport` 级超时（`ResponseHeaderTimeout`、`TLSHandshakeTimeout`、`net.Dialer.Timeout`）时，这些超时不覆盖响应体的读取，**MUST** 另给 Body 的读取设截止时间。Go 的 `Client` 没有名为 Connect、Read、Write 的三个字段。
- 客户端与 `Transport` **MUST** 复用，**MUST NOT** 每次请求新建。
- `Client.Do` 返回的 `err == nil` 时，`Body` 非 nil，调用方 **MUST** 关闭。只 `Close` 不读到 EOF，连接往往无法复用；排水是为了复用，不是为了把任意大小的 body 读进进程。
- `err != nil` 时不得假设 `resp` 可用。重定向检查失败时 Go 可能返回非 nil 的 `Response`，但其 `Body` 已关闭，这种错误直接返回，不要按成功路径排水。

```go
resp, err := client.Do(req)
if err != nil {
    return fmt.Errorf("do request: %w", err)
}
defer func() {
    // 业务代码先读自己需要的部分。返回前最多再丢弃 1 MiB 便于连接复用，
    // 超出上限就放弃复用，不得为排空而读完大小未知的响应。
    _, copyErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
    closeErr := resp.Body.Close()
    if copyErr != nil || closeErr != nil {
        slog.Warn("drain response", "copy", copyErr, "close", closeErr)
    }
}()
```

调用方要把 body 转发给下游时，先转发，再按上面的上限丢弃剩余部分。

### 8.3 重试策略 `[REVIEW]`

- 重试 **MUST** 仅针对幂等操作或已确认可安全重试的操作（§8.4），**MUST NOT** 对非幂等写操作盲目重试。
- 重试 **MUST** 使用指数退避加随机抖动，**MUST NOT** 固定间隔。重试次数 **MUST** 设上限。客户端 **SHOULD** 尊重下游返回的 `Retry-After`。

### 8.4 幂等性 `[REVIEW]`

- 对外暴露的写操作 API（支付、下单、状态变更类）**MUST** 支持幂等键，**MUST NOT** 假设网络层不会重复投递。HTTP 上 **SHOULD** 使用 `Idempotency-Key` 请求头。该头目前仍是 IETF 草案，状态变化以 IETF 官方页面为准，采用时在 ADR 里记录。
- 幂等键的去重判定 **MUST** 落库（§6.1），**MUST NOT** 仅存于内存或缓存。

### 8.5 熔断与降级 `[REVIEW]`

- 对下游依赖的调用 **SHOULD** 实现熔断：错误率超过阈值时快速失败，而不是持续等待超时。
- 核心服务 **MUST** 为关键依赖故障预先设计降级行为（返回缓存值、默认值或明确的降级提示），**MUST NOT** 让单一非核心依赖的故障拖垮整个请求，降级路径 **MUST** 有测试（§13.4）。
- 降级 **MUST NOT** 以牺牲 §4、§5、§6 的数据完整性与契约红线为代价。

### 8.6 优雅关闭与排空 `[CI]` / `[REVIEW]`

仅 `kind: service` 生效。

- 收到停止信号后 **MUST NOT** 立刻退出，分两步：
  1. `/readyz` 返回 503，从负载均衡摘除，停止接受新请求。`/healthz` 在排空期间保持成功。
  2. 等待在途请求结束，随后释放数据库连接池、关闭消息队列消费者等资源。等待上限来自配置：起点可以是 p99 的数倍，长上传与 SSE 必须单独加大。代码里写死 `15s` 且没有配置项，不合格。
- 超过上限仍未结束时，记录错误并退出，不得无限期停在停机流程里挡住后续发布。编排系统的终止宽限期 **MUST** 大于排空上限。
- Unix 上的停止信号通常是 `SIGTERM`；Windows 服务的停止通知来自服务控制管理器，不来自 `SIGTERM`。程序实际监听哪一种，写在 `PROJECT_RULES.md`。
- 测试 **MUST** 覆盖一次“收到停止后 readiness 失败且 liveness 仍成功”。

### 8.7 健康与就绪 `[REVIEW]`

- `kind: service` **MUST** 分开两个检查：`/healthz` 只表示进程还活着（liveness），`/readyz` 表示可以接流量（readiness）。Kubernetes 在 liveness 失败时会重启容器，把“摘流量”做成 liveness 失败，滚动发布会在排空过程中把进程杀掉。启动很慢的进程 **SHOULD** 另设启动探针。
- readiness **MUST** 检查关键下游。下游不可用时 readiness 失败，liveness 保持成功，直到进程自己无法继续运行。
- 存活判定 **MUST** 基于真实的进程身份，**MUST NOT** 只因为端口有响应就认为是本次发布的进程。
- 安装、卸载、部署 **MUST** 可重复执行，重复执行不得制造第二份互相矛盾的状态。部署形态的细则（Windows 服务的停止通知、探针路径）写在 `PROJECT_RULES.md`，L0 不替项目发明。

### 8.8 关键文件替换 `[CI]`

仅 `persistence: file`，或服务需要把配置、证书、规则写到磁盘时生效。本条减少“读者看到半截文件”的窗口，它不能保证断电后新数据还在，也不能把 Windows 上的 `os.Rename` 说成原子操作。

Go 的 `os.Rename` 文档写明：目标已存在且不是目录时会替换它；在非 Unix 平台上，即使在同一目录内，这次替换也不是原子操作；目标文件被占用时，Windows 上的调用会失败。

- **MUST** 把临时文件创建在目标文件的同一目录（由目标路径推出，不另传目录参数）。禁止先删除目标再写入。
- **MUST** 写完后 `Sync`，再 `Close`，再 `Rename`。任何一步失败都要关闭并删除临时文件，保留原目标。`Rename` 失败时返回错误，**MUST NOT** 调用仓库里没有定义的“备用回滚函数”。
- `os.CreateTemp` 建出的文件权限是 `0600`。替换后 **MUST** 保留原文件的权限位，否则以其他用户运行的读者会突然读不到。所有者与 ACL 不随之保留，需要时在 `PROJECT_RULES.md` 写明处理方式。
- POSIX 上同一目录内的 `rename` 对读者是原子的：要么看到旧文件，要么看到新文件。要求断电后目录项也不丢时，**SHOULD** 再对该目录 `fsync`。Windows 没有同等的目录 `fsync`。需要崩溃原子替换时，**MUST** 在 `PROJECT_RULES.md` 写明所用 API（例如 `ReplaceFile`，或带 POSIX 语义的重命名），并附一次失败注入的测试记录。没有这份记录，发布说明里不得写“断电安全”。

```go
// replaceFile 用同目录临时文件替换 target。target 已存在时沿用其权限位，
// 不存在时使用 perm。
func replaceFile(target string, data []byte, perm fs.FileMode) error {
    if info, err := os.Stat(target); err == nil {
        perm = info.Mode().Perm()
    } else if !errors.Is(err, fs.ErrNotExist) {
        return fmt.Errorf("stat target: %w", err)
    }
    f, err := os.CreateTemp(filepath.Dir(target), ".tmp-*")
    if err != nil {
        return fmt.Errorf("create temp: %w", err)
    }
    tmp := f.Name()
    committed := false
    defer func() {
        if !committed {
            if rmErr := os.Remove(tmp); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
                slog.Warn("remove temp", "err", rmErr)
            }
        }
    }()
    if err := f.Chmod(perm); err != nil {
        _ = f.Close() // 关闭失败不掩盖本次错误；临时文件由 defer 删除
        return fmt.Errorf("chmod temp: %w", err)
    }
    if _, err := f.Write(data); err != nil {
        _ = f.Close() // 同上
        return fmt.Errorf("write temp: %w", err)
    }
    if err := f.Sync(); err != nil {
        _ = f.Close() // 同上
        return fmt.Errorf("sync temp: %w", err)
    }
    if err := f.Close(); err != nil {
        return fmt.Errorf("close temp: %w", err)
    }
    if err := os.Rename(tmp, target); err != nil {
        return fmt.Errorf("replace %s: %w", target, err)
    }
    committed = true
    return nil
}
```

### 8.9 Context 与取消 `[REVIEW]`

- 常驻 goroutine 与网络循环 **MUST** 接收 `context.Context`，并在 `ctx.Done()` 时退出。Rust 的异步任务 **MUST** 能被取消或超时（§12.2）。
- 处理请求的函数里 **MUST NOT** 使用 `context.Background()`，那会丢掉上游的取消与超时。入口确实没有上游 context 时，使用带超时的 `context.WithTimeout`，并在函数返回时 `cancel`。
- 入参是 `nil` context 时 **MUST** 返回错误，**MUST NOT** 替换成 `context.Background()`。替换会把调用方的错误变成一次没有超时、没有取消的调用。Go 的文档要求调用方不要传入 nil context，收到 nil 就失败，才能在测试里看见这个错误。

### 8.10 宿主全局状态 `[REVIEW]`

- 程序默认 **MUST NOT** 修改宿主的全局防火墙、路由或网络配置。
- 项目确实要改时，具体规则写在 `PROJECT_RULES.md`：每条规则有可识别的标记，进程正常退出时删除，并提供一条可手动执行的清理命令。L0 不规定某个产品的看门狗怎么写。没有清理命令和一次“强杀之后残留是否还在”的记录，不得声称宿主状态会自动恢复。

### 8.11 SLO 与错误预算 `[ADVISORY]`

核心对外服务 **SHOULD** 定义可用性与延迟 SLO 并据此设定错误预算。错误预算耗尽时 **SHOULD** 优先安排稳定性修复而不是新功能。

---

## §9 资源效率与性能预算

> 本章把“占用资源少”从口号变成可执行的预算与检查项。预算数字只有剖面或 `PROJECT_RULES.md` 写了上限并规定“超出阻断”时，才让 CI 失败。

### 9.1 服务端资源预算 `[CI]` / `[REVIEW]`

- 部署在编排系统上的 `kind: service` **MUST** 声明 CPU 与内存的 `requests` 和 `limits`（§7.7）。没有 limits 的容器可以吃满节点。单文件 CLI 不部署在编排系统上时，改为遵守 §9.2：进程对外部输入造成的内存与并发数量 **MUST** 有上限。
- 预算数字 **MUST** 来自 §13.4 的测量，**SHOULD** 取峰值测量值的 1.3 到 1.5 倍作为 limits 的起点。没有测量记录时，PR 里写“估算”，不得写“已按实测设定”。
- Go 运行时自 1.25 起按容器的 CPU limit 设置 `GOMAXPROCS`，不要再引入 `automaxprocs`。容器内 **SHOULD** 设置 `GOMEMLIMIT`，起点取内存 limit 的 90% 左右，并留出非堆内存的余量。
- 启动时间 **SHOULD** 有上限，超出时 PR 说明原因。本项默认不阻断合并。

### 9.2 并发资源治理 `[CI]` / `[REVIEW]`

- 每个请求、每条连接启动的 goroutine 或异步任务 **MUST** 有数量上限和退出路径。无上限地 `go func()`，对端可以靠连接数把内存打满（CWE-770、CWE-400）。Rust 的异步任务 **MUST** 能取消或超时。
- channel 缓冲、内存队列、在途任务数 **MUST** 有上限。达到上限时 **MUST** 返回明确错误或施加回压，禁止继续分配并假装仍然正常。
- 外部输入里的长度、个数、嵌套深度 **MUST NOT** 直接传给 `make([]T, n)` 或等价分配，先与上限比较，超出则拒绝。
- `concurrency: in-process` 的测试结束时，goroutine 数量 **MUST** 回到基线（§11.4）。

### 9.3 连接与文件描述符治理 `[CI]`

数据库、Redis、RPC 客户端的连接池 **MUST** 设置显式的最大连接数，**MUST NOT** 使用无上限的默认配置（§6.8）。HTTP 客户端与 `Transport` 的复用要求见 §8.2。

### 9.4 二进制与镜像体积预算 `[CI]`

生产二进制体积 **SHOULD** 有项目自定的预算上限，超出 **MUST** 在 PR 中说明原因。镜像要求见 §7.7。

### 9.5 剖析与热路径 `[REVIEW]`

- `kind: service` **SHOULD** 集成 `pprof`（Go）或等价工具（Rust 的 `pprof-rs`、`tokio-console`）。监听地址遵守 §10.6。没有按 §10.6 限制地址时，宁可不暴露端点，也不得为了满足“已集成”而挂到公网。
- 新增预期会占明显 CPU 或内存的路径之前，**SHOULD** 先有一段测量。没有测量时，PR 写“未测量”，不要写预期 QPS。
- 已测量到分配造成延迟升高的热路径，**SHOULD** 复用缓冲区。`sync.Pool` 取出的缓冲区在放回之前 **MUST** 清掉本次内容（如 `b = b[:0]`），避免上一个请求的数据留到下一个请求。没有测量结果时，**MUST NOT** 为了符合本条给整个仓库套上对象池。

---

## §10 错误处理、日志与可观测性

### 10.1 Go 错误处理 `[CI]`

- `error` **MUST NOT** 隐式丢弃。确需忽略时 **MUST** 写成 `_ = f()`，并在同一行注释原因。`errcheck` 的排除清单入库，无注释的 `_ =` 不合格。
- 唯一的默认例外：只读资源的 `defer x.Close()`（`sql.Rows`、HTTP 响应 `Body`、只读打开的文件），关闭错误不改变已经得到的结果，**MAY** 直接 `defer`，并 **MUST** 列进 `errcheck` 排除清单。写入过的文件不在此列：写入错误可能到 `Close` 才出现，**MUST** 检查 `Close` 的返回值（见 §8.8 示例）。
- 向外传递时 **MUST** 用 `%w` 保留错误链，判定 **MUST** 使用 `errors.Is` 或 `errors.As`。已经是带稳定身份的哨兵错误、再包一层会破坏调用方的 `errors.Is` 时，可以原样返回并注释原因。
- 跨进程返回的是 §4.5 的对外错误。`%w` 链写入日志，**MUST NOT** 原样放进 HTTP 或 RPC 响应。

### 10.2 Rust 错误处理 `[CI]`

- 生产路径 **MUST NOT** 使用 `.unwrap()`。可证明不变量处 **MAY** 使用 `.expect("原因")`。完整的 lint 清单见 §12.3。
- 库 crate 的错误 **MUST** 是实现了 `std::error::Error` 的具体类型，**SHOULD** 用 `thiserror` 派生；应用 **SHOULD** 用 `anyhow` 或等价方案附加上下文。库 **MUST NOT** 在公开 API 里返回 `anyhow::Error`。

### 10.3 Panic 边界 `[REVIEW]`

- `panic` **MUST** 仅用于不可恢复的逻辑错误。
- Go 的 Handler 层 **MUST** 有 `recover` 中间件兜底并记录日志。Rust 服务 **MUST** 在任务与请求边界处理 panic，不让单个请求的 panic 带走整个进程；项目选择 `panic = "abort"` 时，由编排系统重启并在 `PROJECT_RULES.md` 说明。

### 10.4 结构化日志与追踪 `[CI]`

- `kind: service` 的生产进程 **MUST** 使用结构化日志（Go 的 `slog`，Rust 的 `tracing`），JSON 输出，**MUST NOT** 用裸 `Println` 记录业务错误。日志 **MUST NOT** 记录密钥、Token、密码和未脱敏的敏感字段。
- `network: inbound` 时，每个请求 **MUST** 有 request id，写入日志并传到下游调用。多服务架构 **MUST** 按 W3C Trace Context（`traceparent`）传递追踪上下文，**SHOULD** 使用 OpenTelemetry。没有这个 id，§14.5 的链路在生产上无法对照。

### 10.5 日志级别、采样与 CLI 输出 `[REVIEW]`

- 日志 **MUST** 分级使用，级别 **MUST** 运行时可调，生产 **MUST NOT** 默认 `DEBUG`。**SHOULD** 对高频重复日志启用采样，避免日志风暴拖垮磁盘 I/O，这同时服务于 §9。
- CLI 的界面渲染 **MAY** 用 `Println`，业务错误路径仍 **MUST** 使用结构化日志。

### 10.6 指标与剖析端点 `[REVIEW]`

- 指标标签的取值范围 **MUST** 有上限。**MUST NOT** 把用户 ID、完整 URL 或错误原文放进指标标签。标签基数失控会打垮监控，这是资源滥用，不是可观测性。
- `/metrics` **MUST NOT** 无鉴权暴露在公网。
- pprof 或等价的剖析端点若开启，**MUST** 只监听 `127.0.0.1`，或放在已鉴权的管理端口，**MUST NOT** 挂在公网业务端口上。
- `kind: service` **SHOULD** 暴露延迟分位数（p50、p95、p99）与资源占用，用来对照 §9 的预算。没有这些数字时，不得声称“负载在预算内”。

---

## §11 Go 编码缺陷门禁

> 适用：`language` 含 `go`。架构条款看不住函数体内的错误处理、锁与资源释放，本章只写已经能对上语言文档的约束，它不能保证函数逻辑正确。本章按 `go` 行不低于 §1.2 的下限撰写，语言与标准库的行为以该下限为准，不再为更旧版本保留写法。只在更高版本才成立的写法，条文里标明“`go` 行 ≥ X 时”，并写明低于 X 时怎么做（§1.1）。

### 11.1 函数体自检 `[LOCAL]` / `[REVIEW]`

任何新增或重构的函数，合并前 **MUST** 逐项满足：

1. **返回值**：`error` 必须处理，忽略时遵守 §10.1。
2. **成对释放**：拿到文件、连接、锁之后，确认获取成功再 `defer` 释放。获取失败时对象可能是 nil，不得先 `defer` 再检查错误。
3. **校验位置**：空串、`nil`、空切片的拒绝放在信任边界，按 §11.6 做一次。边界之内的函数信任已经成立的不变量。
4. **错误链**：需要追加上下文时，Go 使用 `fmt.Errorf("正在做什么: %w", err)`，Rust 使用 `context`。进程边界上的脱敏按 §4.5，不靠每一层再包一段字符串。
5. **退出**：循环与 goroutine 必须有退出条件，并能在 context 取消时返回。无条件 `for {}` 且不监听取消，不合格。

### 11.2 释放、defer 与锁 `[CI]` / `[REVIEW]`

- 获取成功后再 `defer Close`：`obj, err := Acquire(); if err != nil { return err }; defer obj.Close()`。
- 自己实现的 `Close` 第二次调用 **MUST NOT** panic。`os.File.Close` 与 `sql.Rows.Close` 已规定第二次调用的行为，不要再包一层 `sync.Once`。
- `for` 循环体内 **MUST NOT** 直接 `defer` 资源清理（`defer f.Close()`、`defer rows.Close()`）。`defer` 在外层函数返回时才执行，极易引发 `too many open files` 或连接池耗尽。解法：把循环体提取成函数，或用立即执行的匿名闭包 `func() { ... }()` 隔离作用域，或在单次迭代末尾显式 `Close`。`[REVIEW]`
- `sync.Mutex`、`sync.RWMutex` 的临界区内 **MUST NOT** 做网络、磁盘或可能阻塞的 channel 发送。锁内复制需要的数据，解锁后再做 I/O。`[REVIEW]`
- 含有 `sync.Mutex`、`sync.RWMutex`、`sync.WaitGroup` 或 `atomic` 值的结构体，方法 **MUST** 使用指针接收器，**MUST NOT** 按值传递或浅拷贝，副本上的锁不再保护原来的数据。`go vet` 的 `copylocks` 失败即拒绝合并。`[CI]`

### 11.3 作用域与错误处理顺序 `[CI]` / `[REVIEW]`

- 内层 `:=` **MUST NOT** 遮蔽外层的 `err` 或 `ctx`。CI **MUST** 启用 shadow 分析（它不在 `go vet` 的默认集合里，需单独启用）。分析有误报时，在排除清单写明具体那一行，而不是关掉整个检查。`[CI]`
- `for` 循环变量每一轮都是新变量，不要再要求把循环变量手动拷进闭包参数。仍然要避免的是：闭包捕获循环外面的变量，而该变量在循环里被反复赋值，各 goroutine 会看到最后一次赋值。`[REVIEW]`
- 调用返回错误之后，先处理这个错误，再做有副作用的下一步。禁止先把 `err` 放着，继续写数据库或发请求，隔几行再看。请求校验可以把多个字段错误收集起来一次返回，这不是“带着错误继续做副作用”。错误分支处理完后 **MUST** `return`、`break` 或 `continue`，不得落入后面的成功路径。`[REVIEW]`
- 临时错误变量统一命名为 `err`。同一作用域内处理多阶段错误时，**MUST** 用有业务含义的命名（`dialErr`、`parseErr`、`dbErr`），**MUST NOT** 使用 `e`、`err1`、`err2`。`[REVIEW]`

### 11.4 并发与 channel `[CI]` / `[REVIEW]`

- 后台 goroutine **MUST** 有退出条件：`ctx.Done()` 或专门的退出 channel。启动一组并发任务时 **SHOULD** 使用 `sync.WaitGroup.Go`，减少 `Add`、`Done` 配对错误。`[CI]` / `[REVIEW]`
- `concurrency: in-process` 的测试 **MUST** 使用 `go.uber.org/goleak` 或等价断言，测试结束时 goroutine 数回到基线。可以忽略测试开始前就存在的 goroutine，但忽略项必须写明来源，禁止一个空的忽略函数把泄漏全部放行。涉及时间与并发的测试 **SHOULD** 用 `testing/synctest`。预发与生产排查泄漏时，`go` 行 ≥ 1.27 可直接使用 `runtime/pprof` 的 goroutine 泄漏 profile；1.26 上它需要 `GOEXPERIMENT=goroutineleakprofile`，属实验特性，只用于排查，不进生产构建（§1.6）。`[CI]`
- 排空队列 **MUST** 有长度上限与等待上限，超时后返回错误并释放，不得无界堆积。等待上限的规则同 §8.6。
- 跨 goroutine 共享的 `map` **MUST** 由 `sync.Mutex`、`sync.RWMutex` 或 `sync.Map` 保护。`sync.Map` 不是默认选择，它的键值是 `any`，类型错误要到运行时才出现，普通 map 加锁即可。
- CI **MUST** 对并发包运行 `-race`，竞态报告即失败。`-race` 只报告测试实际执行到的写入，并发包的测试 **MUST** 真的并发调用共享状态，否则绿灯不说明没有竞态。`[CI]`
- channel：故意用阻塞发送做回压时，同一个 `select` **MUST** 包含 `ctx.Done()`，调用方取消时发送方必须返回。用超时放弃发送时，**MUST** 把这次丢弃计为错误并返回给调用方，禁止超时后继续执行、好像发送已经成功。接收方提前退出时，发送方必须能从 context 或退出 channel 得知。`[REVIEW]`
- 关闭 channel 的只能是发送方，接收方 **MUST NOT** 调用 `close`。多个发送方时，**MUST NOT** 由其中任何一个关闭数据 channel，也 **MUST NOT** 用 `sync.Once` 包住 `close` 就算解决，`Once` 只让 `close` 发生一次，挡不住另一个发送方往已关闭的 channel 里发送。多个发送方用 `ctx.Done()` 或单独的退出 channel 通知停止，确认不再发送之后，由唯一负责关闭的一方关闭。`[REVIEW]`

### 11.5 空值、零值与 nil `[REVIEW]`

> 空串、数值零和 nil 会在拨号、查询、权限判断里变成“看起来成功”的错误路径。本节要求在信任边界上拒绝它们。

- **必填字符串**：跨进程的必填字符串（主机、地址、Token、设备 ID）在离开信任边界之前，**MUST** 用 `strings.TrimSpace` 判断，结果为空就拒绝，并有 §13.3 要求的断言。
- **可选字段**：需要区分“未传”和“传了零值”时，可以使用指针或等价的存在位。使用指针的字段，业务代码 **MUST** 先判断 nil 再解引用。必填字段不要为了统一风格改成指针。`*string` 有三种状态（nil、指向空串、指向非空串），协议里 **MUST** 写明空串算不算未传，不能只写“用了指针所以没有二义性”。
- **切片与 map**：协议 **MUST** 规定 JSON 的 `null` 与 `[]` 哪一种合法。`encoding/json` 对 nil 切片输出 `null`，对空切片输出 `[]`；`encoding/json/v2` 的默认行为不同，以所用包的文档为准。未规定时，对外响应使用空切片而不是 nil，避免对端把 `null` 当成失败。
- **零值**：对外暴露或跨包传递的领域结构体，其零值 **MUST** 在类型注释里声明是否为可用的合法状态。零值属于非法状态的类型（如未初始化的连接池、端口为 0 的节点配置），**MUST** 让包外无法直接构造出非法实例：关键字段不导出（必要时类型本身也不导出、只导出接口），只能经导出的构造函数（如 `NewClient`）创建，构造函数按 §11.6 校验并返回 `error`。严禁让半空状态流入生产。
- **typed nil**：把值为 nil 的具体指针放进接口后，该接口与 nil 比较的结果是 false（`var p *T = nil; var i I = p` 时 `i != nil`），随后调用方法会解引用崩溃，`error` 接口同样。返回接口或 `error` 时，失败路径 **MUST** 写 `return nil, err`，**MUST NOT** 把 nil 的具体指针赋给接口再返回。

### 11.6 输入校验流水线 `[REVIEW]`

信任边界指：请求体、报文、配置文件、环境变量、命令行参数、外部文件。校验 **MUST** 在边界上一次完成；边界之内的函数信任已经成立的不变量，**MUST NOT** 每一层各写一套不同的 `TrimSpace`，检查结果会互相矛盾。缺省值 **MUST** 在业务校验之前填好，否则可选字段的默认值会在校验阶段被当成缺失。

```
[第 1 层：反序列化]
    解码失败则 400。日志里的请求体必须脱敏。未知字段按 §4.3，不在生产默认拒绝。
[第 2 层：必填与缺省]
    必填字符串做 TrimSpace，空则拒绝并带上字段名。
    只给“未出现”的可选字段填默认值，必填字段不得靠默认值变成合法。
[第 3 层：业务规则]
    范围、枚举、格式。非法则 422，带字段名。端口若要求是可用端口，范围是 1 到 65535。
[第 4 层：交给业务逻辑]
    进入这一层的对象已经完成上面三步，业务函数不再发明另一套空值规则。
```

- 校验错误 **MUST** 带层级、字段名和规则。实际值必须脱敏，Token、密码不得出现在错误信息里。
- 下列标准库调用对空入参的行为各不相同：有的返回含糊的错误，有的返回看似成功的零值。因此边界上 **MUST** 拒绝这些空值并带上字段名，而不是依赖下游报错：`net.Dial`、`net.ResolveTCPAddr`、`tls.Dial` 的地址；`os.Open`、`os.Create` 的路径；`exec.CommandContext` 的命令名；`json.Unmarshal` 的空 payload；要求是带 host 的绝对 URL 时 `url.Parse` 的结果（拒绝空串与空 host；相对路径与 `file` URL 的 host 可以为空，不适用）。SQL 文本 **MUST NOT** 由外部输入拼出（§7.3）。

### 11.7 JSON 与数值 `[REVIEW]`

- `encoding/json` 把数字解进 `int64` 字段时不经过 `float64`。精度丢失发生在解进 `float64`、`interface{}` 或 `map[string]any` 的时候，这些目标 **MUST** 使用 `Decoder.UseNumber()`，再用 `json.Number.Int64()` 取值。`json.Unmarshal` 没有 `UseNumber`，需要这个行为时用 `Decoder`。
- 大于 2^53-1 的整数若会被 JavaScript 消费（包括无框架的浏览器页面），JSON 里 **MUST** 使用字符串。浏览器的 `JSON.parse` 先把数字变成 IEEE 754，服务端的 `UseNumber` 看不到原始十进制。雪花 ID 和时间戳用数字 JSON 发给前端，会在浏览器里坏掉。
- `go` 行 ≥ 1.27 时，`encoding/json` 由 v2 实现支撑，编解码行为保持兼容，但错误信息的文本可能变化，**MUST NOT** 用字符串匹配判断 JSON 错误。此时新代码 **MAY** 直接使用 `encoding/json/v2`，它的默认更严格（拒绝无效 UTF-8、拒绝对象内重复键）。选用 v2 时，未知字段策略仍遵守 §4.3。
- `go` 行为 1.26 时，`encoding/json/v2` 需要 `GOEXPERIMENT=jsonv2`，属实验特性，按 §1.6 **MUST NOT** 用于生产。

### 11.8 切片、时间与配置零值 `[REVIEW]` / `[CI]`

- `append` 的结果 **MUST** 赋回变量：`s = append(s, x)`，不赋值时元素可能写进了新数组，调用方手里的切片却没变。从大切片上切下一小段并长期保存时（`small := big[0:2]`），**MUST** `copy` 到新切片，否则大数组不会被回收。把切片交给另一个 goroutine 且之后还会 `append` 时，**MUST** 先复制，扩容之前两个切片共享底层数组，一边写会改到另一边。`[REVIEW]`
- 进程内部的超时与间隔 **MUST** 使用 `time.Duration`，禁止用没有单位的 `int` 表示时间。跨进程的时间整数 **MUST** 在字段名或 schema 里写单位（如 `timeout_ms`）。时间点使用 UTC，RFC 3339 字符串与带单位的整数二选一，在该字段的契约里写死，禁止一个字段同时接受两种单位。`[CI]` / `[REVIEW]`
- 配置文件或环境变量缺了某个字段时，**MUST** 保留程序内的默认值。反序列化进普通 `bool`、`int`、`string` 时，缺字段与“显式写成零值”看起来一样，零值会盖掉默认值。环境变量设成空串也是一次赋值，不是“没设置”：空串 **MUST NOT** 悄悄变成默认值，也 **MUST NOT** 在未声明的情况下把默认值擦掉。用指针或存在位区分“没设置”和“设成空”，默认值的填法遵守 §11.6。`[REVIEW]`
- 无界循环里 **MUST NOT** 使用 `time.After`，每一轮都会分配一个 timer。使用循环外的 `time.NewTimer` 或 `time.NewTicker`，退出时 `Stop`。有界的少量重试可以使用 `time.After`。不再被引用的 `Timer` 与 `Ticker` 可在触发前被回收，但这不等于没有分配成本。`Reset` 在当前 timer 语义下的用法以官方文档为准，**MUST** 为 `Reset` 补一个测试。`[REVIEW]`

### 11.9 调试代码防泄露 `[CI]`

非测试代码 **MUST NOT** 提交 `skipAuth = true`、`debugBypass = true`、`InsecureSkipVerify: true` 或 `panic("not implemented")`，CI 用搜索拦截。搜索 **MUST** 排除 `*_test.go` 与 Rust 的测试目标，否则测试里的替身会被同一条规则打中，人们就会关掉整个搜索。

### 11.10 死代码、孤儿与废弃 `[CI]` / `[REVIEW]`

- CI **MUST** 运行死代码分析（Go 使用 `golang.org/x/tools/cmd/deadcode`，Rust 使用编译器的 `dead_code` lint 并以 `-D warnings` 执行）。`deadcode` 从 `main` 包出发分析，没有 `main` 包的库要加 `-test` 从测试出发，或改用 `staticcheck` 的 `U1000`。扫描 **MUST** 覆盖实际发布的 `GOOS`、`GOARCH` 与 build tag，只在 Linux 上扫一遍，会把 `//go:build windows` 的文件当成死代码。`[CI]`
- 默认构建里没有引用的私有函数、常量、类型 **MUST** 删除，或在排除清单写明原因（反射、生成代码、构建标签），没有原因的排除项等于关闭检查。库的导出 API 可以没有仓库内调用方，删除导出符号按 §4.6 判断兼容性，不因为 deadcode 没看到外部用户就删。`[CI]`
- 业务文件被删除或重命名时，其配套的测试文件 **MUST** 同步重构或删除。CI **MUST** 校验全仓测试文件都有对应的生产代码，杜绝孤儿测试空转、提供虚假安全感。下列文件没有同名生产文件是正常的，检查脚本 **MUST** 按规则放行，不靠逐个加排除项：`export_test.go`、只含 `TestMain` 的文件、`example_test.go`、`*_integration_test.go`、Rust 的 `tests/` 与 `benches/` 目录。其余例外写进排除清单并注明原因。`[CI]`
- 计划下线的旧函数 **MUST** 经历三个阶段：声明 `Deprecated` 注释，全仓检索并迁移调用链，确认调用归零后立即删除。严禁长期保留无用的废弃实现。`[REVIEW]`
- 函数签名变更的同步见 §14.4。

---

## §12 Rust 编码缺陷门禁

> 适用：`language` 含 `rust`。统一用 `[workspace.lints]` 配置，CI 以 `cargo clippy --workspace --all-targets --locked -- -D warnings` 执行，并按 §1.3 的 edition 与工具链固定。

### 12.1 `unsafe` `[CI]` / `[REVIEW]`

- 默认 **MUST** 禁止：workspace lint 设 `unsafe_code = "forbid"`。确需 `unsafe` 的 crate **MUST** 在 `PROJECT_RULES.md` 登记原因与范围，并把 `unsafe` 收敛在尽量小的模块里。`[CI]`
- 登记过的 crate 不能靠源码里的 `#![allow(unsafe_code)]` 放开：`forbid` 不能被下层覆盖，而 `[lints] workspace = true` 也不能只改其中一项。做法是这个 crate **不**写 `workspace = true`，在自己的 `Cargo.toml` 复制一份完整 lint 表，把 `unsafe_code` 设为 `deny`，再只在用到的模块上 `#[allow(unsafe_code)]`。CI **MUST** 检查：不继承 workspace lints 的 crate 都已登记。`[CI]`
- 每个 `unsafe` 块 **MUST** 有 `// SAFETY:` 注释，说明所依赖的不变量，并开启 `clippy::undocumented_unsafe_blocks`。`unsafe fn` 内部的 `unsafe` 操作 **MUST** 同样包在显式的 `unsafe` 块里（`unsafe_op_in_unsafe_fn`）。`[CI]`
- 含 `unsafe` 的 crate **SHOULD** 在 CI 里跑 `cargo miri test`；FFI 的不变量 **MUST** 在边界处检查（§1.4）。`[REVIEW]`

### 12.2 异步与并发 `[CI]` / `[REVIEW]`

- 异步任务 **MUST** 有归属与退出路径：被 `spawn` 的任务要么被 `await`、`abort`，要么由取消信号终止，**MUST NOT** 留下无人管理的游离任务（§9.2）。`[REVIEW]`
- 同步锁（`std::sync`、`parking_lot`）的守卫与 `RefCell` 借用 **MUST NOT** 跨 `.await`（`clippy::await_holding_lock`、`clippy::await_holding_refcell_ref`）。`[CI]` 确需跨 `.await` 持有时使用异步锁（如 `tokio::sync::Mutex`），并 **MUST** 评估持有时长，持有期间不得等待可能无限期阻塞的 I/O。`[REVIEW]`
- 异步上下文里的阻塞调用（同步 I/O、重计算）**MUST** 放进 `spawn_blocking` 或专用线程，不得阻塞运行时的工作线程。`[REVIEW]`
- `select!` 的未完成分支会被直接丢弃，**MUST** 评估被丢弃的 future 是否留下不一致状态（取消安全）。所有对外 I/O 都有超时（§8.1）。`[REVIEW]`
- 共享状态跨线程传递依赖 `Send`、`Sync` 的编译期检查，**MUST NOT** 用 `unsafe impl Send/Sync` 绕过，确需时按 §12.1 登记。`[CI]`

### 12.3 panic、溢出与索引 `[CI]`

- 生产路径 **MUST NOT** 出现 `unwrap`、`panic!`、`todo!`、`unimplemented!`（`clippy::unwrap_used`、`clippy::panic`、`clippy::todo`、`clippy::unimplemented` 设为 deny，测试除外）。`expect` 仅用于可证明的不变量，并写明原因。
- 由外部输入决定的索引与切片 **MUST** 使用 `get` 之类返回 `Option` 的方式，**MUST NOT** 直接下标取值。`clippy::indexing_slicing` 会拦截所有下标而不只是外部输入，**MUST** 在解析外部输入的模块或 crate 上设为 `deny`；其他位置 **MAY** 开启，开启后可证明不越界的下标用 `#[allow]` 加注释说明。
- 业务金额、长度、计数的运算 **MUST** 显式选择 `checked_`、`saturating_` 或 `wrapping_`。release 构建默认不检查整数溢出，会静默回绕（§6.2、CWE-190）。

### 12.4 依赖与 feature `[CI]`

- CI **MUST** 运行 `cargo deny check`（advisories、licenses、bans、sources），构建 **MUST** 带 `--locked`（§7.6）。
- 依赖 **SHOULD** 关闭不需要的默认 feature（`default-features = false`）并精确开启所需 feature，减少编译产物与攻击面。
- 库 crate 的公开 API 里暴露第三方类型，等于把该依赖的版本绑进自己的 SemVer，**SHOULD** 谨慎，并纳入 §4.6 的 `cargo semver-checks`。

---

## §13 测试规范

### 13.1 硬性要求 `[CI]`

- 已有业务包测试时，核心业务（包清单写在 `PROJECT_RULES.md`，§0.7）覆盖率 **MUST** 不低于 70%，整体 **SHOULD** 不低于 60%，且 **MUST NOT** 比上次下降超过 2 个百分点。分母排除只有 `main` 的入口文件。还没有测试的新仓库，不得因为覆盖率是 0 而失败。
- **MUST NOT** 保留已知会间歇失败的测试。CI **MUST NOT** 自动重试失败测试，重试会把间歇失败洗成绿色。
- **MUST NOT** 用 `sleep` 做并发同步。Go 测试 **SHOULD** 用 `testing/synctest` 让时间与并发可确定，Rust 异步测试 **SHOULD** 用暂停时钟。测试 **MUST NOT** 依赖真实外网、固定端口、时钟绝对值和执行顺序。Go 测试 **MUST** 使用 `-shuffle=on`。
- 主干上新增 `t.Skip`（Rust 的 `#[ignore]`）**MUST NOT** 合并，已有的 **MUST** 带 issue 链接。
- 测试 **MUST** 对预期结果作出断言。只打印日志、失败也不报错的测试不算覆盖。

### 13.2 组织约定 `[REVIEW]`

- **SHOULD** 用表驱动测试。并发包 **MUST** 有竞态测试。外部依赖 **MUST** 经 `interface` 或 `trait` 注入替身。Go 测试 **SHOULD** 用 `t.Context()` 管理测试内的取消，基准测试 **SHOULD** 用 `b.Loop()`。
- 联动功能 **MUST** 按 §4.2 状态机的每条迁移边组织测试用例，**MUST NOT** 只覆盖“正常路径”。

### 13.3 错误分支、边界与模糊测试 `[CI]`

- 返回 `error` 的函数，测试 **MUST** 至少覆盖一条失败路径。只有成功路径的测试不算完成。一条失败测试也不等于所有失败分支都测到了，报告里按实际覆盖的分支写。
- 在信任边界上拒绝空串、`nil`、空切片的函数，**MUST** 有对应断言。
- 覆盖率统计 **MUST** 能看出关键路径的分支覆盖。不得用一串 getter 与 setter 把总百分比抬上去，再声称关键路径已覆盖。
- `network: inbound` 时，解析外部输入的函数 **MUST** 有表格测试，至少包含空输入、截断输入和超出上限的长度。有 fuzz 种子时（Go 的原生 fuzzing，Rust 的 `cargo-fuzz` 或属性测试），CI **SHOULD** 跑有限时间的 fuzz。没有 fuzz，不得写成“已做模糊测试”。

### 13.4 压力与容量测试 `[REVIEW]`

> 对齐 Google SRE 的容量规划实践：不了解服务的失效边界，就无法设定合理的资源预算（§9）与超时、降级策略（§8）。

- 核心服务上线前 **MUST** 有一次基准负载测试，记录 QPS、延迟、资源占用的曲线，作为 §9 预算与 §8.1 超时的依据。
- 核心服务 **SHOULD** 在设计阶段明确“最坏情况下的降级行为”，并有对应测试验证降级路径，而不是只验证正常路径。

---

## §14 研发流程与 AI 协作

### 14.1 六步闭环

**【设计（含 §4 契约定稿）】→【审查】→【编码】→【回测】→【验证】→【交付前交叉验证】**

交付前交叉验证指：全仓构建、全量测试、契约 diff 与剖面检查都有命令输出可对照。

### 14.2 多人团队模式 `[REVIEW]`

主干 **MUST** 开启分支保护，**MUST NOT** 直接 push。合并 **MUST** 有不少于一位非作者的 Reviewer，并且 §15.2 的全部 `[CI]` 检查被设为必需检查。分支保护是托管平台的设置，流水线自己查不到，由仓库管理员在平台上核对。

### 14.3 单人与 AI 结对模式（Trunk-Based 豁免）`[LOCAL]`

**MAY** 直接推主干，但 **MUST** 同时满足：

1. 本地 pre-commit 通过 §15.1。这只是短检查，不能代替 §15.2。
2. 推送之后的 CI 执行 §15.2。CI 失败时，下一次推送功能之前 **MUST** 先让主干变绿（revert 或修复）。禁止在已知失败的主干上继续叠功能。
3. commit message 使用 Conventional Commits。
4. 这次提交可以单独 revert。
5. 涉及契约点时遵守 §14.6。

自检报告不是通过证据，证据是命令、退出码和输出（§14.7）。

### 14.4 函数签名变更的全仓同步原子性 `[CI]`

- 同一模块内，公共函数、方法、接口方法的签名变更（参数增删、返回值类型或数量变更）**MUST** 在同一次提交里改完所有调用点。**MUST NOT** 先提交新签名、以后再修调用点，主干历史里不得留下编译失败的中间提交。
- 别的仓库里的调用方做不到在同一次提交里修改。跨仓库按 §4.6 发布兼容版本，不要把本条理解成“要求下游仓库同一分钟提交”。
- CI 对本次提交执行 `go build ./...` 或 `cargo build --workspace`，编译失败即拒绝。签名变更若超过 3 个文件，按 §14.6 的例外执行。

### 14.5 数据链路逐步穿透追踪 `[REVIEW]`

在代码审查、调试重构与 AI 结对自检中，修改或审查任何配置与字段，**MUST** 走完完整数据链路的 5 步：

1. **生成端构造**：确认数据源取值合法，非空、非零值，编码符合规范。
2. **网络序列化**：确认 JSON tag 或 Protobuf 字段名对齐，没有大小写漂移，没有 `omitempty` 误丢弃。
3. **接收端反序列化**：确认类型匹配，数值无截断；未知字段按 §4.3 的兼容策略处理，不默认在生产拒绝。
4. **业务引擎提取**：确认校验与归一化通过，默认值回填完备（§11.6）。
5. **最终系统调用**：确认实际入参进入底层套接字、SQL 查询或文件句柄，且有边界上的前置校验。

严禁只在单个文件里确认函数存在、类型兼容，就下“修复完成”的结论。

### 14.6 AI 代理分步执行与防漂移 `[LOCAL]` / `[REVIEW]`

> 代理会在长上下文里改错文件、漏掉调用点，或在没有命令输出时声称已经通过。本节的 `[LOCAL]` 部分只有在仓库有拒绝写入的钩子时才算机器执行，没有钩子时只是操作要求，**MUST NOT** 在合规声明里写成“CI 已保证代理遵守本节”。

1. **单步原子性**：一次执行只做一个已经写明的任务。一次修改的非生成文件默认不超过 3 个。例外只有三类：§14.4 的签名同步、契约生成物、同一个契约点的全部文件（§4.7）。例外 **MUST** 写在这一步的任务说明里，不得用来夹带无关重构，也不得把任务拆成无法编译的中间状态。
2. **前置任务说明**：改文件之前，在不入库的 `tmp/step.md` 或 PR 描述里写下四行。缺少任务说明就改文件，这一步视为未按本节执行；思考里默写一遍不能代替。

   ```markdown
   [STEP]
   1. 目标：一句话。文件数超过 3 时写明属于哪一类例外。
   2. 剖面：engineering-profile.yaml 里与这次改动有关的字段。没有引入新能力就写“剖面不变”。
   3. 当前签名：从文件里读到的函数签名，不凭记忆写。
   4. 验证命令：这一步结束要跑的命令。跑完把退出码补进汇报。
   ```
3. **契约点粒度**：联动任务 **MUST** 按 §4.7 的粒度，一个契约点一个任务，**MUST NOT** 把多个契约点合并成一次请求。每个任务完成后、进入下一任务前，**MUST** 完成：① 自动化核验（类型检查、契约 diff、对应单测）；② 输出结构化自检报告；③ 核验通过方可继续，未通过 **MUST** 回退重做，**MUST NOT** 带着不一致状态继续。契约定稿后代理 **MUST NOT** 擅自修改契约（§4.1）。
4. **上下文校准**：多步任务修改文件超过 3 个，或任务链跨越多次对话时，启动下一阶段前 **MUST** 输出中间状态校准报告：已完成清单、目标最新签名、待修改调用点。严禁基于模糊的历史假设编写下游代码。
5. **命名与字段一致**：新增类型名、函数名、结构体字段名时 **MUST** 全仓搜索确认无冲突或语义漂移。修改结构体字段时 **MUST** 同步三处：序列化 tag、业务赋值与归一化逻辑、测试字面量，禁止改一漏三。
6. **短指令重校准**：用户只说“继续”“修一下”“再查一遍”时，**MUST NOT** 凭会话记忆直接改文件。先看 `git status` 与上一次验证的退出码，写明这一步的边界，再改。上一次验证失败时，下一步是修这次失败，不是开始另一个功能。
7. **自检报告格式**：每步修改后 **MUST** 输出下面的报告，人类确认后方可声明本步结束。

   ```markdown
   【本步做了什么】: 修改的文件路径、行数、核心变更逻辑
   【函数签名变更】: 无 / 修改前后的完整签名对比
   【影响调用链】: 直接调用方列表与全仓调用点同步状态
   【可能遗漏的边界】: 尚未覆盖的边界与 edge case
   【下一步前必须确认】: 必须本地执行并通过的验证命令清单
   ```
8. **执行前后动作**：执行前写任务说明、从文件里抄当前签名、看 `git status`。执行中，同一模块里的签名变更一次改完（§14.4），新的 goroutine 要有退出条件（§11.4），信任边界上的空值按 §11.6。执行后运行任务说明里列出的命令，把退出码写进汇报，没跑的命令不得写成已通过。

### 14.7 汇报必须带证据 `[LOCAL]` / `[REVIEW]`

- 汇报、提交说明与发布说明里 **MUST NOT** 使用“完美”“终极”“无可挑剔”“彻底搞定”“零 bug”“已符合全部标准”。这些句子不能被检查，改用命令、退出码、版本号和文件路径。
- 没有编译或测试的退出码与输出时，**MUST NOT** 写“已经修复”或“测试已通过”。
- “60 秒内能看完”取决于 diff 大小，不得把它写成质量已经合格。

### 14.8 跨工具的一致执行 `[LOCAL]` / `[REVIEW]`

> 同一仓库可能先后由不同的 AI 工具修改。本节保证换一个工具，遵守的仍是同一套规则。

- **单一规则源**：所有 AI 代理执行同一份 L0 与 L1。L2 文件（附录 F）只写接入方式和工具特有的操作，**MUST NOT** 复制或改写 L0 正文。复制出来的副本会和原文慢慢变得不一样，到时候不同工具各守一个版本。
- **会话开始**：代理在修改任何文件之前 **MUST** 读取 `engineering-profile.yaml` 与 `PROJECT_RULES.md`，并按 §0.6 确定本仓库启用了哪些章节。上下文放不下全文时，**MUST** 加载附录 F.2 的速查卡与 §14.6、§14.7，其余章节按条款号按需读取，**MUST NOT** 凭记忆复述条款内容。
- **不确定时**：无法判断某条是否适用，按剖面判断；剖面也判断不了时，按更严格的理解执行并在汇报里写明，**MUST NOT** 自行放宽。
- **与用户指令冲突时**：指出条款号与冲突点，由人决定修改指令或按 §18.2 登记豁免（§0.8 的条款不可豁免）。**MUST NOT** 静默遵守其中一方。
- **不改规则本身**：代理 **MUST NOT** 修改 `GLOBAL_ENGINEERING_RULES.md`、`engineering-profile.yaml`、`WAIVERS.md`，除非本次任务明确就是修订它们。新增能力需要改剖面时，作为单独一步提出（§0.6、§14.6）。
- **交接**：一次会话结束、后续可能由其他工具继续时，**MUST** 按 §14.6 第 4 项输出校准报告，写进 PR 描述或不入库的 `tmp/handoff.md`，内容包括已完成项、最近一次验证命令及其退出码、未完成项。

---

## §15 CI/CD、发布与回滚

### 15.1 快速卡点（pre-commit 与 CI 首阶段，目标小于 60 秒）`[LOCAL]` / `[CI]`

| 检查 | Go | Rust |
|---|---|---|
| 格式 | `gofmt -l .` | `cargo fmt --check` |
| 静态分析 | `go vet ./...` | `cargo clippy --workspace --all-targets --locked -- -D warnings` |
| 错误检查 | `go tool errcheck ./...` | clippy 已覆盖 |
| 遮蔽检查 | `go tool shadow ./...`（§11.3） | 不适用 |
| 快速测试 | 受影响包的 `go test`；小仓库可 `go test ./...` | 受影响包的 `cargo test` |

60 秒是目标，不是把全量竞态测试塞进 pre-commit 的理由。全量 `-race` 放在 §15.2。不得为了赶时间给失败测试加重试。

### 15.2 完整卡点（合并主干与 push 之后）`[CI]`

1. **测试**：Go 全量 `-race -shuffle=on`，Rust 全量 `cargo test --locked`，失败不重试。含 `unsafe` 的 crate 加 `cargo miri test`（§12.1）。
2. **覆盖率**：门槛见 §13.1。
3. **构建**：交叉编译到 `tmp/build/`。声称静态单二进制时，日志里要有 `CGO_ENABLED=0` 或已声明的等价参数（§2.4）。
4. **漏洞扫描**：`govulncheck`、`cargo audit` 或 `cargo deny` 的 advisories，高危为零（§7.6）。
5. **密钥扫描**：全历史加前端产物（§5.5、§7.1）。检出 **MUST** 是完整历史（如 `fetch-depth: 0`），浅克隆只能扫到最近的提交，不得报告为“全历史”。
6. **依赖许可证与来源**（§7.6）。
7. **API 兼容性**（§4.6）。
8. **仓库纯净性**：`.gitignore` 基线、按文件头检测二进制入库、孤儿文件与孤儿测试、死代码、调试代码搜索（§2.3 至 §2.5、§11.9、§11.10）。
9. **前端产物门槛**：公开变量前缀与产物密钥扫描（§5.5）；`embedded` 的运行时依赖数为 0 且 gzip 小于 150 KB，`web` 的锁定安装与 L1 预算（§5.6）。
10. **数据库迁移**：`.up.sql` 与 `.down.sql` 成对存在，临时实例可完整执行（§6.3）。
11. **契约一致性**（§4.3）：调用方字段与契约逐字段 diff，后端响应通过 schema 测试，未通过校验的接口对应 flag 不得为 `ON`。
12. **资源预算**（§9）：剖面或 `PROJECT_RULES.md` 写了数字上限并规定“超出阻断”的项，超出即失败。只标了 **SHOULD** 的项，超出时 PR 必须说明，CI 不得把“已说明”报告成“已阻断”。
13. **稳定性静态检查**（§8）：要求超时的对外 I/O 没有超时则失败。
14. **剖面校验**（§0.6）。
15. **版本时效**（§1.2、§1.3）：`go` 行与 `toolchain`、`rust-toolchain.toml` 没有落后于受支持窗口。检查脚本查询官方发布源，不在脚本里写死版本号。
16. **发布产物**：`*.py` 数为 0（§1.5）；`kind` 为 `library` 或 `service` 时生成 SBOM（§7.6）。
17. **豁免有效期**（§18.2）：`WAIVERS.md` 中任一条目过期，或缺少条款号、有效期、复审日期，即失败；条款号属于 §0.8 的，同样失败。
18. **静态分析扩展**：Go 的 `errcheck`、shadow（§10.1、§11.3）在本阶段全量再跑一次，不只依赖 pre-commit。

### 15.3 流水线自身的安全 `[CI]`

CI Action **MUST** 以完整 commit SHA 锁定，**MUST** 最小权限（默认 `contents: read`），fork PR **MUST NOT** 获得 Secret 访问权限。发布任务访问外部系统 **SHOULD** 使用短期凭证（§7.1）。

### 15.4 版本、标签与发布物 `[CI]`

发布才递增版本，普通提交不改 `VERSION`。每个提交都递增，会把 SemVer 变成提交计数，补丁号不再表示“修了兼容缺陷”。

1. **MUST** 遵循 SemVer，破坏性变更 **MUST** 升主版本。一次发布对应一个版本。版本的唯一来源由 `PROJECT_RULES.md` 指定（`VERSION` 文件、`Cargo.toml` 的 `version`，或构建时从 tag 注入，§0.7），该来源、Git tag、Release 标题三者 **MUST** 相同，CI 在打 tag 的流水线里核对。安装脚本或包描述里写了默认版本时，也 **MUST** 是这个值。
2. 已经推送的 tag **MUST NOT** 移动或重写，已发布的 Release **MUST NOT** 改写其 tag，需要改正时发布新版本。托管平台不限于 GitHub，使用 GitHub 时 Release 资产就是本节的发布物。
3. Release **MUST** 由 CI 从该 tag 构建，二进制 **MUST** 内嵌版本信息。本地编译后手工上传的文件，不得称作该 tag 的发布产物。说明里保留构建命令、目标平台和校验和。`kind` 为 `library` 或 `service` 时附 SBOM。没有签名就 **MUST NOT** 写成已签名。
4. 发布说明写这次改变了什么行为，有几条写几条。**MUST NOT** 为了凑满固定条数编造条目。没有用户可见变化时，写“无用户可见变化”，再列出内部改动。用词遵守 §14.7。
5. 仓库根目录 **MUST** 有 `README.md`，至少包含：用途、如何构建、如何运行测试、版本从哪里读。行为变更记在 Release 说明或 `CHANGELOG` 的一处，两处都写时内容不得矛盾。
6. 主干 **MUST** 开启分支保护或等价的“CI 不通过不能当发布提交”设置。单人仓库若平台做不到禁止直推，则执行 §14.3。
7. 数据迁移、鉴权、计费、不可逆删除属于高风险变更。`kind: service` 且已有用户流量时，这类变更 **MUST** 先走一小部分流量，核对错误率和 §9 里已采集的资源指标，再扩大。单机 CLI 没有流量可切分，不要求金丝雀，但仍 **MUST** 有 §15.5 第一条的回滚路径。

### 15.5 回滚与发布后核对 `[REVIEW]`

- 每次发布 **MUST** 明确回滚路径。含不可逆迁移的变更 **MUST** 拆分成多次发布。**MUST NOT** 无回滚方案发布生产。
- `kind: service` 在宣布交付之前 **MUST** 核对四项，有一项对不上就回滚，不得把“CI 曾经是绿的”写成已经交付：
  1. 运行中的版本与本次 tag 一致。
  2. 迁移版本与这次发布的预期一致，没有数据库则跳过。
  3. readiness 成功，liveness 没有因为摘流量而失败。
  4. 一条不修改数据的探针返回契约内的结果。
- 回滚用的数字（例如“5 分钟内 5xx 比例比发布前基线高出某个点数”）写在 `PROJECT_RULES.md`。没有这个数字，就不存在自动回滚，只能人工判断；人工判断 **MUST** 写明谁在多长时间内看哪一项。CLI 本地工具没有流量可摘，不执行发布后核对。

---

## §16 AI/LLM 调用治理

> 适用：`ai: llm`。项目里的 AI 能力本身是新的攻击面，也是新的不可信数据来源。本章把 §5.1 的零信任判定原样延伸到“AI 输出”：AI 生成的内容不因为“是系统自己调用的”而天然可信。威胁对照 OWASP Top 10 for LLM Applications 2025（提示注入、敏感信息泄露、过度代理等），见附录 C。

### 16.1 调用边界与成本控制 `[CI]` / `[REVIEW]`

- 对第三方 AI/LLM 服务的调用 **MUST** 设置显式超时与最大 token 或成本预算上限，**MUST NOT** 无限制调用（§8.1）。
- **MUST** 有失败降级路径。AI 服务不可用 **MUST NOT** 导致非 AI 相关的核心业务流程整体失败（§8.5）。

### 16.2 数据出境与敏感信息边界 `[CI]` / `[REVIEW]`

- 发给第三方 AI 服务的请求内容 **MUST NOT** 包含密钥、Token、用户密码等 §5、§6 定义的敏感数据。**MUST** 有输入侧的脱敏与过滤机制，并纳入与 §5.5 同等级别的扫描思路。
- 涉及用户 PII 的场景 **MUST** 评估数据出境与供应商数据处理协议是否合规，**SHOULD** 优先选择零数据留存协议的供应商。

### 16.3 AI 输出的可信边界 `[CI]` / `[REVIEW]` — 不可豁免

- AI/LLM 的输出 **MUST** 被当作与外部用户输入同等级别的不可信数据。**MUST NOT** 把未经校验的输出用于写操作、执行代码、调用有副作用的 API，或作为鉴权、计费依据。
- 程序要解析模型输出时，**MUST** 先做 schema 校验，校验失败就按失败处理，**MUST NOT** 把原文拼进 SQL、shell 或权限判断。schema 校验挡的是格式，不是提示词注入的全部手段。
- 由 AI 输出驱动的任何动作，**MUST** 经过与人工输入相同的输入校验、权限校验、业务规则校验。判定公式同 §5.1：“如果攻击者能操纵这个 AI 输出，后端是否会照单全收？”答案是“会”，就 **MUST** 移入服务端权威判定。**MUST NOT** 因为来源是“己方 AI”而弱化校验。
- Prompt 构造里，用户可控内容 **MUST** 与系统指令做结构化隔离（而非字符串拼接），以降低提示注入导致越权操作的风险。

### 16.4 代理与工具权限 `[REVIEW]`

- 赋予模型调用工具或 API 的能力时，**MUST** 按最小权限授予。高风险动作（写入、支付、删除、对外发送数据）**MUST** 经确认，确认可以是人工，也可以是服务端策略。
- 工具返回的内容（网页、文件、邮件、检索结果）**MUST** 视为不可信输入，其中可能夹带间接提示注入。凭证 **MUST NOT** 进入模型的上下文。
- 第三方工具、插件与 MCP 服务器 **MUST** 经过 §7.6 同等的准入审查。

### 16.5 可观测性与回归 `[REVIEW]`

AI 调用 **SHOULD** 记录脱敏后的请求与响应摘要、延迟、token 消耗，纳入 §10 的可观测基线。更换模型或修改提示词 **SHOULD** 跑回归评测集并留下结果。

---

## §17 运维治理

### 17.1 事故复盘 `[REVIEW]`

- 造成 SLO 违反（§8.11）、数据不一致、安全事件，或被人工判定为“用户可感知的严重故障”的事故，**MUST** 在事故解决后 5 个工作日内产出复盘文档。
- 复盘 **MUST** 包含：时间线、原因、影响范围、临时措施、修复、是否要改规则或补测试。能看到系统性缺口就写缺口；原因就是一次错误输入时，就写错误输入，不得为了符合“系统性”而编造流程问题。**MUST NOT** 以追责个人为目的书写（Blameless Postmortem）。
- 复盘里识别出的“应有但缺失的自动化校验”，**MUST** 列出对应的 issue 或 PR 跟踪落地，**MUST NOT** 只停留在文档描述层面。

### 17.2 告警响应与升级 `[REVIEW]`

- 只有 `kind: service` 且 `PROJECT_RULES.md` 写明有人值班时，才执行本节。单人维护的 CLI 不因本条而承诺 15 分钟响应。
- 需要值班的服务 **MUST** 在 `PROJECT_RULES.md` 写明分级与时限（例如 P0 多长时间内开始处理）。数字由项目自己定，本文件不把某个数字写成所有项目的事实。
- 超时未响应 **MUST** 有下一级通知。只有一个人值班时，写明“没有下一级”，不得假装有升级链。
- 会把人叫起来的告警 **MUST** 有一页说明：看哪一项、怎样算恢复、何时通知下一级。没有这页说明的告警只进入日志或工单，不得做成电话级。

### 17.3 架构决策记录（ADR）`[REVIEW]`

- 下列变更 **MUST** 写 ADR：语言或存储引擎、鉴权模型、跨进程协议、数据迁移策略、同进程 FFI（§1.4）、采用协议草案或实验特性（§1.6）。背景、备选、理由、后果四项都要有，放在 `docs/adr/`。其他改动 **MAY** 写 ADR。单文件 CLI 没有这些变更时，不要求先建一堆 ADR。
- ADR **MUST NOT** 事后修改历史内容。决策变更 **MUST** 新增 ADR 并标注“取代（supersedes）”关系，**MUST NOT** 覆盖旧记录。

---

## §18 豁免与规则演进

### 18.1 层叠关系 `[REVIEW]`

本文件是全局底座。项目规则只能细化、增强、收紧，**MUST NOT** 抵触或削弱（§0.5）。

### 18.2 豁免登记机制 `[CI]`

- **MUST** 级条款的偏离 **MUST** 登记在项目的 `WAIVERS.md`：条款号、偏离描述、理由、缓解措施、有效期（**MUST NOT** 填“永久”）、复审日期。未登记视为违规。过期条目 **MUST** 让 CI 失败，不得只打一条警告然后继续发布。
- §0.8 列出的核心原则 **MUST NOT** 走本机制。
- 同一条款在 3 个以上项目被豁免，**MUST** 触发该条款本身的合理性复审。

### 18.3 Review Checklist `[REVIEW]`

各项目 **MUST** 从 `[REVIEW]` 条款生成 PR 模板的 Checklist。条款标题上的标注可由脚本抽取。

### 18.4 规则演进

- 更新 **MUST** 改 `Version` 与 `Last-Updated`，遵循 SemVer。MAJOR 更新后，存量项目 **MUST** 在下一个迭代周期内完成适配评估。
- 正文只记录当前基线，不保留历史版本的迭代痕迹，变更说明写在 Git 历史与发布说明里。
- 新增条款 **MUST** 带执行方式标注（§0.2）。修订依据 **MUST** 是具体事故、官方文档的变更或评审结论。
- 附录 C 的基线快照 **SHOULD** 每半年，或在所用语言发布新大版本时复核更新（§1.6）。

---

## 附录 A：CI 检查清单与配置样例

下面是 §15.2 的落地参考。工具名是示例，同类工具可替换；**MUST** 固定工具版本（§1.2、§7.6）。Go 的开发工具用 `go.mod` 的 `tool` 指令固定（`go get -tool golang.org/x/tools/cmd/deadcode@<版本>` 等），CI 用 `go tool <名字>` 调用，不在 CI 里 `go install @latest`。按剖面删掉不适用的步骤；删掉某步就不得在发布说明里声称通过了该项（§0.2）。

```yaml
# GitHub Actions 示例。uses 在真实仓库里 MUST 替换为完整 commit SHA（§15.3）。
name: ci
on:
  push:
    branches: [main]
  pull_request:
permissions:
  contents: read
jobs:
  quick:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
      - uses: actions/setup-go@<sha>            # language 含 go
        with: { go-version-file: go.mod }
      - run: rustup toolchain install           # language 含 rust；按 rust-toolchain.toml 安装
      - run: scripts/ci/profile-check.sh        # §0.6 剖面与导入一致性
      - run: scripts/ci/currency-check.sh       # §15.2-15：工具链未落后于受支持窗口
      - run: scripts/ci/waiver-check.sh         # §18.2：豁免过期或格式不全即失败
      - run: test -z "$(gofmt -l .)"
      - run: go vet ./...
      - run: go tool errcheck ./...
      - run: go tool shadow ./...
      - run: cargo fmt --check
      - run: cargo clippy --workspace --all-targets --locked -- -D warnings
  full:
    needs: quick
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
        with: { fetch-depth: 0 }                # 密钥扫描与兼容性对比需要完整历史
      - uses: actions/setup-go@<sha>
        with: { go-version-file: go.mod }
      - run: rustup toolchain install
      - run: mkdir -p tmp/build                 # tmp/ 被 .gitignore 忽略，新检出时不存在
      - run: go test -race -shuffle=on -coverprofile=tmp/cover.out ./...
      - run: scripts/ci/coverage-check.sh tmp/cover.out   # §13.1：核心包 70%、下降不超过 2 点
      - run: go tool deadcode -test ./...
      - run: go tool govulncheck ./...
      - run: cargo test --workspace --locked
      - run: cargo deny check                   # 预先以 cargo install --locked cargo-deny@<版本> 安装
      - run: gitleaks git --log-opts="--all" .  # 全历史；gitleaks 版本固定
      - run: scripts/ci/frontend-check.sh       # frontend 非 none
      - run: scripts/ci/contract-check.sh       # components: multi 等：契约一致性 + schema 测试
      - if: github.event_name == 'pull_request'
        run: buf breaking --against ".git#ref=$(git rev-parse origin/${{ github.base_ref }})"
      - if: github.event_name == 'pull_request'
        run: |
          git show "origin/${{ github.base_ref }}:api/openapi.yaml" > tmp/openapi-base.yaml
          oasdiff breaking tmp/openapi-base.yaml api/openapi.yaml --fail-on ERR
      - run: scripts/ci/repo-hygiene.sh         # 二进制入库、孤儿文件、.gitignore 基线、*.py、调试代码
```

| 脚本 | 检查内容 | 对应条款 |
|---|---|---|
| `profile-check.sh` | 剖面存在、枚举合法、导入与声明无矛盾、`language` 与 `PROJECT_RULES.md` 一致 | §0.6、§0.7 |
| `currency-check.sh` | `go` 行、`toolchain`、`rust-toolchain.toml` 未落后于官方受支持窗口，数据来自官方发布源，不写死版本号 | §1.2、§1.3 |
| `waiver-check.sh` | `WAIVERS.md` 每条有条款号、有效期、复审日期；未过期；条款不属于 §0.8 | §18.2 |
| `coverage-check.sh` | 按 `PROJECT_RULES.md` 的核心包清单计算覆盖率，与主干上次结果比较 | §13.1 |
| `frontend-check.sh` | 公开变量前缀、产物密钥与关键词扫描；`embedded` 的依赖数与 150 KB；`web` 的锁定安装与 L1 预算 | §5.5、§5.6 |
| `contract-check.sh` | 调用方与契约 diff、后端响应 schema 测试、未通过的接口对应 flag 不为 `ON`、错误码注册与前缀 | §4.3、§4.4、§4.5 |
| `repo-hygiene.sh` | 按文件头检测二进制入库、孤儿文件与孤儿测试、`.gitignore` 基线、`*.py` 数量、§11.9 的调试代码搜索（排除测试文件） | §1.5、§2.3 至 §2.5、§11.9、§11.10 |

脚本由项目自己实现。某个脚本还不存在时，对应条款对该仓库视为未生效（§0.2），CI 里 **MUST NOT** 用空脚本或 `exit 0` 占位。

---

## 附录 B：阶段核对与自检清单

本附录只指向正文，不新增规则。

### B.1 阶段核对

| 阶段 | 必须核对 | 条款 |
|---|---|---|
| 改动之前 | 剖面是否需要先改；任务说明已写；当前签名从文件读取；`git status` 干净 | §0.6、§14.6 |
| 契约 | 契约与状态机已定稿入库；错误码已登记；接口就绪矩阵已建立 | §4 |
| 编码 | 空值在边界拒绝；错误不被丢弃；资源成对释放；goroutine 或任务有退出路径；金额与长度运算有溢出检查 | §10、§11、§12 |
| 数据 | 唯一权威来源；约束在数据库层；事务可回滚；迁移成对 | §6 |
| 稳定性 | 外部 I/O 有超时；重试有上限且仅限幂等操作；停止信号可排空 | §8 |
| 测试 | 失败路径有断言；并发包真的并发；无 `sleep` 同步；覆盖率未下降 | §13 |
| 提交 | 签名变更同一次提交；Conventional Commits；可单独 revert | §14 |
| 交付 | §15.2 全部通过；发布产物由 CI 从 tag 构建；回滚路径明确 | §15 |
| 汇报 | 有命令、退出码与输出；没有无法核对的形容词 | §14.7 |
| 交接 | 换工具或换会话前输出校准报告；没有静默改动规则文件、剖面与豁免 | §14.8 |

### B.2 前端与数据自检（`frontend` 非 `none` 或 `persistence` 非 `none`）

- [ ] 前端产物里没有密钥、连接串、业务规则常量（§5.1）
- [ ] 问过判定公式：攻击者篡改这个值，后端会照单全收吗（§5.1）
- [ ] 本地存储里没有业务事实（§5.3）
- [ ] 展示态以最近一次后端响应为准，没有第二份可变状态（§5.7）
- [ ] flag 默认 `OFF`，放行由服务端判定（§4.4）
- [ ] 每张表只有一个写入方，读写分离不影响“写后读”（§6.1）
- [ ] 金额没有用浮点，溢出检查到位（§6.2）
- [ ] 大整数发给前端时用的是字符串（§11.7）

### B.3 稳定性与资源自检（`kind: service`）

- [ ] 外部 I/O 的超时值有测量依据（§8.1、§13.4）
- [ ] HTTP 客户端复用，且没有使用 `http.DefaultClient`（§8.2）
- [ ] `/healthz` 与 `/readyz` 分开，排空期间 readiness 失败、liveness 成功（§8.6、§8.7）
- [ ] 请求路径里没有 `context.Background()`（§8.9）
- [ ] 每条连接或每个请求启动的 goroutine 与任务有上限和退出路径（§9.2）
- [ ] 连接池有上限，容器有 requests 与 limits（§9.1、§9.3）
- [ ] pprof 与 `/metrics` 没有暴露在公网（§10.6）
- [ ] 指标标签基数有上限（§10.6）

---

## 附录 C：标准与文献基线

本附录说明条款参照了哪份公开文档，**不是**合规声明（见文件开头）。

### C.1 参照对照

| 章节 | 参照 |
|---|---|
| §1 技术栈与时效 | Go 发布策略与 Release Notes（go.dev）；Rust 发布博客、Edition Guide 与 Cargo 文档（rust-lang.org）；cgo 文档与 Rustonomicon 的 FFI 章节 |
| §4 契约治理 | OpenAPI 规范；Protocol Buffers 与 `buf` 兼容性规则；AsyncAPI；RFC 9457（问题详情）；RFC 9745（`Deprecation` 头）；RFC 8594（`Sunset` 头）；契约式设计（B. Meyer） |
| §5 前端零信任 | OWASP ASVS 5.0；OWASP Top 10:2025；OWASP Cheat Sheet Series |
| §6 数据 | NIST SP 800-53 Rev. 5；OWASP ASVS 5.0；Go `database/sql` 文档；SQLite 官方文档 |
| §7.2 鉴权 | OWASP API Security Top 10:2023；RFC 8725（JWT 最佳实践）；RFC 9700（OAuth 2.0 安全最佳实践） |
| §7.3–§7.4 输入与密码学 | CWE-295、CWE-338、CWE-918；RFC 8446（TLS 1.3）；RFC 9106（Argon2）；OWASP Password Storage Cheat Sheet；NIST SP 800-52 |
| §7.6 供应链 | SLSA 规范；Sigstore；CycloneDX 与 SPDX；RustSec 公告库 |
| §7.7 容器 | CIS Docker 与 Kubernetes Benchmark；NIST SP 800-190 |
| §7.8 披露与响应 | 欧盟 Cyber Resilience Act（第 14 条报告义务） |
| §8 稳定性、§13.4、§17 | Google SRE Book 与 SRE Workbook；Kubernetes 探针文档；Go `net/http`、`os` 文档 |
| §9 资源 | CWE-190、CWE-400、CWE-770；Go 运行时文档 |
| §10 错误与可观测 | W3C Trace Context；OpenTelemetry；Rust API Guidelines |
| §11 Go 编码 | Go 语言规范；Go 1.22 起的循环变量语义；Go 1.23 起的 timer 语义；`go vet` 分析器文档 |
| §12 Rust 编码 | Rust Reference；Clippy lint 清单；Miri 文档 |
| §16 AI/LLM | OWASP Top 10 for LLM Applications 2025（LLM01 提示注入、LLM02 敏感信息泄露、LLM06 过度代理） |
| §17.3 ADR | Michael Nygard，《Documenting Architecture Decisions》 |

### C.2 时效基线快照（核对日期：2026-10-08；Go 条目于 2026-11-02 对照 go.dev/doc/go1.27 复核）

条款正文不写死版本号（§1.1），下表只是核对当天的事实，会过期。以官方来源为准，复核周期见 §18.4。

| 项目 | 核对时的状态 | 来源 |
|---|---|---|
| Go | 受维护的是 1.27（2026-08 发布）与 1.26，1.25 及更早已不在维护窗口内。1.27 的变化包括泛型方法（接口方法仍不能声明类型参数）、`encoding/json` 改由 v2 实现支撑（可用 `GOEXPERIMENT=nojsonv2` 临时退回）、goroutine 泄漏 profile 转为正式功能、`go test` 默认运行 `stdversion` | go.dev 发布博客与 Release Notes |
| Rust | 最新稳定版 1.99.0（2026-10-01）；最新 edition 为 2024（随 1.85 稳定，2025-02-20） | blog.rust-lang.org |
| OpenAPI | 3.2.0 为当前版本 | spec.openapis.org |
| SLSA | 1.2（含 Build 与 Source 两条 track） | slsa.dev |
| OWASP | ASVS 5.0.0（2025-05）；Top 10:2025；Top 10 for LLM Applications 2025；API Security Top 10 以 2023 版为准，使用前到官网确认是否有新版 | owasp.org |
| IETF | RFC 9457（2023-07）、RFC 9745（2025-03）；`Idempotency-Key` 仍是 Internet-Draft（draft-ietf-httpapi-idempotency-key-header，2025-10 的第 07 版） | datatracker.ietf.org |
| 欧盟 CRA | 漏洞与事件报告义务自 2026-09-11 适用，其余义务自 2027-12-11 适用 | 欧盟官方文本与委员会指南 |

---

## 附录 D：契约就绪矩阵与验收清单模板

### D.1 接口就绪矩阵（§4.4）

功能立项时创建，存放于 `docs/contract/readiness.md`，**SHOULD** 与项目看板联动。

| 契约点 | 契约状态 | 后端状态 | 一致性校验（§4.3） | 对应 flag | flag 状态 | 备注 |
|---|---|---|---|---|---|---|
| `POST /v1/orders` 提交订单 | `final` | 已实现 | 通过 | `orders_submit` | `ON` | |
| `GET /v1/orders/{id}` 查询订单 | `draft` | 未开始 | 未执行 | `orders_detail` | `OFF` | UI 呈现禁用态 |

契约状态取 `draft` / `final`；后端状态取 `未开始` / `已实现` / `已验收`。`draft` 或校验未通过的行，flag 不得为 `ON`。

### D.2 交互元素验收清单（§4.7）

每个契约点逐项勾选，缺一项不算完成：

- [ ] 契约字段与调用方一致，类型由契约生成，没有手写重复定义
- [ ] 状态机的每条迁移边都有测试用例（初始、进行、成功、按类别细分的失败）
- [ ] 契约里的每个错误码都有对应的处理与用户文案，“未知错误”只作兜底
- [ ] 防重复触发已实现
- [ ] loading 态已实现
- [ ] 超时处理已实现
- [ ] 后端响应通过契约 schema 测试
- [ ] 对应 flag 的放行由服务端判定

---

## 附录 E：新仓库的最小文件

小项目只需要下面这些。大项目在此基础上，按剖面开启的能力补充 §0.7 要求的参数，不需要另起一套规则。

```text
.
├── engineering-profile.yaml     # §0.6
├── PROJECT_RULES.md             # §0.7，通常只有十几行
├── GLOBAL_ENGINEERING_RULES.md  # 本文件，或在 PROJECT_RULES.md 中链接到它
├── AGENTS.md / CLAUDE.md        # 附录 F：AI 工具入口，只做引用，不复制正文
├── README.md                    # §15.4：用途、构建、测试、版本来源
├── .gitignore                   # §2.5 基线
├── go.mod / go.sum              # 或 Cargo.toml / Cargo.lock / rust-toolchain.toml
└── main.go                      # kind: cli 允许根目录单文件入口
```

对外发布的产物另需 `SECURITY.md`（§7.8）；有 `WAIVERS.md` 才表示有登记的豁免（§18.2）。

`engineering-profile.yaml` 的最小例子（单文件 Go 命令行工具）：

```yaml
language: go
kind: cli
persistence: none
network: none
concurrency: none
frontend: none
components: single
tenancy: single
replicas: 1
ai: none
pii: false
```

`PROJECT_RULES.md` 的最小例子：

```markdown
# PROJECT_RULES

继承：GLOBAL_ENGINEERING_RULES.md
language: go

## 职责
把某类日志文件转换成 CSV。

## 版本来源
构建时从 Git tag 注入（`-ldflags "-X main.version=..."`）。

## 业务专有规则
没有。

## 对 L0 的收紧项
没有。
```

起步顺序：先写剖面，再建 `PROJECT_RULES.md`，再写代码。给剖面新增能力（例如从 `network: none` 改为 `outbound`）时，先改剖面并补齐 §0.7 要求的参数，CI 才会开始检查对应条款。

---

## 附录 F：AI 工具接入

本附录只说明怎样让各工具读到 L0 与 L1，不新增规则（§14.8）。各工具的加载机制会变，接入前按 §1.6 查阅该工具的当前文档。

### F.1 入口文件

把速查卡（F.2）放进 `AGENTS.md`，作为唯一的 L2 正文；其他工具的入口文件只引用它，避免几份 L2 各自漂移。

| 工具 | 读取的文件 | 查找范围与限制（2026-11-03 按各工具自带文档核对） | 写法 |
|---|---|---|---|
| Codex CLI | `AGENTS.md` | 仓库根目录到当前目录 | 放速查卡正文 |
| Grok CLI | `AGENTS.md`（也认 `Agents.md`、`AGENT.md`、`Claude.md`） | 在 git 仓库内从仓库根到当前目录逐级读取，不在仓库内只读当前目录；被 `.gitignore` 忽略的文件跳过；每个文件只取前 10000 字符 | 同上，不另建文件 |
| Antigravity（`agy`） | `AGENTS.md` 与 `GEMINI.md` | 从当前目录向上到仓库根；每个文件上限 24000 字节，全部规则共享 2 万 token 预算，超出的只留路径 | 只用 `AGENTS.md`。同时存在 `GEMINI.md` 时两份都会加载，**MUST NOT** 在两处各写一套规则 |
| Claude Code | `CLAUDE.md` | 从当前目录向上逐级读取；支持 `@路径` 引用 | 一行 `@AGENTS.md`；需要常驻全文时再加 `@GLOBAL_ENGINEERING_RULES.md` |
| Cursor | `.cursor/rules/engineering.mdc`（设为始终应用） | 以 Cursor 文档为准 | 写明“遵守仓库根目录的 `AGENTS.md`” |
| GitHub Copilot | `.github/copilot-instructions.md` | 以 Copilot 文档为准 | 同上 |

L0 全文约 13 万字节，超过上表所有工具的单文件上限，所以只常驻速查卡，由代理按条款号读取相应章节（§14.8）。`PROJECT_RULES.md` 同理：它不会被自动加载，速查卡要求代理在会话开始时主动读取。

**只在项目内生效**：规则文件 **MUST** 放在项目仓库里，**MUST NOT** 放进个人级位置（`~/.claude/CLAUDE.md`、`~/.codex/AGENTS.md`、`~/.grok/`、`~/.gemini/`）。放在个人级位置会让每一次会话（包括与项目无关的对话）都加载这套规则；放在仓库里，其他人与 CI 也看到同一份。仓库内的入口 **MUST** 引用仓库内的 L0 副本或固定版本的链接。

**git 仓库**：Grok 与 Codex 只在仓库内向上查找规则文件。项目不是 git 仓库时，AI 工具 **MUST** 在项目根目录启动，否则在子目录里读不到 `AGENTS.md`。

### F.2 常驻速查卡

下面的内容原样放进 `AGENTS.md`。它只是索引，条款以 L0 正文为准。

```markdown
# AGENTS

本仓库遵守 GLOBAL_ENGINEERING_RULES.md（L0）与 PROJECT_RULES.md（L1）。
本文件只是索引，冲突时以 L0、L1 原文为准；不确定的条款按编号去原文读，不凭记忆。

## 每次会话开始
1. 读 engineering-profile.yaml 与 PROJECT_RULES.md，按 L0 §0.6 确定启用的章节。
2. 看 git status 与上一次验证命令的退出码。上次失败就先修它（§14.6-6）。

## 每一步改动（§14.6）
- 先在 tmp/step.md 写四行：目标、剖面、当前签名（从文件读）、验证命令。
- 一步只做一件事；非生成文件默认不超过 3 个。
- 改函数签名时，同一次提交改完全部调用点（§14.4）。
- 改字段时同步：序列化 tag、赋值与归一化、测试字面量（§14.6-5）。
- 契约定稿后不顺手改契约（§4.1）。不改 L0、剖面、WAIVERS.md，除非任务就是改它们（§14.8）。

## 编码底线
- 错误不丢弃；资源获取成功后再 defer 释放；循环里不 defer（§10、§11.2）。
- 空值在信任边界一次拒绝（§11.6）；外部 I/O 有超时（§8.1）；goroutine/任务有退出路径与数量上限（§9.2）。
- 不硬编码密钥；前端不持有业务事实（§5、§7.1）。
- 新增依赖写明理由，许可证在白名单内（§7.6）。

## 汇报（§14.7）
- 只写跑过的命令、退出码和关键输出。没跑的不写“已通过”。
- 不用“完美、彻底、零 bug、已符合全部标准”。
- 与用户指令冲突时，写出条款号，让人决定（§0.3、§14.8）。
- 会话结束且可能换工具继续时，写交接报告（§14.8）。
```

### F.3 `CLAUDE.md` 示例

```markdown
@AGENTS.md
```

需要 Claude Code 常驻 L0 全文时：

```markdown
@AGENTS.md
@GLOBAL_ENGINEERING_RULES.md
@PROJECT_RULES.md
```

### F.4 安装与更新

规则源目录里的 `tools/l0-install.sh` 按本附录把 L0 接入一个项目。速查卡与模板都直接从 L0 正文提取（F.2、§0.6、§2.5），不另外维护副本。

```bash
tools/l0-install.sh --check <项目目录>             # 只报告，不写文件
tools/l0-install.sh [--lang go|rust|go+rust] <项目目录>
```

- 只增不删：复制或升级 L0 副本；在 `AGENTS.md` 里写入或刷新由 `<!-- L0-CARD:BEGIN … -->` 与 `<!-- L0-CARD:END -->` 包住的速查卡，标记之外的项目内容保持不动；确保 `CLAUDE.md` 引用 `@AGENTS.md`；缺失时新建剖面、`PROJECT_RULES.md` 骨架与 `.gitignore`。
- 已存在的剖面、`PROJECT_RULES.md`、`.gitignore` 只检查不改写；项目里的 L0 副本与规则源版本号相同但内容不同时，不覆盖并报警告。
- 标记之间的内容由脚本维护，**MUST NOT** 手改；项目自己的 L2 规则写在标记之外，且不得与速查卡冲突（§0.5）。
- L0 每次升版后，对各项目重跑一次，刷新副本与速查卡。
