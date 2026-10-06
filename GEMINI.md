# AERO Project Execution Rules (GEMINI.md)

This project strictly enforces the Two-Tier Engineering Rules defined in [PROJECT_RULES.md](file:///D:/jacky/gemini/AIsys/PROJECT_RULES.md) (aligned with GLOBAL MASTER RULES v1.0.0 and engineering-profile.yaml):

## Level 1: Global Master Baseline (v1.0.0 & §0.6 Project Profile)
1. **Pure Go Standards**: Single module `github.com/aero-protocol/aero` flat layout per GLOBAL MASTER RULES v1.0.0 §1.1 (Go 1.26+). Native HTML5/CSS/JS embedded via `//go:embed` (runtime deps == 0, gzip < 150KB). Zero `node_modules` committed.
2. **Frontend Zero-Trust & Thin Client**: Frontend holds no business facts, secrets, tokens, or pricing constants. All state is authoritatively computed and validated by the backend.
3. **Standard Layout**: Standard Go conventions, `internal/` for private packages, `cmd/<bin>/main.go` for multi-binary thin entries. Ban on vague container dirs (`common/`, `utils/`, `core/`, `domain/`, `infra/`, `service/`).
4. **Zero Cross-System Imports**: `internal/client`, `internal/edge`, `internal/mid`, `internal/desk` must NOT import each other.
5. **Data Ownership & Database Hardening**: Dual-database isolation (`aero.db` + `aeropay.db`) in midplatform; autonomous encrypted `edge.db` (AES-256-GCM, zero CGO pure Go SQLite) in edge server.
6. **Testing Standards**: Ban on flaky tests, ban on `time.Sleep` for concurrency synchronization, 7-point in-process test verification matrix.
7. **Logging & Observability**: Structured logging in service code. Whitelist `/healthz` and `/metrics`. No plaintext token logging.
8. **Error Standards & Panic Isolation**: No implicit error discarding; `fmt.Errorf("%w", err)`; `errors.Is`/`As`; safeGo wrapper with recover on background goroutines.

## Level 2: AERO Data-Plane & Architecture Specifics
- **P1. Client MTU & ICMP Backpressure**: Initial MTU 1224. gVisor entry inspects IPv4 DF header: exceeding packet with DF=1 generates ICMP Type 3 Code 4 (Next-MTU = currentMaxDatagramSize + 24) written back ONLY to local virtual NIC; DF=0 silent drop. On DatagramTooLargeError, dynamically update currentMaxDatagramSize and call virtual NIC MTU setter immediately.
- **P2. Datagram Pre-check**: If `4 + len(payload) > currentMaxDatagramSize`, discard immediately without SendDatagram, without stream fallback, without reassembly.
- **P3. DNS Zero-Leak Funnel**: .cn direct via physical DNS & drop AAAA; other domains via tunnel short stream; unestablished returns 198.18 fake IP; AAAA returns empty answer. Port 53 nil return drops in-stack without DialUDP.
- **P4. Edge Server Concurrency & Protection**: handleQUICConn unique object; first frame ValidateFull binds Token, subsequent streams exempt from Nonce; ONLY TCP streams call ConnLimiter.TryAcquire; DNS short streams & UDP Context register streams are exempt from TryAcquire/DialGuard; single ReceiveDatagram loop with 4-byte ContextID; 64 UDP Contexts max; bidirectional BandwidthLimiter.Take.
- **P5. Zero Host Tampering**: No sys_proxy, no netsh advfirewall. Windows guard only cleans aero0 routes on PID exit.
- **P6. Mobile Stub**: SetupRoutes returns fmt.Errorf("TUN not supported on this platform").
- **P7. Single Branch main & Remote Deploy**: Only main branch. VPS installs pull directly from GitHub public repo (`jackybig999/aero`). Zero local binary uploads.
- **P8. Native AERO Subscription Only & Zero-Port Mandate**: Strictly `https://domain.com/sub/superadmin` and `https://domain.com/sub/username{六位随机码}` via standard 443 HTTPS. No non-standard ports. 严禁出现任何形如 localhost:18080 或携带端口的订阅链接！
- **P9. Pre-Flight Git Alignment & Zero Untracked**: `git status --porcelain` untracked files must strictly be 0 (`??` == 0); all embed assets and new code staged; clean clone simulation mandatory before push.
- **P10. Reversible Cleanup & Rollback**: No hard `rm -rf`. All cleanups archive to gitignored `backup/` with `BACKUP_MANIFEST.md` and executable `rollback.ps1`/`rollback.sh`.
- **P11. Anti-DPI & Network Defense Patterns**: `crypto/rand` dynamic packet jitter [1280, 1380]; two-stage atomic WebRTC state machine; zero-DNS short circuit for probe.aero; atomic configuration file writes with `.bak` rollback; lock-free `close()` UDP context reaping.
- **P12. Dedicated Tmp Sandbox & Zero Source Pollution**: All tests, temporary databases, test artifacts, build binaries (`-o tmp/...`), and caches are strictly confined to `D:\jacky\gemini\AIsys\tmp`. Absolute zero file generation in source trees.
- **P13. 反假大空与真实交付铁律**: 绝对禁止使用“完美”、“终极”等浮夸词汇；禁止以单测全绿替代真实可用；严格执行数据链路逐行 5 步穿透追踪（生成端 -> 序列化 -> 结构体 -> 引擎提取 -> 底层调用）；前置自检严防字段丢弃与空值盲目上线。
- **P14. 权威线缆契约与零遗漏零空值工程防线**: 跨系统结构体测试强制采用原始 JSON 报文字符流（Wire-Contract-First，如 `TestWireContract_Strict`），禁止纯内存 struct mock；反序列化后强制执行 `ValidateAndNormalize()` 契约归一化，自动回填物理 IP 与备用跳频端口；跨边界 JSON 结构体强制实现双驼峰/下划线兼容（`snake_case` 与 `camelCase`）；Windows GUI 客户端构建必须固化 `-H windowsgui` 并通过标准库 `debug/pe` 门禁（`TestClientSubsystem`）断言 `Subsystem == 2`。
- **P15. 零静默吞咽与强输入校验门禁**: 全仓 HTTP 接口反序列化严禁 `_ = json.NewDecoder...`，一旦解码失败必须直接返回 400 Bad Request；时延等数值字段强制声明为有符号 `int64`，绝对严禁使用 `uint32` 防止负值崩溃；错误传递统一采用 `fmt.Errorf("%w", err)` 保留上下文。
- **P16. 路由探活与健康检查双向对齐**: 服务端进程（客户端守护进程、边缘节点、商业中台）必须同时挂载 `/healthz` 与 `/health`；桌面工作台与探活组件优先探测 `/healthz`，并具备自动回退 `/health` 的双向容错机制。
- **P17. 跨 VPN/TUN 冲突物理隔离与真实网卡回退**: Windows 严禁修改物理网卡 DNS，统一使用带唯一 Comment（`AERO_aero0`）的 NRPT 策略并在退出时精准清理；中台拉取订阅与边缘探活拨号器强制绑定宿主物理网卡真实出站接口，彻底解决多 VPN/Clash TUN 并存时的网络回环死锁。
- **P18. 生产级单写者架构与无锁资源回收**: 单机 Pure-Go SQLite 数据库强制初始化 `db.SetMaxOpenConns(1)` 彻底消灭锁库；闲置会话与 UDP 上下文清理必须遵循“读锁快照 -> 释放锁 -> 异步无锁 Close()”流水线，严禁临界区阻塞 I/O。
- **P19. 遗漏字段、空值、隐藏边界与盲区深层防范机制**: 核心管控接口反序列化强制开启 `DisallowUnknownFields()` 杜绝未知字段静默丢弃；跨边界实体强制执行 `ValidateAndNormalize()` 校验不变量，可选字段采用指针（`*bool`, `*int64`）消灭零值二义性；跨系统公共实体必须实现自定义 `UnmarshalJSON` 兼顾双驼峰/下划线命名；所有 Goroutine 必须前置明确退出条件且读写受滑动 Deadline 或 context 保护；Windows GUI 构建必须固化 `-H windowsgui` 并由独立 `guard.exe` 以 PID 锚点兜底清理 NRPT 与路由。
- **P20. 零本地宿主订阅与标准 443 协议发布死线**: 本地商业中台（:18080）仅为后台管理控制台与内部 API 处理机，自身绝非用户消费订阅的端点！任何 AI 助手在思考、汇报、提示信息中，绝对严禁输出任何形如 `http://localhost:18080/sub/...`、`http://127.0.0.1:18080/sub/...` 或带有任何非 443 端口的订阅链接！向用户展示中台自测时，只允许输出管理控制台 `http://localhost:18080/` 与健康检查 `http://localhost:18080/healthz`，严禁向用户提示或输出任何本地订阅链接！测试订阅必须且只能经由挂载了合法 SSL 证书的标准 443 HTTPS 域名。
- **P21. 持续版本自增、历史版本绝对保留与变更摘要发布铁律**: 任何涉及协议改动、安全加固、Bug 修复、特性增加的提交，推送发布前必须显式自增 `VERSION` 版本号，严禁沿用旧版本号覆盖；必须在 Release 汇报中输出 3~5 条简要核心技术更新摘要；所有历史 Release（如 1.0.4, 1.0.5, 1.0.6...）必须在 GitHub Releases 列表中永久保留用于比对与回退，严禁覆盖历史资产；本地构建必须同步重编译对齐。


