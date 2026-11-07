# PROJECT_RULES

继承：GLOBAL_ENGINEERING_RULES.md（v1.1.1）
language: go

## 职责
承载 AERO 单 Go 模块迁移工程；本阶段只迁移并重构 `aeroprot` 客户端、边缘服务端和 guard，保留 `aeroos` 与 `aerosub` 目录结构供后续整合。

## 版本来源
当前版本来源为根目录 `VERSION`（当前 `1.2.30`）；发布性协议变更必须在发布前递增版本（§15.4）。

## 业务专有规则
协议和数据面以 `AERO-V2 (Hyper-MASQUE) 落地施工方案.md` 为施工基线；`aeroos`、`aeroprot`、`aerosub` 只保留目录和代码边界，严禁交叉 `import`。
前端零信任与单二进制嵌入：HTML5/CSS/Vanilla JS 资源统一通过 `//go:embed` 嵌入可执行文件交付（§5.1）。

## 对 L0 的收紧项
客户端初始 MTU 固定 1224；Windows 不新增宿主防火墙修改；移动端 TUN 明确返回不支持；任何破坏性删除或清理必须先归档并提供清单和回滚脚本。

## 剖面参数（§0.7）
`kind: service`、`network: inbound`、`concurrency: in-process`、`frontend: embedded`、
`components: multi`、`tenancy: multi`、`persistence: file`、`replicas: 1`、`ai: none`、
`pii: true`。

- 核心业务包清单（§13.1）：`aeroprot/internal/client`、`aeroprot/internal/edge`。
- 网络超时基线（§8.1）：QUIC 建连 8 秒，HTTP/TLS 外部调用 10 秒，健康探测 3 秒，订阅候选端口单端口 2.5 秒、总计 6 秒（基于海外与大陆实测数据）。
- 文件持久化（§8.8）：配置、订阅和 GeoData 使用同目录临时文件、`Sync`、`Close`、原子 `Rename`；失败时保留旧文件并返回错误。
- 入站与安全参数（§7.3、§7.5、§5.3）：CONNECT-IP 单帧上限 65535 字节；Web 控制台单 IP 限制 60 req/min；Cookie 必须包含 `Secure; HttpOnly; SameSite=Strict`。
- 服务生命周期与预算（§8.6、§9.1、§15.5、§17.2）：
  - 停止信号：Unix 监听 `SIGINT` 与 `SIGTERM`，Windows 监听服务控制管理器停止事件；优雅排空上限默认为 15 秒（支持配置覆盖）。
  - 资源预算：Edge 服务端内存 limits 设为 512MB（容器设置 `GOMEMLIMIT=460MB`），Client 内存 limits 设为 256MB。
  - 回滚阈值：发布后 5 分钟内错误率相对基线高出 5% 或核心 CONNECT-IP 连通性探针失败自动触发回滚。
  - 值班模式：无专职 24/7 人工值班；发布验证完全依赖自动化探针核验（§15.5），未通过即自动回滚。
- 多组件边界与错误码前缀（§4.5）：`aeroos`、`aeroprot`、`aerosub` 不互相 Go import；仅通过 HTTP REST、订阅 JSON 和 `127.0.0.1:19877` 状态边界通信；各子系统错误码前缀为 `CLIENT_`、`EDGE_`、`SUB_`、`DESK_`。
- 个人信息保护（§6.11）：Token、订阅凭据、节点和用户关联数据严禁打印至应用日志；运行时测试数据保留不超过 7 天并可安全清理。
