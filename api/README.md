# api/：契约清单（M0 草稿）

本目录是组件之间唯一的接口真相源（L0 §4.1）。错误码注册表：`api/errors.yaml`；就绪矩阵：`docs/contract/readiness.md`。

所有契约初始状态为 `draft`；`draft` 契约不得用于生产构建（§4.1）。类型 **MUST** 由契约生成，删除所有 snake_case / camelCase 双字段兼容。

| # | 边界 | 提供方 → 消费方 | 载体 | 文件 | 关键内容 | 状态机 |
|---|---|---|---|---|---|---|
| C1 | 数据面 CONNECT-IP | edge → client | RFC 9484 + 扩展参数 | `api/dataplane.md` | URI 模板、`class`/`env` 参数、地址分配、路由通告、Proxy-Status 错误映射 | 会话：请求中 → 已分配 → 运行 → 断开（按原因细分：吊销 / 过期 / 超配额 / 超设备 / 出口失效 / 网络） |
| C2 | DoH | edge → client | RFC 8484（POST + GET） | 同上 | 记录类型全覆盖、SERVFAIL/NXDOMAIN 语义、体积上限 | — |
| C3 | 用户 token | sub、edge（本地签发）→ edge、client | JSON Schema + Ed25519 签名规范 | `api/token.md`、`api/token.schema.json` | 线上格式 `aero1.<payload>.<sig>`（签原始字节，无需规范化）、两个签发方、校验顺序与错误码、`kid` 轮换、迁移 | — |
| C4 | 吊销列表 | sub → edge | OpenAPI（edge 拉取） | `api/sub-revocation.yaml` | 签名、版本号、增量游标 | — |
| C5 | 订阅文档 | edge → client | JSON Schema | `api/subscription.schema.json` | 节点、候选端口、档位（标准 / 混淆）、ECH 配置、IPv6 声明、场景能力；签名由 edge 节点密钥完成（不再用 token 当 HMAC 密钥） | — |
| C6 | edge 只读外部接口 | edge → sub | OpenAPI `/v1/usage`、`/v1/status` | `api/edge-public.yaml` | 计量游标分页、计量只读密钥鉴权、限流 | — |
| C7 | edge 本地管理接口 | edge → CLI、控制台 | OpenAPI（unix socket） | `api/edge-admin.yaml` | 配置、端口、证书、用户会话查询与强制断开、cleanup-host | 端口选择、证书续期 |
| C8 | geo 数据 | edge → client | OpenAPI + 文件格式 | `api/geo.yaml` | 域名列表 + CN IP 段、ETag、签名、鉴权 | — |
| C9 | 出口模块 | aero-egress → edge | OpenAPI（unix socket） | `api/egress.yaml` | 出口列表、健康分、场景 → 出口映射、环境粘性绑定 | 出口：未就绪 → 健康 → 降级 → 摘除 |
| C10 | 环境绑定 | client ↔ desk | OpenAPI（`127.0.0.1:19877`） | `api/desk-env.yaml` | 环境 ID、出口 IP、时区、出口变更通知 | 绑定中 → 已绑定 → 出口失效 → 已重绑定 |
| C11 | 客户端本地 UI | client 后端 → 内嵌 UI | OpenAPI | `api/client-ui.yaml` | 连接状态、错误码、场景开关 | 连接：未连接 → 连接中 → 已连接 → 重连中 → 失败（按错误码细分） |
| C12 | 候选端口列表 | 共享常量 | 生成代码 | `api/ports.yaml` | 端口顺序 | — |

## 删除的旧接口
- M1 过渡（2026-11-10）：`/sub/admin` 匿名访问已关闭（返回 404，与未知路径不可区分）；管理员订阅暂由不可猜测的 `/sub/{secret}` 提供，M3 由 C3 签名 token + C5 订阅契约取代。
- `/sub/admin` 匿名访问、`/sub/{secret}`、`/admin/subs`（sub 写 edge）、`/admin/ech` 写入、`/console/api/warp/install|uninstall`、`Aero-Timestamp`/`Aero-Nonce`。
