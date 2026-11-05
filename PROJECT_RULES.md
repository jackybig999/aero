# PROJECT_RULES

继承：GLOBAL_ENGINEERING_RULES.md（v1.1.1）
language: go

## 职责
承载 AERO 单 Go 模块迁移工程；本阶段只迁移并重构 `aeroprot` 客户端、边缘服务端和 guard，保留 `aeroos` 与 `aerosub` 目录结构供后续整合。

## 版本来源
当前版本来源为根目录 `VERSION`，迁移阶段沿用源仓库 `1.2.24`；发布性协议变更必须在发布前递增版本（§15.4）。

## 业务专有规则
协议和数据面以 `AERO-V2 (Hyper-MASQUE) 落地施工方案.md` 为施工基线；`aeroos`、`aerosub` 只保留目录和代码边界，不得被本阶段 `aeroprot` 代码直接导入。

## 对 L0 的收紧项
客户端初始 MTU 固定 1224；Windows 不新增宿主防火墙修改；移动端 TUN 明确返回不支持；任何删除或清理必须先归档并提供清单和回滚脚本。

## 剖面参数（§0.7）
`kind: service`、`network: inbound`、`concurrency: in-process`、`frontend: embedded`、
`components: multi`、`tenancy: multi`、`persistence: file`、`replicas: 1`、`ai: none`、
`pii: true`。因此必须记录网络调用超时、文件原子替换方式、请求体和限流参数、
多组件边界、个人信息保留与删除时限。

- 网络超时基线：QUIC 建连 8 秒，HTTP/TLS 外部调用 10 秒，健康探测 3 秒，订阅候选端口单端口 2.5 秒、总计 6 秒；改动这些数值必须由实测或故障证据驱动。
- 文件持久化：配置、订阅和 GeoData 使用同目录临时文件、`Sync`、`Close`、原子 `Rename`；失败时保留旧文件并返回错误。
- 入站参数：CONNECT-IP 请求体上限、限流阈值和 Cookie 属性在 M2/M6 的协议实现定稿前登记，未登记前不得宣称入站门禁完成。
- 多组件边界：`aeroos`、`aeroprot`、`aerosub` 不互相 Go import；仅通过 HTTP REST、订阅 JSON 和 `127.0.0.1:19877` 状态边界通信。
- 个人信息：Token、订阅凭据、节点和用户关联数据不得写入日志；生产保留与删除时限在 `aerosub` 后续整合前确定，当前只允许测试数据进入被忽略的运行态目录。
