# 接口就绪矩阵（附录 D.1）

| 契约点 | 契约状态 | 后端状态 | 一致性校验（§4.3） | 对应 flag | flag 状态 | 备注 |
|---|---|---|---|---|---|---|
| C1 CONNECT-IP `class=default` | draft | 已实现（需按 M1 修复） | 未执行 | `class_default` | OFF | M1 修复 SSRF、吊销后再 ON |
| C1 `class=ai` | draft | 未开始 | 未执行 | `class_ai` | OFF | 依赖 C9 |
| C1 `class=game` | draft | 未开始 | 未执行 | `class_game` | OFF | |
| C1 `class=browser` | draft | 未开始 | 未执行 | `class_browser` | OFF | 依赖 C9、C10 |
| C2 DoH | draft | 已实现（需按 M2 修复） | 未执行 | `doh` | OFF | |
| C3 签名 token | final | edge 校验已接入（§3 第 1–4、7 步；过期断连）；第 5 步依赖 C4，第 6 步依赖 C1 场景；sub 签发未开始 | 未执行 | `auth_signed_token` | OFF | 档位由中台定义，token 携带执行参数。设备数超限时新连接优先、断开最早连接（2026-11-11 修订）。已核实 client 的鉴权流量只走主会话一条连接（连接池仅预热握手、不鉴权，不计数） |
| C5 订阅 | draft | 已实现（需重写） | 未执行 | `subscription_v2` | OFF | |
| C5 ECH | draft | 未开始 | 未执行 | `ech_enabled` | OFF | 先验证 quic-go 路径与国内网络 |
| C5 内层 IPv6 | draft | 部分实现（需重写） | 未执行 | `ipv6_inner` | OFF | 启动自检门禁 |
| C6 计量 | final | 未开始 | 未执行 | `usage_api` | OFF |  |
| C9 出口 warp | draft | 插件形态已实现：只读状态 + 持久化开关（ADR-0012 §6） | 未执行 | `warp_proxy` 非空即开 | 按节点配置 | edge 不安装 WARP |
| 端口中途跳变 | draft | 进程内多端口监听已实现 | 未执行 | `port_hopping` | OFF | 不使用 DNAT（ADR-0012） |
| C7 本地管理接口 | final | 未开始 | 未执行 | `local_admin_api` | OFF | 落地后 deploy/aero 改为调用本接口 |
