# 接口就绪矩阵（附录 D.1）

| 契约点 | 契约状态 | 后端状态 | 一致性校验（§4.3） | 对应 flag | flag 状态 | 备注 |
|---|---|---|---|---|---|---|
| C1 CONNECT-IP `class=default` | draft | 已实现（需按 M1 修复） | 未执行 | `class_default` | OFF | M1 修复 SSRF、吊销后再 ON |
| C1 `class=ai` | draft | 未开始 | 未执行 | `class_ai` | OFF | 依赖 C9 |
| C1 `class=game` | draft | 未开始 | 未执行 | `class_game` | OFF | |
| C1 `class=browser` | draft | 未开始 | 未执行 | `class_browser` | OFF | 依赖 C9、C10 |
| C2 DoH | draft | 已实现（需按 M2 修复） | 未执行 | `doh` | OFF | |
| C3 签名 token | final | edge 校验已接入（§3 第 1–4、7 步；过期断连）；第 5 步依赖 C4，第 6 步依赖 C1 场景；sub 签发已实现（`-signed-tokens` 默认关，密钥 0600，安装时写公钥）；client 剩余 25% 时刷新订阅并轮换会话；edge 按 uid 租约保持隧道地址 | 黄金向量 api/testdata/c3-golden.json（sub 签、edge 验） | `auth_signed_token` | OFF | 档位由中台定义，token 携带执行参数。设备数超限时新连接优先、断开最早连接（2026-11-11 修订）。已核实 client 的鉴权流量只走主会话一条连接（连接池仅预热握手、不鉴权，不计数） |
| C5 订阅 | draft | 已实现（需重写） | 未执行 | `subscription_v2` | OFF | |
| C5 ECH | draft | 未开始 | 未执行 | `ech_enabled` | OFF | 先验证 quic-go 路径与国内网络 |
| C5 内层 IPv6 | draft | 部分实现（需重写） | 未执行 | `ipv6_inner` | OFF | 启动自检门禁 |
| C6 计量 | final | edge 已实现：按 uid/小时累计（usage.db，90 天保留，单调 seq）；`/v1/usage`、`/v1/status`（计量只读密钥、60 次/分钟、未鉴权返回伪装站）；中台已实现拉取：每 60 秒、按 (node_id, uid, period_start) 覆盖写入独立 usage.db，410/节点重装从头重读，严格校验 TLS；计量密钥经 SSH 只读回读，管理接口不返回。按自然月（UTC，用户决定 2026-11-12）汇总写入用户 traffic.used_bytes；超额后的处置（拒绝签发/吊销）待 C4 | 结构字段与错误码由 usage_api_test 对照契约 | `usage_api` | OFF | 只计量签名 token。CONNECT-IP 按 IP 报文长度；TCP/UDP relay 按 payload 字节（不含 IP/传输层头，低于契约“IP 层”口径，待用户决定是否接受或补估算）。无法识别的游标按 410 处理。`classes` 字段待出口健康检查落地后输出 |
| C9 出口 warp | draft | 插件形态已实现：只读状态 + 持久化开关（ADR-0012 §6） | 未执行 | `warp_proxy` 非空即开 | 按节点配置 | edge 不安装 WARP |
| 端口中途跳变 | draft | 进程内多端口监听已实现 | 未执行 | `port_hopping` | OFF | 不使用 DNAT（ADR-0012） |
| C7 本地管理接口 | final | 未开始 | 未执行 | `local_admin_api` | OFF | 落地后 deploy/aero 改为调用本接口 |
| C13 远程管理接口 | final | 未开始 | 未执行 | `remote_admin_v1` | OFF | 落地后中台删除 SSH 版状态/诊断/纯净度/证书/重启/密钥回读（ADR-0016） |
