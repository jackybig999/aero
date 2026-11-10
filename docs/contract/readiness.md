# 接口就绪矩阵（附录 D.1）

| 契约点 | 契约状态 | 后端状态 | 一致性校验（§4.3） | 对应 flag | flag 状态 | 备注 |
|---|---|---|---|---|---|---|
| C1 CONNECT-IP `class=default` | draft | 已实现（需按 M1 修复） | 未执行 | `class_default` | OFF | M1 修复 SSRF、吊销后再 ON |
| C1 `class=ai` | draft | 未开始 | 未执行 | `class_ai` | OFF | 依赖 C9 |
| C1 `class=game` | draft | 未开始 | 未执行 | `class_game` | OFF | |
| C1 `class=browser` | draft | 未开始 | 未执行 | `class_browser` | OFF | 依赖 C9、C10 |
| C2 DoH | draft | 已实现（需按 M2 修复） | 未执行 | `doh` | OFF | |
| C3 签名 token | draft（2026-11-10 起草，待用户审） | 未开始 | 未执行 | `auth_signed_token` | OFF | 见 api/token.md §6 待确认问题 |
| C5 订阅 | draft | 已实现（需重写） | 未执行 | `subscription_v2` | OFF | |
| C5 ECH | draft | 未开始 | 未执行 | `ech_enabled` | OFF | 先验证 quic-go 路径与国内网络 |
| C5 内层 IPv6 | draft | 部分实现（需重写） | 未执行 | `ipv6_inner` | OFF | 启动自检门禁 |
| C6 计量 | draft | 未开始 | 未执行 | `usage_api` | OFF | |
| C9 出口 warp | draft | 未开始 | 未执行 | `egress_warp` | OFF | |
| 端口中途跳变 | draft | 未开始 | 未执行 | `port_hopping` | OFF | 宿主 nftables |
