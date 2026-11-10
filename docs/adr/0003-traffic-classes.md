# ADR-0003 流量场景：每个场景一条 CONNECT-IP 会话，出口由内核策略路由决定

状态：proposed（2026-11-10）

## 背景
产品要求按 AI、浏览器、游戏、其他分流。CONNECT-IP 是三层隧道，edge 看不到域名；现有 WARP 只作用于 TCP CONNECT / CONNECT-UDP，主路径上不生效。

## 备选
1. edge 做 DPI / SNI 嗅探判定场景（侵犯隐私、ECH 下失效）。
2. 全部改走 CONNECT-UDP / TCP CONNECT 以便携带域名（放弃 CONNECT-IP 主路径）。
3. client 分类，每个场景一条独立会话，edge 按会话分配独立地址池，内核按源地址策略路由。

## 理由
选 3。分类信息由会话本身携带，edge 无需解析流量；出口策略在内核完成，开销低；各场景互不影响。

## 后果
- CONNECT-IP 请求增加 `class` 参数（契约变更）；`browser` 额外携带 `env`。
- 地址池示例：`default 10.88/16`、`ai 10.89/16`、`game 10.90/16`、`browser 10.91/16`，IPv6 对应 ULA 子网。
- client 同时维护最多 4 条会话，共用一条 QUIC 连接。
- 浏览器指纹归 desk；数据面只保证环境的出口 IP、时区、DNS 一致。
