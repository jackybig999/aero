# ADR-0006 出口模块独立：egress 管理 direct / warp / relay，WARP 只用官方客户端

状态：proposed（2026-11-10）

## 背景
WARP 以 SOCKS5 形式嵌在 edge；`127.0.0.1:1080` 上任意 SOCKS 服务都会被当作 WARP 接管全部流量；Web 控制台以 root 执行 apt 安装；多跳级联每条流新建一次 QUIC 握手；IP 纯净度检测与 edge 混在一起。用户要求 WARP 与服务端切割、用于保护 IP，且必须按官方版本和标准接入。

## 备选
1. 保留在 edge 内，只修 bug。
2. 独立进程，第三方 WireGuard 配置（wgcf 等）接入：非官方，排除。
3. 独立进程，Cloudflare 官方客户端（`cloudflare-warp`）：
   - 3a 官方 warp 模式，运行在独立网络命名空间，经 veth 与宿主相连；场景地址池按策略路由送入该命名空间。
   - 3b 官方 proxy 模式（本地 SOCKS5），egress 内做三层到四层的转换。

## 理由
选 3。只使用官方客户端与官方模式，升级与支持跟随官方。3a 与 3b 的取舍需要实测：3a 保持三层直通、开销低，但官方客户端在命名空间内运行的行为需验证；3b 是官方明确支持的选择性使用方式，但需要用户态协议栈，开销更高。

## 后果
- 新独立单元 `internal/egress`、`cmd/egress`，契约 `api/egress.yaml`（本地 unix socket）：出口列表、健康分、场景 → 出口映射、环境粘性绑定。
- WARP 软件包由运维按 Cloudflare 官方文档安装；edge、egress、安装脚本均不安装 WARP。
- M5 前以 `spike/egress-warp` 分支验证 3a 与 3b（§0.3：14 日内删除，不合入主干），结论另写 ADR 取代本条的未决部分。
- relay 后端：到出口节点的长连接 CONNECT-IP，一个场景地址池一条；第一版只做 direct 与 warp。
- 纯净度检测并入出口健康分；分数低时只摘该出口。
- `ai`、`browser` 出口失效 fail-closed；`default` 回落 direct。
