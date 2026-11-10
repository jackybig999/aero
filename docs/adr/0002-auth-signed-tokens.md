# ADR-0002 鉴权模型：sub 签发 Ed25519 token，edge 离线验签

状态：proposed（2026-11-10）

## 背景
现有方案：Bearer token + 全局 nonce 表 + 时间戳，无签名绑定；单个用户可在 2 分钟内塞满 10 万条 nonce，使全站鉴权失败。吊销与过期不断开已有会话。多节点时用户需同步到每个 edge，而 sub 不得写 edge（ADR-0001）。

## 备选
1. 每个 edge 自建用户表，由 sub 推送（违反 ADR-0001）。
2. edge 每次建连向 sub 在线校验（sub 故障即全网不可用）。
3. sub 签发自包含签名 token，edge 用公钥离线验签，吊销列表由 edge 拉取。

## 理由
选 3。edge 与 sub 之间只有一把公钥的静态信任，没有运行时写入；短有效期 + 吊销列表兼顾即时性与可用性；去掉 nonce 表消除全局 DoS 面。

## 后果
- token 字段：`uid, tier, classes, max_devices, exp, kid`；`kid` 支持密钥轮换。
- token 有效期 24 小时（估算），client 自动刷新。
- edge 断开会话的触发：吊销、过期、超配额、超设备数，目标 10 秒内（M3 实测）。
- 删除 `Aero-Timestamp`、`Aero-Nonce` 与 `nonce.wal`。
- 凭证分离：签名私钥只在 sub；edge 管理密钥、计量只读密钥、CF DNS 令牌、ECH/混淆密钥、出口凭证各自独立。
