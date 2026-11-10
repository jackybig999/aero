# ADR-0004 隐蔽分层：标准 HTTP/3 + LE 通配符 + ECH，ECH 失效时 fail-closed 切混淆

状态：proposed（2026-11-10）；用户确认“按建议”

## 背景
QUIC Initial 的保护不提供机密性（RFC 9001），SNI 可被读出；LE 证书写入 CT 日志，节点域名可被列举；ECH 的保护依赖共享外层名，节点灰云直连借不到 Cloudflare 的共享名。用户要求最强保护。

## 备选
1. 仅标准 HTTP/3。
2. 默认混淆（非标准）。
3. 标准为默认，叠加 ECH；ECH 失效时回退明文 SNI。
4. 同 3，但 ECH 失效时 fail-closed 并切换到混淆节点组。

## 理由
选 4。前两层均为标准；随机子域名限制 CT 暴露；不回退明文 SNI 与“绝不降级”一致；混淆作为明确划出的非标准档位，与标准档位不共用监听。

## 后果
- edge 内置 ACME（DNS-01，Cloudflare 令牌仅限单个 zone 的 DNS 编辑权限）。
- flag `ech_enabled` 默认 OFF；先完成 quic-go 路径抓包验证与国内主要运营商实测（§1.6 实验特性须记录）。
- 订阅需携带混淆节点组；可用性在 ECH 被干扰的网络中依赖混淆节点。
- 删除 `/admin/ech` 外部写入 ECH 配置的能力。
