# Edge 服务端 v1.0 完成定义（基本完美基线）

> 2026-07-14 · `aero-edge 1.0.0` · `api_level=1`

## 目标

服务端达到：**多用户可运营、小 VPS 可承载、契约冻结**；后期升级以 bugfix / 增字段为主。

## 冻结面

| 层 | 内容 | 文档 |
|----|------|------|
| 协议主路径 | H2 CONNECT + TypedMessage | `protocol-v1.md` + 实现状态表 |
| 运维契约 | Admin / token / 容量 / 错误码 | `contracts/edge-server-v1.md` |
| 版本 | `1.0.0` / api_level=1 | `internal/version` |

## 能力清单（v1 齐）

- [x] 稳定 H2 隧道 + Flush 正确  
- [x] 鉴权 + nonce 防重放 + 上限  
- [x] 多 token 持久化 + Admin 增删改查 + reload  
- [x] 全局/每用户并发 · IP 限速 · 每用户带宽  
- [x] 空闲超时 · 最大寿命 · 拨号并发闸门  
- [x] profile tiny/small/medium  
- [x] Cover · 签名订阅 · pin  
- [x] metrics 拒绝分类 · drain 优雅退出  
- [x] `-version` · 契约文档  

## 升级策略

| 变更类型 | 版本 |
|----------|------|
| 修 bug、优化性能 | 1.0.x |
| 只增 Admin/metrics/配置字段 | 1.x.0 |
| 破坏 CONNECT/帧/签名 | 2.0.0 |

## 回测

```text
go test ./aero-edge/...     PASS
aero-edge -version          1.0.0
proxy smoke                 SMOKE OK（发布前再跑）
```

## 生产一行

```bash
aero-edge -token BOOTSTRAP -listen :443 -domain edge.example.com -profile small -admin-key KEY -data-dir /var/lib/aero
```
