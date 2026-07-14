# S1 服务端硬化（协议核心）— 进度

> 日期：2026-07-14  
> 目标：稳定可靠 · 高速高效 · 多用户可承载 · CLI 简洁

## 已完成

| 项 | 说明 |
|----|------|
| **并发上限** | `connlimit`：全局默认 4096、每 token 默认 128，防小 VPS 被拖垮 |
| **IP 限速** | `ratelimit` 接入 CONNECT；默认 20 新建/秒/IP；认证失败可封禁 |
| **中继性能** | 读缓冲池；小包立刻 Flush、大块 64KB 批量；结束强制 Flush |
| **去掉不可靠逻辑** | 删除伪造 SSE keepalive 注入（会污染业务流）；QUIC 仍不监听 |
| **热路径减负** | 默认内存 AI context（不写 SQLite）；减少每连接日志；QoS 静默 |
| **HTTP/2** | `MaxConcurrentStreams=256`；`ReadHeaderTimeout=10s` 防慢连 |
| **Nonce 防洪** | 上限 10 万条，超限清理/拒绝，保护多用户节点 |
| **CLI 简洁** | `-listen` / `-token` / `-domain` / `-cert` / `-key` / `-max-conn` / `-q` |
| **分目录** | 改动仅在 `aero-edge/` + `docs/` |

## 简洁命令

```bash
aero-edge -token SECRET -listen :443 -domain edge.example.com
aero-edge -token SECRET -listen :443 -cert c.pem -key k.pem -max-conn 1024 -max-conn-user 32 -q
aero-edge -token SECRET   # 开发自签 :8443
```

## 回测

```text
go test ./aero-edge/... -count=1   → PASS
tests/e2e/run_proxy_smoke.ps1     → SMOKE OK
```

## 保留的优秀代码

- `auth` Token + 时间窗 + nonce  
- `subscribe` 签名订阅 + pin  
- `cover` 同端口正站  
- `certmgr` 自签 / 手动 / ACME  
- H2 CONNECT + TypedMessage 主路径  

## 后续（仍属服务端，未做）

- Admin API 多 token 热加载  
- 按 token 带宽限速（字节级）  
- 更细的 metrics（拒绝原因计数）  
- 长稳压测脚本（N 用户 × M 并发）  
