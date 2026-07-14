# 服务端多用户能力（S1 续）

> 2026-07-14 — 目标：小 VPS 多用户、稳定、占坑可控

## 交付

| 能力 | 实现 |
|------|------|
| 多 token 持久化 | `data-dir/tokens.json` + `tokenstore` |
| Admin API | `GET/POST/DELETE /admin/tokens`，`GET /admin/status` |
| 空闲超时 | 默认 15m（档位可调），释连接槽 |
| 每用户带宽 | `-bw-user` / profile 内置 |
| 档位 | `-profile tiny\|small\|medium` |
| 拒绝指标 | capacity / rate / idle 分计数 |
| 优雅退出 | drain → Shutdown 15s |

## 推荐生产命令

```bash
aero-edge -token BOOTSTRAP -listen :443 -domain edge.example.com \
  -profile small -admin-key "$(openssl rand -hex 16)"
```

## 回测

- `go test ./aero-edge/...` PASS  
- proxy smoke OK  
- stability 28/0 OK  

## 仍可选后续

- 按 token 独立订阅 secret  
- 更细的公平队列（非忙等 sleep）  
- 长稳压测（百用户×小时）  
