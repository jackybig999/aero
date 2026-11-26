# AERO

基于标准 HTTP/3 MASQUE（RFC 9298 / RFC 9484）的多用户加密隧道。版本见根目录 `VERSION`。

| 目录 | 内容 |
|---|---|
| `cmd/edge`、`internal/edge` | 服务端 |
| `cmd/client`、`internal/client` | 客户端 |
| `cmd/sub`、`internal/sub` | 订阅与计费中台 |
| `cmd/desk`、`internal/desk` | 桌面工作台 |
| `api/` | 组件之间的契约（组件互不 import，CI 强制） |
| `docs/adr/` | 架构决策记录 |
| `deploy/` | 服务端安装与运维脚本 |

## 验证

```bash
go build ./... && go vet ./... && go test -shuffle=on ./...
```

## 许可

AGPL-3.0-or-later，个人免费使用；商业使用需另取授权。详见 `LICENSING.md`。
