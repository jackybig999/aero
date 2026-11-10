# AERO

基于标准 HTTP/3 MASQUE（RFC 9298 / RFC 9484）的多用户加密隧道系统。版本来源为根目录 `VERSION`。

## 目录（最多两级，ADR-0009）

| 路径 | 内容 |
|---|---|
| `cmd/edge`、`internal/edge` | 服务端：数据面、鉴权校验、计量、证书、geo 分发 |
| `cmd/client`、`cmd/guard`、`internal/client` | 客户端与守护进程 |
| `cmd/sub`、`internal/sub` | 订阅与计费中台（只读 edge 接口，不写服务端） |
| `cmd/desk`、`internal/desk` | 桌面工作台：浏览器环境与指纹 |
| `internal/egress`、`cmd/egress` | 出口模块（M5 新建，ADR-0006） |
| `api/` | 组件之间唯一的契约：清单见 `api/README.md`，错误码 `api/errors.yaml` |
| `docs/adr/` | 架构决策记录 |
| `docs/contract/readiness.md` | 接口就绪矩阵 |
| `deploy/` | 安装脚本（只放置二进制与 systemd unit） |
| `tools/` | 仓库检查脚本 |
| `tests/` | 跨组件测试 |

组件之间 **不得** 互相 import，只通过 `api/` 契约通信；由 `tools/check-imports.sh` 在 CI 中强制。

## 工程规则

先读 `engineering-profile.yaml`、`PROJECT_RULES.md`、`GLOBAL_ENGINEERING_RULES.md`。代理入口为 `AGENTS.md`；`CLAUDE.md` 只引用它。

## 验证

```bash
tools/check-imports.sh
go build ./...
go vet ./...
go test -shuffle=on ./...
```

本地构建输出必须指向 `tmp/`，不得把构建产物写入源码目录。
