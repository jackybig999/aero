# AERO Protocol Migration Workspace

本目录是 AERO 单 Go 模块迁移工作区，版本来源为根目录 `VERSION`。

## 组件边界

- `aeroprot/`：本阶段施工范围，包含客户端、边缘服务端和 guard。
- `aeroos/`：桌面工作台结构，后续整合；本阶段不由 `aeroprot` 直接导入。
- `aerosub/`：商业中台结构，后续整合；本阶段不由 `aeroprot` 直接导入。
- `deploy/`：部署脚本和部署配置。
- `tests/`：跨组件和端到端测试。

## 工程规则

施工必须先读取 `engineering-profile.yaml`、`PROJECT_RULES.md` 和
`GLOBAL_ENGINEERING_RULES.md`。代理入口为 `AGENTS.md`；`CLAUDE.md` 只引用它。

## 当前迁移阶段

M1 已切换客户端生产启动路径到 CONNECT-IP 与 `IPDataPump`，初始 TUN MTU 为 1224。
旧 gVisor 实现暂时保留，待客户端和 edge 的替代数据面分别完成并通过门禁后清理。

## 验证

```bash
go test -run '^$' ./aeroprot/...
go vet ./aeroprot/...
go test ./aeroprot/...
```

本地构建输出必须指向 `tmp/`，验证结束后清空 `tmp/`，不得把构建产物写入源码目录。
