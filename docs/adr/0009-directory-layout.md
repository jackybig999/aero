# ADR-0009 目录布局：两级扁平结构 + CI 强制组件隔离

状态：proposed（2026-11-10）

## 背景
现有结构 `aeroprot/internal/edge`、`aerosub/internal/mid`、`aeroos/internal/desk` 为三级，`cmd` 分散在三个子树；用户要求避免多级目录、易维护，同时组件之间严格分割、不得穿插。L0 §2.1 要求非 main 包位于 `internal/`、多二进制入口位于 `cmd/<bin>/`。

## 备选
1. 保持三棵子树（编译器借 `internal/` 可见性阻止跨子系统 import）。
2. 每个组件独立 Go module（go.work）：隔离最强，但目录与依赖管理成倍增加。
3. 单 module 两级扁平：`cmd/<组件>`、`internal/<组件>`；跨组件 import 由 CI 脚本禁止。

## 理由
选 3。目录最浅；隔离从编译器转移到 `tools/check-imports.sh`，在 CI 中阻断，效果等同且规则可读。

## 后果
- 迁移映射：`aeroprot/internal/edge→internal/edge`、`aeroprot/internal/client→internal/client`、`aerosub/internal/mid→internal/sub`（包名 mid→sub）、`aeroos/internal/desk→internal/desk`、`aeroprot/cmd/{edge,client,guard}→cmd/{edge,client,guard}`、`aerosub/cmd/mid→cmd/sub`、`aeroos/cmd/desk→cmd/desk`。
- 发布物文件名暂不变（`edge_linux_*`、`mid_linux_*` 等），避免破坏现有安装脚本；改名另作一步。
- 契约放 `api/`；类型生成到各消费方包内，不建共享类型包。
- 已知遗留：`tests/e2e` 不 import 任何生产包，测的是自带的模拟实现，须在 M1 重写为真实二进制测试。
