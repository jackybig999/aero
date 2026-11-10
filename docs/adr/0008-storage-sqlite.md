# ADR-0008 存储引擎：edge 使用 SQLite

状态：proposed（2026-11-10）

## 背景
现以多个 JSON 文件持久化（tokens.json、sub_meta.json、edge.json），无 fsync，Reload 先清空再加载；计量只在内存。新设计需持久化计量、设备会话、环境粘性出口、端口选择、吊销缓存。

## 备选
1. 继续使用 JSON 文件。
2. 嵌入式 KV（bbolt）。
3. SQLite（仓库已依赖 `modernc.org/sqlite`，纯 Go）。

## 理由
选 3。事务与约束可用；无 cgo；仓库已有依赖，不新增许可证风险（§7.6）。

## 后果
- 剖面 `persistence: file` → `sqlite`（先改剖面，再改代码，§0.6）。
- 执行 §6.2、§6.3、§6.10、§6.11；迁移脚本入库。
- 计量按小时聚合写入，崩溃丢失窗口不超过 60 秒（估算，M3 实测）。
- 旧 JSON 文件提供一次性迁移，迁移前归档（PROJECT_RULES 收紧项）。
