# ADR-0001 组件边界：edge 权威、sub 只读、安装脚本只放置文件

状态：proposed（2026-11-10）

## 背景
v1.2.40 中 sub 通过 `/admin/subs` 写 edge，edge 本应向 sub 推送计量（从未调用）；安装脚本与 `deploy/aero` 用 `sed` 改 `/etc/aero/edge.json`；edge 内含 WARP 安装器（Web 控制台以 root 执行 `apt`/`sh -c`）。多方写同一份事实，导致反复漂移。

## 备选
1. 维持双向耦合，补齐契约。
2. sub 为中心，edge 无状态，全部向 sub 查询。
3. edge 为各自节点的权威，sub 只读 edge 接口；WARP 等出口能力拆为独立进程。

## 理由
选 3。运行时依赖只有单向读取，sub 故障不影响数据面；每类事实只有一个写者（§6.1）；安装脚本与业务解耦后可重复执行（§8.7）。

## 后果
- 需新增 edge 本地管理接口（unix socket）与只读外部接口（`/v1/usage`、`/v1/status`）。
- `deploy/aero` 重写为管理接口的客户端。
- WARP 安装器从 edge 删除，见 ADR-0006。
- 用户在多个节点间的分发不能靠 sub 写 edge，见 ADR-0002。
