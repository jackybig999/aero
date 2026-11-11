## AERO 1.3.0

### 安全修复（请尽快升级）
- 中台：删除无鉴权的 `/sub/superadmin` 与 `/sub/{管理员用户名}` 订阅入口，删除源码中硬编码的 `usr_superadmin` 凭证（曾被写入每个节点）。
- 中台：管理员不再使用固定 slug 与默认密码 `admin123456`；首次启动或检测到旧值时自动轮换，初始密码只写入数据目录 `initial_admin_password`（0600）。**管理员订阅地址会变化**，请在中台重新获取。
- edge（此前版本已修复，随本版发布）：`/sub/admin` 匿名泄露、CONNECT-IP 目的地址 ACL、吊销后在线会话断开、nonce 表 DoS 等。

### 客户端：不再修改宿主系统（ADR-0012 / 0013 / 0014）
- 删除 NRPT、netsh 持久配置、系统 DNS 修改、`/etc/resolv.conf` 改写、物理网卡路由与 `.bat` 脚本。
- 所有宿主状态都挂在自有网卡上（Windows：wintun 固定 GUID + IP Helper API），进程退出或崩溃时由系统自动清除；实测强杀后 0.74 秒内无残留。
- DNS 防泄漏改用进程级动态机制（Windows WFP 动态会话；Linux 仅对 aero0 设置 resolved 链路 DNS）。
- 直连分流改为补集路由（全部挂在 TUN 上），IPv6 不再从物理网卡泄漏。
- 删除崩溃守护进程 `guard.exe`（不再需要）。
- `-mode socks` 不再误入 TUN 模式；未知模式拒绝启动。

### 已知限制
- macOS 的 TUN 模式暂不可用（明确报错），本地代理模式正常；将在后续版本实现。
- 本版客户端仍发送旧版 edge 需要的鉴权头，兼容尚未升级的节点。

### 构建
- 发布产物由 CI 使用最新稳定版 Go 构建（包含 net/http 安全修复 GO-2026-6859）。
