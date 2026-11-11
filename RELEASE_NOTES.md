## AERO 1.3.2

### 服务端：退出、崩溃、重启都还原宿主（ADR-0012）
- edge 修改 `net.ipv4.ip_forward` 前把原值记入数据目录 `host-state.json`，退出时还原（此前只开不还）。
- 转发规则按标记 `aero_edge_default` 扫描删除，覆盖崩溃残留、出口网卡变化与旧版遗留的全局 MSS 规则。
- 新增 `aero-edge cleanup-host`：服务单元以 `ExecStopPost` 调用，进程崩溃后同样还原；edge 运行中拒绝执行。
- 宿主原本未开启转发时，追加只放行 aero 网卡的隔离规则，保持宿主原有语义。
- 只有 TUN 就绪后才修改宿主。

### 中台安装流程不再修改节点系统（安全修复）
- 修复：节点令牌曾为 `tok_<VPS 名称>`、管理密钥与订阅 secret 由时间戳生成，可被猜出。现为 128 位随机密钥，且不再出现在启动命令行。
- 删除：覆盖 `/etc/nftables.conf`、`iptables-save` 持久化、apt 安装软件、永久开放 UFW/firewalld、2083→443 重定向、覆盖 edge 的 `sub_meta.json`。
- 二进制按节点架构下载，并对照 Release 的 `SHA256SUMS` 校验；全新安装只写最小配置，已有配置不覆盖。防火墙仅检测并提示运维。
- 停用中台的 WARP 安装任务（曾以 `ufw allow 40000/tcp` 把 SOCKS5 代理对公网开放）。

### WARP 改为插件
- edge 删除 WARP 安装器，只读取本机官方客户端代理（127.0.0.1:40000）的状态；控制台开关持久化到配置文件，重启后保持。

### 其他
- Release 不再被重复构建覆盖，并附带 `SHA256SUMS`。

### 升级提示
- 服务单元需加入 `ExecStopPost=/usr/local/bin/aero-edge cleanup-host`（新安装自动包含）。

## AERO 1.3.1（上一版本）

### 紧急修复
- **edge：CONNECT-IP 下行中断**。Linux 上打开 TUN 的方式导致读取立即失败（`read /dev/net/tun: not pollable`），共享 TUN 的下行读取协程一启动就退出，隧道建立后没有任何回包。v1.3.0 的 edge 受影响，请立即升级。
- **Linux 客户端**：同一问题导致 TUN 模式读不到报文，已一并修复。
- **客户端 IPv6**：IPv6 已进入 TUN（不再从物理网卡泄漏）后，此前从未启用的本地 IPv6 黑洞现已启用：非 DNS 的 IPv6 在本地回 ICMPv6 不可达，应用立即回落 IPv4，不再等待超时。
- 新增真实设备读包测试（隔离网络命名空间），覆盖 edge 与客户端。

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
