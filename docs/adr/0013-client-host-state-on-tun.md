# ADR-0013 客户端宿主状态全部挂在自有 TUN 网卡上

状态：accepted（2026-11-11）
关系：落实 ADR-0012 在客户端（桌面平台）的实现方式。移动端由系统 VPN API（VpnService、NetworkExtension）管理，不在本条范围。

## 背景
旧实现在 Windows 用 NRPT（注册表）、netsh 默认 persistent 存储（IPv6 路由与地址、metric、网卡 DNS）、物理网卡排除路由与 DNS /32、TEMP 下 .bat；每次随机 GUID 建 wintun 网卡，注册表留下孤儿配置；macOS 用 networksetup 改系统 DNS；Linux 可能改写 /etc/resolv.conf。错误全部丢弃，回滚分散在 engine 六个失败分支里。崩溃后宿主网络失效。

## 决定
客户端只创建与修改“属于自有 TUN 网卡”的状态，网卡销毁时由操作系统一并清除：
1. 网卡：固定名称（Windows 固定 GUID，避免注册表孤儿）。启动前若存在同名/同 GUID 残留网卡，先删除。
2. 地址：只配置在 TUN 上；Windows 走 IP Helper API（active store，不落注册表）。
3. 路由：全部挂在 TUN 上，由 `PlanTUNRoutes` 生成：
   - IPv4 = 全部公网地址 − 直连网段 − 特殊用途网段 − edge 外层地址，再加系统 DNS 服务器 /32（捕获）。
   - IPv6 = `2000::/3` − edge 外层地址（内层 IPv6 可用则转发，否则在 TUN 内丢弃）。
   - 物理网卡上不加任何路由。
4. DNS：不修改任何网卡或系统 DNS 设置；系统 DNS 服务器地址被路由进 TUN，由端口 53 拦截处理。
5. 防回环：客户端自身的出站 socket（到 edge 的 QUIC、直连 DNS 上游）绑定物理网卡（Windows `IP_UNICAST_IF`、macOS `IP_BOUND_IF`、Linux `SO_BINDTODEVICE`）。
6. kill switch 在 TUN 内丢弃实现，不使用系统防火墙。
7. 崩溃兜底：Linux、macOS 的 TUN 随进程文件描述符关闭自动销毁；Windows 由 guard 进程在父进程退出后删除自有网卡，下次启动再检查一次。

## 后果
- 崩溃后网络回到直连、可用、无残留；代价是崩溃期间 kill switch 不生效（不动系统防火墙的必然结果）。
- 删除：NRPT、netsh、networksetup DNS、resolv.conf 改写、物理网卡路由、.bat、ProtectHostRoute 与 RotatePhysicalDNSRoute。
- 路由条数约为直连名单的 2.5 倍（当前名单 3898 条 → 9886 条）；各平台用批量接口下发（Windows IP Helper、macOS 路由 socket、Linux `ip -batch`）。
- 每个平台附一次“强杀进程后残留检查”实测记录。
