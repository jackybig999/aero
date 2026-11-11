# ADR-0012 宿主状态铁律：只改属于自己的、可自动回滚的状态

状态：accepted（2026-11-11，用户决定）
关系：收紧 PROJECT_RULES“宿主全局状态”；部分取代 ADR-0005 中“端口跳变用 nftables DNAT”（改为进程内多端口监听）与 ADR-0006 中 WARP 归属 egress 的设计（改为独立插件）。

## 背景
用户要求：任何时候服务端不得修改 VPS 的系统与配置，客户端不得修改宿主机（Windows 的配置文件、注册表，macOS 等同理），只在程序内部完善。客户端曾因残留把宿主网络弄坏。
现状核实（2026-11-11）：
- 客户端 Windows 用 NRPT（`Add-DnsClientNrptRule -Namespace '.'`，持久化到注册表）把全机 DNS 指向隧道；物理网卡上挂直连排除路由与 DNS /32 路由；在 TEMP 写 .bat 执行。崩溃且 guard 未运行时全机 DNS 失效。
- 客户端 macOS 用 `networksetup -setdnsservers` 改系统 DNS；Linux 无 resolved 时改写 `/etc/resolv.conf`。
- edge 写 `ip_forward=1` 且从不还原；iptables 规则只在正常退出时删除；`warp_installer.go` 在 edge 内执行 apt、systemctl、改防火墙。
- 安装流水线（probe.go）配置 iptables 2083→443 重定向等系统修改。

## 决定
1. **禁止 gVisor 及任何用户态 TCP/IP 协议栈**（用户已于 v1.2.25 移除，不得回退）。
2. **客户端 TUN 允许**，但只能改“属于本程序 TUN 网卡”的状态：
   - 允许：创建本程序的 TUN 网卡；挂在该网卡上的路由；设置该网卡自身的 DNS。这些随网卡销毁自动消失。
   - 禁止：NRPT、注册表、系统 DNS 设置（networksetup、/etc/resolv.conf）、物理网卡上的路由、防火墙规则、任何系统配置文件、在系统临时目录落脚本执行。
   - 防回环：用 socket 绑定物理网卡（Windows `IP_UNICAST_IF`、macOS `IP_BOUND_IF`、Linux `SO_BINDTODEVICE`），不再添加到服务器的主机路由。
   - 直连分流：只把“非直连”网段路由进 TUN（补集路由），不在物理网卡上加排除路由。
   - kill switch 在程序内实现（TUN 内丢弃），不使用系统防火墙。
3. **三重回滚**（客户端与服务端都适用）：任何无法随网卡自动消失的修改，都必须同时具备
   - 正常退出时回滚；
   - 崩溃应急：独立守护进程（客户端 `cmd/guard`，各桌面平台通用）或 systemd `ExecStopPost`（服务端）执行回滚；
   - 启动时自检：按本程序数据目录内的变更日志先回滚上次残留，再开始工作。
   变更日志只写在本程序数据目录内。
4. **服务端**：CONNECT-IP 需要内核 TUN + NAT，这是唯一保留的宿主修改，必须带本程序标签、可三重回滚。
   - `ip_forward`：启动前记录原值，退出与应急时还原；若原值为 0，额外加一条带标签的规则，只放行 aero TUN 的转发，保持宿主原有“不转发”的语义。
   - CONNECT-UDP 与 TCP 中继只用普通 socket，不改系统。
5. **安装**：中台经 SSH 安装 edge 允许（ADR-0011），限于二进制、数据目录与 `aero-edge.service`，卸载时全部删除；安装流水线不得配置 iptables 重定向、sysctl 调优或 apt 安装。端口冲突由端口轮试解决（ADR-0005）。
6. **WARP 是独立插件**，与 edge 无代码、配置、进程上的任何交叉：
   - edge 只提供一个通用出口接口：“某些流量场景经指定的本地 SOCKS5 上游发出”，不认识 WARP。
   - 插件独立组件，WARP 官方客户端由运维按官方文档安装（官方 proxy 模式提供本地 SOCKS5）；edge 与安装流水线都不安装 WARP。
   - 插件不存在时，edge 行为不变。

## 后果
- 删除：客户端 NRPT、系统 DNS 修改、物理网卡路由、.bat 执行；edge 的 `warp_installer.go` 与 WARP 专用参数；安装流水线中的系统修改。
- 新增：客户端 socket 绑定网卡、补集路由、通用守护与变更日志；edge 的 `ip_forward` 还原与 `cleanup-host` 子命令、ExecStopPost。
- 每项宿主修改附一次“强杀后残留”实测记录。
