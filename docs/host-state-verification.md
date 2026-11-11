# 宿主状态实测记录（ADR-0012 / 0013 / 0014）

每项宿主修改须有一次“强杀后残留”实测。新增记录追加在对应平台下。

## 客户端 Linux（tunHost）
- 2026-11-11，WSL2 Debian 13，内核 6.18，`unshare -rn` 隔离命名空间，HEAD 788806a 起。
- `TestTunHostLinuxLifecycle`、`TestTunHostLinuxRollbackOnFailure`、`TestTunHostLinuxNoResidueAfterKill`：通过。
- kill -9 后 aero0 及其全部路由消失；IPv6 路由进入 TUN（网卡 MTU 1280，IPv4 路由 mtu 1224）。
- 未覆盖：systemd-resolved 链路 DNS（测试中禁止调用真实 resolvectl）。

## 客户端 Windows（tunHost + WFP DNS 防护）
- 2026-11-11，用户 Windows 主机（管理员），wintun 0.14.1，HEAD 之 `test(client): Windows lifecycle test checks every planned route`。
- `TestTunHostWindowsLifecycle`：通过（网卡、IPv4/IPv6 MTU、本网卡 DNS、WFP 动态会话、全部规划路由、增量更新、换地址、Close 后网卡消失）。
- `TestTunHostWindowsNoResidueAfterKill`：通过，强杀后 0.74 秒内网卡消失。
- `TestTunHostWindowsChinaListTiming`：9887 条路由，下发 0.79 秒，拆除 2.73 秒。
- 运行后检查均为空：`Get-NetAdapter -IncludeHidden`（aerotest*）、`Get-DnsClientNrptRule`、`route print -4 | findstr 10.88`、`netsh wfp show filters` 中 “AERO DNS leak guard”。
- 未覆盖：真实流量下的 DNS 泄漏检测（待 engine 接入后做端到端测试）。

## 客户端 macOS
- 待实现（C4）。

## 服务端 edge
- 待实现（ip_forward 还原、cleanup-host、ExecStopPost）。
