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
- 2026-11-11 线上节点（Debian，x86_64，edge 1.3.1，sha256 7bf93be6…05ad）：
  - 升级时旧进程退出日志 “Firewall rules added by this process were removed”，新进程规则全部带 `aero_edge_default` 标签且限定 `aero-tun0`/地址池（FORWARD MSS 2 条、filter 2 条、nat MASQUERADE 1 条），无重复叠加。
  - 端口轮试：UDP 8443 被同机 xray 占用，edge 自动跳过，其余 8 个端口正常。
  - 闭环（tmp/e2e，进程内，不建网卡）：QUIC 握手 746ms；TCP 中继出口 207.57.187.35；DoH 解析 www.google.com 正常；CONNECT-IP 分配 10.88.36.254/32，ICMP 1.1.1.1 往返 227ms，UDP DNS 8.8.8.8 往返 226ms。
  - `/sub/admin` 返回 404（匿名泄露已关闭）。
- 2026-11-11 回滚机制（隔离网络命名空间，真实 iptables 与 ip_forward）：`TestHostStateLifecycleForwardingOff/On`、`TestHostStateRemovesLegacyRules`、`TestCleanupHostRefusesWhileRunning` 通过；`aero-edge cleanup-host` 命令行在模拟崩溃现场（ip_forward=1、3 条标记规则、日志原值 0）执行后：ip_forward=0、标记规则 0、外来规则保留、日志删除，二次执行幂等。宿主 ip_forward 全程未变。
- 线上待部署：需发布新版本并在服务单元加入 `ExecStopPost=/usr/local/bin/aero-edge cleanup-host`。
