# ADR-0014 允许“随进程或自有网卡自动消失”的宿主状态

状态：accepted（2026-11-11，用户决定）
关系：修订 ADR-0012（“禁止防火墙规则”）与 ADR-0013（“不修改任何 DNS 设置”）。

## 背景
仅把系统 DNS 服务器路由进 TUN 拦不住 DNS 泄漏：Windows 强主机模型下 DNS 客户端按网卡分别发查询，源地址是物理网卡地址，不走 TUN 路由；macOS 解析器按网卡限定作用域；Linux systemd-resolved 把查询 socket 绑定到网卡。旧实现用 NRPT、改系统 DNS 解决，但这些是持久状态，崩溃后残留并导致宿主断网。

## 决定
宿主状态分两类：
1. **允许**：操作系统在本进程退出（含崩溃、被强杀）或自有网卡销毁时**自动删除**、且不写持久存储的状态。
   - 全平台：自有 TUN 网卡及其地址、路由、MTU。
   - 自有网卡自身的 DNS 服务器设置（Windows 记录在本网卡固定 GUID 名下，正常退出时清空；崩溃后仅留下与已不存在的网卡关联、无作用的条目，下次运行覆盖）。
   - Windows：WFP **动态会话**（`FWPM_SESSION_FLAG_DYNAMIC`）中的过滤规则，会话句柄关闭或进程终止时由内核删除。
   - macOS：SCDynamicStore **会话键**（`kSCDynamicStoreUseSessionKeys`），会话结束即删除。
   - Linux：systemd-resolved 中挂在自有网卡上的链路级 DNS 配置，网卡消失即删除。
2. **禁止**：任何持久或系统级状态——NRPT、注册表（上条所述除外）、netsh persistent 存储、系统或其他网卡的 DNS 设置、`/etc` 下文件、`networksetup`、pf/iptables 等持久防火墙规则、物理网卡上的路由。

## DNS 防泄漏实现
- Windows：本网卡 DNS = 隧道虚拟网关；WFP 动态会话：放行本进程、放行出接口为本网卡的流量、屏蔽其余发往 53 端口的 UDP/TCP。
- macOS：SCDynamicStore 会话键发布本服务 DNS（待实现）。
- Linux：`resolvectl` 只对 aero0 设置 DNS 与 `~.` 路由域；无 resolved 时系统直接按路由发查询，TUN 路由已能捕获。

## 后果
- 运行时 DNS 不泄漏；崩溃或强杀后上述状态由系统自动清除，宿主网络回到原状。
- 每个平台附一次“强杀后残留检查”实测记录。
