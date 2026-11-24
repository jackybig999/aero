# AI 稳定通道真机验证清单（ADR-0017）

**为什么需要它**：本仓库的自动化测试在没有 `/dev/net/tun` 的环境里无法覆盖“真实服务端 + 真实 TUN”这一段。
下面是在一台真实服务器和一台真实客户端上做的人工验证，每项给出步骤和预期结果。

已经由自动化测试覆盖的部分（不需要再手工验）：会话协商与传输方式核对、源地址改写与校验和、分类、复用层隔离、
引擎状态机与重拨、服务端按类别建会话与授权、真实 HTTP/3 上两条会话各自往返。
**只有真机能验证**：服务端 TUN 与 NAT 对两个子网的实际转发、客户端真实 TUN 上的 AI 连接、真实 AI 站点。

## 前置条件
- 服务端和客户端都是含 ADR-0017 P1–P3 的版本。本清单在新版本发布之前不能用 `aero update` 完成，需用你自己编译的程序。
- 服务端节点开启全局隧道（`aero tunnel` 显示“开启”，即 `connect_ip` 未设为 false）。
- 一台装有 `tcpdump` 的服务端（只读抓包，不改配置）。

## A. 服务端
1. `aero check`：全部 OK（含防火墙后端、`/dev/net/tun`）。
2. 取订阅文档（`aero info` 里的订阅地址）：
   `curl -s <订阅地址> | grep -o '"transports":\[[^]]*\]'`
   预期：`"transports":["datagram","capsule"]`（每个节点都有）。
3. 另开一个终端跟日志：`aero log`，下面各步观察 `[CONNECT-IP]` 行。

## B. 客户端建立
4. 客户端以 TUN 模式连接。
5. `curl -s http://127.0.0.1:19877/api/v1/status`（端口以 `-api` 参数为准）。
   预期：`"connected":true`，`"ai_channel":"up"`，`"ai_channel_reason"` 为空，`"ai_channel_enabled":true`。
6. 服务端日志预期两行（地址只是示例）：
   - `[CONNECT-IP] session up class=default transport=datagram addr=10.88.0.x … 10.88.127.x`
   - `[CONNECT-IP] session up class=ai transport=capsule addr=10.88.128.x … 10.88.255.x`
   两个地址必须一个在前半、一个在后半，且互不相同。

## C. 分流是否生效
7. 服务端抓包（只读）：
   `tcpdump -ni aero-tun0 'net 10.88.128.0/17'` 与另一个终端 `tcpdump -ni aero-tun0 'net 10.88.0.0/17'`
8. 在客户端访问一个 AI 站点，例如 `curl -sI https://api.openai.com`（返回什么状态码都可以，关键是连得上）。
   预期：后半子网（10.88.128.0/17）的抓包里出现该连接的 TCP 包；前半子网只有 DNS、UDP 等其他流量。
9. 访问一个普通站点，例如 `curl -sI https://example.org`。
   预期：只出现在前半子网（10.88.0.0/17）。
10. 客户端发 UDP（例如 `dig @1.1.1.1 example.org` 经隧道，或任意 UDP 应用）。
    预期：只出现在前半子网。**UDP 绝不应出现在后半子网**。

## D. 故障演练
11. 在服务端执行 `aero restart`。
    预期：客户端自动重连，`ai_channel` 经历 `connecting`（可能很短）后回到 `up`，不需要任何手工操作；
    日志里 default 与 ai 会话都先 `down` 再 `up`，ai 会话尽量拿回原来的地址（租约）。
12. 在客户端把网络切换一次（例如关掉再打开 Wi-Fi）。预期同上。
13. 断开客户端。预期：服务端两条会话都有 `session down` 日志；客户端 `aero0` 网卡和路由消失（沿用原有残留检查）。

## E. 旧节点兼容（可选，需要一个旧版本服务端）
14. 客户端连接不声明 `transports` 的旧节点。
    预期：`"ai_channel":"unsupported"`，客户端工作方式与升级前完全一致（AI 流量走原来的会话，不报错）。

## 出现问题时请提供
- `aero log | grep CONNECT-IP` 的相关行；
- 客户端 `/api/v1/status` 的完整输出；
- 客户端日志文件 `client.log`（在客户端数据目录）；
- 第 7 步的抓包片段（可以只保留前几行）。

## 回滚
`aero update <旧版本>`；客户端换回旧版本。本改动不修改服务器的系统配置，也没有新增宿主修改。

## 已知限制（不是缺陷）
- 目前没有界面或接口开关，AI 稳定通道默认开启（P7 提供开关）。
- 用户关闭通道时，已建立在 ai 会话上的连接会中断（源地址改变），这是显式操作。
- 数据泵重启（重连）后第一个包可能丢失，TCP 会重传。
