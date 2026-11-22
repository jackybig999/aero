# AERO 对 connect-ip-go 的 fork

- 上游：`github.com/quic-go/connect-ip-go` **v0.4.0**（MIT，版权 Marten Seemann；`LICENSE` 保持不变）
- 上游模块校验（主模块 go.sum 原值）：`h1:m9xcVslaw9OzLQV79shdXHhKJZZhUmYQhWe6J342W3w=`
- 引入方式：主模块 `go.mod` 里 `replace github.com/quic-go/connect-ip-go => ./third_party/connect-ip-go`
- 原因与设计：ADR-0017（双传输 CONNECT-IP）。上游只能经 QUIC DATAGRAM 发送 IP 包，并把类型 0x00 的 capsule 丢弃；本项目需要 RFC 9297 §3.5 的 DATAGRAM capsule 承载（流上的可靠传输）。
- 授权：本目录保持上游的 MIT 许可，不改为 AGPL（ADR-0018、`LICENSING.md`）。新增的两个文件在头部写明了来源与许可。

## 相对上游的全部改动

| 文件 | 性质 | 内容 |
|---|---|---|
| `datamode.go` | 新增 | `DataMode`（`DataModeDatagram` 默认、`DataModeCapsule`）；`(*Proxy).ProxyWithMode`、`(*ClientConn).DialWithMode`；`(*Conn).DataMode`、`DroppedModeMismatch`；DATAGRAM capsule 的编码与拆包；队列常量 |
| `conn.go` | 修改 | `Conn` 增加 `mode` 等字段；`newProxiedConn` 改为包装 `newProxiedConnMode`；`readFromStream` 增加 DATAGRAM capsule 分支（`handleDataCapsule`）；`writeToStream` 出队后通知写端；`ReadPacket`/`WritePacket` 在 capsule 模式下走 `readPacketCapsule`/`writePacketCapsule` |
| `client.go` | 修改 | `dial` 改为包装 `dialMode`，其余不变 |
| `datamode_test.go` | 新增 | 编码、往返、反压不丢不乱序、对端关闭后已排队的包仍交付、多写者并发、Close 释放阻塞写、模式不一致丢弃、未知 Context ID、畸形 capsule 关闭连接、真实 HTTP/3 端到端（两种模式）、模糊测试 `FuzzCapsuleStream` |

默认（数据报）模式的行为与上游一致：上游自带的全部测试仍然通过。

## 行为要点
- 两端必须使用同一模式。模式不在线上协商，由应用按带外信息（请求头，ADR-0017 决定 2）决定。
- capsule 模式仍要求连接协商出 QUIC DATAGRAM，不把 capsule 当作无数据报时的降级路径（ADR-0017 决定 8）。
- capsule 模式的 `WritePacket` 在写队列满（`maxQueuedDataWrites`，32）时阻塞，形成反压；控制类 capsule 总有余量，不会因数据占满而被判“队列满”关闭连接。
- 接收端必须持续调用 `ReadPacket`；否则排在数据后面的控制 capsule 会被卡住（RFC 9297 §3.2）。同一 Conn 的 `ReadPacket` 与 `WritePacket` 必须在不同 goroutine：两端流控窗口都满时，单个 goroutine 先写后读会自己等自己。
- 应用停止读包时，接收队列满后读流协程会停住，对端的 FIN 或重置要到本端 `Close` 才会被察觉。
- 对端正常关闭流（EOF）时，已经收到并排队的包仍会由 `ReadPacket` 先返回，之后才报关闭；本端主动 `Close` 则丢弃队列里的包。
- 内存上界（每个 Conn 约 8 MiB 接收 + 2 MiB 写队列）按条数计、不按字节计；多租户的 edge 总量是连接数乘以约 10 MiB。P5 标定时改成按字节限额。
- 数据模式不一致时：数据报模式收到 DATAGRAM capsule 会丢弃并计数；capsule 模式不读取 QUIC 数据报。
- 数值（队列长度等）为估算，待 ADR-0017 P5 的丢包测量标定。

## 运行测试
```bash
cd third_party/connect-ip-go
go vet ./...
go test -race -shuffle=on ./...
go test -run='^$' -fuzz=FuzzCapsuleStream -fuzztime=60s ./...
```
fork 目录有自己的 `go.mod`，所以主模块的 `go test ./...` 不会包含它；CI 另有一步运行上面的前两条。

## 升级上游时
1. 对比上游新版本与 v0.4.0 在 `conn.go`、`client.go` 的差异，重放上表的改动。
2. 运行上面的测试与主模块全量门禁。
3. 更新本文件的“上游”与校验行。
