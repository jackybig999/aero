# AERO 对 quic-go 的 fork

- 上游：`github.com/quic-go/quic-go` **v0.63.0**（MIT，版权 Marten Seemann；`LICENSE` 保持不变）
- 上游模块校验（主模块 go.sum 原值）见主模块 `go.sum` 中 `github.com/quic-go/quic-go v0.63.0` 两行
- 引入方式：主模块 `go.mod` 里 `replace github.com/quic-go/quic-go => ./third_party/quic-go`
- 授权：本目录保持上游的 MIT 许可，不改为 AGPL（ADR-0018、`LICENSING.md`）。新增或修改的文件在头部或本文件注明。
- 裁剪：去掉了上游的 `integrationtests/`、`interop/`、`assets/`、`example/`、`docs/`（体积与依赖，运行时代码与单元测试保持完整）。

## 为什么要 fork
上游的拥塞控制只有一种基于丢包的实现（`internal/congestion`，实际是 NewReno，见下），没有对外的替换接口。它把每一次丢包都当作链路拥塞并降低发送窗口，
在往返约 190ms、随机丢包 ≥0.1% 的跨境链路上，吞吐只有 1~5 Mbit/s（本地 netem 复现：无损 156 Mbit/s，
每方向 0.1% 丢包 3~5 Mbit/s，0.5% 丢包 1.9 Mbit/s；让发送方忽略随机丢包后同一链路 97~128 Mbit/s）。
IP 数据报（DATAGRAM 帧）同样受它约束，所以经 TUN 与经 SOCKS（QUIC 流）一样慢。详见 ADR-0019。

## 相对上游的全部改动
上游实际使用的是 **NewReno**（`sent_packet_handler.go` 里 `NewCubicSender(..., true /* use Reno */, ...)`），不是 CUBIC：丢包乘 0.7，拥塞避免期每个往返只加一个包。

| 文件 | 性质 | 内容 |
|---|---|---|
| `internal/congestion/loss_tolerant.go` | 新增 | “lossy” 发送方的常量与判定：`lossStats`（最近 128 个包结果的衰减丢包率，样本不足按 32 计）、`rttInflated`（平滑 RTT 超过最小 RTT 加 `max(minRTT/8, 10ms)`）；分级阈值：丢包率 `< 10%`（`lossTolerantRatio`）且没有排队不降窗口，`10%~25%`（`lossHardRatio`）只轻降 ×0.85（`lossMildCutFactor`），更高或在排队按原行为降窗口 |
| `internal/congestion/cubic_sender.go` | 修改 | `cubicSender` 增加 `lossTolerant`、`outcomes`、`largestSentAtMildCut`；新增 `NewLossTolerantSender`（CUBIC 增长曲线）；`OnPacketAcked` 统计确认；`OnCongestionEvent` 统计丢失，并在没有排队时按丢包率分级响应（不降 / 轻降 / 原行为）。轻降只在同一批丢失里做一次（`largestSentAtMildCut`，与原行为的 `largestSentAtLastCutback` 分开记），同一批里丢包率升到 `lossHardRatio` 以上会升级为原行为的降窗。`lostBytes == 0` 的事件是 ECN-CE（`sent_packet_handler.go` 里 `OnCongestionEvent(largestAcked, 0, …)`），始终按原行为处理，不计入丢包统计 |
| `internal/congestion/cubic.go` | 修改 | 新增 `CongestionWindowAfterMildLoss(cwnd, factor)`：与 `CongestionWindowAfterPacketLoss` 共用 `windowAfterLoss`，同样更新 `lastMaxCongestionWindow` 并重置 `epoch`，只是降幅可调。没有这一步时轻降一个往返后窗口就回到降之前的值 |
| `internal/ackhandler/sent_packet_handler.go` | 修改 | 新增 `NewSentPacketHandlerWithCongestionControl` 与 `newSendAlgorithm`；`NewSentPacketHandler` 签名不变（上游测试无需改）；连接迁移后重建拥塞控制时沿用所选发送方 |
| `connection.go` | 修改 | 两处创建 `SentPacketHandler` 的位置改用新构造函数，按 `Config.CongestionControl == "lossy"` 选择 |
| `interface.go`、`config.go` | 修改 | `Config.CongestionControl string`（`""`/`"cubic"` 为上游行为，`"lossy"` 为新行为，未知值按 `"cubic"`）；`populateConfig` 拷贝该字段 |
| `config_test.go` | 修改 | `configWithNonZeroNonFunctionFields` 给新字段赋非零值（Clone 往返测试） |
| `internal/congestion/loss_tolerant_test.go` | 新增 | 随机丢包不降窗口（对照上游行为窗口被压低）、RTT 膨胀时降窗口、高丢包率时按原行为降窗口、轻降的具体幅度与“一个往返后不弹回”、同批严重丢包升级为原行为降窗、ECN 始终降窗、默认关闭时与上游一致、构造函数用 CUBIC 增长曲线 |

## 运行测试
fork 目录有自己的 `go.mod`，主模块的 `go test ./...` 不会包含它；CI 另有一步运行下面的命令（只跑被改动的包与编译检查，上游全量测试体积大且部分依赖不在离线缓存里）：
```bash
cd third_party/quic-go
go vet ./...
go test -race -shuffle=on ./internal/congestion/... ./internal/ackhandler/...
```

## 升级上游时
1. 对比上游新版本与 v0.63.0 在上表所列文件的差异，重放表中的改动。
2. 运行上面的测试与主模块全量门禁（含 `tests/e2e` 的 netem 吞吐矩阵）。
3. 更新本文件的“上游”行。

## 已知限制
- quic-go 本身不会调用 `OnRetransmissionTimeout`（持续拥塞处理在上游和本分叉里都不存在），本分叉没有改变这一点。
- **没有测与其他流共用瓶颈时的公平性**：`tests/e2e` 的瓶颈只被隧道自己占用。已测的只有单流、单配置：20 Mbit/s、30 KB 缓冲、60 MiB 传输、无随机丢包时，
  瓶颈丢包 0.38%（原行为 0.25%），吞吐 18.4 对 16.0 Mbit/s——只能说明这一配置下没有失控，**不能**推出“不会稳定在高丢包率”。
  没测到：竞争的 TCP 流、AQM（CoDel/RED）与运营商限速（丢包分散、不成突发）、浅缓冲加随机丢包、多条并发连接。
- RTT 排队信号的余量 `max(minRTT/8, 10ms)`：往返 190ms 时约 24ms，比它短的排队（浅缓冲、CoDel）不会触发，这时退让只靠丢包率阈值与瓶颈丢包的突发性；
  往返小于 80ms 或抖动大（Wi-Fi、跨境 ±30ms）时容易被判为排队而退回原行为降窗（偏保守，收益会下降）；quic-go 的最小 RTT 不过期，路由变长后会一直判为排队。
- 阈值（10%、25%、×0.85、128 个包的窗口、RTT 余量）是估算，由 `tests/e2e` 的 netem 矩阵标定，没有在真实网络上长期验证。
- 统计窗口只有 128 个包，对突发丢包敏感；真正的解决办法是用 BBR 取代本发送方（ADR-0019 方案 A）。
- 包乱序（RFC 9002 的包数量阈值为 3）会被 QUIC 当作丢包。`tc netem` 的抖动会让高速流量大量乱序，所以 `delay 95ms 15ms` 这类测试会很慢；
  真实链路上排队抖动是 FIFO，几乎不乱序，但不排除多路径造成的乱序。需要真机确认。
