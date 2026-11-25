# AERO 对 quic-go 的 fork

- 上游：`github.com/quic-go/quic-go` **v0.63.0**（MIT，版权 Marten Seemann；`LICENSE` 保持不变）
- 上游模块校验（主模块 go.sum 原值）见主模块 `go.sum` 中 `github.com/quic-go/quic-go v0.63.0` 两行
- 引入方式：主模块 `go.mod` 里 `replace github.com/quic-go/quic-go => ./third_party/quic-go`
- 授权：本目录保持上游的 MIT 许可，不改为 AGPL（ADR-0018、`LICENSING.md`）。新增或修改的文件在头部或本文件注明。
- 裁剪：去掉了上游的 `integrationtests/`、`interop/`、`assets/`、`example/`、`docs/`（体积与依赖，运行时代码与单元测试保持完整）。

## 为什么要 fork
上游的拥塞控制只有 CUBIC（`internal/congestion`），没有对外的替换接口。CUBIC 把每一次丢包都当作链路拥塞并降低发送窗口，
在往返约 190ms、随机丢包 ≥0.1% 的跨境链路上，吞吐只有 1~5 Mbit/s（本地 netem 复现：无损 156 Mbit/s，
每方向 0.1% 丢包 3~5 Mbit/s，0.5% 丢包 1.9 Mbit/s；让发送方忽略随机丢包后同一链路 97~128 Mbit/s）。
IP 数据报（DATAGRAM 帧）同样受它约束，所以经 TUN 与经 SOCKS（QUIC 流）一样慢。详见 ADR-0019。

## 相对上游的全部改动
上游实际使用的是 **NewReno**（`sent_packet_handler.go` 里 `NewCubicSender(..., true /* use Reno */, ...)`），不是 CUBIC：丢包乘 0.7，拥塞避免期每个往返只加一个包。

| 文件 | 性质 | 内容 |
|---|---|---|
| `internal/congestion/loss_tolerant.go` | 新增 | “lossy” 发送方的常量与判定：`lossStats`（最近 128 个包结果的衰减丢包率，样本不足按 32 计）、`rttInflated`（平滑 RTT 超过最小 RTT 加 `max(minRTT/4, 25ms)`）；阈值 `lossTolerantRatio = 5%` |
| `internal/congestion/cubic_sender.go` | 修改 | `cubicSender` 增加 `lossTolerant`、`outcomes`；新增 `NewLossTolerantSender`（CUBIC 增长曲线）；`OnPacketAcked` 统计确认；`OnCongestionEvent` 统计丢失，并在“丢包率低且没有排队”时直接返回（不降窗口、不进入恢复） |
| `internal/ackhandler/sent_packet_handler.go` | 修改 | 新增 `NewSentPacketHandlerWithCongestionControl` 与 `newSendAlgorithm`；`NewSentPacketHandler` 签名不变（上游测试无需改）；连接迁移后重建拥塞控制时沿用所选发送方 |
| `connection.go` | 修改 | 两处创建 `SentPacketHandler` 的位置改用新构造函数，按 `Config.CongestionControl == "lossy"` 选择 |
| `interface.go`、`config.go` | 修改 | `Config.CongestionControl string`（`""`/`"cubic"` 为上游行为，`"lossy"` 为新行为，未知值按 `"cubic"`）；`populateConfig` 拷贝该字段 |
| `config_test.go` | 修改 | `configWithNonZeroNonFunctionFields` 给新字段赋非零值（Clone 往返测试） |
| `internal/congestion/loss_tolerant_test.go` | 新增 | 随机丢包不降窗口（对照上游行为窗口被压低）、RTT 膨胀时降窗口、高丢包率时降窗口、默认关闭时与上游一致、构造函数用 CUBIC 增长曲线 |

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
