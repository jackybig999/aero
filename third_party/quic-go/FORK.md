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
（第 1 步只引入分叉，没有任何改动；后续步骤在此表登记。）

| 文件 | 性质 | 内容 |
|---|---|---|

## 运行测试
fork 目录有自己的 `go.mod`，主模块的 `go test ./...` 不会包含它；CI 另有一步运行下面的命令（只跑被改动的包与编译检查，上游全量测试体积大且部分依赖不在离线缓存里）：
```bash
cd third_party/quic-go
go vet ./...
go test -race -shuffle=on ./internal/congestion/...
```

## 升级上游时
1. 对比上游新版本与 v0.63.0 在上表所列文件的差异，重放表中的改动。
2. 运行上面的测试与主模块全量门禁（含 `tests/e2e` 的 netem 吞吐矩阵）。
3. 更新本文件的“上游”行。
