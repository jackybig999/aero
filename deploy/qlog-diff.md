# AERO 与 Chrome 协议参数对照表 (qlog-diff)

本对照表记录 AERO 协议栈（基于 quic-go v0.59.1）与标准浏览器客户端（Chrome / QUICHE）在真实 QUIC 传输参数（RFC 9000）与 HTTP/3 SETTINGS（RFC 9114）层面的配置差异。

---

## 1. QUIC 传输参数 (QUIC Transport Parameters)

| 参数 | Chrome | AERO | 是否相同 |
| :--- | :--- | :--- | :--- |
| `original_destination_connection_id` | 仅服务端返回（匹配客户端 Initial DCID） | 仅服务端返回（匹配客户端 Initial DCID） | 相同 |
| `max_idle_timeout` | 30000 ms (30s) | 30000 ms (30s) | 相同 |
| `stateless_reset_token` | 服务端下发 16 字节随机令牌 | 服务端下发 16 字节随机令牌 | 相同 |
| `max_udp_payload_size` | 1350 / 1472 字节 (IPv6/IPv4 自适应) | 1200 / 1224 字节 (对齐 AERO Next-MTU 1224 紧凑帧) | 否 |
| `initial_max_data` | 15,728,640 字节 (15 MB) | 67,108,864 字节 (64 MB，高性能大窗口) | 否 |
| `initial_max_stream_data_bidi_local` | 6,291,456 字节 (6 MB) | 16,777,216 字节 (16 MB 单流初始窗口) | 否 |
| `initial_max_stream_data_bidi_remote` | 6,291,456 字节 (6 MB) | 16,777,216 字节 (16 MB) | 否 |
| `initial_max_stream_data_uni` | 6,291,456 字节 (6 MB) | 16,777,216 字节 (16 MB) | 否 |
| `initial_max_streams_bidi` | 100 (默认并发双向流上限) | 1000 (高并发多路复用隧道) | 否 |
| `initial_max_streams_uni` | 100 (单向控制/推流上限) | 1000 (控制流与单向通知) | 否 |
| `ack_delay_exponent` | 3 (RFC 9000 默认基准) | 3 (RFC 9000 默认基准) | 相同 |
| `max_ack_delay` | 25 ms (RFC 9000 默认基准) | 25 ms (RFC 9000 默认基准) | 相同 |
| `disable_active_migration` | false (不禁用，支持连接迁移) | false (不禁用，支持移动端/客户端平滑漫游) | 相同 |
| `active_connection_id_limit` | 4 (RFC 9000 默认下发上限) | 4 (quic-go 默认活跃 CID 上限) | 相同 |
| `initial_source_connection_id` | 随机生成 8 字节 CID | 随机生成 8 字节 CID | 相同 |
| `retry_source_connection_id` | 未触发 Retry 时不发送 | 未触发 Retry 时不发送 | 相同 |
| `max_datagram_frame_size` | 65535 (RFC 9221 Datagram 扩展支持) | 65535 (EnableDatagrams 开启) | 相同 |
| `grease_quic_bit` | true (RFC 9287，防中间件僵化) | true (quic-go 默认启用) | 相同 |
| `version_information` | 支持 draft-ietf-quic-version-negotiation | 支持 RFC 9000 v1 / Version 1 | 否 |
| `min_ack_delay` | 支持 draft-ietf-quic-ack-frequency (可选) | 未启用 AckFrequency 扩展 | 否 |

---

## 2. HTTP/3 设置参数 (HTTP/3 SETTINGS)

| 参数 | Chrome | AERO | 是否相同 |
| :--- | :--- | :--- | :--- |
| `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (0x01) | 0 或 4096 (动态表容量) | 0 (仅使用 QPACK 静态表，零内存放大) | 否 |
| `SETTINGS_MAX_FIELD_SECTION_SIZE` (0x06) | 65536 字节 (64 KB 头部上限) | 10,485,760 字节 (10 MB 安全边界) | 否 |
| `SETTINGS_QPACK_BLOCKED_STREAMS` (0x07) | 0 或 100 (阻塞流配额) | 0 (静态表无需等待动态表解码流) | 否 |
| `SETTINGS_ENABLE_CONNECT_PROTOCOL` (0x08) | 1 (RFC 9220 Extended CONNECT 启用) | 0 (P1 阶段尚未挂载 Extended CONNECT 处理器) | 否 |
| `SETTINGS_H3_DATAGRAM` (0x33) | 1 (RFC 9297 HTTP Datagram 启用) | 1 (数据报通道开启) | 相同 |
| `SETTINGS_ENABLE_WEBTRANSPORT` (0x2b603742) | 1 (WebTransport 扩展协商) | 0 (未启用 WebTransport) | 否 |
| `GREASE Settings` (0x1f * N + 0x21) | 随机注入 GREASE ID 与随机值 | 未启用 HTTP/3 SETTINGS GREASE | 否 |

---

## 3. 差异分析与演进规划

1. **窗口与流上限**：AERO 采用更大的初始窗口与流并发限制（64MB 连接窗口、16MB 单流窗口、1000 并发流），旨在保证隧道多路复用下的极高吞吐量与低延迟，避免频繁等待窗口更新帧。
2. **MTU 与数据报边界**：AERO 严格对齐虚拟网卡 MTU 1224（Payload 1200），通过 gVisor DF 检查与 ICMP 反压实现精准防分片；Chrome 倾向使用标准以太网 1350~1472 字节。
3. **Extended CONNECT 与 MASQUE**：P1 阶段保持经典隧道私有帧协议，`SETTINGS_ENABLE_CONNECT_PROTOCOL` 尚未接管流量。将在后续 P2/P3 阶段对接标准 RFC 9298 MASQUE CONNECT-IP 架构并对齐该参数。
4. **qlog 观测开关**：边缘节点在生产环境中默认关闭 qlog 降低 CPU 与磁盘 IO 开销；当配置环境变量 `AERO_QLOG_DIR` 时，自动装载标准 `qlog.DefaultConnectionTracer` 生成 `.sqlog` 跟踪事件用于协议深度调优与取证。
