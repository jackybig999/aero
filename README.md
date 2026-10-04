# AERO Protocol

Next-generation, commercial-grade anti-censorship tunneling framework powered by native **HTTP/3**, **QUIC (RFC 9000)**, and **Autonomous Edge Architecture**.

---

## 架构组成 (Unified Flat Architecture)

- **`cmd/client/`**: 跨平台客户端薄入口，内置嵌入式 Web UI 控制台 (`127.0.0.1:19877`)。
- **`cmd/guard/`**: Windows 守卫守护进程，监控主进程 PID 并在退出时清理路由。
- **`cmd/edge/`**: 边缘服务端 (`aero-edge`) 独立入口，提供真源站伪装、HTTP/3 探活与标准 MASQUE / CONNECT-IP 代理。
- **`internal/client/`**: 客户端核心数据面，基于纯 HTTP/3 会话与 MASQUE / CONNECT-IP 协议栈，内置两级 DNS 漏斗、APNIC 国内分流与 ICMP Type 3 Code 4 反压。
- **`internal/edge/`**: 边缘服务端核心，支持连接级 Token 绑定、用户态 NAT 路由、TCP/UDP 流控隔离与多租户配额。
- **`deploy/`**: 边缘一键自动化部署脚本 (`edge-install.sh`) 与生产配置资产。

---

## 核心特性 (Key Features)

1. **纯正空中协议**：基于原生 HTTP/3 与 QUIC 承载，消灭明文 SNI 泄露与非标准 TLS 握手特征。
2. **两级 DNS 漏斗**：`.cn` 域名直连物理 DNS 剥离 AAAA；非 `.cn` 全量通过隧道短流由边缘节点解析，建连前 Fake-IP (198.18.0.0/15) 隔离。
3. **APNIC 智能分流**：内置 APNIC 大陆 3,900+ 聚合网段二分查找，国内流量 100% 物理网卡直连。
4. **MTU 自适应与 ICMP 反压**：初始 MTU 1224，栈入口 IPv4 DF 检测超限包并在栈内回写 ICMP Fragmentation Needed (Type 3 Code 4)；捕获 `DatagramTooLargeError` 动态同步网卡 MTU。
5. **容量防雪崩流控**：TCP 业务流进入 `ConnLimiter.TryAcquire` 限额门禁；短流 DNS 与 UDP Context 豁免连接槽，单 Token 最多 64 个 UDP Context 并扣减带宽。
6. **零系统环境破坏**：全量网络捕获收敛于 L3 TUN 与 L4 gVisor 用户态协议栈，严禁篡改系统代理与注册表。
7. **HTTP/2 回退与降级防御 (P4)**：TUN 模式下若 UDP/443 (QUIC) 拨号失败，禁止将整机流量降级走 TCP 伪装隧道，立即阻断全局 TUN 驱动（不打开虚拟网卡、不安装 `/1` 路由），向客户端返回 `UDP_UNAVAILABLE` 状态，仅保留本地 55555 代理端口监听。
8. **移动端通道抽象与契约 (P5)**：Android/iOS 仅依赖标准 `StartTunnel(fd int)` 与 `CopyTunnel` 双向流转，描述符严格由系统层 `VpnService` 或 `NEPacketTunnelProvider` 创建，排除路由仅放节点公网 IP，不篡改主机路由表。
9. **跳间凭证与 ECH 真实协商 (阶段四规范)**：支持 `single`、`ingress`、`egress` 拓扑角色，跳间凭证与用户 Token 严格隔离；ECH 采用订阅驱动解耦公网 HTTPS RR，防审查抗封锁全面硬化。

---

## ECH 真实协商与抗封锁规范 (阶段四规范落地)

### 1. 边缘节点拓扑角色与跳间凭证
- **Role 字段**：只接受 `single`（默认单机）、`ingress`（多跳入口）、`egress`（多跳出口）。
- **HopCredential 凭证**：当 Role 为 `ingress` 或 `egress` 时强制要求配置跳间凭证；若为空启动直接失败（报错 `hop credential required`）。跳间凭证是节点内部集群专用密钥，与用户 Token 绝非同一个值。

### 2. ECH（Encrypted Client Hello）订阅驱动机制与解耦
- **订阅驱动模式**：服务端 ECH 公钥配置发布进节点订阅 JSON，客户端解析读取后写入 `EncryptedClientHelloConfigList`。
- **解耦公网 HTTPS RR**：服务端 ECH 激活不再强依赖公网 DNS 的 HTTPS RR（Type 65 / RFC 9460）记录。只要 Go 工具链版本满足（Go 1.26.0+ 原生 ECH 支持）且配置了有效的 `EncryptedClientHelloKeys`，服务端即开启 ECH（日志输出 `[EDGE] ECH enabled for domain ...`）。
- **标准 TLS 1.3 回退**：未配置 ECH 时，严格保持标准 TLS 1.3 握手，并在启动日志中明确输出 `[EDGE] ECH disabled`。严禁填充虚假 ECH 配置或伪造 GREASE 特征。

### 3. 外层 SNI 与双层流量安全边界
- **外层 SNI（Public Name）可见性**：在网络监听与 DPI 视角下，QUIC / TLS 外层 SNI 仍然可见。
- **安全隔离事实**：AERO 协议客户端外层 SNI 严格为**边缘节点/网关域名**，绝非用户实际访问的目标网站域名。
- **内层加密保护**：用户实际访问的目标域名与业务载荷 100% 运行在内层 HTTP/3 MASQUE / CONNECT-IP 加密隧道中，受到端到端完全保护。

### 4. 抗封锁与网络抗审查规范 (Anti-Censorship Guardrails)
- **ClientHello Scrambling（切开 SNI）**：`quic-go` 协议栈默认开启 ClientHello Scrambling，将 SNI 扩展切分到多个加密包/帧中以挫败特征匹配。**生产环境严禁设置环境变量 `QUIC_GO_DISABLE_CLIENTHELLO_SCRAMBLING`**。
- **DPLPMTUD 规范遵循 (`InitialPacketSize == 0`)**：保持 RFC 8899 与 RFC 9000 规范标准，`InitialPacketSize` 保持默认值 0，交由协议栈协商自适应，**严禁人为注入不可控的固定或随机填充指纹**，防止成为审查系统的特定识别标志。

---

## 快速构建与部署 (Build & Deployment)

### 1. 服务端部署 (Linux VPS)
```bash
# 1. 一键安装命令 (单节点标准部署)
curl -fsSL https://raw.githubusercontent.com/jackybig999/aero/main/deploy/edge-install.sh | bash -s -- -d edge.your-domain.com

# 2. 多跳角色部署配置示例 (aero-edge.json)
# 入口节点 (ingress):
# { "role": "ingress", "hop_credential": "YOUR_SECRET_HOP_KEY", ... }
# 出口节点 (egress):
# { "role": "egress", "hop_credential": "YOUR_SECRET_HOP_KEY", ... }

# 3. 源码编译
go build -v -ldflags="-s -w" -o aero-edge ./cmd/edge
```

### 2. 客户端构建 (Client Builds)

#### Windows
```powershell
go build -ldflags "-s -w" -o aero-client.exe ./cmd/client
go build -ldflags "-s -w" -o aero-guard.exe ./cmd/guard
```

#### Linux
```bash
GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o aero-client ./cmd/client
```

#### macOS
```bash
GOOS=darwin GOARCH=arm64 go build -ldflags "-s -w" -o aero-client-arm64 ./cmd/client
GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w" -o aero-client-amd64 ./cmd/client
```

---

## 许可证 (License)

Apache-2.0 License.

