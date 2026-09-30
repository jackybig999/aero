# AERO Protocol

Next-generation, commercial-grade anti-censorship tunneling framework powered by native **HTTP/3**, **QUIC (RFC 9000)**, **Encrypted Client Hello (ECH)**, and **Autonomous Edge Architecture**.

---

## 架构组成 (Unified Flat Architecture)

- **`cmd/client/`**: 跨平台客户端薄入口，内置嵌入式 Web UI 控制台 (`127.0.0.1:19877`)。
- **`cmd/guard/`**: Windows 守卫守护进程，监控主进程 PID 并在退出时清理路由。
- **`cmd/edge/`**: 边缘服务端 (`aero-edge`) 独立入口，毫秒级本地验权、短流 DNS 与单连接数据报分发。
- **`cmd/panel/`**: 边缘管理面板 (`aero-panel`)，8090 端口轻量可视化运维控制台。
- **`internal/client/`**: 客户端核心数据面，支持 Windows (Wintun + gVisor)、macOS (utun)、Linux (TUN)，内置两级 DNS 漏斗、APNIC 国内分流与 ICMP Type 3 Code 4 反压。
- **`internal/edge/`**: 边缘服务端核心，支持连接级 Token 绑定、TCP/UDP 流控隔离与多租户配额。
- **`internal/proto/`**: 底层 Protobuf 消息契约与纯二进制数据报定义。
- **`deploy/`**: 边缘一键自动化部署脚本 (`edge-install.sh`) 与生产配置资产。

---

## 核心特性 (Key Features)

1. **纯正空中协议**：基于原生 HTTP/3、QUIC 与 ECH 隐匿，消灭明文 SNI 泄露与 TLS 握手特征。
2. **两级 DNS 漏斗**：`.cn` 域名直连物理 DNS 剥离 AAAA；非 `.cn` 全量通过隧道短流由边缘节点解析，建连前 Fake-IP (198.18.0.0/15) 隔离。
3. **APNIC 智能分流**：内置 APNIC 大陆 3,900+ 聚合网段二分查找，国内流量 100% 物理网卡直连。
4. **MTU 自适应与 ICMP 反压**：初始 MTU 1224，栈入口 IPv4 DF 检测超限包并在栈内回写 ICMP Fragmentation Needed (Type 3 Code 4)；捕获 `DatagramTooLargeError` 动态同步网卡 MTU。
5. **容量防雪崩流控**：TCP 业务流进入 `ConnLimiter.TryAcquire` 限额门禁；短流 DNS 与 UDP Context 豁免连接槽，单 Token 最多 64 个 UDP Context 并扣减带宽。
6. **零系统环境破坏**：全量网络捕获收敛于 L3 TUN 与 L4 gVisor 用户态协议栈，严禁篡改系统代理与注册表。

---

## 快速构建与部署 (Build & Deployment)

### 1. 服务端部署 (Linux VPS)
```bash
# 1. 一键安装命令 (推荐)
curl -fsSL https://raw.githubusercontent.com/jackybig999/aero/main/deploy/edge-install.sh | bash -s -- -d edge.your-domain.com

# 2. 或源码直接编译
go build -v -ldflags="-s -w" -o aero-edge ./cmd/edge
go build -v -ldflags="-s -w" -o aero-panel ./cmd/panel
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
