# AERO Protocol

Next-generation, commercial-grade anti-censorship tunneling framework powered by native **HTTP/3**, **QUIC (RFC 9000)**, **Encrypted Client Hello (ECH)**, and **Autonomous Edge Architecture**.

---

## 架构组成 (Architecture)

- **`protocol/client/`**: 跨平台客户端核心，支持 **Windows** (Wintun + gVisor)、**macOS** (utun)、**Linux** (TUN/CLI)、**iOS** (`NEPacketTunnelProvider`) 与 **Android** (`VpnService`)。
- **`protocol/server/`**: 边缘服务端 (`aero-edge`)，具备 100% 离线自治数据面、纯 Go AES-256-GCM 加密数据库 (`edge.db`)、毫秒级本地验权、伪装站自动回落与纯正 HTTP/3 监听。
- **`protocol/proto/`**: 底层 Protobuf 消息契约与分帧定义。
- **`api/`**: OpenAPI 3.1 REST API 与订阅契约规范。

---

## 核心特性 (Key Features)

1. **纯正空中协议**：基于原生 HTTP/3、QUIC 与 ECH 隐匿，彻底消灭明文 SNI 泄露与 TLS 握手特征。
2. **APNIC 智能分流**：内置 APNIC 大陆 3,900 条聚合网段，二分查找耗时仅 10.48ns，国内服务 100% 物理网卡直连，打满本地带宽。
3. **加密 DoH 与防污染**：RFC 8484 标准 DoH (`https://223.5.5.5/dns-query`) + 60s 内存 TTL 缓存，Fake-IP 双栈即时响应。
4. **连接自愈韧性**：5 级指数退避自动重连 (150ms ~ 3s) 与真 0-RTT Session Ticket 握手复用，消灭瞬时网络抖动 502。
5. **零系统环境破坏**：全量网络捕获收敛于 L3 TUN 与 L4 gVisor 用户态协议栈，严禁篡改 Windows 注册表与注入系统代理环境变量。
6. **标准化 443 订阅**：严格遵循端口纯净契约，全站统一标准 443 HTTPS 域名分发。

---

## 快速构建与部署 (Build & Deployment)

### 1. 服务端部署 (Linux VPS)
```bash
# 1. 克隆官方公开源并就地构建
git clone --depth 1 https://github.com/jackybig999/aero.git /tmp/aero-git
cd /tmp/aero-git/protocol/server/vps
go build -v -o /usr/local/bin/aero-edge .
chmod 755 /usr/local/bin/aero-edge
rm -rf /tmp/aero-git

# 2. 启动服务 (以 443 端口为例)
/usr/local/bin/aero-edge -listen :443 -domain your-domain.com -token your-token -admin-key your-key -autocert your-domain.com -data-dir /var/lib/aero
```

### 2. 客户端构建 (Client Builds)

#### Windows
```powershell
# 编译图形化托盘客户端
go build -ldflags "-s -w" -o dist/win/aero-client.exe ./protocol/client/win

# 编译命令行客户端
go build -ldflags "-s -w" -o dist/win/aero-cli.exe ./protocol/client/cli
```

#### macOS (Apple Silicon / Intel)
```bash
# 编译 Apple Silicon 原生命令行程序
GOOS=darwin GOARCH=arm64 go build -ldflags "-s -w" -o dist/mac/aero-cli ./protocol/client/cli

# 运行 (需 sudo 调起 utun 虚拟网卡)
sudo ./dist/mac/aero-cli --sub https://your-domain.com/sub/superadmin
```

#### Linux
```bash
GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o dist/linux/aero-cli ./protocol/client/cli
sudo ./dist/linux/aero-cli --sub https://your-domain.com/sub/superadmin
```

#### Mobile (iOS / Android)
移动端核心逻辑位于 `protocol/client/mobile`：
- **Android**: `gomobile bind -target=android -androidapi=24 -o aero-mobile.aar ./protocol/client/mobile`
- **iOS**: `gomobile bind -target=ios -o AeroMobile.xcframework ./protocol/client/mobile`

---

## 许可证 (License)

Apache-2.0 License.
