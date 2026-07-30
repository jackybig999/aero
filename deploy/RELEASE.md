# AERO Edge 发布与安装

## 仓库

- GitHub: https://github.com/jackybig999/aero  
- 当前发布：`v1.1.0`（旧 `v1.0.0` 已废弃并删除）

## 构建

```bash
cd aero-edge
# Linux 服务端（发布用）
GOOS=linux GOARCH=amd64 go build -o ../dist/aero-edge-linux-amd64 ./cmd/aero-edge
GOOS=linux GOARCH=arm64 go build -o ../dist/aero-edge-linux-arm64 ./cmd/aero-edge
```

## Release 附件命名（install.sh 下载约定）

```
aero-edge-linux-amd64
aero-edge-linux-arm64
```

上传到 GitHub Release 标签 `v1.1.0`。  
`install.sh` 内 `VERSION` / `REPO` 必须与仓库一致：

- `REPO=jackybig999/aero`
- `VERSION=1.1.0`

## 安装

```bash
# 推荐：本机编译后安装（不依赖 Release）
sudo bash deploy/install.sh -d edge.example.com -b ./aero-edge

# 或：从 GitHub Release 自动下载 v1.1.0 二进制
curl -fsSL https://raw.githubusercontent.com/jackybig999/aero/main/deploy/install.sh | sudo bash -s -- -d edge.example.com
```

证书策略：检测已有 PEM → 否则 acme.sh **Let's Encrypt** → 失败 **ZeroSSL** → 自动续签 → **禁止自签**。

数据目录：`/var/lib/aero`  
证书：`/var/lib/aero/tls/{fullchain,privkey}.pem`  
监听默认：**443**（`-p` 可改）

| 文件 | 说明 |
|------|------|
| `sub_meta.json` | secret + meta |
| `client-sub.json` | 客户端 `-sub` 导入 |

## 客户端

```bash
# 本机混合口默认 55555，不改系统注册表
aero-ech -sub https://edge.example.com/sub/<secret> -listen 127.0.0.1:55555
# 浏览器/软件代理填 127.0.0.1:55555（HTTP 或 SOCKS5）
```

## 注意

- 不监听未完成的 QUIC 数据面
- 有域名时必须能走 HTTP-01（:80）或事先放好 PEM
