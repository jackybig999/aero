# AERO Edge Server v1.1.0

> Independent tunnel protocol **server** (not a multi-protocol panel).  
> Repository: https://github.com/jackybig999/aero

中文说明 → **[README.zh-CN.md](./README.zh-CN.md)** · English → **[README.en.md](./README.en.md)**

| | |
|--|--|
| Version | **1.1.0** |
| Protocol | `aero/2.0` (TLS 1.3 + HTTP/2 CONNECT) |
| API level | **1** (ops contract) |
| Layout | `aero-edge/` · `proto/` · `docs/` · `deploy/` |
| Listen default | **:443** |
| Cert | Let's Encrypt → ZeroSSL backup · **no self-sign** · auto-renew |

## Quick start

```bash
# 一键安装（有域名；自动 ACME + systemd）
sudo bash deploy/install.sh -d edge.example.com -b ./aero-edge

# 或本机编译后指定二进制
cd aero-edge && go build -o aero-edge ./cmd/aero-edge
sudo bash ../deploy/install.sh -d edge.example.com -b ./aero-edge
```

```bash
# cross-compile release binary for linux/amd64
cd aero-edge
set GOOS=linux
set GOARCH=amd64
go build -o aero-edge-linux-amd64 ./cmd/aero-edge
```

## Client

Local mixed proxy default **127.0.0.1:55555** (HTTP + SOCKS5). Do not rely on OS system proxy.

```bash
aero-ech -sub https://edge.example.com/sub/<secret> -listen 127.0.0.1:55555
```

## For subscription platforms

- Pull **Release** assets from this repo (`jackybig999/aero` tag `v1.1.0`), do **not** vendor into billing code.
- Ops contract: [docs/edge-server-v1.md](./docs/edge-server-v1.md)
- Install notes: [deploy/RELEASE.md](./deploy/RELEASE.md)

## License

Apache License 2.0
