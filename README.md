# AERO Edge Server v1.0.0

> Independent tunnel protocol **server** (not a multi-protocol panel).  
> Repository: https://github.com/jackybig999/aero

中文说明 → **[README.zh-CN.md](./README.zh-CN.md)** · English → **[README.en.md](./README.en.md)**

| | |
|--|--|
| Version | **1.0.0** |
| Protocol | `aero/2.0` (TLS 1.3 + HTTP/2 CONNECT) |
| API level | **1** (frozen ops contract) |
| Layout | `aero-edge/` · `proto/` · `docs/` · `deploy/` |

## Quick start

```bash
# build (Linux VPS)
cd aero-edge
go build -o aero-edge ./cmd/aero-edge

# run
./aero-edge -token SECRET -listen :443 -domain edge.example.com -profile small
```

Or use install helper (see `deploy/install.sh`).

```bash
# cross-compile release binary for linux/amd64
cd aero-edge
set GOOS=linux
set GOARCH=amd64
go build -o aero-edge-linux-amd64 ./cmd/aero-edge
```

## For subscription platforms

- Pull **Release** assets (or build from this tag), do **not** vendor this repo into your billing code.
- Ops contract: [docs/edge-server-v1.md](./docs/edge-server-v1.md)
- Admin API: `/admin/tokens`, `/admin/status` (see README.zh-CN)

## License

Apache License 2.0
