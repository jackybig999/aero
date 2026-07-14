# AERO Edge Server v1.0.0 — Frozen Release

> Standalone **frozen copy** of the AERO protocol server for independent deploy and maintenance.  
> Path: `grok/aero/server` · Version **1.0.0** · API level **1**

中文: [README.zh-CN.md](./README.zh-CN.md)

---

## 1. What this is

**AERO Edge** is the **server node** for the AERO independent tunnel protocol:

- Data path: TLS 1.3 + **HTTP/2 CONNECT** + TypedMessage relay  
- **Never** VMess / VLESS / Trojan / Shadowsocks multi-protocol outs  
- Built for **multi-user / small VPS**: connection caps, per-user bandwidth, idle timeout, persistent tokens  
- Ops: subscription `GET /sub/{secret}`, Cover site, Admin API, metrics  

Frozen contract: [`docs/edge-server-v1.md`](./docs/edge-server-v1.md)

---

## 2. Layout

```
server/
├── README.md / README.zh-CN.md / README.en.md
├── FROZEN.md
├── VERSION                 # 1.0.0
├── go.work
├── aero-edge/              # server source
│   ├── cmd/aero-edge/
│   └── internal/
├── proto/                  # shared protobuf
├── deploy/                 # install / systemd / docker
└── docs/
```

---

## 3. Build

Requires Go **1.22+** (1.25 recommended).

```bash
cd grok/aero/server/aero-edge
go build -o aero-edge ./cmd/aero-edge
./aero-edge -version
# aero-edge 1.0.0 protocol=aero/2.0 api_level=1
```

Windows:

```powershell
cd D:\Jacky\grok\aero\server\aero-edge
go build -o aero-edge.exe .\cmd\aero-edge
.\aero-edge.exe -version
```

---

## 4. Usage (CLI)

### 4.1 Dev / self-signed

```bash
./aero-edge -token my-secret -profile small
# default listen :8443, self-signed cert, data dir ./aero_data or AERO_DATA_DIR
```

### 4.2 Production

```bash
./aero-edge \
  -token BOOTSTRAP_TOKEN \
  -listen :443 \
  -domain edge.example.com \
  -profile small \
  -admin-key "$(openssl rand -hex 16)" \
  -data-dir /var/lib/aero
```

Existing certificates:

```bash
./aero-edge -token SECRET -listen :443 -domain edge.example.com \
  -cert /path/fullchain.pem -key /path/privkey.pem -profile small
```

Let's Encrypt:

```bash
./aero-edge -token SECRET -listen :443 -domain edge.example.com \
  -autocert edge.example.com -profile small
```

### 4.3 Profiles (`-profile`)

| Profile | Hardware | Global conns | Per-user | Bandwidth / user | Idle | Max life |
|---------|----------|--------------|----------|------------------|------|----------|
| `tiny` | 1 vCPU 1G | 256 | 16 | 2 MiB/s | 10m | 12h |
| `small` | 2 vCPU 2G | 1024 | 32 | 5 MiB/s | 15m | 24h |
| `medium` | 4G+ | 4096 | 64 | unlimited | 20m | unlimited |

Overrides: `-max-conn` `-max-conn-user` `-bw-user` `-idle-sec` `-max-life-sec` `-max-dial` `-rate-ip` `-q`

### 4.4 Common flags

| Flag | Meaning |
|------|---------|
| `-token` | Bootstrap auth token (stored as `default`) |
| `-listen` | Listen address, e.g. `:443` |
| `-domain` | Public domain / SNI |
| `-data-dir` | Tokens + subscription meta |
| `-admin-key` | Remote Admin key (loopback is always allowed) |
| `-profile` | `tiny` / `small` / `medium` |
| `-q` | Quiet per-connection logs |
| `-version` | Print version |

---

## 5. Connecting a client

After start, logs show import hints, e.g.:

```text
import: aero-ech -sub https://edge.example.com/sub/<secret>
# self-signed:
aero-ech -sub /var/lib/aero/client-sub.json -insecure
```

Subscription JSON includes `signature` and optional `pin_spki`; clients must verify.

---

## 6. Multi-user tokens (Admin)

Persist: `{data-dir}/tokens.json`  
Hot reload: `POST /admin/reload` or Linux `SIGHUP`

**Loopback examples** (port 8443 default):

```bash
curl -s http://127.0.0.1:8443/admin/version
curl -s http://127.0.0.1:8443/admin/status
curl -s http://127.0.0.1:8443/admin/tokens
curl -s -X POST http://127.0.0.1:8443/admin/tokens -d '{"label":"user2","ttl_hours":8760}'
curl -s -X DELETE "http://127.0.0.1:8443/admin/tokens?token=THE_TOKEN"
curl -s -X POST http://127.0.0.1:8443/admin/reload
```

Remote:

```bash
curl -s -H "X-Aero-Admin-Key: YOUR_KEY" https://edge.example.com/admin/status
```

> Always set `-admin-key` in production; Admin shares the public TLS port with Cover.

---

## 7. Request routing order

1. ACME `/.well-known/...`  
2. **CONNECT** tunnel  
3. **`/admin/*`** (auth required)  
4. **`/sub/{secret}`**  
5. Loopback `/health` `/metrics`  
6. Cover camouflage site  

---

## 8. Operations

| Endpoint | Access | Purpose |
|----------|--------|---------|
| `/health` | loopback | health |
| `/metrics` | loopback | Prometheus text |
| `/sub/{secret}` | public | subscription |
| `/admin/*` | loopback or admin-key | ops API |

Graceful stop: `SIGINT` / `SIGTERM` → drain new CONNECTs → shutdown.

---

## 9. Deploy helpers

See `deploy/`:

- `install.sh`  
- `aero-edge.service`  
- `Dockerfile` / `docker-compose.yml`  

Use the **1.0.0** binary built from this tree.

---

## 10. Upgrade policy (after freeze)

| Change | Version |
|--------|---------|
| Bugfix / performance | **1.0.x** |
| Additive Admin/metrics fields only | **1.x.0** |
| Breaking CONNECT / frames / signature | **2.0.0** |

Clients and panels should honor **api_level**; v1 fields are append-only.

---

## 11. Related docs

| Doc | Content |
|-----|---------|
| [docs/edge-server-v1.md](./docs/edge-server-v1.md) | Ops contract (frozen) |
| [docs/SERVER-V1-COMPLETE.md](./docs/SERVER-V1-COMPLETE.md) | Completeness checklist |
| [docs/SERVER-MULTIUSER.md](./docs/SERVER-MULTIUSER.md) | Multi-user notes |
| [docs/protocol-v1.md](./docs/protocol-v1.md) | Protocol summary |
| [FROZEN.md](./FROZEN.md) | Snapshot metadata |

---

## 12. License

Same as upstream AERO Protocol (Apache License 2.0).
