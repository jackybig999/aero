# AERO Project Execution Rules (GEMINI.md)

This project strictly enforces the Two-Tier Engineering Rules defined in [PROJECT_RULES.md](file:///D:/jacky/gemini/aisysnew/PROJECT_RULES.md) (aligned with GLOBAL MASTER RULES v1.0.0 and newplan.md):

## Level 1: Global Master Baseline (v1.0.0)
1. **Pure Go Standards**: Single module `github.com/aero-protocol/aero` flat layout. Native HTML5/CSS/JS embedded via `//go:embed` (runtime deps == 0, gzip < 150KB). Zero `node_modules` committed.
2. **Frontend Zero-Trust & Thin Client**: Frontend holds no business facts, secrets, tokens, or pricing constants. All state is authoritatively computed and validated by the backend.
3. **Standard Layout**: Standard Go conventions, `internal/` for private packages, `cmd/<bin>/main.go` for multi-binary thin entries. Ban on vague container dirs (`common/`, `utils/`, `core/`, `domain/`, `infra/`, `service/`).
4. **Zero Cross-System Imports**: `internal/client`, `internal/edge`, `internal/mid`, `internal/desk` must NOT import each other.
5. **Data Ownership & Database Hardening**: Dual-database isolation (`aero.db` + `aeropay.db`) in midplatform; autonomous encrypted `edge.db` (AES-256-GCM, zero CGO pure Go SQLite) in edge server.
6. **Testing Standards**: Ban on flaky tests, ban on `time.Sleep` for concurrency synchronization, 7-point in-process test verification matrix.
7. **Logging & Observability**: Structured logging in service code. Whitelist `/healthz` and `/metrics`. No plaintext token logging.
8. **Error Standards & Panic Isolation**: No implicit error discarding; `fmt.Errorf("%w", err)`; `errors.Is`/`As`; safeGo wrapper with recover on background goroutines.

## Level 2: AERO Data-Plane & Architecture Specifics
- **P1. Client MTU & ICMP Backpressure**: Initial MTU 1224. gVisor entry inspects IPv4 DF header: exceeding packet with DF=1 generates ICMP Type 3 Code 4 (Next-MTU = currentMaxDatagramSize + 24) written back ONLY to local virtual NIC; DF=0 silent drop. On DatagramTooLargeError, dynamically update currentMaxDatagramSize and call virtual NIC MTU setter immediately.
- **P2. Datagram Pre-check**: If `4 + len(payload) > currentMaxDatagramSize`, discard immediately without SendDatagram, without stream fallback, without reassembly.
- **P3. DNS Zero-Leak Funnel**: .cn direct via physical DNS & drop AAAA; other domains via tunnel short stream; unestablished returns 198.18 fake IP; AAAA returns empty answer. Port 53 nil return drops in-stack without DialUDP.
- **P4. Edge Server Concurrency & Protection**: handleQUICConn unique object; first frame ValidateFull binds Token, subsequent streams exempt from Nonce; ONLY TCP streams call ConnLimiter.TryAcquire; DNS short streams & UDP Context register streams are exempt from TryAcquire/DialGuard; single ReceiveDatagram loop with 4-byte ContextID; 64 UDP Contexts max; bidirectional BandwidthLimiter.Take.
- **P5. Zero Host Tampering**: No sys_proxy, no netsh advfirewall. Windows guard only cleans aero0 routes on PID exit.
- **P6. Mobile Stub**: SetupRoutes returns fmt.Errorf("TUN not supported on this platform").
- **P7. Single Branch main & Remote Deploy**: Only main branch. VPS installs pull directly from GitHub public repo (`jackybig999/aero`). Zero local binary uploads.
- **P8. Native AERO Subscription Only**: Strictly `https://domain.com/sub/superadmin` and `https://domain.com/sub/username{六位随机码}` via standard 443 HTTPS. No non-standard ports.
