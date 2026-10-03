# AERO Subagent & Tool Operational Guidelines (AGENTS.md)

All subagents and background tools working on this codebase must strictly follow [PROJECT_RULES.md](file:///D:/jacky/gemini/aisysnew/PROJECT_RULES.md) (aligned with GLOBAL MASTER RULES v1.0.0 and newplan.md):

1. **Go Only (Solidified)**: Production code must be standard Go 1.24+ single module (`github.com/aero-protocol/aero`) flat layout. Frontends are native HTML5/CSS/JS embedded in Go binaries without `node_modules` (gzip < 150KB, 0 runtime deps).
2. **Frontend Zero-Trust**: Frontend holds no business facts, secrets, tokens, or pricing constants. All state is authoritatively computed and validated by the backend.
3. **Directory Conventions & Flat 3-Tier Layout**: `cmd/<bin>/main.go` for thin entries, `internal/<pkg>/` for packages. Ban on vague container directories (`common/`, `utils/`, `core/`, `domain/`, `infra/`, `service/`).
4. **Zero Cross-System Imports**: `internal/client`, `internal/edge`, `internal/mid`, `internal/desk` must NOT import each other in Go code! Shared boundaries are strictly limited to HTTP REST /admin/subs, subscription JSON aero/3.0, and local 127.0.0.1:19877.
5. **Data-Plane Guardrails**:
   - Client initial MTU 1224; IPv4 DF check at gVisor entry: exceeding MTU with DF=1 generates ICMP Type 3 Code 4 (Next-MTU = currentMaxDatagramSize + 24) written back ONLY to local virtual NIC; DF=0 silent drop.
   - Dynamic MTU sync upon *quic.DatagramTooLargeError: decrease currentMaxDatagramSize and update virtual NIC MTU immediately.
   - Datagram pre-check `4 + len(payload) > currentMaxDatagramSize` discarded immediately without SendDatagram, without stream fallback, without reassembly.
   - Two-stage DNS funnel (.cn direct via physical DNS & drop AAAA; rest via tunnel short stream; unestablished fake IP 198.18; AAAA empty answer).
   - Server: handleQUICConn unique object; ONLY TCP streams call ConnLimiter.TryAcquire; DNS short streams & UDP Context register streams are exempt from TryAcquire/DialGuard; single ReceiveDatagram loop with 4-byte ContextID; 64 UDP Contexts max; no plaintext tokens in logs.
6. **Mobile Honesty**: SetupRoutes returns fmt.Errorf("TUN not supported on this platform"). No .aar, no .xcframework, no StartTunnelWithFD.
7. **Zero Host Tampering**: No sys_proxy, no netsh advfirewall. Windows guard only cleans aero0 routes on PID exit.
8. **Artifact Isolation & 3-Path Model**: Intermediate artifacts (`tmp/`) are auto-cleaned; `dist/` is exclusively for embedded static assets; release binaries go to GitHub Release Assets, never git tree.
9. **Quality Gate**: Must pass `gofmt`, `go vet ./...`, and race detector (`go test -race -shuffle=on ./...`).
10. **Error Standards**: No implicit error discarding; explicit `_ = f()` with rationale comments only; safeGo wrapper with recover on background goroutines.
11. **Native AERO Sub Only & Zero-Port URL Mandate**: Strict ban on third-party formats. Only `https://domain.com/sub/superadmin` and `https://domain.com/sub/username{六位随机码}` via standard 443 HTTPS.
12. **Pre-Flight Git Alignment & Zero Untracked**: Before any commit/push, `git status --porcelain` must have 0 untracked files (`??` == 0) and 0 unstaged deletions. All new files and embeds must be staged.
13. **Non-Destructive Cleanup & Rollback Contract**: No hard `rm -rf`. All cleanup must archive to gitignored `backup/` + external mirror, accompanied by `BACKUP_MANIFEST.md` and executable rollback script.
14. **Dedicated Tmp Sandbox & Zero Source Pollution**: `D:\jacky\gemini\AIsysnew\tmp` is the sole authorized local sandbox for all tests, build artifacts (`-o tmp/...`), and runtime caches. Writing, dropping, or generating any temporary file in source directories is strictly prohibited.
