# AERO Subagent & Tool Operational Guidelines (AGENTS.md)

All subagents and background tools working on this codebase must strictly follow [PROJECT_RULES.md](file:///D:/jacky/gemini/aisys/PROJECT_RULES.md) (aligned with GLOBAL MASTER RULES v1.0.0):

1. **Go Only (Solidified)**: Production code must be standard Go 1.24+ flat layout. Frontends are native HTML5/CSS/JS embedded in Go binaries without `node_modules` (gzip < 150KB, 0 runtime deps).
2. **Frontend Zero-Trust**: Frontend holds no business facts, secrets, tokens, or pricing constants. All state is authoritatively computed and validated by the backend.
3. **Directory Conventions**: `internal/` for private packages, thin entry in `cmd/<bin>/main.go`. Ban on generic container directories (`common/`, `utils/`, `core/`).
4. **Artifact Isolation & 3-Path Model**: Intermediate artifacts (`tmp/`) are auto-cleaned; `dist/` is exclusively for embedded static assets; release binaries go to GitHub Release Assets, never git tree.
5. **Decoupled API Invocation**: Standard HTTP REST / JSON / Protobuf interfaces. No cross-boundary direct DB access. Intra-process via interfaces defined in consumer packages.
6. **Data Ownership & Database Hardening**: Dual-database isolation (`aero.db` + `aeropay.db`) in midplatform; autonomous encrypted `edge.db` (AES-256-GCM, zero CGO pure Go SQLite) in edge server; field encryption in finger `app.db`.
7. **Cross-Validation**: Rigorous exclusive health verification: Port 443 + Process Identity (`pgrep aero-edge`) + Midplatform Registry (`ep.Installed`). Uninstall must kill processes and clean state.
8. **Single Branch `main`**: All commits remain on `main`. Never checkout or push any other branch.
9. **100% Remote Public Source**: All deployments must pull from official public GitHub repo (`jackybig999/aero`). Zero local binary uploads.
10. **Quality Gate**: Must pass `gofmt`, `go vet ./...`, and race detector (`go test -race -shuffle=on ./...`).
11. **Reliability & Resource Budgets**: Explicit timeouts on all I/O calls, graceful shutdown, exponential backoff with jitter, zero goroutine/connection leaks.
12. **Error Standards**: No implicit error discarding; explicit `_ = f()` with rationale comments only; safeGo wrapper with recover on background goroutines.
13. **Waiver Registry**: Any deviation from MUST-level rules requires logging in `WAIVERS.md`.
14. **Native AERO Sub Only & Zero-Port URL Mandate**: Absolute ban on third-party subscription formats (Clash, v2rayN, sing-box, Surge). Strict adherence to the ONLY TWO official subscription formats: (1) `https://domain.com/sub/superadmin`, (2) `https://domain.com/sub/username{六位随机码}`. Absolute ban on explicit non-standard ports (such as `:18080`, `:8080`) in subscription URLs. Subscriptions must be standard 443 HTTPS. Clients connect using domain and token only.


