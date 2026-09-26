# AERO Project Execution Rules (GEMINI.md)

This project strictly enforces the Two-Tier Engineering Rules defined in [PROJECT_RULES.md](file:///D:/jacky/gemini/aisys/PROJECT_RULES.md) (aligned with GLOBAL MASTER RULES v1.0.0):

## Level 1: Global Master Baseline (v1.0.0)
1. **Pure Go Standards**: Solidified stack: **Go 1.24+ Flat Layout**. Native HTML5/CSS/JS frontend embedded via `//go:embed` (runtime deps == 0, gzip < 150KB). Zero `node_modules` committed.
2. **Frontend Zero-Trust & Thin Client**: Frontend holds no business facts, secrets, tokens, or pricing constants. All state is authoritatively computed and validated by the backend.
3. **Standard Layout**: Standard Go conventions, `internal/` for private packages, `cmd/<bin>/main.go` for multi-binary thin entries. Ban on vague container dirs (`common/`, `utils/`, `core/`).
4. **Artifact Isolation & 3-Path Model**:
   - `tmp/` for dev & CI intermediate outputs (auto-cleaned, never committed).
   - `dist/` exclusively for embedded lightweight web assets.
   - Release binaries uploaded to GitHub Release Assets, never git tree.
5. **Decoupled API Invocation**: Cross-service: HTTP REST / JSON / Protobuf RPC contracts (zero DB sharing). Intra-service: Go `interface` abstraction in consumer packages, unidirectional dependencies.
6. **API Compatibility**: No breaking changes on published APIs. Reserved field numbers for Protobuf.
7. **Data Ownership & Database Hardening**: Single writer per database. Cache-Aside pattern. Database schema constraints (NOT NULL, check, foreign keys). Financials in fixed-point integer. Field-level encryption (AES-256-GCM). No long external I/O inside DB transactions.
8. **Engineering Verification Loop**: 6-step loop. Single developer / AI pair programming Trunk-Based mode allowed with pre-commit gates (`gofmt`, `go vet`, fast test) + structured self-check report + Conventional Commits.
9. **Testing Standards**: Core coverage >= 70%, ban on flaky tests, ban on `time.Sleep` for concurrency synchronization, randomize execution (`go test -shuffle=on`).
10. **CI/CD Quality Gate**: Fast checks (< 60s), full race tests (`go test -race -shuffle=on ./...`), `govulncheck`, `gitleaks` secret scanning, Action commit SHA pinning.
11. **Security & Runtime Hardening**: Credentials injected via env/secrets (never hardcoded), TLS 1.2+, input validation, non-root read-only container deployments, zero unpatched CVEs.
12. **Logging & Observability**: Structured logging (`log/slog`) in service code (raw terminal prints allowed only in CLI UI layer). `/healthz` (liveness/readiness) and `/metrics` (Prometheus) endpoints.
13. **Error Standards & Panic Isolation**: No implicit error discarding (explicit `_ = f()` allowed only with inline justification comment), `fmt.Errorf("%w", err)`, `errors.Is`/`As`, safeGo wrapper with recover on background goroutines.
14. **Release & Rollback**: SemVer 2.0.0, automated CI releases with `-ldflags` version injection, documented rollback paths.
15. **Reliability Engineering**: Explicit timeouts on all cross-process I/O calls, exponential backoff with jitter on retries, idempotency keys persisted to DB, graceful shutdown with SIGTERM.
16. **Resource Efficiency**: Performance budgets, worker pools on high concurrency, connection pool reuse with hard limits, zero goroutine leaks.

## Level 2: AERO Project Specifics
- **P1. Single Branch `main` Only**: Strictly maintain ONLY `main` branch on GitHub (`jackybig999/aero`). NEVER create feature or secondary branches locally or remotely.
- **P2. 100% Official Remote Source Dual-Pipeline**: VPS installation must pull directly from GitHub public repo (`jackybig999/aero`): Release asset if available, or repo source clone/compile fallback. ZERO local binary transfers or private uploads.
- **P3. Exclusive Probe Defense**: Never judge service health solely by port 443 (exclude third-party processes like `sui`). Check: Port + Process Identity (`pgrep aero-edge`) + Midplatform Registry (`ep.Installed`). Uninstall must kill processes (`pkill -9`), clean configs, and sync status to `UNINSTALLED`. UI loading state mandatory.
- **P4. User Authority Boundary**: NEVER execute installs on remote VPS without explicit user instructions.
- **P5. Frontend Budget**: gzip < 150KB, 0 runtime dependencies, embedded via `//go:embed`.
- **P6. Observability**: Whitelist `/healthz` and `/metrics` through `web_handler.go`.
- **P7. Error Conventions**: Explicit `_ = f()` with comments for unrecoverable errors.
- **P8. Subsystem Decoupling & Autonomous Edge Architecture**:
  - Midplatform (`sub/vpn`): control-plane with isolated dual DB (`aero.db` + `aeropay.db`). No SNI or protocol-level tables. 403 on sub switch off/expired.
  - Edge Server (`protocol/server` / `aero-edge`): 100% offline autonomous data-plane with encrypted `edge.db` (AES-256-GCM, zero CGO pure Go SQLite) for local token verification and cover site routing.
  - Client (`protocol/client`): pure Go multi-platform (Windows, macOS, Linux), zero internal coupling.
  - Finger (`connect/os`): isolated application sandbox, dual-platform builds, field-level encryption, connecting only via local SOCKS5 proxy port.
- **P9. Native AERO Subscription Only & Zero-Port URL Mandate**:
  - STRICT BAN on third-party subscription formats (Clash, v2rayN, sing-box, Surge). AERO ONLY produces and consumes native `aero/2.0` JSON format.
  - ONLY TWO official subscription formats are permitted across the entire system:
    1. Admin Sub: `https://domain.com/sub/superadmin`
    2. User Sub: `https://domain.com/sub/username{六位随机码}` (e.g. `https://domain.com/sub/jacky123456`)
  - STRICT BAN on explicit non-standard ports (such as `:18080`, `:8080`) in subscription links. Subscriptions are exclusively distributed via standard 443 HTTPS domain URLs. Client connects using domain and token only.


