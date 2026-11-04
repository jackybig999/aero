# AERO Test Infrastructure & E2E Test Suite Specification (TEST_INFRA.md)

## 1. Overview & Architecture

The AERO E2E Test Suite (`tests/e2e/`) is a comprehensive, requirement-driven, opaque-box testing framework covering the autonomous HTTP/3 VPN edge and client system. It validates all eight core architectural features (F1 through F8) without violating Go module boundaries or Rule 4 (`internal/client`, `internal/edge`, `internal/mid`, `internal/desk` zero cross-system imports).

### Opaque-Box Wire-Contract-First Principles
1. **Network & Wire-Contract Driven**: All tests operate against external contracts — HTTP/HTTPS endpoints, wire JSON payloads (`SubDocument`, `SubServer`, `UserSub`), TLS certificates, DNS datagrams, and STUN packets.
2. **Deterministic Test Isolation**: Every test sets up its own isolated state, utilizes dedicated ephemeral ports or in-memory mock servers, avoids global mutable state conflicts, and cleans up completely upon completion.
3. **Strict Concurrency Safety**: All test components pass race condition analysis under `go test -race -shuffle=on` with zero warnings.

---

## 2. Feature Coverage Matrix (F1 - F8)

| Feature | Scope & Specification | Tier 1 (Coverage) | Tier 2 (Boundaries) | Tier 3 (Interactions) | Tier 4 (Real-World) |
|---|---|---|---|---|---|
| **F1** | **Admin Subscription**: `https://{domain}/sub/admin` with permanent validity (`expireAt: 0`), unlimited traffic (`trafficLimitBytes: 0`), valid HMAC-SHA256 signature, zero-port address formatting | 5 tests | 5 tests | Pairwise: F1 + F4 (Port Probing) | Scenario 1 |
| **F2** | **User Subscription**: `https://{domain}/sub/{user}{6random}` with strict expiration timestamp (`expireAt`) and traffic quota (`trafficLimitBytes`) enforcement returning HTTP 403 Forbidden | 5 tests | 5 tests | Pairwise: F2 + F5 (WARP Outbound) | Scenario 2 |
| **F3** | **Zero-Port Mandate**: URL generation strictly matching `https://{domain}/sub/...` without explicit ports, client-side fallback via candidate ports when 443 blocked, ban on `localhost:18080` | 5 tests | 5 tests | Pairwise: F3 + F8 (ClearPins on update) | Scenario 3 |
| **F4** | **Candidate Ports Contract**: Global contract `StandardCandidatePorts = []int{2083, 2087, 8443, 2053, 2096, 10443, 24443, 34443, 44443}` independently defined, length 9, no duplicates | 5 tests | 5 tests | Pairwise: F4 + F7 (UFW sync) | Scenario 1 & 3 |
| **F5** | **Embedded Web Console & WARP**: `/console?key=<AdminKey>` with constant-time auth, hardware metrics, IP cleanliness scoring (0-100), Cloudflare WARP installer bypass protection & outbound routing switch | 5 tests | 5 tests | Pairwise: F5 + F2 (User sub API) | Scenario 5 |
| **F6** | **TLS Certificate Hot Reload**: Auto-discovery in `/root/.acme.sh/${domain}_ecc/`, `tls.Config.GetCertificate` file `ModTime` tracking, zero-downtime certificate rotation, SPKI SHA-256 pin extraction | 5 tests | 5 tests | Pairwise: F6 + Live QUIC session | Scenario 4 |
| **F7** | **Pure Physical Socket Deployment**: `deploy/edge-install.sh` verification for zero `iptables/nftables PREROUTING REDIRECT` rules, direct physical UFW allow, zero-python execution, zero-port URL output | 5 tests | 5 tests | Pairwise: F7 + F4 (Firewall rule alignment) | Script Audit |
| **F8** | **Client Ladder Probe, ClearPins, DNS, STUN & Badges**: Concurrent ladder port probe, `ClearPins()` in `engine.go:Apply()`, DNS Fake-IP (198.18.0.0/15), AAAA dropping, WebRTC STUN physical blocking, UI badges | 6 tests | 5 tests | Pairwise: F8 + DNS/STUN concurrency | Scenario 6 |
| **Total** | **95 Test Cases Implemented** | **41 tests** | **40 tests** | **8 tests** | **6 scenarios** |

---

## 3. Test Tier Breakdown

### Tier 1: Feature Coverage (41 Test Cases)
- **F1 (5 tests)**: `TestTier1_F1_AdminSub_PermanentValidity`, `TestTier1_F1_AdminSub_UnlimitedTraffic`, `TestTier1_F1_AdminSub_ZeroPortURL`, `TestTier1_F1_AdminSub_HMACSignature`, `TestTier1_F1_AdminSub_ProtocolVersionAndServers`
- **F2 (5 tests)**: `TestTier1_F2_UserSub_NormalAccess`, `TestTier1_F2_UserSub_ExpireAtEnforcement`, `TestTier1_F2_UserSub_TrafficLimitEnforcement`, `TestTier1_F2_UserSub_NonExistentSlug`, `TestTier1_F2_UserSub_UniqueUserToken`
- **F3 (5 tests)**: `TestTier1_F3_ZeroPort_GeneratedURLStrictFormat`, `TestTier1_F3_ZeroPort_FallbackOn443Failure`, `TestTier1_F3_ZeroPort_NoPortInServerAddress`, `TestTier1_F3_ZeroPort_NoLocalhost18080Leak`, `TestTier1_F3_ZeroPort_AltPortsPreserved`
- **F4 (5 tests)**: `TestTier1_F4_CandidatePorts_ExactSequence`, `TestTier1_F4_CandidatePorts_PoolLength`, `TestTier1_F4_CandidatePorts_NoDuplicates`, `TestTier1_F4_CandidatePorts_RangeCheck`, `TestTier1_F4_CandidatePorts_DecoupledContract`
- **F5 (5 tests)**: `TestTier1_F5_Console_AuthConstantTime`, `TestTier1_F5_Console_MissingKeyDenied`, `TestTier1_F5_Console_VPSMetricsJSON`, `TestTier1_F5_Console_IPCleanlinessScoring`, `TestTier1_F5_Console_WARPBypassProtection`
- **F6 (5 tests)**: `TestTier1_F6_Cert_AutoDiscoveryPath`, `TestTier1_F6_Cert_ModTimeDetection`, `TestTier1_F6_Cert_GetCertificateHotReload`, `TestTier1_F6_Cert_SPKIPinExtraction`, `TestTier1_F6_Cert_NoSelfSignedProduction`
- **F7 (5 tests)**: `TestTier1_F7_Deploy_ZeroNATRedirect`, `TestTier1_F7_Deploy_ZeroPythonBaseline`, `TestTier1_F7_Deploy_PhysicalUFWAllow`, `TestTier1_F7_Deploy_DirectPhysicalListeners`, `TestTier1_F7_Deploy_ZeroPortSubOutput`
- **F8 (6 tests)**: `TestTier1_F8_Client_ConcurrentLadderProbe`, `TestTier1_F8_Client_ClearPinsOnApply`, `TestTier1_F8_Client_DNSFakeIPPool`, `TestTier1_F8_Client_DNSAAAADropping`, `TestTier1_F8_Client_STUNPhysicalBlocking`, `TestTier1_F8_Client_NodeBadgesRendering`

### Tier 2: Boundary & Corner Cases (40 Test Cases)
- **F1 (5 tests)**: `TestTier2_F1_AdminSub_NegativeExpireAt`, `TestTier2_F1_AdminSub_EmptyServerListReject`, `TestTier2_F1_AdminSub_ClockSkewFuture`, `TestTier2_F1_AdminSub_ConcurrentAdminFetches`, `TestTier2_F1_AdminSub_ExcessiveHeaderPayload`
- **F2 (5 tests)**: `TestTier2_F2_UserSub_BoundaryExpireAtExactSecond`, `TestTier2_F2_UserSub_BoundaryTrafficExactByte`, `TestTier2_F2_UserSub_SlugSpecialChars`, `TestTier2_F2_UserSub_MalformedRandomCodeLength`, `TestTier2_F2_UserSub_ZeroTrafficLimitMeansUnlimited`
- **F3 (5 tests)**: `TestTier2_F3_ZeroPort_URLWithPortRejected`, `TestTier2_F3_ZeroPort_IPv6AddressFormatting`, `TestTier2_F3_ZeroPort_ProbeAllPortsDown`, `TestTier2_F3_ZeroPort_ProbePortJitterTimeout`, `TestTier2_F3_ZeroPort_DNSResolutionFailure`
- **F4 (5 tests)**: `TestTier2_F4_CandidatePorts_BoundaryPorts`, `TestTier2_F4_CandidatePorts_NoPrivilegedPorts`, `TestTier2_F4_CandidatePorts_NoPortZero`, `TestTier2_F4_CandidatePorts_ImmutableContract`, `TestTier2_F4_CandidatePorts_AltPortsDeduplication`
- **F5 (5 tests)**: `TestTier2_F5_Console_KeyBruteForceResistance`, `TestTier2_F5_Console_EmptyAdminKeyReject`, `TestTier2_F5_Console_MetricsMissingProcFiles`, `TestTier2_F5_Console_CleanlinessScoresClamp0To100`, `TestTier2_F5_Console_WARPUnreachableFallback`
- **F6 (5 tests)**: `TestTier2_F6_Cert_MissingKeyFile`, `TestTier2_F6_Cert_CorruptPEMFile`, `TestTier2_F6_Cert_ExpiredCertDetection`, `TestTier2_F6_Cert_SymlinkResolution`, `TestTier2_F6_Cert_ZeroModTime`
- **F7 (5 tests)**: `TestTier2_F7_Deploy_MissingEnvironmentVars`, `TestTier2_F7_Deploy_IdempotentExecution`, `TestTier2_F7_Deploy_NonRootWarning`, `TestTier2_F7_Deploy_UFWUnavailableGraceful`, `TestTier2_F7_Deploy_SystemdServiceTemplate`
- **F8 (5 tests)**: `TestTier2_F8_Client_ConcurrentLadderProbeTimeout`, `TestTier2_F8_Client_ClearPinsEmptySet`, `TestTier2_F8_Client_DNSFakeIPExhaustion`, `TestTier2_F8_Client_DNSDotCNPassthrough`, `TestTier2_F8_Client_STUNNonStandardPorts`

### Tier 3: Cross-Feature Interactions (8 Test Cases)
- `TestTier3_AdminSub_CandidatePortProbing`: Admin sub fetched across candidate ports during primary port failover.
- `TestTier3_UserSubQuota_WARPSmartRouting`: User under quota routes traffic through WARP proxy, user over quota blocked before WARP dial.
- `TestTier3_CertRenewal_LiveConnection`: Dynamic cert reload does not disrupt active QUIC/TLS connections.
- `TestTier3_ZeroPortURL_ClearPinsOnUpdate`: Ingesting new zero-port subscription clears SPKI pins and updates active server pins.
- `TestTier3_CandidatePorts_UFWFirewallSync`: Candidate ports in Go contract match the exact port list in `edge-install.sh`.
- `TestTier3_WebConsole_UserSubCreationLifecycle`: Web Console creates user sub, verifies it appears in `/sub/{slug}`, then verifies quota enforcement.
- `TestTier3_DNSFakeIP_STUNBlocking`: Incoming DNS fake-IP query paired with outgoing STUN packet: DNS resolves to 198.18 while STUN is dropped.
- `TestTier3_WARPBypass_MetricsReporting`: WARP status correctly reflected in Web Console metrics and IP cleanliness score.

### Tier 4: Real-World Scenarios (6 Test Cases)
- `TestTier4_FullEndToEnd_SubscriptionToQUICConnection`: Edge server spins up, admin generates user sub, client fetches via zero-port URL, traverses candidate port, verifies SPKI pin, establishes connection, and exchanges data.
- `TestTier4_QuotaExhaustionCutoff_LiveSession`: Active user session consuming data hits quota limit, triggering immediate HTTP 403 Forbidden on refresh, cache purge, and session termination.
- `TestTier4_PortBlocked_AutoHealingTraversal`: Primary port 443 blocked by DPI/firewall; client concurrent ladder probe discovers open candidate port 8443 under low latency budget without user intervention.
- `TestTier4_ACMERenewal_HotReloadWithoutDowntime`: Live edge service automatically reloads certificate from disk via `ModTime` tracking when acme.sh writes updated fullchain.cer/key without restarting edge daemon.
- `TestTier4_WARPFailover_CleanlinessTransition`: Outbound AI routing detects blocked direct connection, triggers WARP proxy activation, and upgrades cleanliness score to 95.
- `TestTier4_AntiLeak_FullStackVerification`: Client network stack receives mixed traffic (.cn DNS, international DNS, IPv6 AAAA, WebRTC STUN), validating physical .cn passthrough, 198.18 Fake-IP mapping, AAAA empty answer dropping, and WebRTC STUN physical blocking.

---

## 4. Test Harness Design (`tests/e2e/harness_test.go`)

1. **`MockEdgeServer`**: Full-fledged in-process HTTPS/HTTP server implementing:
   - Dynamic TLS cert reload (`GetCertificateDynamic`) checking file `ModTime`
   - Constant-time admin authentication (`subtle.ConstantTimeCompare`)
   - Complete `/sub/admin` and `/sub/{slug}` subscription endpoints with `expireAt` and `trafficLimitBytes` validation
   - `POST /admin/subs` management API
   - `/api/metrics`, `/api/purity`, `/api/warp/toggle`
2. **`GenerateTestCertificate`**: In-memory ECDSA P-256 certificate authority generating x509 certificates and keys on the fly with SPKI SHA-256 base64 pin extraction.
3. **`SimulateConcurrentLadderProbe`**: Fast concurrent port probe simulating client connection ladder across candidate ports under context cancellation and timeout budgets.
4. **`SimulateDNSFunnel`**: In-stack DNS funnel testing .cn physical resolution, 198.18 Fake-IP pool, and IPv6 AAAA dropping.
5. **`IsSTUNPacket` / `BuildSTUNBindingRequest`**: STUN RFC 5389 packet synthesis with magic cookie `0x2112A442` for DPI physical blocking validation.

---

## 5. How to Run the Tests

```bash
# Run all E2E tests with verbose logging, race detector, and randomized execution order
go test -v -race -shuffle=on ./tests/e2e/...

# Run specific tier
go test -v -race -run TestTier1 ./tests/e2e/...
go test -v -race -run TestTier2 ./tests/e2e/...
go test -v -race -run TestTier3 ./tests/e2e/...
go test -v -race -run TestTier4 ./tests/e2e/...

# Run static checks
go vet ./tests/e2e/...
gofmt -l tests/e2e/
```
