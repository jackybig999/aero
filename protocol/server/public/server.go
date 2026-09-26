// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// aero-edge — AERO 协议服务端 v1（多用户 · 小 VPS · 契约冻结）
//
//	aero-edge -token SECRET -listen :443 -domain example.com -profile small
//	aero-edge -version
package public

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aero-protocol/aero-edge/public/internal/auth"
	"github.com/aero-protocol/aero-edge/public/internal/config"
	"github.com/aero-protocol/aero-edge/public/internal/contextstore"
	"github.com/aero-protocol/aero-edge/public/internal/cover"
	"github.com/aero-protocol/aero-edge/public/internal/listener"
	"github.com/aero-protocol/aero-edge/public/internal/metrics"
	"github.com/aero-protocol/aero-edge/public/internal/traffic"
	"github.com/aero-protocol/aero-edge/public/internal/transport"
)

func RunServer() {
	showVer := flag.Bool("version", false, "print version and exit")
	listen := flag.String("listen", "", "listen addr e.g. :443")
	token := flag.String("token", "", "bootstrap auth token (auto if empty)")
	domain := flag.String("domain", "", "public domain / SNI")
	certFile := flag.String("cert", "", "TLS cert PEM")
	keyFile := flag.String("key", "", "TLS key PEM")
	autoCert := flag.String("autocert", "", "Let's Encrypt domain")
	dataDir := flag.String("data-dir", "", "data dir (tokens/sub)")

	profName := flag.String("profile", "", "tiny|small|medium")
	maxConn := flag.Int("max-conn", 0, "max tunnels global (0=profile)")
	maxConnUser := flag.Int("max-conn-user", 0, "max tunnels per token (0=profile)")
	rateIP := flag.Int("rate-ip", 0, "CONNECT/s/IP (0=profile)")
	bwUser := flag.Int("bw-user", -1, "bytes/s per token (-1=profile, 0=unlimited)")
	idleSec := flag.Int("idle-sec", 0, "idle timeout sec (0=profile)")
	lifeSec := flag.Int("max-life-sec", -1, "max tunnel life sec (-1=profile, 0=unlimited)")
	maxDial := flag.Int("max-dial", 0, "concurrent dials (0=profile)")
	adminKey := flag.String("admin-key", "", "remote Admin key")

	portsFlag := flag.String("ports", "", "legacy ports")
	sniFlag := flag.String("sni", "", "legacy SNI")
	autoCertDir := flag.String("autocert-dir", "./certs", "ACME cache")
	autoCertEmail := flag.String("autocert-email", "", "ACME email")
	advertiseHost := flag.String("advertise-host", "", "host in subscription")
	coverName := flag.String("cover-name", "CloudEdge CDN", "cover title")
	acmeWebRoot := flag.String("acme-webroot", "", "ACME HTTP-01 webroot dir (empty=off)")
	logFile := flag.String("log-file", "", "log file")
	logFormat := flag.String("log-format", "text", "text|json")
	configPath := flag.String("config", "", "optional config")
	quiet := flag.Bool("q", false, "quiet logs")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "AERO edge v%s — multi-user protocol server\n\n", Version)
		fmt.Fprintf(os.Stderr, "  aero-edge -token SECRET -listen :443 -domain edge.example.com -profile small\n\n")
		fmt.Fprintf(os.Stderr, "Admin: GET /admin/version|/status  GET/POST/DELETE /admin/tokens  POST /admin/reload\n")
		fmt.Fprintf(os.Stderr, "SIGHUP: reload tokens.json and -cert/-key PEM\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *showVer {
		fmt.Printf("aero-edge %s protocol=%s api_level=%d\n", Version, Protocol, APILevel)
		return
	}

	initMemoryLimit()

	if *configPath != "" {
		if cfg, err := config.LoadServerFile(*configPath); err == nil {
			applyServerConfig(cfg, listen, portsFlag, token, domain, sniFlag, autoCert, autoCertEmail, autoCertDir, certFile, keyFile, logFormat, logFile)
			log.Printf("[CONFIG] %s", *configPath)
		} else {
			log.Printf("[CONFIG] %v", err)
		}
	}
	if err := setupLogging(*logFile, *logFormat); err != nil {
		log.Fatalf("log: %v", err)
	}

	ps := GetProfile(*profName)
	maxC, maxU, rate, bw, idle, life, dialN, q := applyProfile(ps, *maxConn, *maxConnUser, *rateIP, *bwUser, *idleSec, *lifeSec, *maxDial, *quiet)

	memBytes := detectAvailableMemory()
	if memBytes > 0 && memBytes <= 1024*1024*1024 && *maxConn == 0 {
		if maxC > 500 {
			maxC = 500
			log.Printf("[PROFILE] Low-spec VPS (<=1GB RAM): dynamically capped maxConn to %d to protect stability", maxC)
		}
	}

	ports := resolvePorts(*listen, *portsFlag)
	tlsPorts, plainPorts, quicPorts := config.ClassifyPorts(ports)

	// Auto-probe fallback: If preferred port (e.g. 443) is occupied,
	// automatically fallback to the next available standard HTTPS candidate port.
	if len(tlsPorts) > 0 {
		firstPort := tlsPorts[0]
		if !IsPortAvailable(firstPort) {
			chosen := AutoProbeHTTPSPort(firstPort)
			if chosen != firstPort {
				log.Printf("[PORT] Port %d occupied by another service (e.g. sing-box/s-ui/nginx). Auto-switched to :%d", firstPort, chosen)
				tlsPorts[0] = chosen
			}
		}
	}

	// Autocert HTTP-01 needs :80. If only :443 was given, add 80 automatically.
	if *autoCert != "" {
		has80 := false
		for _, p := range plainPorts {
			if p == 80 {
				has80 = true
				break
			}
		}
		if !has80 {
			plainPorts = append(plainPorts, 80)
			log.Printf("[CERT] autocert enabled — also listening :80 for HTTP-01 ACME")
		}
	}
	// QUIC (HTTP/3) 优先原则：默认让所有 TLS 端口自动开启 QUIC UDP 监听，除非显式禁用 (0/false/off)
	enableQUIC := true
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("AERO_ENABLE_QUIC"))); v == "0" || v == "false" || v == "off" {
		enableQUIC = false
	}
	if enableQUIC {
		for _, p := range tlsPorts {
			already := false
			for _, qp := range quicPorts {
				if qp == p {
					already = true
					break
				}
			}
			if !already {
				quicPorts = append(quicPorts, p)
			}
		}
	}

	publicName := *domain
	if publicName == "" {
		publicName = *sniFlag
	}
	if publicName == "" {
		publicName = "cdn-aero.com"
	}

	validator := auth.NewValidator()
	dataDirResolved, err := bootstrapDataDirOnly(*dataDir)
	if err != nil {
		log.Fatalf("data-dir: %v", err)
	}
	tokStore, err := auth.Open(dataDirResolved, validator)
	if err != nil {
		log.Fatalf("tokens: %v", err)
	}
	tok := *token
	if tok == "" {
		if list := tokStore.List(); len(list) > 0 {
			tok = list[0].Token
			log.Printf("token (from store): %s", tok)
		} else {
			tok = generateToken()
			log.Printf("token (auto): %s", tok)
		}
	}
	if err := tokStore.Ensure(tok, "default", 365*24*time.Hour); err != nil {
		log.Fatalf("token ensure: %v", err)
	}
	if ed := tokStore.EdgeDB(); ed != nil {
		ed.StartSNIHealthChecker(5*time.Minute, nil)
		log.Printf("[SNI-HEALTH] edge.db autonomous SNI health checker started (best: %s)", ed.BestActiveSNI())
	}

	var certSource transport.Source
	switch {
	case *certFile != "" && *keyFile != "":
		// Prefer static PEMs (acme.sh / LE / ZeroSSL) — production path
		certSource = transport.Manual
	case *autoCert != "":
		certSource = transport.LetsEncrypt
	default:
		// No silent self-signed for production domains; require explicit certs
		isRealDomain := (*domain != "" && net.ParseIP(*domain) == nil) || (*sniFlag != "" && net.ParseIP(*sniFlag) == nil)
		if isRealDomain {
			log.Fatalf("[CERT] refuse self-signed: provide -cert/-key (recommended) or -autocert for ACME")
		}
		certSource = transport.SelfSigned
		log.Printf("[CERT] WARNING: self-signed fallback enabled for IP/dev")
	}
	certCfg := transport.CertConfig{
		Source: certSource, CertFile: *certFile, KeyFile: *keyFile,
		Domains: []string{publicName}, CacheDir: *autoCertDir, Email: *autoCertEmail,
	}
	if *autoCert != "" {
		certCfg.Domains = []string{*autoCert, publicName}
	}
	certManager, err := transport.NewCertManager(certCfg)
	if err != nil {
		log.Fatalf("cert: %v", err)
	}
	// Best-effort LE warm-up so first client does not get self-signed fallback.
	if *autoCert != "" {
		go certManager.WarmPublicCert(*autoCert)
	} else if publicName != "" && publicName != "cdn-aero.com" {
		go certManager.WarmPublicCert(publicName)
	}

	serverCfg := &config.ServerConfig{
		TLSPorts: tlsPorts, PlainPorts: plainPorts, QUICPorts: quicPorts,
		TLSCert: certManager.Certificate(), GetCertificate: certManager.GetCertificate,
	}
	echMgr := transport.NewECHManager(publicName)
	if _, err := echMgr.GenerateKey(); err != nil {
		log.Printf("[ECH] %v", err)
	}
	echStopCh := make(chan struct{})
	defer close(echStopCh)
	echMgr.StartAutoRotation(3*24*time.Hour, echStopCh)

	ctxStore := contextstore.NewDefault()
	defer ctxStore.Close()
	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for range t.C {
			_, _ = ctxStore.Cleanup(30 * time.Minute)
		}
	}()

	listenPort := 443
	if len(tlsPorts) > 0 {
		listenPort = tlsPorts[0]
	}
	adv := *advertiseHost
	if adv == "" {
		adv = publicName
	}
	subSNI := publicName
	if ed := tokStore.EdgeDB(); ed != nil {
		if best := ed.BestActiveSNI(); best != "" {
			subSNI = best
		}
	}
	subStore, dataDirResolved, err := bootstrapSubscription(*dataDir, adv, listenPort, tok, subSNI, certManager.Certificate())
	if err != nil {
		log.Fatalf("subscription: %v", err)
	}

	reg := metrics.NewRegistry()
	cl := traffic.NewConnLimiter(maxC, maxU)
	rl := traffic.NewRateLimiter(rate)
	bl := traffic.NewBandwidthLimiter(bw)
	dg := traffic.NewDialGuard(dialN)
	coverSite := cover.New(cover.Config{SiteName: *coverName, Enabled: true})

	handler := NewEdgeHandler(HandlerOptions{
		Validator: validator, ECH: echMgr, ACME: certManager.ACMEHandler(),
		Metrics: reg, ContextStore: ctxStore, SubStore: subStore, Cover: coverSite,
		ConnLimit: cl, RateLimit: rl, BWLimit: bl, DialGuard: dg, TokenStore: tokStore,
		CertMgr: certManager, ACMEWebRoot: *acmeWebRoot,
		AdminKey: *adminKey, IdleTimeout: idle, MaxLife: life, Quiet: q,
		StrictCamouflage: true,
	})

	mgr, err := listener.NewManager(handler, validator, serverCfg, echMgr.TLSKeys())
	if err != nil {
		log.Fatalf("listener: %v", err)
	}
	if err := mgr.Start(serverCfg); err != nil {
		log.Fatalf("start: %v", err)
	}

	profLabel := *profName
	if profLabel == "" {
		profLabel = "custom"
	}
	log.Printf("AERO edge %s profile=%s tls=%v max-conn=%d/%d rate-ip=%d bw=%d idle=%v life=%v dial=%d",
		Version, profLabel, tlsPorts, cl.MaxGlobal(), cl.MaxPerTok(), rate, bw, idle, life, dialN)
	log.Printf("token=%s tokens=%s data=%s", tok, tokStore.Path(), dataDirResolved)
	log.Printf("sub=/sub/%s admin=/admin/*", subStore.Secret())

	// SIGHUP 热重载 tokens + 证书 PEM（Windows 仅 Admin POST /admin/reload）
	go func() {
		hup := make(chan os.Signal, 1)
		notifyConfigReload(hup)
		for range hup {
			n, err := tokStore.Reload()
			if err != nil {
				log.Printf("[RELOAD] tokens: %v", err)
			} else {
				log.Printf("[RELOAD] tokens ok count=%d", n)
			}
			if err := certManager.ReloadFromDisk(); err != nil {
				log.Printf("[RELOAD] cert: %v (keeping previous)", err)
			}
		}
	}()
	go func() {
		tick := time.NewTicker(5 * time.Minute)
		defer tick.Stop()
		for range tick.C {
			if err := certManager.ReloadFromDisk(); err != nil {
				log.Printf("[CERT] poll reload: %v (keeping previous)", err)
			}
		}
	}()

	go func() {
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for range t.C {
			for _, a := range reg.CheckThresholds(metrics.DefaultThresholds()) {
				reg.RecordAlert(a.Severity, a.Name, a.Message)
				log.Printf("[ALERT] %s %s: %s", a.Severity, a.Name, a.Message)
			}
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("draining...")
		handler.SetDraining(true)
		time.Sleep(500 * time.Millisecond)
		log.Println("shutting down...")
		mgr.Close()
	}()
	mgr.Wait()
}

func applyProfile(ps *ProfileSettings, maxC, maxU, rate, bw, idleSec, lifeSec, maxDial int, quiet bool) (
	int, int, int, int, time.Duration, time.Duration, int, bool,
) {
	outMaxC, outMaxU, outRate := traffic.DefaultMaxGlobal, traffic.DefaultMaxPerTok, 20
	outBW, outDial := 0, 256
	outIdle, outLife := 15*time.Minute, 24*time.Hour
	outQ := quiet
	if ps != nil {
		outMaxC, outMaxU, outRate = ps.MaxConn, ps.MaxConnUser, ps.RateIP
		outBW, outDial = ps.BandwidthUser, ps.MaxDial
		outIdle, outLife = ps.IdleTimeout, ps.MaxLife
		if ps.Quiet {
			outQ = true
		}
		if quiet {
			outQ = true
		}
		if ps.MaxDial <= 0 {
			outDial = 256
		}
	}
	if maxC > 0 {
		outMaxC = maxC
	}
	if maxU > 0 {
		outMaxU = maxU
	}
	if rate > 0 {
		outRate = rate
	}
	if bw >= 0 {
		outBW = bw
	}
	if idleSec > 0 {
		outIdle = time.Duration(idleSec) * time.Second
	}
	if lifeSec >= 0 {
		outLife = time.Duration(lifeSec) * time.Second
	}
	if maxDial > 0 {
		outDial = maxDial
	}
	return outMaxC, outMaxU, outRate, outBW, outIdle, outLife, outDial, outQ
}

// StandardHTTPSPorts standard HTTPS candidate ports in priority order (Cloudflare & IANA standard HTTPS ports)
var StandardHTTPSPorts = []int{443, 8443, 2053, 2083, 2087, 2096}

// IsPortAvailable checks if a TCP port can be bound on 0.0.0.0
func IsPortAvailable(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

// AutoProbeHTTPSPort probes the preferred port (e.g. 443) and falls back to StandardHTTPSPorts
func AutoProbeHTTPSPort(preferred int) int {
	if IsPortAvailable(preferred) {
		return preferred
	}
	for _, cand := range StandardHTTPSPorts {
		if cand == preferred {
			continue
		}
		if IsPortAvailable(cand) {
			log.Printf("[PORT] Preferred port %d is occupied. Auto-selected standard HTTPS candidate port: %d", preferred, cand)
			return cand
		}
	}
	return preferred
}

func resolvePorts(listen, portsLegacy string) []int {
	if listen == "auto" || listen == ":auto" || portsLegacy == "auto" {
		return []int{AutoProbeHTTPSPort(443)}
	}
	if listen != "" {
		s := strings.TrimSpace(listen)
		if i := strings.LastIndex(s, ":"); i >= 0 {
			s = s[i+1:]
		}
		if p := config.ParsePorts(s); len(p) > 0 {
			return p
		}
	}
	if portsLegacy != "" {
		if p := config.ParsePorts(portsLegacy); len(p) > 0 {
			return p
		}
	}
	return []int{443}
}

func setupLogging(file, format string) error { return applogInit(file, format) }

func applyServerConfig(
	cfg *config.ServerFileConfig,
	listen, portsFlag, token, domain, sniFlag, autoCert, autoCertEmail, autoCertDir, certFile, keyFile, logFormat, logFile *string,
) {
	s := &cfg.Aero.Server
	if *listen == "" && *portsFlag == "" && len(s.Listen.Ports) > 0 {
		*portsFlag = joinPorts(s.Listen.Ports)
	}
	if *token == "" && len(s.Auth.Tokens) > 0 {
		*token = s.Auth.Tokens[0].Token
	}
	if *domain == "" && *sniFlag == "" && s.ECH.PublicName != "" {
		*domain = s.ECH.PublicName
	}
	if *autoCert == "" && s.TLS.AutoCert.Domain != "" {
		*autoCert = s.TLS.AutoCert.Domain
	}
	if *autoCertEmail == "" && s.TLS.AutoCert.Email != "" {
		*autoCertEmail = s.TLS.AutoCert.Email
	}
	if *autoCertDir == "./certs" && s.TLS.AutoCert.CacheDir != "" {
		*autoCertDir = s.TLS.AutoCert.CacheDir
	}
	if *certFile == "" && s.TLS.CertFile != "" {
		*certFile = s.TLS.CertFile
	}
	if *keyFile == "" && s.TLS.KeyFile != "" {
		*keyFile = s.TLS.KeyFile
	}
	if *logFormat == "text" && s.Log.Format != "" {
		*logFormat = s.Log.Format
	}
	if *logFile == "" && s.Log.File != "" {
		*logFile = s.Log.File
	}
}

func joinPorts(ports []int) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = fmt.Sprintf("%d", p)
	}
	return strings.Join(parts, ",")
}

// RunEdge is an alias for RunServer.
func RunEdge() {
	RunServer()
}

// initMemoryLimit 自动探测宿主机/cgroup 真实物理内存，并设置 GOMEMLIMIT 软上限 (70%)，杜绝低配 VPS 宕机
func initMemoryLimit() {
	memBytes := detectAvailableMemory()
	if memBytes > 0 {
		limit := int64(float64(memBytes) * 0.70)
		debug.SetMemoryLimit(limit)
		log.Printf("[MEM] System memory %d MB detected, GOMEMLIMIT set to %d MB (70%% protection)", memBytes/(1024*1024), limit/(1024*1024))
	}
}

func detectAvailableMemory() int64 {
	// 1. cgroup v2
	if data, err := os.ReadFile("/sys/fs/cgroup/memory.max"); err == nil {
		s := strings.TrimSpace(string(data))
		if s != "max" && s != "" {
			if v, err := strconv.ParseInt(s, 10, 64); err == nil && v > 0 {
				return v
			}
		}
	}
	// 2. cgroup v1
	if data, err := os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"); err == nil {
		s := strings.TrimSpace(string(data))
		if v, err := strconv.ParseInt(s, 10, 64); err == nil && v > 0 && v < (1<<60) {
			return v
		}
	}
	// 3. Linux /proc/meminfo
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "MemTotal:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if kb, err := strconv.ParseInt(fields[1], 10, 64); err == nil && kb > 0 {
						return kb * 1024
					}
				}
			}
		}
	}
	return 0
}
