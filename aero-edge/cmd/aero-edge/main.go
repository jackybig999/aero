// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// aero-edge — AERO 协议服务端 v1（多用户 · 小 VPS · 契约冻结）
//
//	aero-edge -token SECRET -listen :443 -domain example.com -profile small
//	aero-edge -version
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aero-protocol/aero-edge/internal/auth"
	"github.com/aero-protocol/aero-edge/internal/bwlimit"
	"github.com/aero-protocol/aero-edge/internal/certmgr"
	"github.com/aero-protocol/aero-edge/internal/config"
	"github.com/aero-protocol/aero-edge/internal/connlimit"
	"github.com/aero-protocol/aero-edge/internal/contextstore"
	"github.com/aero-protocol/aero-edge/internal/cover"
	"github.com/aero-protocol/aero-edge/internal/dialguard"
	"github.com/aero-protocol/aero-edge/internal/ech"
	"github.com/aero-protocol/aero-edge/internal/listener"
	"github.com/aero-protocol/aero-edge/internal/metrics"
	"github.com/aero-protocol/aero-edge/internal/profile"
	"github.com/aero-protocol/aero-edge/internal/ratelimit"
	"github.com/aero-protocol/aero-edge/internal/tokenstore"
	"github.com/aero-protocol/aero-edge/internal/version"
)

func main() {
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
	logFile := flag.String("log-file", "", "log file")
	logFormat := flag.String("log-format", "text", "text|json")
	configPath := flag.String("config", "", "optional config")
	quiet := flag.Bool("q", false, "quiet logs")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "AERO edge v%s — multi-user protocol server\n\n", version.Version)
		fmt.Fprintf(os.Stderr, "  aero-edge -token SECRET -listen :443 -domain edge.example.com -profile small\n\n")
		fmt.Fprintf(os.Stderr, "Admin: GET /admin/version|/status  GET/POST/DELETE /admin/tokens  POST /admin/reload\n")
		fmt.Fprintf(os.Stderr, "SIGHUP: reload tokens.json\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *showVer {
		fmt.Printf("aero-edge %s protocol=%s api_level=%d\n", version.Version, version.Protocol, version.APILevel)
		return
	}

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

	ps := profile.Get(*profName)
	maxC, maxU, rate, bw, idle, life, dialN, q := applyProfile(ps, *maxConn, *maxConnUser, *rateIP, *bwUser, *idleSec, *lifeSec, *maxDial, *quiet)

	ports := resolvePorts(*listen, *portsFlag)
	tlsPorts, plainPorts, quicPorts := config.ClassifyPorts(ports)
	if len(quicPorts) > 0 {
		log.Printf("[LISTEN] QUIC ports ignored")
		quicPorts = nil
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
	tokStore, err := tokenstore.Open(dataDirResolved, validator)
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

	var certSource certmgr.Source
	switch {
	case *autoCert != "":
		certSource = certmgr.LetsEncrypt
	case *certFile != "" && *keyFile != "":
		certSource = certmgr.Manual
	default:
		certSource = certmgr.SelfSigned
	}
	certCfg := certmgr.Config{
		Source: certSource, CertFile: *certFile, KeyFile: *keyFile,
		Domains: []string{publicName}, CacheDir: *autoCertDir, Email: *autoCertEmail,
	}
	if *autoCert != "" {
		certCfg.Domains = []string{*autoCert, publicName}
	}
	certManager, err := certmgr.NewManager(certCfg)
	if err != nil {
		log.Fatalf("cert: %v", err)
	}

	serverCfg := &config.ServerConfig{
		TLSPorts: tlsPorts, PlainPorts: plainPorts, QUICPorts: quicPorts,
		TLSCert: certManager.Certificate(), GetCertificate: certManager.GetCertificate,
	}
	echMgr := ech.NewManager(publicName)
	if _, err := echMgr.GenerateKey(); err != nil {
		log.Printf("[ECH] %v", err)
	}

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
	subStore, dataDirResolved, err := bootstrapSubscription(*dataDir, adv, listenPort, tok, publicName, certManager.Certificate())
	if err != nil {
		log.Fatalf("subscription: %v", err)
	}

	reg := metrics.NewRegistry()
	cl := connlimit.New(maxC, maxU)
	rl := ratelimit.New(rate)
	bl := bwlimit.New(bw)
	dg := dialguard.New(dialN)
	coverSite := cover.New(cover.Config{SiteName: *coverName, Enabled: true})

	handler := NewEdgeHandler(HandlerOptions{
		Validator: validator, ECH: echMgr, ACME: certManager.ACMEHandler(),
		Metrics: reg, ContextStore: ctxStore, SubStore: subStore, Cover: coverSite,
		ConnLimit: cl, RateLimit: rl, BWLimit: bl, DialGuard: dg, TokenStore: tokStore,
		AdminKey: *adminKey, IdleTimeout: idle, MaxLife: life, Quiet: q,
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
		version.Version, profLabel, tlsPorts, cl.MaxGlobal(), cl.MaxPerTok(), rate, bw, idle, life, dialN)
	log.Printf("token=%s tokens=%s data=%s", tok, tokStore.Path(), dataDirResolved)
	log.Printf("sub=/sub/%s admin=/admin/*", subStore.Secret())

	// SIGHUP 热重载 tokens（Windows 仅 Admin POST /admin/reload）
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

func applyProfile(ps *profile.Settings, maxC, maxU, rate, bw, idleSec, lifeSec, maxDial int, quiet bool) (
	int, int, int, int, time.Duration, time.Duration, int, bool,
) {
	outMaxC, outMaxU, outRate := connlimit.DefaultMaxGlobal, connlimit.DefaultMaxPerTok, 20
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

func resolvePorts(listen, portsLegacy string) []int {
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
	return []int{8443}
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
