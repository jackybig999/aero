// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
)

// ServerConfig configures the AERO edge server
type ServerConfig struct {
	Listen        string `json:"listen"`         // e.g. ":443"
	Domain        string `json:"domain"`         // public domain / SNI
	Token         string `json:"token"`          // initial auth token (auto if empty)
	CertFile      string `json:"cert_file"`      // TLS cert PEM
	KeyFile       string `json:"key_file"`       // TLS key PEM
	DataDir       string `json:"data_dir"`       // data dir for tokens.json / client-sub.json
	AdminKey      string `json:"admin_key"`      // admin auth key
	Profile       string `json:"profile"`        // tiny|small|medium
	MaxConn       int    `json:"max_conn"`       // max tunnels global
	MaxConnUser   int    `json:"max_conn_user"`  // max tunnels per user
	RateIP        int    `json:"rate_ip"`        // new conns/s/IP
	BWUser        int    `json:"bw_user"`        // bytes/s per token
	AdvertiseHost string `json:"advertise_host"` // host in subscription
	CoverName     string `json:"cover_name"`     // cover site title
}

// Server is the unified edge server instance
type Server struct {
	cfg          ServerConfig
	validator    *Validator
	tokenStore   *TokenStore
	subStore     *SubStore
	connLimit    *ConnLimiter
	bwLimit      *BandwidthLimiter
	dialGuard    *DialGuard
	rateLimit    *RateLimiter
	quicServer   *QUICServer
	adminHandler *AdminHandler
	subHandler   *SubHandler

	tlsCert      *tls.Certificate
	httpServer   *http.Server
	tcpListener  net.Listener
	quicListener *quic.Listener

	startedAt time.Time
}

// MaskToken masks a token for safe logging (never print plaintext tokens)
func MaskToken(t string) string {
	if len(t) <= 8 {
		return "***"
	}
	return t[:4] + "…" + t[len(t)-4:]
}

// NewServer creates a new Server instance from ServerConfig
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Listen == "" {
		cfg.Listen = ":443"
	}
	if cfg.DataDir == "" {
		cfg.DataDir = "./data"
	}
	absDataDir, err := filepath.Abs(cfg.DataDir)
	if err != nil {
		absDataDir = cfg.DataDir
	}
	if err := os.MkdirAll(absDataDir, 0o755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	// 1. Validator & TokenStore (tokens.json)
	validator := NewValidator()
	tokenStore, err := OpenTokenStore(absDataDir, validator)
	if err != nil {
		return nil, fmt.Errorf("open token store: %w", err)
	}

	tok := cfg.Token
	if tok == "" {
		if list := tokenStore.List(); len(list) > 0 {
			tok = list[0].Token
		} else {
			tok = GenerateToken()
		}
	}
	if err := tokenStore.Ensure(tok, "default", 365*24*time.Hour); err != nil {
		return nil, fmt.Errorf("ensure token: %w", err)
	}

	// 2. TLS Certificate
	var cert *tls.Certificate
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		c, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load tls cert: %w", err)
		}
		cert = &c
	} else {
		dom := cfg.Domain
		if dom == "" {
			dom = "localhost"
		}
		c, err := generateSelfSignedCert(dom)
		if err != nil {
			return nil, fmt.Errorf("generate self-signed cert: %w", err)
		}
		cert = c
	}

	// 3. Subscriptions (sub_meta.json & client-sub.json)
	_, portStr, _ := net.SplitHostPort(cfg.Listen)
	tlsPort, _ := strconv.Atoi(portStr)
	if tlsPort <= 0 {
		tlsPort = 443
	}

	adv := cfg.AdvertiseHost
	if adv == "" {
		adv = cfg.Domain
	}
	if adv == "" {
		adv = "127.0.0.1"
	}

	sni := cfg.Domain
	if sni == "" {
		sni = "localhost"
	}

	subStore, _, err := BootstrapSubscription(absDataDir, adv, tlsPort, tok, sni, cert)
	if err != nil {
		return nil, fmt.Errorf("bootstrap subscription: %w", err)
	}

	// 4. Traffic & Flow Limiters
	maxConn := cfg.MaxConn
	if maxConn <= 0 {
		maxConn = DefaultMaxGlobal
	}
	maxConnUser := cfg.MaxConnUser
	if maxConnUser <= 0 {
		maxConnUser = DefaultMaxPerTok
	}
	connLimit := NewConnLimiter(maxConn, maxConnUser)
	bwLimit := NewBandwidthLimiter(cfg.BWUser)
	dialGuard := NewDialGuard(256)
	rateLimit := NewRateLimiter(cfg.RateIP)

	// 5. QUIC Server
	quicServer := NewQUICServer(validator, connLimit, bwLimit, dialGuard)

	// 6. Admin & Sub HTTP Handlers
	adminHandler := NewAdminHandler(cfg.AdminKey, validator, tokenStore, subStore, connLimit, bwLimit, dialGuard)
	subHandler := &SubHandler{Store: subStore}

	srv := &Server{
		cfg:          cfg,
		validator:    validator,
		tokenStore:   tokenStore,
		subStore:     subStore,
		connLimit:    connLimit,
		bwLimit:      bwLimit,
		dialGuard:    dialGuard,
		rateLimit:    rateLimit,
		quicServer:   quicServer,
		adminHandler: adminHandler,
		subHandler:   subHandler,
		tlsCert:      cert,
		startedAt:    time.Now(),
	}

	return srv, nil
}

// Start launches the TCP/TLS and QUIC servers
func (s *Server) Start() error {
	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{*s.tlsCert},
		NextProtos:   []string{"http/1.1"},
	}

	// 1. TCP/TLS Listener
	ln, err := tls.Listen("tcp", s.cfg.Listen, tlsCfg)
	if err != nil {
		return fmt.Errorf("tcp listen %s: %w", s.cfg.Listen, err)
	}
	s.tcpListener = ln

	s.httpServer = &http.Server{
		Handler:           s,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		_ = s.httpServer.Serve(ln)
	}()

	// 2. QUIC Listener
	quicLn, err := StartQUIC(s.cfg.Listen, tlsCfg, s.quicServer)
	if err != nil {
		_ = s.tcpListener.Close()
		return fmt.Errorf("quic listen %s: %w", s.cfg.Listen, err)
	}
	s.quicListener = quicLn

	log.Printf("[EDGE] Server started on %s (TLS + QUIC)", s.cfg.Listen)
	log.Printf("[EDGE] Subscriptions ready at /sub/%s (client-sub: %s/client-sub.json)", s.subStore.Secret(), s.subStore.Dir())
	log.Printf("[EDGE] Tokens loaded from %s (count: %d)", s.tokenStore.Path(), s.tokenStore.v.Count())

	return nil
}

// ServeHTTP routes HTTP requests to /admin, /sub, /health, or Cover page
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.adminHandler != nil && s.adminHandler.TryServe(w, r) {
		return
	}
	if s.subHandler != nil && s.subHandler.TryServe(w, r) {
		return
	}
	if r.URL.Path == "/health" || r.URL.Path == "/healthz" {
		writeJSON(w, map[string]any{
			"status":     "ok",
			"version":    Version,
			"protocol":   Protocol,
			"uptime_sec": time.Since(s.startedAt).Seconds(),
		})
		return
	}
	s.serveCover(w, r)
}

func (s *Server) serveCover(w http.ResponseWriter, r *http.Request) {
	title := s.cfg.CoverName
	if title == "" {
		title = "CloudEdge High-Performance CDN"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>%s</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0b1120; color: #f8fafc; text-align: center; padding-top: 15vh; margin: 0; }
        .card { background: #1e293b; border-radius: 12px; display: inline-block; padding: 40px 60px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
        h1 { font-size: 28px; margin-bottom: 8px; color: #38bdf8; }
        p { color: #94a3b8; font-size: 15px; margin: 4px 0; }
        .badge { display: inline-block; background: #0369a1; color: #e0f2fe; padding: 4px 12px; border-radius: 9999px; font-size: 12px; font-weight: bold; margin-top: 16px; }
    </style>
</head>
<body>
    <div class="card">
        <h1>%s</h1>
        <p>Global Anycast Acceleration Edge Node</p>
        <p>Operational Status: Normal</p>
        <div class="badge">HTTP/3 QUIC &amp; TLS 1.3 Enabled</div>
    </div>
</body>
</html>`, title, title)
}

// Close gracefully closes all listeners and servers
func (s *Server) Close() {
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = s.httpServer.Shutdown(ctx)
		cancel()
	}
	if s.tcpListener != nil {
		_ = s.tcpListener.Close()
	}
	if s.quicListener != nil {
		_ = s.quicListener.Close()
	}
}

// Run starts the edge server and blocks until SIGINT/SIGTERM, supporting SIGHUP reloads
func Run(cfg ServerConfig) error {
	server, err := NewServer(cfg)
	if err != nil {
		return err
	}
	if err := server.Start(); err != nil {
		return err
	}

	// SIGHUP reload of tokens.json
	hupCh := make(chan os.Signal, 1)
	notifyConfigReload(hupCh)
	go func() {
		for range hupCh {
			n, err := server.tokenStore.Reload()
			if err != nil {
				log.Printf("[RELOAD] tokens.json reload failed: %v", err)
			} else {
				log.Printf("[RELOAD] tokens.json reloaded successfully, active tokens: %d", n)
			}
		}
	}()

	// Graceful shutdown on SIGINT / SIGTERM
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigCh
	log.Printf("[EDGE] Received signal %v, shutting down gracefully...", sig)
	server.Close()
	log.Printf("[EDGE] Server stopped.")

	return nil
}

func generateSelfSignedCert(domain string) (*tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"AERO Edge Node"},
			CommonName:   domain,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(domain); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{domain, "localhost"}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
}
