// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/binary"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
)

//go:embed cover.html
var coverHTML []byte

//go:embed cover.css
var coverCSS []byte

// ServerConfig configures the AERO edge server
type ServerConfig struct {
	Listen                     string                        `json:"listen"`         // e.g. ":443"
	Domain                     string                        `json:"domain"`         // public domain / SNI
	Token                      string                        `json:"token"`          // initial auth token (auto if empty)
	CertFile                   string                        `json:"cert_file"`      // TLS cert PEM
	KeyFile                    string                        `json:"key_file"`       // TLS key PEM
	DataDir                    string                        `json:"data_dir"`       // data dir for tokens.json / client-sub.json
	AdminKey                   string                        `json:"admin_key"`      // admin auth key
	Profile                    string                        `json:"profile"`        // tiny|small|medium
	MaxConn                    int                           `json:"max_conn"`       // max tunnels global
	MaxConnUser                int                           `json:"max_conn_user"`  // max tunnels per user
	RateIP                     int                           `json:"rate_ip"`        // new conns/s/IP
	BWUser                     int                           `json:"bw_user"`        // bytes/s per token
	AdvertiseHost              string                        `json:"advertise_host"` // host in subscription
	CoverName                  string                        `json:"cover_name"`     // cover site title
	LineType                   string                        `json:"line_type,omitempty" yaml:"line_type"`
	ISPAffinity                string                        `json:"isp_affinity,omitempty" yaml:"isp_affinity"`
	IP                         string                        `json:"ip,omitempty" yaml:"ip"`
	AltPorts                   []int                         `json:"alt_ports,omitempty" yaml:"alt_ports"`
	AllowSelfSignedCertForTest bool                          `json:"-"`                        // 仅允许单元测试显式开启，生产环境严禁自签
	Role                       string                        `json:"role,omitempty"`           // single|ingress|egress, default single
	HopCredential              string                        `json:"hop_credential,omitempty"` // hop credential for multi-hop (strictly distinct from user token)
	NextHopAddr                string                        `json:"next_hop_addr,omitempty" yaml:"next_hop_addr"`
	NextHopSNI                 string                        `json:"next_hop_sni,omitempty" yaml:"next_hop_sni"`
	ECH                        string                        `json:"ech,omitempty" yaml:"ech"`
	EncryptedClientHelloKeys   []tls.EncryptedClientHelloKey `json:"-"` // ECH server keys (never serialised)
	ObfsPassword               string                        `json:"obfs_password,omitempty" yaml:"obfs_password"`
	FallbackObfsPasswords      []string                      `json:"fallback_obfs_passwords,omitempty" yaml:"fallback_obfs_passwords"`
	PaddingJitter              bool                          `json:"padding_jitter,omitempty" yaml:"padding_jitter"`
	AltListenPorts             []int                         `json:"alt_listen_ports,omitempty" yaml:"alt_listen_ports"`
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
	geoHandler   *GeoDataHandler

	ctx    context.Context
	cancel context.CancelFunc

	tlsCert          *tls.Certificate
	httpServer       *http.Server
	tcpListener      net.Listener
	quicListener     *quic.Listener
	altQuicListeners []*quic.Listener

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
	// 0. Multi-hop Role 与跳间凭证校验 (P7 规范)
	role := strings.ToLower(strings.TrimSpace(cfg.Role))
	if role == "" {
		role = "single"
	}
	if role != "single" && role != "ingress" && role != "egress" {
		return nil, fmt.Errorf("invalid server role %q: only single, ingress, egress allowed", cfg.Role)
	}
	cfg.Role = role

	if role == "ingress" || role == "egress" {
		if strings.TrimSpace(cfg.HopCredential) == "" {
			return nil, fmt.Errorf("hop credential required: multi-hop role %s requires valid hop credential (hop credential must not be empty and is strictly distinct from user token)", role)
		}
	}
	if role == "ingress" {
		if strings.TrimSpace(cfg.NextHopAddr) == "" && !cfg.AllowSelfSignedCertForTest {
			return nil, fmt.Errorf("next hop address required: ingress role requires valid next_hop_addr in production")
		}
	}

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
	walPath := filepath.Join(absDataDir, "nonce.wal")
	validator := NewValidator(walPath)
	tokenStore, err := OpenTokenStore(absDataDir, validator)
	if err != nil {
		return nil, fmt.Errorf("open token store: %w", err)
	}

	tok := cfg.Token
	if tok == "" {
		if list := tokenStore.List(); len(list) > 0 {
			tok = list[0].Token
		} else {
			var err error
			tok, err = GenerateToken()
			if err != nil {
				return nil, fmt.Errorf("bootstrap token: %w", err)
			}
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
		if !cfg.AllowSelfSignedCertForTest {
			return nil, fmt.Errorf("production edge server strictly requires valid TLS certificate (--cert and --key); self-signed cert is prohibited to prevent active probing")
		}
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

	cfg.Token = tok
	cfg.AdvertiseHost = adv
	cfg.Domain = sni
	subStore, _, err := BootstrapSubscription(cfg, cert)
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
	if cfg.AllowSelfSignedCertForTest {
		dialGuard.AllowLocal = true
	}
	rateLimit := NewRateLimiter(cfg.RateIP)

	// 5. QUIC Server
	quicServer := NewQUICServer(validator, connLimit, bwLimit, dialGuard, rateLimit)
	quicServer.SetServerConfig(&cfg)
	if cfg.AllowSelfSignedCertForTest {
		quicServer.SetAllowLoopbackForTest(true)
	}

	// 6. Admin & Sub HTTP Handlers
	adminHandler := NewAdminHandler(cfg.AdminKey, validator, tokenStore, subStore, connLimit, bwLimit, dialGuard)
	subHandler := &SubHandler{Store: subStore}

	// 7. GeoData Handler
	geoHandler := NewGeoDataHandler(cfg.DataDir)

	ctx, cancel := context.WithCancel(context.Background())

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
		geoHandler:   geoHandler,
		ctx:          ctx,
		cancel:       cancel,
		tlsCert:      cert,
		startedAt:    time.Now(),
	}

	if cfg.ObfsPassword != "" && len(cfg.FallbackObfsPasswords) > 0 {
		RegisterFallbackPasswords(cfg.ObfsPassword, cfg.FallbackObfsPasswords)
	}

	return srv, nil
}

// Start launches the TCP/TLS and QUIC servers
func (s *Server) Start() error {
	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{*s.tlsCert},
		NextProtos:   []string{"h2", "http/1.1"},
	}

	// ECH (Encrypted Client Hello) 阶段四规范：
	// 订阅驱动模式下，服务端 ECH 无须依赖公网 HTTPS RR (Type 65) 记录。
	// 1) Go 工具链版本满足（Go 1.26.0+ 原生 ECH 支持）；
	// 2) 配置中提供了有效的 EncryptedClientHelloKeys。
	// 缺任何一项，服务按普通 TLS 1.3 启动，日志明确打印 "ECH disabled"。禁止填充虚假 ECH 配置或伪造 GREASE。
	if !isGo126OrLater(runtime.Version()) {
		log.Printf("[EDGE] ECH disabled: toolchain version %s does not meet requirement (Go 1.26.0+ required)", runtime.Version())
	} else if len(s.cfg.EncryptedClientHelloKeys) == 0 {
		log.Printf("[EDGE] ECH disabled: no EncryptedClientHelloKeys provided in configuration")
	} else {
		tlsCfg.EncryptedClientHelloKeys = s.cfg.EncryptedClientHelloKeys
		log.Printf("[EDGE] ECH enabled for domain %s (keys count: %d)", s.cfg.Domain, len(s.cfg.EncryptedClientHelloKeys))
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
	s.quicServer.SetHandler(s)
	quicLn, err := StartQUIC(s.cfg.Listen, tlsCfg, s.quicServer, s.ctx)
	if err != nil {
		_ = s.tcpListener.Close()
		return fmt.Errorf("quic listen %s: %w", s.cfg.Listen, err)
	}
	s.quicListener = quicLn

	// 2b. Multi-port Hopping Alternative Listeners
	host := ""
	if h, _, herr := net.SplitHostPort(s.cfg.Listen); herr == nil {
		host = h
	}
	for _, port := range s.cfg.AltListenPorts {
		if port <= 0 || port > 65535 {
			continue
		}
		altAddr := net.JoinHostPort(host, strconv.Itoa(port))
		altLn, aerr := StartQUIC(altAddr, tlsCfg, s.quicServer, s.ctx)
		if aerr == nil {
			s.altQuicListeners = append(s.altQuicListeners, altLn)
			log.Printf("[EDGE] QUIC multi-port hopping listener active on %s", altAddr)
		} else {
			log.Printf("[EDGE] [WARN] Failed to bind alt QUIC port %s: %v", altAddr, aerr)
		}
	}

	if s.geoHandler != nil {
		s.geoHandler.StartCronUpdate(s.ctx)
	}

	log.Printf("[EDGE] Server started on %s (TLS + QUIC)", s.cfg.Listen)
	log.Printf("[EDGE] Subscriptions ready at /sub/%s (client-sub: %s/client-sub.json)", s.subStore.Secret(), s.subStore.Dir())
	log.Printf("[EDGE] Tokens loaded from %s (count: %d)", s.tokenStore.Path(), s.tokenStore.v.Count())

	return nil
}

// ServeHTTP routes HTTP requests to /admin, /sub, /health, /healthz, /assets/*, or Cover page
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Alt-Svc", `h3=":443"; ma=86400`)

	// 纯正 HTTP/3 门禁：TCP/443 仅作 Web 伪装站点，坚决禁用任何 TCP 代理或回退
	isQUIC := r.Context().Value(quicConnKey{}) != nil
	if r.Method == http.MethodConnect {
		if !isQUIC {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		s.quicServer.ServeDefault(w, r)
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == "/dns-query" {
		if !isQUIC {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		s.quicServer.ServeDefault(w, r)
		return
	}

	if s.geoHandler != nil && s.geoHandler.TryServe(w, r) {
		return
	}
	if s.adminHandler != nil && s.adminHandler.TryServe(w, r) {
		return
	}
	if s.subHandler != nil && s.subHandler.TryServe(w, r) {
		return
	}
	if r.URL.Path == "/healthz" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		return
	}
	if r.URL.Path == "/health" {
		reqKey := r.Header.Get("Aero-Admin-Key")
		if reqKey == "" {
			reqKey = r.URL.Query().Get("admin_key")
		}
		if s.cfg.AdminKey == "" || subtle.ConstantTimeCompare([]byte(reqKey), []byte(s.cfg.AdminKey)) != 1 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSON(w, map[string]any{
			"status":     "ok",
			"version":    Version,
			"protocol":   Protocol,
			"uptime_sec": time.Since(s.startedAt).Seconds(),
		})
		return
	}
	if strings.HasPrefix(r.URL.Path, "/assets/") {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(coverCSS)
		return
	}
	s.serveCover(w, r)
}

func (s *Server) serveCover(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	if s.cfg.CoverName != "" && s.cfg.CoverName != "AERO Edge Cloud" {
		body := bytes.ReplaceAll(coverHTML, []byte("AERO Edge Cloud"), []byte(s.cfg.CoverName))
		_, _ = w.Write(body)
		return
	}
	_, _ = w.Write(coverHTML)
}

// Close gracefully closes all listeners and servers
func (s *Server) Close() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.quicServer != nil {
		s.quicServer.Close()
	}
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
	for _, altLn := range s.altQuicListeners {
		if altLn != nil {
			_ = altLn.Close()
		}
	}
	s.altQuicListeners = nil
	if s.validator != nil {
		s.validator.Close()
	}
	if s.cfg.ObfsPassword != "" {
		RegisterFallbackPasswords(s.cfg.ObfsPassword, nil)
	}
}

// AltAddrs returns addresses of all active alternative QUIC listeners
func (s *Server) AltAddrs() []string {
	var res []string
	for _, ln := range s.altQuicListeners {
		if ln != nil {
			res = append(res, ln.Addr().String())
		}
	}
	return res
}

// Addr returns the QUIC listener address (or TCP listener address if QUIC is nil)
func (s *Server) Addr() string {
	if s.quicListener != nil {
		return s.quicListener.Addr().String()
	}
	if s.tcpListener != nil {
		return s.tcpListener.Addr().String()
	}
	return s.cfg.Listen
}

// QUICServer returns the underlying QUICServer instance
func (s *Server) QUICServer() *QUICServer {
	return s.quicServer
}

// SetNextHopDialerForTest sets custom NextHop TCP dialer on Server's QUICServer
func (s *Server) SetNextHopDialerForTest(d func(nextHopAddr, target, hopCred string) (net.Conn, error)) {
	if s.quicServer != nil {
		s.quicServer.SetNextHopDialerForTest(d)
	}
}

// SetNextHopUDPDialerForTest sets custom NextHop UDP dialer on Server's QUICServer
func (s *Server) SetNextHopUDPDialerForTest(d func(nextHopAddr, target, hopCred string) (net.Conn, error)) {
	if s.quicServer != nil {
		s.quicServer.SetNextHopUDPDialerForTest(d)
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

var httpsRRChecker func(domain string) bool

// SetHTTPSRRCheckerForTest 允许单元测试注入 HTTPS RR 记录探测模拟器
func SetHTTPSRRCheckerForTest(fn func(domain string) bool) {
	httpsRRChecker = fn
}

func checkDomainHasHTTPSRR(domain string) bool {
	if httpsRRChecker != nil {
		return httpsRRChecker(domain)
	}
	domain = strings.TrimSpace(domain)
	if domain == "" || domain == "localhost" || net.ParseIP(domain) != nil {
		return false
	}
	return queryHTTPSRR(domain)
}

func queryHTTPSRR(domain string) bool {
	c, err := net.DialTimeout("udp", "8.8.8.8:53", 1*time.Second)
	if err != nil {
		return false
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(1 * time.Second))

	req := buildType65Query(domain)
	if req == nil {
		return false
	}
	if _, err := c.Write(req); err != nil {
		return false
	}
	resp := make([]byte, 512)
	n, err := c.Read(resp)
	if err != nil || n < 12 {
		return false
	}
	ancount := binary.BigEndian.Uint16(resp[6:8])
	return ancount > 0
}

func buildType65Query(domain string) []byte {
	labels := strings.Split(strings.TrimSuffix(domain, "."), ".")
	if len(labels) == 0 {
		return nil
	}
	var buf bytes.Buffer
	buf.Write([]byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 {
			return nil
		}
		buf.WriteByte(byte(len(l)))
		buf.WriteString(l)
	}
	buf.WriteByte(0x00)
	buf.Write([]byte{0x00, 0x41, 0x00, 0x01}) // Type 65 (HTTPS), Class 1 (IN)
	return buf.Bytes()
}

func isGo126OrLater(ver string) bool {
	if !strings.HasPrefix(ver, "go") {
		return true
	}
	ver = strings.TrimPrefix(ver, "go")
	parts := strings.Split(ver, ".")
	if len(parts) < 2 {
		return false
	}
	major, err1 := strconv.Atoi(parts[0])
	if err1 != nil {
		return false
	}
	if major > 1 {
		return true
	}
	if major < 1 {
		return false
	}
	minorStr := parts[1]
	for i, c := range minorStr {
		if c < '0' || c > '9' {
			minorStr = minorStr[:i]
			break
		}
	}
	minor, err2 := strconv.Atoi(minorStr)
	if err2 != nil {
		return false
	}
	return minor >= 26
}
