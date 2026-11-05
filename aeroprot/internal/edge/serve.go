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
	"errors"
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
	"sync"
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
	IPv6Prefix                 string                        `json:"ipv6_prefix,omitempty" yaml:"ipv6_prefix"`
	GlobalTUNDevice            string                        `json:"global_tun_device,omitempty" yaml:"global_tun_device"`
	WarpProxy                  string                        `json:"warp_proxy,omitempty" yaml:"warp_proxy"`
	WarpAll                    bool                          `json:"warp_all,omitempty" yaml:"warp_all"`
}

// Server is the unified edge server instance
type Server struct {
	cfg              ServerConfig
	validator        *Validator
	tokenStore       *TokenStore
	subStore         *SubStore
	connLimit        *ConnLimiter
	bwLimit          *BandwidthLimiter
	dialGuard        *DialGuard
	rateLimit        *RateLimiter
	quicServer       *QUICServer
	adminHandler     *AdminHandler
	subHandler       *SubHandler
	geoHandler       *GeoDataHandler
	consoleHandler   *ConsoleHandler
	metricsCollector *MetricsCollector
	purityEngine     *PurityEngine
	warpInstaller    *WarpInstaller

	ctx    context.Context
	cancel context.CancelFunc

	certLoader       *DynamicCertLoader
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

	// 2. TLS Certificate & ACME Auto-Discovery
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		candidates := make([]string, 0, 2)
		if cfg.Domain != "" {
			candidates = append(candidates, cfg.Domain)
		}
		if cfg.AdvertiseHost != "" && cfg.AdvertiseHost != cfg.Domain {
			candidates = append(candidates, cfg.AdvertiseHost)
		}
		if certPath, keyPath, found := DiscoverACMECert(candidates...); found {
			log.Printf("[EDGE] Auto-discovered ACME certificate: cert=%s, key=%s", certPath, keyPath)
			cfg.CertFile = certPath
			cfg.KeyFile = keyPath
			if cfg.Domain == "" && len(candidates) > 0 {
				cfg.Domain = candidates[0]
			}
		}
	}

	var certLoader *DynamicCertLoader
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		c, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load tls cert: %w", err)
		}
		certLoader = NewDynamicCertLoader(cfg.CertFile, cfg.KeyFile, &c)
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
		certLoader = NewDynamicCertLoader("", "", c)
	}
	cert := certLoader.CurrentCert()

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

	// 3b. Sync user tokens from subStore into tokenStore and validator
	if subStore != nil && tokenStore != nil {
		for _, u := range subStore.ListUserSubs() {
			if u.Token == "" {
				continue
			}
			ttl := 100 * 365 * 24 * time.Hour
			if u.ExpireAt > 0 {
				rem := time.Until(time.Unix(u.ExpireAt, 0))
				if rem > 0 {
					ttl = rem
				} else {
					continue
				}
			}
			if err := tokenStore.Ensure(u.Token, "user:"+u.Slug, ttl); err != nil {
				log.Printf("[EDGE] Warning: failed to sync user token %s (%s): %v", MaskToken(u.Token), u.Slug, err)
			}
		}
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

	// 4b. 智能探测/配置 Cloudflare WARP SOCKS5 代理
	warpProxy := strings.TrimSpace(cfg.WarpProxy)
	if warpProxy == "" {
		for _, candWarp := range []string{"127.0.0.1:40000", "127.0.0.1:1080"} {
			if c, err := net.DialTimeout("tcp", candWarp, 150*time.Millisecond); err == nil {
				_ = c.Close()
				warpProxy = candWarp
				log.Printf("[WARP] Auto-detected local Cloudflare WARP SOCKS5 proxy at %s, AI & Google unblocking active!", candWarp)
				break
			}
		}
	} else {
		log.Printf("[WARP] Explicit Cloudflare WARP SOCKS5 proxy configured at %s, AI unblocking active (all=%v)", warpProxy, cfg.WarpAll)
	}
	if warpProxy != "" {
		dialGuard.SetWarpProxy(warpProxy, cfg.WarpAll)
	}

	rateLimit := NewRateLimiter(cfg.RateIP)

	// 5. QUIC Server
	ipv6Prefix := strings.TrimSpace(cfg.IPv6Prefix)
	if ipv6Prefix == "" && !cfg.AllowSelfSignedCertForTest {
		if prefix, err := ProbeHostPublicIPv6(); err == nil {
			ipv6Prefix = prefix.String()
			log.Printf("[EDGE] Auto-probed public routed IPv6 prefix on host: %s", ipv6Prefix)
		} else {
			log.Printf("[EDGE] No public IPv6 detected on host (%v); running in IPv4-only mode", err)
		}
	}
	quicServer := NewQUICServerWithIPv6Prefix(validator, connLimit, bwLimit, dialGuard, rateLimit, ipv6Prefix)
	quicServer.SetServerConfig(&cfg)
	if cfg.AllowSelfSignedCertForTest {
		quicServer.SetAllowLoopbackForTest(true)
	}
	if strings.TrimSpace(cfg.GlobalTUNDevice) != "" {
		if err := quicServer.AttachGlobalTunnelDeviceByName(context.Background(), strings.TrimSpace(cfg.GlobalTUNDevice)); err != nil {
			quicServer.Close()
			return nil, fmt.Errorf("attach configured global TUN: %w", err)
		}
	}

	// 6. Admin & Sub HTTP Handlers
	adminHandler := NewAdminHandler(cfg.AdminKey, validator, tokenStore, subStore, connLimit, bwLimit, dialGuard)
	subHandler := &SubHandler{Store: subStore}

	// 7. GeoData Handler
	geoHandler := NewGeoDataHandler(cfg.DataDir)

	// 8. Console, Sysinfo, Purity & WARP Installer (Milestone 3)
	metricsCollector := NewMetricsCollector(2 * time.Second)
	purityEngine := NewPurityEngine(warpProxy)
	warpInstaller := NewWarpInstaller(dialGuard)

	ctx, cancel := context.WithCancel(context.Background())

	srv := &Server{
		cfg:              cfg,
		validator:        validator,
		tokenStore:       tokenStore,
		subStore:         subStore,
		connLimit:        connLimit,
		bwLimit:          bwLimit,
		dialGuard:        dialGuard,
		rateLimit:        rateLimit,
		quicServer:       quicServer,
		adminHandler:     adminHandler,
		subHandler:       subHandler,
		geoHandler:       geoHandler,
		metricsCollector: metricsCollector,
		purityEngine:     purityEngine,
		warpInstaller:    warpInstaller,
		ctx:              ctx,
		cancel:           cancel,
		certLoader:       certLoader,
		tlsCert:          cert,
		startedAt:        time.Now(),
	}

	consoleHandler := NewConsoleHandler(
		cfg.AdminKey,
		srv,
		dialGuard,
		tokenStore,
		subStore,
		metricsCollector,
		purityEngine,
		warpInstaller,
		srv.serveCover,
	)
	srv.consoleHandler = consoleHandler

	if cfg.ObfsPassword != "" && len(cfg.FallbackObfsPasswords) > 0 {
		RegisterFallbackPasswords(cfg.ObfsPassword, cfg.FallbackObfsPasswords)
	}

	return srv, nil
}

// ConsoleHandler returns the Web Console handler
func (s *Server) ConsoleHandler() *ConsoleHandler { return s.consoleHandler }

// MetricsCollector returns the hardware metrics collector
func (s *Server) MetricsCollector() *MetricsCollector { return s.metricsCollector }

// PurityEngine returns the IP cleanliness engine
func (s *Server) PurityEngine() *PurityEngine { return s.purityEngine }

// WarpInstaller returns the Cloudflare WARP installer
func (s *Server) WarpInstaller() *WarpInstaller { return s.warpInstaller }

// CertLoader returns the server's dynamic cert loader
func (s *Server) CertLoader() *DynamicCertLoader {
	return s.certLoader
}

// CurrentCert returns the active TLS certificate
func (s *Server) CurrentCert() *tls.Certificate {
	if s.certLoader != nil {
		return s.certLoader.CurrentCert()
	}
	return s.tlsCert
}

// GetCertificateDynamic implements dynamic certificate retrieval tracking ModTime
func (s *Server) GetCertificateDynamic(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if s.certLoader != nil {
		return s.certLoader.GetCertificate(hello)
	}
	if s.tlsCert != nil {
		return s.tlsCert, nil
	}
	return nil, fmt.Errorf("no certificate available")
}

// Start launches the TCP/TLS and QUIC servers
func (s *Server) Start() error {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"},
	}
	if s.certLoader != nil {
		tlsCfg.GetCertificate = s.certLoader.GetCertificate
	} else if s.tlsCert != nil {
		tlsCfg.Certificates = []tls.Certificate{*s.tlsCert}
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

	// 1. TCP/TLS Listener (支持 443/8443 端口被第三方业务占用时进程内无损智能轮试自愈)
	ln, err := tls.Listen("tcp", s.cfg.Listen, tlsCfg)
	if err != nil {
		if isAddrInUse(err) {
			rotatedLn, newAddr, rerr := tryPortFallbackTCP(s.cfg.Listen, tlsCfg)
			if rerr == nil {
				log.Printf("[EDGE] [WARN] Listen address %s already in use (e.g. 443/8443 occupied), in-process auto-fallback switched to %s", s.cfg.Listen, newAddr)
				ln = rotatedLn
				s.cfg.Listen = newAddr
				if h, pStr, herr := net.SplitHostPort(newAddr); herr == nil {
					if pNum, perr := strconv.Atoi(pStr); perr == nil && s.subStore != nil {
						_ = s.subStore.UpdatePrimaryPort(pNum, h)
					}
				}
			} else {
				return fmt.Errorf("tcp listen %s: %w", s.cfg.Listen, err)
			}
		} else {
			return fmt.Errorf("tcp listen %s: %w", s.cfg.Listen, err)
		}
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
	if s.metricsCollector != nil {
		s.metricsCollector.Start(s.ctx)
	}

	log.Printf("[EDGE] Server started on %s (TLS + QUIC)", s.cfg.Listen)
	log.Printf("[EDGE] Subscriptions ready at /sub/%s (client-sub: %s/client-sub.json)", s.subStore.Secret(), s.subStore.Dir())
	log.Printf("[EDGE] Tokens loaded from %s (count: %d)", s.tokenStore.Path(), s.tokenStore.v.Count())
	if s.cfg.AdminKey != "" {
		log.Printf("[EDGE] Web Console ready at /console?key=%s", MaskToken(s.cfg.AdminKey))
	} else {
		log.Printf("[EDGE] Web Console ready at /console (loopback only)")
	}

	return nil
}

// ServeHTTP routes HTTP requests to /console, /admin, /sub, /health, /healthz, /assets/*, or Cover page
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
	if s.consoleHandler != nil && s.consoleHandler.TryServe(w, r) {
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
	if s.dialGuard != nil {
		s.dialGuard.Close()
	}
	if s.metricsCollector != nil {
		s.metricsCollector.Stop()
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

// DynamicCertLoader manages dynamic certificate reloading based on file ModTime
type DynamicCertLoader struct {
	mu          sync.RWMutex
	certFile    string
	keyFile     string
	certModTime time.Time
	cachedCert  *tls.Certificate
}

// NewDynamicCertLoader creates a new DynamicCertLoader
func NewDynamicCertLoader(certFile, keyFile string, initialCert *tls.Certificate) *DynamicCertLoader {
	var modTime time.Time
	if certFile != "" {
		if fi, err := os.Stat(certFile); err == nil {
			modTime = fi.ModTime()
		}
	}
	return &DynamicCertLoader{
		certFile:    certFile,
		keyFile:     keyFile,
		certModTime: modTime,
		cachedCert:  initialCert,
	}
}

// CurrentCert returns the active cached certificate
func (d *DynamicCertLoader) CurrentCert() *tls.Certificate {
	if d == nil {
		return nil
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.cachedCert
}

// CertModTime returns the last recorded ModTime of the certificate file
func (d *DynamicCertLoader) CertModTime() time.Time {
	if d == nil {
		return time.Time{}
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.certModTime
}

// GetCertificate dynamically returns the certificate, reloading if the certificate file has updated
func (d *DynamicCertLoader) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if d == nil {
		return nil, fmt.Errorf("nil dynamic cert loader")
	}

	d.mu.RLock()
	certFile := d.certFile
	keyFile := d.keyFile
	modTime := d.certModTime
	cached := d.cachedCert
	d.mu.RUnlock()

	// If no certFile is specified (e.g. in-memory test cert), return cached certificate
	if certFile == "" {
		if cached != nil {
			return cached, nil
		}
		return nil, fmt.Errorf("no certificate loaded")
	}

	fi, err := os.Stat(certFile)
	if err != nil {
		// Fallback to cached cert if stat fails to avoid dropping active connections
		if cached != nil {
			return cached, nil
		}
		return nil, fmt.Errorf("stat cert file %s: %w", certFile, err)
	}

	if !fi.ModTime().After(modTime) {
		if cached != nil {
			return cached, nil
		}
	}

	// File updated or no cached cert: reload under write lock
	d.mu.Lock()
	defer d.mu.Unlock()

	if fi.ModTime().After(d.certModTime) || d.cachedCert == nil {
		newCert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Printf("[EDGE] [WARN] Dynamic certificate reload failed for %s (keeping existing cert): %v", certFile, err)
			if d.cachedCert != nil {
				return d.cachedCert, nil
			}
			return nil, fmt.Errorf("reload x509 keypair: %w", err)
		}
		d.cachedCert = &newCert
		d.certModTime = fi.ModTime()
		log.Printf("[EDGE] TLS certificate hot-reloaded successfully from %s (modTime: %v)", certFile, d.certModTime)
	}
	return d.cachedCert, nil
}

// DiscoverACMECert searches standard acme.sh directories for fullchain.cer and key
func DiscoverACMECert(domains ...string) (certFile, keyFile string, found bool) {
	var baseDirs []string
	if custom := strings.TrimSpace(os.Getenv("ACME_HOME")); custom != "" {
		baseDirs = append(baseDirs, custom, filepath.Join(custom, ".acme.sh"))
	}
	baseDirs = append(baseDirs, "/root/.acme.sh")
	if home := strings.TrimSpace(os.Getenv("HOME")); home != "" {
		baseDirs = append(baseDirs, filepath.Join(home, ".acme.sh"), home)
	}
	if userHome, err := os.UserHomeDir(); err == nil && strings.TrimSpace(userHome) != "" {
		baseDirs = append(baseDirs, filepath.Join(userHome, ".acme.sh"))
	}
	return DiscoverACMECertIn(baseDirs, domains...)
}

// DiscoverACMECertIn searches specified base directories for domain certificates
func DiscoverACMECertIn(baseDirs []string, domains ...string) (certFile, keyFile string, found bool) {
	seenDomains := make(map[string]bool)
	var candidateDomains []string
	for _, d := range domains {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if h, _, err := net.SplitHostPort(d); err == nil {
			d = h
		}
		d = strings.Trim(d, "[]")
		if d == "" || d == "localhost" || d == "127.0.0.1" || d == "::1" || net.ParseIP(d) != nil {
			continue
		}
		if !seenDomains[d] {
			seenDomains[d] = true
			candidateDomains = append(candidateDomains, d)
		}
	}

	seenBases := make(map[string]bool)
	for _, base := range baseDirs {
		base = strings.TrimSpace(base)
		if base == "" || seenBases[base] {
			continue
		}
		seenBases[base] = true

		for _, dom := range candidateDomains {
			subDirs := []string{dom + "_ecc", dom}
			for _, sub := range subDirs {
				dirPath := filepath.Join(base, sub)
				fi, err := os.Stat(dirPath)
				if err != nil || !fi.IsDir() {
					continue
				}

				certCandidates := []string{
					filepath.Join(dirPath, "fullchain.cer"),
					filepath.Join(dirPath, "fullchain.pem"),
					filepath.Join(dirPath, "cert.pem"),
				}
				var foundCert string
				for _, cp := range certCandidates {
					if cfi, err := os.Stat(cp); err == nil && !cfi.IsDir() && cfi.Size() > 0 {
						foundCert = cp
						break
					}
				}

				keyCandidates := []string{
					filepath.Join(dirPath, dom+".key"),
					filepath.Join(dirPath, "privkey.key"),
					filepath.Join(dirPath, "privkey.pem"),
					filepath.Join(dirPath, "key.pem"),
				}
				var foundKey string
				for _, kp := range keyCandidates {
					if kfi, err := os.Stat(kp); err == nil && !kfi.IsDir() && kfi.Size() > 0 {
						foundKey = kp
						break
					}
				}

				if foundCert != "" && foundKey != "" {
					return foundCert, foundKey, true
				}
			}
		}
	}

	return "", "", false
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

func isAddrInUse(err error) bool {
	if err == nil {
		return false
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		var sysErr *os.SyscallError
		if errors.As(opErr.Err, &sysErr) {
			if errors.Is(sysErr.Err, syscall.EADDRINUSE) {
				return true
			}
		}
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "address already in use") ||
		strings.Contains(errStr, "only one usage of each socket address")
}

// tryPortFallbackTCP probes standard HTTPS candidate ports sequentially (8443, 2053, 2083, 2087, 2096, 10443)
// and returns the first available listener whose TCP and UDP ports are both free.
func tryPortFallbackTCP(initialListen string, tlsCfg *tls.Config) (net.Listener, string, error) {
	host, portStr, err := net.SplitHostPort(initialListen)
	if err != nil {
		host = ""
		portStr = strings.TrimPrefix(initialListen, ":")
	}
	initPort, _ := strconv.Atoi(portStr)

	// Tier 1 (标准 HTTPS 候选池，优先 2083/2087) + Tier 2 (自治高位避让候选池)
	candidates := StandardCandidatePorts
	for _, cand := range candidates {
		if cand == initPort {
			continue
		}
		candAddr := net.JoinHostPort(host, strconv.Itoa(cand))

		// Pre-flight check: ensure UDP port is also unbound for QUIC
		uconn, uerr := net.ListenPacket("udp", candAddr)
		if uerr != nil {
			continue
		}
		_ = uconn.Close()

		ln, terr := tls.Listen("tcp", candAddr, tlsCfg)
		if terr == nil {
			return ln, candAddr, nil
		}
	}
	return nil, "", fmt.Errorf("all fallback candidate ports %v are in use", candidates)
}
