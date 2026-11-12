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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	// C3 签名 token（api/token.md）：开关与 sub 的签发公钥（kid → 32 字节 Ed25519 公钥 base64）。
	AuthSignedToken bool              `json:"auth_signed_token,omitempty" yaml:"auth_signed_token"`
	TokenIssuers    map[string]string `json:"token_issuers,omitempty" yaml:"token_issuers"`
	// C6 只读接口（api/edge-public.yaml）：开关、计量只读密钥（32 字节随机 hex，开启时自动生成并持久化）、
	// 节点稳定标识（不是域名）。关闭时不计量、不生成。
	UsageAPI    bool   `json:"usage_api,omitempty" yaml:"usage_api"`
	MeteringKey string `json:"metering_key,omitempty" yaml:"metering_key"`
	NodeID      string `json:"node_id,omitempty" yaml:"node_id"`
	// DrainTimeoutSec 是收到停止信号后的排空上限（秒，L0 §8.6）；0 表示默认 15 秒。
	DrainTimeoutSec int `json:"drain_timeout,omitempty"`
	// ConfigPath 是 edge 持久化自身配置的文件路径，仅由 cmd/edge 显式设置。
	// 为空时 NewServer 不读写任何宿主配置文件（测试与嵌入使用）。
	ConfigPath string `json:"-"`
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

	ctx    context.Context
	cancel context.CancelFunc

	certLoader       *DynamicCertLoader
	tlsCert          *tls.Certificate
	httpServer       *http.Server
	tcpListener      net.Listener
	quicListener     *quic.Listener
	altQuicListeners []*quic.Listener

	startedAt time.Time

	instanceLock *instanceLock
	hostStateDir string      // 非空：已修改宿主（规则、ip_forward），Close 时按该目录的状态日志还原
	usageMeter   *UsageMeter // C6 计量；nil 表示 usage_api 关闭
	usageAPI     *usageAPI
	usageDone    chan struct{} // 计量落盘协程退出
	warpMu       sync.Mutex    // 串行化 WARP 开关的修改与持久化

	// ready 为真表示可以接流量：Start 完成后置位，排空开始时清除（/readyz）。
	ready atomic.Bool
}

// isLoopbackRemote 判断请求来源是否为本机回环地址。
func isLoopbackRemote(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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
		if runtime.GOOS == "linux" && os.Geteuid() == 0 {
			cfg.DataDir = "/var/lib/aero"
		} else {
			cfg.DataDir = "./data"
		}
	}
	absDataDir, err := filepath.Abs(cfg.DataDir)
	if err != nil {
		absDataDir = cfg.DataDir
	}
	if err := os.MkdirAll(absDataDir, 0o755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	// 同一数据目录只允许一个实例（ADR-0005）；构造失败的所有路径都释放锁。
	lock, err := acquireInstanceLock(absDataDir)
	if err != nil {
		return nil, err
	}
	constructed := false
	defer func() {
		if !constructed {
			_ = lock.release()
		}
	}()

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

	// 2. TLS 证书：未显式配置时，从系统 acme.sh / certbot 的默认位置查找（只读）。
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		dirs := systemCertDirs()
		var found bool
		for _, d := range []string{cfg.Domain, cfg.AdvertiseHost} {
			if d = normalizeCertDomain(d); d == "" {
				continue
			}
			if c, ok := findSystemCert(dirs, d, time.Now()); ok {
				cfg.CertFile, cfg.KeyFile, found = c.CertFile, c.KeyFile, true
				break
			}
		}
		if !found && normalizeCertDomain(cfg.Domain) == "" {
			if c, ok := findSystemCert(dirs, "", time.Now()); ok { // 未配置域名：采用宿主上的有效证书及其域名
				cfg.CertFile, cfg.KeyFile, cfg.Domain, found = c.CertFile, c.KeyFile, c.Domain, true
			}
		}
		if found {
			log.Printf("[EDGE] using system certificate %s (domain %s)", cfg.CertFile, cfg.Domain)
		} else if !cfg.AllowSelfSignedCertForTest {
			return nil, errNoSystemCert(normalizeCertDomain(cfg.Domain), dirs)
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

	// 2b. 端口轮试（ADR-0005）：只在启动时选择一次，按契约列表 StandardCandidatePorts 顺序；
	// 选定的地址随配置持久化，下次启动优先沿用。
	if addr, moved := selectListenAddr(cfg.Listen, StandardCandidatePorts, checkPortAvailable); moved {
		log.Printf("[EDGE] [PORT] %s is occupied by another program; using %s", cfg.Listen, addr)
		cfg.Listen = addr
	}

	// 2c. AdminKey 自治生成与持久化保底
	if cfg.AdminKey == "" {
		if existingKey := loadExistingAdminKey(cfg.ConfigPath); existingKey != "" {
			cfg.AdminKey = existingKey
		} else {
			key, err := generateSecureAdminKey()
			if err != nil {
				return nil, fmt.Errorf("generate admin key: %w", err)
			}
			cfg.AdminKey = key
			// 不在日志中打印密钥（PROJECT_RULES：密钥与凭据不得写入日志）。
			if cfg.ConfigPath != "" {
				log.Printf("[EDGE] [AUTH] No AdminKey configured; generated one (%s) and stored it in %s", MaskToken(key), cfg.ConfigPath)
			} else {
				log.Printf("[EDGE] [AUTH] No AdminKey configured; generated an ephemeral key (%s). Set --admin-key to make it persistent", MaskToken(key))
			}
		}
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

	if cfg.UsageAPI {
		if err := ensureUsageIdentity(&cfg); err != nil {
			return nil, err
		}
	}

	cfg.Token = tok
	cfg.AdvertiseHost = adv
	cfg.Domain = sni
	subStore, _, err := BootstrapSubscription(cfg, cert)
	if err != nil {
		return nil, fmt.Errorf("bootstrap subscription: %w", err)
	}
	if err := persistServerConfig(cfg); err != nil {
		log.Printf("[EDGE] [WARN] persist config: %v", err)
	}

	// 3b. Sync user tokens from subStore into tokenStore and validator
	syncUserTokensFromSubs(subStore, tokenStore)

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

	// 4b. WARP 只在显式配置时启用（ADR-0006）。不探测本机端口：本机上任何恰好监听
	// 40000/1080 的服务都会被误当作出口并接管流量。
	warpProxy := strings.TrimSpace(cfg.WarpProxy)
	if warpProxy != "" {
		log.Printf("[WARP] Configured WARP proxy %s (all=%v)", warpProxy, cfg.WarpAll)
		dialGuard.SetWarpProxy(warpProxy, cfg.WarpAll)
	}

	rateLimit := NewRateLimiter(cfg.RateIP)

	// 4c. C6 计量（usage_api）
	var usageMeter *UsageMeter
	if cfg.UsageAPI {
		if usageMeter, err = OpenUsageMeter(filepath.Join(absDataDir, "usage.db")); err != nil {
			return nil, fmt.Errorf("usage_api: %w", err)
		}
		defer func() {
			if !constructed {
				_ = usageMeter.Close()
			}
		}()
	}

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
	if usageMeter != nil {
		quicServer.SetUsageMeter(usageMeter)
	}
	if cfg.AuthSignedToken {
		keys, err := parseTokenIssuers(cfg.TokenIssuers)
		if err != nil {
			quicServer.Close()
			return nil, fmt.Errorf("auth_signed_token: %w", err)
		}
		quicServer.SetTokenVerifier(NewTokenVerifier(keys))
		log.Printf("[AUTH] signed tokens (C3) enabled with %d sub key(s)", len(keys))
	}
	if cfg.AllowSelfSignedCertForTest {
		quicServer.SetAllowLoopbackForTest(true)
	}
	tunDevice := strings.TrimSpace(cfg.GlobalTUNDevice)
	if tunDevice == "" && runtime.GOOS == "linux" && !cfg.AllowSelfSignedCertForTest {
		tunDevice = "aero-tun0"
	} else if tunDevice == "" && runtime.GOOS == "linux" {
		if _, err := net.InterfaceByName("aero-tun0"); err == nil {
			tunDevice = "aero-tun0"
		}
	}
	hostStateDir := "" // 非空表示已修改宿主，Close 时据此还原
	if tunDevice != "" && runtime.GOOS == "linux" {
		if err := quicServer.AttachGlobalTunnelDeviceByName(context.Background(), tunDevice); err != nil {
			if strings.TrimSpace(cfg.GlobalTUNDevice) != "" || !cfg.AllowSelfSignedCertForTest {
				quicServer.Close()
				return nil, fmt.Errorf("attach global TUN %s failed: %w (production CONNECT-IP requires functional TUN interface)", tunDevice, err)
			}
			log.Printf("[EDGE] [WARN] Auto-configured global TUN %s could not be attached: %v (CONNECT-IP proxy may be disabled)", tunDevice, err)
		} else {
			log.Printf("[EDGE] Global TUN device %s attached and active for CONNECT-IP data plane", tunDevice)
			_ = ConfigureGlobalTunnelDevice(tunDevice, "10.88.0.1/16", "fd88:ae80::1/64", 1360)
			// 只有 TUN 就绪后才修改宿主（ADR-0012）；失败时已做的修改由 PrepareHostForTunnel 自行还原。
			if err := PrepareHostForTunnel(absDataDir, tunDevice); err != nil {
				log.Printf("[EDGE] [ERROR] CONNECT-IP forwarding not prepared, tunnel egress will fail: %v", err)
			} else {
				hostStateDir = absDataDir
			}
		}
	} else if tunDevice != "" {
		if err := quicServer.AttachGlobalTunnelDeviceByName(context.Background(), tunDevice); err != nil {
			if strings.TrimSpace(cfg.GlobalTUNDevice) != "" {
				quicServer.Close()
				return nil, fmt.Errorf("attach configured global TUN %s: %w", tunDevice, err)
			}
			log.Printf("[EDGE] [WARN] Global TUN %s could not be attached: %v", tunDevice, err)
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
		srv.serveCover,
	)
	srv.consoleHandler = consoleHandler

	if cfg.ObfsPassword != "" && len(cfg.FallbackObfsPasswords) > 0 {
		RegisterFallbackPasswords(cfg.ObfsPassword, cfg.FallbackObfsPasswords)
	}

	srv.instanceLock = lock
	srv.hostStateDir = hostStateDir
	if usageMeter != nil {
		srv.usageMeter = usageMeter
		srv.usageAPI = newUsageAPI(usageMeter, cfg.MeteringKey, cfg.NodeID, srv.nodeStatus)
		log.Printf("[USAGE] C6 metering enabled (node %s, key %s)", cfg.NodeID, MaskToken(cfg.MeteringKey))
	}
	constructed = true
	return srv, nil
}

// syncUserTokensFromSubs 启动时按订阅同步用户 token：有效期总是覆盖为订阅当前的
// 到期时间（续费后不会按旧到期时间被断开）；订阅已过期则移除其 token。
// ExpireAt 为 0 表示不限期（与控制台创建用户一致，100 年）。
func syncUserTokensFromSubs(subStore *SubStore, tokenStore *TokenStore) {
	if subStore == nil || tokenStore == nil {
		return
	}
	now := time.Now()
	for _, u := range subStore.ListUserSubs() {
		if u.Token == "" {
			continue
		}
		if u.ExpireAt > 0 && !now.Before(time.Unix(u.ExpireAt, 0)) {
			if err := tokenStore.Remove(u.Token); err != nil {
				log.Printf("[EDGE] Warning: failed to remove expired user token %s (%s): %v", MaskToken(u.Token), u.Slug, err)
			}
			continue
		}
		ttl := 100 * 365 * 24 * time.Hour
		if u.ExpireAt > 0 {
			ttl = time.Unix(u.ExpireAt, 0).Sub(now)
		}
		if err := tokenStore.Add(u.Token, "user:"+u.Slug, ttl); err != nil {
			log.Printf("[EDGE] Warning: failed to sync user token %s (%s): %v", MaskToken(u.Token), u.Slug, err)
		}
	}
}

// ConsoleHandler returns the Web Console handler
func (s *Server) ConsoleHandler() *ConsoleHandler { return s.consoleHandler }

// MetricsCollector returns the hardware metrics collector
func (s *Server) MetricsCollector() *MetricsCollector { return s.metricsCollector }

// PurityEngine returns the IP cleanliness engine
func (s *Server) PurityEngine() *PurityEngine { return s.purityEngine }

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

	// 1. TCP/TLS 监听。端口已在 NewServer 中按契约列表选定；此处绑定失败直接报错，
	// 不再做第二套回退（由服务管理器重启后重新选择）。
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
	s.quicServer.startTokenEnforcer()
	quicLn, err := StartQUIC(s.cfg.Listen, tlsCfg, s.quicServer, s.ctx)
	if err != nil {
		_ = s.tcpListener.Close()
		return fmt.Errorf("quic listen %s: %w", s.cfg.Listen, err)
	}
	s.quicListener = quicLn

	// 2b. Multi-port Hopping Alternative Listeners（严格去重并跳过主端口；独占绑定，被占用的端口直接跳过）
	host := ""
	primaryPort := 0
	if h, pStr, herr := net.SplitHostPort(s.cfg.Listen); herr == nil {
		host = h
		primaryPort, _ = strconv.Atoi(pStr)
	}
	boundPorts := make(map[int]bool)
	if primaryPort > 0 {
		boundPorts[primaryPort] = true
	}
	altPorts := s.cfg.AltListenPorts
	if len(altPorts) == 0 {
		altPorts = StandardCandidatePorts
	}
	for _, port := range altPorts {
		if port <= 0 || port > 65535 || boundPorts[port] {
			continue
		}
		boundPorts[port] = true
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

	if s.usageMeter != nil {
		s.usageDone = make(chan struct{})
		go func() {
			defer close(s.usageDone)
			s.usageMeter.Run(s.ctx.Done())
		}()
	}

	s.ready.Store(true)
	log.Printf("[EDGE] Server started on %s (TLS + QUIC)", s.cfg.Listen)
	log.Printf("[EDGE] Subscriptions ready: Admin(/sub/<secret>, see console), User(/sub/{username}{6random}) (client-sub: %s/client-sub.json)", s.subStore.Dir())
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

	if s.usageAPI.TryServe(w, r) { // 未鉴权时返回 false，最终落到伪装站
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
	// 探针只对本机开放（PROJECT_RULES 收紧项）；其他来源看到的是伪装站。
	// /healthz：进程存活；/readyz：Start 完成且未在排空中才可接流量（L0 §8.7）。
	if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
		if !isLoopbackRemote(r.RemoteAddr) {
			s.serveCover(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if r.URL.Path == "/readyz" && !s.ready.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("not ready"))
			return
		}
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
	if s.usageMeter != nil { // 会话已全部关闭：等落盘协程退出后做最后一次落盘
		if s.usageDone != nil {
			<-s.usageDone
		}
		if err := s.usageMeter.Close(); err != nil {
			log.Printf("[USAGE] [ERROR] final flush: %v", err)
		}
		s.usageMeter = nil
	}
	if s.hostStateDir != "" {
		if err := RestoreHost(s.hostStateDir); err != nil {
			log.Printf("[EDGE] [ERROR] restore host state (run `aero-edge cleanup-host`): %v", err)
		}
		s.hostStateDir = ""
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
	if s.dialGuard != nil {
		s.dialGuard.Close()
	}
	if s.metricsCollector != nil {
		s.metricsCollector.Stop()
	}
	if s.cfg.ObfsPassword != "" {
		RegisterFallbackPasswords(s.cfg.ObfsPassword, nil)
	}
	if s.instanceLock != nil {
		if err := s.instanceLock.release(); err != nil {
			log.Printf("[EDGE] [WARN] release instance lock: %v", err)
		}
		s.instanceLock = nil
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
	drain := time.Duration(cfg.DrainTimeoutSec) * time.Second
	if drain <= 0 {
		drain = 15 * time.Second
	}
	log.Printf("[EDGE] Received signal %v, draining (up to %v)...", sig, drain)
	ctx, cancel := context.WithTimeout(context.Background(), drain)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("[EDGE] [WARN] shutdown: %v", err)
	}
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

// persistServerConfig 把当前生效配置合并写入 cfg.ConfigPath（键名与 ServerConfig 的
// json tag 一致），保留文件中的其他键。ConfigPath 为空时不写任何文件。写盘按
// L0 §8.8：同目录临时文件、Sync、Close、Rename，失败时保留原文件并返回错误。
func persistServerConfig(cfg ServerConfig) error {
	path := strings.TrimSpace(cfg.ConfigPath)
	if path == "" {
		return nil
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	existing := make(map[string]any)
	if data, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(data, &existing); err != nil {
			return fmt.Errorf("parse existing %s: %w", path, err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", path, err)
	}
	// 旧版本写入的键名与读取时的 json tag 不一致，重启后证书路径丢失；统一改为 tag 名。
	delete(existing, "cert")
	delete(existing, "key")
	set := func(k, v string) {
		if v != "" {
			existing[k] = v
		}
	}
	set("listen", cfg.Listen)
	set("domain", cfg.Domain)
	set("cert_file", cfg.CertFile)
	set("key_file", cfg.KeyFile)
	set("data_dir", cfg.DataDir)
	set("admin_key", cfg.AdminKey)
	set("token", cfg.Token)
	set("metering_key", cfg.MeteringKey)
	set("node_id", cfg.NodeID)
	// WARP 开关显式写入（关闭时为空串），否则“关闭”无法持久化
	existing["warp_proxy"] = cfg.WarpProxy
	existing["warp_all"] = cfg.WarpAll

	data, err := json.MarshalIndent(existing, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return replaceFileAtomic(path, data, 0o600)
}

// replaceFileAtomic 用同目录临时文件替换 target（L0 §8.8）。
func replaceFileAtomic(target string, data []byte, perm os.FileMode) error {
	if info, err := os.Stat(target); err == nil {
		perm = info.Mode().Perm()
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat %s: %w", target, err)
	}
	f, err := os.CreateTemp(filepath.Dir(target), ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmp := f.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync temp: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmp, target); err != nil {
		return fmt.Errorf("replace %s: %w", target, err)
	}
	committed = true
	if d, err := os.Open(filepath.Dir(target)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// selectListenAddr 返回实际监听地址：requested 可用则保留；否则按 candidates 顺序取第一个
// 可用端口（主机部分不变）。全部不可用时返回 requested 与 false，由后续绑定报错。
func selectListenAddr(requested string, candidates []int, available func(string) bool) (string, bool) {
	if available(requested) {
		return requested, false
	}
	host, portStr, err := net.SplitHostPort(requested)
	if err != nil {
		return requested, false
	}
	for _, cand := range candidates {
		if strconv.Itoa(cand) == portStr {
			continue
		}
		addr := net.JoinHostPort(host, strconv.Itoa(cand))
		if available(addr) {
			return addr, true
		}
	}
	return requested, false
}

// checkPortAvailable 预检目标地址是否未被占用 (TCP与UDP双栈均空闲)
func checkPortAvailable(addr string) bool {
	if addr == "" {
		return false
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	_ = ln.Close()

	uconn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return false
	}
	_ = uconn.Close()
	return true
}

// generateSecureAdminKey 生成 128 位随机管理密钥（32 个十六进制字符）。随机源失败时
// 返回错误，不退化为可预测的值（L0 §7.4）。
func generateSecureAdminKey() (string, error) {
	k, err := randomHexBytes(16)
	if err != nil {
		return "", fmt.Errorf("read crypto random: %w", err)
	}
	return k, nil
}

// ensureUsageIdentity 为 usage_api 生成缺失的计量只读密钥（32 字节随机，hex）与节点标识；
// 随后由 persistServerConfig 持久化，重启后保持不变（否则 sub 的拉取会失效）。
func ensureUsageIdentity(cfg *ServerConfig) error {
	if cfg.MeteringKey == "" {
		k, err := randomHexBytes(32)
		if err != nil {
			return fmt.Errorf("generate metering key: %w", err)
		}
		cfg.MeteringKey = k
	} else if len(cfg.MeteringKey) < 64 {
		return fmt.Errorf("metering_key must be at least 64 hex characters (32 bytes)")
	}
	if cfg.NodeID == "" {
		id, err := randomHexBytes(8)
		if err != nil {
			return fmt.Errorf("generate node id: %w", err)
		}
		cfg.NodeID = "node-" + id
	}
	return nil
}

// nodeStatus 供 C6 /v1/status：就绪状态与在线会话；每用户只给出 uid 与连接数（无地址、无目的地）。
func (s *Server) nodeStatus() nodeStatus {
	total, byUID := s.quicServer.connTracker.Sessions()
	st := nodeStatus{Version: Version, Ready: s.ready.Load(), ActiveSessions: total}
	for uid, n := range byUID {
		st.SessionsByUID = append(st.SessionsByUID, uidSession{UID: uid, Sessions: n})
	}
	sort.Slice(st.SessionsByUID, func(i, j int) bool { return st.SessionsByUID[i].UID < st.SessionsByUID[j].UID })
	return st
}

// randomHexBytes 返回 n 字节密码学随机数的十六进制编码。
func randomHexBytes(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// loadExistingAdminKey 从显式配置文件中装载已存在的 admin_key；path 为空时不读取。
func loadExistingAdminKey(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return ""
	}
	if k, ok := m["admin_key"].(string); ok && strings.TrimSpace(k) != "" {
		return strings.TrimSpace(k)
	}
	return ""
}

// Shutdown 优雅停机（L0 §8.6）：先清除 readiness（/readyz 503，/healthz 仍 200），
// 再向已鉴权的在线连接发送 CONNECTION_CLOSE，使客户端立即重连而不是等待空闲超时，
// 最后释放全部资源。ctx 为排空上限；超时则直接 Close 并返回 ctx 的错误。
func (s *Server) Shutdown(ctx context.Context) error {
	s.ready.Store(false)
	done := make(chan int, 1)
	go func() {
		n := 0
		if s.quicServer != nil {
			n = s.quicServer.connTracker.CloseAllForShutdown()
		}
		done <- n
	}()
	var err error
	select {
	case n := <-done:
		log.Printf("[EDGE] drain: notified %d client connection(s)", n)
	case <-ctx.Done():
		err = ctx.Err()
		log.Printf("[EDGE] [WARN] drain timed out: %v", err)
	}
	s.Close()
	return err
}

// SetWarpEgress 打开或关闭 WARP 出口插件（经本机官方客户端 SOCKS5 代理），立即生效并持久化到配置文件。
// edge 只使用、不安装 WARP（ADR-0012 第 6 条）。
func (s *Server) SetWarpEgress(enabled, all bool) error {
	s.warpMu.Lock()
	defer s.warpMu.Unlock()
	cfg := s.cfg
	if enabled {
		cfg.WarpProxy, cfg.WarpAll = warpLocalProxy, all
	} else {
		cfg.WarpProxy, cfg.WarpAll = "", false
	}
	if err := persistServerConfig(cfg); err != nil {
		return fmt.Errorf("persist WARP setting: %w", err)
	}
	s.cfg.WarpProxy, s.cfg.WarpAll = cfg.WarpProxy, cfg.WarpAll
	if s.dialGuard != nil {
		s.dialGuard.SetWarpProxy(cfg.WarpProxy, cfg.WarpAll)
	}
	log.Printf("[WARP] egress plugin %s (all=%v)", map[bool]string{true: "enabled", false: "disabled"}[enabled], cfg.WarpAll)
	return nil
}
