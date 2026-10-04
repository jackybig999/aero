// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/connect-ip-go"
	"github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/qlog"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/sync/singleflight"
)

// ==========================================
// 1. DNS Short Stream Resolver (50 QPS, Singleflight, 300s/30s Cache)
// ==========================================

type dnsCacheEntry struct {
	ip        net.IP
	expiresAt time.Time
}

// DNSResolver resolves hostnames for tunnel DNS short streams (StreamType_CONTROL)
type DNSResolver struct {
	mu          sync.RWMutex
	cache       map[string]dnsCacheEntry
	group       singleflight.Group
	rateMu      sync.Mutex
	rateBuckets map[string]*rateTokenBucket // 50 QPS per token
	lastCleanup time.Time
	lookupFn    func(ctx context.Context, host string) ([]net.IP, error)
}

// NewDNSResolver creates a new DNSResolver
func NewDNSResolver() *DNSResolver {
	return &DNSResolver{
		cache:       make(map[string]dnsCacheEntry),
		rateBuckets: make(map[string]*rateTokenBucket),
		lookupFn: func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip4", host)
		},
	}
}

// SetLookupFunc allows injecting a mock lookup function for testing
func (r *DNSResolver) SetLookupFunc(fn func(ctx context.Context, host string) ([]net.IP, error)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lookupFn = fn
}

// checkRateLimit checks 50 QPS rate limit per token
func (r *DNSResolver) checkRateLimit(token string) bool {
	if token == "" {
		return false
	}
	r.rateMu.Lock()
	defer r.rateMu.Unlock()

	now := time.Now()
	if len(r.rateBuckets) > 500 && now.Sub(r.lastCleanup) > time.Minute {
		for k, v := range r.rateBuckets {
			if now.Sub(v.lastTime) > 5*time.Minute {
				delete(r.rateBuckets, k)
			}
		}
		r.lastCleanup = now
	}
	b, ok := r.rateBuckets[token]
	if !ok {
		b = &rateTokenBucket{
			tokens:   49,
			lastTime: now,
			rate:     50,
			max:      50,
		}
		r.rateBuckets[token] = b
		return true
	}
	elapsed := now.Sub(b.lastTime).Seconds()
	b.tokens += elapsed * b.rate
	if b.tokens > b.max {
		b.tokens = b.max
	}
	b.lastTime = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// Resolve resolves domain to 4-byte IPv4 payload
func (r *DNSResolver) Resolve(token, host string) ([]byte, error) {
	if !r.checkRateLimit(token) {
		return nil, fmt.Errorf("dns rate limit exceeded")
	}

	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return nil, fmt.Errorf("empty host")
	}

	// 1. Check Cache
	now := time.Now()
	r.mu.RLock()
	entry, found := r.cache[host]
	r.mu.RUnlock()

	if found && now.Before(entry.expiresAt) {
		if entry.ip != nil {
			if ip4 := entry.ip.To4(); ip4 != nil {
				return ip4, nil
			}
		}
		return nil, fmt.Errorf("cached negative resolution")
	}

	// 2. Singleflight Resolution with 1.0s Timeout
	res, err, _ := r.group.Do(host, func() (any, error) {
		// Double check cache inside singleflight
		r.mu.RLock()
		e, ok := r.cache[host]
		r.mu.RUnlock()
		if ok && time.Now().Before(e.expiresAt) {
			if e.ip != nil {
				return e.ip.To4(), nil
			}
			return nil, fmt.Errorf("cached negative resolution")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
		defer cancel()

		r.mu.RLock()
		fn := r.lookupFn
		r.mu.RUnlock()

		ips, lookupErr := fn(ctx, host)
		r.mu.Lock()
		defer r.mu.Unlock()

		if lookupErr != nil {
			negTTL := 30 * time.Second
			var netErr net.Error
			if errors.Is(lookupErr, context.DeadlineExceeded) || (errors.As(lookupErr, &netErr) && netErr.Timeout()) {
				negTTL = 5 * time.Second
			}
			r.cache[host] = dnsCacheEntry{
				ip:        nil,
				expiresAt: time.Now().Add(negTTL),
			}
			return nil, lookupErr
		}
		if len(ips) == 0 {
			r.cache[host] = dnsCacheEntry{
				ip:        nil,
				expiresAt: time.Now().Add(30 * time.Second),
			}
			return nil, fmt.Errorf("no ipv4 found for %s", host)
		}

		var selected net.IP
		for _, ip := range ips {
			if ip4 := ip.To4(); ip4 != nil {
				selected = ip4
				break
			}
		}
		if selected == nil {
			r.cache[host] = dnsCacheEntry{
				ip:        nil,
				expiresAt: time.Now().Add(30 * time.Second),
			}
			return nil, fmt.Errorf("no ipv4 found")
		}

		// Positive cache: 300s
		r.cache[host] = dnsCacheEntry{
			ip:        selected,
			expiresAt: time.Now().Add(300 * time.Second),
		}
		return selected, nil
	})

	if err != nil || res == nil {
		return nil, err
	}

	ipBytes, ok := res.(net.IP)
	if !ok || len(ipBytes.To4()) != 4 {
		return nil, fmt.Errorf("invalid resolved ip")
	}
	return ipBytes.To4(), nil
}

// ==========================================
// 2. IP Pool & Dynamic Allocation (10.88.0.0/16)
// ==========================================

// IPPool dynamically allocates client IP prefixes within a CIDR pool.
type IPPool struct {
	mu       sync.Mutex
	baseIP   netip.Addr
	prefix   int
	nextHost uint32
	maxHost  uint32
	used     map[netip.Addr]struct{}
}

// NewIPPool creates an IPPool with specified CIDR (default 10.88.0.0/16).
func NewIPPool(cidrStr string) (*IPPool, error) {
	if cidrStr == "" {
		cidrStr = "10.88.0.0/16"
	}
	prefix, err := netip.ParsePrefix(cidrStr)
	if err != nil {
		return nil, err
	}
	return &IPPool{
		baseIP:   prefix.Addr(),
		prefix:   prefix.Bits(),
		nextHost: 2,
		maxHost:  65534,
		used:     make(map[netip.Addr]struct{}),
	}, nil
}

// Allocate returns an unused IP prefix from the pool.
func (p *IPPool) Allocate() (netip.Prefix, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	base4 := p.baseIP.As4()
	baseVal := binary.BigEndian.Uint32(base4[:])

	for i := uint32(0); i < p.maxHost; i++ {
		host := p.nextHost
		p.nextHost++
		if p.nextHost >= p.maxHost {
			p.nextHost = 2
		}
		val := baseVal + host
		var cand4 [4]byte
		binary.BigEndian.PutUint32(cand4[:], val)
		candAddr := netip.AddrFrom4(cand4)
		if _, exists := p.used[candAddr]; !exists {
			p.used[candAddr] = struct{}{}
			return netip.PrefixFrom(candAddr, 32), nil
		}
	}
	return netip.Prefix{}, errors.New("ip pool exhausted")
}

// Release returns a prefix back to the pool.
func (p *IPPool) Release(prefix netip.Prefix) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.used, prefix.Addr())
}

// Available checks if there is any available IP address in the pool.
func (p *IPPool) Available() bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return uint32(len(p.used)) < p.maxHost
}

// ==========================================
// 3. Connection Token Tracker
// ==========================================

type quicConnKey struct{}

// ConnTracker associates each active quic.Conn with its authenticated token.
type ConnTracker struct {
	mu    sync.RWMutex
	conns map[*quic.Conn]string
}

// NewConnTracker creates a new ConnTracker.
func NewConnTracker() *ConnTracker {
	return &ConnTracker{conns: make(map[*quic.Conn]string)}
}

// Get returns the token bound to c.
func (ct *ConnTracker) Get(c *quic.Conn) (string, bool) {
	if c == nil {
		return "", false
	}
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	token, ok := ct.conns[c]
	return token, ok
}

// Bind associates token with c.
func (ct *ConnTracker) Bind(c *quic.Conn, token string) {
	if c == nil {
		return
	}
	ct.mu.Lock()
	ct.conns[c] = token
	ct.mu.Unlock()
}

// Remove dissociates c.
func (ct *ConnTracker) Remove(c *quic.Conn) {
	if c == nil {
		return
	}
	ct.mu.Lock()
	delete(ct.conns, c)
	ct.mu.Unlock()
}

// ==========================================
// 4. QUIC Server Instance & UDP Context Management
// ==========================================

const (
	MaxUDPContextsPerToken = 64
	DefaultMaxGlobalUDP    = 4096
)

// QUICServer manages QUIC connections, HTTP/3, MASQUE proxies, UDP contexts, and DNS
type QUICServer struct {
	validator        *Validator
	connLimiter      *ConnLimiter
	bandwidthLimiter *BandwidthLimiter
	dialGuard        *DialGuard
	rateLimiter      *RateLimiter
	dnsResolver      *DNSResolver
	connTracker      *ConnTracker
	ipPool           *IPPool
	authJail         *AuthFailureJail
	masqueProxy      *masque.Proxy
	connectIPProxy   *connectip.Proxy
	h3Server         *http3.Server

	udpTempl *uritemplate.Template
	ipTempl  *uritemplate.Template

	handlerMu sync.RWMutex
	handler   http.Handler

	udpMu                sync.Mutex
	tokenUDPCtx          map[string]int
	globalUDPCtx         atomic.Int64
	maxGlobalUDP         int64
	allowLoopbackForTest bool
}

// SetAllowLoopbackForTest enables loopback dialing for unit tests.
func (s *QUICServer) SetAllowLoopbackForTest(allow bool) {
	s.allowLoopbackForTest = allow
}

// NewQUICServer creates a new QUICServer instance
func NewQUICServer(v *Validator, cl *ConnLimiter, bl *BandwidthLimiter, dg *DialGuard, rl *RateLimiter) *QUICServer {
	ipPool, _ := NewIPPool("10.88.0.0/16")
	qs := &QUICServer{
		validator:        v,
		connLimiter:      cl,
		bandwidthLimiter: bl,
		dialGuard:        dg,
		rateLimiter:      rl,
		dnsResolver:      NewDNSResolver(),
		connTracker:      NewConnTracker(),
		ipPool:           ipPool,
		authJail:         NewAuthFailureJail(),
		masqueProxy:      &masque.Proxy{},
		connectIPProxy:   &connectip.Proxy{},
		tokenUDPCtx:      make(map[string]int),
		maxGlobalUDP:     DefaultMaxGlobalUDP,
		udpTempl:         uritemplate.MustNew("https://placeholder/.well-known/masque/udp/{target_host}/{target_port}/"),
		ipTempl:          uritemplate.MustNew("https://placeholder/.well-known/masque/ip/*/*/"),
	}
	qs.h3Server = &http3.Server{
		Handler:         qs,
		EnableDatagrams: true,
		ConnContext: func(ctx context.Context, c *quic.Conn) context.Context {
			return context.WithValue(ctx, quicConnKey{}, c)
		},
	}
	return qs
}

// AuthJail returns the internal AuthFailureJail
func (s *QUICServer) AuthJail() *AuthFailureJail {
	return s.authJail
}

// Close closes the QUICServer and its background components
func (s *QUICServer) Close() {
	if s.authJail != nil {
		s.authJail.Close()
	}
}

// SetHandler sets the HTTP handler for HTTP/3 requests.
func (s *QUICServer) SetHandler(h http.Handler) {
	s.handlerMu.Lock()
	defer s.handlerMu.Unlock()
	s.handler = h
}

// Handler returns the current HTTP handler.
func (s *QUICServer) Handler() http.Handler {
	s.handlerMu.RLock()
	defer s.handlerMu.RUnlock()
	return s.handler
}

// DNSResolver returns the internal DNSResolver
func (s *QUICServer) DNSResolver() *DNSResolver {
	return s.dnsResolver
}

func (s *QUICServer) acquireUDPSlot(token string) bool {
	if token == "" {
		return false
	}
	// Check global UDP cap
	if s.globalUDPCtx.Load() >= s.maxGlobalUDP {
		return false
	}

	s.udpMu.Lock()
	defer s.udpMu.Unlock()

	n := s.tokenUDPCtx[token]
	if n >= MaxUDPContextsPerToken {
		return false
	}
	s.tokenUDPCtx[token] = n + 1
	s.globalUDPCtx.Add(1)
	return true
}

func (s *QUICServer) releaseUDPSlot(token string) {
	if token == "" {
		return
	}
	s.udpMu.Lock()
	defer s.udpMu.Unlock()

	if n, ok := s.tokenUDPCtx[token]; ok {
		if n <= 1 {
			delete(s.tokenUDPCtx, token)
		} else {
			s.tokenUDPCtx[token] = n - 1
		}
	}
	s.globalUDPCtx.Add(-1)
}

// ==========================================
// 4. QUIC Listener & Connection Loop
// ==========================================

// DefaultQUICConfig returns the hardened QUIC configuration for AERO edge nodes
func DefaultQUICConfig() *quic.Config {
	return &quic.Config{
		Allow0RTT:                      false,
		MaxIncomingStreams:             1000,
		MaxIncomingUniStreams:          1000,
		MaxIdleTimeout:                 90 * time.Second,
		EnableDatagrams:                true,
		InitialStreamReceiveWindow:     16 * 1024 * 1024,  // 16 MB single stream window (Rule L6)
		MaxStreamReceiveWindow:         32 * 1024 * 1024,  // 32 MB
		InitialConnectionReceiveWindow: 64 * 1024 * 1024,  // 64 MB
		MaxConnectionReceiveWindow:     128 * 1024 * 1024, // 128 MB connection window (Rule L6)
		KeepAlivePeriod:                10 * time.Second,  // 10s KeepAlive (beats domestic NAT timeout)
	}
}

// StartQUIC starts the QUIC listener on addr
func StartQUIC(addr string, tlsConfig *tls.Config, server *QUICServer, ctx context.Context) (*quic.Listener, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	quicCfg := DefaultQUICConfig()
	if qlogDir := os.Getenv("AERO_QLOG_DIR"); qlogDir != "" {
		_ = os.MkdirAll(qlogDir, 0o755)
		_ = os.Setenv("QLOGDIR", qlogDir)
		quicCfg.Tracer = qlog.DefaultConnectionTracer
	}

	quicTLS := tlsConfig.Clone()
	quicTLS.NextProtos = []string{"h3"}

	network := "udp4"
	if strings.Contains(addr, "[") || strings.HasPrefix(addr, "::") {
		network = "udp6"
	}
	conn, err := net.ListenPacket(network, addr)
	if err != nil {
		return nil, fmt.Errorf("quic listen packet %s: %w", addr, err)
	}

	tr := &quic.Transport{
		Conn: conn,
		ConnContext: func(c context.Context, info *quic.ClientInfo) (context.Context, error) {
			host, _, err := net.SplitHostPort(info.RemoteAddr.String())
			if err != nil || host == "" {
				host = info.RemoteAddr.String()
			}
			if server != nil && server.rateLimiter != nil && !server.rateLimiter.Allow(host) {
				return nil, errors.New("rate limited")
			}
			return c, nil
		},
	}

	ln, err := tr.Listen(quicTLS, quicCfg)
	if err != nil {
		_ = tr.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("quic listen %s: %w", addr, err)
	}

	go func() {
		defer func() {
			_ = tr.Close()
			_ = conn.Close()
		}()
		for {
			c, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			go server.handleQUICConn(c)
		}
	}()

	return ln, nil
}

// ServeListener accepts and handles connections from an existing quic.Listener with external context
func (s *QUICServer) ServeListener(ctx context.Context, ln *quic.Listener) error {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			return err
		}
		go s.handleQUICConn(conn)
	}
}

// handleQUICConn is the connection-level handler
func (s *QUICServer) handleQUICConn(conn *quic.Conn) {
	if s.h3Server != nil {
		_ = s.h3Server.ServeQUICConn(conn)
	}
}

// ==========================================
// 5. HTTP/3 & MASQUE Request Handlers
// ==========================================

// ServeHTTP implements http.Handler for QUICServer, delegating to Server if configured.
func (s *QUICServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handlerMu.RLock()
	h := s.handler
	s.handlerMu.RUnlock()

	if h != nil {
		h.ServeHTTP(w, r)
		return
	}

	s.ServeDefault(w, r)
}

// ServeDefault provides default HTTP/3 handling for standalone tests and edge server routing.
func (s *QUICServer) ServeDefault(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" || r.URL.Path == "/index.html" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(coverHTML)
		return
	}

	if strings.HasPrefix(r.URL.Path, "/assets/") {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(coverCSS)
		return
	}

	if r.URL.Path == "/healthz" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		return
	}

	if r.Method == http.MethodPost && r.URL.Path == "/dns-query" {
		s.serveDoH(w, r)
		return
	}

	if r.Method == http.MethodConnect {
		if r.Proto == "connect-udp" || strings.HasPrefix(r.URL.Path, "/.well-known/masque/udp/") {
			s.serveConnectUDP(w, r)
			return
		}
		if r.Proto == "connect-ip" || strings.HasPrefix(r.URL.Path, "/.well-known/masque/ip/") {
			s.serveConnectIP(w, r)
			return
		}
		s.serveStandardConnect(w, r)
		return
	}

	w.WriteHeader(http.StatusNotFound)
}

func (s *QUICServer) authRequest(w http.ResponseWriter, r *http.Request) (string, bool) {
	remoteIP := ClientIP(r)
	if s.authJail != nil && s.authJail.IsBanned(remoteIP) {
		w.Header().Set("Retry-After", "900")
		w.WriteHeader(http.StatusTooManyRequests)
		return "", false
	}

	authHdr := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHdr, "Bearer ") {
		if s.authJail != nil {
			s.authJail.RecordFailure(remoteIP)
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="aero"`)
		w.Header().Set("Proxy-Status", "aero; error=proxy_authorization_required")
		w.WriteHeader(http.StatusUnauthorized)
		return "", false
	}
	token := strings.TrimSpace(strings.TrimPrefix(authHdr, "Bearer "))

	qc, _ := r.Context().Value(quicConnKey{}).(*quic.Conn)
	if qc != nil && s.connTracker != nil {
		if bound, ok := s.connTracker.Get(qc); ok {
			if token != bound || !s.validator.Validate(token) {
				if s.authJail != nil {
					s.authJail.RecordFailure(remoteIP)
				}
				w.Header().Set("WWW-Authenticate", `Bearer realm="aero"`)
				w.Header().Set("Proxy-Status", "aero; error=proxy_authorization_required")
				w.WriteHeader(http.StatusUnauthorized)
				return "", false
			}
			return token, true
		}

		tsStr := r.Header.Get("Aero-Timestamp")
		nonceHex := r.Header.Get("Aero-Nonce")
		if tsStr == "" || nonceHex == "" {
			if s.authJail != nil {
				s.authJail.RecordFailure(remoteIP)
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="aero"`)
			w.Header().Set("Proxy-Status", `aero; error=proxy_authorization_required; details="missing timestamp or nonce on first request"`)
			w.WriteHeader(http.StatusUnauthorized)
			return "", false
		}
		ts, err1 := strconv.ParseUint(tsStr, 10, 64)
		nonceBytes, err2 := hex.DecodeString(nonceHex)
		if err1 != nil || err2 != nil || len(nonceBytes) != 32 || !s.validator.ValidateFull(token, ts, nonceBytes) {
			if s.authJail != nil {
				s.authJail.RecordFailure(remoteIP)
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="aero"`)
			w.Header().Set("Proxy-Status", `aero; error=proxy_authorization_required; details="invalid timestamp, nonce or signature"`)
			w.WriteHeader(http.StatusUnauthorized)
			return "", false
		}
		s.connTracker.Bind(qc, token)
		return token, true
	}

	if s.validator != nil {
		tsStr := r.Header.Get("Aero-Timestamp")
		nonceHex := r.Header.Get("Aero-Nonce")
		if tsStr == "" || nonceHex == "" {
			if s.authJail != nil {
				s.authJail.RecordFailure(remoteIP)
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="aero"`)
			w.Header().Set("Proxy-Status", `aero; error=proxy_authorization_required; details="missing timestamp or nonce on fallback"`)
			w.WriteHeader(http.StatusUnauthorized)
			return "", false
		}
		ts, err1 := strconv.ParseUint(tsStr, 10, 64)
		nonceBytes, err2 := hex.DecodeString(nonceHex)
		if err1 != nil || err2 != nil || len(nonceBytes) != 32 || !s.validator.ValidateFull(token, ts, nonceBytes) {
			if s.authJail != nil {
				s.authJail.RecordFailure(remoteIP)
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="aero"`)
			w.Header().Set("Proxy-Status", `aero; error=proxy_authorization_required; details="invalid timestamp, nonce or signature"`)
			w.WriteHeader(http.StatusUnauthorized)
			return "", false
		}
		return token, true
	}
	return token, true
}

func (s *QUICServer) serveStandardConnect(w http.ResponseWriter, r *http.Request) {
	token, ok := s.authRequest(w, r)
	if !ok {
		return
	}

	target := r.RequestURI
	if target == "" || !strings.Contains(target, ":") {
		target = r.Host
	}
	if target == "" {
		w.Header().Set("Proxy-Status", "aero; error=destination_ip_unroutable")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !s.allowLoopbackForTest {
		if blocked, why := IsBlockedTarget(target); blocked {
			w.Header().Set("Proxy-Status", fmt.Sprintf("aero; error=destination_ip_prohibited; details=%q", why))
			w.WriteHeader(http.StatusForbidden)
			return
		}
	}

	if s.connLimiter != nil {
		if !s.connLimiter.TryAcquire(token) {
			w.Header().Set("Proxy-Status", "aero; error=connection_limit_exceeded")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		defer s.connLimiter.Release(token)
	}

	var targetConn net.Conn
	var err error
	if s.dialGuard != nil {
		targetConn, err = s.dialGuard.DialTimeout("tcp", target, 10*time.Second)
	} else {
		targetConn, err = net.DialTimeout("tcp", target, 10*time.Second)
	}
	if err != nil {
		w.Header().Set("Proxy-Status", fmt.Sprintf("aero; error=connection_refused; details=%q", err.Error()))
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	w.WriteHeader(http.StatusOK)
	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		return
	}
	str := streamer.HTTPStream()
	defer str.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, 32768)
		for {
			n, err := str.Read(buf)
			if n > 0 {
				if s.bandwidthLimiter != nil {
					s.bandwidthLimiter.Take(token, n)
				}
				if _, werr := targetConn.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		_ = targetConn.Close()
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 32768)
		for {
			n, err := targetConn.Read(buf)
			if n > 0 {
				if s.bandwidthLimiter != nil {
					s.bandwidthLimiter.Take(token, n)
				}
				if _, werr := str.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		_ = str.Close()
	}()

	wg.Wait()
}

func (s *QUICServer) serveConnectUDP(w http.ResponseWriter, r *http.Request) {
	token, ok := s.authRequest(w, r)
	if !ok {
		return
	}

	origHost := r.Host
	r.Host = "placeholder"
	proxyReq, err := masque.ParseProxyRequest(r, s.udpTempl)
	r.Host = origHost
	if proxyReq != nil {
		proxyReq.Host = origHost
	}
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !s.allowLoopbackForTest {
		if blocked, why := IsBlockedTarget(proxyReq.Target); blocked {
			w.Header().Set("Proxy-Status", fmt.Sprintf("aero; error=destination_ip_prohibited; details=%q", why))
			w.WriteHeader(http.StatusForbidden)
			return
		}
	}

	if !s.acquireUDPSlot(token) {
		w.Header().Set("Proxy-Status", "aero; error=udp_slot_limit_exceeded")
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	defer s.releaseUDPSlot(token)

	dstAddr, err := net.ResolveUDPAddr("udp", proxyReq.Target)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	targetUDP, err := net.DialUDP("udp", nil, dstAddr)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer targetUDP.Close()

	// 45s 空闲滑动超时控制
	lastActive := atomic.Int64{}
	lastActive.Store(time.Now().UnixNano())
	stopWatchdog := make(chan struct{})
	defer close(stopWatchdog)

	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopWatchdog:
				return
			case <-ticker.C:
				if time.Since(time.Unix(0, lastActive.Load())) > 45*time.Second {
					_ = targetUDP.Close()
					return
				}
			}
		}
	}()

	_ = s.masqueProxy.ProxyConnectedSocket(w, proxyReq, targetUDP)
}

func (s *QUICServer) serveConnectIP(w http.ResponseWriter, r *http.Request) {
	token, ok := s.authRequest(w, r)
	if !ok {
		return
	}

	origHost := r.Host
	r.Host = "placeholder"
	proxyReq, err := connectip.ParseProxyRequest(r, s.ipTempl)
	r.Host = origHost
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if s.ipPool == nil {
		w.Header().Set("Proxy-Status", `aero; error=address_pool_exhausted; details="IP pool not configured"`)
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	assignedPrefix, err := s.ipPool.Allocate()
	if err != nil {
		w.Header().Set("Proxy-Status", "aero; error=address_pool_exhausted; details=\"IP pool exhausted\"")
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	defer s.ipPool.Release(assignedPrefix)

	conn, err := s.connectIPProxy.Proxy(w, proxyReq)
	if err != nil {
		return
	}
	defer conn.Close()

	if err := conn.AssignAddresses([]netip.Prefix{assignedPrefix}); err != nil {
		return
	}
	if err := conn.AdvertiseRoute([]connectip.IPRoute{
		{
			StartIP:    netip.MustParseAddr("0.0.0.0"),
			EndIP:      netip.MustParseAddr("255.255.255.255"),
			IPProtocol: 0,
		},
	}); err != nil {
		return
	}

	// 启动真实 RFC 9484 用户态 NAT 路由器，绝不使用虚假回显
	natRouter, err := NewUserSpaceNATRouter(r.Context(), s, token, assignedPrefix.Addr(), conn)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer natRouter.Close()

	natRouter.Run()
}

func (s *QUICServer) serveDoH(w http.ResponseWriter, r *http.Request) {
	token, ok := s.authRequest(w, r)
	if !ok {
		return
	}

	if r.Header.Get("Content-Type") != "application/dns-message" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}

	queryBytes, err := io.ReadAll(r.Body)
	if err != nil || len(queryBytes) < 12 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	qname, qtype := extractDNSQuestionAndType(queryBytes)
	if qname == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if qtype == 0x001C { // AAAA -> Empty answer
		resp := buildEmptyResponse(queryBytes, qname, qtype)
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(resp)
		return
	}

	if qtype == 0x0001 { // A
		if qname == "localhost" {
			resp := buildAResponse(queryBytes, qname, net.IPv4(127, 0, 0, 1))
			w.Header().Set("Content-Type", "application/dns-message")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(resp)
			return
		}

		ip4, err := s.dnsResolver.Resolve(token, qname)
		if err != nil {
			if strings.Contains(err.Error(), "rate limit") {
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			resp := buildEmptyResponse(queryBytes, qname, qtype)
			w.Header().Set("Content-Type", "application/dns-message")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(resp)
			return
		}

		resp := buildAResponse(queryBytes, qname, net.IP(ip4))
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(resp)
		return
	}

	resp := buildEmptyResponse(queryBytes, qname, qtype)
	w.Header().Set("Content-Type", "application/dns-message")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}

// ==========================================
// 6. Packet & DNS Wire Format Helpers
// ==========================================

func calcChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func extractDNSQuestionAndType(pkt []byte) (string, uint16) {
	if len(pkt) <= 12 {
		return "", 0
	}
	offset := 12
	var name []byte
	for offset < len(pkt) {
		length := int(pkt[offset])
		if length == 0 {
			offset++
			break
		}
		if length > 63 || offset+1+length > len(pkt) {
			return "", 0
		}
		if len(name) > 0 {
			name = append(name, '.')
		}
		name = append(name, pkt[offset+1:offset+1+length]...)
		offset += 1 + length
	}
	if offset+4 > len(pkt) {
		return string(name), 0x0001
	}
	qtype := binary.BigEndian.Uint16(pkt[offset : offset+2])
	return string(name), qtype
}

func buildAResponse(req []byte, host string, ip net.IP) []byte {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}
	resp := []byte{
		0x00, 0x00,
		0x81, 0x80,
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
	}
	if len(req) >= 2 {
		resp[0], resp[1] = req[0], req[1]
	}
	resp = append(resp, encodeDNSName(host)...)
	resp = append(resp, 0x00, 0x01)
	resp = append(resp, 0x00, 0x01)

	resp = append(resp, 0xC0, 0x0C)
	resp = append(resp, 0x00, 0x01)
	resp = append(resp, 0x00, 0x01)
	resp = append(resp, 0x00, 0x00, 0x01, 0x2C)
	resp = append(resp, 0x00, 0x04)
	resp = append(resp, ip4...)
	return resp
}

func buildEmptyResponse(req []byte, host string, qtype uint16) []byte {
	resp := []byte{
		0x00, 0x00,
		0x81, 0x80,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
	}
	if len(req) >= 2 {
		resp[0], resp[1] = req[0], req[1]
	}
	resp = append(resp, encodeDNSName(host)...)
	resp = append(resp, byte(qtype>>8), byte(qtype))
	resp = append(resp, 0x00, 0x01)
	return resp
}

func encodeDNSName(domain string) []byte {
	var buf []byte
	parts := strings.Split(domain, ".")
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		buf = append(buf, byte(len(part)))
		buf = append(buf, []byte(part)...)
	}
	buf = append(buf, 0x00)
	return buf
}
