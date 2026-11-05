// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ==========================================
// 1. Connection Limiter (Multi-tenant & Global)
// ==========================================

const (
	DefaultMaxGlobal = 4096 // Global active tunnel connection limit
	DefaultMaxPerTok = 1024 // Per-token connection limit
)

// ConnLimiter manages concurrent connections globally and per token
type ConnLimiter struct {
	maxGlobal int64
	maxPerTok int64

	global atomic.Int64

	mu     sync.Mutex
	perTok map[string]int64
}

// NewConnLimiter creates a new ConnLimiter
func NewConnLimiter(maxGlobal, maxPerTok int) *ConnLimiter {
	if maxGlobal <= 0 {
		maxGlobal = DefaultMaxGlobal
	}
	if maxPerTok <= 0 {
		maxPerTok = DefaultMaxPerTok
	}
	return &ConnLimiter{
		maxGlobal: int64(maxGlobal),
		maxPerTok: int64(maxPerTok),
		perTok:    make(map[string]int64),
	}
}

// TryAcquire attempts to acquire a connection slot for the given token.
// Returns false if global limit or per-token limit is exceeded.
func (l *ConnLimiter) TryAcquire(token string) bool {
	if token == "" {
		return false
	}
	// Global limit CAS
	for {
		cur := l.global.Load()
		if cur >= l.maxGlobal {
			return false
		}
		if l.global.CompareAndSwap(cur, cur+1) {
			break
		}
	}

	l.mu.Lock()
	n := l.perTok[token]
	if n >= l.maxPerTok {
		l.mu.Unlock()
		l.global.Add(-1)
		return false
	}
	l.perTok[token] = n + 1
	l.mu.Unlock()
	return true
}

// Release releases a connection slot for the given token.
func (l *ConnLimiter) Release(token string) {
	if token == "" {
		return
	}
	l.mu.Lock()
	if n, ok := l.perTok[token]; ok {
		if n <= 1 {
			delete(l.perTok, token)
		} else {
			l.perTok[token] = n - 1
		}
	}
	l.mu.Unlock()
	l.global.Add(-1)
}

// Active returns current global active count
func (l *ConnLimiter) Active() int64 {
	return l.global.Load()
}

// ActiveToken returns active count for a specific token
func (l *ConnLimiter) ActiveToken(token string) int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.perTok[token]
}

// MaxGlobal returns maximum global limit
func (l *ConnLimiter) MaxGlobal() int64 { return l.maxGlobal }

// MaxPerTok returns maximum per-token limit
func (l *ConnLimiter) MaxPerTok() int64 { return l.maxPerTok }

// ==========================================
// 2. Bandwidth Limiter (Token Bucket per Token)
// ==========================================

// BandwidthLimiter limits bandwidth per token in bytes/second. 0 = unlimited.
type BandwidthLimiter struct {
	mu      sync.Mutex
	rate    float64 // bytes per second
	burst   float64
	buckets map[string]*bandwidthBucket
}

type bandwidthBucket struct {
	tokens float64
	last   time.Time
}

// NewBandwidthLimiter creates a BandwidthLimiter; bytesPerSec <= 0 disables limiting.
func NewBandwidthLimiter(bytesPerSec int) *BandwidthLimiter {
	if bytesPerSec <= 0 {
		return &BandwidthLimiter{rate: 0, buckets: make(map[string]*bandwidthBucket)}
	}
	r := float64(bytesPerSec)
	return &BandwidthLimiter{
		rate:    r,
		burst:   r * 2, // 2s burst capacity
		buckets: make(map[string]*bandwidthBucket),
	}
}

// Enabled returns true if bandwidth limiting is active
func (l *BandwidthLimiter) Enabled() bool {
	return l != nil && l.rate > 0
}

// Rate returns configured rate in bytes/sec
func (l *BandwidthLimiter) Rate() float64 {
	if l == nil {
		return 0
	}
	return l.rate
}

// TakeContext deducts n bytes; sleeps until available or until ctx is canceled
func (l *BandwidthLimiter) TakeContext(ctx context.Context, token string, n int) error {
	if l == nil || l.rate <= 0 || n <= 0 || token == "" {
		return nil
	}
	for {
		wait := l.tryTake(token, n)
		if wait <= 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

// Take deducts n bytes; sleeps until available if rate exceeded (backward compatibility wrapper)
func (l *BandwidthLimiter) Take(token string, n int) {
	_ = l.TakeContext(context.Background(), token, n)
}

func (l *BandwidthLimiter) tryTake(token string, n int) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b, ok := l.buckets[token]
	if !ok {
		b = &bandwidthBucket{tokens: l.burst, last: now}
		l.buckets[token] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	need := float64(n)
	if b.tokens >= need {
		b.tokens -= need
		return 0
	}
	deficit := need - b.tokens
	b.tokens = 0
	sec := deficit / l.rate
	if sec < 0.001 {
		sec = 0.001
	}
	return time.Duration(sec * float64(time.Second))
}

// ==========================================
// 3. Dial Guard & SSRF Protection
// ==========================================

// IsBlockedTarget returns true if target must not be dialed (loopback, private, CGNAT, etc.)
func IsBlockedTarget(target string) (bool, string) {
	host := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	host = strings.TrimSpace(host)
	if host == "" {
		return true, "empty host"
	}
	low := strings.ToLower(host)
	if low == "localhost" || low == "localhost." {
		return true, "localhost"
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false, ""
	}
	return IsBlockedIP(ip)
}

// IsBlockedIP returns true if IP is loopback, private, link-local, unspecified, or CGNAT.
func IsBlockedIP(ip net.IP) (bool, string) {
	if ip == nil {
		return true, "nil ip"
	}
	if ip.IsLoopback() {
		return true, "loopback"
	}
	if ip.IsPrivate() {
		return true, "private"
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true, "link-local"
	}
	if ip.IsUnspecified() {
		return true, "unspecified"
	}
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return true, "cgnat"
		}
	}
	return false, ""
}

// WarpRouteConfig holds the upstream Cloudflare WARP proxy address and routing scope
type WarpRouteConfig struct {
	ProxyAddr string // e.g. "127.0.0.1:40000"
	WarpAll   bool   // true: route all outbound traffic; false: AI & Google domains only
	FailOpen  bool   // true: fail-open to direct dial on WARP error; false: fail-closed for AI domains (M4)
}

// DialGuard provides concurrency limiting, SSRF protection, and intelligent Cloudflare WARP upstream routing
type DialGuard struct {
	sem          chan struct{}
	AllowLocal   bool
	warpCfg      atomic.Pointer[WarpRouteConfig]
	warpHealthy  atomic.Bool
	probeTrigger chan struct{}
	stopCh       chan struct{}
	closeOnce    sync.Once
}

// NewDialGuard creates a DialGuard; maxConcurrent <= 0 defaults to 256
func NewDialGuard(maxConcurrent int) *DialGuard {
	if maxConcurrent <= 0 {
		maxConcurrent = 256
	}
	dg := &DialGuard{
		sem:          make(chan struct{}, maxConcurrent),
		probeTrigger: make(chan struct{}, 1),
		stopCh:       make(chan struct{}),
	}
	dg.warpCfg.Store(&WarpRouteConfig{})
	dg.warpHealthy.Store(true)
	go dg.backgroundWarpHealthChecker()
	return dg
}

// Close gracefully stops the background WARP health checker
func (g *DialGuard) Close() {
	if g != nil {
		g.closeOnce.Do(func() {
			close(g.stopCh)
		})
	}
}

// SetWarpProxy configures upstream Cloudflare WARP SOCKS5 proxy
func (g *DialGuard) SetWarpProxy(proxyAddr string, all bool) {
	g.SetWarpProxyWithPolicy(proxyAddr, all, false)
}

// SetWarpProxyWithPolicy configures upstream Cloudflare WARP SOCKS5 proxy with explicit Fail-Open policy (M4)
func (g *DialGuard) SetWarpProxyWithPolicy(proxyAddr string, all bool, failOpen bool) {
	if g != nil {
		cleanAddr := strings.TrimSpace(proxyAddr)
		g.warpCfg.Store(&WarpRouteConfig{
			ProxyAddr: cleanAddr,
			WarpAll:   all,
			FailOpen:  failOpen,
		})
		if cleanAddr != "" {
			select {
			case g.probeTrigger <- struct{}{}:
			default:
			}
		}
	}
}

// GetWarpStatus returns the current WARP proxy address, full-route flag, enabled state, and health
func (g *DialGuard) GetWarpStatus() (proxy string, all bool, enabled bool, healthy bool) {
	if g == nil {
		return "", false, false, false
	}
	cfg := g.warpCfg.Load()
	if cfg == nil || cfg.ProxyAddr == "" {
		return "", false, false, false
	}
	return cfg.ProxyAddr, cfg.WarpAll, true, g.warpHealthy.Load()
}

// DialTimeout dials with concurrency limiting, SSRF protection, and WARP unblocking
func (g *DialGuard) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	dialFn := safeDial
	if g != nil && g.AllowLocal {
		dialFn = net.DialTimeout
	}

	isAIDomain := isTargetAIDomain(address)

	var warpCfg *WarpRouteConfig
	if g != nil {
		warpCfg = g.warpCfg.Load()
	}
	hasWarp := warpCfg != nil && warpCfg.ProxyAddr != ""

	// 智能 WARP 出口净化：当配置/探测到远端 VPS 运行了 Cloudflare WARP SOCKS5 代理时，
	// 对 Google、OpenAI、Gemini 等 AI 限制域名（或全量流量）经由 WARP 出口转发，彻底消灭 IP 标记与 403 封锁！
	if g != nil && hasWarp && (warpCfg.WarpAll || isAIDomain) {
		if g.warpHealthy.Load() {
			c, err := dialViaSOCKS5(warpCfg.ProxyAddr, address, timeout)
			if err == nil {
				return c, nil
			}
			g.warpHealthy.Store(false)
			select {
			case g.probeTrigger <- struct{}{}:
			default:
			}
			log.Printf("[WARP-CIRCUIT-OPEN] Upstream WARP dial failed for %s (%v). Circuit tripped.", address, err)
		}

		// WARP 策略收敛（M4）：统一支持 Fail-Open（平滑放行直连）与 Fail-Closed（审计阻断防泄漏）。
		// 当配置 FailOpen=true 或设置 AERO_WARP_MODE=fail-open 时平滑放行直连出站；默认保留 Fail-Closed 保护。
		mode := os.Getenv("AERO_WARP_MODE")
		failOpen := (warpCfg != nil && warpCfg.FailOpen) || strings.EqualFold(mode, "fail-open")
		if isAIDomain && !failOpen {
			return nil, fmt.Errorf("AERO_WARP_FAIL_CLOSED: direct dial refused to prevent AI region leak (target: %s)", address)
		}

		log.Printf("[WARP-FALLBACK] Target %s dial via direct due to open circuit (fail-open=%v).", address, failOpen)
	}

	if g == nil || g.sem == nil {
		return dialFn(network, address, timeout)
	}
	select {
	case g.sem <- struct{}{}:
		defer func() { <-g.sem }()
	case <-time.After(timeout):
		return nil, fmt.Errorf("dial queue full")
	}
	return dialFn(network, address, timeout)
}

func (g *DialGuard) backgroundWarpHealthChecker() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-g.stopCh:
			return
		case <-ticker.C:
		case <-g.probeTrigger:
		}

		if g == nil {
			continue
		}
		cfg := g.warpCfg.Load()
		if cfg == nil || cfg.ProxyAddr == "" {
			continue
		}

		probeConn, err := net.DialTimeout("tcp", cfg.ProxyAddr, 1500*time.Millisecond)
		if err == nil {
			_ = probeConn.Close()
			if !g.warpHealthy.Load() {
				log.Printf("[WARP-CIRCUIT-RESET] WARP proxy %s recovered. Normal routing restored.", cfg.ProxyAddr)
				g.warpHealthy.Store(true)
			}
		}
	}
}

var googleAICIDRs = parseAICIDRs([]string{
	"142.250.0.0/16",
	"172.217.0.0/16",
	"216.58.192.0/19",
	"108.177.0.0/17",
	"74.125.0.0/16",
	"173.194.0.0/16",
	"64.233.160.0/19",
	"66.249.64.0/19",
	"2607:f8b0::/32",
	"2001:4860::/32",
})

func parseAICIDRs(cidrs []string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, ipNet, err := net.ParseCIDR(c)
		if err == nil && ipNet != nil {
			nets = append(nets, ipNet)
		}
	}
	return nets
}

func isTargetAIDomain(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	host = strings.Trim(strings.TrimRight(strings.ToLower(strings.TrimSpace(host)), "."), "[]")
	if host == "" {
		return false
	}

	if ip := net.ParseIP(host); ip != nil {
		for _, ipNet := range googleAICIDRs {
			if ipNet.Contains(ip) {
				return true
			}
		}
		return false
	}

	aiSuffixes := []string{
		"google.com",
		"googleapis.com",
		"gstatic.com",
		"googleusercontent.com",
		"ggpht.com",
		"youtube.com",
		"ytimg.com",
		"openai.com",
		"chatgpt.com",
		"oaistatic.com",
		"oaiusercontent.com",
		"anthropic.com",
		"claude.ai",
		"ai.google.dev",
		"makersuite.google.com",
		"aistudio.google.com",
		"gemini.google.com",
		"clients6.google.com",
		"generativelanguage.googleapis.com",
		"deepmind.google",
		"deepmind.com",
		"bing.com",
		"copilot.microsoft.com",
		"perplexity.ai",
		"x.ai",
		"grok.com",
		"mistral.ai",
		"groq.com",
		"cohere.ai",
		"together.xyz",
		"replicate.com",
		"openrouter.ai",
		"fireworks.ai",
		"cursor.sh",
		"cursorapi.com",
	}

	for _, suffix := range aiSuffixes {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

func dialViaSOCKS5(proxyAddr, targetAddr string, timeout time.Duration) (net.Conn, error) {
	tcpNet := "tcp4"
	proxyHost, _, _ := net.SplitHostPort(proxyAddr)
	if ip := net.ParseIP(proxyHost); ip != nil && ip.To4() == nil {
		tcpNet = "tcp"
	}
	conn, err := net.DialTimeout(tcpNet, proxyAddr, timeout)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("invalid target address: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		_ = conn.Close()
		return nil, fmt.Errorf("invalid port in %s", targetAddr)
	}

	// 1. SOCKS5 握手: 客户端问候 [VER=5, NMETHODS=1, METHOD=0 (No Auth)]
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 greeting failed: %w", err)
	}

	// 读取服务端选择
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 auth resp failed: %w", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 auth rejected: 0x%02x", resp[1])
	}

	// 2. CONNECT 请求 [VER=5, CMD=1 (CONNECT), RSV=0, ATYP=..., DST.ADDR, DST.PORT]
	var req []byte
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		req = make([]byte, 4+net.IPv4len+2)
		req[0] = 0x05
		req[1] = 0x01
		req[2] = 0x00
		req[3] = 0x01 // IPv4
		copy(req[4:4+net.IPv4len], ip4)
		binary.BigEndian.PutUint16(req[4+net.IPv4len:], uint16(port))
	} else if ip6 := ip.To16(); ip6 != nil {
		req = make([]byte, 4+net.IPv6len+2)
		req[0] = 0x05
		req[1] = 0x01
		req[2] = 0x00
		req[3] = 0x04 // IPv6
		copy(req[4:4+net.IPv6len], ip6)
		binary.BigEndian.PutUint16(req[4+net.IPv6len:], uint16(port))
	} else {
		// 域名 (FQDN)
		if len(host) > 255 {
			_ = conn.Close()
			return nil, fmt.Errorf("domain name too long: %s", host)
		}
		req = make([]byte, 4+1+len(host)+2)
		req[0] = 0x05
		req[1] = 0x01
		req[2] = 0x00
		req[3] = 0x03 // Domain name
		req[4] = byte(len(host))
		copy(req[5:5+len(host)], host)
		binary.BigEndian.PutUint16(req[5+len(host):], uint16(port))
	}

	if _, err := conn.Write(req); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 connect request failed: %w", err)
	}

	// 3. 读取连接响应 [VER, REP, RSV, ATYP, BND.ADDR, BND.PORT]
	connResp := make([]byte, 4)
	if _, err := io.ReadFull(conn, connResp); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 connect resp header failed: %w", err)
	}
	if connResp[1] != 0x00 {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 connect rejected by upstream: 0x%02x", connResp[1])
	}

	// 消费剩余的绑定地址
	switch connResp[3] {
	case 0x01: // IPv4
		bnd := make([]byte, 4+2)
		_, _ = io.ReadFull(conn, bnd)
	case 0x04: // IPv6
		bnd := make([]byte, 16+2)
		_, _ = io.ReadFull(conn, bnd)
	case 0x03: // Domain
		lenBuf := make([]byte, 1)
		_, _ = io.ReadFull(conn, lenBuf)
		bnd := make([]byte, int(lenBuf[0])+2)
		_, _ = io.ReadFull(conn, bnd)
	}

	// 连接成功后清除滑动 deadline，恢复长连接全双工通信
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

var socks5UDPReadPool = sync.Pool{
	New: func() any {
		b := make([]byte, 65535)
		return &b
	},
}

var socks5UDPWritePool = sync.Pool{
	New: func() any {
		b := make([]byte, 65535)
		return &b
	},
}

type socksTargetAddr struct {
	network string
	addr    string
}

func (a socksTargetAddr) Network() string { return a.network }
func (a socksTargetAddr) String() string  { return a.addr }

// socks5UDPConn wraps a UDP connection associate session with an upstream SOCKS5 proxy
type socks5UDPConn struct {
	tcpConn   net.Conn
	udpConn   *net.UDPConn
	relayAddr *net.UDPAddr
	targetHdr []byte
	raddr     net.Addr
	closeOnce sync.Once
	closed    atomic.Bool
}

func (c *socks5UDPConn) Read(p []byte) (int, error) {
	bufPtr := socks5UDPReadPool.Get().(*[]byte)
	defer socks5UDPReadPool.Put(bufPtr)
	rawBuf := *bufPtr

	for {
		if c.closed.Load() {
			return 0, net.ErrClosed
		}
		n, err := c.udpConn.Read(rawBuf)
		if err != nil {
			return 0, err
		}
		if n < 4 {
			continue
		}
		if rawBuf[0] != 0x00 || rawBuf[1] != 0x00 {
			continue
		}
		if rawBuf[2] != 0x00 {
			// RFC 1928: fragment dropped
			continue
		}
		var hdrLen int
		switch rawBuf[3] {
		case 0x01: // IPv4 (4 bytes IP + 2 bytes port)
			hdrLen = 10
		case 0x04: // IPv6 (16 bytes IP + 2 bytes port)
			hdrLen = 22
		case 0x03: // Domain (1 byte len + domain + 2 bytes port)
			if n < 5 {
				continue
			}
			dLen := int(rawBuf[4])
			hdrLen = 7 + dLen
		default:
			continue
		}
		if n < hdrLen {
			continue
		}
		payload := rawBuf[hdrLen:n]
		copied := copy(p, payload)
		return copied, nil
	}
}

func (c *socks5UDPConn) Write(p []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	hdrLen := len(c.targetHdr)
	totalLen := hdrLen + len(p)
	if totalLen <= 65535 {
		bufPtr := socks5UDPWritePool.Get().(*[]byte)
		defer socks5UDPWritePool.Put(bufPtr)
		buf := *bufPtr
		copy(buf[:hdrLen], c.targetHdr)
		copy(buf[hdrLen:totalLen], p)
		_, err := c.udpConn.Write(buf[:totalLen])
		if err != nil {
			return 0, err
		}
		return len(p), nil
	}
	packet := make([]byte, totalLen)
	copy(packet[:hdrLen], c.targetHdr)
	copy(packet[hdrLen:], p)
	_, err := c.udpConn.Write(packet)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *socks5UDPConn) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		if c.udpConn != nil {
			_ = c.udpConn.Close()
		}
		if c.tcpConn != nil {
			_ = c.tcpConn.Close()
		}
	})
	return nil
}

func (c *socks5UDPConn) LocalAddr() net.Addr {
	if c.udpConn != nil {
		return c.udpConn.LocalAddr()
	}
	return nil
}

func (c *socks5UDPConn) RemoteAddr() net.Addr {
	return c.raddr
}

func (c *socks5UDPConn) SetDeadline(t time.Time) error {
	if c.udpConn != nil {
		return c.udpConn.SetDeadline(t)
	}
	return nil
}

func (c *socks5UDPConn) SetReadDeadline(t time.Time) error {
	if c.udpConn != nil {
		return c.udpConn.SetReadDeadline(t)
	}
	return nil
}

func (c *socks5UDPConn) SetWriteDeadline(t time.Time) error {
	if c.udpConn != nil {
		return c.udpConn.SetWriteDeadline(t)
	}
	return nil
}

func dialUDPViaSOCKS5(proxyAddr, targetAddr string, timeout time.Duration) (net.Conn, error) {
	tcpNet := "tcp4"
	proxyHost, _, _ := net.SplitHostPort(proxyAddr)
	if ip := net.ParseIP(proxyHost); ip != nil && ip.To4() == nil {
		tcpNet = "tcp"
	}
	tcpConn, err := net.DialTimeout(tcpNet, proxyAddr, timeout)
	if err != nil {
		return nil, err
	}
	_ = tcpConn.SetDeadline(time.Now().Add(timeout))
	if tc, ok := tcpConn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(15 * time.Second)
	}

	// 1. SOCKS5 握手: 客户端问候 [VER=5, NMETHODS=1, METHOD=0 (No Auth)]
	if _, err := tcpConn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		_ = tcpConn.Close()
		return nil, fmt.Errorf("socks5 greeting failed: %w", err)
	}

	authResp := make([]byte, 2)
	if _, err := io.ReadFull(tcpConn, authResp); err != nil {
		_ = tcpConn.Close()
		return nil, fmt.Errorf("socks5 auth resp failed: %w", err)
	}
	if authResp[0] != 0x05 || authResp[1] != 0x00 {
		_ = tcpConn.Close()
		return nil, fmt.Errorf("socks5 auth rejected: 0x%02x", authResp[1])
	}

	// 2. UDP ASSOCIATE 请求 [VER=5, CMD=3 (UDP ASSOCIATE), RSV=0, ATYP=1, 0.0.0.0:0]
	if _, err := tcpConn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		_ = tcpConn.Close()
		return nil, fmt.Errorf("socks5 udp associate request failed: %w", err)
	}

	// 3. 读取连接响应头 [VER, REP, RSV, ATYP]
	respHdr := make([]byte, 4)
	if _, err := io.ReadFull(tcpConn, respHdr); err != nil {
		_ = tcpConn.Close()
		return nil, fmt.Errorf("socks5 udp associate resp header failed: %w", err)
	}
	if respHdr[0] != 0x05 {
		_ = tcpConn.Close()
		return nil, fmt.Errorf("socks5 udp associate invalid version: 0x%02x", respHdr[0])
	}
	if respHdr[1] != 0x00 {
		_ = tcpConn.Close()
		return nil, fmt.Errorf("socks5 udp associate rejected by upstream: 0x%02x", respHdr[1])
	}

	var relayIP net.IP
	var relayPort uint16
	switch respHdr[3] {
	case 0x01: // IPv4
		b := make([]byte, 4+2)
		if _, err := io.ReadFull(tcpConn, b); err != nil {
			_ = tcpConn.Close()
			return nil, fmt.Errorf("socks5 read bnd.addr ipv4 failed: %w", err)
		}
		relayIP = net.IP(b[:4])
		relayPort = binary.BigEndian.Uint16(b[4:])
	case 0x04: // IPv6
		b := make([]byte, 16+2)
		if _, err := io.ReadFull(tcpConn, b); err != nil {
			_ = tcpConn.Close()
			return nil, fmt.Errorf("socks5 read bnd.addr ipv6 failed: %w", err)
		}
		relayIP = net.IP(b[:16])
		relayPort = binary.BigEndian.Uint16(b[16:])
	case 0x03: // Domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(tcpConn, lenBuf); err != nil {
			_ = tcpConn.Close()
			return nil, fmt.Errorf("socks5 read bnd.addr domain len failed: %w", err)
		}
		b := make([]byte, int(lenBuf[0])+2)
		if _, err := io.ReadFull(tcpConn, b); err != nil {
			_ = tcpConn.Close()
			return nil, fmt.Errorf("socks5 read bnd.addr domain failed: %w", err)
		}
		domain := string(b[:lenBuf[0]])
		relayPort = binary.BigEndian.Uint16(b[lenBuf[0]:])
		if domain == "" || domain == "localhost" {
			tcpHost, _, _ := net.SplitHostPort(proxyAddr)
			if ip := net.ParseIP(tcpHost); ip != nil {
				relayIP = ip
			} else {
				relayIP = net.IPv4(127, 0, 0, 1)
			}
		} else {
			ips, err := net.LookupIP(domain)
			if err != nil || len(ips) == 0 {
				_ = tcpConn.Close()
				return nil, fmt.Errorf("socks5 resolve bnd domain %s failed: %w", domain, err)
			}
			for _, ip := range ips {
				if ip4 := ip.To4(); ip4 != nil {
					relayIP = ip4
					break
				}
			}
			if relayIP == nil {
				relayIP = ips[0]
			}
		}
	default:
		_ = tcpConn.Close()
		return nil, fmt.Errorf("socks5 unknown bnd address type: 0x%02x", respHdr[3])
	}

	_ = tcpConn.SetDeadline(time.Time{})

	if relayIP == nil || relayIP.IsUnspecified() {
		tcpHost, _, _ := net.SplitHostPort(proxyAddr)
		if ip := net.ParseIP(tcpHost); ip != nil {
			relayIP = ip
		} else {
			relayIP = net.IPv4(127, 0, 0, 1)
		}
	}

	if relayPort == 0 {
		_ = tcpConn.Close()
		return nil, fmt.Errorf("socks5 udp associate returned invalid relay port 0")
	}

	relayUDPAddr := &net.UDPAddr{
		IP:   relayIP,
		Port: int(relayPort),
	}

	udpNet := "udp4"
	if relayIP.To4() == nil {
		udpNet = "udp"
	}
	udpConn, err := net.DialUDP(udpNet, nil, relayUDPAddr)
	if err != nil {
		_ = tcpConn.Close()
		return nil, fmt.Errorf("socks5 dial relay udp %s failed: %w", relayUDPAddr, err)
	}

	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		host = targetAddr
		portStr = "443"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		port = 443
	}
	host = strings.Trim(strings.TrimRight(strings.ToLower(strings.TrimSpace(host)), "."), "[]")
	if host == "" {
		_ = udpConn.Close()
		_ = tcpConn.Close()
		return nil, fmt.Errorf("empty target host in %s", targetAddr)
	}

	var targetHdr []byte
	ip := net.ParseIP(host)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			targetHdr = make([]byte, 10)
			targetHdr[3] = 0x01
			copy(targetHdr[4:8], ip4)
			binary.BigEndian.PutUint16(targetHdr[8:10], uint16(port))
		} else {
			targetHdr = make([]byte, 22)
			targetHdr[3] = 0x04
			copy(targetHdr[4:20], ip.To16())
			binary.BigEndian.PutUint16(targetHdr[20:22], uint16(port))
		}
	} else {
		if len(host) > 255 {
			_ = udpConn.Close()
			_ = tcpConn.Close()
			return nil, fmt.Errorf("domain too long: %s", host)
		}
		targetHdr = make([]byte, 7+len(host))
		targetHdr[3] = 0x03
		targetHdr[4] = byte(len(host))
		copy(targetHdr[5:5+len(host)], host)
		binary.BigEndian.PutUint16(targetHdr[5+len(host):], uint16(port))
	}

	sc := &socks5UDPConn{
		tcpConn:   tcpConn,
		udpConn:   udpConn,
		relayAddr: relayUDPAddr,
		targetHdr: targetHdr,
		raddr:     socksTargetAddr{network: "udp", addr: targetAddr},
	}

	go func() {
		buf := make([]byte, 1)
		for {
			if _, err := tcpConn.Read(buf); err != nil {
				_ = sc.Close()
				return
			}
		}
	}()

	return sc, nil
}

// ShouldRouteUDP determines whether the target UDP traffic should be routed via Cloudflare WARP.
func (g *DialGuard) ShouldRouteUDP(target string, port int) bool {
	if g == nil {
		return false
	}
	cfg := g.warpCfg.Load()
	if cfg == nil || cfg.ProxyAddr == "" {
		return false
	}
	if cfg.WarpAll {
		return true
	}
	if port == 0 {
		_, portStr, err := net.SplitHostPort(target)
		if err == nil {
			if p, err := strconv.Atoi(portStr); err == nil {
				port = p
			}
		}
	}
	// AI HTTP/3 / QUIC traffic (UDP 443) must be routed via WARP IPv6 to protect VPS source IP
	if port == 443 && isTargetAIDomain(target) {
		return true
	}
	return false
}

// DialUDPViaWARP dials targetAddr using SOCKS5 UDP Associate via upstream Cloudflare WARP.
func (g *DialGuard) DialUDPViaWARP(targetAddr string, timeout time.Duration) (net.Conn, error) {
	if g == nil {
		return nil, fmt.Errorf("dial guard not configured")
	}
	cfg := g.warpCfg.Load()
	if cfg == nil || cfg.ProxyAddr == "" {
		return nil, fmt.Errorf("warp proxy not configured")
	}
	if !g.warpHealthy.Load() {
		return nil, fmt.Errorf("AERO_WARP_FAIL_CLOSED: WARP circuit open, direct dial refused (target: %s)", targetAddr)
	}
	conn, err := dialUDPViaSOCKS5(cfg.ProxyAddr, targetAddr, timeout)
	if err != nil {
		g.warpHealthy.Store(false)
		select {
		case g.probeTrigger <- struct{}{}:
		default:
		}
		log.Printf("[WARP-UDP-CIRCUIT-OPEN] Upstream WARP UDP Associate failed for %s (%v). Circuit tripped.", targetAddr, err)
		mode := os.Getenv("AERO_WARP_MODE")
		failOpen := (cfg != nil && cfg.FailOpen) || strings.EqualFold(mode, "fail-open")
		if isTargetAIDomain(targetAddr) && !failOpen {
			return nil, fmt.Errorf("AERO_WARP_FAIL_CLOSED: WARP UDP Associate failed to prevent AI region leak (target: %s): %w", targetAddr, err)
		}
		return nil, err
	}
	return conn, nil
}

func safeDial(network, address string, timeout time.Duration) (net.Conn, error) {
	if network == "tcp" {
		host, _, _ := net.SplitHostPort(address)
		if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
			// Explicit IPv6 literal
		} else {
			network = "tcp4"
		}
	} else if network == "udp" {
		host, _, _ := net.SplitHostPort(address)
		if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
			// Explicit IPv6 literal
		} else {
			network = "udp4"
		}
	}
	d := &net.Dialer{
		Timeout: timeout,
		Control: func(network, address string, c syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err == nil {
				if ip := net.ParseIP(host); ip != nil {
					if blocked, why := IsBlockedIP(ip); blocked {
						return fmt.Errorf("blocked target IP %s (%s)", ip, why)
					}
				}
			}
			return nil
		},
	}
	return d.Dial(network, address)
}

// Cap returns concurrency capacity
func (g *DialGuard) Cap() int {
	if g == nil || g.sem == nil {
		return 0
	}
	return cap(g.sem)
}

// ==========================================
// 4. Rate Limiter (IP Connection Rate & Ban)
// ==========================================

// RateLimiter limits incoming connection rates per IP and manages temporary bans
type RateLimiter struct {
	mu            sync.Mutex
	buckets       map[string]*rateTokenBucket
	maxPerIP      float64
	banAfter      int
	banDuration   time.Duration
	bans          map[string]time.Time
	fails         map[string]int
	lastSweep     time.Time
	lastSweepUnix atomic.Int64
}

type rateTokenBucket struct {
	tokens   float64
	lastTime time.Time
	rate     float64
	max      float64
}

// NewRateLimiter creates a RateLimiter; maxConnsPerIPPerSec <= 0 defaults to 200
func NewRateLimiter(maxConnsPerIPPerSec int) *RateLimiter {
	if maxConnsPerIPPerSec <= 0 {
		maxConnsPerIPPerSec = 200
	}
	return &RateLimiter{
		buckets:     make(map[string]*rateTokenBucket),
		maxPerIP:    float64(maxConnsPerIPPerSec),
		banAfter:    20,
		banDuration: 10 * time.Minute,
		bans:        make(map[string]time.Time),
		fails:       make(map[string]int),
		lastSweep:   time.Now(),
	}
}

// ClientIP extracts IP from HTTP request using physical RemoteAddr
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Allow returns true if IP is allowed to connect
func (l *RateLimiter) Allow(ip string) bool {
	nowUnix := time.Now().Unix()
	// 锁外无锁检查：若距上次清理不足 120 秒，绝不进锁全量清扫！ (NEW-04)
	if nowUnix-l.lastSweepUnix.Load() > 120 {
		if l.lastSweepUnix.CompareAndSwap(l.lastSweepUnix.Load(), nowUnix) {
			l.mu.Lock()
			l.sweepLocked()
			l.mu.Unlock()
		}
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if until, ok := l.bans[ip]; ok {
		if time.Now().Before(until) {
			return false
		}
		delete(l.bans, ip)
		delete(l.fails, ip)
	}

	now := time.Now()
	b, ok := l.buckets[ip]
	if !ok {
		l.buckets[ip] = &rateTokenBucket{
			tokens:   l.maxPerIP - 1,
			lastTime: now,
			rate:     l.maxPerIP,
			max:      l.maxPerIP,
		}
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

// RecordFail increments failure count and bans IP if threshold exceeded
func (l *RateLimiter) RecordFail(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fails[ip]++
	if l.fails[ip] >= l.banAfter {
		l.bans[ip] = time.Now().Add(l.banDuration)
		l.fails[ip] = 0
		return true
	}
	return false
}

// IsBanned returns true if IP is currently banned
func (l *RateLimiter) IsBanned(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	until, ok := l.bans[ip]
	return ok && time.Now().Before(until)
}

func (l *RateLimiter) sweepLocked() {
	if time.Since(l.lastSweep) < 2*time.Minute {
		return
	}
	l.lastSweep = time.Now()
	cutoff := time.Now().Add(-5 * time.Minute)
	for k, b := range l.buckets {
		if b.lastTime.Before(cutoff) {
			delete(l.buckets, k)
		}
	}
	now := time.Now()
	for k, until := range l.bans {
		if now.After(until) {
			delete(l.bans, k)
		}
	}
}
