// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/quicvarint"
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
			tokens:   299,
			lastTime: now,
			rate:     100,
			max:      300,
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

// IPPool 在 CIDR 内为 CONNECT-IP 会话分配 /32 地址。按 token 粘性分配：会话释放后，
// 该地址为同一 token 保留 ipLeaseTTL，期间不分给其他会话；同一 token 重连优先拿回原地址，
// 使客户端在网络切换或短暂断线后隧道 IP 不变。
type IPPool struct {
	mu       sync.Mutex
	base     uint32 // 网络地址（已掩码）
	nextHost uint32
	maxHost  uint32 // 可分配的最大主机号（不含广播）
	used     map[netip.Addr]struct{}
	leases   map[string]ipLease    // token → 释放后保留的地址
	leasedBy map[netip.Addr]string // 地址 → 持有租约的 token
	now      func() time.Time
}

type ipLease struct {
	addr  netip.Addr
	until time.Time
}

// ipLeaseTTL 是地址为原 token 保留的时长（估算，覆盖网络切换与 edge 平滑重启之外的短暂断线）。
const ipLeaseTTL = 30 * time.Minute

// NewIPPool 创建地址池（默认 10.88.0.0/16）。主机号从 2 开始（1 为网关）。
func NewIPPool(cidrStr string) (*IPPool, error) {
	if cidrStr == "" {
		cidrStr = "10.88.0.0/16"
	}
	prefix, err := netip.ParsePrefix(cidrStr)
	if err != nil {
		return nil, err
	}
	if !prefix.Addr().Is4() || prefix.Bits() > 29 {
		return nil, fmt.Errorf("IPv4 pool %s must be an IPv4 prefix no smaller than /29", cidrStr)
	}
	b := prefix.Masked().Addr().As4()
	return &IPPool{
		base:     binary.BigEndian.Uint32(b[:]),
		nextHost: 2,
		maxHost:  (uint32(1) << (32 - prefix.Bits())) - 2,
		used:     make(map[netip.Addr]struct{}),
		leases:   make(map[string]ipLease),
		leasedBy: make(map[netip.Addr]string),
		now:      time.Now,
	}, nil
}

// Allocate 分配一个不绑定 token 的地址。
func (p *IPPool) Allocate() (netip.Prefix, error) { return p.AllocateFor("") }

// AllocateFor 为 key（token）分配地址：优先归还该 key 未过期租约中的地址。
func (p *IPPool) AllocateFor(key string) (netip.Prefix, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	if l, ok := p.leases[key]; ok && key != "" {
		p.dropLease(key, l.addr)
		if _, inUse := p.used[l.addr]; !inUse && now.Before(l.until) {
			p.used[l.addr] = struct{}{}
			return netip.PrefixFrom(l.addr, 32), nil
		}
	}
	// 主机号范围 [2, maxHost]。带 token 的分配从 token 哈希位置开始探测，edge 重启（租约丢失）
	// 后同一 token 仍大概率拿回同一地址；无 token 的分配沿用顺序指针。
	span := p.maxHost - 1
	start := p.nextHost - 2
	if key != "" {
		h := fnv.New32a()
		_, _ = h.Write([]byte(key))
		start = h.Sum32() % span
	}
	for i := uint32(0); i < span; i++ {
		host := 2 + (start+i)%span
		var a [4]byte
		binary.BigEndian.PutUint32(a[:], p.base+host)
		cand := netip.AddrFrom4(a)
		if _, inUse := p.used[cand]; inUse {
			continue
		}
		if owner, leased := p.leasedBy[cand]; leased {
			if now.Before(p.leases[owner].until) {
				continue // 为其他 token 保留中
			}
			p.dropLease(owner, cand)
		}
		p.used[cand] = struct{}{}
		if key == "" {
			p.nextHost = 2 + (host-1)%span // 下一个主机号，越过上界回到 2
		}
		return netip.PrefixFrom(cand, 32), nil
	}
	return netip.Prefix{}, errors.New("ip pool exhausted")
}

// Release 释放不绑定 token 的地址。
func (p *IPPool) Release(prefix netip.Prefix) { p.ReleaseFor("", prefix) }

// ReleaseFor 释放地址；key 非空时为该 key 保留 ipLeaseTTL。
func (p *IPPool) ReleaseFor(key string, prefix netip.Prefix) {
	p.mu.Lock()
	defer p.mu.Unlock()
	addr := prefix.Addr()
	delete(p.used, addr)
	if key == "" {
		return
	}
	if old, ok := p.leases[key]; ok {
		p.dropLease(key, old.addr)
	}
	p.leases[key] = ipLease{addr: addr, until: p.now().Add(ipLeaseTTL)}
	p.leasedBy[addr] = key
}

// dropLease 删除 key 对 addr 的租约（调用方持锁）。
func (p *IPPool) dropLease(key string, addr netip.Addr) {
	delete(p.leases, key)
	if p.leasedBy[addr] == key {
		delete(p.leasedBy, addr)
	}
}

// Available 报告是否还有未使用的地址（租约中的地址计为可能可用）。
func (p *IPPool) Available() bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return uint32(len(p.used)) < p.maxHost-1
}

// IPv6Pool dynamically allocates client IPv6 addresses from a configured prefix.
type IPv6Pool struct {
	mu       sync.Mutex
	baseIP   netip.Addr
	prefix   int
	nextHost uint32
	maxHost  uint32
	used     map[netip.Addr]struct{}
}

// Allocate returns an unused /128 IPv6 prefix from the pool.
func (p *IPv6Pool) Allocate() (netip.Prefix, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	base16 := p.baseIP.As16()
	baseVal := binary.BigEndian.Uint32(base16[12:16])

	for i := uint32(0); i < p.maxHost; i++ {
		host := p.nextHost
		p.nextHost++
		if p.nextHost >= p.maxHost {
			p.nextHost = 2
		}
		val := baseVal + host
		var cand16 [16]byte
		copy(cand16[:12], base16[:12])
		binary.BigEndian.PutUint32(cand16[12:], val)
		candAddr := netip.AddrFrom16(cand16)
		if _, exists := p.used[candAddr]; !exists {
			p.used[candAddr] = struct{}{}
			return netip.PrefixFrom(candAddr, 128), nil
		}
	}
	return netip.Prefix{}, errors.New("ipv6 pool exhausted")
}

// Release returns a prefix back to the pool.
func (p *IPv6Pool) Release(prefix netip.Prefix) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.used, prefix.Addr())
}

// Available checks if there is any available IPv6 address in the pool.
func (p *IPv6Pool) Available() bool {
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
	conns map[*quic.Conn]connBinding
	seq   uint64 // 绑定顺序，用于找出最早的连接
}

// connAlive 报告连接是否仍存活；可在测试中替换（零值 quic.Conn 没有上下文）。
var connAlive = func(c *quic.Conn) bool {
	select {
	case <-c.Context().Done():
		return false
	default:
		return true
	}
}

// connBinding 是连接绑定的 token 与（签名 token 的）uid；uid 用于本节点设备数计数（C3 §3 第 7 步）。
type connBinding struct {
	token, uid string
	seq        uint64
}

// NewConnTracker creates a new ConnTracker.
func NewConnTracker() *ConnTracker {
	return &ConnTracker{conns: make(map[*quic.Conn]connBinding)}
}

// Get returns the token bound to c.
func (ct *ConnTracker) Get(c *quic.Conn) (string, bool) {
	if c == nil {
		return "", false
	}
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	b, ok := ct.conns[c]
	return b.token, ok
}

// UID 返回 c 绑定的签名 token 的 uid（不透明 token 或未绑定时为空）。
func (ct *ConnTracker) UID(c *quic.Conn) string {
	if c == nil {
		return ""
	}
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return ct.conns[c].uid
}

// Bind associates token with c.
func (ct *ConnTracker) Bind(c *quic.Conn, token string) {
	if c == nil {
		return
	}
	ct.mu.Lock()
	ct.conns[c] = connBinding{token: token}
	ct.mu.Unlock()
}

// BindEvictOldest 在同一把锁内计数并绑定（L0 §7.5 原子，C3 §3 第 7 步）：uid 非空且 max > 0 时，
// 若该 uid 在本节点的存活连接加上本连接超过 max，则摘除最早的连接并返回它们，由调用方在锁外断开。
// 新连接总是被接受：服务端无法及时区分“同一设备换网重连”与“另一设备上线”（最长 90 秒空闲超时）。
func (ct *ConnTracker) BindEvictOldest(c *quic.Conn, token, uid string, max int) []*quic.Conn {
	if c == nil {
		return nil
	}
	ct.mu.Lock()
	defer ct.mu.Unlock()
	var evict []*quic.Conn
	if uid != "" && max > 0 {
		var same []*quic.Conn
		for other, b := range ct.conns {
			if other == c || b.uid != uid {
				continue
			}
			if !connAlive(other) { // 已关闭的连接不计数（定期清理每 5 分钟才删除记录）
				delete(ct.conns, other)
				continue
			}
			same = append(same, other)
		}
		if extra := len(same) + 1 - max; extra > 0 {
			sort.Slice(same, func(i, j int) bool { return ct.conns[same[i]].seq < ct.conns[same[j]].seq })
			evict = same[:extra]
			for _, e := range evict {
				delete(ct.conns, e)
			}
		}
	}
	ct.seq++
	ct.conns[c] = connBinding{token: token, uid: uid, seq: ct.seq}
	return evict
}

// closeEvictedConn 断开因设备数上限被替换的连接；可在测试中替换。
var closeEvictedConn = func(c *quic.Conn) {
	_ = c.CloseWithError(0x103, "EDGE_DEVICE_LIMIT: replaced by a newer connection of the same user")
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

// CloseByToken actively disconnects and removes all QUIC connections associated with the specified token.
func (ct *ConnTracker) CloseByToken(token string) {
	if ct == nil || token == "" {
		return
	}
	ct.mu.Lock()
	var toClose []*quic.Conn
	for c, b := range ct.conns {
		if b.token == token {
			toClose = append(toClose, c)
			delete(ct.conns, c)
		}
	}
	ct.mu.Unlock()

	for _, c := range toClose {
		if c != nil {
			_ = c.CloseWithError(0x100, "token revoked / quota exceeded")
		}
	}
}

// CloseAll actively disconnects and removes all tracked QUIC connections.
func (ct *ConnTracker) CloseAll() {
	if ct == nil {
		return
	}
	ct.mu.Lock()
	var toClose []*quic.Conn
	for c := range ct.conns {
		toClose = append(toClose, c)
		delete(ct.conns, c)
	}
	ct.mu.Unlock()

	for _, c := range toClose {
		if c != nil {
			_ = c.CloseWithError(0x101, "offline grace period expired")
		}
	}
}

// CloseUnauthorized 断开并移除 token 已不再有效的全部连接（删除、吊销、过期），
// 返回断开的连接数。valid 在锁外调用，避免与 Validator 的锁嵌套。
func (ct *ConnTracker) CloseUnauthorized(valid func(token string) bool) int {
	if ct == nil || valid == nil {
		return 0
	}
	ct.mu.RLock()
	snapshot := make(map[*quic.Conn]string, len(ct.conns))
	for c, b := range ct.conns {
		snapshot[c] = b.token
	}
	ct.mu.RUnlock()

	var toClose []*quic.Conn
	for c, tok := range snapshot {
		if !valid(tok) {
			toClose = append(toClose, c)
		}
	}
	if len(toClose) == 0 {
		return 0
	}
	ct.mu.Lock()
	for _, c := range toClose {
		delete(ct.conns, c)
	}
	ct.mu.Unlock()
	for _, c := range toClose {
		_ = c.CloseWithError(0x100, "token no longer valid")
	}
	return len(toClose)
}

// Sessions 返回在线（未关闭）连接总数与签名 token 用户的每 uid 连接数（C6 /v1/status，C3 §7 跨节点汇总）。
func (ct *ConnTracker) Sessions() (total int, byUID map[string]int) {
	byUID = make(map[string]int)
	if ct == nil {
		return 0, byUID
	}
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	for c, b := range ct.conns {
		if !connAlive(c) {
			continue
		}
		total++
		if b.uid != "" {
			byUID[b.uid]++
		}
	}
	return total, byUID
}

// CloseAllForShutdown 以 H3_NO_ERROR 关闭全部已跟踪连接并说明原因“server shutting down”，
// 客户端据此立即重连。返回关闭的连接数。
func (ct *ConnTracker) CloseAllForShutdown() int {
	if ct == nil {
		return 0
	}
	ct.mu.Lock()
	toClose := make([]*quic.Conn, 0, len(ct.conns))
	for c := range ct.conns {
		toClose = append(toClose, c)
		delete(ct.conns, c)
	}
	ct.mu.Unlock()
	for _, c := range toClose {
		_ = c.CloseWithError(0x100, "server shutting down")
	}
	return len(toClose)
}

// StartReaper starts periodic dead connection scanning to prevent lingering pointers. (NEW-02)
func (ct *ConnTracker) StartReaper(stopCh <-chan struct{}) {
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				ct.sweepDeadPointers()
			}
		}
	}()
}

func (ct *ConnTracker) sweepDeadPointers() {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	for c := range ct.conns {
		if c == nil {
			delete(ct.conns, c)
			continue
		}
		select {
		case <-c.Context().Done():
			delete(ct.conns, c)
		default:
		}
	}
}

// ==========================================
// 4. QUIC Server Instance & UDP Context Management
// ==========================================

const (
	MaxUDPContextsPerToken = 64
	DefaultMaxGlobalUDP    = 4096
)

type udpSessionTracker struct {
	token      string
	isSTUN     *atomic.Bool
	lastActive *atomic.Int64
	closeFn    func()
}

// QUICServer manages QUIC connections, HTTP/3, MASQUE proxies, UDP contexts, and DNS
type QUICServer struct {
	cfg              *ServerConfig
	validator        *Validator
	tokenVerifier    *TokenVerifier             // 非 nil 即启用 C3 签名 token（auth_signed_token）
	usageMeter       atomic.Pointer[UsageMeter] // C6 计量；nil 表示不计量
	connLimiter      *ConnLimiter
	bandwidthLimiter *BandwidthLimiter
	dialGuard        *DialGuard
	rateLimiter      *RateLimiter
	dnsResolver      *DNSResolver
	connTracker      *ConnTracker
	ipPool           *IPPool
	ipv6Pool         *IPv6Pool
	globalRouter     *GlobalTunnelRouter
	globalReaderMu   sync.Mutex
	globalReader     *GlobalTunnelReader
	authJail         *AuthFailureJail
	masqueProxy      *masque.Proxy
	connectIPProxy   *connectip.Proxy
	h3Server         *http3.Server

	udpTempl *uritemplate.Template
	ipTempl  *uritemplate.Template

	handlerMu sync.RWMutex
	handler   http.Handler

	tokenStore           *TokenStore
	udpMu                sync.Mutex
	tokenUDPCtx          map[string]int
	globalUDPCtx         atomic.Int64
	maxGlobalUDP         int64
	allowLoopbackForTest bool
	resolveUDPFn         func(network, addr string) (*net.UDPAddr, error)
	udpDialFn            func(network string, laddr, raddr *net.UDPAddr) (*net.UDPConn, error)
	icmpForwardHook      func(target net.IP, echoReq []byte) ([]byte, error)
	icmpv6ForwardHook    func(target net.IP, echoReq []byte) ([]byte, error)
	nextHopDialer        func(nextHopAddr, target, hopCred string) (net.Conn, error)
	nextHopUDPDialer     func(nextHopAddr, target, hopCred string) (net.Conn, error)

	// WebRTC STUN fast aging & session tracking
	udpSessions     map[*udpSessionTracker]struct{}
	stunIdleTimeout time.Duration
	udpIdleTimeout  time.Duration

	// tcpIdleTimeout 是标准 CONNECT 中继的空闲上限（双向均无流量）；0 表示默认值。
	tcpIdleTimeout time.Duration

	// token 有效性集中执行（PROJECT_RULES：吊销、过期等 10 秒内断开）
	tokenEnforceInterval time.Duration
	tokenEnforceOnce     sync.Once

	stopCh    chan struct{}
	closeOnce sync.Once
}

const defaultTokenEnforceInterval = 5 * time.Second

// startTokenEnforcer 周期性断开 token 已失效的在线连接。只启动一次，随 Close 退出。
// 在 Server.Start 中启动；测试可在启动前调整 tokenEnforceInterval。
func (s *QUICServer) startTokenEnforcer() {
	if s == nil || s.validator == nil || s.connTracker == nil {
		return
	}
	s.tokenEnforceOnce.Do(func() {
		interval := s.tokenEnforceInterval
		if interval <= 0 {
			interval = defaultTokenEnforceInterval
		}
		ticker := time.NewTicker(interval)
		go func() {
			defer ticker.Stop()
			for {
				select {
				case <-s.stopCh:
					return
				case <-ticker.C:
					if n := s.connTracker.CloseUnauthorized(s.tokenStillValid); n > 0 {
						log.Printf("[AUTH] closed %d connection(s) whose token is no longer valid", n)
					}
				}
			}
		}()
	})
}

// SetTokenStore sets the token store for token management and revocation.
func (s *QUICServer) SetTokenStore(ts *TokenStore) {
	s.tokenStore = ts
}

// TokenStore returns the associated TokenStore instance.
func (s *QUICServer) TokenStore() *TokenStore {
	return s.tokenStore
}

// SetUDPIdleTimeoutsForTest sets custom idle timeouts for STUN and standard UDP sessions in unit tests.
func (s *QUICServer) SetUDPIdleTimeoutsForTest(stunTimeout, normalTimeout time.Duration) {
	s.stunIdleTimeout = stunTimeout
	s.udpIdleTimeout = normalTimeout
}

func (s *QUICServer) registerUDPSession(tracker *udpSessionTracker) {
	s.udpMu.Lock()
	defer s.udpMu.Unlock()
	if s.udpSessions == nil {
		s.udpSessions = make(map[*udpSessionTracker]struct{})
	}
	s.udpSessions[tracker] = struct{}{}
}

func (s *QUICServer) unregisterUDPSession(tracker *udpSessionTracker) {
	s.udpMu.Lock()
	defer s.udpMu.Unlock()
	delete(s.udpSessions, tracker)
}

func (s *QUICServer) reclaimStaleSTUN(token string) {
	timeout := 15 * time.Second
	if s.stunIdleTimeout > 0 {
		timeout = s.stunIdleTimeout
	}

	var toClose []func()
	now := time.Now()

	s.udpMu.Lock()
	for tracker := range s.udpSessions {
		if tracker.token == token && tracker.isSTUN != nil && tracker.isSTUN.Load() {
			if tracker.lastActive != nil && now.Sub(time.Unix(0, tracker.lastActive.Load())) >= timeout {
				if tracker.closeFn != nil {
					toClose = append(toClose, tracker.closeFn)
				}
			}
		}
	}
	s.udpMu.Unlock()

	for _, closeFn := range toClose {
		closeFn()
	}
}

// isSTUNTarget checks if the target port is a known STUN/TURN port (3478, 19302, 5349).
func isSTUNTarget(target string) bool {
	_, portStr, err := net.SplitHostPort(target)
	if err == nil {
		switch portStr {
		case "3478", "19302", "5349":
			return true
		}
	}
	return false
}

// isSTUNPayload inspects the payload to detect RFC 5389 STUN magic cookie 0x2112A442.
func isSTUNPayload(payload []byte) bool {
	if len(payload) >= 8 {
		return binary.BigEndian.Uint32(payload[4:8]) == 0x2112A442
	}
	return false
}

// SetServerConfig sets the server configuration for QUICServer
func (s *QUICServer) SetServerConfig(cfg *ServerConfig) {
	s.cfg = cfg
}

// ServerConfig returns the server configuration
func (s *QUICServer) ServerConfig() *ServerConfig {
	return s.cfg
}

// SetICMPForwardHookForTest sets custom ICMP forward hook for testing
func (s *QUICServer) SetICMPForwardHookForTest(hook func(target net.IP, echoReq []byte) ([]byte, error)) {
	s.icmpForwardHook = hook
}

// SetICMPv6ForwardHookForTest sets custom ICMPv6 forward hook for testing
func (s *QUICServer) SetICMPv6ForwardHookForTest(hook func(target net.IP, echoReq []byte) ([]byte, error)) {
	s.icmpv6ForwardHook = hook
}

// SetAllowLoopbackForTest enables loopback dialing for unit tests.
func (s *QUICServer) SetAllowLoopbackForTest(allow bool) {
	s.allowLoopbackForTest = allow
}

// SetNextHopDialerForTest sets a custom dialer for next-hop cascading in tests
func (s *QUICServer) SetNextHopDialerForTest(d func(nextHopAddr, target, hopCred string) (net.Conn, error)) {
	s.nextHopDialer = d
}

// SetNextHopUDPDialerForTest sets a custom UDP dialer for next-hop cascading in tests
func (s *QUICServer) SetNextHopUDPDialerForTest(d func(nextHopAddr, target, hopCred string) (net.Conn, error)) {
	s.nextHopUDPDialer = d
}

// SetUDPDialFunc sets custom UDP dial function for testing
func (s *QUICServer) SetUDPDialFunc(fn func(network string, laddr, raddr *net.UDPAddr) (*net.UDPConn, error)) {
	s.udpDialFn = fn
}

// SetResolveUDPFunc sets custom UDP resolution function for testing
func (s *QUICServer) SetResolveUDPFunc(fn func(network, addr string) (*net.UDPAddr, error)) {
	s.resolveUDPFn = fn
}

func (s *QUICServer) resolveUDP(network, addr string) (*net.UDPAddr, error) {
	if s.resolveUDPFn != nil {
		return s.resolveUDPFn(network, addr)
	}
	return net.ResolveUDPAddr(network, addr)
}

func (s *QUICServer) dialUDP(network string, laddr, raddr *net.UDPAddr) (*net.UDPConn, error) {
	if s.udpDialFn != nil {
		return s.udpDialFn(network, laddr, raddr)
	}
	return net.DialUDP(network, laddr, raddr)
}

type quicStreamConn struct {
	stream *http3.RequestStream
	qConn  *quic.Conn
}

func (c *quicStreamConn) Read(b []byte) (int, error) {
	return c.stream.Read(b)
}

func (c *quicStreamConn) Write(b []byte) (int, error) {
	return c.stream.Write(b)
}

func (c *quicStreamConn) Close() error {
	var err1, err2 error
	if c.stream != nil {
		err1 = c.stream.Close()
	}
	if c.qConn != nil {
		err2 = c.qConn.CloseWithError(0, "normal")
	}
	if err1 != nil {
		return err1
	}
	return err2
}

func (c *quicStreamConn) LocalAddr() net.Addr {
	if c.qConn != nil {
		return c.qConn.LocalAddr()
	}
	return nil
}

func (c *quicStreamConn) RemoteAddr() net.Addr {
	if c.qConn != nil {
		return c.qConn.RemoteAddr()
	}
	return nil
}

func (c *quicStreamConn) SetDeadline(t time.Time) error {
	if c.stream != nil {
		return c.stream.SetDeadline(t)
	}
	return nil
}

func (c *quicStreamConn) SetReadDeadline(t time.Time) error {
	if c.stream != nil {
		return c.stream.SetReadDeadline(t)
	}
	return nil
}

func (c *quicStreamConn) SetWriteDeadline(t time.Time) error {
	if c.stream != nil {
		return c.stream.SetWriteDeadline(t)
	}
	return nil
}

var _ net.Conn = (*quicStreamConn)(nil)

func (s *QUICServer) dialNextHopTCP(nextHopAddr, target, hopCred string) (net.Conn, error) {
	if s.nextHopDialer != nil {
		return s.nextHopDialer(nextHopAddr, target, hopCred)
	}

	sni := ""
	if s.cfg != nil && s.cfg.NextHopSNI != "" {
		sni = s.cfg.NextHopSNI
	} else {
		host, _, err := net.SplitHostPort(nextHopAddr)
		if err == nil && host != "" {
			sni = host
		} else {
			sni = nextHopAddr
		}
	}

	tlsConf := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: s.allowLoopbackForTest,
		NextProtos:         []string{"h3"},
	}
	quicConf := DefaultQUICConfig()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer dialCancel()

	qConn, err := quic.DialAddr(dialCtx, nextHopAddr, tlsConf, quicConf)
	if err != nil {
		return nil, fmt.Errorf("dial next hop %s over quic: %w", nextHopAddr, err)
	}

	tr := &http3.Transport{EnableDatagrams: true}
	h3Conn := tr.NewClientConn(qConn)

	targetHost := strings.TrimPrefix(target, "//")
	targetHost = strings.TrimPrefix(targetHost, "/")
	targetHost = strings.TrimPrefix(targetHost, "/")
	req, err := http.NewRequestWithContext(context.Background(), http.MethodConnect, "//"+targetHost, nil)
	if err != nil {
		_ = qConn.CloseWithError(0, "failed to create request")
		return nil, fmt.Errorf("create next hop connect request: %w", err)
	}
	req.Proto = "HTTP/1.1"
	req.Header.Set("Aero-Hop-Token", hopCred)

	reqStr, err := h3Conn.OpenRequestStream(dialCtx)
	if err != nil {
		_ = qConn.CloseWithError(0, "failed to open stream")
		return nil, fmt.Errorf("open next hop request stream: %w", err)
	}

	if err := reqStr.SendRequestHeader(req); err != nil {
		_ = reqStr.Close()
		_ = qConn.CloseWithError(0, "failed to send header")
		return nil, fmt.Errorf("send next hop request header: %w", err)
	}

	resp, err := reqStr.ReadResponse()
	if err != nil {
		_ = reqStr.Close()
		_ = qConn.CloseWithError(0, "failed to read response")
		return nil, fmt.Errorf("read next hop response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		proxyStatus := resp.Header.Get("Proxy-Status")
		_ = reqStr.Close()
		_ = qConn.CloseWithError(0, "next hop rejected")
		return nil, fmt.Errorf("next hop connect rejected with status %d (Proxy-Status: %s)", resp.StatusCode, proxyStatus)
	}

	return &quicStreamConn{
		stream: reqStr,
		qConn:  qConn,
	}, nil
}

func (s *QUICServer) dialNextHopUDP(nextHopAddr, target, hopCred string) (net.Conn, error) {
	if s.nextHopUDPDialer != nil {
		return s.nextHopUDPDialer(nextHopAddr, target, hopCred)
	}

	// 生产真实链路：通过 MASQUE CONNECT-UDP 向上游下一跳中继建立隧道 (NEW-01)
	sni := ""
	if s.cfg != nil && s.cfg.NextHopSNI != "" {
		sni = s.cfg.NextHopSNI
	} else {
		host, _, err := net.SplitHostPort(nextHopAddr)
		if err == nil && host != "" {
			sni = host
		} else {
			sni = nextHopAddr
		}
	}

	tlsConf := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: s.allowLoopbackForTest,
		NextProtos:         []string{"h3"},
	}
	qConn, err := quic.DialAddr(context.Background(), nextHopAddr, tlsConf, &quic.Config{EnableDatagrams: true})
	if err != nil {
		return nil, fmt.Errorf("dial next hop quic: %w", err)
	}

	tr := &http3.Transport{EnableDatagrams: true}
	h3Conn := tr.NewClientConn(qConn)
	masqueClient := masque.NewClientConn(h3Conn)

	tmpl := uritemplate.MustNew("https://" + nextHopAddr + "/.well-known/masque/udp/{target_host}/{target_port}/")
	mreq, err := masque.NewRequest(context.Background(), tmpl, target)
	if err != nil {
		_ = qConn.CloseWithError(0, "req err")
		return nil, err
	}
	if hopCred != "" {
		mreq.Header().Set("Authorization", "Bearer "+hopCred)
	}

	mConn, resp, err := masqueClient.Dial(mreq)
	if err != nil {
		_ = qConn.CloseWithError(0, "masque err")
		return nil, fmt.Errorf("next hop masque dial: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = mConn.Close()
		_ = qConn.CloseWithError(0, "rejected")
		return nil, fmt.Errorf("next hop rejected: %s", resp.Status)
	}

	return &nextHopUDPRelayConn{mConn: mConn, qConn: qConn}, nil
}

type nextHopUDPRelayConn struct {
	mConn *masque.Conn
	qConn *quic.Conn
}

func (c *nextHopUDPRelayConn) Read(p []byte) (int, error) {
	n, _, err := c.mConn.ReadFrom(p)
	return n, err
}
func (c *nextHopUDPRelayConn) Write(p []byte) (int, error) {
	return c.mConn.WriteTo(p, nil)
}
func (c *nextHopUDPRelayConn) Close() error {
	_ = c.mConn.Close()
	if c.qConn != nil {
		_ = c.qConn.CloseWithError(0, "relay closed")
	}
	return nil
}
func (c *nextHopUDPRelayConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (c *nextHopUDPRelayConn) RemoteAddr() net.Addr               { return &net.UDPAddr{} }
func (c *nextHopUDPRelayConn) SetDeadline(t time.Time) error      { return nil }
func (c *nextHopUDPRelayConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *nextHopUDPRelayConn) SetWriteDeadline(t time.Time) error { return nil }

// NewQUICServerWithIPv6Prefix creates a production QUICServer. An empty prefix
// deliberately disables IPv6 allocation until a routed public prefix is proven.
func NewQUICServerWithIPv6Prefix(v *Validator, cl *ConnLimiter, bl *BandwidthLimiter, dg *DialGuard, rl *RateLimiter, ipv6CIDR string) *QUICServer {
	ipPool, _ := NewIPPool("10.88.0.0/16")
	var ipv6Pool *IPv6Pool
	if strings.TrimSpace(ipv6CIDR) != "" {
		ipv6Pool, _ = newRoutedIPv6Pool(ipv6CIDR)
	}
	return newQUICServer(v, cl, bl, dg, rl, ipPool, ipv6Pool)
}

func newRoutedIPv6Pool(cidrStr string) (*IPv6Pool, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(cidrStr))
	if err != nil {
		return nil, fmt.Errorf("parse IPv6 prefix: %w", err)
	}
	addr := prefix.Addr()
	if !addr.Is6() || !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLinkLocalUnicast() {
		return nil, fmt.Errorf("IPv6 prefix is not globally routable: %s", prefix)
	}
	if bits := prefix.Bits(); bits < 48 || bits > 64 {
		return nil, fmt.Errorf("IPv6 prefix length must be between /48 and /64: %s", prefix)
	}
	return &IPv6Pool{
		baseIP:   addr,
		prefix:   prefix.Bits(),
		nextHost: 2,
		maxHost:  65534,
		used:     make(map[netip.Addr]struct{}),
	}, nil
}

func newQUICServer(v *Validator, cl *ConnLimiter, bl *BandwidthLimiter, dg *DialGuard, rl *RateLimiter, ipPool *IPPool, ipv6Pool *IPv6Pool) *QUICServer {
	qs := &QUICServer{
		validator:        v,
		connLimiter:      cl,
		bandwidthLimiter: bl,
		dialGuard:        dg,
		rateLimiter:      rl,
		dnsResolver:      NewDNSResolver(),
		connTracker:      NewConnTracker(),
		ipPool:           ipPool,
		ipv6Pool:         ipv6Pool,
		globalRouter:     NewGlobalTunnelRouter(),
		authJail:         NewAuthFailureJail(),
		masqueProxy:      &masque.Proxy{},
		connectIPProxy:   &connectip.Proxy{},
		tokenUDPCtx:      make(map[string]int),
		maxGlobalUDP:     DefaultMaxGlobalUDP,
		udpTempl:         uritemplate.MustNew("https://placeholder/.well-known/masque/udp/{target_host}/{target_port}/"),
		ipTempl:          uritemplate.MustNew("https://placeholder/.well-known/masque/ip/*/*/"),
		udpSessions:      make(map[*udpSessionTracker]struct{}),
		stopCh:           make(chan struct{}),

		tokenEnforceInterval: defaultTokenEnforceInterval,
	}
	qs.connTracker.StartReaper(qs.stopCh)
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
	s.closeOnce.Do(func() {
		if s.stopCh != nil {
			close(s.stopCh)
		}
	})
	if s.authJail != nil {
		s.authJail.Close()
	}
	s.globalReaderMu.Lock()
	reader := s.globalReader
	s.globalReader = nil
	s.globalReaderMu.Unlock()
	if reader != nil {
		if err := reader.Close(); err != nil {
			log.Printf("[TUN] shared reader close failed: %v", err)
		}
	}
	if s.globalRouter != nil {
		s.globalRouter.Close()
	}
}

// AttachGlobalTunnelDevice starts the shared reader explicitly. Platform
// device opening remains outside QUICServer so startup cannot mutate host
// networking unless the caller has opted into the M6 data plane.
func (s *QUICServer) AttachGlobalTunnelDevice(ctx context.Context, device GlobalTunnelDevice) error {
	if s == nil || s.globalRouter == nil {
		return errors.New("global tunnel router is not initialized")
	}
	reader, err := NewGlobalTunnelReader(ctx, device, s.globalRouter)
	if err != nil {
		return err
	}
	s.globalReaderMu.Lock()
	previous := s.globalReader
	s.globalReader = reader
	s.globalReaderMu.Unlock()
	if previous != nil {
		if err := previous.Close(); err != nil {
			return fmt.Errorf("close previous shared reader: %w", err)
		}
	}
	reader.Start()
	return nil
}

func (s *QUICServer) globalTunnelReader() *GlobalTunnelReader {
	if s == nil {
		return nil
	}
	s.globalReaderMu.Lock()
	reader := s.globalReader
	s.globalReaderMu.Unlock()
	return reader
}

// AttachGlobalTunnelDeviceByName opens a platform device and starts the shared
// reader. It is only called when explicitly enabled by server configuration.
func (s *QUICServer) AttachGlobalTunnelDeviceByName(ctx context.Context, name string) error {
	device, err := openGlobalTunnelDevice(name)
	if err != nil {
		return err
	}
	if err := s.AttachGlobalTunnelDevice(ctx, device); err != nil {
		if closeErr := device.Close(); closeErr != nil {
			return fmt.Errorf("attach shared TUN: %w; close device: %v", err, closeErr)
		}
		return err
	}
	return nil
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
	n := s.tokenUDPCtx[token]
	s.udpMu.Unlock()

	if n >= 60 {
		// When user concurrent UDP Context reaches alert threshold (>=60),
		// prioritize reclaiming STUN probes that have been inactive for >= 15s.
		s.reclaimStaleSTUN(token)
	}

	s.udpMu.Lock()
	defer s.udpMu.Unlock()

	n = s.tokenUDPCtx[token]
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

	// 根据部署 Profile 动态收紧接收窗口，防范 512MB VPS 内存撑爆 (SEC-02)
	if server != nil && server.cfg != nil {
		switch strings.ToLower(server.cfg.Profile) {
		case "tiny": // <= 512MB RAM
			quicCfg.InitialStreamReceiveWindow = 2 * 1024 * 1024     // 2MB
			quicCfg.MaxStreamReceiveWindow = 4 * 1024 * 1024         // 4MB
			quicCfg.InitialConnectionReceiveWindow = 4 * 1024 * 1024 // 4MB
			quicCfg.MaxConnectionReceiveWindow = 8 * 1024 * 1024     // 8MB
		case "small": // 1GB RAM
			quicCfg.InitialStreamReceiveWindow = 8 * 1024 * 1024      // 8MB
			quicCfg.MaxStreamReceiveWindow = 16 * 1024 * 1024         // 16MB
			quicCfg.InitialConnectionReceiveWindow = 16 * 1024 * 1024 // 16MB
			quicCfg.MaxConnectionReceiveWindow = 32 * 1024 * 1024     // 32MB
		}
	}
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
	// 独占绑定（不设 SO_REUSEPORT）：端口被占用时由系统报错，供端口轮试避开（ADR-0005）。
	var lc net.ListenConfig
	conn, err := lc.ListenPacket(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("quic listen packet %s: %w", addr, err)
	}
	if uc, ok := conn.(*net.UDPConn); ok {
		_ = uc.SetReadBuffer(7 * 1024 * 1024)
		_ = uc.SetWriteBuffer(7 * 1024 * 1024)
	}

	if server != nil && server.cfg != nil && server.cfg.ObfsPassword != "" {
		conn = NewSalamanderPacketConn(conn, server.cfg.ObfsPassword, server.cfg.PaddingJitter)
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

	if s.cfg != nil && s.cfg.Role == "egress" {
		expected := []byte(s.cfg.HopCredential)
		matches := func(v string) bool {
			return v != "" && len(expected) > 0 && subtle.ConstantTimeCompare([]byte(v), expected) == 1
		}
		bearer, _ := bearerToken(r)
		if matches(strings.TrimSpace(r.Header.Get("Aero-Hop-Token"))) || matches(bearer) {
			return s.cfg.HopCredential, true
		}
		s.rejectAuth(w, remoteIP, "invalid hop credential")
		return "", false
	}

	// 只校验 token；Aero-Timestamp / Aero-Nonce 已废弃并被忽略（C3 §5）。
	token, ok := bearerToken(r)
	if !ok {
		s.rejectAuth(w, remoteIP, "")
		return "", false
	}
	claims, err := s.checkToken(token)
	if errors.Is(err, ErrTokenExpired) {
		// 过期是正常用户的常态（休眠后），客户端会刷新 token；不计入防爆破封禁
		w.Header().Set("WWW-Authenticate", `Bearer realm="aero", error="invalid_token"`)
		w.Header().Set("Proxy-Status", `aero; error=proxy_authorization_required; details="EDGE_AUTH_TOKEN_EXPIRED"`)
		w.WriteHeader(http.StatusUnauthorized)
		return "", false
	}
	if err != nil {
		s.rejectAuth(w, remoteIP, err.Error())
		return "", false
	}
	// 同一 QUIC 连接上的请求必须使用首次请求绑定的 token；首次绑定时执行本节点设备数限制（C3 §3 第 7 步）。
	if qc, _ := r.Context().Value(quicConnKey{}).(*quic.Conn); qc != nil && s.connTracker != nil {
		if bound, tracked := s.connTracker.Get(qc); tracked {
			if subtle.ConstantTimeCompare([]byte(bound), []byte(token)) != 1 {
				s.rejectAuth(w, remoteIP, "token differs from the one bound to this connection")
				return "", false
			}
		} else {
			uid, maxDevices := "", 0
			if claims != nil {
				uid, maxDevices = claims.UID, claims.MaxDevices
			}
			if evicted := s.connTracker.BindEvictOldest(qc, token, uid, maxDevices); len(evicted) > 0 {
				for _, old := range evicted {
					closeEvictedConn(old)
				}
				log.Printf("[AUTH] uid %s at device limit %d: closed %d oldest connection(s)", uid, maxDevices, len(evicted))
			}
		}
	}
	return token, true
}

// checkToken 校验 token（C3 §3 第 1–4 步）。aero1 签名 token 只在 auth_signed_token 开启时接受；
// 其他视为旧的不透明 token（过渡期 30 天，C3 §8）。返回签名 token 的载荷，不透明 token 返回 nil。
func (s *QUICServer) checkToken(token string) (*TokenClaims, error) {
	if strings.HasPrefix(token, tokenPrefix) {
		if s.tokenVerifier == nil {
			return nil, ErrTokenInvalid
		}
		return s.tokenVerifier.Verify(token)
	}
	if s.validator == nil || !s.validator.Validate(token) {
		return nil, ErrTokenInvalid
	}
	return nil, nil
}

// tokenStillValid 供执行器周期检查已绑定连接（过期、删除、吊销后断开）。
func (s *QUICServer) tokenStillValid(token string) bool {
	_, err := s.checkToken(token)
	return err == nil
}

// SetUsageMeter 启用 C6 计量（nil 关闭）；只影响之后建立的会话。
func (s *QUICServer) SetUsageMeter(m *UsageMeter) { s.usageMeter.Store(m) }

// usageCell 返回 token 的计量单元；未启用计量或不透明 token 返回 nil（Add 为无操作）。
func (s *QUICServer) usageCell(token string) *usageCell { return s.usageMeter.Load().Cell(token) }

// SetTokenVerifier 启用 C3 签名 token 校验（nil 关闭）。
func (s *QUICServer) SetTokenVerifier(v *TokenVerifier) {
	s.tokenVerifier = v
}

func bearerToken(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return "", false
	}
	token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	return token, token != ""
}

// rejectAuth 记录失败并返回 401（RFC 9209 Proxy-Status）。
func (s *QUICServer) rejectAuth(w http.ResponseWriter, remoteIP, details string) {
	if s.authJail != nil {
		s.authJail.RecordFailure(remoteIP)
	}
	w.Header().Set("WWW-Authenticate", `Bearer realm="aero"`)
	status := "aero; error=proxy_authorization_required"
	if details != "" {
		status += fmt.Sprintf("; details=%q", details)
	}
	w.Header().Set("Proxy-Status", status)
	w.WriteHeader(http.StatusUnauthorized)
}

var relayBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 16384)
		return &b
	},
}

func (s *QUICServer) serveStandardConnect(w http.ResponseWriter, r *http.Request) {
	token, ok := s.authRequest(w, r)
	if !ok {
		return
	}
	usage := s.usageCell(token) // relay 计 payload 字节（不含 IP/传输层头）

	target := strings.TrimPrefix(r.RequestURI, "//")
	if target == "" || !strings.Contains(target, ":") {
		target = strings.TrimPrefix(r.Host, "//")
	}
	target = strings.TrimPrefix(target, "/")
	target = strings.TrimPrefix(target, "/")
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
	if s.cfg != nil && s.cfg.Role == "ingress" && s.cfg.NextHopAddr != "" {
		targetConn, err = s.dialNextHopTCP(s.cfg.NextHopAddr, target, s.cfg.HopCredential)
	} else if s.dialGuard != nil {
		targetConn, err = s.dialGuard.DialTimeout("tcp", target, 10*time.Second)
	} else {
		tcpNet := "tcp4"
		targetHost, _, _ := net.SplitHostPort(target)
		if tip := net.ParseIP(targetHost); tip != nil && tip.To4() == nil {
			tcpNet = "tcp"
		}
		targetConn, err = net.DialTimeout(tcpNet, target, 10*time.Second)
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

	idle := s.tcpIdleTimeout
	if idle <= 0 {
		idle = defaultTCPIdleTimeout
	}
	// lastActive 记录任一方向最近一次有数据的时间：空闲按“双向都无流量”判定，
	// 只有单方向流量（如大文件上传、只下载）的连接不会被误判为空闲。
	var lastActive atomic.Int64
	touch := func() { lastActive.Store(time.Now().UnixNano()) }
	stillActive := func() bool { return time.Since(time.Unix(0, lastActive.Load())) < idle }
	touch()

	relayCtx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// 任一方向出错或整体空闲时，关闭两端以唤醒阻塞的读写。
	go func() {
		<-relayCtx.Done()
		_ = targetConn.Close()
		str.CancelRead(quic.StreamErrorCode(0))
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	// 客户端 → 目标。客户端关闭写端（EOF）时只关闭目标的写端（半关闭），继续回传响应。
	go func() {
		defer wg.Done()
		bufPtr := relayBufPool.Get().(*[]byte)
		defer relayBufPool.Put(bufPtr)
		buf := *bufPtr
		for {
			_ = str.SetReadDeadline(time.Now().Add(idle))
			n, err := str.Read(buf)
			if n > 0 {
				touch()
				if s.bandwidthLimiter != nil {
					s.bandwidthLimiter.Take(token, n)
				}
				usage.Add(int64(n), 0)
				_ = targetConn.SetWriteDeadline(time.Now().Add(idle))
				if _, werr := targetConn.Write(buf[:n]); werr != nil {
					cancel()
					return
				}
			}
			if err != nil {
				if isTimeoutErr(err) && stillActive() {
					continue
				}
				if errors.Is(err, io.EOF) {
					closeWriteSide(targetConn)
					return
				}
				cancel()
				return
			}
		}
	}()

	// 目标 → 客户端。目标关闭（EOF）时关闭流的发送方向，客户端读到 EOF。
	go func() {
		defer wg.Done()
		bufPtr := relayBufPool.Get().(*[]byte)
		defer relayBufPool.Put(bufPtr)
		buf := *bufPtr
		for {
			_ = targetConn.SetReadDeadline(time.Now().Add(idle))
			n, err := targetConn.Read(buf)
			if n > 0 {
				touch()
				if s.bandwidthLimiter != nil {
					s.bandwidthLimiter.Take(token, n)
				}
				usage.Add(0, int64(n))
				if _, werr := str.Write(buf[:n]); werr != nil {
					cancel()
					return
				}
			}
			if err != nil {
				if isTimeoutErr(err) && stillActive() {
					continue
				}
				if errors.Is(err, io.EOF) {
					_ = str.Close()
					return
				}
				cancel()
				return
			}
		}
	}()

	wg.Wait()
}

// defaultTCPIdleTimeout 是标准 CONNECT 中继双向均无流量时的关闭上限（估算，待实测）。
const defaultTCPIdleTimeout = 10 * time.Minute

func isTimeoutErr(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// closeWriteSide 关闭连接的写方向（TCP 半关闭）；不支持时保持连接，等待对端结束。
func closeWriteSide(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

func (s *QUICServer) serveConnectUDP(w http.ResponseWriter, r *http.Request) {
	token, ok := s.authRequest(w, r)
	if !ok {
		return
	}
	usage := s.usageCell(token) // relay 计 payload 字节（不含 IP/传输层头）

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

	var targetUDP io.ReadWriteCloser
	if s.cfg != nil && s.cfg.Role == "ingress" && s.cfg.NextHopAddr != "" {
		uConn, err := s.dialNextHopUDP(s.cfg.NextHopAddr, proxyReq.Target, s.cfg.HopCredential)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		targetUDP = uConn
	} else if s.udpDialFn == nil && s.dialGuard != nil && s.dialGuard.ShouldRouteUDP(proxyReq.Target, 0) {
		warpConn, err := s.dialGuard.DialUDPViaWARP(proxyReq.Target, 10*time.Second)
		if err != nil {
			w.Header().Set("Proxy-Status", fmt.Sprintf("aero; error=connection_refused; details=%q", err.Error()))
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		targetUDP = warpConn
	} else {
		resolveNet := "udp4"
		targetHost, _, _ := net.SplitHostPort(proxyReq.Target)
		if tip := net.ParseIP(targetHost); tip != nil && tip.To4() == nil {
			resolveNet = "udp"
		}
		dstAddr, err := s.resolveUDP(resolveNet, proxyReq.Target)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if !s.allowLoopbackForTest {
			if blocked, why := IsBlockedIP(dstAddr.IP); blocked {
				w.Header().Set("Proxy-Status", fmt.Sprintf("aero; error=destination_ip_prohibited; details=%q", why))
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}

		if s.udpDialFn == nil && s.dialGuard != nil && s.dialGuard.ShouldRouteUDP(dstAddr.String(), dstAddr.Port) {
			warpConn, err := s.dialGuard.DialUDPViaWARP(dstAddr.String(), 10*time.Second)
			if err != nil {
				w.Header().Set("Proxy-Status", fmt.Sprintf("aero; error=connection_refused; details=%q", err.Error()))
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			targetUDP = warpConn
		} else {
			udpNet := "udp4"
			if dstAddr.IP != nil && dstAddr.IP.To4() == nil {
				udpNet = "udp"
			}
			uConn, err := s.dialUDP(udpNet, nil, dstAddr)
			if err != nil {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			targetUDP = uConn
		}
	}
	defer targetUDP.Close()

	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	str := streamer.HTTPStream()
	defer str.Close()

	w.Header().Set("Capsule-Protocol", "?1")
	w.WriteHeader(http.StatusOK)

	// WebRTC ICE Candidate detection: target port 3478, 19302, 5349 or STUN Magic Cookie
	var isSTUN atomic.Bool
	if isSTUNTarget(proxyReq.Target) {
		isSTUN.Store(true)
	}

	var lastActive atomic.Int64
	lastActive.Store(time.Now().UnixNano())

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	closeOnce := sync.Once{}
	closeSession := func() {
		closeOnce.Do(func() {
			cancel()
			_ = targetUDP.Close()
			str.CancelRead(quic.StreamErrorCode(http3.ErrCodeConnectError))
			_ = str.Close()
		})
	}

	sessionTracker := &udpSessionTracker{
		token:      token,
		isSTUN:     &isSTUN,
		lastActive: &lastActive,
		closeFn:    closeSession,
	}
	s.registerUDPSession(sessionTracker)
	defer s.unregisterUDPSession(sessionTracker)

	stopWatchdog := make(chan struct{})
	defer close(stopWatchdog)

	go func() {
		checkInterval := 1 * time.Second
		if s.stunIdleTimeout > 0 && s.stunIdleTimeout < 1*time.Second {
			checkInterval = s.stunIdleTimeout / 4
			if checkInterval < 10*time.Millisecond {
				checkInterval = 10 * time.Millisecond
			}
		}
		ticker := time.NewTicker(checkInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stopWatchdog:
				return
			case <-ticker.C:
				timeout := 45 * time.Second
				if s.udpIdleTimeout > 0 {
					timeout = s.udpIdleTimeout
				}
				if isSTUN.Load() {
					timeout = 15 * time.Second
					if s.stunIdleTimeout > 0 {
						timeout = s.stunIdleTimeout
					}
				}
				if time.Since(time.Unix(0, lastActive.Load())) > timeout {
					closeSession()
					return
				}
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	// 下行（QUIC -> UDP）
	go func() {
		defer wg.Done()
		defer closeSession()

		for {
			data, err := str.ReceiveDatagram(ctx)
			if err != nil {
				break
			}
			contextID, n, err := quicvarint.Parse(data)
			if err != nil {
				continue
			}
			if contextID == 0 {
				payload := data[n:]
				if !isSTUN.Load() && isSTUNPayload(payload) {
					isSTUN.Store(true)
				}
				lastActive.Store(time.Now().UnixNano())
				if s.bandwidthLimiter != nil {
					s.bandwidthLimiter.Take(token, len(payload))
				}
				usage.Add(int64(len(payload)), 0)
				if _, err := targetUDP.Write(payload); err != nil {
					if isTransientUDPErr(err) {
						continue // 目标端口暂不可达（ICMP），不终止会话
					}
					break
				}
			}
		}
	}()

	// 上行（UDP -> QUIC）
	go func() {
		defer wg.Done()
		defer closeSession()

		buf := make([]byte, 1+65535) // 容纳最大 UDP 报文，不静默截断
		buf[0] = 0x00                // contextID 0 in QUIC varint
		for {
			n, err := targetUDP.Read(buf[1:])
			if n > 0 {
				if !isSTUN.Load() && isSTUNPayload(buf[1:1+n]) {
					isSTUN.Store(true)
				}
				lastActive.Store(time.Now().UnixNano())
				if s.bandwidthLimiter != nil {
					s.bandwidthLimiter.Take(token, n)
				}
				usage.Add(0, int64(n))
				if serr := str.SendDatagram(buf[:1+n]); serr != nil {
					if isDroppableDatagramErr(serr) {
						continue // 单个报文超过 QUIC 数据报上限：丢弃该报文，会话继续
					}
					break
				}
			}
			if err != nil {
				if isTransientUDPErr(err) {
					continue
				}
				break
			}
		}
	}()

	// 监控请求流 EOF/取消以加速释放
	go func() {
		buf := make([]byte, 1024)
		for {
			if _, err := str.Read(buf); err != nil {
				closeSession()
				break
			}
		}
	}()

	wg.Wait()
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

	// 地址租约键：签名 token 按 uid（token 每 24 小时轮换，地址保持不变，隧道内 TCP 不中断）；
	// 旧的不透明 token 按 token 本身。
	leaseKey := token
	if qc, _ := r.Context().Value(quicConnKey{}).(*quic.Conn); qc != nil && s.connTracker != nil {
		if uid := s.connTracker.UID(qc); uid != "" {
			leaseKey = "uid:" + uid
		}
	}
	assignedPrefix, err := s.ipPool.AllocateFor(leaseKey)
	if err != nil {
		w.Header().Set("Proxy-Status", "aero; error=address_pool_exhausted; details=\"IP pool exhausted\"")
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	defer s.ipPool.ReleaseFor(leaseKey, assignedPrefix)

	var assignedIPv6 netip.Prefix
	if s.ipv6Pool != nil {
		if v6Prefix, err := s.ipv6Pool.Allocate(); err == nil {
			assignedIPv6 = v6Prefix
			defer s.ipv6Pool.Release(assignedIPv6)
		}
	}

	conn, err := s.connectIPProxy.Proxy(w, proxyReq)
	if err != nil {
		return
	}
	defer conn.Close()

	assignedPrefixes := []netip.Prefix{assignedPrefix}
	if assignedIPv6.IsValid() {
		assignedPrefixes = append(assignedPrefixes, assignedIPv6)
	}

	if err := conn.AssignAddresses(assignedPrefixes); err != nil {
		return
	}
	if err := conn.AdvertiseRoute([]connectip.IPRoute{
		{
			StartIP:    netip.MustParseAddr("0.0.0.0"),
			EndIP:      netip.MustParseAddr("255.255.255.255"),
			IPProtocol: 0,
		},
		{
			StartIP:    netip.MustParseAddr("::"),
			EndIP:      netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
			IPProtocol: 0,
		},
	}); err != nil {
		return
	}

	// 同一份 binding 先登记到路由表（下行按目的地址查到它），再交给 reader（上行）。
	binding := GlobalTunnelBinding{Token: token, IPv4: assignedPrefix.Addr(), Conn: conn, usage: s.usageCell(token)}
	if assignedIPv6.IsValid() {
		binding.IPv6 = assignedIPv6.Addr()
	}
	if s.globalRouter != nil {
		binding.Generation, err = s.globalRouter.Register(binding)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		defer s.globalRouter.Unregister(assignedPrefix.Addr(), binding.Generation)
	}

	reader := s.globalTunnelReader()
	if reader == nil && s.ServerConfig() != nil && s.ServerConfig().AllowSelfSignedCertForTest {
		memDev := newInMemoryTunnelDevice(s)
		if err := s.AttachGlobalTunnelDevice(r.Context(), memDev); err == nil {
			reader = s.globalTunnelReader()
		}
	}
	if reader != nil {
		if err := reader.StartBinding(r.Context(), binding); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		<-r.Context().Done()
		return
	}

	w.WriteHeader(http.StatusServiceUnavailable)
}

// maxDoHQueryBytes 是 DoH 请求体上限（PROJECT_RULES §7.3）。
const maxDoHQueryBytes = 4096

// isDroppableDatagramErr 判定 SendDatagram 的错误是否只影响当前报文（超过数据报上限），
// 此时应丢弃该报文而不是终止会话。
func isDroppableDatagramErr(err error) bool {
	var tooLarge *quic.DatagramTooLargeError
	return errors.As(err, &tooLarge)
}

// isTransientUDPErr 判定已连接 UDP socket 上由 ICMP 端口不可达引起的暂时性错误。
func isTransientUDPErr(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
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

	queryBytes, err := io.ReadAll(io.LimitReader(r.Body, maxDoHQueryBytes+1))
	if err == nil && len(queryBytes) > maxDoHQueryBytes {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}
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
