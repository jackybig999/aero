// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025 Aero AI System

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
	"strconv"
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
)

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
	maxDevices int // 签名 token 的 max_devices；0 表示未限制或不透明 token
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

// Limits 返回 c 绑定的 uid 与其设备数上限（不透明 token 或未绑定时为 "", 0）。
func (ct *ConnTracker) Limits(c *quic.Conn) (uid string, maxDevices int) {
	if c == nil {
		return "", 0
	}
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	b := ct.conns[c]
	return b.uid, b.maxDevices
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
	ct.conns[c] = connBinding{token: token, uid: uid, maxDevices: max, seq: ct.seq}
	return evict
}

// closeEvictedConn 断开因设备数上限被替换的连接；可在测试中替换。
var closeEvictedConn = func(c *quic.Conn) {
	_ = c.CloseWithError(0x103, "EDGE_DEVICE_LIMIT: replaced by a newer connection of the same user")
}

// Remove dissociates c.
func (ct *ConnTracker) Remove(c *quic.Conn) {
	if ct == nil || c == nil {
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
// 测试注入钩子的函数类型；字段用 atomic.Pointer 存放，保证服务运行后设置也无数据竞争。
type (
	resolveUDPFunc  func(network, addr string) (*net.UDPAddr, error)
	udpDialFunc     func(network string, laddr, raddr *net.UDPAddr) (*net.UDPConn, error)
	icmpForwardFunc func(target net.IP, echoReq []byte) ([]byte, error)
	nextHopDialFunc func(nextHopAddr, target, hopCred string) (net.Conn, error)
)

// storeHook 把可为 nil 的函数存入 atomic.Pointer；nil 表示清除钩子。
func storeHook[T any](p *atomic.Pointer[T], fn *T, isNil bool) {
	if isNil {
		p.Store(nil)
		return
	}
	p.Store(fn)
}

type QUICServer struct {
	cfg               *ServerConfig
	validator         *Validator
	tokenVerifier     *TokenVerifier             // 非 nil 即启用 C3 签名 token（auth_signed_token）
	connectIPDisabled bool                       // connect_ip=false：CONNECT-IP 返回 503，不使用 TUN
	usageMeter        atomic.Pointer[UsageMeter] // C6 计量；nil 表示不计量
	connLimiter       *ConnLimiter
	bandwidthLimiter  *BandwidthLimiter
	dialGuard         *DialGuard
	rateLimiter       *RateLimiter
	doh               *dohForwarder
	hopDoHc           hopDoHClient // 入口到出口的 DoH 复用连接（role=ingress）
	hopPool           hopConnPool  // 入口到出口的 TCP CONNECT 共享 QUIC 连接，每用户一条（role=ingress）
	hopDoHLog         logThrottle  // 入口 DoH 转发失败日志限频（TCP 失败日志若要限频应另设一个，不共用窗口）
	hopDials          atomic.Int64 // 入口向出口新建 QUIC 连接的次数（测试断言复用用）
	connTracker       *ConnTracker
	ipPool            *IPPool
	aiPool            *IPPool // ai 类别会话的地址池（10.88.128.0/17）；nil 表示不提供该类别
	ipv6Pool          *IPv6Pool
	globalRouter      *GlobalTunnelRouter
	globalReaderMu    sync.Mutex
	globalReader      *GlobalTunnelReader
	authJail          *AuthFailureJail
	masqueProxy       *masque.Proxy
	connectIPProxy    *connectip.Proxy
	h3Server          *http3.Server

	udpTempl *uritemplate.Template
	ipTempl  *uritemplate.Template

	handlerMu sync.RWMutex
	handler   http.Handler

	tokenStore           *TokenStore
	udpMu                sync.Mutex
	tokenUDPCtx          map[string]int
	globalUDPCtx         atomic.Int64
	maxGlobalUDP         int64
	maxUDPPerToken       int         // 每个 token 的 UDP 上下文上限；出口（role=egress）的 token 是共用的跳间凭证，放宽到全局上限
	allowLoopbackForTest atomic.Bool // 测试钩子：服务运行后可能被设置，须并发安全
	resolveUDPFn         atomic.Pointer[resolveUDPFunc]
	udpDialFn            atomic.Pointer[udpDialFunc]
	icmpForwardHook      atomic.Pointer[icmpForwardFunc]
	icmpv6ForwardHook    atomic.Pointer[icmpForwardFunc]
	nextHopDialer        atomic.Pointer[nextHopDialFunc]
	nextHopUDPDialer     atomic.Pointer[nextHopDialFunc]

	// WebRTC STUN fast aging & session tracking
	udpSessions     map[*udpSessionTracker]struct{}
	stunIdleTimeout atomic.Int64 // time.Duration 纳秒；测试钩子可能在服务运行后设置
	udpIdleTimeout  atomic.Int64 // time.Duration 纳秒

	// tcpIdleTimeout 是标准 CONNECT 中继的空闲上限（双向均无流量）；0 表示默认值。
	tcpIdleTimeout time.Duration

	// connectIPSessions 登记活动的 CONNECT-IP 会话并限制其数量。
	connectIPSessions connectIPSessionTable

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
	s.stunIdleTimeout.Store(int64(stunTimeout))
	s.udpIdleTimeout.Store(int64(normalTimeout))
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
	if d := time.Duration(s.stunIdleTimeout.Load()); d > 0 {
		timeout = d
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
	storeHook(&s.icmpForwardHook, (*icmpForwardFunc)(&hook), hook == nil)
}

// SetICMPv6ForwardHookForTest sets custom ICMPv6 forward hook for testing
func (s *QUICServer) SetICMPv6ForwardHookForTest(hook func(target net.IP, echoReq []byte) ([]byte, error)) {
	storeHook(&s.icmpv6ForwardHook, (*icmpForwardFunc)(&hook), hook == nil)
}

// SetAllowLoopbackForTest enables loopback dialing for unit tests.
func (s *QUICServer) SetAllowLoopbackForTest(allow bool) {
	s.allowLoopbackForTest.Store(allow)
}

// SetNextHopDialerForTest sets a custom dialer for next-hop cascading in tests
func (s *QUICServer) SetNextHopDialerForTest(d func(nextHopAddr, target, hopCred string) (net.Conn, error)) {
	storeHook(&s.nextHopDialer, (*nextHopDialFunc)(&d), d == nil)
}

// SetNextHopUDPDialerForTest sets a custom UDP dialer for next-hop cascading in tests
func (s *QUICServer) SetNextHopUDPDialerForTest(d func(nextHopAddr, target, hopCred string) (net.Conn, error)) {
	storeHook(&s.nextHopUDPDialer, (*nextHopDialFunc)(&d), d == nil)
}

// SetUDPDialFunc sets custom UDP dial function for testing
func (s *QUICServer) SetUDPDialFunc(fn func(network string, laddr, raddr *net.UDPAddr) (*net.UDPConn, error)) {
	storeHook(&s.udpDialFn, (*udpDialFunc)(&fn), fn == nil)
}

// SetResolveUDPFunc sets custom UDP resolution function for testing
func (s *QUICServer) SetResolveUDPFunc(fn func(network, addr string) (*net.UDPAddr, error)) {
	storeHook(&s.resolveUDPFn, (*resolveUDPFunc)(&fn), fn == nil)
}

func (s *QUICServer) resolveUDP(network, addr string) (*net.UDPAddr, error) {
	if fn := s.resolveUDPFn.Load(); fn != nil {
		return (*fn)(network, addr)
	}
	return net.ResolveUDPAddr(network, addr)
}

func (s *QUICServer) dialUDP(network string, laddr, raddr *net.UDPAddr) (*net.UDPConn, error) {
	if fn := s.udpDialFn.Load(); fn != nil {
		return (*fn)(network, laddr, raddr)
	}
	return net.DialUDP(network, laddr, raddr)
}

type quicStreamConn struct {
	stream *http3.RequestStream
	qConn  *quic.Conn
	shared bool      // qConn 是入口到出口的共享连接：Close 只结束这一个流，不关连接
	lease  *hopLease // 共享连接的租约，Close 时归还
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
		if c.shared {
			// 共享连接上不会再有人读这个流：取消读方向，避免对端继续发送占着流量窗口。
			c.stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		}
		err1 = c.stream.Close()
	}
	if c.lease != nil {
		c.lease.release()
	}
	if c.qConn != nil && !c.shared {
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

// dialNextHopTCP 经出口建立到 target 的 TCP 隧道。userKey 是入口认证出的用户 token：
// 同一用户的请求共用一条到出口的 QUIC 连接（每请求一个流），不同用户互不共用，
// 这样一个用户的慢流只占自己连接的流控窗口，不会拖住其他用户（队头阻塞隔离）。
// 连接池满且无空闲连接可回收时，本次请求用一条独立连接（Close 时一并关闭）。
func (s *QUICServer) dialNextHopTCP(nextHopAddr, target, hopCred, userKey string) (net.Conn, error) {
	if fn := s.nextHopDialer.Load(); fn != nil {
		return (*fn)(nextHopAddr, target, hopCred)
	}

	targetHost := strings.TrimPrefix(target, "//")
	targetHost = strings.TrimPrefix(targetHost, "/")
	targetHost = strings.TrimPrefix(targetHost, "/")
	req, err := http.NewRequestWithContext(context.Background(), http.MethodConnect, "//"+targetHost, nil)
	if err != nil {
		return nil, fmt.Errorf("create next hop connect request: %w", err)
	}
	req.Proto = "HTTP/1.1"
	req.Header.Set("Aero-Hop-Token", hopCred)

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer dialCancel()

	// 取得连接与流。共享连接可能刚被对端关闭（空闲超时、出口重启）：开流失败且连接已死时换新连接重试一次。
	var (
		lease  *hopLease // 共享连接的租约；独立连接时为 nil
		pc     *hopPooledConn
		reqStr *http3.RequestStream
	)
	for attempt := 0; ; attempt++ {
		lease, err = s.hopPool.get(dialCtx, userKey, func() (*hopPooledConn, error) { return s.dialHopConn(nextHopAddr) })
		switch {
		case err == nil:
			pc = lease.conn
		case errors.Is(err, errHopPoolFull):
			if pc, err = s.dialHopConn(nextHopAddr); err != nil {
				return nil, err
			}
			lease = nil
		default:
			return nil, err
		}
		reqStr, err = pc.h3.OpenRequestStream(dialCtx)
		if err == nil {
			break
		}
		if lease == nil {
			_ = pc.q.CloseWithError(0, "failed to open stream")
			return nil, fmt.Errorf("open next hop request stream: %w", err)
		}
		if pc.alive() || attempt >= 1 {
			// 连接还活着（多半是流数量到上限或超时）：不动共享连接，只让本次请求失败。
			lease.release()
			return nil, fmt.Errorf("open next hop request stream: %w", err)
		}
		s.hopPool.invalidate(lease)
		lease.release()
	}

	// abort 在流建立之后的失败路径上释放流与租约（独立连接则关闭整条连接）。
	abort := func() {
		reqStr.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		reqStr.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		switch {
		case lease == nil:
			_ = pc.q.CloseWithError(0, "next hop request failed")
		case !pc.alive():
			s.hopPool.invalidate(lease)
			lease.release()
		default:
			lease.release()
		}
	}
	if err := reqStr.SendRequestHeader(req); err != nil {
		abort()
		return nil, fmt.Errorf("send next hop request header: %w", err)
	}
	// 出口不应答时不能一直占着流（§8.1）：响应头读取加超时，之后清除，数据传输阶段由中继自己的空闲超时管理。
	_ = reqStr.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, err := reqStr.ReadResponse()
	_ = reqStr.SetReadDeadline(time.Time{})
	if err != nil {
		abort()
		return nil, fmt.Errorf("read next hop response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		proxyStatus := resp.Header.Get("Proxy-Status")
		abort()
		return nil, fmt.Errorf("next hop connect rejected with status %d (Proxy-Status: %s)", resp.StatusCode, proxyStatus)
	}

	return &quicStreamConn{stream: reqStr, qConn: pc.q, shared: lease != nil, lease: lease}, nil
}

// dialHopConn 建立到出口的 QUIC 连接并包成 HTTP/3 客户端连接（只在连接池里没有可用连接时调用）。
func (s *QUICServer) dialHopConn(nextHopAddr string) (*hopPooledConn, error) {
	s.hopDials.Add(1)
	tlsConf := &tls.Config{
		ServerName:         dialSNI(s.cfg, nextHopAddr),
		InsecureSkipVerify: s.allowLoopbackForTest.Load(),
		NextProtos:         []string{"h3"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	qConn, err := quic.DialAddr(ctx, nextHopAddr, tlsConf, DefaultQUICConfig())
	if err != nil {
		// 故意用 %v 而不是 %w，原因见 dialNextHopUDP。
		return nil, fmt.Errorf("dial next hop %s over quic: %v", nextHopAddr, err)
	}
	tr := &http3.Transport{EnableDatagrams: true}
	return &hopPooledConn{q: qConn, h3: tr.NewClientConn(qConn)}, nil
}

func (s *QUICServer) dialNextHopUDP(nextHopAddr, target, hopCred string) (net.Conn, error) {
	if fn := s.nextHopUDPDialer.Load(); fn != nil {
		return (*fn)(nextHopAddr, target, hopCred)
	}

	// 生产真实链路：通过 MASQUE CONNECT-UDP 向上游下一跳中继建立隧道 (NEW-01)
	sni := dialSNI(s.cfg, nextHopAddr)

	tlsConf := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: s.allowLoopbackForTest.Load(),
		NextProtos:         []string{"h3"},
	}
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer dialCancel()
	qConn, err := quic.DialAddr(dialCtx, nextHopAddr, tlsConf, &quic.Config{EnableDatagrams: true})
	if err != nil {
		// 故意用 %v 而不是 %w：下一跳地址解析失败若被 rejectDial 识别成 DNS 错误，会返回
		// destination_ip_unroutable，与契约“出口失败一律 502 connection_refused”不符（api/dataplane.md §8）。
		return nil, fmt.Errorf("dial next hop quic: %v", err)
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
	ipPool, _ := NewIPPool(edgeDefaultPoolCIDR)
	aiPool, _ := NewIPPool(edgeAIPoolCIDR)
	var ipv6Pool *IPv6Pool
	if strings.TrimSpace(ipv6CIDR) != "" {
		ipv6Pool, _ = newRoutedIPv6Pool(ipv6CIDR)
	}
	qs := newQUICServer(v, cl, bl, dg, rl, ipPool, ipv6Pool)
	qs.aiPool = aiPool
	return qs
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
		doh:              newDoHForwarder(),
		connTracker:      NewConnTracker(),
		ipPool:           ipPool,
		ipv6Pool:         ipv6Pool,
		globalRouter:     NewGlobalTunnelRouter(),
		authJail:         NewAuthFailureJail(),
		masqueProxy:      &masque.Proxy{},
		connectIPProxy:   &connectip.Proxy{},
		tokenUDPCtx:      make(map[string]int),
		maxGlobalUDP:     DefaultMaxGlobalUDP,
		maxUDPPerToken:   MaxUDPContextsPerToken,
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
	s.closeHopDoH()
	s.hopPool.close()
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
	if n >= s.maxUDPPerToken {
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
	// 连接结束后立即摘除跟踪记录；否则只能等 5 分钟一次的 reaper，期间指针与绑定一直占用内存。
	defer s.connTracker.Remove(conn)
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
	token, _, ok := s.authRequestClaims(w, r)
	return token, ok
}

// authRequestClaims 与 authRequest 相同，并返回本次请求验签得到的 token 载荷。
// 不透明 token 与出口跳间凭证没有载荷，返回 nil。调用方应直接用返回的载荷做授权判定，
// 不要依赖连接绑定表：绑定发生在验签之后的另一步，其间别的请求可能读到尚未写完的状态。
func (s *QUICServer) authRequestClaims(w http.ResponseWriter, r *http.Request) (string, *TokenClaims, bool) {
	remoteIP := ClientIP(r)

	// 出口：先比对跳间凭证。持有正确凭证的入口不受认证封禁限制——封禁按 IPv6 /64 计，
	// 同一 /64 里的其他租户对出口认证失败，不能让入口被一起封掉而使多跳整体中断（§11.6）。
	// 凭证错误的请求仍先过封禁检查，行为不变。
	var egressHopOK bool
	if s.cfg != nil && s.cfg.Role == "egress" {
		expected := []byte(s.cfg.HopCredential)
		matches := func(v string) bool {
			return v != "" && len(expected) > 0 && subtle.ConstantTimeCompare([]byte(v), expected) == 1
		}
		bearer, _ := bearerToken(r)
		egressHopOK = matches(strings.TrimSpace(r.Header.Get("Aero-Hop-Token"))) || matches(bearer)
		if egressHopOK {
			return s.cfg.HopCredential, nil, true
		}
	}

	if s.authJail != nil && s.authJail.IsBanned(remoteIP) {
		w.Header().Set("Retry-After", "900")
		w.WriteHeader(http.StatusTooManyRequests)
		return "", nil, false
	}

	if s.cfg != nil && s.cfg.Role == "egress" {
		s.rejectAuth(w, remoteIP, "invalid hop credential")
		return "", nil, false
	}

	// 只校验 token；Aero-Timestamp / Aero-Nonce 已废弃并被忽略（C3 §5）。
	token, ok := bearerToken(r)
	if !ok {
		s.rejectAuth(w, remoteIP, "")
		return "", nil, false
	}
	claims, err := s.checkToken(token)
	if errors.Is(err, ErrTokenExpired) {
		// 过期是正常用户的常态（休眠后），客户端会刷新 token；不计入防爆破封禁
		w.Header().Set("WWW-Authenticate", `Bearer realm="aero", error="invalid_token"`)
		w.Header().Set("Proxy-Status", `aero; error=proxy_authorization_required; details="EDGE_AUTH_TOKEN_EXPIRED"`)
		w.WriteHeader(http.StatusUnauthorized)
		return "", nil, false
	}
	if err != nil {
		s.rejectAuth(w, remoteIP, err.Error())
		return "", nil, false
	}
	// 同一 QUIC 连接上的请求必须使用首次请求绑定的 token；首次绑定时执行本节点设备数限制（C3 §3 第 7 步）。
	if qc, _ := r.Context().Value(quicConnKey{}).(*quic.Conn); qc != nil && s.connTracker != nil {
		if bound, tracked := s.connTracker.Get(qc); tracked {
			if subtle.ConstantTimeCompare([]byte(bound), []byte(token)) != 1 {
				s.rejectAuth(w, remoteIP, "token differs from the one bound to this connection")
				return "", nil, false
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
	return token, claims, true
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

// 数据面拒绝响应（C1 §7）。details 只放固定文本或 EDGE_* 错误码（api/errors.yaml），
// 绝不放原始 err.Error()：它可能含 WARP 本地代理地址、下一跳地址等内部信息。

// rejectBadRequest 返回 400：请求本身格式错误（缺目标、端口非数字、无法解析的 URI），不属于 §7 的 502 类。
// error 取 RFC 9209 的 http_request_error。
func rejectBadRequest(w http.ResponseWriter) {
	w.Header().Set("Proxy-Status", `aero; error=http_request_error; details="EDGE_BAD_REQUEST"`)
	w.WriteHeader(http.StatusBadRequest)
}

// rejectDestinationProhibited 返回 403：目的地址或端口被 §5 拒绝；why 是固定的分类词（如 private、smtp）。
func rejectDestinationProhibited(w http.ResponseWriter, why string) {
	w.Header().Set("Proxy-Status", fmt.Sprintf("aero; error=destination_ip_prohibited; details=%q", why))
	w.WriteHeader(http.StatusForbidden)
}

// rejectLimitExceeded 返回 503：本节点的并发资源（连接、拨号、CONNECT-IP 会话）已达上限。
func rejectLimitExceeded(w http.ResponseWriter) {
	w.Header().Set("Proxy-Status", "aero; error=connection_limit_exceeded")
	w.WriteHeader(http.StatusServiceUnavailable)
}

// rejectDial 把拨号失败映射为 §7 的拒绝响应，用 sentinel 错误判定，不依赖错误文本：
// 解析到被禁地址 403；本地并发上限 503；WARP 出口 fail-closed 与 DNS 解析失败、其他拨号失败 502。
func rejectDial(w http.ResponseWriter, err error) {
	var dnsErr *net.DNSError
	switch {
	case errors.Is(err, errBlockedTarget):
		rejectDestinationProhibited(w, "EDGE_DEST_PROHIBITED")
	case errors.Is(err, errDialTokenLimit), errors.Is(err, errDialQueueFull):
		rejectLimitExceeded(w)
	case errors.Is(err, errWarpFailClosed):
		w.Header().Set("Proxy-Status", `aero; error=connection_refused; details="EGRESS_UNAVAILABLE"`)
		w.WriteHeader(http.StatusBadGateway)
	case errors.As(err, &dnsErr):
		w.Header().Set("Proxy-Status", "aero; error=destination_ip_unroutable")
		w.WriteHeader(http.StatusBadGateway)
	default:
		w.Header().Set("Proxy-Status", "aero; error=connection_refused")
		w.WriteHeader(http.StatusBadGateway)
	}
}

// parseTargetPort 取 host:port 的端口。端口必须是 1-65535 的纯数字：
// net.Dial 还接受 "smtp" 之类的服务名，不限制会绕过端口策略。
func parseTargetPort(target string) (uint16, bool) {
	_, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return 0, false
	}
	p, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || p == 0 {
		return 0, false
	}
	return uint16(p), true
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
		rejectBadRequest(w)
		return
	}
	// 端口策略（C1 §5）：与 CONNECT-IP、connect-udp 同一套。端口必须是数字，
	// 否则 net.Dial 会把 "smtp" 之类服务名解析成 25 而绕过策略。
	port, ok := parseTargetPort(target)
	if !ok {
		rejectBadRequest(w)
		return
	}
	if blocked, why := destinationPortBlocked(6, port); blocked {
		rejectDestinationProhibited(w, why)
		return
	}

	if !s.allowLoopbackForTest.Load() {
		if blocked, why := IsBlockedTarget(target); blocked {
			rejectDestinationProhibited(w, why)
			return
		}
	}

	if s.connLimiter != nil {
		if !s.connLimiter.TryAcquire(token) {
			rejectLimitExceeded(w)
			return
		}
		defer s.connLimiter.Release(token)
	}

	var targetConn net.Conn
	var err error
	if s.cfg != nil && s.cfg.Role == "ingress" && s.cfg.NextHopAddr != "" {
		targetConn, err = s.dialNextHopTCP(s.cfg.NextHopAddr, target, s.cfg.HopCredential, token)
	} else if s.dialGuard != nil {
		targetConn, err = s.dialGuard.DialTimeoutFor(token, "tcp", target, 10*time.Second)
	} else {
		tcpNet := "tcp4"
		targetHost, _, _ := net.SplitHostPort(target)
		if tip := net.ParseIP(targetHost); tip != nil && tip.To4() == nil {
			tcpNet = "tcp"
		}
		targetConn, err = net.DialTimeout(tcpNet, target, 10*time.Second)
	}
	if err != nil {
		rejectDial(w, err)
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
	// aborted 表示因空闲超时而终止；此时还要取消流的发送方向，唤醒阻塞在 str.Write 的下行
	// goroutine（客户端不读流时它不会自行返回）。普通出错不取消发送方向，避免丢弃已写入但尚未送达的数据。
	var aborted atomic.Bool
	abort := func() {
		aborted.Store(true)
		cancel()
	}

	// 任一方向出错或整体空闲时，关闭两端以唤醒阻塞的读写。
	go func() {
		<-relayCtx.Done()
		_ = targetConn.Close()
		str.CancelRead(quic.StreamErrorCode(0))
		if aborted.Load() {
			str.CancelWrite(quic.StreamErrorCode(0))
		}
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
				if isTimeoutErr(err) {
					if stillActive() {
						continue
					}
					abort() // 双向都空闲：唤醒可能阻塞在 str.Write 的另一方向
					return
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
				// 写超时：客户端长时间不读流（流控窗口满）时 Write 会一直阻塞，用空闲上限兜底。
				_ = str.SetWriteDeadline(time.Now().Add(idle))
				if _, werr := str.Write(buf[:n]); werr != nil {
					cancel()
					return
				}
			}
			if err != nil {
				if isTimeoutErr(err) {
					if stillActive() {
						continue
					}
					abort() // 双向都空闲：唤醒可能阻塞在 str.Write 的另一方向
					return
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
		rejectBadRequest(w)
		return
	}
	udpPort, ok := parseTargetPort(proxyReq.Target)
	if !ok {
		rejectBadRequest(w)
		return
	}
	// 与 TCP、CONNECT-IP 同一套端口策略（C1 §5）；当前策略对 UDP 无端口限制。
	if blocked, why := destinationPortBlocked(17, udpPort); blocked {
		rejectDestinationProhibited(w, why)
		return
	}

	if !s.allowLoopbackForTest.Load() {
		if blocked, why := IsBlockedTarget(proxyReq.Target); blocked {
			rejectDestinationProhibited(w, why)
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
			rejectDial(w, err)
			return
		}
		targetUDP = uConn
	} else if s.udpDialFn.Load() == nil && s.dialGuard != nil && s.dialGuard.ShouldRouteUDP(proxyReq.Target, 0) {
		warpConn, err := s.dialGuard.DialUDPViaWARP(proxyReq.Target, 10*time.Second)
		if err != nil {
			rejectDial(w, err)
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
			// 目标无法解析属于“目标不可达”（§7 的 502），不是请求格式错误。
			w.Header().Set("Proxy-Status", "aero; error=destination_ip_unroutable")
			w.WriteHeader(http.StatusBadGateway)
			return
		}

		if !s.allowLoopbackForTest.Load() {
			if blocked, why := IsBlockedIP(dstAddr.IP); blocked {
				rejectDestinationProhibited(w, why)
				return
			}
		}

		if s.udpDialFn.Load() == nil && s.dialGuard != nil && s.dialGuard.ShouldRouteUDP(dstAddr.String(), dstAddr.Port) {
			warpConn, err := s.dialGuard.DialUDPViaWARP(dstAddr.String(), 10*time.Second)
			if err != nil {
				rejectDial(w, err)
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
				rejectDial(w, err)
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
		if d := time.Duration(s.stunIdleTimeout.Load()); d > 0 && d < 1*time.Second {
			checkInterval = d / 4
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
				if d := time.Duration(s.udpIdleTimeout.Load()); d > 0 {
					timeout = d
				}
				if isSTUN.Load() {
					timeout = 15 * time.Second
					if d := time.Duration(s.stunIdleTimeout.Load()); d > 0 {
						timeout = d
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
	token, claims, ok := s.authRequestClaims(w, r)
	if !ok {
		return
	}
	if s.connectIPDisabled {
		w.Header().Set("Proxy-Status", `aero; error=connect_ip_disabled; details="CONNECT-IP is disabled on this node"`)
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	// 场景类别（ADR-0017）：缺省 default；无效或保留值 400；token 未授权 403。
	class, ok := parseConnectIPClass(w, r)
	if !ok {
		return
	}
	qc, _ := r.Context().Value(quicConnKey{}).(*quic.Conn)
	if !classAllowedByClaims(claims, class.name) {
		rejectClassNotAllowed(w)
		return
	}

	origHost := r.Host
	r.Host = "placeholder"
	proxyReq, err := connectip.ParseProxyRequest(r, s.ipTempl)
	r.Host = origHost
	if err != nil {
		rejectBadRequest(w)
		return
	}

	pool := s.poolForClass(class.name)
	if pool == nil {
		w.Header().Set("Proxy-Status", `aero; error=address_pool_exhausted; details="IP pool not configured"`)
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	// 地址租约键：签名 token 按 uid（token 每 24 小时轮换，地址保持不变，隧道内 TCP 不中断）；
	// 旧的不透明 token 按 token 本身。
	leaseKey := token
	perKeyLimit := connectIPMaxSessionsOpaque
	if qc != nil && s.connTracker != nil {
		if uid, maxDevices := s.connTracker.Limits(qc); uid != "" {
			leaseKey = "uid:" + uid
			if maxDevices > 0 {
				perKeyLimit = maxDevices // 每个设备一条连接、一个会话
			}
		}
	}

	// 会话数上限（L0 §9.2）：每个会话占用地址、64KB 缓冲与多个 goroutine，
	// 单 QUIC 连接最多可开 1000 个请求流，不加限制可被一个用户耗尽节点资源。
	sess, ok := s.connectIPSessions.acquireClass(qc, leaseKey, class.name, perKeyLimit, s.connectIPGlobalLimit())
	if !ok {
		rejectLimitExceeded(w)
		return
	}
	defer s.connectIPSessions.release(sess)

	// 地址租约键：default 保持原键（升级后行为不变），其他类别加类别后缀，两个类别的地址互不相同。
	addrKey := leaseKey
	if class.name != classDefault {
		addrKey += "/" + class.name
	}
	assignedPrefix, err := pool.AllocateFor(addrKey)
	if err != nil {
		w.Header().Set("Proxy-Status", "aero; error=address_pool_exhausted; details=\"IP pool exhausted\"")
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	defer pool.ReleaseFor(addrKey, assignedPrefix)

	// v1：只有 default 会话分配 IPv6（客户端 TUN 对 IPv6 黑洞，ADR-0017 决定 3）。
	var assignedIPv6 netip.Prefix
	if s.ipv6Pool != nil && class.name == classDefault {
		if v6Prefix, err := s.ipv6Pool.Allocate(); err == nil {
			assignedIPv6 = v6Prefix
			defer s.ipv6Pool.Release(assignedIPv6)
		}
	}

	w.Header().Set(headerTransport, class.transport)
	conn, err := s.connectIPProxy.ProxyWithMode(w, proxyReq, class.mode)
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
	var packetConn IPPacketConn = conn
	if s.bandwidthLimiter.Enabled() {
		// 与 TCP/UDP 相同：按 token 限速，上下行都计入同一个令牌桶。
		packetConn = &limitedIPConn{IPPacketConn: conn, ctx: r.Context(), token: token, limiter: s.bandwidthLimiter}
	}
	binding := GlobalTunnelBinding{Token: token, IPv4: assignedPrefix.Addr(), Conn: packetConn, usage: s.usageCell(token)}
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

// connectIPMaxSessionsOpaque 是不透明 token（没有 max_devices）与未设置设备数上限的签名 token 的
// CONNECT-IP 并发会话上限。取 8：正常用户一台设备一个会话，8 覆盖多设备共用一个旧 token 的情形，
// 又把单 token 可占用的地址与 goroutine 限制在很小的范围内（估算，待实测）。
const connectIPMaxSessionsOpaque = 8

// connectIPGlobalLimit 返回 CONNECT-IP 的全局会话上限：复用全局连接上限（ConnLimiter），
// 没有配置限制器时用其默认值（DefaultMaxGlobal，远小于 /16 地址池的容量）。
func (s *QUICServer) connectIPGlobalLimit() int {
	if s.connLimiter != nil {
		return int(s.connLimiter.MaxGlobal())
	}
	return DefaultMaxGlobal
}

// connectIPSession 是一个已登记的 CONNECT-IP 会话。
type connectIPSession struct {
	conn     *quic.Conn // 可为 nil（测试中没有 QUIC 连接）
	key      string
	class    string
	released bool
}

// connectIPSessionTable 登记活动的 CONNECT-IP 会话并执行三层上限（ADR-0017 决定 7）：
// 每个 QUIC 连接每个类别 1 个；每个 uid/token（key）不超过 perKey 个设备（按不同 QUIC 连接计，
// 同一连接上的两条类别会话算一台）；全局不超过 global 个会话。
type connectIPSessionTable struct {
	mu     sync.Mutex
	byConn map[*quic.Conn]map[string]*connectIPSession
	byKey  map[string]map[*connectIPSession]struct{}
	total  int
}

// acquire 登记一个 default 类别会话（保留给不区分类别的调用方）。
func (t *connectIPSessionTable) acquire(conn *quic.Conn, key string, perKey, global int) (*connectIPSession, bool) {
	return t.acquireClass(conn, key, classDefault, perKey, global)
}

// devicesLocked 返回 key 下的设备数：不同的 QUIC 连接各算一台，没有连接的会话（测试）各算一台。
func (t *connectIPSessionTable) devicesLocked(key string) int {
	seen := make(map[*quic.Conn]struct{})
	n := 0
	for sess := range t.byKey[key] {
		if sess.conn == nil {
			n++
			continue
		}
		if _, dup := seen[sess.conn]; !dup {
			seen[sess.conn] = struct{}{}
		}
	}
	return n + len(seen)
}

// hasConnLocked 报告 key 下是否已有来自 conn 的会话。
func (t *connectIPSessionTable) hasConnLocked(key string, conn *quic.Conn) bool {
	if conn == nil {
		return false
	}
	for sess := range t.byKey[key] {
		if sess.conn == conn {
			return true
		}
	}
	return false
}

// acquireClass 登记一个会话；任一上限已满返回 false。成功后调用方必须在 defer 中 release。
func (t *connectIPSessionTable) acquireClass(conn *quic.Conn, key, class string, perKey, global int) (*connectIPSession, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.byConn == nil {
		t.byConn = make(map[*quic.Conn]map[string]*connectIPSession)
		t.byKey = make(map[string]map[*connectIPSession]struct{})
	}
	if conn != nil {
		if _, busy := t.byConn[conn][class]; busy {
			return nil, false
		}
	}
	if global > 0 && t.total >= global {
		return nil, false
	}
	// 同一连接已有该 key 的另一类别会话时不增加设备数。
	if perKey > 0 && !t.hasConnLocked(key, conn) && t.devicesLocked(key) >= perKey {
		// 设备数上限替换旧连接时，旧连接的处理协程可能还没来得及退出：
		// 先清掉连接已关闭的会话，避免把“换设备重连”误判为超限。
		for other := range t.byKey[key] {
			if other.conn != nil && !connAlive(other.conn) {
				t.removeLocked(other)
			}
		}
		if t.devicesLocked(key) >= perKey {
			return nil, false
		}
	}
	sess := &connectIPSession{conn: conn, key: key, class: class}
	if conn != nil {
		if t.byConn[conn] == nil {
			t.byConn[conn] = make(map[string]*connectIPSession)
		}
		t.byConn[conn][class] = sess
	}
	if t.byKey[key] == nil {
		t.byKey[key] = make(map[*connectIPSession]struct{})
	}
	t.byKey[key][sess] = struct{}{}
	t.total++
	return sess, true
}

// release 释放会话；可重复调用。
func (t *connectIPSessionTable) release(sess *connectIPSession) {
	if sess == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.removeLocked(sess)
}

func (t *connectIPSessionTable) removeLocked(sess *connectIPSession) {
	if sess.released {
		return
	}
	sess.released = true
	if sess.conn != nil {
		if m := t.byConn[sess.conn]; m != nil {
			if m[sess.class] == sess {
				delete(m, sess.class)
			}
			if len(m) == 0 {
				delete(t.byConn, sess.conn)
			}
		}
	}
	if set := t.byKey[sess.key]; set != nil {
		delete(set, sess)
		if len(set) == 0 {
			delete(t.byKey, sess.key)
		}
	}
	t.total--
}

// active 返回当前登记的会话总数。
func (t *connectIPSessionTable) active() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.total
}

// limitedIPConn 给 CONNECT-IP 会话套上 bandwidthLimiter（与 TCP/UDP 同一个按 token 的令牌桶）。
// 上行在读到报文后扣减（拖慢后续读取，QUIC 流控向客户端反压），下行在写出前扣减；
// 等待随会话上下文取消而结束，Close 之后不会卡住发送协程。
type limitedIPConn struct {
	IPPacketConn
	ctx     context.Context
	token   string
	limiter *BandwidthLimiter
}

func (c *limitedIPConn) ReadPacket(b []byte) (int, error) {
	n, err := c.IPPacketConn.ReadPacket(b)
	if n > 0 {
		_ = c.limiter.TakeContext(c.ctx, c.token, n)
	}
	return n, err
}

func (c *limitedIPConn) WritePacket(b []byte) ([]byte, error) {
	if err := c.limiter.TakeContext(c.ctx, c.token, len(b)); err != nil {
		return nil, net.ErrClosed // 会话已结束：与连接关闭同样处理，发送协程不记噪声日志
	}
	return c.IPPacketConn.WritePacket(b)
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

	qtype, ok := dnsQueryType(queryBytes)
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// 出口（role=egress）收到的 token 是跳间凭证，所有用户共用；用户级限流已在入口完成，这里不再限流。
	isEgress := s.cfg != nil && s.cfg.Role == "egress"
	if !isEgress && !s.doh.allow(token) {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	var resp []byte
	if s.cfg != nil && s.cfg.Role == "ingress" {
		// 入口不自行解析：一律交给出口（含 AAAA 是否有 IPv6 出口的判断），失败回 SERVFAIL。
		if out, err := s.forwardDoHToNextHop(r.Context(), queryBytes); err == nil {
			resp = out
		} else {
			// 出口宕机时每个查询都会失败：限频，避免日志量与查询量相当（被动放大磁盘占用）。
			if ok, suppressed := s.hopDoHLog.allow(time.Now(), hopLogEvery); ok {
				log.Printf("[HOP] DoH forward to next hop failed: %v (%d similar suppressed)", err, suppressed)
			}
			resp = dnsReply(queryBytes, 2)
		}
	} else if qtype == dnsTypeAAAA && s.ipv6Pool == nil {
		resp = dnsReply(queryBytes, 0) // 节点没有 IPv6 出口：空应答，应用直接用 IPv4
	} else if out, err := s.doh.exchange(r.Context(), queryBytes); err == nil {
		resp = out
	} else {
		resp = dnsReply(queryBytes, 2) // SERVFAIL：上游不可用，不伪造“无记录”
	}
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
