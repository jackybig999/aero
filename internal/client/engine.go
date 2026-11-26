// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	ClientVersion = "1.8.0"
	Protocol      = "aero/3.0"
)

const (
	stateStopped  int32 = 0
	stateStarting int32 = 1
	stateRunning  int32 = 2
	stateStopping int32 = 3
)

var (
	// ErrUDPUnavailable 标识 TUN 模式下 UDP/443 (QUIC/HTTP/3) 拨号失败，降级防御阻止整机伪装
	ErrUDPUnavailable = errors.New("UDP_UNAVAILABLE")
	ErrStartAborted   = errors.New("start aborted by stop request")
	// ErrEngineClosed 引擎已 Close（进程退出路径）：一切建立数据面的入口都返回它，不再重新建网卡
	ErrEngineClosed = errors.New("engine closed")
	// ErrTunUnavailable 表示虚拟网卡无法创建/配置（缺驱动或 DLL、没有管理员权限、驱动启动失败等）。
	// 这类失败不是网络问题，引擎据此降级为“仅本地代理”而不是让整个连接失败。
	ErrTunUnavailable   = errors.New("virtual network adapter unavailable")
	subSingleFlight     singleflight.Group
	detectThirdPartyTUN = DetectThirdPartyTUN
	dialIPFn            = func(ctx context.Context, m *SessionManager) (IPPacketConn, string, error) {
		if m != nil {
			conn, prefixes, err := m.DialIP(ctx)
			if err != nil {
				return nil, "", err
			}
			var ipv4Prefix netip.Prefix
			for _, prefix := range prefixes {
				if prefix.IsValid() && prefix.Addr().Is4() {
					ipv4Prefix = prefix
					break
				}
			}
			if !ipv4Prefix.IsValid() {
				if closeErr := conn.Close(); closeErr != nil {
					return nil, "", fmt.Errorf("CONNECT-IP response has no valid IPv4 prefix; close connection: %w", closeErr)
				}
				return nil, "", errors.New("CONNECT-IP response has no valid IPv4 prefix")
			}
			return conn, ipv4Prefix.String(), nil
		}
		return nil, "", errors.New("session manager is nil")
	}
)

// AppState 描述客户端当前运行状态
type AppState struct {
	Connected   bool   `json:"connected"`
	Starting    bool   `json:"starting,omitempty"`
	Stopping    bool   `json:"stopping,omitempty"`
	LastError   string `json:"last_error,omitempty"`
	ErrorCode   string `json:"error_code,omitempty"`
	ConflictVPN string `json:"conflict_vpn,omitempty"`
	Mode        string `json:"mode"`
	Listen      string `json:"listen"`
	ActiveNode  string `json:"active_node"`
	ActiveSNI   string `json:"active_sni"`
	ActualPort  int    `json:"actual_port,omitempty"`
	SubURL      string `json:"sub_url,omitempty"`
	NodesCount  int    `json:"nodes_count"`
	Version     string `json:"version"`

	Node         string `json:"node,omitempty"`
	SNI          string `json:"sni,omitempty"`
	ISP          string `json:"isp,omitempty"`
	ISPName      string `json:"isp_name,omitempty"`
	RttMs        int64  `json:"rtt_ms"`
	ProbeOk      bool   `json:"probe_ok"`
	ProbeMs      int64  `json:"probe_ms"`
	GeoRuleCount int    `json:"geo_rule_count"`
	// GeoUpdatedAt 是最近一次成功获取（含“已是最新”）直连规则的 Unix 秒；0 表示尚未获取，仅用内置规则。
	GeoUpdatedAt int64 `json:"geo_updated_at"`
	// GeoError 是最近一次同步失败的简要原因；成功后清空。
	GeoError string `json:"geo_error,omitempty"`
	// ResidentListening 表示常驻混合代理（本地 SOCKS5/HTTP 端口）当前是否真的在监听；
	// Listen 是它实际使用的地址（默认端口不可用时可能是备用端口）。
	ResidentListening bool `json:"resident_listening"`
	// Degraded 为真表示请求的是 TUN 但虚拟网卡不可用，当前仅本地代理可用（此时 Mode 为 sysproxy）；
	// DegradedReason 是原因（引擎原始错误文本，界面再翻译）。
	Degraded       bool   `json:"degraded"`
	DegradedReason string `json:"degraded_reason,omitempty"`
	// AIChannel 是 AI 稳定通道状态（off、unsupported、connecting、up、unavailable，隧道未建立时为空），
	// AIChannelReason 是 unavailable 时的原因码；AIChannelEnabled 是用户开关（ADR-0017）。
	AIChannel        string `json:"ai_channel,omitempty"`
	AIChannelReason  string `json:"ai_channel_reason,omitempty"`
	AIChannelEnabled bool   `json:"ai_channel_enabled"`
}

// Engine 客户端核心引擎
type Engine struct {
	mu           sync.RWMutex
	splitEngine  *SplitEngine
	dnsHandler   *DNSHandler
	tunnelClient *TunnelClient
	sessionPool  ISessionPool
	stackEngine  *StackEngine
	tunHost      tunHost // 自有网卡及其上的全部宿主状态（ADR-0013）
	sessionMgr   *SessionManager

	appliedSub    *Applied
	activeAddr    string
	activeToken   string
	activeSNI     string
	mode          string
	listenAddr    string
	mixedListener net.Listener
	// mixedHandshakeTimeout 为 0 时用默认 10 秒；仅测试注入更短的值（须在连接建立前设置）
	mixedHandshakeTimeout time.Duration
	// startTr 是最近一次启动的阶段耗时记录（只写日志）。启动由 lifecycleMu 串行，其他协程只读指针。
	startTr atomic.Pointer[startTrace]

	currentISP  string
	savedSubURL string
	// subAppliedAt / subAppliedFromCache 记录 savedSubURL 最近一次成功应用的时间与是否来自离线缓存（e.mu 保护）。
	subAppliedAt        time.Time
	subAppliedFromCache bool
	geoDataURL          string

	// degraded 为真表示请求的是 TUN，但虚拟网卡不可用，当前以“仅本地代理”运行（隧道已连上，只有走本地端口的流量经隧道）。
	degraded       atomic.Bool
	degradedReason atomic.Pointer[string]

	geoSyncOnce sync.Once
	geoSyncSem  chan struct{} // 容量 1 的同步信号量（界面按钮与后台自动同步不并发）
	geoStatMu   sync.Mutex
	geoUpdated  time.Time
	geoLastErr  string
	geoAutoOnce sync.Once
	geoLoopDone chan struct{} // 后台同步协程退出时关闭（测试等待用）

	running           atomic.Bool
	state             atomic.Int32
	startEpoch        uint64
	startPending      atomic.Bool
	closed            atomic.Bool // Close 已调用；仅在 e.mu 下置位，建立数据面的入口在 e.mu 下检查
	pendingMode       string
	lifecycleMu       sync.Mutex
	startCancel       context.CancelFunc
	tcpDialer         func(ctx context.Context, target string) (net.Conn, error)
	rootCtx           context.Context
	rootCancel        context.CancelFunc
	netMon            NetworkMonitor
	activeConns       sync.Map
	residentConns     sync.Map
	mixedStarting     bool
	killSwitch        atomic.Bool
	sentinel          *nodeSentinel
	nodeGen           uint64                            // 活动节点代数（e.mu 保护）：每次提交节点切换自增；锁外解析后据此判断状态是否被改过
	resolveIPv4       func(host string) (net.IP, error) // 节点主机名解析；nil 时用 resolvePhysicalIPv4（测试可注入）
	packetConnFactory PacketConnFactory
	daemonCtx         context.Context
	daemonCancel      context.CancelFunc
	tokenRefreshKick  chan struct{} // 订阅应用后通知 token 刷新协程（token_refresh.go）
	unavailableMu     sync.Mutex
	unavailableNodes  map[string]time.Time // 返回“节点不可用”（503）的节点 → 截止时间；换节点时跳过
	authRefreshMu     sync.Mutex
	lastAuthRefresh   time.Time // 上次因 401 强制刷新订阅的时间（至多每分钟一次）
	tokenRefreshOnce  sync.Once // 首次应用订阅时才启动刷新协程

	chainProxyMu  sync.RWMutex
	chainProxyCfg ChainProxyConfig

	lastErrMu          sync.RWMutex
	lastErr            string
	lastErrCode        string
	lastErrConflictVPN string

	socksAuthToken string

	// AI 稳定通道（ADR-0017）：ai 是通道状态，aiCls 由 DNS 处理器登记 AI 地址、供复用层分类（跨重连保留）。
	ai    aiChannel
	aiCls *flowClassifier

	// rootMu 保护 rootCtx 的跨协程读取（getContext）与 Start 的重写。
	rootMu sync.RWMutex
}

// NewEngine 创建客户端引擎
func NewEngine() *Engine {
	split := NewSplitEngine()
	dns := NewDNSHandler(split)
	pool := GlobalSessionPool
	tunnel := NewTunnelClient(pool, split)
	sessMgr := NewSessionManager()
	tunnel.SetSessionManager(sessMgr)
	SetGlobalSessionManager(sessMgr)

	// 将 DoH 解析器连接至 DNS 处理器
	dns.SetDoHResolver(func(ctx context.Context, dnsReq []byte) ([]byte, error) {
		return sessMgr.DoHQuery(ctx, dnsReq)
	})

	// 将短流解析器连接至 DNS 处理器
	dns.SetTunnelResolver(func(ctx context.Context, domain string) (net.IP, error) {
		return tunnel.ResolveDNS(ctx, domain)
	})

	eng := &Engine{
		splitEngine:       split,
		dnsHandler:        dns,
		tunnelClient:      tunnel,
		sessionPool:       pool,
		sessionMgr:        sessMgr,
		mode:              "tun",
		listenAddr:        "127.0.0.1:55555",
		netMon:            NewNetworkMonitor(),
		packetConnFactory: ListenPhysicalPacket,
	}
	eng.aiCls = newFlowClassifier()
	eng.ai.enabled.Store(true)
	dns.SetAIRecorder(func(addrs []netip.Addr, ttl time.Duration) {
		for _, a := range addrs {
			eng.aiCls.ai.Add(a, ttl)
		}
	})
	eng.daemonCtx, eng.daemonCancel = context.WithCancel(context.Background())
	eng.tokenRefreshKick = make(chan struct{}, 1)
	sessMgr.SetAuthFailureHook(eng.refreshAfterAuthFailure)
	eng.sentinel = newNodeSentinel(eng)
	SetPacketConnFactory(ListenPhysicalPacket)
	eng.loadChainProxyConfig()
	StartAsyncSNIProber(context.Background())
	return eng
}

func (e *Engine) chainProxyPath() string {
	return filepath.Join(GetDataDir(), "chain_proxy.json")
}

func (e *Engine) loadChainProxyConfig() {
	p := e.chainProxyPath()
	data, err := os.ReadFile(p)
	if err == nil {
		var cfg ChainProxyConfig
		if jerr := json.Unmarshal(data, &cfg); jerr == nil {
			e.chainProxyMu.Lock()
			e.chainProxyCfg = cfg
			e.chainProxyMu.Unlock()
			if e.tunnelClient != nil {
				e.tunnelClient.SetChainProxy(&cfg)
			}
		}
	}
}

// GetChainProxyConfig 获取当前配置的链式代理参数
func (e *Engine) GetChainProxyConfig() ChainProxyConfig {
	e.chainProxyMu.RLock()
	defer e.chainProxyMu.RUnlock()
	return e.chainProxyCfg
}

// SetChainProxyConfig 设置并持久化链式代理配置 (静态住宅出口净化)
func (e *Engine) SetChainProxyConfig(cfg ChainProxyConfig) error {
	e.chainProxyMu.Lock()
	defer e.chainProxyMu.Unlock()
	e.chainProxyCfg = cfg
	if e.tunnelClient != nil {
		e.tunnelClient.SetChainProxy(&cfg)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	p := e.chainProxyPath()
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// SessionManager 获取当前会话管理器
func (e *Engine) SessionManager() *SessionManager {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.sessionMgr
}

// IsRunning 查询引擎当前运行状态
func (e *Engine) IsRunning() bool {
	return e.running.Load() && e.state.Load() == stateRunning
}

// IsStopping 查询引擎是否正在停止中
func (e *Engine) IsStopping() bool {
	return e.state.Load() == stateStopping
}

// PrepareModeSwitch 准备模式切换：停着时仅改模式；运行或启动中时标记 stateStopping 并签发递增票据
func (e *Engine) PrepareModeSwitch(targetMode string) (needRestart bool, ticket uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.closed.Load() {
		// 引擎已关闭：不改模式、不签发票据
		return false, 0
	}
	cur := e.state.Load()
	if cur != stateRunning && cur != stateStarting {
		// 已经停着：只改下次要启动的模式，不签发 ticket，不动 epoch
		e.mode = targetMode
		return false, 0
	}

	if e.startCancel != nil {
		e.startCancel()
	}
	e.state.Store(stateStopping)
	e.running.Store(false)
	e.startEpoch++
	e.startPending.Store(true)
	e.pendingMode = targetMode
	return true, e.startEpoch
}

// IsClosed 报告引擎是否已 Close
func (e *Engine) IsClosed() bool {
	return e.closed.Load()
}

// RequestStart 请求启动：递增票据并设置 startPending。
// 引擎已 Close 时不签发票据，返回 0（0 永远无效，StartWith(0) 返回 ErrEngineClosed）。
func (e *Engine) RequestStart() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed.Load() {
		return 0
	}
	e.startEpoch++
	e.startPending.Store(true)
	e.pendingMode = ""
	return e.startEpoch
}

// BeginStop 标记停止意图：清理 startPending、使待处理票据失效、取消正在进行的探测，若处于活跃态则返回 true
func (e *Engine) BeginStop() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.startPending.Store(false)
	e.startEpoch++
	e.pendingMode = ""
	if e.startCancel != nil {
		e.startCancel()
	}
	cur := e.state.Load()
	if cur != stateRunning && cur != stateStarting {
		return false
	}
	e.state.Store(stateStopping)
	e.running.Store(false)
	return true
}

// ClearStartPending 清除指定票据的挂起状态
func (e *Engine) ClearStartPending(ticket uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if ticket != 0 && e.startEpoch == ticket {
		e.startPending.Store(false)
	}
}

// setRejection 把 edge 的拒绝反映到状态（UI 据错误码提示：token 失效、被限流、节点不可用）。
func (e *Engine) setRejection(r *EdgeRejectError) {
	code := "EDGE_REJECTED"
	switch {
	case strings.HasPrefix(r.Details, "EDGE_"):
		code = r.Details
	case r.AuthFailure():
		code = "EDGE_AUTH_INVALID_TOKEN"
	case r.Status == http.StatusTooManyRequests:
		code = "EDGE_RATE_LIMITED"
	case r.Code == "connect_ip_disabled":
		code = "EDGE_CONNECT_IP_DISABLED"
	case r.Code == "address_pool_exhausted":
		code = "EDGE_POOL_EXHAUSTED"
	}
	e.lastErrMu.Lock()
	e.lastErr = r.Error()
	e.lastErrCode = code
	e.lastErrMu.Unlock()
}

// SetLastError 设置最后错误信息
func (e *Engine) SetLastError(msg string) {
	e.lastErrMu.Lock()
	e.lastErr = msg
	e.lastErrCode = "CONNECT_ERROR"
	e.lastErrMu.Unlock()
}

// SetTCPDialer 允许在测试中注入自定义 TCP 拨号器
func (e *Engine) SetTCPDialer(dialer func(ctx context.Context, target string) (net.Conn, error)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.tcpDialer = dialer
}

// GetListenAddr 获取当前监听地址
func (e *Engine) GetListenAddr() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.listenAddr
}

// SetNetworkMonitor 允许注入自定义网络监控器 (用于单元测试与调试)
func (e *Engine) SetNetworkMonitor(nm NetworkMonitor) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.netMon = nm
}

// SetKillSwitch 激活或关闭客户端纯内存 Kill Switch
func (e *Engine) SetKillSwitch(active bool) {
	e.killSwitch.Store(active)
	if e.stackEngine != nil {
		e.stackEngine.SetKillSwitch(active)
	}
}

// KillSwitch 返回当前 Kill Switch 激活状态
func (e *Engine) KillSwitch() bool {
	return e.killSwitch.Load()
}

// errNodeSwitchSuperseded 表示锁外解析期间节点状态已被其他调用改动，本次切换结果被放弃。
var errNodeSwitchSuperseded = errors.New("active node changed during resolve; switch abandoned")

// Apply 应用已解析好的订阅配置
// 规则：当前活动节点仍在新订阅中时，只就地刷新它的 token/SNI/IP/钉扎，不切换、不排空会话（订阅刷新
// 不得打断隧道，也不得覆盖哨兵 failover 或用户手动选择的节点）；只有活动节点已不在订阅中（或尚无活动节点）
// 才切换，且按订阅顺序优先选不在冷却名单中的节点。严禁调用 Reset()！
// 调用 switchActiveNodeLocked 时可能临时释放并重新获取 e.mu（见该函数注释）。
func (e *Engine) Apply(applied *Applied) error {
	if applied == nil || len(applied.Servers) == 0 {
		return fmt.Errorf("empty applied subscription")
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	e.appliedSub = applied

	// Feature 18: 在注册新钉扎前强制执行 ClearPins()，消除历史 SPKI 钉扎残留
	ClearPins()
	if len(applied.AllPins) > 0 {
		AddPins(applied.AllPins...)
	}

	defer e.kickTokenRefresh()
	if cur, ok := findActiveServer(applied, e.activeAddr); ok {
		e.refreshActiveNodeLocked(applied, cur)
		return nil
	}

	target := applied.Servers[0]
	for _, srv := range applied.Servers {
		if srv.Address != "" && !e.nodeUnavailable(srv.Address) {
			target = srv
			break
		}
	}
	if err := e.switchActiveNodeLocked(target.Address, target.Token, target.SNI); err != nil && !errors.Is(err, errNodeSwitchSuperseded) {
		return err
	}
	return nil
}

// findActiveServer 在订阅中查找当前活动节点：先按 host:port 精确匹配，再按主机名匹配
// （多端口跳频后活动地址的端口可能与订阅里的不同）。
func findActiveServer(applied *Applied, activeAddr string) (ServerConfig, bool) {
	if activeAddr == "" {
		return ServerConfig{}, false
	}
	for _, srv := range applied.Servers {
		if srv.Address == activeAddr {
			return srv, true
		}
	}
	host, _, err := net.SplitHostPort(activeAddr)
	if err != nil || host == "" {
		return ServerConfig{}, false
	}
	for _, srv := range applied.Servers {
		if h, _, _ := net.SplitHostPort(srv.Address); h == host {
			return srv, true
		}
	}
	return ServerConfig{}, false
}

// lookupAppliedIPLocked 从订阅的 IPs 取节点 IPv4（先精确地址，再同主机名）；没有则返回 nil，不做网络解析。
func lookupAppliedIPLocked(applied *Applied, addr string) net.IP {
	if applied == nil || applied.IPs == nil {
		return nil
	}
	if ipStr, ok := applied.IPs[addr]; ok && ipStr != "" {
		if parsed := net.ParseIP(ipStr); parsed != nil {
			if ip4 := parsed.To4(); ip4 != nil {
				return ip4
			}
		}
	}
	host, _, _ := net.SplitHostPort(addr)
	for a, ipStr := range applied.IPs {
		if h, _, _ := net.SplitHostPort(a); h == host && ipStr != "" {
			if parsed := net.ParseIP(ipStr); parsed != nil {
				return parsed.To4()
			}
		}
	}
	return nil
}

// refreshActiveNodeLocked 就地刷新活动节点的凭证（含刷新后的签名 token）与 IP；调用方持 e.mu 写锁。
// 不切换、不排空：已有会话继续使用旧值，下次启动与重连使用新值。
func (e *Engine) refreshActiveNodeLocked(applied *Applied, srv ServerConfig) {
	addr := e.activeAddr
	e.activeToken, e.activeSNI = srv.Token, srv.SNI
	SetActiveEdgePinSPKI(srv.PinSPKI)

	var ech []byte
	if applied.ECHConfigs != nil {
		if c, ok := applied.ECHConfigs[addr]; ok && len(c) > 0 {
			ech = c
		} else if c, ok := applied.ECHConfigs[srv.Address]; ok && len(c) > 0 {
			ech = c
		}
	}
	_, _, _, curIP := getActiveEdge()
	newIP := curIP
	if ip := lookupAppliedIPLocked(applied, addr); ip != nil {
		newIP = ip
	}
	if len(ech) > 0 {
		SetActiveEdge(addr, srv.Token, srv.SNI, newIP, ech)
	} else {
		SetActiveEdge(addr, srv.Token, srv.SNI, newIP)
	}
	if newIP != nil && !newIP.Equal(curIP) {
		// 节点 IP 变化：新旧 IP 都需要走物理网卡（现有会话仍连旧 IP，直到断线重连用新 IP）。
		// 不在 e.mu 内执行：refreshTunRoutes 自行加锁。
		if host, _, err := net.SplitHostPort(addr); err == nil && e.dnsHandler != nil && host != "" {
			e.dnsHandler.SetEdge(host, newIP)
			e.dnsHandler.Flush()
		}
		if e.mode == "tun" && e.running.Load() {
			go e.refreshTunRoutes(newIP, curIP)
		}
	}
}

// LoadAndApplySubscription 从远程 URL 加载并应用订阅，挂载 singleflight 阻断重入
func (e *Engine) LoadAndApplySubscription(src string) (*Applied, error) {
	tCall := time.Now()
	v, err, shared := subSingleFlight.Do(src, func() (any, error) {
		ctx, cancel := context.WithTimeout(e.getContext(), 30*time.Second)
		defer cancel()
		sub, err := FetchSubscription(ctx, src, SubFetchOptions{})
		if err != nil {
			return nil, err
		}
		applied, err := ApplySubscription(sub)
		if err != nil {
			return nil, err
		}

		ispRes := DetectISP(ctx, 500*time.Millisecond)
		bestISP := "DEFAULT"
		if ispRes != nil && ispRes.BestISP != "" {
			bestISP = ispRes.BestISP
		}
		sortServersByISP(applied.Servers, bestISP)

		e.mu.Lock()
		e.currentISP = bestISP
		e.savedSubURL = src
		// savedSubURL 先于 Apply 写入，而 Apply 会先替换节点列表、切换节点还可能失败：
		// 在应用成功之前清零，ReuseAppliedSubscription 不会把“新地址 + 旧节点”或“应用失败的订阅”当作可复用。
		e.subAppliedAt = time.Time{}
		e.subAppliedFromCache = false
		e.mu.Unlock()

		if err := e.Apply(applied); err != nil {
			return nil, err
		}
		e.mu.Lock()
		e.subAppliedAt = time.Now()
		e.subAppliedFromCache = applied.FromCache
		e.mu.Unlock()
		return applied, nil
	})
	if err != nil {
		log.Printf("[SUB] load failed after %v (%s)", time.Since(tCall).Round(time.Millisecond), subErrKind(err))
		return nil, err
	}
	applied := v.(*Applied)
	// shared 为真表示与另一个同 URL 的导入合并（等待它完成）；日志里的耗时是本次调用的总等待
	log.Printf("[SUB] load+apply ok in %v (nodes=%d, fromCache=%v, joinedInflight=%v)", time.Since(tCall).Round(time.Millisecond), len(applied.Servers), applied.FromCache, shared)
	return applied, nil
}

// ReuseAppliedSubscription 在 src 就是当前已应用的订阅、且近期（maxAge 内）成功拉取过时返回节点数与 true，
// 调用方据此跳过网络拉取。点“连接”时用它：订阅在界面启动时已经导入过，每次点连接都重新拉一遍只会白白等待
// （到节点的 TCP/443 新连接首包偶尔丢失，要多等 1~3 秒）。令牌由后台刷新协程负责更新，不依赖点连接时重拉。
// 以下情况不复用，交给正常导入：地址不同、没有应用过、上次结果来自离线缓存、超过 maxAge、
// 当前令牌已到刷新时刻（有效期的 75%）。
func (e *Engine) ReuseAppliedSubscription(src string, maxAge time.Duration) (nodes int, ok bool) {
	e.mu.RLock()
	applied := e.appliedSub
	same := src != "" && src == e.savedSubURL
	at, fromCache := e.subAppliedAt, e.subAppliedFromCache
	e.mu.RUnlock()
	if !same || applied == nil || len(applied.Servers) == 0 || fromCache || at.IsZero() {
		return 0, false
	}
	age := time.Since(at)
	if age > maxAge {
		return 0, false
	}
	if _, tok, _, _ := getActiveEdge(); tok != "" {
		if when, signed := nextTokenRefresh(tok); signed && !tokenRefreshNow().Before(when) {
			return 0, false
		}
	}
	log.Printf("[SUB] reused the subscription applied %v ago (skipped the network fetch)", age.Round(time.Second))
	return len(applied.Servers), true
}

// SwitchActiveNode 切换激活节点
// 核心规则：仅比对 host:port（相同则短路返回，严禁 Reset()）
func (e *Engine) SwitchActiveNode(addr string) error {
	e.mu.Lock()

	if e.activeAddr == addr {
		e.mu.Unlock()
		return nil
	}

	var tok, sni string
	if e.appliedSub != nil {
		tok = e.appliedSub.Tokens[addr]
		sni = e.appliedSub.SNIs[addr]
		if tok == "" || sni == "" {
			host, _, _ := net.SplitHostPort(addr)
			for a, t := range e.appliedSub.Tokens {
				if h, _, _ := net.SplitHostPort(a); h == host {
					if tok == "" {
						tok = t
					}
					if sni == "" {
						sni = e.appliedSub.SNIs[a]
					}
					break
				}
			}
		}
	}

	err := e.switchActiveNodeLocked(addr, tok, sni)
	e.mu.Unlock()
	return err
}

func resolvePhysicalIPv4(host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4, nil
		}
		return nil, fmt.Errorf("IPv6 not supported: %s", host)
	}

	gw, _, _ := PhysicalDefaultGateway()

	isBlacklisted := func(ipStr string) bool {
		return strings.HasPrefix(ipStr, "198.18.") ||
			strings.HasPrefix(ipStr, "198.19.") ||
			strings.HasPrefix(ipStr, "10.88.") ||
			strings.HasPrefix(ipStr, "127.") ||
			strings.HasPrefix(ipStr, "169.254.")
	}

	dialDNS := func(targetDNS string) func(ctx context.Context, network, address string) (net.Conn, error) {
		return func(ctx context.Context, network, address string) (net.Conn, error) {
			target := address
			h, p, err := net.SplitHostPort(address)
			if err == nil && isBlacklisted(h) {
				if targetDNS != "" {
					target = net.JoinHostPort(targetDNS, p)
				} else if gw != "" {
					target = net.JoinHostPort(gw, p)
				} else {
					target = net.JoinHostPort("223.5.5.5", p)
				}
			}
			return DialPhysicalDirect(ctx, network, target)
		}
	}

	r := &net.Resolver{
		PreferGo: true,
		Dial:     dialDNS(gw),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, err := r.LookupIP(ctx, "ip4", host)

	// 若物理网关 DNS 解析失败或未返回有效公网 IPv4，使用直连公共 DNS 兜底
	if err != nil || len(ips) == 0 {
		r2 := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				_, p, _ := net.SplitHostPort(address)
				if p == "" {
					p = "53"
				}
				return DialPhysicalDirect(ctx, network, net.JoinHostPort("223.5.5.5", p))
			},
		}
		ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel2()
		ips, err = r2.LookupIP(ctx2, "ip4", host)
	}

	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("physical resolve %s: %w", host, err)
	}
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			if !isBlacklisted(ip4.String()) {
				return ip4, nil
			}
		}
	}
	return nil, fmt.Errorf("no valid public IPv4 address found for %s", host)
}

// switchActiveNodeLocked 切换活动节点；调用方持 e.mu 写锁。
// 节点 IP 只能经网络解析得到时（最坏阻塞约 6 秒），本函数会临时释放 e.mu，在锁外解析，再重新获取并复核
// （节点代数、订阅、活动地址均未变）后提交；复核失败返回 errNodeSwitchSuperseded，放弃本次结果。
// 因此调用方不得假定调用前后 e.mu 保护的状态不变，且调用后不能依赖调用前读到的值。
// 锁顺序不变：lifecycleMu → e.mu；解析期间不持有任何引擎锁。
func (e *Engine) switchActiveNodeLocked(addr, tok, sni string) error {
	host, _, err := net.SplitHostPort(addr)
	if err == nil && net.ParseIP(host) == nil && host != "" {
		sni = host
	}

	_, _, _, oldIP := getActiveEdge()
	newHost, _, _ := net.SplitHostPort(addr)

	newIP := lookupAppliedIPLocked(e.appliedSub, addr)
	if newIP == nil && net.ParseIP(newHost) != nil {
		// IP 字面量无需网络，直接转换
		ip, rerr := resolvePhysicalIPv4(newHost)
		if rerr != nil {
			return fmt.Errorf("resolve active node %s: %w", newHost, rerr)
		}
		newIP = ip
	}
	if newIP == nil && newHost != "" {
		gen, sub, prevAddr := e.nodeGen, e.appliedSub, e.activeAddr
		resolve := e.resolveIPv4
		if resolve == nil {
			resolve = resolvePhysicalIPv4
		}
		e.mu.Unlock()
		ip, rerr := resolve(newHost)
		e.mu.Lock()
		if e.nodeGen != gen || e.appliedSub != sub || e.activeAddr != prevAddr || e.closed.Load() {
			return errNodeSwitchSuperseded
		}
		if rerr != nil {
			return fmt.Errorf("resolve active node %s: %w", newHost, rerr)
		}
		newIP = ip
		_, _, _, oldIP = getActiveEdge()
	}
	if newIP != nil && e.mode == "tun" && e.running.Load() {
		// 新旧节点都走物理网卡：旧会话在 20 秒排空期内仍在使用旧节点（见下方 Drain）。
		// 不在 e.mu 内执行：refreshTunRoutes 自行加锁。
		go e.refreshTunRoutes(newIP, oldIP)
	}

	var altPorts []int
	if e.appliedSub != nil && e.appliedSub.AltPorts != nil {
		if ap, ok := e.appliedSub.AltPorts[addr]; ok && len(ap) > 0 {
			altPorts = ap
		} else {
			for a, ap := range e.appliedSub.AltPorts {
				if h, _, _ := net.SplitHostPort(a); h == newHost && len(ap) > 0 {
					altPorts = ap
					break
				}
			}
		}
	}
	SetActiveEdgeAltPorts(altPorts)

	var nodePins []string
	if e.appliedSub != nil {
		for _, s := range e.appliedSub.Servers {
			if s.Address == addr {
				nodePins = s.PinSPKI
				break
			}
		}
	}
	SetActiveEdgePinSPKI(nodePins)

	e.nodeGen++
	e.activeAddr = addr
	e.activeToken = tok
	e.activeSNI = sni
	var ech []byte
	if e.appliedSub != nil && e.appliedSub.ECHConfigs != nil {
		if c, ok := e.appliedSub.ECHConfigs[addr]; ok && len(c) > 0 {
			ech = c
		} else {
			for a, c := range e.appliedSub.ECHConfigs {
				if h, _, _ := net.SplitHostPort(a); h == newHost && len(c) > 0 {
					ech = c
					break
				}
			}
		}
	}
	if len(ech) > 0 {
		SetActiveEdge(addr, tok, sni, newIP, ech)
	} else {
		SetActiveEdge(addr, tok, sni, newIP)
	}

	if e.dnsHandler != nil && newHost != "" && newIP != nil {
		e.dnsHandler.SetEdge(newHost, newIP)
		e.dnsHandler.Flush()
	}

	// 平滑软切线（Graceful Draining）：
	// 旧 Session 标记为 draining，不立即 Close()，排空期内旧节点保持 bypass，开启 20 秒排空定时器（锁绝不盖住这 20 秒！）；
	// 新请求立刻走向新 Session。
	if e.sessionMgr != nil {
		e.sessionMgr.Drain(20 * time.Second)
	}
	if e.sessionPool != nil {
		if sp, ok := e.sessionPool.(*SessionPool); ok && sp != nil {
			sp.DrainGraceful(20 * time.Second)
		} else {
			e.sessionPool.Reset()
		}
	}

	if e.mode == "tun" && e.running.Load() && oldIP != nil && (newIP == nil || !oldIP.Equal(newIP)) {
		// 排空结束后重新规划：旧节点不在订阅中时其 bypass 随之移除
		time.AfterFunc(20*time.Second, func() { e.refreshTunRoutes() })
	}

	log.Printf("[ENGINE] active node switched to %s (sni=%s)", addr, sni)
	return nil
}

// Start 启动客户端数据面（给测试及外部旧调用兼容，自动申请票据）
func (e *Engine) Start() error {
	ticket := e.RequestStart()
	return e.StartWith(ticket)
}

// StartWith 使用指定票据在 lifecycleMu 锁保护下启动引擎
func (e *Engine) StartWith(ticket uint64) error {
	tWait := time.Now()
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	if w := time.Since(tWait); w >= 100*time.Millisecond {
		log.Printf("[START] waited %v for the lifecycle lock (another start/stop was in progress)", w.Round(time.Millisecond))
	}
	return e.startLocked(ticket)
}

func (e *Engine) startLocked(ticket uint64) error {
	var nm NetworkMonitor
	var ip net.IP

	e.mu.Lock()
	if e.closed.Load() {
		e.mu.Unlock()
		return ErrEngineClosed
	}
	if ticket == 0 || e.startEpoch != ticket || !e.startPending.Load() {
		e.mu.Unlock()
		return ErrStartAborted
	}
	if e.state.Load() == stateRunning {
		e.startPending.Store(false)
		e.mu.Unlock()
		return nil
	}
	if e.state.Load() != stateStopped {
		e.mu.Unlock()
		return fmt.Errorf("engine is not in stopped state (current: %d)", e.state.Load())
	}
	if e.pendingMode != "" {
		e.mode = e.pendingMode
	}
	e.state.Store(stateStarting)

	e.lastErrMu.Lock()
	e.lastErr = ""
	e.lastErrCode = ""
	e.lastErrConflictVPN = ""
	e.lastErrMu.Unlock()

	startCtx, startCancel := context.WithCancel(context.Background())
	e.startCancel = startCancel
	tr := newStartTrace(e.mode)
	e.startTr.Store(tr)
	e.mu.Unlock()

	rollbackLocked := func(ticket uint64, startCancel context.CancelFunc, err error) error {
		if startCancel != nil {
			startCancel()
		}
		if e.sessionMgr != nil {
			e.sessionMgr.Reset()
		}
		e.mu.Lock()
		e.startCancel = nil
		if e.startEpoch == ticket {
			e.startPending.Store(false)
		}
		e.mu.Unlock()
		e.state.Store(stateStopped)
		e.running.Store(false)

		e.lastErrMu.Lock()
		if err != nil {
			e.lastErr = err.Error()
			var conflictErr *ErrConflictingTUN
			if errors.As(err, &conflictErr) {
				e.lastErrCode = "CONFLICT_TUN"
				e.lastErrConflictVPN = conflictErr.VPNName
			} else if errors.Is(err, ErrUDPUnavailable) || strings.Contains(err.Error(), "UDP_UNAVAILABLE") {
				e.lastErrCode = "UDP_UNAVAILABLE"
			} else {
				e.lastErrCode = "CONNECT_ERROR"
			}
		} else {
			e.lastErr = ""
			e.lastErrCode = ""
			e.lastErrConflictVPN = ""
		}
		e.lastErrMu.Unlock()

		return err
	}

	// 只有停止流程（Stop/Restart/BeginStop/PrepareModeSwitch/Close）发起的取消才走 abort：
	// 它们要么已把状态置为 stopping，要么取消了本次的 startCtx，并由停止流程负责收尾状态。
	// 底层库自行返回的 context.Canceled 不属于此类，按普通失败回滚到 stopped 并清 startPending。
	failStart := func(err error) error {
		if e.state.Load() == stateStopping || startCtx.Err() != nil {
			tr.fail(err, true)
			return e.abortStartLocked(startCancel, nm)
		}
		tr.fail(err, false)
		return rollbackLocked(ticket, startCancel, err)
	}
	e.degraded.Store(false)
	e.degradedReason.Store(nil)

	e.mu.RLock()
	activeAddr := e.activeAddr
	activeToken := e.activeToken
	activeSNI := e.activeSNI
	mode := e.mode
	e.mu.RUnlock()

	// 只有明确的 "tun" 才会修改宿主网络；其他未知值拒绝启动（fail-closed）。
	if mode != "tun" && mode != "sysproxy" {
		return failStart(fmt.Errorf("unsupported mode %q (use tun or sysproxy)", mode))
	}
	// 本地模式（sysproxy）不碰宿主；TUN 模式先检测第三方 TUN 冲突（只读）。
	// 自有网卡的全部状态随网卡销毁而消失，无需清理上次残留（ADR-0013）。
	if mode != "sysproxy" {
		tr.enter("detect-tun")
		conflict, vpnName, err := detectThirdPartyTUN()
		if err != nil {
			return failStart(fmt.Errorf("detect third-party tun: %w", err))
		}
		if conflict {
			// 命中冲突：绝不创建 aero0，绝不调用 TeardownRoutes，绝不写 /32，绝不写两条 /1，running 保持 false
			return failStart(&ErrConflictingTUN{VPNName: vpnName})
		}
		invalidateGatewayCache()
	}

	if activeAddr == "" {
		return failStart(fmt.Errorf("no active node configured"))
	}

	host, portStr, err := net.SplitHostPort(activeAddr)
	if err != nil {
		host = activeAddr
		portStr = "443"
	}
	port := 443
	if p, perr := strconv.Atoi(portStr); perr == nil && p > 0 {
		port = p
	}

	tr.enter("resolve")
	var nodeIP net.IP
	if curAddr, _, _, curIP := getActiveEdge(); curAddr == activeAddr && curIP != nil {
		nodeIP = curIP
	}
	if nodeIP == nil && e.appliedSub != nil && e.appliedSub.IPs != nil {
		if ipStr, ok := e.appliedSub.IPs[activeAddr]; ok && ipStr != "" {
			if parsed := net.ParseIP(ipStr); parsed != nil {
				nodeIP = parsed.To4()
			}
		}
		if nodeIP == nil {
			for a, ipStr := range e.appliedSub.IPs {
				if h, _, _ := net.SplitHostPort(a); h == host && ipStr != "" {
					if parsed := net.ParseIP(ipStr); parsed != nil {
						nodeIP = parsed.To4()
						break
					}
				}
			}
		}
	}
	if nodeIP == nil {
		var rerr error
		nodeIP, rerr = resolvePhysicalIPv4(host)
		if rerr != nil {
			return failStart(fmt.Errorf("resolve active node %s: %w", host, rerr))
		}
	}
	ip = nodeIP

	var ech []byte
	if e.appliedSub != nil && e.appliedSub.ECHConfigs != nil {
		if c, ok := e.appliedSub.ECHConfigs[activeAddr]; ok && len(c) > 0 {
			ech = c
		}
	}
	var altPorts []int
	if e.appliedSub != nil && e.appliedSub.AltPorts != nil {
		if ap, ok := e.appliedSub.AltPorts[activeAddr]; ok && len(ap) > 0 {
			altPorts = ap
		}
	}
	SetActiveEdgeAltPorts(altPorts)

	var activePins []string
	if e.appliedSub != nil {
		for _, s := range e.appliedSub.Servers {
			if s.Address == activeAddr {
				activePins = s.PinSPKI
				break
			}
		}
	}
	SetActiveEdgePinSPKI(activePins)

	if len(ech) > 0 {
		SetActiveEdge(activeAddr, activeToken, activeSNI, ip, ech)
	} else {
		SetActiveEdge(activeAddr, activeToken, activeSNI, ip)
	}
	if e.dnsHandler != nil {
		e.dnsHandler.SetEdge(host, ip)
		e.dnsHandler.Flush()
	}

	select {
	case <-startCtx.Done():
		return failStart(startCtx.Err())
	default:
	}

	probeCtx, probeCancel := context.WithTimeout(startCtx, 8*time.Second)
	defer probeCancel()

	cfg := DefaultTransportConfig(activeAddr, activeSNI)
	if len(ech) > 0 {
		cfg.ECHConfigList = ech
	}
	if len(altPorts) > 0 {
		cfg.AltPorts = altPorts
	}
	cfg.RemoteUDPAddr = &net.UDPAddr{IP: ip, Port: port}
	cfg.ConnectTimeout = 8 * time.Second
	e.mu.RLock()
	cfg.PacketConnFactory = e.packetConnFactory
	e.mu.RUnlock()

	tr.enter("quic-dial")
	start := time.Now()
	cl, err := Dial(probeCtx, cfg)
	if err != nil {
		if mode == "tun" {
			// 模式是 tun 而 UDP/443 (QUIC/HTTP/3) 拨号失败时：
			// 不调用 OpenTunDevice，不装 /1 路由，55555 照常监听，向 UI 返回固定错误码 UDP_UNAVAILABLE。
			// 严禁将整机流量降级走 TCP 再宣称全局隧道仍在。
			_ = e.startMixedProxy()
			return failStart(fmt.Errorf("%w: connect to %s failed: %v", ErrUDPUnavailable, activeAddr, err))
		}
		return failStart(fmt.Errorf("connect to %s failed: %w", activeAddr, err))
	}
	actualPort := cl.ActualPort()
	rtt := time.Since(start)
	tr.note("port=%d", actualPort)
	tr.note("cc=%s", congestionControl()) // 本端上行用的拥塞控制（ADR-0019）
	tr.enter("connect-ip")

	// 多端口跳频动态对齐 (Port Hopping Alignment Contract)
	if actualPort > 0 && actualPort != port {
		log.Printf("[ENGINE] Multi-port hopping aligned: probe primary port %d hopped to alt port %d", port, actualPort)
		alignedAddr := net.JoinHostPort(host, strconv.Itoa(actualPort))
		e.mu.Lock()
		if e.appliedSub != nil {
			if e.appliedSub.IPs != nil {
				e.appliedSub.IPs[alignedAddr] = ip.String()
			}
			if e.appliedSub.Tokens != nil {
				e.appliedSub.Tokens[alignedAddr] = activeToken
			}
			if e.appliedSub.SNIs != nil {
				e.appliedSub.SNIs[alignedAddr] = activeSNI
			}
			if e.appliedSub.ECHConfigs != nil && len(ech) > 0 {
				e.appliedSub.ECHConfigs[alignedAddr] = ech
			}
			if e.appliedSub.AltPorts != nil && len(altPorts) > 0 {
				e.appliedSub.AltPorts[alignedAddr] = altPorts
			}
			for i := range e.appliedSub.Servers {
				if e.appliedSub.Servers[i].Address == activeAddr {
					e.appliedSub.Servers[i].Address = alignedAddr
					break
				}
			}
		}
		_ = e.switchActiveNodeLocked(alignedAddr, activeToken, activeSNI)
		e.mu.Unlock()

		if len(ech) > 0 {
			SetActiveEdge(alignedAddr, activeToken, activeSNI, ip, ech)
		} else {
			SetActiveEdge(alignedAddr, activeToken, activeSNI, ip)
		}
		activeAddr = alignedAddr
		port = actualPort
	}

	// 启动会话单例复用：将已握手的 cl 直接包装为 Session 并注入 sessionMgr，消除二次建连延迟
	if e.sessionMgr != nil {
		if newSess, sessErr := NewSession(cl, activeToken, activeAddr, activeSNI); sessErr == nil {
			e.sessionMgr.SetSession(newSess)
		} else {
			_ = cl.Close()
		}
	} else {
		_ = cl.Close()
	}

	select {
	case <-startCtx.Done():
		return failStart(startCtx.Err())
	default:
	}

	e.mu.Lock()
	if e.sentinel == nil {
		e.sentinel = newNodeSentinel(e)
	}
	e.sentinel.lastRTT.Store(rtt.Nanoseconds())
	sentinel := e.sentinel
	if e.netMon == nil {
		e.netMon = NewNetworkMonitor()
	}
	nm = e.netMon
	e.mu.Unlock()

	e.rootMu.Lock()
	e.rootCtx, e.rootCancel = context.WithCancel(context.Background())
	e.rootMu.Unlock()
	// 本次启动的取消域：后面的协程必须用这个局部变量，不能在协程里再读 e.rootCtx——
	// Stop 之后紧接着再 Start 会重写该字段，协程会读到下一轮的上下文（数据竞争，也让上一轮的哨兵停不下来）。
	rootCtx := e.rootCtx
	if e.dnsHandler != nil {
		SetGlobalMobileDNSHandler(e.dnsHandler)
	}

	// 本地代理数据面：只启动哨兵、网络监控与本地混合代理，不碰宿主网络。
	// 命令行/无头的 sysproxy 模式走这里；TUN 虚拟网卡不可用时降级也走这里。
	runLocalProxyPlane := func(desc string) error {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[SENTINEL] panic recovered: %v", r)
				}
			}()
			sentinel.run(rootCtx)
		}()
		nm.Start(func(newGW, ifName string) {
			e.onNetworkChange(newGW, ifName)
		})
		_ = e.startMixedProxy()

		e.mu.Lock()
		if e.startEpoch != ticket || !e.startPending.Load() || e.state.Load() != stateStarting {
			e.mu.Unlock()
			tr.fail(errors.New("stop requested while finishing start"), true)
			return e.abortStartLocked(startCancel, nm)
		}
		e.state.Store(stateRunning)
		e.running.Store(true)
		e.startPending.Store(false)
		e.startCancel = nil
		e.mu.Unlock()
		tr.finish()
		log.Printf("[ENGINE] data plane started in %s (mixed proxy %s)", desc, e.listenAddr)
		return nil
	}

	if mode == "sysproxy" {
		return runLocalProxyPlane("local sysproxy mode")
	}

	// 先建立 CONNECT-IP 取得地址，再创建自有网卡：网卡、地址、路由、DNS 防护一次就绪（ADR-0013）。
	if err := e.bringUpTunLocked(startCtx, nodeIP); err != nil {
		// 虚拟网卡本身不可用（不是拨号/网络失败、也不是第三方 TUN 冲突）：隧道已能连上，
		// 降级为“仅本地代理”，并在状态里明确标出，而不是让用户面对一个完全不能用的“连接失败”。
		if errors.Is(err, ErrTunUnavailable) && startCtx.Err() == nil {
			reason := err.Error()
			e.degraded.Store(true)
			e.degradedReason.Store(&reason)
			log.Printf("[ENGINE] TUN unavailable, degrading to local proxy only: %v", err)
			return runLocalProxyPlane("degraded local proxy mode (TUN unavailable)")
		}
		if e.rootCancel != nil {
			e.rootCancel()
		}
		return failStart(err)
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[SENTINEL] panic recovered: %v", r)
			}
		}()
		sentinel.run(rootCtx)
	}()

	nm.Start(func(newGW, ifName string) {
		e.onNetworkChange(newGW, ifName)
	})

	_ = e.startMixedProxy()

	e.mu.Lock()
	if e.startEpoch != ticket || !e.startPending.Load() || e.state.Load() != stateStarting {
		e.mu.Unlock()
		tr.fail(errors.New("stop requested while finishing start"), true)
		return e.abortStartLocked(startCancel, nm)
	}
	e.state.Store(stateRunning)
	e.running.Store(true)
	e.startPending.Store(false)
	e.startCancel = nil
	e.mu.Unlock()
	log.Printf("[ENGINE] data plane started successfully (TUN aero0, mixed proxy %s)", e.listenAddr)
	return nil
}

// abortStartLocked 清理本次启动申请的临时资源，不置空全局基础设施，不修改状态
func (e *Engine) abortStartLocked(startCancel context.CancelFunc, nm NetworkMonitor) error {
	if startCancel != nil {
		startCancel()
	}
	if e.sessionMgr != nil {
		e.sessionMgr.Reset()
	}
	e.mu.Lock()
	e.startCancel = nil
	e.mu.Unlock()

	e.releaseTunLocked()
	if e.rootCancel != nil {
		e.rootCancel()
		e.rootCancel = nil
	}
	if nm != nil {
		nm.Stop()
	}
	return ErrStartAborted
}

// onNetworkChange 响应底层物理网络切换事件
// 规则：按新网络的系统 DNS 重新规划 TUN 路由、清理存量悬挂连接、重置会话池、更新物理解析、异步预热 QUIC
func (e *Engine) onNetworkChange(newGW, ifName string) {
	invalidateGatewayCache()
	log.Printf("[ENGINE] onNetworkChange triggered: newGW=%s, ifName=%s", newGW, ifName)

	e.mu.RLock()
	activeAddr := e.activeAddr
	activeSNI := e.activeSNI
	sentinel := e.sentinel
	stackEng := e.stackEngine
	mode := e.mode
	e.mu.RUnlock()

	if stackEng != nil {
		stackEng.SetWebRTCActive(false)
	}
	SetGlobalMobileWebRTCActive(false)

	if sentinel != nil {
		sentinel.wakeup()
	}

	_, _, _, ip := getActiveEdge()

	// 1. 新网络的 DNS 服务器不同：重新规划 TUN 路由（仅 TUN 模式；sysproxy 不碰宿主）
	if mode == "tun" && e.running.Load() {
		e.refreshTunRoutes(ip)
	}

	// 2. 斩断前一网络留存的悬挂连接
	e.closeActiveConns()

	// 3. 重置 QUIC 会话池与会话管理器
	e.sessionPool.Reset()
	if e.sessionMgr != nil {
		e.sessionMgr.Reset()
	}

	// 4. 更新物理 DNS (固定设为 223.5.5.5:53)
	if e.dnsHandler != nil {
		e.dnsHandler.SetPhysicalDNS("223.5.5.5:53")
		e.dnsHandler.Flush()
	}

	// 5. 异步预热新网络接口上的 QUIC 拨号
	go func() {
		if activeAddr == "" {
			return
		}
		cfg := DefaultTransportConfig(activeAddr, activeSNI)
		if ip != nil {
			port := 443
			if _, portStr, err := net.SplitHostPort(activeAddr); err == nil {
				if p, perr := strconv.Atoi(portStr); perr == nil && p > 0 {
					port = p
				}
			}
			cfg.RemoteUDPAddr = &net.UDPAddr{IP: ip, Port: port}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := e.sessionPool.Get(ctx, cfg); err == nil {
			if stackEng != nil && e.running.Load() {
				stackEng.SetWebRTCActive(true)
				SetGlobalMobileWebRTCActive(true)
			}
		}
	}()
}

func (e *Engine) closeActiveConns() {
	e.activeConns.Range(func(key, value any) bool {
		if c, ok := key.(io.Closer); ok {
			_ = c.Close()
		}
		e.activeConns.Delete(key)
		return true
	})
}

func (e *Engine) getContext() context.Context {
	e.rootMu.RLock()
	root := e.rootCtx
	e.rootMu.RUnlock()
	if root != nil && root.Err() == nil {
		return root
	}
	if e.daemonCtx != nil && e.daemonCtx.Err() == nil {
		return e.daemonCtx
	}
	return context.Background()
}

// Close 优雅释放引擎全局资源与常驻代理端口 (进程退出时调用)
// 幂等；Close 之后一切建立数据面的入口返回 ErrEngineClosed。
// 锁顺序：先在 e.mu 下置位 closed、作废票据并取消在途启动（不持 lifecycleMu，与 BeginStop 一致），
// 再走 Stop（取消后获取 lifecycleMu，等在途 StartWith 退出后清理），最后在 e.mu 下关闭常驻监听。
func (e *Engine) Close() error {
	e.mu.Lock()
	e.closed.Store(true)
	e.startEpoch++
	e.startPending.Store(false)
	e.pendingMode = ""
	if e.startCancel != nil {
		e.startCancel()
	}
	e.mu.Unlock()

	_ = e.Stop()
	if e.daemonCancel != nil {
		e.daemonCancel()
	}
	e.mu.Lock()
	if e.mixedListener != nil {
		_ = e.mixedListener.Close()
		e.mixedListener = nil
	}
	e.mixedStarting = false
	e.mu.Unlock()
	e.residentConns.Range(func(key, value any) bool {
		if c, ok := key.(net.Conn); ok {
			_ = c.Close()
		}
		e.residentConns.Delete(key)
		return true
	})
	return nil
}

// Stop 停止客户端数据面
func (e *Engine) Stop() error {
	invalidateGatewayCache()

	// 快速取消正在进行的 Start()
	e.mu.Lock()
	cancel := e.startCancel
	e.mu.Unlock()
	if cancel != nil {
		cancel()
	}

	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	return e.stopLocked()
}

func (e *Engine) stopLocked() error {
	if e.state.Load() == stateStopped && !e.running.Load() {
		e.lastErrMu.Lock()
		e.lastErr = ""
		e.lastErrCode = ""
		e.lastErrConflictVPN = ""
		e.lastErrMu.Unlock()
		return nil
	}
	e.state.Store(stateStopping)
	e.running.Store(false)
	e.lastErrMu.Lock()
	e.lastErr = ""
	e.lastErrCode = ""
	e.lastErrConflictVPN = ""
	e.lastErrMu.Unlock()

	if e.rootCancel != nil {
		e.rootCancel()
	}

	e.mu.Lock()
	nm := e.netMon
	e.mu.Unlock()
	if nm != nil {
		nm.Stop()
	}

	e.closeActiveConns()

	e.releaseTunLocked()

	if e.tunnelClient != nil {
		e.tunnelClient.Close()
	}

	e.sessionPool.Reset()
	if e.sessionMgr != nil {
		e.sessionMgr.Reset()
	}
	invalidateGatewayCache()

	e.mu.Lock()
	e.state.Store(stateStopped)
	e.running.Store(false)
	e.degraded.Store(false)
	e.degradedReason.Store(nil)
	e.mu.Unlock()

	log.Printf("[ENGINE] data plane stopped")
	return nil
}

// Restart 在同一把 lifecycleMu 锁内依次执行停止与使用特定票据重新启动
func (e *Engine) Restart(ticket uint64) error {
	if e.closed.Load() {
		return ErrEngineClosed
	}
	invalidateGatewayCache()

	e.mu.Lock()
	cancel := e.startCancel
	e.mu.Unlock()
	if cancel != nil {
		cancel()
	}

	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	if err := e.stopLocked(); err != nil {
		return err
	}
	return e.startLocked(ticket)
}

// GetState 获取运行状态快照
func (e *Engine) GetState() AppState {
	e.mu.RLock()
	defer e.mu.RUnlock()

	nodesCount := 0
	if e.appliedSub != nil {
		nodesCount = len(e.appliedSub.Servers)
	}

	var rttMs int64
	var probeOk bool
	if e.sentinel != nil {
		d := e.sentinel.LastRTT()
		if d > 0 {
			rttMs = d.Milliseconds()
			probeOk = true
		}
	}

	geoCount := 0
	if e.splitEngine != nil {
		geoCount = e.splitEngine.TotalRules()
	}

	geoUpdated, geoErr := e.geoStatus()

	// 降级时对外报告实际运行的模式（sysproxy），界面据此显示“仅本地代理”
	mode := e.mode
	degraded := e.degraded.Load()
	degradedReason := ""
	if p := e.degradedReason.Load(); p != nil {
		degradedReason = *p
	}
	if degraded {
		mode = "sysproxy"
	}

	subURL := e.savedSubURL
	isp := e.currentISP
	if isp == "" {
		isp = "DEFAULT"
	}
	actualPort := 0
	if _, pStr, err := net.SplitHostPort(e.activeAddr); err == nil {
		if pNum, err := strconv.Atoi(pStr); err == nil {
			actualPort = pNum
		}
	}

	e.lastErrMu.RLock()
	lastErr := e.lastErr
	lastCode := e.lastErrCode
	conflictVPN := e.lastErrConflictVPN
	e.lastErrMu.RUnlock()

	aiState, aiReasonText := e.ai.snapshot()
	return AppState{
		Connected:    e.state.Load() == stateRunning,
		Starting:     e.state.Load() == stateStarting || e.startPending.Load(),
		Stopping:     e.state.Load() == stateStopping,
		LastError:    lastErr,
		ErrorCode:    lastCode,
		ConflictVPN:  conflictVPN,
		Mode:         mode,
		Listen:       e.listenAddr,
		ActiveNode:   e.activeAddr,
		ActiveSNI:    e.activeSNI,
		ActualPort:   actualPort,
		SubURL:       subURL,
		NodesCount:   nodesCount,
		Version:      ClientVersion,
		Node:         e.activeAddr,
		SNI:          e.activeSNI,
		ISP:          isp,
		ISPName:      ispToName(isp),
		RttMs:        rttMs,
		ProbeOk:      probeOk,
		ProbeMs:      rttMs,
		GeoRuleCount: geoCount,
		GeoUpdatedAt: geoUpdated,
		GeoError:     geoErr,

		ResidentListening: e.mixedListener != nil,
		Degraded:          degraded,
		DegradedReason:    degradedReason,

		AIChannel:        aiState,
		AIChannelReason:  aiReasonText,
		AIChannelEnabled: e.ai.enabled.Load(),
	}
}

func ispToName(isp string) string {
	switch strings.ToUpper(isp) {
	case "CT":
		return "中国电信"
	case "CU":
		return "中国联通"
	case "CM":
		return "中国移动"
	default:
		return "默认"
	}
}

// PingActiveNode 向当前活跃节点发送 HTTP/3 GET /healthz 探活请求，度量往返 RTT 并更新 sentinel.lastRTT
func (e *Engine) PingActiveNode(ctx context.Context) (time.Duration, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
	}

	if e.sessionMgr != nil {
		rtt, err := e.sessionMgr.Ping(ctx)
		if err == nil {
			e.mu.RLock()
			sentinel := e.sentinel
			e.mu.RUnlock()
			if sentinel != nil {
				sentinel.lastRTT.Store(rtt.Nanoseconds())
			}
			return rtt, nil
		}
	}

	return 0, fmt.Errorf("ping active node failed: no response")
}

// SetGeoDataURL 设置分流地理数据同步源 URL (用于测试与自定义配置)
func (e *Engine) SetGeoDataURL(u string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.geoDataURL = u
}

// geoDataMaxBytes 是 geodata 同步响应体的大小上限（16 MiB）
const geoDataMaxBytes = 16 << 20

// mixedHandshakeTimeoutDefault 是混合代理握手阶段的读超时
const mixedHandshakeTimeoutDefault = 10 * time.Second

// SetMode 设置工作模式
// NormalizeMode 把用户输入的模式规范为 "tun" 或 "sysproxy"（"socks"、"proxy" 为 sysproxy 的别名）。
// 未知模式报错：不得因拼写错误默认进入会修改宿主网络的 TUN 模式。
func NormalizeMode(m string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(m)) {
	case "tun":
		return "tun", nil
	case "sysproxy", "socks", "proxy":
		return "sysproxy", nil
	}
	return "", fmt.Errorf("unsupported mode %q (use tun or sysproxy)", m)
}

func (e *Engine) SetMode(m string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.mode = m
}

// GetMode 获取当前工作模式
func (e *Engine) GetMode() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mode
}

// SetListenAddr 设置本地混合代理监听地址
func (e *Engine) SetListenAddr(addr string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.listenAddr = addr
}

type residentConnContextKey struct{}

// DialTCP 导出供外部使用的 TCP 拨号接口，并注册至活跃连接池
func (e *Engine) DialTCP(ctx context.Context, target string) (net.Conn, error) {
	isResident := ctx.Value(residentConnContextKey{}) != nil
	storeConn := func(c net.Conn) {
		if isResident {
			e.residentConns.Store(c, struct{}{})
		} else {
			e.activeConns.Store(c, struct{}{})
		}
	}
	deleteConn := func(c net.Conn) {
		if isResident {
			e.residentConns.Delete(c)
		} else {
			e.activeConns.Delete(c)
		}
	}

	e.mu.RLock()
	dialer := e.tcpDialer
	split := e.splitEngine
	dnsH := e.dnsHandler
	e.mu.RUnlock()
	if dialer != nil {
		conn, err := dialer(ctx, target)
		if err != nil {
			return nil, err
		}
		storeConn(conn)
		return &trackedConn{
			Conn: conn,
			onClose: func() {
				deleteConn(conn)
			},
		}, nil
	}

	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}
	var ip net.IP
	if dnsH != nil && dnsH.FakeIP() != nil {
		if parsedIP := net.ParseIP(host); parsedIP != nil && dnsH.FakeIP().Contains(parsedIP) {
			if domain, _ := dnsH.FakeIP().Acquire(parsedIP); domain != "" {
				host = domain
			}
		}
	}
	ip = net.ParseIP(host)

	if split != nil && split.Match(host, ip) == DIRECT {
		conn, err := DialPhysicalDirect(ctx, "tcp", target)
		if err != nil {
			return nil, err
		}
		storeConn(conn)
		return &trackedConn{
			Conn: conn,
			onClose: func() {
				deleteConn(conn)
			},
		}, nil
	}

	var conn net.Conn
	if e.sessionMgr != nil {
		conn, err = e.sessionMgr.DialTCP(ctx, target)
	} else if e.tunnelClient != nil {
		conn, err = e.tunnelClient.DialTCP(ctx, target)
	} else {
		return nil, fmt.Errorf("no dialer available")
	}
	if err != nil {
		return nil, err
	}
	storeConn(conn)
	return &trackedConn{
		Conn: conn,
		onClose: func() {
			deleteConn(conn)
		},
	}, nil
}

// DialUDP 导出供外部使用的 UDP 拨号接口 (MASQUE CONNECT-UDP / 本地物理直连)
func (e *Engine) DialUDP(ctx context.Context, target string) (net.Conn, error) {
	e.mu.RLock()
	split := e.splitEngine
	dnsH := e.dnsHandler
	e.mu.RUnlock()

	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}
	var ip net.IP
	if dnsH != nil && dnsH.FakeIP() != nil {
		if parsedIP := net.ParseIP(host); parsedIP != nil && dnsH.FakeIP().Contains(parsedIP) {
			if domain, _ := dnsH.FakeIP().Acquire(parsedIP); domain != "" {
				host = domain
			}
		}
	}
	ip = net.ParseIP(host)

	// 分流匹配：如果目标属于 DIRECT，直接走物理网卡 DialPhysicalDirect
	if split != nil && split.Match(host, ip) == DIRECT {
		return DialPhysicalDirect(ctx, "udp", target)
	}

	if e.sessionMgr != nil {
		return e.sessionMgr.DialUDP(ctx, target)
	}
	return nil, fmt.Errorf("no session manager available")
}

type trackedConn struct {
	net.Conn
	onClose func()
	once    sync.Once
}

func (c *trackedConn) Close() error {
	c.once.Do(c.onClose)
	return c.Conn.Close()
}

// 常驻混合代理的默认地址与备用端口。Windows 会把一批端口划为“排除段”（Hyper-V、WSL、Docker 等占用，
// 重启后还会变），或被其他软件独占，绑定默认端口会报“访问权限不允许”。换一台机器、换一个网络环境，
// 可用端口都不同，所以回退顺序是：上次成功的备用端口（保持稳定）→ 固定备用端口 → 最后让系统分配一个，
// 保证常驻代理总能起来。真实地址写回 listenAddr，状态接口与界面据此显示。
// 固定备用端口选在 8000–11000 之间，避开常见软件占用的端口（8080、8888、9090、9050、10808/10809 等）。
// 只有使用默认地址时才回退；用户显式指定的地址失败就如实报错。
const (
	defaultMixedListen = "127.0.0.1:55555"
	residentPortFile   = "resident_port" // 记住上次成功的备用端口，让浏览器里填的端口尽量保持不变
)

var mixedFallbackPorts = []string{"8731", "9457", "10231"}

// residentFallbackAddrs 返回回退时依次尝试的地址（去重）。
func residentFallbackAddrs() []string {
	var out []string
	seen := map[string]bool{defaultMixedListen: true}
	add := func(a string) {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	if b, err := os.ReadFile(filepath.Join(GetDataDir(), residentPortFile)); err == nil {
		if p, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && p >= 1024 && p <= 65535 {
			add(net.JoinHostPort("127.0.0.1", strconv.Itoa(p)))
		}
	}
	for _, p := range mixedFallbackPorts {
		add(net.JoinHostPort("127.0.0.1", p))
	}
	add("127.0.0.1:0") // 最后一招：交给系统分配
	return out
}

// rememberResidentPort 记录成功回退到的端口；失败不影响运行。
func rememberResidentPort(addr net.Addr) {
	if ta, ok := addr.(*net.TCPAddr); ok {
		_ = os.WriteFile(filepath.Join(GetDataDir(), residentPortFile), []byte(strconv.Itoa(ta.Port)), 0o600)
	}
}

// StartResidentMixedProxy 启动 SOCKS5 + HTTP CONNECT 混合端口常驻守护监听 (Daemon 模式)
func (e *Engine) StartResidentMixedProxy(addr ...string) error {
	// 常驻混合代理只允许绑定回环地址；在写入 listenAddr 与 Listen 之前拒绝
	if len(addr) > 0 && addr[0] != "" {
		if err := requireLoopbackListenAddr(addr[0]); err != nil {
			return err
		}
	}
	e.mu.Lock()
	if len(addr) > 0 && addr[0] != "" {
		e.listenAddr = addr[0]
	}
	if e.closed.Load() {
		e.mu.Unlock()
		return ErrEngineClosed
	}
	targetAddr := e.listenAddr
	if targetAddr == "" {
		targetAddr = "127.0.0.1:55555"
	}
	if e.mixedListener != nil || e.mixedStarting {
		e.mu.Unlock()
		return nil
	}
	e.mixedStarting = true
	e.mu.Unlock()

	if err := requireLoopbackListenAddr(targetAddr); err != nil {
		e.mu.Lock()
		e.mixedStarting = false
		e.mu.Unlock()
		log.Printf("[PROXY] resident mixed proxy refused to listen: %v", err)
		return err
	}

	ln, err := net.Listen("tcp", targetAddr)
	moved := false
	if err != nil && targetAddr == defaultMixedListen {
		firstErr := err
		for _, alt := range residentFallbackAddrs() {
			if l2, e2 := net.Listen("tcp", alt); e2 == nil {
				log.Printf("[PROXY] %s unavailable (%v); resident mixed proxy moved to %s", targetAddr, firstErr, l2.Addr())
				ln, err, targetAddr, moved = l2, nil, l2.Addr().String(), true
				rememberResidentPort(l2.Addr())
				break
			}
		}
	}
	if err != nil {
		e.mu.Lock()
		e.mixedStarting = false
		e.mu.Unlock()
		log.Printf("[PROXY] resident mixed proxy listen on %s failed: %v", targetAddr, err)
		return err
	}

	e.mu.Lock()
	if e.closed.Load() {
		e.mixedStarting = false
		e.mu.Unlock()
		_ = ln.Close()
		return ErrEngineClosed
	}
	if e.mixedListener != nil {
		e.mixedStarting = false
		e.mu.Unlock()
		_ = ln.Close()
		return nil
	}
	e.mixedListener = ln
	e.mixedStarting = false
	if moved || strings.HasSuffix(targetAddr, ":0") {
		e.listenAddr = ln.Addr().String()
	}
	actualAddr := e.listenAddr
	e.mu.Unlock()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// NEW-08: 本地绑定加固，非回环地址一律拒绝
			rHost, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			if rHost != "127.0.0.1" && rHost != "::1" && !strings.HasPrefix(rHost, "127.") {
				_ = conn.Close()
				continue
			}

			e.residentConns.Store(conn, struct{}{})
			go func(c net.Conn) {
				defer func() {
					_ = c.Close()
					e.residentConns.Delete(c)
				}()
				e.serveMixedConn(c)
			}(conn)
		}
	}()
	log.Printf("[PROXY] resident mixed proxy listening on %s (permanent daemon)", actualAddr)
	return nil
}

// startMixedProxy 启动 SOCKS5 + HTTP CONNECT 混合端口监听 (兼容旧接口)
func (e *Engine) startMixedProxy() error {
	return e.StartResidentMixedProxy()
}

// requireLoopbackListenAddr 校验监听地址的主机部分是回环地址（127.0.0.0/8、::1、localhost）。
// 空主机（如 ":8080"）与通配地址（0.0.0.0、::）都会监听全部网卡，一律拒绝。
func requireLoopbackListenAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid mixed proxy listen address %q: %w", addr, err)
	}
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "localhost" {
		return nil
	}
	if ip := net.ParseIP(strings.Trim(h, "[]")); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("mixed proxy listen address %q is not loopback: refusing to bind", addr)
}

// handshakeTimeout 返回混合代理握手阶段的读超时（测试可通过字段注入更短的值）。
func (e *Engine) handshakeTimeout() time.Duration {
	if e.mixedHandshakeTimeout > 0 {
		return e.mixedHandshakeTimeout
	}
	return mixedHandshakeTimeoutDefault
}

func (e *Engine) serveMixedConn(conn net.Conn) {
	// 握手阶段（首字节与请求头）设读 deadline，防止慢速连接长期占用；握手完成后由各处理函数清除
	_ = conn.SetReadDeadline(time.Now().Add(e.handshakeTimeout()))
	br := bufio.NewReader(conn)
	peek, err := br.Peek(1)
	if err != nil {
		return
	}

	if peek[0] == 0x05 {
		// SOCKS5 握手
		e.handleSocks5(conn, br)
	} else {
		// HTTP CONNECT 代理
		e.handleHTTPConnect(conn, br)
	}
}

func (e *Engine) handleSocks5(conn net.Conn, br *bufio.Reader) {
	// 读取 SOCKS5 问候帧
	header := make([]byte, 2)
	if _, err := io.ReadFull(br, header); err != nil || header[0] != 0x05 {
		return
	}
	nmethods := int(header[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}

	e.mu.RLock()
	authToken := e.socksAuthToken
	e.mu.RUnlock()

	if authToken != "" {
		hasUserPass := false
		for _, m := range methods {
			if m == 0x02 { // USERNAME/PASSWORD 认证
				hasUserPass = true
				break
			}
		}
		if !hasUserPass {
			_, _ = conn.Write([]byte{0x05, 0xFF}) // No acceptable methods
			return
		}
		// 响应选择 0x02 认证
		if _, err := conn.Write([]byte{0x05, 0x02}); err != nil {
			return
		}
		// 读取子协商版本与用户名密码
		ver, err := br.ReadByte()
		if err != nil || ver != 0x01 {
			return
		}
		ulen, err := br.ReadByte()
		if err != nil {
			return
		}
		user := make([]byte, ulen)
		if _, err := io.ReadFull(br, user); err != nil {
			return
		}
		plen, err := br.ReadByte()
		if err != nil {
			return
		}
		pass := make([]byte, plen)
		if _, err := io.ReadFull(br, pass); err != nil {
			return
		}

		// 密码常数时间核对 (NEW-08)
		if subtle.ConstantTimeCompare(pass, []byte(authToken)) != 1 {
			_, _ = conn.Write([]byte{0x01, 0x01}) // 认证失败
			return
		}
		if _, err := conn.Write([]byte{0x01, 0x00}); err != nil { // 认证成功
			return
		}
	} else {
		// 响应无鉴权 (0x05, 0x00)
		if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
			return
		}
	}

	// 读取请求头
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil || req[0] != 0x05 {
		return
	}
	cmd := req[1]
	atyp := req[3]

	host, port, err := readSocks5Target(br, atyp)
	if err != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Time{}) // 握手完成，清除 deadline

	if cmd == 0x03 { // UDP ASSOCIATE
		e.handleSocks5UDPAssociate(conn, host, port)
		return
	}
	if cmd != 0x01 { // 仅支持 CONNECT (0x01) 与 UDP ASSOCIATE (0x03)
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	target := fmt.Sprintf("%s:%d", host, port)

	residentCtx := context.WithValue(e.daemonCtx, residentConnContextKey{}, true)
	ctx, cancel := context.WithTimeout(residentCtx, 10*time.Second)
	remote, err := e.DialTCP(ctx, target)
	cancel()
	if err != nil {
		_, _ = conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()

	// 成功响应
	_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0})

	relayTraffic(conn, remote, residentCtx)
}

func (e *Engine) handleHTTPConnect(conn net.Conn, br *bufio.Reader) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Time{}) // 请求头已读完，清除 deadline
	if req.Method != http.MethodConnect {
		return
	}

	target := req.RequestURI
	residentCtx := context.WithValue(e.daemonCtx, residentConnContextKey{}, true)
	ctx, cancel := context.WithTimeout(residentCtx, 10*time.Second)
	remote, err := e.DialTCP(ctx, target)
	cancel()
	if err != nil {
		_, _ = conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer remote.Close()

	_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	relayTraffic(conn, remote, residentCtx)
}

func readSocks5Target(br *bufio.Reader, atyp byte) (string, uint16, error) {
	var host string
	switch atyp {
	case 0x01: // IPv4
		var ip [4]byte
		if _, err := io.ReadFull(br, ip[:]); err != nil {
			return "", 0, err
		}
		host = net.IP(ip[:]).String()
	case 0x03: // Domain
		l, err := br.ReadByte()
		if err != nil {
			return "", 0, err
		}
		domainBuf := make([]byte, l)
		if _, err := io.ReadFull(br, domainBuf); err != nil {
			return "", 0, err
		}
		host = string(domainBuf)
	case 0x04: // IPv6
		var ip [16]byte
		if _, err := io.ReadFull(br, ip[:]); err != nil {
			return "", 0, err
		}
		host = net.IP(ip[:]).String()
	default:
		return "", 0, fmt.Errorf("unsupported atyp: %d", atyp)
	}

	var portBuf [2]byte
	if _, err := io.ReadFull(br, portBuf[:]); err != nil {
		return "", 0, err
	}
	port := binary.BigEndian.Uint16(portBuf[:])
	return host, port, nil
}

func (e *Engine) handleSocks5UDPAssociate(tcpConn net.Conn, clientHost string, clientPort uint16) {
	localUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		_, _ = tcpConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer localUDP.Close()

	assignedPort := uint16(localUDP.LocalAddr().(*net.UDPAddr).Port)
	resp := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, byte(assignedPort >> 8), byte(assignedPort)}
	if _, err := tcpConn.Write(resp); err != nil {
		return
	}

	done := make(chan struct{})
	go func() {
		buf := make([]byte, 128)
		for {
			if _, err := tcpConn.Read(buf); err != nil {
				break
			}
		}
		close(done)
		_ = localUDP.Close()
	}()

	type udpRelayEntry struct {
		remote net.Conn
		closed atomic.Bool
	}
	var relays sync.Map
	defer func() {
		relays.Range(func(k, v any) bool {
			if r, ok := v.(*udpRelayEntry); ok {
				r.closed.Store(true)
				_ = r.remote.Close()
			}
			return true
		})
	}()

	buf := make([]byte, 65535)
	for {
		n, clientAddr, err := localUDP.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < 4 {
			continue
		}
		if buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
			continue
		}

		atyp := buf[3]
		var targetHost string
		headerLen := 0
		switch atyp {
		case 0x01: // IPv4
			if n < 10 {
				continue
			}
			targetHost = net.IP(buf[4:8]).String()
			headerLen = 8
		case 0x03: // Domain
			if n < 5 {
				continue
			}
			domainLen := int(buf[4])
			if n < 5+domainLen+2 {
				continue
			}
			targetHost = string(buf[5 : 5+domainLen])
			headerLen = 5 + domainLen
		case 0x04: // IPv6
			if n < 22 {
				continue
			}
			targetHost = net.IP(buf[4:20]).String()
			headerLen = 20
		default:
			continue
		}

		targetPort := binary.BigEndian.Uint16(buf[headerLen : headerLen+2])
		headerLen += 2
		payload := buf[headerLen:n]
		target := fmt.Sprintf("%s:%d", targetHost, targetPort)

		hdrCopy := append([]byte(nil), buf[:headerLen]...)
		val, ok := relays.Load(target)
		var entry *udpRelayEntry
		if !ok {
			ctx, cancel := context.WithTimeout(e.getContext(), 5*time.Second)
			remote, err := e.DialUDP(ctx, target)
			cancel()
			if err != nil {
				continue
			}
			entry = &udpRelayEntry{remote: remote}
			relays.Store(target, entry)

			go func(tgt string, hdr []byte, r *udpRelayEntry, cAddr *net.UDPAddr) {
				defer func() {
					r.closed.Store(true)
					_ = r.remote.Close()
					relays.Delete(tgt)
				}()
				replyBuf := make([]byte, 65535)
				for {
					if r.closed.Load() {
						return
					}
					rn, err := r.remote.Read(replyBuf)
					if err != nil {
						return
					}
					outPkt := make([]byte, len(hdr)+rn)
					copy(outPkt, hdr)
					copy(outPkt[len(hdr):], replyBuf[:rn])
					if _, err := localUDP.WriteToUDP(outPkt, cAddr); err != nil {
						return
					}
				}
			}(target, hdrCopy, entry, clientAddr)
		} else {
			entry = val.(*udpRelayEntry)
		}

		_, _ = entry.remote.Write(payload)
	}
}

// NodeInfo 表示供应商线路节点的运行与探测状态
type NodeInfo struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Address     string   `json:"address"`
	IP          string   `json:"ip,omitempty"`
	SNI         string   `json:"sni"`
	LineType    string   `json:"line_type,omitempty"`
	ISPAffinity string   `json:"isp_affinity,omitempty"`
	Country     string   `json:"country,omitempty"`
	PurityScore int      `json:"purity_score,omitempty"`
	AIBlocked   bool     `json:"ai_blocked,omitempty"`
	WarpActive  bool     `json:"warp_active,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Badges      []string `json:"badges,omitempty"`
	Active      bool     `json:"active"`
	Connected   bool     `json:"connected"`
	Reachable   bool     `json:"reachable"`
	LatencyMs   int64    `json:"latency_ms"`
	LastProbeAt string   `json:"last_probe_at,omitempty"`
}

// inferNodeCountry 根据节点名或主机名推断国别代码
func inferNodeCountry(name, host string) string {
	combined := strings.ToUpper(name + " " + host)
	if strings.Contains(combined, "US") || strings.Contains(combined, "美国") || strings.Contains(combined, "🇺🇸") {
		return "US"
	}
	if strings.Contains(combined, "HK") || strings.Contains(combined, "香港") || strings.Contains(combined, "🇭🇰") {
		return "HK"
	}
	if strings.Contains(combined, "JP") || strings.Contains(combined, "日本") || strings.Contains(combined, "🇯🇵") {
		return "JP"
	}
	if strings.Contains(combined, "SG") || strings.Contains(combined, "新加坡") || strings.Contains(combined, "🇸🇬") {
		return "SG"
	}
	if strings.Contains(combined, "TW") || strings.Contains(combined, "台湾") || strings.Contains(combined, "🇹🇼") {
		return "TW"
	}
	if strings.Contains(combined, "KR") || strings.Contains(combined, "韩国") || strings.Contains(combined, "🇰🇷") {
		return "KR"
	}
	if strings.Contains(combined, "UK") || strings.Contains(combined, "英国") || strings.Contains(combined, "🇬🇧") || strings.Contains(combined, "GB") {
		return "UK"
	}
	if strings.Contains(combined, "DE") || strings.Contains(combined, "德国") || strings.Contains(combined, "🇩🇪") {
		return "DE"
	}
	return ""
}

// GetNodes 提取当前节点状态快照
func (e *Engine) GetNodes() []NodeInfo {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.appliedSub == nil || len(e.appliedSub.Servers) == 0 {
		return nil
	}
	res := make([]NodeInfo, 0, len(e.appliedSub.Servers))
	for _, s := range e.appliedSub.Servers {
		name := s.Address
		if s.Name != "" {
			name = s.Name
		} else if s.LineType != "" {
			name = fmt.Sprintf("%s (%s)", s.LineType, s.Address)
		}
		country := s.Country
		if country == "" {
			country = inferNodeCountry(s.Name, s.Host)
		}
		warp := s.WarpActive || strings.Contains(strings.ToUpper(s.Name), "WARP") || strings.Contains(strings.ToLower(s.LineType), "warp")
		badges := RenderNodeBadgesSlice(country, s.PurityScore, s.AIBlocked, warp)

		info := NodeInfo{
			ID:          s.Address,
			Name:        name,
			Address:     s.Address,
			IP:          s.IP,
			SNI:         s.SNI,
			LineType:    s.LineType,
			ISPAffinity: s.ISPAffinity,
			Country:     country,
			PurityScore: s.PurityScore,
			AIBlocked:   s.AIBlocked,
			WarpActive:  warp,
			Tags:        s.Tags,
			Badges:      badges,
			Active:      s.Address == e.activeAddr,
			Connected:   s.Address == e.activeAddr && e.running.Load(),
			Reachable:   true,
			LatencyMs:   -1,
		}
		res = append(res, info)
	}
	return res
}

// ProbeAllNodes 缺陷 D 规范：在 e.mu.RLock() 下取快照 -> 立即释放读锁 -> 8路并发无锁探测
func (e *Engine) ProbeAllNodes(ctx context.Context) []NodeInfo {
	e.mu.RLock()
	var servers []ServerConfig
	var echConfigs map[string][]byte
	if e.appliedSub != nil {
		servers = append(servers, e.appliedSub.Servers...)
		if e.appliedSub.ECHConfigs != nil {
			echConfigs = make(map[string][]byte, len(e.appliedSub.ECHConfigs))
			for k, v := range e.appliedSub.ECHConfigs {
				echConfigs[k] = v
			}
		}
	}
	activeAddr := e.activeAddr
	e.mu.RUnlock() // 立即释放读锁，严禁持锁进行网络探测

	if len(servers) == 0 {
		return nil
	}

	type probeResult struct {
		idx       int
		reachable bool
		rttMs     int64
	}

	results := make([]NodeInfo, len(servers))
	for i, s := range servers {
		name := s.Address
		if s.Name != "" {
			name = s.Name
		} else if s.LineType != "" {
			name = fmt.Sprintf("%s (%s)", s.LineType, s.Address)
		}
		country := s.Country
		if country == "" {
			country = inferNodeCountry(s.Name, s.Host)
		}
		warp := s.WarpActive || strings.Contains(strings.ToUpper(s.Name), "WARP") || strings.Contains(strings.ToLower(s.LineType), "warp")
		badges := RenderNodeBadgesSlice(country, s.PurityScore, s.AIBlocked, warp)

		results[i] = NodeInfo{
			ID:          s.Address,
			Name:        name,
			Address:     s.Address,
			IP:          s.IP,
			SNI:         s.SNI,
			LineType:    s.LineType,
			ISPAffinity: s.ISPAffinity,
			Country:     country,
			PurityScore: s.PurityScore,
			AIBlocked:   s.AIBlocked,
			WarpActive:  warp,
			Tags:        s.Tags,
			Badges:      badges,
			Active:      s.Address == activeAddr,
			Connected:   s.Address == activeAddr && e.running.Load(),
			Reachable:   false,
			LatencyMs:   -1,
		}
	}

	jobs := make(chan int, len(servers))
	resChan := make(chan probeResult, len(servers))

	workers := 8
	if len(servers) < workers {
		workers = len(servers)
	}

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				srv := servers[idx]
				host, portStr, err := net.SplitHostPort(srv.Address)
				if err != nil {
					host = srv.Address
					portStr = "443"
				}
				port := 443
				if p, perr := strconv.Atoi(portStr); perr == nil && p > 0 {
					port = p
				}
				var ip net.IP
				if srv.IP != "" {
					if parsed := net.ParseIP(srv.IP); parsed != nil {
						ip = parsed.To4()
					}
				}
				if ip == nil {
					ip, _ = resolvePhysicalIPv4(host)
				}
				if ip == nil {
					resChan <- probeResult{idx: idx, reachable: false, rttMs: -1}
					continue
				}

				cfg := DefaultTransportConfig(srv.Address, srv.SNI)
				cfg.RemoteUDPAddr = &net.UDPAddr{IP: ip, Port: port}
				cfg.ConnectTimeout = 2500 * time.Millisecond
				if len(srv.AltPorts) > 0 {
					cfg.AltPorts = srv.AltPorts
				}
				if echConfigs != nil {
					if c, ok := echConfigs[srv.Address]; ok && len(c) > 0 {
						cfg.ECHConfigList = c
					}
				}

				probeCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
				start := time.Now()
				cl, dialErr := Dial(probeCtx, cfg)
				cancel()

				if dialErr != nil {
					resChan <- probeResult{idx: idx, reachable: false, rttMs: -1}
					continue
				}
				rtt := time.Since(start).Milliseconds()
				_ = cl.Close() // 测完立即关闭，绝不入池

				resChan <- probeResult{idx: idx, reachable: true, rttMs: rtt}
			}
		}()
	}

	for i := range servers {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	close(resChan)

	nowStr := time.Now().Format("15:04:05")
	for r := range resChan {
		results[r.idx].Reachable = r.reachable
		results[r.idx].LatencyMs = r.rttMs
		results[r.idx].LastProbeAt = nowStr
	}

	return results
}
