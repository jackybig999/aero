// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
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
	stateStopped  int32 = 0
	stateStarting int32 = 1
	stateRunning  int32 = 2
	stateStopping int32 = 3
)

var (
	// ErrUDPUnavailable 标识 TUN 模式下 UDP/443 (QUIC/HTTP/3) 拨号失败，降级防御阻止整机伪装
	ErrUDPUnavailable   = errors.New("UDP_UNAVAILABLE")
	subSingleFlight     singleflight.Group
	detectThirdPartyTUN = DetectThirdPartyTUN
	openTunDeviceFn     = OpenTunDevice
	setupRoutesFn       = SetupRoutes
	teardownRoutesFn    = TeardownRoutes
)

// AppState 描述客户端当前运行状态
type AppState struct {
	Connected  bool   `json:"connected"`
	Mode       string `json:"mode"`
	Listen     string `json:"listen"`
	ActiveNode string `json:"active_node"`
	ActiveSNI  string `json:"active_sni"`
	ActualPort int    `json:"actual_port,omitempty"`
	SubURL     string `json:"sub_url,omitempty"`
	NodesCount int    `json:"nodes_count"`
	Version    string `json:"version"`

	Node         string `json:"node,omitempty"`
	SNI          string `json:"sni,omitempty"`
	ISP          string `json:"isp,omitempty"`
	ISPName      string `json:"isp_name,omitempty"`
	RttMs        int64  `json:"rtt_ms"`
	ProbeOk      bool   `json:"probe_ok"`
	ProbeMs      int64  `json:"probe_ms"`
	GeoRuleCount int    `json:"geo_rule_count"`
}

// Engine 客户端核心引擎
type Engine struct {
	mu           sync.RWMutex
	splitEngine  *SplitEngine
	dnsHandler   *DNSHandler
	tunnelClient *TunnelClient
	sessionPool  ISessionPool
	stackEngine  *StackEngine
	tunDevice    TunDevice
	sessionMgr   *SessionManager

	appliedSub    *Applied
	activeAddr    string
	activeToken   string
	activeSNI     string
	mode          string
	listenAddr    string
	mixedListener net.Listener

	currentISP  string
	savedSubURL string
	geoDataURL  string

	running           atomic.Bool
	state             atomic.Int32
	lifecycleMu       sync.Mutex
	startCancel       context.CancelFunc
	tcpDialer         func(ctx context.Context, target string) (net.Conn, error)
	stopMixed         chan struct{}
	rootCtx           context.Context
	rootCancel        context.CancelFunc
	netMon            NetworkMonitor
	activeConns       sync.Map
	killSwitch        atomic.Bool
	sentinel          *nodeSentinel
	packetConnFactory PacketConnFactory

	chainProxyMu  sync.RWMutex
	chainProxyCfg ChainProxyConfig
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
		stopMixed:         make(chan struct{}),
		netMon:            NewNetworkMonitor(),
		packetConnFactory: ListenPhysicalPacket,
	}
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

// DrainingSessionCount 获取当前会话管理器中排空队列的深度
func (e *Engine) DrainingSessionCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.sessionMgr != nil {
		return e.sessionMgr.DrainingCount()
	}
	return 0
}

// SetPacketConnFactory 设置当前引擎的物理网卡 Socket 工厂
func (e *Engine) SetPacketConnFactory(f PacketConnFactory) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.packetConnFactory = f
}

// IsRunning 查询引擎当前运行状态
func (e *Engine) IsRunning() bool {
	return e.running.Load() && e.state.Load() == stateRunning
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

// Apply 应用已解析好的订阅配置
// 核心规则：若首节点 host:port 与当前激活节点相同，短路返回，严禁调用 Reset()！
func (e *Engine) Apply(applied *Applied) error {
	if applied == nil || len(applied.Servers) == 0 {
		return fmt.Errorf("empty applied subscription")
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	e.appliedSub = applied
	if len(applied.AllPins) > 0 {
		AddPins(applied.AllPins...)
	}

	primary := applied.Servers[0]
	if e.activeAddr == primary.Address {
		// host:port 严格一致，短路返回，绝对不调用 Reset()！
		var ech []byte
		if applied.ECHConfigs != nil {
			if c, ok := applied.ECHConfigs[primary.Address]; ok && len(c) > 0 {
				ech = c
			}
		}
		_, _, _, curIP := getActiveEdge()
		if len(ech) > 0 {
			SetActiveEdge(primary.Address, primary.Token, primary.SNI, curIP, ech)
		} else {
			SetActiveEdge(primary.Address, primary.Token, primary.SNI, curIP)
		}
		return nil
	}

	return e.switchActiveNodeLocked(primary.Address, primary.Token, primary.SNI)
}

// LoadAndApplySubscription 从远程 URL 加载并应用订阅，挂载 singleflight 阻断重入
func (e *Engine) LoadAndApplySubscription(src string) (*Applied, error) {
	v, err, _ := subSingleFlight.Do(src, func() (any, error) {
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
		e.mu.Unlock()

		if err := e.Apply(applied); err != nil {
			return nil, err
		}
		return applied, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*Applied), nil
}

// LoadAndApplySubscriptionBytes 解析字节流并应用订阅
func (e *Engine) LoadAndApplySubscriptionBytes(data []byte) (*Applied, error) {
	sub, err := ParseSubscriptionBytes(data)
	if err != nil {
		return nil, err
	}
	applied, err := ApplySubscription(sub)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(e.getContext(), 2*time.Second)
	defer cancel()
	ispRes := DetectISP(ctx, 500*time.Millisecond)
	bestISP := "DEFAULT"
	if ispRes != nil && ispRes.BestISP != "" {
		bestISP = ispRes.BestISP
	}
	sortServersByISP(applied.Servers, bestISP)

	e.mu.Lock()
	e.currentISP = bestISP
	e.mu.Unlock()

	if err := e.Apply(applied); err != nil {
		return nil, err
	}
	return applied, nil
}

// SwitchActiveNode 切换激活节点
// 核心规则：仅比对 host:port（相同则短路返回，严禁 Reset()）
func (e *Engine) SwitchActiveNode(addr string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.activeAddr == addr {
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

	return e.switchActiveNodeLocked(addr, tok, sni)
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

func (e *Engine) switchActiveNodeLocked(addr, tok, sni string) error {
	host, _, err := net.SplitHostPort(addr)
	if err == nil && net.ParseIP(host) == nil && host != "" {
		sni = host
	}

	_, _, _, oldIP := getActiveEdge()
	newHost, _, _ := net.SplitHostPort(addr)

	var newIP net.IP
	if e.appliedSub != nil && e.appliedSub.IPs != nil {
		if ipStr, ok := e.appliedSub.IPs[addr]; ok && ipStr != "" {
			if parsed := net.ParseIP(ipStr); parsed != nil {
				newIP = parsed.To4()
			}
		}
		if newIP == nil {
			for a, ipStr := range e.appliedSub.IPs {
				if h, _, _ := net.SplitHostPort(a); h == newHost && ipStr != "" {
					if parsed := net.ParseIP(ipStr); parsed != nil {
						newIP = parsed.To4()
						break
					}
				}
			}
		}
	}
	if newIP == nil && newHost != "" {
		ip, rerr := resolvePhysicalIPv4(newHost)
		if rerr != nil {
			return fmt.Errorf("resolve active node %s: %w", newHost, rerr)
		}
		newIP = ip
	}
	if newIP != nil && e.mode == "tun" && e.running.Load() {
		_ = ProtectHostRoute(newIP.String())
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
	}

	// 平滑软切线（Graceful Draining）：
	// 旧 Session 标记为 draining，不立即 Close()，保留其宿主机保护路由，开启 20 秒排空定时器（锁绝不盖住这 20 秒！）；
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
		oldIPStr := oldIP.String()
		time.AfterFunc(20*time.Second, func() {
			UnprotectHostRoute(oldIPStr)
		})
	}

	log.Printf("[ENGINE] active node switched to %s (sni=%s)", addr, sni)
	return nil
}

// Start 启动客户端数据面（TUN 虚拟网卡 + gVisor 协议栈 + 物理网络监控 + 混合代理端口）
func (e *Engine) Start() error {
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()

	if e.state.Load() == stateRunning {
		return nil
	}
	if !e.state.CompareAndSwap(stateStopped, stateStarting) {
		return fmt.Errorf("engine is not in stopped state (current: %d)", e.state.Load())
	}

	startCtx, startCancel := context.WithCancel(context.Background())
	e.mu.Lock()
	e.startCancel = startCancel
	e.mu.Unlock()

	rollback := func(err error) error {
		startCancel()
		e.mu.Lock()
		e.startCancel = nil
		e.mu.Unlock()
		e.state.Store(stateStopped)
		e.running.Store(false)
		return err
	}

	e.mu.RLock()
	activeAddr := e.activeAddr
	activeToken := e.activeToken
	activeSNI := e.activeSNI
	mode := e.mode
	e.mu.RUnlock()

	// 1. 本地模式 (sysproxy)：
	// 绝对不调用 DetectThirdPartyTUN()，绝对不调完整 TeardownRoutes；
	// 但清理上次崩溃可能残留在 aero0 上的 /1 路由（仅通过 interface aero0 指定删除，绝不碰 Clash）
	if mode == "sysproxy" {
		CleanAero0StaleRoutes()
	} else {
		// 2. 全局 TUN 模式：
		// 第一行执行无死角第三方 TUN 冲突检测
		conflict, vpnName, err := detectThirdPartyTUN()
		if err != nil {
			return rollback(fmt.Errorf("detect third-party tun: %w", err))
		}
		if conflict {
			// 命中冲突：绝不创建 aero0，绝不调用 TeardownRoutes，绝不写 /32，绝不写两条 /1，running 保持 false
			return rollback(&ErrConflictingTUN{VPNName: vpnName})
		}

		CleanAero0StaleRoutes()
		invalidateGatewayCache()
	}

	if activeAddr == "" {
		return rollback(fmt.Errorf("no active node configured"))
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

	ip, err := resolvePhysicalIPv4(host)
	if err != nil {
		return rollback(fmt.Errorf("resolve active node %s: %w", host, err))
	}

	// 规则：仅在 tun 模式下保护节点路由；sysproxy 严格执行零主机篡改
	if mode == "tun" {
		_ = ProtectHostRoute(ip.String())
	}
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

	if len(ech) > 0 {
		SetActiveEdge(activeAddr, activeToken, activeSNI, ip, ech)
	} else {
		SetActiveEdge(activeAddr, activeToken, activeSNI, ip)
	}
	if e.dnsHandler != nil {
		e.dnsHandler.SetEdge(host, ip)
	}

	select {
	case <-startCtx.Done():
		if mode == "tun" {
			UnprotectHostRoute(ip.String())
		}
		return rollback(startCtx.Err())
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

	start := time.Now()
	cl, err := Dial(probeCtx, cfg)
	if err != nil {
		if mode == "tun" {
			UnprotectHostRoute(ip.String())
			// 模式是 tun 而 UDP/443 (QUIC/HTTP/3) 拨号失败时：
			// 不调用 OpenTunDevice，不装 /1 路由，55555 照常监听，向 UI 返回固定错误码 UDP_UNAVAILABLE。
			// 严禁将整机流量降级走 TCP 再宣称全局隧道仍在。
			_ = e.startMixedProxy()
			return rollback(fmt.Errorf("%w: connect to %s failed: %v", ErrUDPUnavailable, activeAddr, err))
		}
		return rollback(fmt.Errorf("connect to %s failed: %w", activeAddr, err))
	}
	actualPort := cl.ActualPort()
	_ = cl.Close()
	rtt := time.Since(start)

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

	select {
	case <-startCtx.Done():
		if mode == "tun" {
			UnprotectHostRoute(ip.String())
		}
		return rollback(startCtx.Err())
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
	nm := e.netMon
	e.mu.Unlock()

	e.rootCtx, e.rootCancel = context.WithCancel(context.Background())
	e.stopMixed = make(chan struct{})

	if mode == "sysproxy" {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[SENTINEL] panic recovered: %v", r)
				}
			}()
			sentinel.run(e.rootCtx)
		}()
		nm.Start(func(newGW, ifName string) {
			e.onNetworkChange(newGW, ifName)
		})
		_ = e.startMixedProxy()
		e.running.Store(true)
		e.state.Store(stateRunning)
		e.mu.Lock()
		e.startCancel = nil
		e.mu.Unlock()
		log.Printf("[ENGINE] data plane started in local sysproxy mode (mixed proxy %s)", e.listenAddr)
		return nil
	}

	dev, err := openTunDeviceFn("aero0", 1360)
	if err != nil {
		UnprotectHostRoute(ip.String())
		if e.rootCancel != nil {
			e.rootCancel()
		}
		return rollback(fmt.Errorf("open tun device: %w", err))
	}
	e.tunDevice = dev

	e.stackEngine = NewStackEngine(dev, e.tunnelClient, e.dnsHandler)
	e.stackEngine.SetKillSwitch(e.killSwitch.Load())
	if err := e.stackEngine.Start(); err != nil {
		_ = dev.Close()
		e.tunDevice = nil
		teardownRoutesFn(dev.Name())
		UnprotectHostRoute(ip.String())
		if e.rootCancel != nil {
			e.rootCancel()
		}
		return rollback(fmt.Errorf("start stack: %w", err))
	}

	// WebRTC 生产激活：探测成功且 stackEngine 启动后，显式激活 WebRTC
	e.stackEngine.SetWebRTCActive(true)

	// 路由配置固定使用 10.88.0.2/24，与 gVisor 保持一致；彻底剔除桌面 DialIP 调用
	prefixStr := "10.88.0.2/24"

	if err := setupRoutesFn(dev.Name(), prefixStr); err != nil {
		if e.stackEngine != nil {
			e.stackEngine.Stop()
			e.stackEngine = nil
		}
		_ = dev.Close()
		e.tunDevice = nil
		teardownRoutesFn(dev.Name())
		UnprotectHostRoute(ip.String())
		if e.rootCancel != nil {
			e.rootCancel()
		}
		return rollback(fmt.Errorf("setup routes: %w", err))
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[SENTINEL] panic recovered: %v", r)
			}
		}()
		sentinel.run(e.rootCtx)
	}()

	nm.Start(func(newGW, ifName string) {
		e.onNetworkChange(newGW, ifName)
	})

	_ = e.startMixedProxy()

	e.running.Store(true)
	e.state.Store(stateRunning)
	e.mu.Lock()
	e.startCancel = nil
	e.mu.Unlock()
	log.Printf("[ENGINE] data plane started successfully (TUN aero0, mixed proxy %s)", e.listenAddr)
	return nil
}

// onNetworkChange 响应底层物理网络切换事件
// 规则：原子级刷新 ProtectHostRoute、清理存量悬挂连接、重置会话池、更新物理解析、异步预热 QUIC
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

	if sentinel != nil {
		sentinel.wakeup()
	}

	_, _, _, ip := getActiveEdge()

	// 1. 刷新活跃节点保护路由（仅限全局 TUN 模式，sysproxy 模式绝对不篡改主机路由表）
	if mode == "tun" && e.running.Load() {
		if ip != nil {
			_ = ProtectHostRoute(ip.String())
		}
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
	if e.rootCtx != nil {
		return e.rootCtx
	}
	return context.Background()
}

// Stop 停止客户端数据面
func (e *Engine) Stop() error {
	invalidateGatewayCache()

	// 快速取消正在进行的 Start()
	e.mu.Lock()
	if cancel := e.startCancel; cancel != nil {
		cancel()
	}
	e.mu.Unlock()

	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()

	if e.state.Load() == stateStopped && !e.running.Load() {
		if e.mixedListener != nil {
			_ = e.mixedListener.Close()
			e.mixedListener = nil
		}
		return nil
	}
	e.state.Store(stateStopping)
	e.running.Store(false)

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

	if e.mixedListener != nil {
		_ = e.mixedListener.Close()
		e.mixedListener = nil
	}
	select {
	case <-e.stopMixed:
	default:
		close(e.stopMixed)
	}

	if e.stackEngine != nil {
		e.stackEngine.SetWebRTCActive(false)
		e.stackEngine.Stop()
		e.stackEngine = nil
	}

	if e.tunnelClient != nil {
		e.tunnelClient.Close()
	}

	if e.tunDevice != nil {
		devName := e.tunDevice.Name()
		if devName != "" {
			TeardownRoutes(devName)
		}
		_ = os.Remove(utunRecordPath())
		_ = e.tunDevice.Close()
		e.tunDevice = nil
	}

	_, _, _, ip := getActiveEdge()
	if ip != nil {
		UnprotectHostRoute(ip.String())
	}

	e.sessionPool.Reset()
	if e.sessionMgr != nil {
		e.sessionMgr.Reset()
	}
	invalidateGatewayCache()
	e.state.Store(stateStopped)
	log.Printf("[ENGINE] data plane stopped")
	return nil
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

	return AppState{
		Connected:    e.running.Load(),
		Mode:         e.mode,
		Listen:       e.listenAddr,
		ActiveNode:   e.activeAddr,
		ActiveSNI:    e.activeSNI,
		ActualPort:   actualPort,
		SubURL:       subURL,
		NodesCount:   nodesCount,
		Version:      "aero/3.0",
		Node:         e.activeAddr,
		SNI:          e.activeSNI,
		ISP:          isp,
		ISPName:      ispToName(isp),
		RttMs:        rttMs,
		ProbeOk:      probeOk,
		ProbeMs:      rttMs,
		GeoRuleCount: geoCount,
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

// SyncGeoData 从云端同步最新中国直连域名与网段规则库
// 规则：必须使用 DialPhysicalDirect 构建 HTTP Transport 防止 TUN 路由环路死锁，比对 If-None-Match ETag，200 则原子写入 GetDataDir()/geodata_direct.txt 并调用 e.splitEngine.ReloadRules
func (e *Engine) SyncGeoData(ctx context.Context) (int, bool, error) {
	e.mu.RLock()
	targetURL := e.geoDataURL
	subURL := e.savedSubURL
	e.mu.RUnlock()

	if targetURL == "" {
		if subURL != "" {
			if u, err := url.Parse(subURL); err == nil && u.Host != "" {
				scheme := u.Scheme
				if scheme == "" {
					scheme = "https"
				}
				targetURL = fmt.Sprintf("%s://%s/api/v1/geodata/direct", scheme, u.Host)
			}
		}
	}
	if targetURL == "" {
		targetURL = "https://rules.aero-protocol.com/geodata_direct.txt"
	}

	dataDir := GetDataDir()
	filePath := filepath.Join(dataDir, "geodata_direct.txt")
	etagPath := filepath.Join(dataDir, "geodata_direct.etag")

	var currentETag string
	if b, err := os.ReadFile(etagPath); err == nil {
		currentETag = strings.TrimSpace(string(b))
	} else if existing, err := os.ReadFile(filePath); err == nil && len(existing) > 0 {
		sum := sha256.Sum256(existing)
		currentETag = `"` + hex.EncodeToString(sum[:]) + `"`
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return 0, false, fmt.Errorf("create geodata request: %w", err)
	}
	req.Header.Set("User-Agent", "AeroClient/2.0")
	if currentETag != "" {
		req.Header.Set("If-None-Match", currentETag)
	}

	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(c context.Context, network, addr string) (net.Conn, error) {
			return DialPhysicalDirect(c, network, addr)
		},
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 8 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   15 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, false, fmt.Errorf("sync geodata network error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		count := 0
		if e.splitEngine != nil {
			count = e.splitEngine.TotalRules()
		}
		return count, false, nil
	}

	if resp.StatusCode != http.StatusOK {
		return 0, false, fmt.Errorf("sync geodata unexpected HTTP status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, false, fmt.Errorf("read geodata body: %w", err)
	}

	// 原子写入 GetDataDir()/geodata_direct.txt
	tmpFile, err := os.CreateTemp(dataDir, "geodata_direct.*.tmp")
	if err != nil {
		return 0, false, fmt.Errorf("create geodata temp file: %w", err)
	}
	tmpName := tmpFile.Name()

	var renameSuccess bool
	defer func() {
		if !renameSuccess {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmpFile.Write(body); err != nil {
		_ = tmpFile.Close()
		return 0, false, fmt.Errorf("write geodata temp file: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return 0, false, fmt.Errorf("sync geodata temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return 0, false, fmt.Errorf("close geodata temp file: %w", err)
	}

	if err := os.Rename(tmpName, filePath); err == nil {
		renameSuccess = true
	} else {
		bakPath := filePath + ".bak"
		_ = os.Remove(bakPath)
		if renBakErr := os.Rename(filePath, bakPath); renBakErr == nil {
			if renTmpErr := os.Rename(tmpName, filePath); renTmpErr == nil {
				renameSuccess = true
				_ = os.Remove(bakPath)
			} else {
				_ = os.Rename(bakPath, filePath) // 立即回滚恢复原文件
				return 0, false, fmt.Errorf("rename geodata fallback failed: %w", renTmpErr)
			}
		} else {
			if werr := os.WriteFile(filePath, body, 0644); werr != nil {
				return 0, false, fmt.Errorf("write geodata direct fallback: %w", werr)
			}
			renameSuccess = true
		}
	}

	newETag := resp.Header.Get("ETag")
	if newETag == "" {
		sum := sha256.Sum256(body)
		newETag = `"` + hex.EncodeToString(sum[:]) + `"`
	}
	_ = os.WriteFile(etagPath, []byte(newETag), 0644)

	if e.splitEngine == nil {
		return 0, true, fmt.Errorf("split engine not initialized")
	}
	count, err := e.splitEngine.ReloadRules(body)
	if err != nil {
		return 0, true, fmt.Errorf("reload rules failed: %w", err)
	}

	return count, true, nil
}

// SetMode 设置工作模式
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

// DialTCP 导出供外部使用的 TCP 拨号接口，并注册至活跃连接池
func (e *Engine) DialTCP(ctx context.Context, target string) (net.Conn, error) {
	e.mu.RLock()
	dialer := e.tcpDialer
	e.mu.RUnlock()
	if dialer != nil {
		conn, err := dialer(ctx, target)
		if err != nil {
			return nil, err
		}
		e.activeConns.Store(conn, struct{}{})
		return &trackedConn{
			Conn: conn,
			onClose: func() {
				e.activeConns.Delete(conn)
			},
		}, nil
	}

	var conn net.Conn
	var err error
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
	e.activeConns.Store(conn, struct{}{})
	return &trackedConn{
		Conn: conn,
		onClose: func() {
			e.activeConns.Delete(conn)
		},
	}, nil
}

// DialUDP 导出供外部使用的 UDP 拨号接口 (MASQUE CONNECT-UDP)
func (e *Engine) DialUDP(ctx context.Context, target string) (net.Conn, error) {
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

// startMixedProxy 启动 SOCKS5 + HTTP CONNECT 混合端口监听
func (e *Engine) startMixedProxy() error {
	e.mu.RLock()
	addr := e.listenAddr
	existingLn := e.mixedListener
	e.mu.RUnlock()

	if existingLn != nil {
		return nil
	}

	if addr == "" {
		addr = "127.0.0.1:55555"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[PROXY] listen on %s failed: %v", addr, err)
		return err
	}
	e.mu.Lock()
	e.mixedListener = ln
	if strings.HasSuffix(addr, ":0") {
		e.listenAddr = ln.Addr().String()
	}
	e.mu.Unlock()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			e.activeConns.Store(conn, struct{}{})
			go func(c net.Conn) {
				defer func() {
					_ = c.Close()
					e.activeConns.Delete(c)
				}()
				e.serveMixedConn(c)
			}(conn)
		}
	}()
	return nil
}

func (e *Engine) serveMixedConn(conn net.Conn) {
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

	// 响应无鉴权 (0x05, 0x00)
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
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

	if cmd == 0x03 { // UDP ASSOCIATE
		e.handleSocks5UDPAssociate(conn, host, port)
		return
	}
	if cmd != 0x01 { // 仅支持 CONNECT (0x01) 与 UDP ASSOCIATE (0x03)
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	target := fmt.Sprintf("%s:%d", host, port)

	ctx, cancel := context.WithTimeout(e.getContext(), 10*time.Second)
	remote, err := e.DialTCP(ctx, target)
	cancel()
	if err != nil {
		_, _ = conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()

	// 成功响应
	_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0})

	relayTraffic(conn, remote)
}

func (e *Engine) handleHTTPConnect(conn net.Conn, br *bufio.Reader) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method != http.MethodConnect {
		return
	}

	target := req.RequestURI
	ctx, cancel := context.WithTimeout(e.getContext(), 10*time.Second)
	remote, err := e.DialTCP(ctx, target)
	cancel()
	if err != nil {
		_, _ = conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer remote.Close()

	_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	relayTraffic(conn, remote)
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
	ID          string `json:"id"`
	Name        string `json:"name"`
	Address     string `json:"address"`
	IP          string `json:"ip,omitempty"`
	SNI         string `json:"sni"`
	LineType    string `json:"line_type,omitempty"`
	ISPAffinity string `json:"isp_affinity,omitempty"`
	Active      bool   `json:"active"`
	Connected   bool   `json:"connected"`
	Reachable   bool   `json:"reachable"`
	LatencyMs   int64  `json:"latency_ms"`
	LastProbeAt string `json:"last_probe_at,omitempty"`
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
		info := NodeInfo{
			ID:          s.Address,
			Name:        name,
			Address:     s.Address,
			IP:          s.IP,
			SNI:         s.SNI,
			LineType:    s.LineType,
			ISPAffinity: s.ISPAffinity,
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
		results[i] = NodeInfo{
			ID:          s.Address,
			Name:        name,
			Address:     s.Address,
			IP:          s.IP,
			SNI:         s.SNI,
			LineType:    s.LineType,
			ISPAffinity: s.ISPAffinity,
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
