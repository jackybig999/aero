// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"
)

var (
	subSingleFlight singleflight.Group
)

// AppState 描述客户端当前运行状态
type AppState struct {
	Connected  bool   `json:"connected"`
	Mode       string `json:"mode"`
	Listen     string `json:"listen"`
	ActiveNode string `json:"active_node"`
	ActiveSNI  string `json:"active_sni"`
	SubURL     string `json:"sub_url,omitempty"`
	NodesCount int    `json:"nodes_count"`
	Version    string `json:"version"`
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

	appliedSub    *Applied
	activeAddr    string
	activeToken   string
	activeSNI     string
	mode          string
	listenAddr    string
	mixedListener net.Listener

	running     atomic.Bool
	stopMixed   chan struct{}
	rootCtx     context.Context
	rootCancel  context.CancelFunc
	netMon      NetworkMonitor
	activeConns sync.Map
	killSwitch  atomic.Bool
}

// NewEngine 创建客户端引擎
func NewEngine() *Engine {
	split := NewSplitEngine()
	dns := NewDNSHandler(split)
	pool := GlobalSessionPool
	tunnel := NewTunnelClient(pool, split)

	// 将短流解析器连接至 DNS 处理器
	dns.SetTunnelResolver(func(ctx context.Context, domain string) (net.IP, error) {
		return tunnel.ResolveDNS(ctx, domain)
	})

	return &Engine{
		splitEngine:  split,
		dnsHandler:   dns,
		tunnelClient: tunnel,
		sessionPool:  pool,
		mode:         "tun",
		listenAddr:   "127.0.0.1:55555",
		stopMixed:    make(chan struct{}),
		netMon:       NewNetworkMonitor(),
	}
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
		return nil
	}

	return e.switchActiveNodeLocked(primary.Address, primary.Token, primary.SNI)
}

// LoadAndApplySubscription 从远程 URL 加载并应用订阅，挂载 singleflight 阻断重入
func (e *Engine) LoadAndApplySubscription(src string) (*Applied, error) {
	v, err, _ := subSingleFlight.Do(src, func() (any, error) {
		sub, err := FetchSubscription(context.Background(), src, SubFetchOptions{})
		if err != nil {
			return nil, err
		}
		applied, err := ApplySubscription(sub)
		if err != nil {
			return nil, err
		}
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
	}

	return e.switchActiveNodeLocked(addr, tok, sni)
}

func (e *Engine) switchActiveNodeLocked(addr, tok, sni string) error {
	host, _, err := net.SplitHostPort(addr)
	if err == nil && net.ParseIP(host) == nil && host != "" {
		sni = host
	}

	oldHost, _, _ := net.SplitHostPort(e.activeAddr)
	newHost, _, _ := net.SplitHostPort(addr)

	if newHost != "" {
		_ = ProtectHostRoute(newHost)
	}

	e.activeAddr = addr
	e.activeToken = tok
	e.activeSNI = sni
	SetActiveEdge(addr, tok, sni)

	if e.dnsHandler != nil && newHost != "" {
		e.dnsHandler.SetEdge(newHost, net.ParseIP(newHost))
	}

	// 仅在真实换线后重置连接池
	e.sessionPool.Reset()

	if oldHost != "" && oldHost != newHost {
		UnprotectHostRoute(oldHost)
	}

	log.Printf("[ENGINE] active node switched to %s (sni=%s)", addr, sni)
	return nil
}

// Start 启动客户端数据面（TUN 虚拟网卡 + gVisor 协议栈 + 物理网络监控 + 混合代理端口）
func (e *Engine) Start() error {
	if e.running.Swap(true) {
		return nil
	}

	e.rootCtx, e.rootCancel = context.WithCancel(context.Background())
	e.stopMixed = make(chan struct{})

	// 1. 打开虚拟网卡与网络栈
	dev, err := OpenTunDevice("aero0", 1224)
	if err != nil {
		e.running.Store(false)
		if e.rootCancel != nil {
			e.rootCancel()
		}
		return fmt.Errorf("open tun device: %w", err)
	}
	e.tunDevice = dev

	if err := SetupRoutes("aero0", "10.88.0.2/24"); err != nil {
		_ = dev.Close()
		e.running.Store(false)
		if e.rootCancel != nil {
			e.rootCancel()
		}
		return fmt.Errorf("setup routes: %w", err)
	}

	e.stackEngine = NewStackEngine(dev, e.tunnelClient, e.dnsHandler)
	e.stackEngine.SetKillSwitch(e.killSwitch.Load())
	if err := e.stackEngine.Start(); err != nil {
		TeardownRoutes("aero0")
		_ = dev.Close()
		e.running.Store(false)
		if e.rootCancel != nil {
			e.rootCancel()
		}
		return fmt.Errorf("start stack: %w", err)
	}

	// 2. 启动物理网络变动监控 (Netmon)
	e.mu.Lock()
	if e.netMon == nil {
		e.netMon = NewNetworkMonitor()
	}
	nm := e.netMon
	e.mu.Unlock()

	nm.Start(func(newGW, ifName string) {
		e.onNetworkChange(newGW, ifName)
	})

	// 3. 启动本地 127.0.0.1:55555 混合代理监听器
	go e.startMixedProxy()

	log.Printf("[ENGINE] data plane started successfully (TUN aero0, mixed proxy %s)", e.listenAddr)
	return nil
}

// onNetworkChange 响应底层物理网络切换事件
// 规则：原子级刷新 ProtectHostRoute、清理存量悬挂连接、重置会话池、更新物理解析、异步预热 QUIC
func (e *Engine) onNetworkChange(newGW, ifName string) {
	log.Printf("[ENGINE] onNetworkChange triggered: newGW=%s, ifName=%s", newGW, ifName)

	e.mu.RLock()
	activeAddr := e.activeAddr
	activeSNI := e.activeSNI
	e.mu.RUnlock()

	// 1. 刷新活跃节点保护路由
	if activeAddr != "" {
		host, _, _ := net.SplitHostPort(activeAddr)
		if host != "" {
			_ = ProtectHostRoute(host)
		}
	}

	// 2. 斩断前一网络留存的悬挂连接
	e.closeActiveConns()

	// 3. 重置 QUIC 会话池
	e.sessionPool.Reset()

	// 4. 更新物理 DNS
	if e.dnsHandler != nil {
		if newGW != "" && net.ParseIP(newGW) != nil {
			e.dnsHandler.SetPhysicalDNS(newGW + ":53")
		} else {
			e.dnsHandler.SetPhysicalDNS("223.5.5.5:53")
		}
	}

	// 5. 异步预热新网络接口上的 QUIC 拨号
	go func() {
		if activeAddr == "" {
			return
		}
		cfg := DefaultTransportConfig(activeAddr, activeSNI)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = e.sessionPool.Get(ctx, cfg)
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
	if !e.running.Swap(false) {
		return nil
	}

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
		e.stackEngine.Stop()
		e.stackEngine = nil
	}

	TeardownRoutes("aero0")

	if e.tunDevice != nil {
		_ = e.tunDevice.Close()
		e.tunDevice = nil
	}

	e.sessionPool.Reset()
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

	return AppState{
		Connected:  e.running.Load(),
		Mode:       e.mode,
		Listen:     e.listenAddr,
		ActiveNode: e.activeAddr,
		ActiveSNI:  e.activeSNI,
		NodesCount: nodesCount,
		Version:    "aero/2.0",
	}
}

// SetMode 设置工作模式
func (e *Engine) SetMode(m string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.mode = m
}

// SetListenAddr 设置本地混合代理监听地址
func (e *Engine) SetListenAddr(addr string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.listenAddr = addr
}

// DialTCP 导出供外部使用的 TCP 拨号接口，并注册至活跃连接池
func (e *Engine) DialTCP(ctx context.Context, target string) (net.Conn, error) {
	conn, err := e.tunnelClient.DialTCP(ctx, target)
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
func (e *Engine) startMixedProxy() {
	addr := e.listenAddr
	if addr == "" {
		addr = "127.0.0.1:55555"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[PROXY] listen on %s failed: %v", addr, err)
		return
	}
	e.mixedListener = ln
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
	if req[1] != 0x01 { // 仅支持 CONNECT
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var host string
	switch req[3] {
	case 0x01: // IPv4
		var ip [4]byte
		if _, err := io.ReadFull(br, ip[:]); err != nil {
			return
		}
		host = net.IP(ip[:]).String()
	case 0x03: // Domain
		l, err := br.ReadByte()
		if err != nil {
			return
		}
		domainBuf := make([]byte, l)
		if _, err := io.ReadFull(br, domainBuf); err != nil {
			return
		}
		host = string(domainBuf)
	case 0x04: // IPv6
		var ip [16]byte
		if _, err := io.ReadFull(br, ip[:]); err != nil {
			return
		}
		host = net.IP(ip[:]).String()
	default:
		return
	}

	var portBuf [2]byte
	if _, err := io.ReadFull(br, portBuf[:]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf[:])
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
