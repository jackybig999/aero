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
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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

	running     atomic.Bool
	stopMixed   chan struct{}
	rootCtx     context.Context
	rootCancel  context.CancelFunc
	netMon      NetworkMonitor
	activeConns sync.Map
	killSwitch  atomic.Bool
	sentinel    *nodeSentinel
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

	eng := &Engine{
		splitEngine:  split,
		dnsHandler:   dns,
		tunnelClient: tunnel,
		sessionPool:  pool,
		mode:         "tun",
		listenAddr:   "127.0.0.1:55555",
		stopMixed:    make(chan struct{}),
		netMon:       NewNetworkMonitor(),
	}
	eng.sentinel = newNodeSentinel(eng)
	return eng
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

	// 2. 初始化并启动节点健康哨兵 (Node Sentinel)
	e.mu.Lock()
	if e.sentinel == nil {
		e.sentinel = newNodeSentinel(e)
	}
	sentinel := e.sentinel
	if e.netMon == nil {
		e.netMon = NewNetworkMonitor()
	}
	nm := e.netMon
	e.mu.Unlock()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[SENTINEL] panic recovered: %v", r)
			}
		}()
		sentinel.run(e.rootCtx)
	}()

	// 3. 启动物理网络变动监控 (Netmon)
	nm.Start(func(newGW, ifName string) {
		e.onNetworkChange(newGW, ifName)
	})

	// 4. 启动本地 127.0.0.1:55555 混合代理监听器
	go e.startMixedProxy()

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
	e.mu.RUnlock()

	if stackEng != nil {
		stackEng.SetWebRTCActive(false)
	}

	if sentinel != nil {
		sentinel.wakeup()
	}

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
		e.stackEngine.SetWebRTCActive(false)
		e.stackEngine.Stop()
		e.stackEngine = nil
	}

	if e.tunnelClient != nil {
		e.tunnelClient.Close()
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

	return AppState{
		Connected:    e.running.Load(),
		Mode:         e.mode,
		Listen:       e.listenAddr,
		ActiveNode:   e.activeAddr,
		ActiveSNI:    e.activeSNI,
		SubURL:       subURL,
		NodesCount:   nodesCount,
		Version:      "aero/2.0",
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

// PingActiveNode 向当前活跃节点发送 probe.aero 控制短流，度量往返 RTT 并更新 sentinel.lastRTT
func (e *Engine) PingActiveNode(ctx context.Context) (time.Duration, error) {
	if e.tunnelClient == nil {
		return 0, fmt.Errorf("tunnel client not initialized")
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
	}

	start := time.Now()
	if _, err := e.tunnelClient.ResolveDNS(ctx, "probe.aero"); err != nil {
		return 0, fmt.Errorf("ping active node failed: %w", err)
	}
	rtt := time.Since(start)

	e.mu.RLock()
	sentinel := e.sentinel
	e.mu.RUnlock()
	if sentinel != nil {
		sentinel.lastRTT.Store(rtt.Nanoseconds())
	}

	return rtt, nil
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
			MinVersion: tls.VersionTLS12,
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
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
