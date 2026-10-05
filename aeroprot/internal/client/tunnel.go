// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	contextIDCounter   atomic.Uint32
	activeEdgeAddr     atomic.Pointer[string]
	activeEdgeToken    atomic.Pointer[string]
	activeEdgeSNI      atomic.Pointer[string]
	activeEdgeIP       atomic.Pointer[net.IP]
	activeEdgeECH      atomic.Pointer[[]byte]
	activeEdgeAltPorts atomic.Pointer[[]int]

	inboundDatagramHandlers sync.Map // map[uint32]func(payload []byte)
)

func init() {
	contextIDCounter.Store(100)
	empty := ""
	activeEdgeAddr.Store(&empty)
	activeEdgeToken.Store(&empty)
	activeEdgeSNI.Store(&empty)
}

// SetActiveEdge 设置当前激活节点的拨号信息
func SetActiveEdge(addr, tok, sni string, ip net.IP, ech ...[]byte) {
	activeEdgeAddr.Store(&addr)
	activeEdgeToken.Store(&tok)
	activeEdgeSNI.Store(&sni)
	if ip != nil {
		ipCopy := append(net.IP(nil), ip.To4()...)
		activeEdgeIP.Store(&ipCopy)
	} else {
		activeEdgeIP.Store(nil)
	}
	if len(ech) > 0 && len(ech[0]) > 0 {
		echCopy := append([]byte(nil), ech[0]...)
		activeEdgeECH.Store(&echCopy)
	} else {
		activeEdgeECH.Store(nil)
	}
}

// SetActiveEdgeAltPorts 设置当前激活节点的备用轮试端口池
func SetActiveEdgeAltPorts(ports []int) {
	if len(ports) > 0 {
		pCopy := append([]int(nil), ports...)
		activeEdgeAltPorts.Store(&pCopy)
	} else {
		activeEdgeAltPorts.Store(nil)
	}
}

func getActiveEdgeAltPorts() []int {
	p := activeEdgeAltPorts.Load()
	if p != nil && *p != nil {
		return append([]int(nil), (*p)...)
	}
	return nil
}

func getActiveEdgeECH() []byte {
	echP := activeEdgeECH.Load()
	if echP != nil && *echP != nil {
		return append([]byte(nil), (*echP)...)
	}
	return nil
}

func getActiveEdge() (string, string, string, net.IP) {
	addrP := activeEdgeAddr.Load()
	tokP := activeEdgeToken.Load()
	sniP := activeEdgeSNI.Load()
	ipP := activeEdgeIP.Load()
	addr, tok, sni := "", "", ""
	var ip net.IP
	if addrP != nil {
		addr = *addrP
	}
	if tokP != nil {
		tok = *tokP
	}
	if sniP != nil {
		sni = *sniP
	}
	if ipP != nil && *ipP != nil {
		ip = append(net.IP(nil), (*ipP)...)
	}
	return addr, tok, sni, ip
}

// RegisterInboundDatagramHandler 注册指定 ContextID 的数据报入站回调
func RegisterInboundDatagramHandler(contextID uint32, handler func(payload []byte)) {
	inboundDatagramHandlers.Store(contextID, handler)
}

// UnregisterInboundDatagramHandler 注销指定 ContextID 的数据报入站回调
func UnregisterInboundDatagramHandler(contextID uint32) {
	inboundDatagramHandlers.Delete(contextID)
}

func dispatchInboundDatagram(contextID uint32, payload []byte) {
	if val, ok := inboundDatagramHandlers.Load(contextID); ok && val != nil {
		handler := val.(func([]byte))
		handler(payload)
	}
}

type StreamType int

const (
	StreamTypeGeneral StreamType = 0
	StreamTypeControl StreamType = 1
	StreamTypeUDP     StreamType = 2
	StreamTypeAI      StreamType = 3
	StreamTypeBrowser StreamType = 4
)

func (s StreamType) String() string {
	switch s {
	case StreamTypeGeneral:
		return "GENERAL"
	case StreamTypeControl:
		return "CONTROL"
	case StreamTypeUDP:
		return "UDP"
	case StreamTypeAI:
		return "AI"
	case StreamTypeBrowser:
		return "BROWSER"
	default:
		return fmt.Sprintf("StreamType(%d)", s)
	}
}

type streamTarget struct {
	Raw        string
	Host       string
	Port       uint32
	StreamType StreamType
}

func isAITraffic(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	for _, domain := range builtinAIDomains() {
		if h == domain || strings.HasSuffix(h, "."+domain) {
			return true
		}
	}
	return false
}

// classifyTarget 严格按 IP 报头与 AI 规则判定，结合 splitEngine 激活多通道
func (tc *TunnelClient) classifyTarget(raw string) streamTarget {
	st := streamTarget{Raw: raw, StreamType: StreamTypeGeneral}
	host, portStr, err := net.SplitHostPort(raw)
	if err != nil {
		st.Host = raw
		host = raw
	} else {
		st.Host = host
		var port int
		fmt.Sscanf(portStr, "%d", &port)
		st.Port = uint32(port)
	}

	if isAITraffic(host) {
		st.StreamType = StreamTypeAI
	} else if tc != nil && tc.splitEngine != nil {
		ip := net.ParseIP(host)
		strat := tc.splitEngine.Match(host, ip)
		if strat == AI {
			st.StreamType = StreamTypeAI
		}
	}
	return st
}

// TunnelClient 客户端隧道管理器
type TunnelClient struct {
	pool        ISessionPool
	splitEngine *SplitEngine
	activeConn  atomic.Pointer[Client]
	ctx         context.Context
	cancel      context.CancelFunc
	cancelLoop  atomic.Pointer[context.CancelFunc]
	sessionMgr  *SessionManager
}

// SetSessionManager binds a SessionManager to TunnelClient
func (tc *TunnelClient) SetSessionManager(mgr *SessionManager) {
	tc.sessionMgr = mgr
}

// NewTunnelClient 创建隧道客户端
func NewTunnelClient(pool ISessionPool, split *SplitEngine) *TunnelClient {
	if pool == nil {
		pool = GlobalSessionPool
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &TunnelClient{
		pool:        pool,
		splitEngine: split,
		ctx:         ctx,
		cancel:      cancel,
	}
}

// Close 关闭隧道客户端及其后台接收循环
func (tc *TunnelClient) Close() {
	if tc.cancel != nil {
		tc.cancel()
	}
	if prevCancel := tc.cancelLoop.Swap(nil); prevCancel != nil {
		(*prevCancel)()
	}
}

func (tc *TunnelClient) getActiveQUICClient(ctx context.Context) (*Client, error) {
	addr, _, sni, ip := getActiveEdge()
	if addr == "" {
		return nil, fmt.Errorf("no active edge address configured")
	}
	cfg := DefaultTransportConfig(addr, sni)
	if ech := getActiveEdgeECH(); len(ech) > 0 {
		cfg.ECHConfigList = ech
	}
	if altPorts := getActiveEdgeAltPorts(); len(altPorts) > 0 {
		cfg.AltPorts = altPorts
	}
	if ip != nil {
		port := 443
		if _, portStr, err := net.SplitHostPort(addr); err == nil {
			if p, perr := strconv.Atoi(portStr); perr == nil && p > 0 {
				port = p
			}
		}
		cfg.RemoteUDPAddr = &net.UDPAddr{IP: ip, Port: port}
	}
	client, err := tc.pool.Get(ctx, cfg)
	if err != nil {
		return nil, err
	}

	// 确保该 Client 启动了数据报接收监听
	old := tc.activeConn.Swap(client)
	if old != client {
		loopCtx, loopCancel := context.WithCancel(tc.ctx)
		if prevCancel := tc.cancelLoop.Swap(&loopCancel); prevCancel != nil {
			(*prevCancel)()
		}
		go tc.runDatagramReceiveLoop(loopCtx, client)
	}
	return client, nil
}

func (tc *TunnelClient) runDatagramReceiveLoop(ctx context.Context, client *Client) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		dg, err := client.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		if len(dg) < 4 {
			continue
		}
		contextID := binary.BigEndian.Uint32(dg[:4])
		payload := dg[4:]
		dispatchInboundDatagram(contextID, payload)
	}
}

// DialTCP 拨号建立经由 AERO 隧道的 TCP 业务流连接
// 规则：单流最多重试 1 次（不睡眠，使用 select 和 ctx.Done() 退避）；单流超时绝对不调用 GlobalSessionPool.Remove！
func (tc *TunnelClient) DialTCP(ctx context.Context, target string) (net.Conn, error) {
	if tc.sessionMgr != nil {
		return tc.sessionMgr.DialTCP(ctx, target)
	}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(50 * time.Millisecond):
			}
		}

		_, err := tc.getActiveQUICClient(ctx)
		if err != nil {
			lastErr = err
			continue
		}

		return nil, fmt.Errorf("session manager required for MASQUE CONNECT")
	}

	return nil, fmt.Errorf("dial TCP %s failed (after max 1 retry): %w", target, lastErr)
}

// RegisterUDPContext 注册出站 UDP Context，服务端建立对应 UDP 端点
func (tc *TunnelClient) RegisterUDPContext(ctx context.Context, contextID uint32, targetHost string, targetPort uint32) error {
	_, err := tc.getActiveQUICClient(ctx)
	return err
}

// SendDatagram 发送 UDP 数据报
// 规则：严格发送前预检 4 + len(payload) > currentMaxDatagramSize，超限直接丢弃
func (tc *TunnelClient) SendDatagram(contextID uint32, payload []byte) error {
	maxDatagram := GetCurrentMaxDatagramSize()
	frameLen := 4 + len(payload)
	if frameLen > maxDatagram {
		// 超限立即静默丢弃
		return nil
	}

	addr, _, sni, ip := getActiveEdge()
	if addr == "" {
		return fmt.Errorf("no active edge")
	}
	cfg := DefaultTransportConfig(addr, sni)
	if ech := getActiveEdgeECH(); len(ech) > 0 {
		cfg.ECHConfigList = ech
	}
	if altPorts := getActiveEdgeAltPorts(); len(altPorts) > 0 {
		cfg.AltPorts = altPorts
	}
	if ip != nil {
		port := 443
		if _, portStr, err := net.SplitHostPort(addr); err == nil {
			if p, perr := strconv.Atoi(portStr); perr == nil && p > 0 {
				port = p
			}
		}
		cfg.RemoteUDPAddr = &net.UDPAddr{IP: ip, Port: port}
	}
	poolCtx := tc.ctx
	if poolCtx == nil {
		poolCtx = context.Background()
	}
	client, err := tc.pool.Get(poolCtx, cfg)
	if err != nil {
		return err
	}

	frame := make([]byte, frameLen)
	binary.BigEndian.PutUint32(frame[:4], contextID)
	copy(frame[4:], payload)

	return client.SendDatagram(frame)
}

// ResolveDNS 解析域名
// 严禁调用 net.DefaultResolver 造成境外 DNS 泄露！
// 纯 HTTP/3 架构下，非直连域名必须经由 HTTP/3 DoH 解析；若短流不可用则直接返回错误，由上层安全下发 198.18 Fake-IP
func (tc *TunnelClient) ResolveDNS(ctx context.Context, domain string) (net.IP, error) {
	return nil, fmt.Errorf("direct DNS resolution disabled to prevent leak; fallback to fake-ip or DoH for %s", domain)
}
