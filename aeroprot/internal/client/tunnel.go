// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
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

// ChainProxyConfig 链式代理配置 (静态住宅 IP 出口净化)
type ChainProxyConfig struct {
	Enabled  bool   `json:"enabled"`
	Protocol string `json:"protocol"` // "socks5" or "http"
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
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
	chainProxy  atomic.Pointer[ChainProxyConfig]
}

// SetChainProxy 配置可选的链式代理 (静态住宅 IP 出口净化)
func (tc *TunnelClient) SetChainProxy(cfg *ChainProxyConfig) {
	if cfg != nil {
		cCopy := *cfg
		tc.chainProxy.Store(&cCopy)
	} else {
		tc.chainProxy.Store(nil)
	}
}

// GetChainProxy 获取当前配置的链式代理
func (tc *TunnelClient) GetChainProxy() *ChainProxyConfig {
	cp := tc.chainProxy.Load()
	if cp != nil {
		cCopy := *cp
		return &cCopy
	}
	return nil
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
	ech := getActiveEdgeECH()
	if len(ech) > 0 {
		cfg.ECHConfigList = ech
	}
	if altPorts := getActiveEdgeAltPorts(); len(altPorts) > 0 {
		cfg.AltPorts = altPorts
	}
	port := 443
	if _, portStr, err := net.SplitHostPort(addr); err == nil {
		if p, perr := strconv.Atoi(portStr); perr == nil && p > 0 {
			port = p
		}
	}
	if ip != nil {
		cfg.RemoteUDPAddr = &net.UDPAddr{IP: ip, Port: port}
	}
	client, err := tc.pool.Get(ctx, cfg)
	if err != nil {
		return nil, err
	}

	if client.ActualPort() > 0 && client.ActualPort() != port {
		h, _, _ := net.SplitHostPort(addr)
		alignedAddr := net.JoinHostPort(h, strconv.Itoa(client.ActualPort()))
		tokP := activeEdgeToken.Load()
		tok := ""
		if tokP != nil {
			tok = *tokP
		}
		if len(ech) > 0 {
			SetActiveEdge(alignedAddr, tok, sni, ip, ech)
		} else {
			SetActiveEdge(alignedAddr, tok, sni, ip)
		}
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
// 规则：若开启链式代理，流量经由 AERO 隧道级联至静态住宅代理出站以净化出口；单流最多重试 1 次
func (tc *TunnelClient) DialTCP(ctx context.Context, target string) (net.Conn, error) {
	cp := tc.chainProxy.Load()
	if cp != nil && cp.Enabled && cp.Host != "" && cp.Port > 0 {
		return tc.dialChainTCP(ctx, target, cp)
	}

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

func (tc *TunnelClient) dialChainTCP(ctx context.Context, target string, cp *ChainProxyConfig) (net.Conn, error) {
	if tc.sessionMgr == nil {
		return nil, fmt.Errorf("session manager required for chain proxy dialing")
	}
	chainAddr := net.JoinHostPort(cp.Host, strconv.Itoa(cp.Port))
	conn, err := tc.sessionMgr.DialTCP(ctx, chainAddr)
	if err != nil {
		return nil, fmt.Errorf("dial chain proxy %s via tunnel: %w", chainAddr, err)
	}

	proto := strings.ToLower(strings.TrimSpace(cp.Protocol))
	if proto == "http" {
		if herr := httpConnectHandshake(ctx, conn, target, cp.Username, cp.Password); herr != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("http chain handshake to %s failed: %w", target, herr)
		}
		return conn, nil
	}

	// 默认为 SOCKS5
	if serr := socks5ClientHandshake(ctx, conn, target, cp.Username, cp.Password); serr != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 chain handshake to %s failed: %w", target, serr)
	}
	return conn, nil
}

func socks5ClientHandshake(ctx context.Context, conn net.Conn, target string, user, pass string) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("invalid target address: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return fmt.Errorf("invalid port in %s", target)
	}

	// 1. 发送 Method 协商
	if user != "" || pass != "" {
		if _, err := conn.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
			return fmt.Errorf("write socks5 greeting: %w", err)
		}
	} else {
		if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			return fmt.Errorf("write socks5 greeting: %w", err)
		}
	}

	methodResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, methodResp); err != nil {
		return fmt.Errorf("read socks5 method resp: %w", err)
	}
	if methodResp[0] != 0x05 {
		return fmt.Errorf("unsupported socks version: 0x%02x", methodResp[0])
	}

	// 2. 身份验证
	if methodResp[1] == 0x02 { // USERNAME/PASSWORD (RFC 1929)
		authReq := make([]byte, 0, 3+len(user)+len(pass))
		authReq = append(authReq, 0x01, byte(len(user)))
		authReq = append(authReq, []byte(user)...)
		authReq = append(authReq, byte(len(pass)))
		authReq = append(authReq, []byte(pass)...)
		if _, err := conn.Write(authReq); err != nil {
			return fmt.Errorf("write socks5 auth req: %w", err)
		}
		authResp := make([]byte, 2)
		if _, err := io.ReadFull(conn, authResp); err != nil {
			return fmt.Errorf("read socks5 auth resp: %w", err)
		}
		if authResp[1] != 0x00 {
			return fmt.Errorf("socks5 auth rejected by chain proxy: 0x%02x", authResp[1])
		}
	} else if methodResp[1] != 0x00 {
		return fmt.Errorf("unsupported socks5 auth method: 0x%02x", methodResp[1])
	}

	// 3. 发起 CONNECT 请求
	req := make([]byte, 0, 6+len(host))
	req = append(req, 0x05, 0x01, 0x00) // VER=5, CMD=CONNECT, RSV=0
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		req = append(req, 0x01) // ATYP=IPv4
		req = append(req, ip4...)
	} else if ip6 := ip.To16(); ip6 != nil && !strings.Contains(host, ".") {
		req = append(req, 0x04) // ATYP=IPv6
		req = append(req, ip6...)
	} else {
		req = append(req, 0x03, byte(len(host))) // ATYP=Domain
		req = append(req, []byte(host)...)
	}
	var pBuf [2]byte
	binary.BigEndian.PutUint16(pBuf[:], uint16(port))
	req = append(req, pBuf[:]...)

	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("write socks5 connect req: %w", err)
	}

	// 4. 读取连接响应
	respHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, respHeader); err != nil {
		return fmt.Errorf("read socks5 connect resp: %w", err)
	}
	if respHeader[1] != 0x00 {
		return fmt.Errorf("socks5 connect rejected: rep=0x%02x", respHeader[1])
	}

	// 丢弃绑定的 BND.ADDR 与 BND.PORT
	switch respHeader[3] {
	case 0x01: // IPv4
		b := make([]byte, 4+2)
		_, _ = io.ReadFull(conn, b)
	case 0x04: // IPv6
		b := make([]byte, 16+2)
		_, _ = io.ReadFull(conn, b)
	case 0x03: // Domain
		lenBuf := make([]byte, 1)
		_, _ = io.ReadFull(conn, lenBuf)
		b := make([]byte, int(lenBuf[0])+2)
		_, _ = io.ReadFull(conn, b)
	}

	return nil
}

func httpConnectHandshake(ctx context.Context, conn net.Conn, target string, user, pass string) error {
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if user != "" || pass != "" {
		cred := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		req += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", cred)
	}
	req += "Proxy-Connection: Keep-Alive\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return fmt.Errorf("write http connect req: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return fmt.Errorf("read http connect resp: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http proxy connect %s rejected: %s", target, resp.Status)
	}
	return nil
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
