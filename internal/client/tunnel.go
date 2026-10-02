// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	protocol "github.com/aero-protocol/aero/internal/proto"
)

var (
	contextIDCounter atomic.Uint32
	activeEdgeAddr   atomic.Pointer[string]
	activeEdgeToken  atomic.Pointer[string]
	activeEdgeSNI    atomic.Pointer[string]

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
func SetActiveEdge(addr, tok, sni string) {
	activeEdgeAddr.Store(&addr)
	activeEdgeToken.Store(&tok)
	activeEdgeSNI.Store(&sni)
}

func getActiveEdge() (string, string, string) {
	addrP := activeEdgeAddr.Load()
	tokP := activeEdgeToken.Load()
	sniP := activeEdgeSNI.Load()
	addr, tok, sni := "", "", ""
	if addrP != nil {
		addr = *addrP
	}
	if tokP != nil {
		tok = *tokP
	}
	if sniP != nil {
		sni = *sniP
	}
	return addr, tok, sni
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

type streamTarget struct {
	Raw        string
	Host       string
	Port       uint32
	StreamType protocol.StreamType
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
	st := streamTarget{Raw: raw, StreamType: protocol.StreamType_GENERAL}
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
		st.StreamType = protocol.StreamType_AI
	} else if tc != nil && tc.splitEngine != nil {
		ip := net.ParseIP(host)
		strat := tc.splitEngine.Match(host, ip)
		if strat == AI {
			st.StreamType = protocol.StreamType_AI
		}
	}
	return st
}

func generateNonce() []byte {
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	return nonce
}

func connectRequest(st streamTarget, streamID uint32) *protocol.ConnectRequest {
	_, tok, _ := getActiveEdge()
	return &protocol.ConnectRequest{
		Version:   "aero/2.0",
		Token:     tok,
		Nonce:     generateNonce(),
		Timestamp: uint64(time.Now().UnixMilli()),
		Streams: []*protocol.StreamSpec{{
			StreamId:   streamID,
			StreamType: st.StreamType,
			TargetHost: st.Host,
			TargetPort: st.Port,
		}},
	}
}

func aeroHandshake(stream io.ReadWriter, st streamTarget, streamID uint32) (*protocol.ConnectResponse, error) {
	req := connectRequest(st, streamID)
	if err := protocol.WriteMessage(stream, req); err != nil {
		return nil, fmt.Errorf("write ConnectRequest: %w", err)
	}
	var resp protocol.ConnectResponse
	if err := protocol.ReadMessage(stream, &resp); err != nil {
		return nil, fmt.Errorf("read ConnectResponse: %w", err)
	}
	if !resp.Accepted {
		return nil, fmt.Errorf("stream rejected: %s", resp.Message)
	}
	return &resp, nil
}

// TunnelClient 客户端隧道管理器
type TunnelClient struct {
	pool        ISessionPool
	splitEngine *SplitEngine
	activeConn  atomic.Pointer[Client]
	ctx         context.Context
	cancel      context.CancelFunc
	cancelLoop  atomic.Pointer[context.CancelFunc]
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
	addr, _, sni := getActiveEdge()
	if addr == "" {
		return nil, fmt.Errorf("no active edge address configured")
	}
	cfg := DefaultTransportConfig(addr, sni)
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
	st := tc.classifyTarget(target)

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(50 * time.Millisecond):
			}
		}

		client, err := tc.getActiveQUICClient(ctx)
		if err != nil {
			lastErr = err
			continue
		}

		stream, err := client.OpenStream(ctx)
		if err != nil {
			lastErr = err
			// 单流超时或打开失败，绝对不拆除底层物理 QUIC 连接！
			continue
		}

		streamID := contextIDCounter.Add(1)
		_ = stream.SetDeadline(time.Now().Add(4 * time.Second))
		if _, err := aeroHandshake(stream, st, streamID); err != nil {
			_ = stream.Close()
			lastErr = err
			// 单流握手超时或拒绝，绝对不调用 GlobalSessionPool.Remove！
			continue
		}
		_ = stream.SetDeadline(time.Time{})

		return newAeroStreamConn(stream, streamID, target, false), nil
	}

	return nil, fmt.Errorf("dial TCP %s failed (after max 1 retry): %w", target, lastErr)
}

// RegisterUDPContext 注册出站 UDP Context，服务端建立对应 UDP 端点
func (tc *TunnelClient) RegisterUDPContext(ctx context.Context, contextID uint32, targetHost string, targetPort uint32) error {
	client, err := tc.getActiveQUICClient(ctx)
	if err != nil {
		return err
	}

	stream, err := client.OpenStream(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()

	st := streamTarget{
		Host:       targetHost,
		Port:       targetPort,
		StreamType: protocol.StreamType_UDP,
	}

	_ = stream.SetDeadline(time.Now().Add(4 * time.Second))
	_, err = aeroHandshake(stream, st, contextID)
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

	addr, _, sni := getActiveEdge()
	if addr == "" {
		return fmt.Errorf("no active edge")
	}
	cfg := DefaultTransportConfig(addr, sni)
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

// ResolveDNS 通过隧道内 StreamType_CONTROL 短流快速解析域名
func (tc *TunnelClient) ResolveDNS(ctx context.Context, domain string) (net.IP, error) {
	client, err := tc.getActiveQUICClient(ctx)
	if err != nil {
		return nil, err
	}

	stream, err := client.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	defer stream.Close()

	streamID := contextIDCounter.Add(1)
	st := streamTarget{
		Host:       domain,
		Port:       53,
		StreamType: protocol.StreamType_CONTROL,
	}

	_ = stream.SetDeadline(time.Now().Add(2500 * time.Millisecond))
	if _, err := aeroHandshake(stream, st, streamID); err != nil {
		return nil, err
	}

	var ipBuf [4]byte
	n, rerr := io.ReadFull(stream, ipBuf[:])
	if rerr != nil || n != 4 {
		return nil, fmt.Errorf("read dns short stream response failed: %v", rerr)
	}

	return net.IP(ipBuf[:]), nil
}

type aeroStreamConn struct {
	raw      Stream
	streamID uint32
	target   string
	udp      bool
	readBuf  []byte
	readMu   sync.Mutex
	writeMu  sync.Mutex
	closed   atomic.Bool
	seq      uint64
	stopHB   chan struct{}
}

func newAeroStreamConn(raw Stream, streamID uint32, target string, udp bool) *aeroStreamConn {
	c := &aeroStreamConn{
		raw:      raw,
		streamID: streamID,
		target:   target,
		udp:      udp,
		seq:      1,
		stopHB:   make(chan struct{}),
	}
	go c.heartbeatLoop()
	return c
}

func (c *aeroStreamConn) heartbeatLoop() {
	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopHB:
			return
		case <-ticker.C:
			if c.closed.Load() {
				return
			}
			c.writeMu.Lock()
			_ = protocol.TypedWriteMessage(c.raw, protocol.MsgTypeHeartbeat, &protocol.Heartbeat{
				Timestamp: uint64(time.Now().UnixMilli()),
				Sequence:  uint32(c.seq),
			})
			c.writeMu.Unlock()
		}
	}
}

func (c *aeroStreamConn) Read(p []byte) (int, error) {
	if c.closed.Load() {
		return 0, io.EOF
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	for {
		msgType, msg, err := protocol.TypedReadMessage(c.raw)
		if err != nil {
			return 0, err
		}
		switch msgType {
		case protocol.MsgTypeTcpFrame:
			frame, ok := msg.(*protocol.TcpFrame)
			if !ok || len(frame.Payload) == 0 {
				continue
			}
			n := copy(p, frame.Payload)
			if n < len(frame.Payload) {
				c.readBuf = append(c.readBuf, frame.Payload[n:]...)
			}
			return n, nil
		case protocol.MsgTypeUdpFrame:
			frame, ok := msg.(*protocol.UdpFrame)
			if !ok || len(frame.Payload) == 0 {
				continue
			}
			n := copy(p, frame.Payload)
			if n < len(frame.Payload) {
				c.readBuf = append(c.readBuf, frame.Payload[n:]...)
			}
			return n, nil
		case protocol.MsgTypeHeartbeat:
			hb, ok := msg.(*protocol.Heartbeat)
			if ok {
				c.writeMu.Lock()
				_ = protocol.TypedWriteMessage(c.raw, protocol.MsgTypeHeartbeatAck, &protocol.HeartbeatAck{
					Timestamp: hb.Timestamp, Sequence: hb.Sequence,
				})
				c.writeMu.Unlock()
			}
		case protocol.MsgTypeHeartbeatAck:
			// 忽略保活响应
		default:
		}
	}
}

func (c *aeroStreamConn) Write(p []byte) (int, error) {
	if c.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	if len(p) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	const maxChunk = 24 * 1024
	sent := 0
	for sent < len(p) {
		end := sent + maxChunk
		if end > len(p) {
			end = len(p)
		}
		var err error
		if c.udp {
			err = protocol.TypedWriteMessage(c.raw, protocol.MsgTypeUdpFrame, &protocol.UdpFrame{
				StreamId: c.streamID, Payload: p[sent:end], SrcAddr: c.target,
			})
		} else {
			c.seq++
			err = protocol.TypedWriteMessage(c.raw, protocol.MsgTypeTcpFrame, &protocol.TcpFrame{
				StreamId: c.streamID, Payload: p[sent:end], Sequence: c.seq,
			})
		}
		if err != nil {
			return sent, err
		}
		sent = end
	}
	return len(p), nil
}

func (c *aeroStreamConn) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	select {
	case <-c.stopHB:
	default:
		close(c.stopHB)
	}
	return c.raw.Close()
}

func (c *aeroStreamConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
}

func (c *aeroStreamConn) RemoteAddr() net.Addr {
	host, portStr, err := net.SplitHostPort(c.target)
	if err == nil {
		var port int
		fmt.Sscanf(portStr, "%d", &port)
		return &net.TCPAddr{IP: net.ParseIP(host), Port: port}
	}
	return &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0}
}

func (c *aeroStreamConn) SetDeadline(t time.Time) error {
	return c.raw.SetDeadline(t)
}

func (c *aeroStreamConn) SetReadDeadline(t time.Time) error {
	return c.raw.SetReadDeadline(t)
}

func (c *aeroStreamConn) SetWriteDeadline(t time.Time) error {
	return c.raw.SetWriteDeadline(t)
}
