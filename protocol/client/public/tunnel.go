package public

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"github.com/aero-protocol/aero-ech/internal/protocol"
	"github.com/aero-protocol/aero-ech/internal/split"
	"github.com/aero-protocol/aero-ech/internal/tun"
	"golang.org/x/net/http2"
	aeroproto "github.com/aero-protocol/proto"
)

// -----------------------------------------------------------------------------
// Source: aero_stream.go
// -----------------------------------------------------------------------------
// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");



type aeroStreamConn struct {
	raw      net.Conn
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

func openAEROStream(target string) (net.Conn, error) {
	return openAEROTyped(target, aeroproto.StreamType_GENERAL, false)
}

func openAEROUDP(target string) (net.Conn, error) {
	return openAEROTyped(target, aeroproto.StreamType_UDP, true)
}

func openAEROTyped(target string, typ aeroproto.StreamType, udp bool) (net.Conn, error) {
	tunnel, _, err := dialBestTransport(target, nil)
	if err != nil {
		return nil, err
	}
	st := classifyTarget(target)
	st.StreamType = typ
	streamID := uint32(contextIDCounter.Add(1))
	_ = tunnel.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := aeroHandshake(tunnel, st, streamID); err != nil {
		_ = tunnel.Close()
		return nil, err
	}
	_ = tunnel.SetDeadline(time.Time{})
	c := &aeroStreamConn{
		raw: tunnel, streamID: streamID, target: target, udp: udp, seq: 1,
		stopHB: make(chan struct{}),
	}
	go c.heartbeatLoop()
	return c, nil
}

func (c *aeroStreamConn) heartbeatLoop() {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	seq := uint32(0)
	for {
		select {
		case <-c.stopHB:
			return
		case <-t.C:
			if c.closed.Load() {
				return
			}
			seq++
			c.writeMu.Lock()
			_ = protocol.TypedWriteMessage(c.raw, protocol.MsgTypeHeartbeat, &aeroproto.Heartbeat{
				Timestamp: uint64(time.Now().UnixMilli()), Sequence: seq,
			})
			c.writeMu.Unlock()
		}
	}
}

func (c *aeroStreamConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.closed.Load() {
		return 0, io.EOF
	}
	for len(c.readBuf) == 0 {
		msgType, msg, err := protocol.TypedReadMessage(c.raw)
		if err != nil {
			return 0, err
		}
		switch msgType {
		case protocol.MsgTypeTcpFrame:
			f := msg.(*aeroproto.TcpFrame)
			c.readBuf = append(c.readBuf, f.Payload...)
		case protocol.MsgTypeUdpFrame:
			f := msg.(*aeroproto.UdpFrame)
			c.readBuf = append(c.readBuf, f.Payload...)
		case protocol.MsgTypeAiStreamFrame:
			f := msg.(*aeroproto.AiStreamFrame)
			c.readBuf = append(c.readBuf, f.Payload...)
		case protocol.MsgTypeHeartbeat:
			hb := msg.(*aeroproto.Heartbeat)
			c.writeMu.Lock()
			_ = protocol.TypedWriteMessage(c.raw, protocol.MsgTypeHeartbeatAck, &aeroproto.HeartbeatAck{
				Timestamp: hb.Timestamp, Sequence: hb.Sequence,
			})
			c.writeMu.Unlock()
		case protocol.MsgTypeHeartbeatAck:
		default:
		}
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *aeroStreamConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	if len(p) == 0 {
		return 0, nil
	}
	const maxChunk = 24 * 1024
	sent := 0
	for sent < len(p) {
		end := sent + maxChunk
		if end > len(p) {
			end = len(p)
		}
		var err error
		if c.udp {
			err = protocol.TypedWriteMessage(c.raw, protocol.MsgTypeUdpFrame, &aeroproto.UdpFrame{
				StreamId: c.streamID, Payload: p[sent:end], SrcAddr: c.target,
			})
		} else {
			c.seq++
			err = protocol.TypedWriteMessage(c.raw, protocol.MsgTypeTcpFrame, &aeroproto.TcpFrame{
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

func (c *aeroStreamConn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *aeroStreamConn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *aeroStreamConn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *aeroStreamConn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *aeroStreamConn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }

// -----------------------------------------------------------------------------
// Source: h2tunnel.go
// -----------------------------------------------------------------------------
// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");



// h2Tunnel 包装 HTTP/2 流为 net.Conn
//
// 核心抽象：将 HTTP/2 DATA 帧的读写伪装成标准 TCP 连接，
// 同时处理 PING/SETTINGS/RST_STREAM 等控制帧。
type h2Tunnel struct {
	conn      net.Conn
	framer    *http2.Framer
	streamID  uint32
	readBuf   bytes.Buffer
	readErr   error
	writeMu   sync.Mutex
	closed    atomic.Bool
	obfWriter *protocol.ObfuscateWriter
}

func (t *h2Tunnel) Read(p []byte) (int, error) {
	if t.readBuf.Len() > 0 {
		return t.readBuf.Read(p)
	}
	if t.readErr != nil {
		return 0, t.readErr
	}
	if t.closed.Load() {
		return 0, fmt.Errorf("tunnel closed")
	}

	for {
		frame, err := t.framer.ReadFrame()
		if err != nil {
			t.readErr = err
			return 0, err
		}

		switch f := frame.(type) {
		case *http2.DataFrame:
			if len(f.Data()) > 0 {
				t.readBuf.Write(f.Data())
				return t.readBuf.Read(p)
			}
		case *http2.HeadersFrame:
			// Trailers，忽略
		case *http2.RSTStreamFrame:
			t.readErr = fmt.Errorf("stream reset")
			return 0, t.readErr
		case *http2.GoAwayFrame:
			t.readErr = fmt.Errorf("goaway")
			return 0, t.readErr
		case *http2.SettingsFrame:
			if !f.IsAck() {
				t.framer.WriteSettingsAck()
			}
		case *http2.PingFrame:
			t.framer.WritePing(true, f.Data)
		}
	}
}

func (t *h2Tunnel) Write(p []byte) (int, error) {
	written := 0

	for len(p) > 0 {
		n := t.randomChunkSize()
		if n > len(p) {
			n = len(p)
		}

		if t.closed.Load() {
			return written, fmt.Errorf("tunnel closed")
		}
		t.writeMu.Lock()
		err := t.framer.WriteData(t.streamID, false, p[:n])
		t.writeMu.Unlock()

		if err != nil {
			return written, err
		}

		written += n
		p = p[n:]

		if len(p) > 0 {
			t.randomDelay()
		}
	}

	return written, nil
}

func (t *h2Tunnel) Close() error {
	if t.closed.Swap(true) {
		return nil
	}
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	err1 := t.framer.WriteRSTStream(t.streamID, http2.ErrCodeCancel)
	err2 := t.conn.Close()
	if err2 != nil {
		return err2
	}
	return err1
}

func (t *h2Tunnel) LocalAddr() net.Addr                { return t.conn.LocalAddr() }
func (t *h2Tunnel) RemoteAddr() net.Addr               { return t.conn.RemoteAddr() }
func (t *h2Tunnel) SetDeadline(d time.Time) error      { return t.conn.SetDeadline(d) }
func (t *h2Tunnel) SetReadDeadline(d time.Time) error  { return t.conn.SetReadDeadline(d) }
func (t *h2Tunnel) SetWriteDeadline(d time.Time) error { return t.conn.SetWriteDeadline(d) }

func (t *h2Tunnel) randomChunkSize() int {
	if t.obfWriter == nil {
		return 16384
	}
	return t.obfWriter.RandomChunkSize()
}

func (t *h2Tunnel) randomDelay() {
	if t.obfWriter != nil {
		t.obfWriter.RandomDelay()
	}
}

// 确保 h2Tunnel 实现了 net.Conn
var _ net.Conn = (*h2Tunnel)(nil)

// -----------------------------------------------------------------------------
// Source: tunnel_handshake.go
// -----------------------------------------------------------------------------
// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");



func connectRequest(st streamTarget, streamID uint32) *aeroproto.ConnectRequest {
	return &aeroproto.ConnectRequest{
		Version:      "aero/2.0",
		Token:        *token,
		Nonce:        generateNonce(),
		Timestamp:    uint64(time.Now().UnixMilli()),
		IspHint:      detectedISP.String(),
		TestedPorts:  testedPorts,
		UdpAvailable: udpAvailable,
		Streams: []*aeroproto.StreamSpec{{
			StreamId:   streamID,
			StreamType: st.StreamType,
			TargetHost: st.Host,
			TargetPort: st.Port,
		}},
	}
}

func marshalConnectRequest(st streamTarget, streamID uint32) []byte {
	var buf bytes.Buffer
	if err := protocol.WriteMessage(&buf, connectRequest(st, streamID)); err != nil {
		return nil
	}
	return buf.Bytes()
}

func aeroHandshakeRead(tunnel net.Conn) (*aeroproto.ConnectResponse, error) {
	var resp aeroproto.ConnectResponse
	if err := protocol.ReadMessage(tunnel, &resp); err != nil {
		return nil, fmt.Errorf("read ConnectResponse: %w", err)
	}
	if !resp.Accepted {
		return nil, fmt.Errorf("rejected: %s", resp.Message)
	}
	// Keep hot path quiet — browsers open dozens of streams; full log kills I/O.
	return &resp, nil
}

// aeroHandshake 在已建立的传输上完成 ConnectRequest/Response
func aeroHandshake(tunnel net.Conn, st streamTarget, streamID uint32) (*aeroproto.ConnectResponse, error) {
	if err := protocol.WriteMessage(tunnel, connectRequest(st, streamID)); err != nil {
		return nil, fmt.Errorf("write ConnectRequest: %w", err)
	}
	return aeroHandshakeRead(tunnel)
}

// maybeSendAIHeader AI 流发送 AiStreamHeader（断线续传元数据）
func maybeSendAIHeader(tunnel net.Conn, st streamTarget, streamID uint32, contextID string) {
	if st.StreamType != aeroproto.StreamType_AI || contextID == "" {
		return
	}
	_, already := aiContextSent.Load(contextID)
	if !already {
		aiContextSent.Store(contextID, struct{}{})
	}
	header := &aeroproto.AiStreamHeader{
		StreamId:  streamID,
		ModelName: inferModelName(st.Host),
		ContextId: contextID,
		Resume:    already,
	}
	if err := protocol.TypedWriteMessage(tunnel, protocol.MsgTypeAiStreamHeader, header); err != nil {
		log.Printf("[AI] write AiStreamHeader failed: %v", err)
		return
	}
	log.Printf("[AI] StreamHeader context=%s resume=%v", contextID, already)
}

// -----------------------------------------------------------------------------
// Source: tunnel_heartbeat.go
// -----------------------------------------------------------------------------
// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");



func runHeartbeatLoop(
	ctx context.Context,
	cancel context.CancelFunc,
	tunnel net.Conn,
	interval, timeout time.Duration,
	lastAck *time.Time,
	ackMu *sync.Mutex,
	hbSent *time.Time,
	rttMu *sync.Mutex,
	onTimeout func(),
) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	seq := uint32(0)
	// Wait one full interval before first kill check so brand-new tunnels
	// are not torn down before the first HB/ACK round-trip.
	armed := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ackMu.Lock()
			elapsed := time.Since(*lastAck)
			ackMu.Unlock()
			rttMu.Lock()
			sent := *hbSent
			rttMu.Unlock()
			if armed && !sent.IsZero() && elapsed > timeout {
				log.Printf("[HEARTBEAT] timeout no ack for %v — will redial", elapsed)
				if onTimeout != nil {
					onTimeout()
				}
				cancel()
				return
			}
			seq++
			rttMu.Lock()
			*hbSent = time.Now()
			rttMu.Unlock()
			hb := &aeroproto.Heartbeat{
				Timestamp: uint64(time.Now().UnixMilli()),
				Sequence:  seq,
			}
			if err := protocol.TypedWriteMessage(tunnel, protocol.MsgTypeHeartbeat, hb); err != nil {
				cancel()
				return
			}
			armed = true
			// Quiet: per-stream HB ack logs flood the GUI when 20+ tabs are open.
		}
	}
}

// -----------------------------------------------------------------------------
// Source: tunnel_loop.go
// -----------------------------------------------------------------------------
// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");



// replyFn is called once when the first hop is ready (ok) or failed (!ok).
type replyFn func(ok bool)

// isEdgeSelfTarget: traffic to our own edge host (any port) must not re-enter the tunnel.
func isEdgeSelfTarget(target string) bool {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}
	host = strings.Trim(host, "[]")
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	if edgeAddr != nil && *edgeAddr != "" {
		eh, _, e := net.SplitHostPort(*edgeAddr)
		if e != nil {
			eh = *edgeAddr
		}
		eh = strings.ToLower(strings.Trim(eh, "[]"))
		if host == eh {
			return true
		}
	}
	if publicName != nil && *publicName != "" {
		if host == strings.ToLower(*publicName) {
			return true
		}
	}
	return false
}

// isSelfListenTarget is true when dialing would loop back into aero-ech itself.
// System proxy set to 127.0.0.1:55555 caused floods of HEAD / -> 127.0.0.1:55555
// which DIRECT-dialed the mixed port and exhausted sockets (browser dead, chat dead).
func isSelfListenTarget(target string) bool {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		port = ""
	}
	host = strings.Trim(host, "[]")
	h := strings.ToLower(host)
	if h != "127.0.0.1" && h != "localhost" && h != "::1" && h != "0.0.0.0" {
		return false
	}
	// our control + mixed ports
	switch port {
	case "55555", "19877", "19876", "55556":
		return true
	case "":
		// bare host without port — still treat local loop as self-ish for safety when path is empty
		return false
	default:
		// any dial to loopback that matches our listen address
		if listenAddr != nil {
			_, lp, e := net.SplitHostPort(*listenAddr)
			if e == nil && lp == port {
				return true
			}
		}
	}
	return false
}

// serveTarget：已解析目标后的公共转发路径（SOCKS / HTTP CONNECT 共用）
func serveTarget(client net.Conn, target string, ready replyFn) {
	if ready == nil {
		ready = func(bool) {}
	}
	// Fake-IP (198.18.0.0/15) 内存 0ms 快速反查：还原真实域名
	host, port, err := net.SplitHostPort(target)
	if err == nil {
		if ip := net.ParseIP(host); ip != nil {
			if v4 := ip.To4(); v4 != nil && v4[0] == 198 && (v4[1] == 18 || v4[1] == 19) {
				if realDomain, ok := tun.DefaultFakeIPTable.Lookup(ip); ok {
					target = net.JoinHostPort(realDomain, port)
				}
			}
		}
	}

	if isSelfListenTarget(target) {
		log.Printf("[PROXY] reject self-loop target %s (prevent socket exhaustion)", target)
		ready(false)
		_ = client.Close()
		return
	}
	// Never proxy the edge host itself (panel / box on same domain) — causes loops & 503.
	if isEdgeSelfTarget(target) {
		log.Printf("[SPLIT] DIRECT edge-self: %s", target)
		handleDirect(client, target, ready)
		return
	}

	if splitEngine != nil {
		strategy := splitEngine.MatchDomain(target)
		if strategy == split.DIRECT {
			handleDirect(client, target, ready)
			return
		}
	}

	// Mixed/HTTP/SOCKS proxy path = pure TCP byte relay (same as Clash/box).
	// 保留 AI 和 UDP 流类型特征供 QoS / 零延迟调度
	st := classifyTarget(target)

	replied := false
	maxAttempts := 2
	if edgePool != nil && edgePool.Count() > 2 {
		maxAttempts = 3
	}
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if edgePool != nil && edgePool.Count() > 1 {
			best := edgePool.Best()
			current := getEdgeAddr()
			if best != nil && best.Address != current && best.Reachable {
				log.Printf("[POOL] auto switch edge %s -> %s", current, best.Address)
				switchActiveNode(best)
			}
		}

		streamID := uint32(contextIDCounter.Add(1))
		preface := marshalConnectRequest(st, streamID)
		tunnel, usedProto, err := dialBestTransport(target, preface)
		if err != nil {
			log.Printf("dial failed attempt=%d: %v", attempt, err)
			if edgePool != nil {
				edgePool.MarkFail(getEdgeAddr())
			}
			if attempt >= maxAttempts-1 && !replied {
				ready(false)
				replied = true
				_ = client.Close()
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}

		_ = tunnel.SetDeadline(time.Now().Add(10 * time.Second))
		var resp *aeroproto.ConnectResponse
		if usedProto == "tcp_h2" && len(preface) > 0 {
			resp, err = aeroHandshakeRead(tunnel)
		} else {
			resp, err = aeroHandshake(tunnel, st, streamID)
		}
		_ = tunnel.SetDeadline(time.Time{})
		if err != nil {
			log.Printf("handshake failed: %v", err)
			tunnel.Close()
			if edgePool != nil {
				edgePool.MarkFail(getEdgeAddr())
			}
			if attempt >= maxAttempts-1 && !replied {
				ready(false)
				_ = client.Close()
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if !replied {
			ready(true)
			replied = true
		}

		reportTunnelUp(getEdgeAddr(), usedProto)

		hb := time.Duration(resp.HeartbeatInterval) * time.Second
		// After HTTP 200 the browser already started TLS. Do not redial this CONNECT.
		_ = runTunnelRelay(relayParams{
			Client:     client,
			Tunnel:     tunnel,
			StreamID:   streamID,
			StreamType: st.StreamType,
			SessionID:  resp.SessionId,
			TargetHost: st.Host,
			TargetPort: uint16(st.Port),
			UsedProto:  usedProto,
			HBInterval: hb,
			Bridge:     nil,
			Detector:   nil,
		})
		tunnel.Close()
		return
	}
	if !replied {
		ready(false)
	}
}
