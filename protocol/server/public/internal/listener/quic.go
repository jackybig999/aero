// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package listener

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aero-protocol/aero-edge/public/internal/auth"
	"github.com/aero-protocol/aero-edge/public/internal/traffic"
	protocol "github.com/aero-protocol/proto"
	"github.com/quic-go/quic-go"
)

// QUICHandler QUIC 连接处理器接口
type QUICHandler interface {
	// HandleAEROStream 处理 QUIC 流上的 AERO 协议
	HandleAEROStream(stream net.Conn, remoteAddr string)
}

// quicAEROHandler 适配 QUIC 流到 AERO 协议处理
type quicAEROHandler struct {
	validator *auth.Validator
}

// NewQUICHandler 创建 QUIC AERO 处理器
func NewQUICHandler(validator *auth.Validator) QUICHandler {
	return &quicAEROHandler{validator: validator}
}

var quicBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32768)
		return &b
	},
}

// HandleAEROStream 在 QUIC 流上处理 AERO 协议并完成数据双向转发
func (h *quicAEROHandler) HandleAEROStream(stream net.Conn, remoteAddr string) {
	defer stream.Close()

	// === AERO Protobuf 握手 ===
	var req protocol.ConnectRequest
	if err := protocol.ReadMessage(stream, &req); err != nil {
		log.Printf("[QUIC] read ConnectRequest failed: %v", remoteAddr)
		resp := &protocol.ConnectResponse{Accepted: false, Message: "read failed"}
		_ = protocol.WriteMessage(stream, resp)
		return
	}

	if !h.validator.ValidateFull(req.Token, req.Timestamp, req.Nonce) {
		log.Printf("[QUIC] auth failed: invalid token or replay from %s", remoteAddr)
		resp := &protocol.ConnectResponse{Accepted: false, Message: "invalid token or replay"}
		_ = protocol.WriteMessage(stream, resp)
		return
	}

	target := ""
	streamID := uint32(1)
	streamType := protocol.StreamType_GENERAL
	if len(req.GetStreams()) > 0 {
		s0 := req.GetStreams()[0]
		streamID = s0.GetStreamId()
		if s0.GetStreamType() != protocol.StreamType_GENERAL {
			streamType = s0.GetStreamType()
		}
		if s0.GetTargetHost() != "" && s0.GetTargetPort() != 0 {
			target = net.JoinHostPort(s0.GetTargetHost(), fmt.Sprintf("%d", s0.GetTargetPort()))
		}
	}

	if target == "" {
		log.Printf("[QUIC] target missing from %s", remoteAddr)
		resp := &protocol.ConnectResponse{Accepted: false, Message: "missing target"}
		_ = protocol.WriteMessage(stream, resp)
		return
	}

	if blocked, why := traffic.IsBlockedTarget(target); blocked {
		log.Printf("[QUIC] blocked target %s (%s) from %s", target, why, remoteAddr)
		resp := &protocol.ConnectResponse{Accepted: false, Message: "forbidden target"}
		_ = protocol.WriteMessage(stream, resp)
		return
	}

	network := "tcp"
	if streamType == protocol.StreamType_UDP {
		network = "udp"
	}

	targetConn, err := net.DialTimeout(network, target, 10*time.Second)
	if err != nil {
		log.Printf("[QUIC] dial target %s (%s) failed: %v", target, network, err)
		resp := &protocol.ConnectResponse{Accepted: false, Message: "dial failed: " + err.Error()}
		_ = protocol.WriteMessage(stream, resp)
		return
	}
	defer targetConn.Close()

	resp := &protocol.ConnectResponse{
		Accepted:            true,
		SessionId:           generateSessionID(),
		HeartbeatInterval:   30,
		RecommendedProtocol: "quic",
	}
	if err := protocol.WriteMessage(stream, resp); err != nil {
		log.Printf("[QUIC] write ConnectResponse failed: %v", err)
		return
	}
	log.Printf("[QUIC] tunnel established from %s -> %s (proto=quic stream=%d type=%v)", remoteAddr, target, streamID, streamType)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var lastHB, lastAct atomic.Int64
	now := time.Now().UnixNano()
	lastHB.Store(now)
	lastAct.Store(now)

	var wg sync.WaitGroup
	wg.Add(2)

	// A: 目标出站 -> QUIC stream
	go func() {
		defer wg.Done()
		defer cancel()
		bufPtr := quicBufPool.Get().(*[]byte)
		buf := *bufPtr
		defer quicBufPool.Put(bufPtr)
		seq := uint64(1)
		for {
			if ctx.Err() != nil {
				return
			}
			n, err := targetConn.Read(buf)
			if err != nil {
				return
			}
			lastAct.Store(time.Now().UnixNano())
			if streamType == protocol.StreamType_UDP {
				frame := &protocol.UdpFrame{StreamId: streamID, Payload: buf[:n], SrcAddr: target}
				if err := protocol.TypedWriteMessage(stream, protocol.MsgTypeUdpFrame, frame); err != nil {
					return
				}
			} else {
				frame := &protocol.TcpFrame{StreamId: streamID, Payload: buf[:n], Sequence: seq}
				if err := protocol.TypedWriteMessage(stream, protocol.MsgTypeTcpFrame, frame); err != nil {
					return
				}
				seq++
			}
		}
	}()

	// B: QUIC stream -> 目标出站
	go func() {
		defer wg.Done()
		defer cancel()
		for {
			if ctx.Err() != nil {
				return
			}
			msgType, msg, err := protocol.TypedReadMessage(stream)
			if err != nil {
				return
			}
			switch msgType {
			case protocol.MsgTypeTcpFrame:
				frame := msg.(*protocol.TcpFrame)
				lastAct.Store(time.Now().UnixNano())
				if _, err := targetConn.Write(frame.Payload); err != nil {
					return
				}
			case protocol.MsgTypeUdpFrame:
				frame := msg.(*protocol.UdpFrame)
				lastAct.Store(time.Now().UnixNano())
				if _, err := targetConn.Write(frame.Payload); err != nil {
					return
				}
			case protocol.MsgTypeHeartbeat:
				hb := msg.(*protocol.Heartbeat)
				tNow := time.Now().UnixNano()
				lastHB.Store(tNow)
				lastAct.Store(tNow)
				ack := &protocol.HeartbeatAck{Timestamp: hb.Timestamp, Sequence: hb.Sequence}
				if err := protocol.TypedWriteMessage(stream, protocol.MsgTypeHeartbeatAck, ack); err != nil {
					return
				}
			default:
			}
		}
	}()

	// C: 活性保活与超时判定
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				tNow := time.Now()
				if tNow.Sub(time.Unix(0, lastHB.Load())) > 90*time.Second {
					cancel()
					return
				}
				if tNow.Sub(time.Unix(0, lastAct.Load())) > 15*time.Minute {
					cancel()
					return
				}
			}
		}
	}()

	wg.Wait()
}

func generateSessionID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b)
}

// StartQUIC 启动 QUIC 服务端监听
func StartQUIC(addr string, tlsConfig *tls.Config, handler QUICHandler) (*quic.Listener, error) {
	// 铁律 L6：显式声明 16MB/128MB 跨洋超大接收窗口
	quicCfg := &quic.Config{
		MaxIncomingStreams:             1000,
		MaxIncomingUniStreams:          1000,
		MaxIdleTimeout:                 60 * time.Second,
		EnableDatagrams:                true,
		InitialStreamReceiveWindow:     16 * 1024 * 1024,  // 16 MB 单流窗口 (Rule L6)
		MaxStreamReceiveWindow:         32 * 1024 * 1024,  // 32 MB
		InitialConnectionReceiveWindow: 64 * 1024 * 1024,  // 64 MB
		MaxConnectionReceiveWindow:     128 * 1024 * 1024, // 128 MB 连接级窗口 (Rule L6)
		KeepAlivePeriod:                20 * time.Second,  // 20s 强制保活防 NAT 映射超时
		InitialPacketSize:              1350,              // 防分片 MTU 限制
	}

	// 纯正 HTTP/3 契约：独立克隆 TLS 配置，强制仅声明 h3，严禁混入 h2/http1.1
	quicTLS := tlsConfig.Clone()
	quicTLS.NextProtos = []string{"h3"}

	ln, err := quic.ListenAddr(addr, quicTLS, quicCfg)
	if err != nil {
		return nil, fmt.Errorf("quic listen %s: %w", addr, err)
	}

	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				log.Printf("[QUIC] accept error: %v", err)
				return
			}
			go handleQUICConn(conn, handler)
		}
	}()

	return ln, nil
}

func handleQUICConn(conn *quic.Conn, handler QUICHandler) {
	remoteAddr := conn.RemoteAddr().String()
	log.Printf("[QUIC] connection from %s", remoteAddr)

	// 限制每个 QUIC 连接的并发 stream 数（扩充至 1024 与 MaxIncomingStreams=1000 规格严密匹配）
	sem := make(chan struct{}, 1024)

	for {
		stream, err := conn.AcceptStream(conn.Context())
		if err != nil {
			log.Printf("[QUIC] accept stream finished for %s: %v", remoteAddr, err)
			return
		}

		sem <- struct{}{}
		go func(s *quic.Stream) {
			defer func() { <-sem }()
			wrapper := &quicStreamWrapper{
				stream:     s,
				localAddr:  conn.LocalAddr(),
				remoteAddr: conn.RemoteAddr(),
			}
			handler.HandleAEROStream(wrapper, remoteAddr)
		}(stream)
	}
}

// quicStreamWrapper 包装 quic.Stream 为 net.Conn
type quicStreamWrapper struct {
	stream     *quic.Stream
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (q *quicStreamWrapper) Read(p []byte) (int, error)         { return q.stream.Read(p) }
func (q *quicStreamWrapper) Write(p []byte) (int, error)        { return q.stream.Write(p) }
func (q *quicStreamWrapper) Close() error                       { return q.stream.Close() }
func (q *quicStreamWrapper) LocalAddr() net.Addr                { return q.localAddr }
func (q *quicStreamWrapper) RemoteAddr() net.Addr               { return q.remoteAddr }
func (q *quicStreamWrapper) SetDeadline(t time.Time) error      { return q.stream.SetDeadline(t) }
func (q *quicStreamWrapper) SetReadDeadline(t time.Time) error  { return q.stream.SetReadDeadline(t) }
func (q *quicStreamWrapper) SetWriteDeadline(t time.Time) error { return q.stream.SetWriteDeadline(t) }
