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
	"time"

	"github.com/aero-protocol/aero-edge/internal/auth"
	"github.com/aero-protocol/aero-edge/internal/protocol"
	aeroproto "github.com/aero-protocol/proto"
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

// HandleAEROStream 在 QUIC 流上处理 AERO 协议
func (h *quicAEROHandler) HandleAEROStream(stream net.Conn, remoteAddr string) {
	defer stream.Close()

	// === AERO Protobuf 握手 ===
	var req aeroproto.ConnectRequest
	if err := protocol.ReadMessage(stream, &req); err != nil {
		log.Printf("[QUIC] read ConnectRequest failed: %v", remoteAddr)
		resp := &aeroproto.ConnectResponse{Accepted: false, Message: "read failed"}
		protocol.WriteMessage(stream, resp)
		return
	}

	if !h.validator.ValidateFull(req.Token, req.Timestamp, req.Nonce) {
		log.Printf("[QUIC] auth failed: invalid token or replay from %s", remoteAddr)
		resp := &aeroproto.ConnectResponse{Accepted: false, Message: "invalid token or replay"}
		protocol.WriteMessage(stream, resp)
		return
	}

	// 简化的响应（不实现完整的目标转发，仅认证通过）
	resp := &aeroproto.ConnectResponse{
		Accepted:          true,
		SessionId:         generateSessionID(),
		HeartbeatInterval: 30,
		RecommendedProtocol: "quic",
	}
	if err := protocol.WriteMessage(stream, resp); err != nil {
		log.Printf("[QUIC] write ConnectResponse failed: %v", err)
		return
	}
	log.Printf("[QUIC] handshake accepted from %s", remoteAddr)

	// TODO: 进入消息路由循环（TcpFrame/Heartbeat/UdpFrame 等）
	// 当前简化版只处理握手，完整转发逻辑与 HTTP/2 CONNECT 后相同
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
	quicCfg := &quic.Config{
		MaxIncomingStreams:    1000,
		MaxIncomingUniStreams: 1000,
		MaxIdleTimeout:        60 * time.Second,
		EnableDatagrams:       true,
	}

	// 公网 ALPN 仅 h3（无私有标识）
	hasH3 := false
	for _, proto := range tlsConfig.NextProtos {
		if proto == "h3" {
			hasH3 = true
			break
		}
	}
	if !hasH3 {
		nextProtos := make([]string, len(tlsConfig.NextProtos)+1)
		copy(nextProtos, tlsConfig.NextProtos)
		nextProtos[len(tlsConfig.NextProtos)] = "h3"
		tlsConfig.NextProtos = nextProtos
	}

	ln, err := quic.ListenAddr(addr, tlsConfig, quicCfg)
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

	// 限制每个 QUIC 连接的并发 stream 数
	sem := make(chan struct{}, 100)

	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			log.Printf("[QUIC] accept stream error: %v", err)
			return
		}

		sem <- struct{}{}
		go func(s *quic.Stream) {
			defer func() { <-sem }()
			wrapper := &quicStreamWrapper{stream: s}
			handler.HandleAEROStream(wrapper, remoteAddr)
		}(stream)
	}
}

// quicStreamWrapper 包装 quic.Stream 为 net.Conn
type quicStreamWrapper struct {
	stream *quic.Stream
}

func (q *quicStreamWrapper) Read(p []byte) (int, error)  { return q.stream.Read(p) }
func (q *quicStreamWrapper) Write(p []byte) (int, error) { return q.stream.Write(p) }
func (q *quicStreamWrapper) Close() error                { return q.stream.Close() }
func (q *quicStreamWrapper) LocalAddr() net.Addr         { return nil }
func (q *quicStreamWrapper) RemoteAddr() net.Addr        { return nil }
func (q *quicStreamWrapper) SetDeadline(t time.Time) error      { return nil }
func (q *quicStreamWrapper) SetReadDeadline(t time.Time) error  { return nil }
func (q *quicStreamWrapper) SetWriteDeadline(t time.Time) error { return nil }
