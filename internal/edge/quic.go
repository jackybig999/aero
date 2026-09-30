// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aero-protocol/aero/internal/proto"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/singleflight"
)

// ==========================================
// 1. DNS Short Stream Resolver (50 QPS, Singleflight, 300s/30s Cache)
// ==========================================

type dnsCacheEntry struct {
	ip        net.IP
	expiresAt time.Time
}

// DNSResolver resolves hostnames for tunnel DNS short streams (StreamType_CONTROL)
type DNSResolver struct {
	mu          sync.RWMutex
	cache       map[string]dnsCacheEntry
	group       singleflight.Group
	rateMu      sync.Mutex
	rateBuckets map[string]*rateTokenBucket // 50 QPS per token
	lookupFn    func(ctx context.Context, host string) ([]net.IP, error)
}

// NewDNSResolver creates a new DNSResolver
func NewDNSResolver() *DNSResolver {
	return &DNSResolver{
		cache:       make(map[string]dnsCacheEntry),
		rateBuckets: make(map[string]*rateTokenBucket),
		lookupFn: func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip4", host)
		},
	}
}

// SetLookupFunc allows injecting a mock lookup function for testing
func (r *DNSResolver) SetLookupFunc(fn func(ctx context.Context, host string) ([]net.IP, error)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lookupFn = fn
}

// checkRateLimit checks 50 QPS rate limit per token
func (r *DNSResolver) checkRateLimit(token string) bool {
	if token == "" {
		return false
	}
	r.rateMu.Lock()
	defer r.rateMu.Unlock()

	now := time.Now()
	b, ok := r.rateBuckets[token]
	if !ok {
		b = &rateTokenBucket{
			tokens:   49,
			lastTime: now,
			rate:     50,
			max:      50,
		}
		r.rateBuckets[token] = b
		return true
	}
	elapsed := now.Sub(b.lastTime).Seconds()
	b.tokens += elapsed * b.rate
	if b.tokens > b.max {
		b.tokens = b.max
	}
	b.lastTime = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// Resolve resolves domain to 4-byte IPv4 payload
func (r *DNSResolver) Resolve(token, host string) ([]byte, error) {
	if !r.checkRateLimit(token) {
		return nil, fmt.Errorf("dns rate limit exceeded")
	}

	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return nil, fmt.Errorf("empty host")
	}

	// 1. Check Cache
	now := time.Now()
	r.mu.RLock()
	entry, found := r.cache[host]
	r.mu.RUnlock()

	if found && now.Before(entry.expiresAt) {
		if entry.ip != nil {
			if ip4 := entry.ip.To4(); ip4 != nil {
				return ip4, nil
			}
		}
		return nil, fmt.Errorf("cached negative resolution")
	}

	// 2. Singleflight Resolution with 1.0s Timeout
	res, err, _ := r.group.Do(host, func() (any, error) {
		// Double check cache inside singleflight
		r.mu.RLock()
		e, ok := r.cache[host]
		r.mu.RUnlock()
		if ok && time.Now().Before(e.expiresAt) {
			if e.ip != nil {
				return e.ip.To4(), nil
			}
			return nil, fmt.Errorf("cached negative resolution")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 1000*time.Millisecond)
		defer cancel()

		r.mu.RLock()
		fn := r.lookupFn
		r.mu.RUnlock()

		ips, lookupErr := fn(ctx, host)
		r.mu.Lock()
		defer r.mu.Unlock()

		if lookupErr != nil || len(ips) == 0 {
			// Negative cache: 30s
			r.cache[host] = dnsCacheEntry{
				ip:        nil,
				expiresAt: time.Now().Add(30 * time.Second),
			}
			return nil, lookupErr
		}

		var selected net.IP
		for _, ip := range ips {
			if ip4 := ip.To4(); ip4 != nil {
				selected = ip4
				break
			}
		}
		if selected == nil {
			r.cache[host] = dnsCacheEntry{
				ip:        nil,
				expiresAt: time.Now().Add(30 * time.Second),
			}
			return nil, fmt.Errorf("no ipv4 found")
		}

		// Positive cache: 300s
		r.cache[host] = dnsCacheEntry{
			ip:        selected,
			expiresAt: time.Now().Add(300 * time.Second),
		}
		return selected, nil
	})

	if err != nil || res == nil {
		return nil, err
	}

	ipBytes, ok := res.(net.IP)
	if !ok || len(ipBytes.To4()) != 4 {
		return nil, fmt.Errorf("invalid resolved ip")
	}
	return ipBytes.To4(), nil
}

// ==========================================
// 2. QUIC Server & UDP Context Management
// ==========================================

const (
	MaxUDPContextsPerToken = 64
	DefaultMaxGlobalUDP    = 4096
)

// QUICServer manages QUIC connections, stream dispatching, UDP contexts, and DNS short streams
type QUICServer struct {
	validator        *Validator
	connLimiter      *ConnLimiter
	bandwidthLimiter *BandwidthLimiter
	dialGuard        *DialGuard
	rateLimiter      *RateLimiter
	dnsResolver      *DNSResolver

	udpMu        sync.Mutex
	tokenUDPCtx  map[string]int
	globalUDPCtx atomic.Int64
	maxGlobalUDP int64
}

// NewQUICServer creates a new QUICServer instance
func NewQUICServer(v *Validator, cl *ConnLimiter, bl *BandwidthLimiter, dg *DialGuard, rl *RateLimiter) *QUICServer {
	return &QUICServer{
		validator:        v,
		connLimiter:      cl,
		bandwidthLimiter: bl,
		dialGuard:        dg,
		rateLimiter:      rl,
		dnsResolver:      NewDNSResolver(),
		tokenUDPCtx:      make(map[string]int),
		maxGlobalUDP:     DefaultMaxGlobalUDP,
	}
}

// DNSResolver returns the internal DNSResolver
func (s *QUICServer) DNSResolver() *DNSResolver {
	return s.dnsResolver
}

func (s *QUICServer) acquireUDPSlot(token string) bool {
	if token == "" {
		return false
	}
	// Check global UDP cap
	if s.globalUDPCtx.Load() >= s.maxGlobalUDP {
		return false
	}

	s.udpMu.Lock()
	defer s.udpMu.Unlock()

	n := s.tokenUDPCtx[token]
	if n >= MaxUDPContextsPerToken {
		return false
	}
	s.tokenUDPCtx[token] = n + 1
	s.globalUDPCtx.Add(1)
	return true
}

func (s *QUICServer) releaseUDPSlot(token string) {
	if token == "" {
		return
	}
	s.udpMu.Lock()
	defer s.udpMu.Unlock()

	if n, ok := s.tokenUDPCtx[token]; ok {
		if n <= 1 {
			delete(s.tokenUDPCtx, token)
		} else {
			s.tokenUDPCtx[token] = n - 1
		}
	}
	s.globalUDPCtx.Add(-1)
}

// ==========================================
// 3. Connection-level State & UDP Context
// ==========================================

type quicConnState struct {
	conn     *quic.Conn
	server   *QUICServer
	remote   string
	mu       sync.RWMutex
	token    string
	authed   bool
	contexts map[uint32]*udpContext
	ctxMu    sync.RWMutex
	closed   atomic.Bool
	cancel   context.CancelFunc
}

type udpContext struct {
	id         uint32
	token      string
	target     string
	conn       *net.UDPConn
	lastActive atomic.Int64
	qConn      *quicConnState
	closed     atomic.Bool
}

func (u *udpContext) close() {
	if u.closed.CompareAndSwap(false, true) {
		_ = u.conn.Close()
		u.qConn.ctxMu.Lock()
		delete(u.qConn.contexts, u.id)
		u.qConn.ctxMu.Unlock()
		u.qConn.server.releaseUDPSlot(u.token)
	}
}

func (qc *quicConnState) closeAllContexts() {
	if qc.closed.CompareAndSwap(false, true) {
		qc.ctxMu.Lock()
		ctxs := make([]*udpContext, 0, len(qc.contexts))
		for _, u := range qc.contexts {
			ctxs = append(ctxs, u)
		}
		qc.contexts = make(map[uint32]*udpContext)
		qc.ctxMu.Unlock()

		for _, u := range ctxs {
			u.close()
		}
	}
}

// ==========================================
// 4. QUIC Listener & Connection Loop
// ==========================================

// DefaultQUICConfig returns the hardened QUIC configuration for AERO edge nodes
func DefaultQUICConfig() *quic.Config {
	return &quic.Config{
		Allow0RTT:                      false,
		MaxIncomingStreams:             1000,
		MaxIncomingUniStreams:          1000,
		MaxIdleTimeout:                 30 * time.Second,
		EnableDatagrams:                true,
		InitialStreamReceiveWindow:     16 * 1024 * 1024,  // 16 MB single stream window (Rule L6)
		MaxStreamReceiveWindow:         32 * 1024 * 1024,  // 32 MB
		InitialConnectionReceiveWindow: 64 * 1024 * 1024,  // 64 MB
		MaxConnectionReceiveWindow:     128 * 1024 * 1024, // 128 MB connection window (Rule L6)
		KeepAlivePeriod:                12 * time.Second,  // 12s KeepAlive
		InitialPacketSize:              1350,
	}
}

// StartQUIC starts the QUIC listener on addr
func StartQUIC(addr string, tlsConfig *tls.Config, server *QUICServer, ctx context.Context) (*quic.Listener, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	quicCfg := DefaultQUICConfig()

	quicTLS := tlsConfig.Clone()
	quicTLS.NextProtos = []string{"h3"}

	conn, err := net.ListenPacket("udp4", addr)
	if err != nil {
		return nil, fmt.Errorf("quic listen packet %s: %w", addr, err)
	}

	tr := &quic.Transport{
		Conn: conn,
		ConnContext: func(c context.Context, info *quic.ClientInfo) (context.Context, error) {
			host, _, err := net.SplitHostPort(info.RemoteAddr.String())
			if err != nil || host == "" {
				host = info.RemoteAddr.String()
			}
			if server != nil && server.rateLimiter != nil && !server.rateLimiter.Allow(host) {
				return nil, errors.New("rate limited")
			}
			return c, nil
		},
	}

	ln, err := tr.Listen(quicTLS, quicCfg)
	if err != nil {
		_ = tr.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("quic listen %s: %w", addr, err)
	}

	go func() {
		defer func() {
			_ = tr.Close()
			_ = conn.Close()
		}()
		for {
			c, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			go server.handleQUICConn(c)
		}
	}()

	return ln, nil
}

// ServeListener accepts and handles connections from an existing quic.Listener
func (s *QUICServer) ServeListener(ln *quic.Listener) error {
	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return err
		}
		go s.handleQUICConn(conn)
	}
}

// handleQUICConn is the connection-level handler
func (s *QUICServer) handleQUICConn(conn *quic.Conn) {
	ctx, cancel := context.WithCancel(conn.Context())
	defer cancel()

	qConn := &quicConnState{
		conn:     conn,
		server:   s,
		remote:   conn.RemoteAddr().String(),
		contexts: make(map[uint32]*udpContext),
		cancel:   cancel,
	}
	defer qConn.closeAllContexts()

	// 1. Single ReceiveDatagram loop per QUIC connection
	go qConn.receiveDatagramLoop(ctx)

	// 2. 45-second idle reaper for UDP contexts
	go qConn.startIdleReaper(ctx)

	sem := make(chan struct{}, 1024)

	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}

		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			_ = stream.Close()
			return
		}

		go func(st *quic.Stream) {
			defer func() { <-sem }()
			qConn.handleStream(st)
		}(stream)
	}
}

// ==========================================
// 5. Stream Handling & Flow Control Gates
// ==========================================

func (qc *quicConnState) handleStream(stream *quic.Stream) {
	defer stream.Close()

	var req proto.ConnectRequest
	if err := proto.ReadMessage(stream, &req); err != nil {
		resp := &proto.ConnectResponse{Accepted: false, Message: "read failed: " + err.Error()}
		_ = proto.WriteMessage(stream, resp)
		return
	}

	// First frame ValidateFull binds Token, subsequent streams exempt from Nonce check
	qc.mu.Lock()
	if !qc.authed {
		if !qc.server.validator.ValidateFull(req.Token, req.Timestamp, req.Nonce) {
			qc.mu.Unlock()
			resp := &proto.ConnectResponse{Accepted: false, Message: "invalid token or replay"}
			_ = proto.WriteMessage(stream, resp)
			return
		}
		qc.token = req.Token
		qc.authed = true
		qc.mu.Unlock()
	} else {
		boundToken := qc.token
		qc.mu.Unlock()

		if req.Token != boundToken || !qc.server.validator.Validate(req.Token) {
			resp := &proto.ConnectResponse{Accepted: false, Message: "invalid token or token mismatch"}
			_ = proto.WriteMessage(stream, resp)
			return
		}
	}

	token := req.Token

	var s0 *proto.StreamSpec
	if len(req.GetStreams()) > 0 {
		s0 = req.GetStreams()[0]
	}
	if s0 == nil {
		resp := &proto.ConnectResponse{Accepted: false, Message: "missing stream spec"}
		_ = proto.WriteMessage(stream, resp)
		return
	}

	streamType := s0.GetStreamType()
	streamID := s0.GetStreamId()
	targetHost := s0.GetTargetHost()
	targetPort := s0.GetTargetPort()

	switch streamType {
	case proto.StreamType_CONTROL:
		// EXEMPTION: DNS short streams MUST NOT call TryAcquire, MUST NOT occupy ConnLimiter slots, MUST NOT enter DialGuard!
		qc.server.handleDNSStream(stream, token, targetHost)
		return

	case proto.StreamType_UDP:
		// EXEMPTION: UDP Context registration streams MUST NOT call TryAcquire, MUST NOT occupy ConnLimiter slots, MUST NOT enter DialGuard!
		qc.handleUDPRegister(stream, token, streamID, targetHost, targetPort)
		return

	case proto.StreamType_GENERAL, proto.StreamType_AI, proto.StreamType_BROWSER:
		// CRITICAL GATE: ONLY for TCP streams call ConnLimiter.TryAcquire(token)
		qc.handleTCPStream(stream, token, streamID, targetHost, targetPort)
		return

	default:
		qc.handleTCPStream(stream, token, streamID, targetHost, targetPort)
		return
	}
}

// handleTCPStream handles outbound TCP streams with ConnLimiter and DialGuard
func (qc *quicConnState) handleTCPStream(stream *quic.Stream, token string, streamID uint32, host string, port uint32) {
	if host == "" || port == 0 {
		resp := &proto.ConnectResponse{Accepted: false, Message: "missing target"}
		_ = proto.WriteMessage(stream, resp)
		return
	}
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	if blocked, why := IsBlockedTarget(target); blocked {
		resp := &proto.ConnectResponse{Accepted: false, Message: "forbidden target: " + why}
		_ = proto.WriteMessage(stream, resp)
		return
	}

	// CRITICAL GATE (TCP Stream Control):
	// ONLY for TCP streams, after AcceptStream succeeds, call ConnLimiter.TryAcquire(token).
	if qc.server.connLimiter != nil {
		if !qc.server.connLimiter.TryAcquire(token) {
			// If TryAcquire returns false: gracefully reject the stream with error response, close stream, KEEP the underlying QUIC connection open.
			resp := &proto.ConnectResponse{Accepted: false, Message: "connection limit exceeded"}
			_ = proto.WriteMessage(stream, resp)
			return
		}
		// If TryAcquire returns true: execute defer ConnLimiter.Release(token) and dial outbound TCP via DialGuard.DialTimeout.
		defer qc.server.connLimiter.Release(token)
	}

	targetConn, err := qc.server.dialGuard.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		resp := &proto.ConnectResponse{Accepted: false, Message: "dial failed: " + err.Error()}
		_ = proto.WriteMessage(stream, resp)
		return
	}
	defer targetConn.Close()

	resp := &proto.ConnectResponse{
		Accepted:            true,
		SessionId:           generateSessionID(),
		HeartbeatInterval:   30,
		RecommendedProtocol: "quic",
	}
	if err := proto.WriteMessage(stream, resp); err != nil {
		return
	}

	qc.relayTCP(stream, targetConn, token, streamID)
}

func (qc *quicConnState) relayTCP(stream *quic.Stream, targetConn net.Conn, token string, streamID uint32) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)

	// A: Outbound target -> QUIC stream
	go func() {
		defer wg.Done()
		defer cancel()
		buf := make([]byte, 32768)
		seq := uint64(1)
		for {
			if ctx.Err() != nil {
				return
			}
			n, err := targetConn.Read(buf)
			if err != nil {
				return
			}
			if qc.server.bandwidthLimiter != nil {
				qc.server.bandwidthLimiter.Take(token, n)
			}
			frame := &proto.TcpFrame{StreamId: streamID, Payload: buf[:n], Sequence: seq}
			if err := proto.TypedWriteMessage(stream, proto.MsgTypeTcpFrame, frame); err != nil {
				return
			}
			seq++
		}
	}()

	// B: QUIC stream -> Outbound target
	go func() {
		defer wg.Done()
		defer cancel()
		for {
			if ctx.Err() != nil {
				return
			}
			msgType, msg, err := proto.TypedReadMessage(stream)
			if err != nil {
				return
			}
			switch msgType {
			case proto.MsgTypeTcpFrame:
				frame := msg.(*proto.TcpFrame)
				if qc.server.bandwidthLimiter != nil {
					qc.server.bandwidthLimiter.Take(token, len(frame.Payload))
				}
				if _, err := targetConn.Write(frame.Payload); err != nil {
					return
				}
			case proto.MsgTypeHeartbeat:
				hb := msg.(*proto.Heartbeat)
				ack := &proto.HeartbeatAck{Timestamp: hb.Timestamp, Sequence: hb.Sequence}
				if err := proto.TypedWriteMessage(stream, proto.MsgTypeHeartbeatAck, ack); err != nil {
					return
				}
			default:
			}
		}
	}()

	wg.Wait()
}

// handleUDPRegister registers a new UDP Context on the QUIC connection
func (qc *quicConnState) handleUDPRegister(stream *quic.Stream, token string, contextID uint32, host string, port uint32) {
	if host == "" || port == 0 {
		resp := &proto.ConnectResponse{Accepted: false, Message: "missing udp target"}
		_ = proto.WriteMessage(stream, resp)
		return
	}
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	if blocked, why := IsBlockedTarget(target); blocked {
		resp := &proto.ConnectResponse{Accepted: false, Message: "forbidden target: " + why}
		_ = proto.WriteMessage(stream, resp)
		return
	}

	qc.ctxMu.Lock()
	if _, exists := qc.contexts[contextID]; exists {
		qc.ctxMu.Unlock()
		resp := &proto.ConnectResponse{Accepted: false, Message: "context id already exists"}
		_ = proto.WriteMessage(stream, resp)
		return
	}

	// LRU eviction if slots are full (>= MaxUDPContextsPerToken)
	var lruCtx *udpContext
	if len(qc.contexts) >= MaxUDPContextsPerToken {
		var oldest int64
		for _, u := range qc.contexts {
			last := u.lastActive.Load()
			if lruCtx == nil || last < oldest {
				oldest = last
				lruCtx = u
			}
		}
	}
	qc.ctxMu.Unlock()

	if lruCtx != nil {
		lruCtx.close()
	}

	// Max 64 Contexts per Token & global UDP cap
	if !qc.server.acquireUDPSlot(token) {
		// If acquire still failed but we have contexts on this connection, evict LRU
		qc.ctxMu.Lock()
		var fallbackLRU *udpContext
		var oldest int64
		for _, u := range qc.contexts {
			last := u.lastActive.Load()
			if fallbackLRU == nil || last < oldest {
				oldest = last
				fallbackLRU = u
			}
		}
		qc.ctxMu.Unlock()
		if fallbackLRU != nil {
			fallbackLRU.close()
			if !qc.server.acquireUDPSlot(token) {
				resp := &proto.ConnectResponse{Accepted: false, Message: "udp context limit exceeded"}
				_ = proto.WriteMessage(stream, resp)
				return
			}
		} else {
			resp := &proto.ConnectResponse{Accepted: false, Message: "udp context limit exceeded"}
			_ = proto.WriteMessage(stream, resp)
			return
		}
	}

	dstAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		qc.server.releaseUDPSlot(token)
		resp := &proto.ConnectResponse{Accepted: false, Message: "resolve udp failed: " + err.Error()}
		_ = proto.WriteMessage(stream, resp)
		return
	}

	udpConn, err := net.DialUDP("udp", nil, dstAddr)
	if err != nil {
		qc.server.releaseUDPSlot(token)
		resp := &proto.ConnectResponse{Accepted: false, Message: "dial udp failed: " + err.Error()}
		_ = proto.WriteMessage(stream, resp)
		return
	}

	uCtx := &udpContext{
		id:     contextID,
		token:  token,
		target: target,
		conn:   udpConn,
		qConn:  qc,
	}
	uCtx.lastActive.Store(time.Now().UnixNano())

	qc.ctxMu.Lock()
	qc.contexts[contextID] = uCtx
	qc.ctxMu.Unlock()

	resp := &proto.ConnectResponse{
		Accepted:            true,
		SessionId:           generateSessionID(),
		HeartbeatInterval:   30,
		RecommendedProtocol: "quic",
	}
	_ = proto.WriteMessage(stream, resp)

	go uCtx.readLoop()
}

func (u *udpContext) readLoop() {
	defer u.close()

	buf := make([]byte, 65535)
	for {
		_ = u.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := u.conn.Read(buf)
		if err != nil {
			return
		}
		if n <= 0 {
			continue
		}

		u.lastActive.Store(time.Now().UnixNano())

		// Ingress/Egress packet bandwidth deduction
		if u.qConn.server.bandwidthLimiter != nil {
			u.qConn.server.bandwidthLimiter.Take(u.token, n)
		}

		// Datagram frame: [ContextID (4 bytes big-endian)][UDP Payload]
		frame := make([]byte, 4+n)
		binary.BigEndian.PutUint32(frame[:4], u.id)
		copy(frame[4:], buf[:n])

		if err := u.qConn.conn.SendDatagram(frame); err != nil {
			if u.qConn.closed.Load() {
				return
			}
		}
	}
}

// receiveDatagramLoop is the single ReceiveDatagram loop per QUIC connection
func (qc *quicConnState) receiveDatagramLoop(ctx context.Context) {
	for {
		dgram, err := qc.conn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		if len(dgram) < 4 {
			continue
		}

		ctxID := binary.BigEndian.Uint32(dgram[:4])
		payload := dgram[4:]

		qc.ctxMu.RLock()
		uCtx, ok := qc.contexts[ctxID]
		qc.ctxMu.RUnlock()

		// Unknown ContextID is silently dropped
		if !ok || uCtx == nil {
			continue
		}

		uCtx.lastActive.Store(time.Now().UnixNano())

		if qc.server.bandwidthLimiter != nil {
			qc.server.bandwidthLimiter.Take(uCtx.token, len(payload))
		}

		_, _ = uCtx.conn.Write(payload)
	}
}

// startIdleReaper closes sockets that are idle for >= 45s and reclaims slots
func (qc *quicConnState) startIdleReaper(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now().UnixNano()
			var toClose []*udpContext

			qc.ctxMu.RLock()
			for _, u := range qc.contexts {
				last := u.lastActive.Load()
				if time.Duration(now-last) > 45*time.Second {
					toClose = append(toClose, u)
				}
			}
			qc.ctxMu.RUnlock()

			for _, u := range toClose {
				u.close()
			}
		}
	}
}

// handleDNSStream handles DNS short streams
func (s *QUICServer) handleDNSStream(stream *quic.Stream, token string, targetHost string) {
	defer stream.Close()

	if targetHost == "" {
		return
	}

	ip4, err := s.dnsResolver.Resolve(token, targetHost)
	if err != nil || len(ip4) != 4 {
		// Empty on failure/timeout
		return
	}

	// 4-byte IPv4 payload on success
	_, _ = stream.Write(ip4)
}

func generateSessionID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b)
}
