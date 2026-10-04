// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/connect-ip-go"
	"github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

// Session represents an active HTTP/3 connection to an edge node, supporting
// standard CONNECT, MASQUE CONNECT-UDP, CONNECT-IP, DoH (/dns-query), and /healthz ping.
type Session struct {
	client        *Client
	h3Conn        *http3.ClientConn
	masqueConn    *masque.ClientConn
	connectIPConn *connectip.ClientConn
	token         string
	addr          string
	sni           string
	nonceSent     atomic.Bool
	draining      atomic.Bool
	closed        atomic.Bool
	closeOnce     sync.Once
	tcpDialer     func(ctx context.Context, target string) (net.Conn, error)
	onClose       func()
}

// NewSession creates a new Session from an existing Client connection.
func NewSession(client *Client, token, addr, sni string) (*Session, error) {
	if client == nil || client.Conn() == nil {
		return nil, errors.New("client connection is nil")
	}

	tr := &http3.Transport{
		EnableDatagrams: true,
		TLSClientConfig: client.config.TLSConfig,
		QUICConfig: &quic.Config{
			EnableDatagrams:                true,
			KeepAlivePeriod:                10 * time.Second,
			MaxIdleTimeout:                 90 * time.Second,
			InitialStreamReceiveWindow:     16 * 1024 * 1024,
			MaxStreamReceiveWindow:         32 * 1024 * 1024,
			InitialConnectionReceiveWindow: 32 * 1024 * 1024,
			MaxConnectionReceiveWindow:     64 * 1024 * 1024,
		},
	}

	h3Conn := tr.NewClientConn(client.Conn())
	masqueConn := masque.NewClientConn(h3Conn)
	connectIPConn := connectip.NewClientConn(h3Conn)

	return &Session{
		client:        client,
		h3Conn:        h3Conn,
		masqueConn:    masqueConn,
		connectIPConn: connectIPConn,
		token:         token,
		addr:          addr,
		sni:           sni,
	}, nil
}

// MarkDraining marks the session as draining (no new streams accepted, existing streams continue).
func (s *Session) MarkDraining() {
	s.draining.Store(true)
}

// IsDraining reports whether the session is currently in draining mode.
func (s *Session) IsDraining() bool {
	return s.draining.Load()
}

// setAuthHeaders attaches authentication headers:
// - Always: Authorization: Bearer <token>
// - First request on connection: Aero-Timestamp (ms), Aero-Nonce (32 hex chars)
func (s *Session) setAuthHeaders(hdr http.Header) {
	hdr.Set("Authorization", "Bearer "+s.token)
	if s.nonceSent.CompareAndSwap(false, true) {
		ts := time.Now().UnixMilli()
		hdr.Set("Aero-Timestamp", strconv.FormatInt(ts, 10))
		nonce := make([]byte, 32)
		_, _ = rand.Read(nonce)
		hdr.Set("Aero-Nonce", hex.EncodeToString(nonce))
	}
}

// DialTCP dials an outbound TCP stream over HTTP/3 standard CONNECT (no :protocol).
func (s *Session) DialTCP(ctx context.Context, target string) (net.Conn, error) {
	if s.closed.Load() {
		return nil, net.ErrClosed
	}
	if s.draining.Load() {
		return nil, errors.New("session is draining")
	}

	if s.tcpDialer != nil {
		return s.tcpDialer(ctx, target)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "//"+target, nil)
	if err != nil {
		return nil, fmt.Errorf("create connect request: %w", err)
	}
	req.Proto = "HTTP/1.1" // Ensures standard CONNECT without :protocol
	s.setAuthHeaders(req.Header)

	str, err := s.h3Conn.OpenRequestStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("open h3 request stream: %w", err)
	}

	if err := str.SendRequestHeader(req); err != nil {
		_ = str.Close()
		return nil, fmt.Errorf("send connect header: %w", err)
	}

	resp, err := str.ReadResponse()
	if err != nil {
		_ = str.Close()
		return nil, fmt.Errorf("read connect response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		_ = str.Close()
		return nil, fmt.Errorf("connect %s rejected: %d %s", target, resp.StatusCode, resp.Status)
	}

	return newH3StreamConn(str, target), nil
}

// DialMASQUE dials a CONNECT-UDP proxied UDP connection using masque-go.
func (s *Session) DialMASQUE(ctx context.Context, target string) (*masque.Conn, error) {
	if s.closed.Load() {
		return nil, net.ErrClosed
	}

	tmpl := uritemplate.MustNew("https://" + s.sni + "/.well-known/masque/udp/{target_host}/{target_port}/")
	mreq, err := masque.NewRequest(ctx, tmpl, target)
	if err != nil {
		return nil, fmt.Errorf("create masque request: %w", err)
	}
	s.setAuthHeaders(mreq.Header())

	mconn, resp, err := s.masqueConn.Dial(mreq)
	if err != nil {
		return nil, fmt.Errorf("dial masque: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = mconn.Close()
		return nil, fmt.Errorf("connect-udp %s rejected: %d %s", target, resp.StatusCode, resp.Status)
	}

	return mconn, nil
}

// DialUDP dials a CONNECT-UDP proxied connection and wraps it in net.Conn.
func (s *Session) DialUDP(ctx context.Context, target string) (net.Conn, error) {
	mconn, err := s.DialMASQUE(ctx, target)
	if err != nil {
		return nil, err
	}
	return newMasqueNetConn(mconn, target), nil
}

// DialIP establishes a CONNECT-IP tunnel session using connect-ip-go.
func (s *Session) DialIP(ctx context.Context) (*connectip.Conn, []netip.Prefix, error) {
	if s.closed.Load() {
		return nil, nil, net.ErrClosed
	}

	tmpl := uritemplate.MustNew("https://" + s.sni + "/.well-known/masque/ip/*/*/")
	ipReq, err := connectip.NewRequest(ctx, tmpl)
	if err != nil {
		return nil, nil, fmt.Errorf("create connect-ip request: %w", err)
	}
	s.setAuthHeaders(ipReq.Header())

	ipConn, resp, err := s.connectIPConn.Dial(ipReq)
	if err != nil {
		return nil, nil, fmt.Errorf("dial connect-ip: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = ipConn.Close()
		return nil, nil, fmt.Errorf("connect-ip rejected: %d %s", resp.StatusCode, resp.Status)
	}

	assignCtx, assignCancel := context.WithTimeout(ctx, 5*time.Second)
	defer assignCancel()
	assigned, err := ipConn.ReceiveAddressAssignment(assignCtx)
	if err != nil {
		_ = ipConn.Close()
		return nil, nil, fmt.Errorf("receive address assignment: %w", err)
	}

	prefixes := make([]netip.Prefix, len(assigned))
	for i, a := range assigned {
		prefixes[i] = a.IPPrefix
	}

	return ipConn, prefixes, nil
}

// DoHQuery sends a DNS query packet to POST /dns-query over HTTP/3.
func (s *Session) DoHQuery(ctx context.Context, dnsReq []byte) ([]byte, error) {
	if s.closed.Load() {
		return nil, net.ErrClosed
	}
	if s.h3Conn == nil {
		return nil, errors.New("h3Conn is nil")
	}

	u := fmt.Sprintf("https://%s/dns-query", s.sni)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(dnsReq))
	if err != nil {
		return nil, fmt.Errorf("create doh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	s.setAuthHeaders(req.Header)

	resp, err := s.h3Conn.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("doh roundtrip: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh status %d %s", resp.StatusCode, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read doh response: %w", err)
	}
	return body, nil
}

// Ping sends GET /healthz over HTTP/3 and measures roundtrip latency.
func (s *Session) Ping(ctx context.Context) (time.Duration, error) {
	if s.closed.Load() {
		return 0, net.ErrClosed
	}
	if s.h3Conn == nil {
		return 0, errors.New("h3Conn is nil")
	}

	u := fmt.Sprintf("https://%s/healthz", s.sni)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, fmt.Errorf("create ping request: %w", err)
	}

	start := time.Now()
	resp, err := s.h3Conn.RoundTrip(req)
	if err != nil {
		return 0, fmt.Errorf("ping roundtrip: %w", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("ping healthz status %d", resp.StatusCode)
	}
	return time.Since(start), nil
}

// Close closes the session and underlying connections.
func (s *Session) Close() error {
	s.closed.Store(true)
	var err error
	s.closeOnce.Do(func() {
		if s.onClose != nil {
			s.onClose()
		}
		if s.client != nil {
			err = s.client.Close()
		}
	})
	return err
}

// IsAlive checks if the session is alive and not closed.
func (s *Session) IsAlive() bool {
	if s.closed.Load() {
		return false
	}
	if s.client != nil && s.client.Conn() != nil {
		return s.client.Conn().Context().Err() == nil
	}
	return true
}

const maxDrainingSessions = 2

// SessionManager manages active Session lifecycle, supporting dial, get, and reset.
type SessionManager struct {
	mu               sync.Mutex
	currentSession   *Session
	dialHook         func(ctx context.Context) (*Session, error)
	drainingMu       sync.Mutex
	drainingSessions []*Session
}

// NewSessionManager creates a new SessionManager.
func NewSessionManager() *SessionManager {
	return &SessionManager{}
}

// SetDialHook sets a custom session dialer (primarily for testing).
func (m *SessionManager) SetDialHook(hook func(ctx context.Context) (*Session, error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dialHook = hook
}

// GetSession returns the active session or creates a new one.
func (m *SessionManager) GetSession(ctx context.Context) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.currentSession != nil && m.currentSession.IsAlive() && !m.currentSession.IsDraining() {
		return m.currentSession, nil
	}

	if m.currentSession != nil {
		if !m.currentSession.IsDraining() {
			_ = m.currentSession.Close()
		}
		m.currentSession = nil
	}

	if m.dialHook != nil {
		sess, err := m.dialHook(ctx)
		if err != nil {
			return nil, err
		}
		m.currentSession = sess
		return sess, nil
	}

	addr, tok, sni, ip := getActiveEdge()
	if addr == "" {
		return nil, errors.New("no active edge address configured")
	}

	cfg := DefaultTransportConfig(addr, sni)
	if ip != nil {
		port := 443
		if _, portStr, err := net.SplitHostPort(addr); err == nil {
			if p, perr := strconv.Atoi(portStr); perr == nil && p > 0 {
				port = p
			}
		}
		cfg.RemoteUDPAddr = &net.UDPAddr{IP: ip, Port: port}
	}

	client, err := Dial(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("dial edge session: %w", err)
	}

	sess, err := NewSession(client, tok, addr, sni)
	if err != nil {
		_ = client.Close()
		return nil, err
	}

	m.currentSession = sess
	return sess, nil
}

// DialTCP dials an outbound TCP stream using the active session.
func (m *SessionManager) DialTCP(ctx context.Context, target string) (net.Conn, error) {
	sess, err := m.GetSession(ctx)
	if err != nil {
		return nil, err
	}
	return sess.DialTCP(ctx, target)
}

// DialUDP dials an outbound UDP connection using MASQUE on the active session.
func (m *SessionManager) DialUDP(ctx context.Context, target string) (net.Conn, error) {
	sess, err := m.GetSession(ctx)
	if err != nil {
		return nil, err
	}
	return sess.DialUDP(ctx, target)
}

// DialMASQUE dials an outbound MASQUE UDP connection using the active session.
func (m *SessionManager) DialMASQUE(ctx context.Context, target string) (*masque.Conn, error) {
	sess, err := m.GetSession(ctx)
	if err != nil {
		return nil, err
	}
	return sess.DialMASQUE(ctx, target)
}

// DialIP establishes a CONNECT-IP tunnel using the active session.
func (m *SessionManager) DialIP(ctx context.Context) (*connectip.Conn, []netip.Prefix, error) {
	sess, err := m.GetSession(ctx)
	if err != nil {
		return nil, nil, err
	}
	return sess.DialIP(ctx)
}

// DoHQuery performs a DNS query via POST /dns-query using the active session.
func (m *SessionManager) DoHQuery(ctx context.Context, dnsReq []byte) ([]byte, error) {
	sess, err := m.GetSession(ctx)
	if err != nil {
		return nil, err
	}
	return sess.DoHQuery(ctx, dnsReq)
}

// Ping measures GET /healthz RTT on the active session.
func (m *SessionManager) Ping(ctx context.Context) (time.Duration, error) {
	sess, err := m.GetSession(ctx)
	if err != nil {
		return 0, err
	}
	return sess.Ping(ctx)
}

// Reset clears and closes the active session and all draining sessions.
func (m *SessionManager) Reset() {
	m.mu.Lock()
	if m.currentSession != nil {
		_ = m.currentSession.Close()
		m.currentSession = nil
	}
	m.mu.Unlock()

	m.drainingMu.Lock()
	toClose := m.drainingSessions
	m.drainingSessions = nil
	m.drainingMu.Unlock()

	for _, s := range toClose {
		_ = s.Close()
	}
}

// Drain marks the current session as draining, releases it from currentSession
// so future requests establish a new session, and schedules its Close after drainTimeout.
// If the draining queue depth exceeds maxDrainingSessions (2), the oldest draining
// session is immediately closed and evicted from the queue to prevent session accumulation.
// IMPORTANT: Locks are NOT held during session Close()!
func (m *SessionManager) Drain(drainTimeout time.Duration) *Session {
	m.mu.Lock()
	oldSess := m.currentSession
	m.currentSession = nil
	m.mu.Unlock()

	if oldSess == nil {
		return nil
	}

	oldSess.MarkDraining()

	m.drainingMu.Lock()
	var toClose []*Session
	for len(m.drainingSessions) >= maxDrainingSessions {
		oldest := m.drainingSessions[0]
		m.drainingSessions = m.drainingSessions[1:]
		toClose = append(toClose, oldest)
	}
	m.drainingSessions = append(m.drainingSessions, oldSess)
	m.drainingMu.Unlock()

	for _, s := range toClose {
		_ = s.Close()
	}

	time.AfterFunc(drainTimeout, func() {
		m.drainingMu.Lock()
		for i, s := range m.drainingSessions {
			if s == oldSess {
				m.drainingSessions = append(m.drainingSessions[:i], m.drainingSessions[i+1:]...)
				break
			}
		}
		m.drainingMu.Unlock()
		_ = oldSess.Close()
	})

	return oldSess
}

// DrainingCount returns the number of sessions currently in draining state.
func (m *SessionManager) DrainingCount() int {
	m.drainingMu.Lock()
	defer m.drainingMu.Unlock()
	return len(m.drainingSessions)
}

// DrainingSessions returns a snapshot of currently draining sessions.
func (m *SessionManager) DrainingSessions() []*Session {
	m.drainingMu.Lock()
	defer m.drainingMu.Unlock()
	res := make([]*Session, len(m.drainingSessions))
	copy(res, m.drainingSessions)
	return res
}

var (
	defaultSessionMgrMu sync.RWMutex
	defaultSessionMgr   *SessionManager
)

// SetGlobalSessionManager sets the process-wide default SessionManager.
func SetGlobalSessionManager(m *SessionManager) {
	defaultSessionMgrMu.Lock()
	defaultSessionMgr = m
	defaultSessionMgrMu.Unlock()
}

// GetGlobalSessionManager returns the process-wide default SessionManager.
func GetGlobalSessionManager() *SessionManager {
	defaultSessionMgrMu.RLock()
	defer defaultSessionMgrMu.RUnlock()
	return defaultSessionMgr
}

type h3StreamConn struct {
	str       *http3.RequestStream
	target    string
	closed    atomic.Bool
	closeOnce sync.Once
}

func newH3StreamConn(str *http3.RequestStream, target string) *h3StreamConn {
	return &h3StreamConn{str: str, target: target}
}

func (c *h3StreamConn) Read(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, io.EOF
	}
	return c.str.Read(b)
}

func (c *h3StreamConn) Write(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	return c.str.Write(b)
}

func (c *h3StreamConn) Close() error {
	c.closed.Store(true)
	var err error
	c.closeOnce.Do(func() {
		if c.str != nil {
			err = c.str.Close()
		}
	})
	return err
}

func (c *h3StreamConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
}

func (c *h3StreamConn) RemoteAddr() net.Addr {
	host, portStr, err := net.SplitHostPort(c.target)
	if err == nil {
		p, _ := strconv.Atoi(portStr)
		return &net.TCPAddr{IP: net.ParseIP(host), Port: p}
	}
	return &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0}
}

func (c *h3StreamConn) SetDeadline(t time.Time) error {
	if c.str != nil {
		return c.str.SetDeadline(t)
	}
	return nil
}
func (c *h3StreamConn) SetReadDeadline(t time.Time) error {
	if c.str != nil {
		return c.str.SetReadDeadline(t)
	}
	return nil
}
func (c *h3StreamConn) SetWriteDeadline(t time.Time) error {
	if c.str != nil {
		return c.str.SetWriteDeadline(t)
	}
	return nil
}

type masqueNetConn struct {
	conn       *masque.Conn
	target     string
	remoteAddr net.Addr
	closed     atomic.Bool
	closeOnce  sync.Once
}

func newMasqueNetConn(conn *masque.Conn, target string) *masqueNetConn {
	var rAddr net.Addr
	if host, portStr, err := net.SplitHostPort(target); err == nil {
		p, _ := strconv.Atoi(portStr)
		rAddr = &net.UDPAddr{IP: net.ParseIP(host), Port: p}
	} else {
		rAddr = &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0}
	}
	return &masqueNetConn{conn: conn, target: target, remoteAddr: rAddr}
}

func (c *masqueNetConn) Read(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, io.EOF
	}
	if c.conn == nil {
		return 0, io.EOF
	}
	n, _, err := c.conn.ReadFrom(b)
	return n, err
}

func (c *masqueNetConn) Write(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	if c.conn == nil {
		return 0, io.ErrClosedPipe
	}
	return c.conn.WriteTo(b, c.remoteAddr)
}

func (c *masqueNetConn) Close() error {
	c.closed.Store(true)
	var err error
	c.closeOnce.Do(func() {
		if c.conn != nil {
			err = c.conn.Close()
		}
	})
	return err
}

func (c *masqueNetConn) LocalAddr() net.Addr {
	if c.conn != nil {
		return c.conn.LocalAddr()
	}
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
}

func (c *masqueNetConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *masqueNetConn) SetDeadline(t time.Time) error {
	if c.conn != nil {
		return c.conn.SetDeadline(t)
	}
	return nil
}
func (c *masqueNetConn) SetReadDeadline(t time.Time) error {
	if c.conn != nil {
		return c.conn.SetReadDeadline(t)
	}
	return nil
}
func (c *masqueNetConn) SetWriteDeadline(t time.Time) error {
	if c.conn != nil {
		return c.conn.SetWriteDeadline(t)
	}
	return nil
}
