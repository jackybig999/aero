// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

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

	connectip "github.com/quic-go/connect-ip-go"
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
	// authRejected：edge 已以 401 拒绝本会话的 token。之后的请求在本地直接返回该拒绝，不再发往 edge
	// （否则每个应用连接都会再失败一次，触发 edge 的防爆破封禁）；token 更换后会新建会话。
	authRejected  atomic.Pointer[EdgeRejectError]
	onAuthFailure func()
}

// checkRejected 返回已记录的认证拒绝（本会话不再向 edge 发请求）。
func (s *Session) checkRejected() error {
	if r := s.authRejected.Load(); r != nil {
		return r
	}
	return nil
}

// noteRejection 记录 edge 的拒绝；认证失败时标记会话并通知刷新 token（只通知一次）。
func (s *Session) noteRejection(r *EdgeRejectError) error {
	if r != nil && r.AuthFailure() && s.authRejected.CompareAndSwap(nil, r) && s.onAuthFailure != nil {
		s.onAuthFailure()
	}
	return r
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
//
// C3 §5.2：新版 edge 已不要求、也不记录这两个头，但客户端行为保持不变——已部署的旧 edge 仍要求它们。
// 全部 edge 升级到不要求 nonce 的版本后，再在客户端删除（不得早于此）。
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

	if err := s.checkRejected(); err != nil {
		return nil, err
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
		return nil, s.noteRejection(rejectionFrom("connect", resp))
	}

	return newH3StreamConn(str, target), nil
}

// DialMASQUE dials a CONNECT-UDP proxied UDP connection using masque-go.
func (s *Session) DialMASQUE(ctx context.Context, target string) (*masque.Conn, error) {
	if s.closed.Load() {
		return nil, net.ErrClosed
	}

	if err := s.checkRejected(); err != nil {
		return nil, err
	}
	tmpl := uritemplate.MustNew("https://" + s.sni + "/.well-known/masque/udp/{target_host}/{target_port}/")
	mreq, err := masque.NewRequest(ctx, tmpl, target)
	if err != nil {
		return nil, fmt.Errorf("create masque request: %w", err)
	}
	s.setAuthHeaders(mreq.Header())

	mconn, resp, err := s.masqueConn.Dial(mreq)
	if err != nil {
		if resp != nil && resp.StatusCode != http.StatusOK { // 库在非 2xx 时返回响应与错误：保留拒绝原因
			return nil, s.noteRejection(rejectionFrom("connect-udp", resp))
		}
		return nil, fmt.Errorf("dial masque: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = mconn.Close()
		return nil, s.noteRejection(rejectionFrom("connect-udp", resp))
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

// 场景类别与传输方式（ADR-0017、api/dataplane.md §4.1）。
const (
	classNameAI     = "ai"
	headerClassName = "Aero-Class"
	headerTransport = "Aero-Transport"
)

// ErrTransportMismatch 表示节点返回的 Aero-Transport 与请求的类别不符。按设计不降级、不按其他方式使用。
var ErrTransportMismatch = errors.New("CLIENT_TRANSPORT_MISMATCH")

// DialIP establishes a CONNECT-IP tunnel session using connect-ip-go.
func (s *Session) DialIP(ctx context.Context) (*connectip.Conn, []netip.Prefix, error) {
	return s.dialIPClass(ctx, "")
}

// DialIPClass 建立指定类别的 CONNECT-IP 会话："" 为 default（数据报），classNameAI 为 ai（DATAGRAM capsule）。
func (s *Session) DialIPClass(ctx context.Context, class string) (*connectip.Conn, []netip.Prefix, error) {
	return s.dialIPClass(ctx, class)
}

func (s *Session) dialIPClass(ctx context.Context, class string) (*connectip.Conn, []netip.Prefix, error) {
	if s.closed.Load() {
		return nil, nil, net.ErrClosed
	}
	mode, wantTransport := connectip.DataModeDatagram, "datagram"
	if class == classNameAI {
		mode, wantTransport = connectip.DataModeCapsule, "capsule"
	} else if class != "" {
		return nil, nil, fmt.Errorf("unsupported class %q", class)
	}

	if err := s.checkRejected(); err != nil {
		return nil, nil, err
	}
	tmpl := uritemplate.MustNew("https://" + s.sni + "/.well-known/masque/ip/*/*/")
	ipReq, err := connectip.NewRequest(ctx, tmpl)
	if err != nil {
		return nil, nil, fmt.Errorf("create connect-ip request: %w", err)
	}
	s.setAuthHeaders(ipReq.Header())
	if class != "" {
		ipReq.Header().Set(headerClassName, class)
	}

	ipConn, resp, err := s.connectIPConn.DialWithMode(ipReq, mode)
	if err != nil {
		if resp != nil && resp.StatusCode != http.StatusOK { // 库在非 2xx 时返回响应与错误：保留拒绝原因
			return nil, nil, s.noteRejection(rejectionFrom("connect-ip", resp))
		}
		return nil, nil, fmt.Errorf("dial connect-ip: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = ipConn.Close()
		return nil, nil, s.noteRejection(rejectionFrom("connect-ip", resp))
	}
	// 核对节点实际使用的传输方式：ai 必须是 capsule（旧节点不认识类别头，会回数据报且没有该头，也算不符）；
	// default 对旧节点没有该头是正常的，但出现了就必须是 datagram。
	got := resp.Header.Get(headerTransport)
	if got != wantTransport && !(class == "" && got == "") {
		_ = ipConn.Close()
		return nil, nil, fmt.Errorf("%w: node answered %q, want %q", ErrTransportMismatch, got, wantTransport)
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

// sessionDialTimeout 是单次会话拨号的总时限。拨号与发起调用方的 ctx 解耦（调用方可能只有 DoH 的 2.5 秒），
// 因此需要独立时限；取值需大于 DefaultTransportConfig 的握手超时（10 秒）并留出 alt_ports 阶梯的余量。
const sessionDialTimeout = 15 * time.Second

// errSessionDialAbandoned 表示在途拨号因 Reset 被放弃：其结果被丢弃并关闭，等待方得到该错误。
var errSessionDialAbandoned = errors.New("session dial abandoned by reset")

// sessionDial 是一次在途拨号。done 在拨号结束（或被 Reset/SetSession 放弃）时关闭；
// sess/err/abandoned/finished 只在 SessionManager.mu 持有时写入，且都先于 close(done)，
// 等待方在 <-done 之后读取 sess/err 是安全的。
type sessionDial struct {
	done      chan struct{}
	cancel    context.CancelFunc
	sess      *Session
	err       error
	abandoned bool // 已被 Reset/SetSession 放弃：拨号协程返回后必须关闭其结果，不得采用
	finished  bool // done 已关闭（保证只关闭一次）
}

// SessionManager manages active Session lifecycle, supporting dial, get, and reset.
type SessionManager struct {
	mu               sync.Mutex
	dial             *sessionDial // 在途拨号（单飞）；nil 表示没有拨号
	currentSession   *Session
	ipSession        *Session // 承载 default CONNECT-IP 会话的 Session；ai 会话必须与它在同一个 QUIC 连接上
	dialHook         func(ctx context.Context) (*Session, error)
	drainingMu       sync.Mutex
	drainingSessions []*Session
	authFailureHook  func() // edge 以 401 拒绝当前 token 时调用（引擎据此换 token）
}

// SetAuthFailureHook 设置认证失败回调，作用于之后采用的会话。
func (m *SessionManager) SetAuthFailureHook(f func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authFailureHook = f
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

// finishDialLocked 结束一次拨号并唤醒全部等待方；重复调用无副作用。调用方必须持有 m.mu。
func (m *SessionManager) finishDialLocked(d *sessionDial, sess *Session, err error) {
	if d.finished {
		return
	}
	d.finished = true
	d.sess, d.err = sess, err
	if m.dial == d {
		m.dial = nil
	}
	close(d.done)
}

// SetSession injects an active session directly into the SessionManager.
// 若此时有在途拨号，注入的会话优先：拨号被放弃（结果会被关闭），等待方直接拿到注入的会话。
func (m *SessionManager) SetSession(s *Session) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.currentSession != nil && !m.currentSession.IsDraining() && m.currentSession != s {
		_ = m.currentSession.Close()
	}
	if s != nil && s.onAuthFailure == nil {
		s.onAuthFailure = m.authFailureHook
	}
	m.currentSession = s
	if s != nil && m.dial != nil {
		d := m.dial
		d.abandoned = true
		d.cancel()
		m.finishDialLocked(d, s, nil)
	}
}

// GetSession returns the active session or creates a new one.
//
// 拨号单飞：同一时间只有一个拨号，由独立协程执行，使用与调用方无关的 ctx（见 sessionDialTimeout）。
// 每个调用方（包括发起者）都只按自己的 ctx 等待拨号结束：ctx 取消立即返回 ctx.Err()，
// 不影响拨号继续进行，也不影响其他等待方。
func (m *SessionManager) GetSession(ctx context.Context) (*Session, error) {
	m.mu.Lock()
	if m.currentSession != nil && m.currentSession.IsAlive() && !m.currentSession.IsDraining() {
		sess := m.currentSession
		m.mu.Unlock()
		return sess, nil
	}
	if err := ctx.Err(); err != nil {
		m.mu.Unlock()
		return nil, err
	}
	d := m.dial
	if d == nil {
		d = m.startDialLocked(ctx)
	}
	m.mu.Unlock()

	select {
	case <-d.done:
		return d.sess, d.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// startDialLocked 启动拨号协程并登记为在途拨号。调用方必须持有 m.mu。
// 拨号 ctx 保留调用方 ctx 的 value，但脱离其取消与截止时间；Reset 会取消它。
func (m *SessionManager) startDialLocked(callerCtx context.Context) *sessionDial {
	dctx, cancel := context.WithTimeout(context.WithoutCancel(callerCtx), sessionDialTimeout)
	d := &sessionDial{done: make(chan struct{}), cancel: cancel}
	m.dial = d
	hook := m.dialHook
	go func() {
		defer cancel()
		var (
			sess    *Session
			adopted func()
			err     error
		)
		if hook != nil {
			sess, err = hook(dctx)
		} else {
			sess, adopted, err = dialActiveEdgeSession(dctx)
		}
		m.completeDial(d, sess, adopted, err)
	}()
	return d
}

// completeDial 在拨号协程内提交结果：已被放弃则关闭结果、不采用；否则替换当前会话。
// adopted（可选）在结果被采用后调用，用于把拨号中发现的实际端口写回活动 edge。
func (m *SessionManager) completeDial(d *sessionDial, sess *Session, adopted func(), err error) {
	if err == nil && sess == nil {
		err = errors.New("dial returned no session")
	}

	m.mu.Lock()
	if d.abandoned {
		// Reset/SetSession 已放弃本次拨号并唤醒了等待方；旧拨号的会话不得装回。
		m.mu.Unlock()
		if sess != nil {
			_ = sess.Close()
		}
		return
	}
	var old *Session
	if err == nil {
		if m.currentSession != nil && !m.currentSession.IsDraining() && m.currentSession != sess {
			old = m.currentSession
		}
		if sess.onAuthFailure == nil {
			sess.onAuthFailure = m.authFailureHook
		}
		m.currentSession = sess
	} else {
		sess = nil
	}
	m.finishDialLocked(d, sess, err)
	m.mu.Unlock()

	if old != nil {
		_ = old.Close()
	}
	if err == nil && adopted != nil {
		adopted()
	}
}

// dialActiveEdgeSession 按当前活动 edge 配置建立新会话。返回的 adopted（可选）只应在会话被采用后调用。
func dialActiveEdgeSession(ctx context.Context) (*Session, func(), error) {
	addr, tok, sni, ip := getActiveEdge()
	if addr == "" {
		return nil, nil, errors.New("no active edge address configured")
	}
	cfg := DefaultTransportConfig(addr, sni)
	if ech := getActiveEdgeECH(); len(ech) > 0 {
		cfg.ECHConfigList = ech
	}
	if altPorts := getActiveEdgeAltPorts(); len(altPorts) > 0 {
		cfg.AltPorts = altPorts
	}
	if pins := getActivePinSPKI(); len(pins) > 0 {
		if cfg.TLSConfig == nil {
			nodeHost := addr
			if h, _, err := net.SplitHostPort(addr); err == nil {
				nodeHost = h
			}
			cfg.TLSConfig = defaultTLSConfig(cfg.TLSServerName, nodeHost)
		}
		configureSPKIPinning(cfg.TLSConfig, pins)
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

	client, err := Dial(ctx, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("dial edge session: %w", err)
	}
	var adopted func()
	if client.ActualPort() > 0 && client.ActualPort() != port {
		h, _, _ := net.SplitHostPort(addr)
		newAddr := net.JoinHostPort(h, strconv.Itoa(client.ActualPort()))
		addr = newAddr
		ech := cfg.ECHConfigList
		// 实际端口写回活动 edge 放在会话被采用之后：被 Reset 放弃的旧拨号不得覆盖新的活动 edge。
		adopted = func() {
			if len(ech) > 0 {
				SetActiveEdge(newAddr, tok, sni, ip, ech)
			} else {
				SetActiveEdge(newAddr, tok, sni, ip)
			}
		}
	}

	sess, err := NewSession(client, tok, addr, sni)
	if err != nil {
		_ = client.Close()
		return nil, nil, err
	}
	return sess, adopted, nil
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

// DialIP establishes a CONNECT-IP tunnel using the active session.
// 成功后记住承载它的 Session：ai 会话要固定在同一个 QUIC 连接上（pinnedSession）。
func (m *SessionManager) DialIP(ctx context.Context) (*connectip.Conn, []netip.Prefix, error) {
	sess, err := m.GetSession(ctx)
	if err != nil {
		return nil, nil, err
	}
	conn, prefixes, err := sess.DialIP(ctx)
	if err != nil {
		return nil, nil, err
	}
	m.mu.Lock()
	m.ipSession = sess
	m.mu.Unlock()
	return conn, prefixes, nil
}

// errNoPinnedSession 表示还没有 default CONNECT-IP 会话，或承载它的 Session 已经关闭。
var errNoPinnedSession = errors.New("no live session carrying the default CONNECT-IP session")

// pinnedSession 返回最近一次 default CONNECT-IP 会话所在的 Session（可能已关闭或处于排空期）。
// 引擎在建立 default 会话后立即读取它并绑定到复用层：ai 会话只能建在这个 Session 上，
// 不经 GetSession——切换节点后旧会话处于排空期（约 20 秒）时，GetSession 会改拨到新的 QUIC 连接甚至新节点，
// 让 ai 会话与 default 会话分处两处，并在 edge 上多占一个设备名额。
// 绑定到复用层而不是每次重拨时再读，是为了旧复用层的重拨协程不会在重连窗口里用到新连接的 Session。
func (m *SessionManager) pinnedSession() *Session {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ipSession
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

// Reset clears and closes the active session and all draining sessions, and abandons any in-flight dial.
func (m *SessionManager) Reset() {
	m.mu.Lock()
	// 在途拨号被放弃：取消其 ctx，立即唤醒等待方并给出错误；拨号协程返回后会关闭其结果、不采用。
	// 登记同时清除，之后的 GetSession 会发起全新的拨号，不必等旧拨号收尾。
	if d := m.dial; d != nil {
		d.abandoned = true
		d.cancel()
		m.finishDialLocked(d, nil, errSessionDialAbandoned)
	}
	if m.currentSession != nil {
		_ = m.currentSession.Close()
		m.currentSession = nil
	}
	m.ipSession = nil // 其 Session 随 currentSession 或排空列表关闭；不再保留引用
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
