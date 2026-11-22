// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package edge

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// 数据面加固（C1 §5、§7）的回归测试：端口策略三路一致、拒绝响应映射、CONNECT-IP 会话上限、
// 按 token 拨号上限、TCP 中继下行写超时、ConnTracker 清理、下行字节预算泄漏。

const dpToken = "valid_dp_token"

func newDPServer(t *testing.T, dg *DialGuard) *QUICServer {
	t.Helper()
	v := NewValidator()
	v.AddToken(dpToken, "user", 24*time.Hour)
	qs := NewQUICServer(v, nil, nil, dg, nil)
	t.Cleanup(qs.Close)
	return qs
}

func dpStandardConnectReq(target string) *http.Request {
	// 直接构造请求：httptest.NewRequest 会拒绝 "host:smtp" 这类非数字端口。
	req := &http.Request{
		Method:     http.MethodConnect,
		RequestURI: target,
		Host:       target,
		URL:        &url.URL{Host: target},
		Header:     http.Header{},
		RemoteAddr: "203.0.113.99:54321",
	}
	req.Header.Set("Authorization", "Bearer "+dpToken)
	return req
}

func dpConnectUDPReq(path string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "https://placeholder"+path, nil)
	req.Method = http.MethodConnect
	req.Proto = "connect-udp"
	req.Header.Set("Upgrade", "connect-udp")
	req.Header.Set("Capsule-Protocol", "?1")
	req.URL.Scheme = ""
	req.URL.Host = ""
	req.RemoteAddr = "203.0.113.99:54321"
	req.Header.Set("Authorization", "Bearer "+dpToken)
	return req
}

// 标准 CONNECT：端口策略（tcp/25）、请求格式错误与被禁地址的响应。
func TestStandardConnectRejectionMapping(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, okPort, _ := net.SplitHostPort(ln.Addr().String())

	dg := NewDialGuard(16)
	defer dg.Close()
	qs := newDPServer(t, dg)

	cases := []struct {
		name          string
		loopback      bool // allowLoopbackForTest
		target        string
		wantStatus    int
		wantErrorTok  string // Proxy-Status 中应含
		wantDetails   string // 为空则不检查
		wantNoDetails string // Proxy-Status 中不得含
	}{
		{"smtp 域名", true, "example.com:25", 403, "destination_ip_prohibited", `details="smtp"`, ""},
		{"smtp 地址", false, "203.0.114.1:25", 403, "destination_ip_prohibited", `details="smtp"`, ""},
		{"smtp 前导零", true, "example.com:025", 403, "destination_ip_prohibited", `details="smtp"`, ""},
		{"smtp 服务名不得绕过", true, "example.com:smtp", 400, "http_request_error", `details="EDGE_BAD_REQUEST"`, ""},
		{"端口缺失", true, "example.com", 400, "http_request_error", `details="EDGE_BAD_REQUEST"`, ""},
		{"端口为 0", true, "example.com:0", 400, "http_request_error", `details="EDGE_BAD_REQUEST"`, ""},
		{"587 不受限", true, "127.0.0.1:" + okPort, 200, "", "", ""},
		{"私网地址", false, "10.0.0.1:443", 403, "destination_ip_prohibited", "", ""},
		// 域名解析到被禁地址：safeDial 的 Control 拒绝；以 sentinel 判定为 403 而不是 502。
		{"拨号到被禁地址", true, "127.0.0.1:9", 403, "destination_ip_prohibited", `details="EDGE_DEST_PROHIBITED"`, "127.0.0.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			qs.SetAllowLoopbackForTest(tc.loopback)
			// 这一组里只有“587 不受限”需要真实拨号到本地监听，其余不应到达拨号。
			dg.AllowLocal = tc.name == "587 不受限"
			rec := httptest.NewRecorder()
			qs.serveStandardConnect(rec, dpStandardConnectReq(tc.target))
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (Proxy-Status %q)", rec.Code, tc.wantStatus, rec.Header().Get("Proxy-Status"))
			}
			ps := rec.Header().Get("Proxy-Status")
			if tc.wantErrorTok != "" && !strings.Contains(ps, "error="+tc.wantErrorTok) {
				t.Fatalf("Proxy-Status = %q, want error=%s", ps, tc.wantErrorTok)
			}
			if tc.wantDetails != "" && !strings.Contains(ps, tc.wantDetails) {
				t.Fatalf("Proxy-Status = %q, want %s", ps, tc.wantDetails)
			}
			if tc.wantNoDetails != "" && strings.Contains(ps, tc.wantNoDetails) {
				t.Fatalf("Proxy-Status leaks %q: %q", tc.wantNoDetails, ps)
			}
		})
	}
}

// rejectDial 的映射表：靠 sentinel 判定，details 不含原始 err.Error()。
func TestRejectDialMapping(t *testing.T) {
	const secret = "127.0.0.1:40000"
	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantTok    string
		wantExtra  string
	}{
		{"被禁地址", fmt.Errorf("dial: %w", fmt.Errorf("%w %s (%s)", errBlockedTarget, "10.0.0.1", "private")), 403, "destination_ip_prohibited", `details="EDGE_DEST_PROHIBITED"`},
		{"单 token 拨号上限", errDialTokenLimit, 503, "connection_limit_exceeded", ""},
		{"拨号队列满", errDialQueueFull, 503, "connection_limit_exceeded", ""},
		{"WARP fail-closed", fmt.Errorf("%w: via %s", errWarpFailClosed, secret), 502, "connection_refused", `details="EGRESS_UNAVAILABLE"`},
		{"DNS 解析失败", &net.DNSError{Err: "no such host", Name: "nx.invalid"}, 502, "destination_ip_unroutable", ""},
		{"其他拨号失败", errors.New("socks5 connect rejected by upstream via " + secret), 502, "connection_refused", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			rejectDial(rec, tc.err)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			ps := rec.Header().Get("Proxy-Status")
			if !strings.Contains(ps, "error="+tc.wantTok) {
				t.Fatalf("Proxy-Status = %q, want error=%s", ps, tc.wantTok)
			}
			if tc.wantExtra != "" && !strings.Contains(ps, tc.wantExtra) {
				t.Fatalf("Proxy-Status = %q, want %s", ps, tc.wantExtra)
			}
			if strings.Contains(ps, secret) || strings.Contains(ps, "40000") || strings.Contains(ps, "socks5") {
				t.Fatalf("Proxy-Status leaks the raw error: %q", ps)
			}
		})
	}
}

// safeDial 拒绝被禁地址时返回可判定的 sentinel。
func TestSafeDialBlockedTargetIsSentinel(t *testing.T) {
	dg := NewDialGuard(8)
	defer dg.Close()
	_, err := dg.DialTimeoutFor("tok", "tcp", "127.0.0.1:9", time.Second)
	if !errors.Is(err, errBlockedTarget) {
		t.Fatalf("err = %v, want errBlockedTarget", err)
	}
}

// connect-udp：端口策略三路一致，解析失败/拨号失败/请求错误的映射，details 不泄露原始错误。
func TestConnectUDPRejectionMapping(t *testing.T) {
	const secret = "10.9.8.7:1080"
	cases := []struct {
		name       string
		path       string
		resolve    func(network, addr string) (*net.UDPAddr, error)
		dial       func(network string, laddr, raddr *net.UDPAddr) (*net.UDPConn, error)
		wantStatus int
		wantTok    string
	}{
		{
			name: "目标端口非数字", path: "/.well-known/masque/udp/example.com/notaport/",
			wantStatus: 400, wantTok: "http_request_error",
		},
		{
			name: "路径不符合模板", path: "/not-masque/",
			wantStatus: 400, wantTok: "http_request_error",
		},
		{
			name: "解析失败", path: "/.well-known/masque/udp/nx.invalid/443/",
			resolve:    func(string, string) (*net.UDPAddr, error) { return nil, errors.New("lookup via " + secret + " failed") },
			wantStatus: 502, wantTok: "destination_ip_unroutable",
		},
		{
			name: "解析到被禁地址", path: "/.well-known/masque/udp/rebind.example/443/",
			resolve: func(string, string) (*net.UDPAddr, error) {
				return &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 443}, nil
			},
			wantStatus: 403, wantTok: "destination_ip_prohibited",
		},
		{
			name: "拨号失败", path: "/.well-known/masque/udp/public.example/443/",
			resolve: func(string, string) (*net.UDPAddr, error) {
				return &net.UDPAddr{IP: net.IPv4(203, 0, 114, 5), Port: 443}, nil
			},
			dial: func(string, *net.UDPAddr, *net.UDPAddr) (*net.UDPConn, error) {
				return nil, errors.New("dial next hop " + secret + " refused")
			},
			wantStatus: 502, wantTok: "connection_refused",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			qs := newDPServer(t, nil)
			if tc.resolve != nil {
				qs.SetResolveUDPFunc(tc.resolve)
			}
			if tc.dial != nil {
				qs.SetUDPDialFunc(tc.dial)
			}
			rec := httptest.NewRecorder()
			qs.serveConnectUDP(rec, dpConnectUDPReq(tc.path))
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (Proxy-Status %q)", rec.Code, tc.wantStatus, rec.Header().Get("Proxy-Status"))
			}
			ps := rec.Header().Get("Proxy-Status")
			if !strings.Contains(ps, "error="+tc.wantTok) {
				t.Fatalf("Proxy-Status = %q, want error=%s", ps, tc.wantTok)
			}
			if strings.Contains(ps, "10.9.8.7") {
				t.Fatalf("Proxy-Status leaks the raw error: %q", ps)
			}
		})
	}
}

// 三条路径的端口策略一致：tcp/25 被拒；udp/25 与 tcp/587 不受限。
func TestDestinationPortPolicyAcrossProtocols(t *testing.T) {
	cases := []struct {
		proto   uint8
		port    uint16
		blocked bool
	}{
		{6, 25, true}, {6, 587, false}, {6, 465, false}, {17, 25, false}, {17, 53, false},
	}
	for _, tc := range cases {
		if got, _ := destinationPortBlocked(tc.proto, tc.port); got != tc.blocked {
			t.Errorf("destinationPortBlocked(%d,%d) = %v, want %v", tc.proto, tc.port, got, tc.blocked)
		}
	}
}

// DialGuard：单 token 并发拨号受限，超限立即失败且不占全局槽位，不影响其他 token。
func TestDialGuardPerTokenLimit(t *testing.T) {
	for _, tc := range []struct{ total, want int }{{256, 32}, {64, 8}, {16, 2}, {4, 1}, {1000, 32}} {
		dg := NewDialGuard(tc.total)
		if dg.perTokMax != tc.want {
			t.Errorf("NewDialGuard(%d).perTokMax = %d, want %d", tc.total, dg.perTokMax, tc.want)
		}
		dg.Close()
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	dg := NewDialGuard(64)
	defer dg.Close()
	dg.AllowLocal = true

	for i := 0; i < dg.perTokMax; i++ {
		if !dg.acquireToken("heavy") {
			t.Fatalf("acquire %d failed before the limit", i)
		}
	}
	start := time.Now()
	_, err = dg.DialTimeoutFor("heavy", "tcp", ln.Addr().String(), 5*time.Second)
	if !errors.Is(err, errDialTokenLimit) {
		t.Fatalf("err = %v, want errDialTokenLimit", err)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("over-limit dial took %v, want immediate failure", time.Since(start))
	}
	if len(dg.sem) != 0 {
		t.Fatalf("global semaphore slots held = %d, want 0", len(dg.sem))
	}
	// 其他 token 不受影响。
	c, err := dg.DialTimeoutFor("light", "tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("other token blocked by heavy token: %v", err)
	}
	_ = c.Close()
	// 释放后恢复；拨号结束后 token 计数归零。
	for i := 0; i < dg.perTokMax; i++ {
		dg.releaseToken("heavy")
	}
	c, err = dg.DialTimeoutFor("heavy", "tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial after release: %v", err)
	}
	_ = c.Close()
	dg.tokMu.Lock()
	n := len(dg.perTok)
	dg.tokMu.Unlock()
	if n != 0 {
		t.Fatalf("per-token counters left = %d, want 0", n)
	}
}

// 标准 CONNECT 在 token 拨号超限时返回 503 connection_limit_exceeded。
func TestStandardConnectDialLimitReturns503(t *testing.T) {
	dg := NewDialGuard(16)
	defer dg.Close()
	dg.AllowLocal = true
	qs := newDPServer(t, dg)
	qs.SetAllowLoopbackForTest(true)
	for i := 0; i < dg.perTokMax; i++ {
		dg.acquireToken(dpToken)
	}
	rec := httptest.NewRecorder()
	qs.serveStandardConnect(rec, dpStandardConnectReq("127.0.0.1:9"))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Header().Get("Proxy-Status"), "error=connection_limit_exceeded") {
		t.Fatalf("got %d %q", rec.Code, rec.Header().Get("Proxy-Status"))
	}
}

// ---- CONNECT-IP 会话上限 ----

// 用零值 quic.Conn 作为连接标识（不触发网络）；connAlive 在测试中替换。
func withAliveConns(t *testing.T, alive func(*quic.Conn) bool) {
	t.Helper()
	old := connAlive
	connAlive = alive
	t.Cleanup(func() { connAlive = old })
}

func TestConnectIPSessionTableLimits(t *testing.T) {
	withAliveConns(t, func(*quic.Conn) bool { return true })
	var tbl connectIPSessionTable
	c1, c2, c3, c4 := &quic.Conn{}, &quic.Conn{}, &quic.Conn{}, &quic.Conn{}

	s1, ok := tbl.acquire(c1, "uid:a", 2, 3)
	if !ok {
		t.Fatal("first session rejected")
	}
	if _, ok := tbl.acquire(c1, "uid:a", 2, 3); ok {
		t.Fatal("second session on the same connection accepted")
	}
	s2, ok := tbl.acquire(c2, "uid:a", 2, 3)
	if !ok {
		t.Fatal("second connection of the same uid rejected below its limit")
	}
	if _, ok := tbl.acquire(c3, "uid:a", 2, 3); ok {
		t.Fatal("third session of uid:a accepted beyond per-key limit 2")
	}
	s3, ok := tbl.acquire(c3, "uid:b", 2, 3)
	if !ok {
		t.Fatal("other uid rejected below the global limit")
	}
	if _, ok := tbl.acquire(c4, "uid:c", 2, 3); ok {
		t.Fatal("session accepted beyond global limit 3")
	}
	if tbl.active() != 3 {
		t.Fatalf("active = %d, want 3", tbl.active())
	}
	// 释放后可重新占用，重复释放无副作用。
	tbl.release(s1)
	tbl.release(s1)
	if tbl.active() != 2 {
		t.Fatalf("active after release = %d, want 2", tbl.active())
	}
	if s, ok := tbl.acquire(c1, "uid:a", 2, 3); !ok {
		t.Fatal("slot not reusable after release")
	} else {
		tbl.release(s)
	}
	tbl.release(s2)
	tbl.release(s3)
	if tbl.active() != 0 || len(tbl.byConn) != 0 || len(tbl.byKey) != 0 {
		t.Fatalf("table not empty: active=%d byConn=%d byKey=%d", tbl.active(), len(tbl.byConn), len(tbl.byKey))
	}
}

// 设备数上限替换旧连接时，旧连接的会话已不再存活，不应占用名额。
func TestConnectIPSessionTableIgnoresDeadConns(t *testing.T) {
	dead := &quic.Conn{}
	withAliveConns(t, func(c *quic.Conn) bool { return c != dead })
	var tbl connectIPSessionTable
	if _, ok := tbl.acquire(dead, "uid:a", 1, 10); !ok {
		t.Fatal("first session rejected")
	}
	fresh := &quic.Conn{}
	s, ok := tbl.acquire(fresh, "uid:a", 1, 10)
	if !ok {
		t.Fatal("session of a replaced (closed) connection still holds the slot")
	}
	tbl.release(s)
	if tbl.active() != 0 {
		t.Fatalf("active = %d, want 0 (dead session's slot must be reclaimed exactly once)", tbl.active())
	}
}

func TestConnectIPSessionTableConcurrent(t *testing.T) {
	var tbl connectIPSessionTable
	withAliveConns(t, func(*quic.Conn) bool { return true })
	var wg sync.WaitGroup
	var admitted atomic.Int64
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, ok := tbl.acquire(&quic.Conn{}, "k", 8, 1000)
			if !ok {
				return
			}
			if n := admitted.Add(1); n > 8 {
				t.Errorf("admitted %d sessions with per-key limit 8", n)
			}
			time.Sleep(5 * time.Millisecond)
			admitted.Add(-1)
			tbl.release(s)
		}()
	}
	wg.Wait()
	if tbl.active() != 0 {
		t.Fatalf("active = %d after all released", tbl.active())
	}
}

func dpConnectIPReq(qc *quic.Conn) *http.Request {
	req := httptest.NewRequest(http.MethodConnect, "https://example.com/.well-known/masque/ip/*/*/", nil)
	req.Proto = "connect-ip"
	req.Host = "example.com"
	req.Header.Set("Capsule-Protocol", "?1")
	req.RemoteAddr = "203.0.113.99:54321"
	req.Header.Set("Authorization", "Bearer "+dpToken)
	if qc != nil {
		req = req.WithContext(context.WithValue(req.Context(), quicConnKey{}, qc))
	}
	return req
}

// 经 serveConnectIP：同一连接的第二个会话、超过 token 上限的会话得到 503 connection_limit_exceeded；
// 提前返回的路径（地址池耗尽）也会释放名额。
func TestServeConnectIPSessionLimits(t *testing.T) {
	withAliveConns(t, func(*quic.Conn) bool { return true })
	qs := newDPServer(t, nil)

	// 同一连接已有活动会话。
	qc := &quic.Conn{}
	held, ok := qs.connectIPSessions.acquire(qc, dpToken, connectIPMaxSessionsOpaque, 100)
	if !ok {
		t.Fatal("setup acquire failed")
	}
	rec := httptest.NewRecorder()
	qs.serveConnectIP(rec, dpConnectIPReq(qc))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Header().Get("Proxy-Status"), "error=connection_limit_exceeded") {
		t.Fatalf("second session on one connection: %d %q", rec.Code, rec.Header().Get("Proxy-Status"))
	}
	qs.connectIPSessions.release(held)

	// 同一 token 的会话数达到上限（不透明 token：connectIPMaxSessionsOpaque）。
	var holds []*connectIPSession
	for i := 0; i < connectIPMaxSessionsOpaque; i++ {
		s, ok := qs.connectIPSessions.acquire(&quic.Conn{}, dpToken, connectIPMaxSessionsOpaque, 100)
		if !ok {
			t.Fatalf("setup acquire %d failed", i)
		}
		holds = append(holds, s)
	}
	rec = httptest.NewRecorder()
	qs.serveConnectIP(rec, dpConnectIPReq(&quic.Conn{}))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Header().Get("Proxy-Status"), "error=connection_limit_exceeded") {
		t.Fatalf("session beyond token limit: %d %q", rec.Code, rec.Header().Get("Proxy-Status"))
	}
	for _, s := range holds {
		qs.connectIPSessions.release(s)
	}
	if qs.connectIPSessions.active() != 0 {
		t.Fatalf("active = %d after releasing", qs.connectIPSessions.active())
	}

	// 未超限但地址池耗尽：返回 address_pool_exhausted，名额随 defer 归还。
	small, err := NewIPPool("10.88.0.0/29")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := small.Allocate(); err != nil {
			t.Fatal(err)
		}
	}
	qs.ipPool = small
	rec = httptest.NewRecorder()
	qs.serveConnectIP(rec, dpConnectIPReq(&quic.Conn{}))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Header().Get("Proxy-Status"), "address_pool_exhausted") {
		t.Fatalf("pool exhausted: %d %q", rec.Code, rec.Header().Get("Proxy-Status"))
	}
	if n := qs.connectIPSessions.active(); n != 0 {
		t.Fatalf("active sessions after early return = %d, want 0", n)
	}
}

// 签名 token 的 max_devices 随连接绑定保存，供 CONNECT-IP 会话上限使用。
func TestConnTrackerLimits(t *testing.T) {
	withAliveConns(t, func(*quic.Conn) bool { return true })
	ct := NewConnTracker()
	c := &quic.Conn{}
	ct.BindEvictOldest(c, "tok", "u1", 3)
	if uid, max := ct.Limits(c); uid != "u1" || max != 3 {
		t.Fatalf("Limits = %q,%d want u1,3", uid, max)
	}
	opaque := &quic.Conn{}
	ct.BindEvictOldest(opaque, "tok2", "", 0)
	if uid, max := ct.Limits(opaque); uid != "" || max != 0 {
		t.Fatalf("opaque Limits = %q,%d want empty,0", uid, max)
	}
	if uid, max := ct.Limits(&quic.Conn{}); uid != "" || max != 0 {
		t.Fatalf("unbound Limits = %q,%d", uid, max)
	}
}

type dpPacketConn struct {
	mu      sync.Mutex
	read    []int // 每次 ReadPacket 返回的长度
	written int
}

func (c *dpPacketConn) ReadPacket(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.read) == 0 {
		return 0, net.ErrClosed
	}
	n := c.read[0]
	c.read = c.read[1:]
	return n, nil
}
func (c *dpPacketConn) WritePacket(b []byte) ([]byte, error) {
	c.mu.Lock()
	c.written += len(b)
	c.mu.Unlock()
	return nil, nil
}
func (c *dpPacketConn) Close() error { return nil }

// CONNECT-IP 的上下行都经 bandwidthLimiter：令牌耗尽后按速率等待，会话取消后立即结束。
// 使用 synctest 的虚拟时钟，结果确定。
func TestLimitedIPConnThrottles(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		limiter := NewBandwidthLimiter(10000) // 10KB/s，突发 20KB
		inner := &dpPacketConn{read: []int{1000, 1000}}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		c := &limitedIPConn{IPPacketConn: inner, ctx: ctx, token: "tok", limiter: limiter}

		start := time.Now()
		for i := 0; i < 20; i++ { // 20 个 1000 字节的下行包 = 突发容量
			if _, err := c.WritePacket(make([]byte, 1000)); err != nil {
				t.Fatalf("write %d: %v", i, err)
			}
		}
		if d := time.Since(start); d != 0 {
			t.Fatalf("burst should not wait, waited %v", d)
		}
		// 突发用尽：再写 5000 字节需要 0.5 秒。
		for i := 0; i < 5; i++ {
			if _, err := c.WritePacket(make([]byte, 1000)); err != nil {
				t.Fatalf("throttled write %d: %v", i, err)
			}
		}
		if d := time.Since(start); d < 400*time.Millisecond {
			t.Fatalf("downlink not throttled: elapsed %v, want >= 0.4s", d)
		}
		// 上行同样扣减同一个桶（按 token）。
		before := time.Now()
		if n, err := c.ReadPacket(make([]byte, 1500)); err != nil || n != 1000 {
			t.Fatalf("read = %d, %v", n, err)
		}
		if n, err := c.ReadPacket(make([]byte, 1500)); err != nil || n != 1000 {
			t.Fatalf("read = %d, %v", n, err)
		}
		if time.Since(before) < 100*time.Millisecond {
			t.Fatalf("uplink not throttled: elapsed %v", time.Since(before))
		}
		// 会话取消：被限速阻塞的写立即以 ErrClosed 结束。
		for i := 0; i < 30; i++ {
			_, _ = c.WritePacket(make([]byte, 1000)) // 先耗尽并积压
			if i == 3 {
				break
			}
		}
		done := make(chan error, 1)
		go func() {
			_, err := c.WritePacket(make([]byte, 20000))
			done <- err
		}()
		synctest.Wait()
		cancel()
		synctest.Wait()
		select {
		case err := <-done:
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("err = %v, want net.ErrClosed", err)
			}
		default:
			t.Fatal("throttled write did not end after the session context was cancelled")
		}
	})
}

// ---- 真实 QUIC：TCP 中继下行写超时、ConnTracker 清理 ----

func dpStartEdge(t *testing.T, tune func(*QUICServer)) *Server {
	t.Helper()
	listenAddr, host := findTestAddr()
	srv, err := NewServer(ServerConfig{Listen: listenAddr, Domain: host, DataDir: t.TempDir(), Token: "relay_token", AllowSelfSignedCertForTest: true})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if tune != nil {
		tune(srv.quicServer)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(srv.Close)
	return srv
}

func dpConnect(t *testing.T, srv *Server, target string) (*quic.Conn, *http3.RequestStream) {
	t.Helper()
	ctx := context.Background()
	qConn, err := quic.DialAddr(ctx, srv.quicListener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}, DefaultQUICConfig())
	if err != nil {
		t.Fatalf("quic dial: %v", err)
	}
	t.Cleanup(func() { _ = qConn.CloseWithError(0, "") })
	cc := (&http3.Transport{EnableDatagrams: true}).NewClientConn(qConn)
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "//"+target, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Proto = "HTTP/1.1"
	req.Header.Set("Authorization", "Bearer relay_token")
	str, err := cc.OpenRequestStream(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if err := str.SendRequestHeader(req); err != nil {
		t.Fatalf("send header: %v", err)
	}
	resp, err := str.ReadResponse()
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d", resp.StatusCode)
	}
	return qConn, str
}

func dpWaitFor(t *testing.T, what string, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

// 一直写数据的目标。
func dpFloodTarget(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			go func() {
				chunk := bytes.Repeat([]byte("z"), 16384)
				for {
					if _, err := c.Write(chunk); err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// 回归：客户端不读流时，下行 goroutine 阻塞在 str.Write，空闲超时无法唤醒，槽位永久占用。
func TestTCPRelayStalledClientReleasesSlot(t *testing.T) {
	var qs *QUICServer
	srv := dpStartEdge(t, func(s *QUICServer) {
		qs = s
		s.tcpIdleTimeout = 300 * time.Millisecond
	})
	target := dpFloodTarget(t)
	_, str := dpConnect(t, srv, target)
	_ = str // 故意不读取

	dpWaitFor(t, "relay slot taken", 3*time.Second, func() bool { return qs.connLimiter.Active() == 1 })
	dpWaitFor(t, "relay slot released after idle timeout", 8*time.Second, func() bool { return qs.connLimiter.Active() == 0 })
}

// 回归：ConnTracker 从不 Remove，连接关闭后记录一直留到 5 分钟一次的 reaper。
func TestConnTrackerRemovedAfterConnClose(t *testing.T) {
	var qs *QUICServer
	srv := dpStartEdge(t, func(s *QUICServer) { qs = s })
	target := readAllThenReply(t)
	qConn, _ := dpConnect(t, srv, target)

	tracked := func() int {
		qs.connTracker.mu.RLock()
		defer qs.connTracker.mu.RUnlock()
		return len(qs.connTracker.conns)
	}
	if n := tracked(); n != 1 {
		t.Fatalf("tracked connections = %d, want 1", n)
	}
	_ = qConn.CloseWithError(0, "bye")
	dpWaitFor(t, "tracker entry removed", 5*time.Second, func() bool { return tracked() == 0 })
}

// ---- 下行字节预算 ----

type dpDiscardConn struct{ once sync.Once }

func (c *dpDiscardConn) ReadPacket([]byte) (int, error)     { return 0, net.ErrClosed }
func (c *dpDiscardConn) WritePacket([]byte) ([]byte, error) { return nil, nil }
func (c *dpDiscardConn) Close() error                       { return nil }

// 会话停止之后入队的报文不得进入队列、不得占用预算；停止前入队的报文全部被归还。
func TestDownlinkBudgetNoLeakAfterStop(t *testing.T) {
	router := NewGlobalTunnelRouter()
	device := &readerTestDevice{packets: make(chan []byte, 1), closed: make(chan struct{})}
	reader, err := NewGlobalTunnelReader(nil, device, router)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	base := downlinkQueuedBytes.Load()

	binding := GlobalTunnelBinding{IPv4: netip.MustParseAddr("10.88.0.50"), Conn: &dpDiscardConn{}}
	pkt := buildRouterTestIPv4(netip.MustParseAddr("1.1.1.1"), binding.IPv4)
	d := reader.downlinkFor(binding)
	d.stop()
	<-d.done
	for i := 0; i < 100; i++ {
		reader.enqueueDownlink(binding, pkt) // downlinkFor 仍返回已停止的 d
	}
	if n := len(d.ch); n != 0 {
		t.Fatalf("packets queued after stop = %d, want 0", n)
	}
	if got := downlinkQueuedBytes.Load(); got != base {
		t.Fatalf("budget after stop = %d, want %d", got, base)
	}
}

// 大量入队与停止交错（-race）：结束后全局预算回到起点。
func TestDownlinkBudgetReturnsToZeroUnderConcurrentClose(t *testing.T) {
	router := NewGlobalTunnelRouter()
	device := &readerTestDevice{packets: make(chan []byte, 1), closed: make(chan struct{})}
	reader, err := NewGlobalTunnelReader(nil, device, router)
	if err != nil {
		t.Fatal(err)
	}
	base := downlinkQueuedBytes.Load()

	binding := GlobalTunnelBinding{IPv4: netip.MustParseAddr("10.88.0.51"), Conn: &dpDiscardConn{}}
	small := buildRouterTestIPv4(netip.MustParseAddr("1.1.1.1"), binding.IPv4)
	big := append(append([]byte(nil), small...), make([]byte, 3000)...) // 超过 2048：走非池化路径
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				if (i+g)%7 == 0 {
					reader.enqueueDownlink(binding, big)
				} else {
					reader.enqueueDownlink(binding, small)
				}
			}
		}(g)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 300; i++ {
			reader.closeDownlink(binding.Generation)
			time.Sleep(50 * time.Microsecond)
		}
		close(stop)
	}()
	wg.Wait()
	if err := reader.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("close: %v", err)
	}
	if got := downlinkQueuedBytes.Load(); got != base {
		t.Fatalf("downlink budget leaked: %d bytes (base %d)", got-base, base)
	}
}
