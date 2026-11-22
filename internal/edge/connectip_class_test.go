// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package edge

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

func classReq(qc *quic.Conn, class ...string) *http.Request {
	req := dpConnectIPReq(qc)
	for _, c := range class {
		req.Header.Add(headerClass, c)
	}
	return req
}

func TestParseConnectIPClass(t *testing.T) {
	cases := []struct {
		name   string
		values []string
		want   string // 空表示拒绝
	}{
		{"absent means default", nil, classDefault},
		{"default", []string{"default"}, classDefault},
		{"ai", []string{"ai"}, classAI},
		{"reserved browser", []string{"browser"}, ""},
		{"reserved game", []string{"game"}, ""},
		{"case sensitive", []string{"AI"}, ""},
		{"leading space", []string{" ai"}, ""},
		{"empty value", []string{""}, ""},
		{"unknown", []string{"vpn"}, ""},
		{"two header lines", []string{"ai", "default"}, ""},
		{"comma list", []string{"ai,default"}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodConnect, "https://example.com/", nil)
			for _, v := range c.values {
				req.Header.Add(headerClass, v)
			}
			rec := httptest.NewRecorder()
			got, ok := parseConnectIPClass(rec, req)
			if c.want == "" {
				if ok || rec.Code != http.StatusBadRequest ||
					!strings.Contains(rec.Header().Get("Proxy-Status"), "error=unsupported_class") ||
					!strings.Contains(rec.Header().Get("Proxy-Status"), "EDGE_UNSUPPORTED_CLASS") {
					t.Fatalf("ok=%v code=%d proxy-status=%q", ok, rec.Code, rec.Header().Get("Proxy-Status"))
				}
				return
			}
			if !ok || got.name != c.want {
				t.Fatalf("got %q ok=%v, want %q", got.name, ok, c.want)
			}
		})
	}
	// 传输方式固定：default 数据报，ai capsule。
	if connectIPClasses[classDefault].transport != "datagram" || connectIPClasses[classDefault].mode != connectip.DataModeDatagram ||
		connectIPClasses[classAI].transport != "capsule" || connectIPClasses[classAI].mode != connectip.DataModeCapsule {
		t.Fatal("class to transport mapping changed")
	}
}

func TestClassAllowedByClaims(t *testing.T) {
	if !classAllowedByClaims(nil, classAI) || !classAllowedByClaims(nil, classDefault) {
		t.Fatal("opaque token / hop credential (nil claims) must be allowed")
	}
	only := &TokenClaims{Classes: []string{classDefault}}
	if !classAllowedByClaims(only, classDefault) || classAllowedByClaims(only, classAI) {
		t.Fatal("signed token classes not enforced")
	}
	both := &TokenClaims{Classes: []string{classDefault, classAI}}
	if !classAllowedByClaims(both, classAI) {
		t.Fatal("ai must be allowed when listed")
	}
	if classAllowedByClaims(&TokenClaims{}, classDefault) {
		t.Fatal("a token without classes must not authorize anything")
	}
}

func TestConnectIPSessionTablePerClass(t *testing.T) {
	withAliveConns(t, func(*quic.Conn) bool { return true })
	var tbl connectIPSessionTable
	c1, c2 := &quic.Conn{}, &quic.Conn{}

	d1, ok := tbl.acquireClass(c1, "uid:a", classDefault, 1, 10)
	if !ok {
		t.Fatal("default session rejected")
	}
	// 同一连接的另一类别：同一台设备，不受 perKey=1 限制。
	a1, ok := tbl.acquireClass(c1, "uid:a", classAI, 1, 10)
	if !ok {
		t.Fatal("ai session on the same connection rejected (same device)")
	}
	if _, ok := tbl.acquireClass(c1, "uid:a", classAI, 1, 10); ok {
		t.Fatal("second ai session on one connection accepted")
	}
	if _, ok := tbl.acquireClass(c1, "uid:a", classDefault, 1, 10); ok {
		t.Fatal("second default session on one connection accepted")
	}
	// 第二台设备超限。
	if _, ok := tbl.acquireClass(c2, "uid:a", classDefault, 1, 10); ok {
		t.Fatal("second device accepted beyond perKey=1")
	}
	if tbl.active() != 2 {
		t.Fatalf("active = %d, want 2 (global limit counts sessions)", tbl.active())
	}
	// 释放其中一条：设备仍占用，另一台仍不能进。
	tbl.release(d1)
	if _, ok := tbl.acquireClass(c2, "uid:a", classDefault, 1, 10); ok {
		t.Fatal("device slot freed while the ai session still holds the connection")
	}
	// 全部释放后，另一台设备可以进。
	tbl.release(a1)
	d2, ok := tbl.acquireClass(c2, "uid:a", classDefault, 1, 10)
	if !ok {
		t.Fatal("device rejected after all sessions released")
	}
	tbl.release(d2)
	if tbl.active() != 0 || len(tbl.byConn) != 0 || len(tbl.byKey) != 0 {
		t.Fatalf("table not empty: active=%d byConn=%d byKey=%d", tbl.active(), len(tbl.byConn), len(tbl.byKey))
	}

	// 全局上限按会话数计：一台设备的两条会话占两个名额。
	x, _ := tbl.acquireClass(c1, "uid:b", classDefault, 5, 2)
	y, ok := tbl.acquireClass(c1, "uid:b", classAI, 5, 2)
	if !ok {
		t.Fatal("setup failed")
	}
	if _, ok := tbl.acquireClass(c2, "uid:c", classDefault, 5, 2); ok {
		t.Fatal("global limit 2 not enforced for sessions")
	}
	tbl.release(x)
	tbl.release(y)
}

func TestConnectIPSessionTableDeadConnPruned(t *testing.T) {
	dead := &quic.Conn{}
	withAliveConns(t, func(c *quic.Conn) bool { return c != dead })
	var tbl connectIPSessionTable
	if _, ok := tbl.acquireClass(dead, "uid:a", classDefault, 1, 10); !ok {
		t.Fatal("setup failed")
	}
	if _, ok := tbl.acquireClass(dead, "uid:a", classAI, 1, 10); !ok {
		t.Fatal("setup failed")
	}
	// 旧连接已关闭：新设备替换它，两条旧会话都被清掉。
	fresh := &quic.Conn{}
	if _, ok := tbl.acquireClass(fresh, "uid:a", classDefault, 1, 10); !ok {
		t.Fatal("new device rejected although the old connection is dead")
	}
	if tbl.active() != 1 {
		t.Fatalf("active = %d, want 1", tbl.active())
	}
}

// 签名 token 的请求：与 dpConnectIPReq 相同的形状，token 由夹具签发。
func signedClassReq(token string, qc *quic.Conn, class ...string) *http.Request {
	req := classReq(qc, class...)
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

// 授权与参数检查发生在认证之后，且在占用任何名额之前。
func TestServeConnectIPClassRejections(t *testing.T) {
	withAliveConns(t, func(*quic.Conn) bool { return true })
	qs := newDPServer(t, nil)

	// 未认证：先 401，不暴露类别校验。
	req := classReq(&quic.Conn{}, "game")
	req.Header.Del("Authorization")
	rec := httptest.NewRecorder()
	qs.serveConnectIP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated bad class: %d, want 401", rec.Code)
	}

	// 保留值与未知值：400。
	for _, c := range []string{"game", "browser", "vpn"} {
		rec = httptest.NewRecorder()
		qs.serveConnectIP(rec, classReq(&quic.Conn{}, c))
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Header().Get("Proxy-Status"), "unsupported_class") {
			t.Fatalf("class %q: %d %q", c, rec.Code, rec.Header().Get("Proxy-Status"))
		}
	}

	// 不透明 token（过渡期）授权全部已实现类别：ai 通过类别检查，在没有地址池处停下。
	qs.aiPool = nil
	rec = httptest.NewRecorder()
	qs.serveConnectIP(rec, classReq(&quic.Conn{}, "ai"))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Header().Get("Proxy-Status"), "address_pool_exhausted") {
		t.Fatalf("opaque token ai: %d %q", rec.Code, rec.Header().Get("Proxy-Status"))
	}

	// 签名 token 只授权 default：ai 得到 403 EDGE_CLASS_NOT_ALLOWED，default 通过类别检查。
	f := newSignedAuthFixture(t) // 夹具签发的 token 的 classes 为 ["default"]
	tok := f.token(t, "user_classes01", 3, time.Hour)
	qc := &quic.Conn{}
	rec = httptest.NewRecorder()
	f.qs.serveConnectIP(rec, signedClassReq(tok, qc, "ai"))
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Header().Get("Proxy-Status"), "EDGE_CLASS_NOT_ALLOWED") {
		t.Fatalf("unauthorized class: %d %q", rec.Code, rec.Header().Get("Proxy-Status"))
	}
	if n := f.qs.connectIPSessions.active(); n != 0 {
		t.Fatalf("rejected request left %d sessions", n)
	}
	f.qs.ipPool = nil // 让 default 在地址池处停下（httptest 的响应写入器没有 H3 流）
	rec = httptest.NewRecorder()
	f.qs.serveConnectIP(rec, signedClassReq(tok, qc))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Header().Get("Proxy-Status"), "address_pool_exhausted") {
		t.Fatalf("default class did not pass the class gate: %d %q", rec.Code, rec.Header().Get("Proxy-Status"))
	}
}

// 授权只取决于本次请求验签得到的载荷，与连接绑定的先后无关：
// 新连接上并发的 ai 请求（token 只授权 default）全部是 403，没有任何一个通过。
// 注意：这是回归测试，对旧实现（类别存放在连接绑定表里）只能按概率触发——旧竞态窗口只有绑定与写入
// 之间的几条指令；对现在的实现它是确定的（每次都是 403），没有时间依赖。
func TestServeConnectIPClassGateIsRaceFree(t *testing.T) {
	withAliveConns(t, func(*quic.Conn) bool { return true })
	prevClose := closeEvictedConn // 轮次多于 max_devices：被驱逐的零值连接不能真的关闭
	closeEvictedConn = func(*quic.Conn) {}
	t.Cleanup(func() { closeEvictedConn = prevClose })
	f := newSignedAuthFixture(t)
	tok := f.token(t, "user_race00001", 3, time.Hour)
	for round := 0; round < 20; round++ {
		qc := &quic.Conn{} // 每轮一条新连接，请求争着做首次绑定
		const n = 16
		codes := make(chan int, n)
		start := make(chan struct{})
		for i := 0; i < n; i++ {
			go func() {
				<-start
				rec := httptest.NewRecorder()
				req := signedClassReq(tok, qc, "ai")
				req.RemoteAddr = "203.0.113.200:5000"
				f.qs.serveConnectIP(rec, req)
				codes <- rec.Code
			}()
		}
		close(start)
		for i := 0; i < n; i++ {
			if code := <-codes; code != http.StatusForbidden {
				t.Fatalf("round %d: concurrent ai request got %d, want 403", round, code)
			}
		}
	}
	if n := f.qs.connectIPSessions.active(); n != 0 {
		t.Fatalf("sessions left: %d", n)
	}
}

// 不透明 token：每台设备（每条连接）最多 2 条会话（default 与 ai），8 台设备共 16 条；第 9 台被拒。
func TestConnectIPSessionTableOpaqueTokenLimit(t *testing.T) {
	withAliveConns(t, func(*quic.Conn) bool { return true })
	var tbl connectIPSessionTable
	var held []*connectIPSession
	for i := 0; i < connectIPMaxSessionsOpaque; i++ {
		c := &quic.Conn{}
		for _, class := range []string{classDefault, classAI} {
			s, ok := tbl.acquireClass(c, "tok", class, connectIPMaxSessionsOpaque, 100)
			if !ok {
				t.Fatalf("device %d class %s rejected below the limit", i, class)
			}
			held = append(held, s)
		}
	}
	if got := tbl.active(); got != 2*connectIPMaxSessionsOpaque {
		t.Fatalf("active = %d, want %d", got, 2*connectIPMaxSessionsOpaque)
	}
	if _, ok := tbl.acquireClass(&quic.Conn{}, "tok", classDefault, connectIPMaxSessionsOpaque, 100); ok {
		t.Fatal("a ninth device was accepted")
	}
	for _, s := range held {
		tbl.release(s)
	}
	if tbl.active() != 0 {
		t.Fatalf("active = %d after release", tbl.active())
	}
}

// 没有为 ai 配置地址池的节点：ai 返回 503 address_pool_exhausted，default 不受影响。
func TestServeConnectIPAIWithoutPool(t *testing.T) {
	withAliveConns(t, func(*quic.Conn) bool { return true })
	qs := newDPServer(t, nil)
	qs.aiPool = nil
	rec := httptest.NewRecorder()
	qs.serveConnectIP(rec, classReq(&quic.Conn{}, "ai"))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Header().Get("Proxy-Status"), "address_pool_exhausted") {
		t.Fatalf("ai without pool: %d %q", rec.Code, rec.Header().Get("Proxy-Status"))
	}
	if n := qs.connectIPSessions.active(); n != 0 {
		t.Fatalf("sessions left: %d", n)
	}
}

// 两个类别的地址互不相同，且分别落在各自子网；同一 token 重连拿回同类别的原地址。
func TestClassPoolsDisjointAndSticky(t *testing.T) {
	qs := newDPServer(t, nil)
	defNet := netip.MustParsePrefix(edgeDefaultPoolCIDR)
	aiNet := netip.MustParsePrefix(edgeAIPoolCIDR)
	d1, err := qs.poolForClass(classDefault).AllocateFor("uid:x")
	if err != nil {
		t.Fatal(err)
	}
	a1, err := qs.poolForClass(classAI).AllocateFor("uid:x/ai")
	if err != nil {
		t.Fatal(err)
	}
	if !defNet.Contains(d1.Addr()) || aiNet.Contains(d1.Addr()) {
		t.Fatalf("default address %s not in %s", d1, defNet)
	}
	if !aiNet.Contains(a1.Addr()) || defNet.Contains(a1.Addr()) {
		t.Fatalf("ai address %s not in %s", a1, aiNet)
	}
	if defNet.Overlaps(aiNet) {
		t.Fatal("class subnets overlap")
	}
	qs.poolForClass(classAI).ReleaseFor("uid:x/ai", a1)
	a2, err := qs.poolForClass(classAI).AllocateFor("uid:x/ai")
	if err != nil || a2 != a1 {
		t.Fatalf("ai lease not sticky: %v %v", a2, err)
	}
	if qs.poolForClass("game") != nil || qs.poolForClass("") != nil {
		t.Fatal("unknown class must have no pool")
	}
}

func udpEchoPacket(src netip.Addr, payload []byte) []byte {
	pkt := make([]byte, 20+8+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = 17
	s := src.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], net.IPv4(1, 1, 1, 1).To4()) // 内存设备回显；目的必须是公网地址（目的 ACL）
	binary.BigEndian.PutUint16(pkt[10:12], calcChecksum(pkt[:20]))
	binary.BigEndian.PutUint16(pkt[20:22], 12345)
	binary.BigEndian.PutUint16(pkt[22:24], 54321)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(8+len(payload)))
	copy(pkt[28:], payload)
	return pkt
}

// 真实 HTTP/3：同一条 QUIC 连接上两条 CONNECT-IP 会话（default 数据报、ai capsule），
// 各自拿到自己子网的地址，各自完成 UDP 往返；同类别第二条被拒；不带 Aero-Class 的请求仍是 default。
func TestConnectIPDualSessionsOverOneConnection(t *testing.T) {
	listenAddr, host := findTestAddr()
	srv, err := NewServer(ServerConfig{
		Listen: listenAddr, Domain: host, DataDir: t.TempDir(),
		Token: "dual_session_token", AllowSelfSignedCertForTest: true,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	qConn, err := quic.DialAddr(ctx, srv.quicListener.Addr().String(),
		&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}, DefaultQUICConfig())
	if err != nil {
		t.Fatalf("DialAddr: %v", err)
	}
	defer qConn.CloseWithError(0, "done")
	cc := connectip.NewClientConn((&http3.Transport{EnableDatagrams: true}).NewClientConn(qConn))
	tmpl := uritemplate.MustNew("https://" + host + "/.well-known/masque/ip/*/*/")

	dial := func(class string, mode connectip.DataMode) (*connectip.Conn, *http.Response, error) {
		req, err := connectip.NewRequest(ctx, tmpl)
		if err != nil {
			t.Fatal(err)
		}
		req.Header().Set("Authorization", "Bearer dual_session_token")
		if class != "" {
			req.Header().Set(headerClass, class)
		}
		return cc.DialWithMode(req, mode)
	}

	// default：不带 Aero-Class，数据报。
	dConn, dResp, err := dial("", connectip.DataModeDatagram)
	if err != nil {
		t.Fatalf("default dial: %v", err)
	}
	defer dConn.Close()
	if got := dResp.Header.Get(headerTransport); got != transportDatagram {
		t.Fatalf("default Aero-Transport = %q", got)
	}
	// ai：capsule。
	aConn, aResp, err := dial("ai", connectip.DataModeCapsule)
	if err != nil {
		t.Fatalf("ai dial: %v", err)
	}
	defer aConn.Close()
	if got := aResp.Header.Get(headerTransport); got != transportCapsule {
		t.Fatalf("ai Aero-Transport = %q", got)
	}

	dAssigned, err := dConn.ReceiveAddressAssignment(ctx)
	if err != nil || len(dAssigned) == 0 {
		t.Fatalf("default assignment: %v %v", dAssigned, err)
	}
	aAssigned, err := aConn.ReceiveAddressAssignment(ctx)
	if err != nil || len(aAssigned) == 0 {
		t.Fatalf("ai assignment: %v %v", aAssigned, err)
	}
	dAddr, aAddr := dAssigned[0].IPPrefix.Addr(), aAssigned[0].IPPrefix.Addr()
	if !netip.MustParsePrefix(edgeDefaultPoolCIDR).Contains(dAddr) {
		t.Fatalf("default address %s outside %s", dAddr, edgeDefaultPoolCIDR)
	}
	if !netip.MustParsePrefix(edgeAIPoolCIDR).Contains(aAddr) {
		t.Fatalf("ai address %s outside %s", aAddr, edgeAIPoolCIDR)
	}
	// 服务端先下发地址再登记路由，客户端收到地址时登记可能还没完成：轮询到截止时间。
	routerDeadline := time.Now().Add(5 * time.Second)
	for srv.quicServer.globalRouter.Size() != 2 {
		if time.Now().After(routerDeadline) {
			t.Fatalf("router has %d bindings, want 2", srv.quicServer.globalRouter.Size())
		}
		time.Sleep(10 * time.Millisecond)
	}

	// 同类别的第二条会话被拒绝（每条连接每个类别 1 条）。
	if _, resp, err := dial("ai", connectip.DataModeCapsule); err == nil || resp == nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("second ai session: resp=%v err=%v, want 503", resp, err)
	}
	// 保留类别被拒绝。
	if _, resp, err := dial("game", connectip.DataModeDatagram); err == nil || resp == nil || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("game class: resp=%v err=%v, want 400", resp, err)
	}

	// 两条会话各自 UDP 往返（内存设备回显）。
	roundtrip := func(name string, c *connectip.Conn, src netip.Addr) {
		payload := []byte("payload-via-" + name)
		done := make(chan []byte, 1)
		go func() {
			buf := make([]byte, 65535)
			for {
				n, err := c.ReadPacket(buf)
				if err != nil {
					return
				}
				if n >= 28 && buf[9] == 17 {
					done <- append([]byte(nil), buf[28:n]...)
					return
				}
			}
		}()
		if _, err := c.WritePacket(udpEchoPacket(src, payload)); err != nil {
			t.Fatalf("%s write: %v", name, err)
		}
		select {
		case got := <-done:
			if !bytes.Equal(got, payload) {
				t.Fatalf("%s echo mismatch: %q", name, got)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: timeout waiting for echo", name)
		}
	}
	roundtrip("datagram", dConn, dAddr)
	roundtrip("capsule", aConn, aAddr)

	// 关闭 ai 会话后，名额释放，可重新建立。
	_ = aConn.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, _, err := dial("ai", connectip.DataModeCapsule)
		if err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("ai session not re-established after close: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
