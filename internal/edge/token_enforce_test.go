package edge

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// newLoopbackQUICPair 在 127.0.0.1 上建立一对真实 QUIC 连接，返回服务端一侧。
// 只使用回环地址，不影响宿主上的其他服务。
func newLoopbackQUICPair(t *testing.T) (server, client *quic.Conn) {
	t.Helper()
	cert, err := generateSelfSignedCert("localhost")
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	ln, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{*cert}, NextProtos: []string{"aero-test"}}, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	accepted := make(chan *quic.Conn, 1)
	go func() {
		c, err := ln.Accept(ctx)
		if err == nil {
			accepted <- c
		}
		close(accepted)
	}()
	client, err = quic.DialAddr(ctx, ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"aero-test"}}, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = client.CloseWithError(0, "") })
	server, ok := <-accepted
	if !ok || server == nil {
		t.Fatal("server did not accept the connection")
	}
	t.Cleanup(func() { _ = server.CloseWithError(0, "") })
	return server, client
}

func waitClosed(t *testing.T, c *quic.Conn, want bool) {
	t.Helper()
	select {
	case <-c.Context().Done():
		if !want {
			t.Fatal("connection was closed but should stay open")
		}
	case <-time.After(500 * time.Millisecond):
		if want {
			t.Fatal("connection was not closed")
		}
	}
}

// 回归（审查 P0-4）：删除、吊销或过期的 token 不会断开已在线的会话。
func TestTokenEnforceClosesOnlyConnectionsWithInvalidTokens(t *testing.T) {
	revokedConn, revokedClient := newLoopbackQUICPair(t)
	validConn, _ := newLoopbackQUICPair(t)

	ct := NewConnTracker()
	ct.Bind(revokedConn, "tok_revoked")
	ct.Bind(validConn, "tok_valid")

	closed := ct.CloseUnauthorized(func(token string) bool { return token == "tok_valid" })

	if closed != 1 {
		t.Fatalf("CloseUnauthorized closed %d connections, want 1", closed)
	}
	waitClosed(t, revokedConn, true)
	waitClosed(t, revokedClient, true)
	waitClosed(t, validConn, false)
	if _, ok := ct.Get(revokedConn); ok {
		t.Fatal("revoked connection still tracked")
	}
	if tok, ok := ct.Get(validConn); !ok || tok != "tok_valid" {
		t.Fatal("valid connection must stay tracked")
	}
}

// QUICServer 必须周期性执行：token 从 validator 中移除后，在线连接在时限内断开。
func TestTokenEnforceServerSweepsRemovedTokens(t *testing.T) {
	v := NewValidator()
	defer v.Close()
	v.AddToken("tok_live", "test", time.Hour)

	s := NewQUICServer(v, nil, nil, nil, nil)
	s.tokenEnforceInterval = 20 * time.Millisecond
	s.startTokenEnforcer()
	defer s.Close()

	conn, _ := newLoopbackQUICPair(t)
	s.connTracker.Bind(conn, "tok_live")

	waitClosed(t, conn, false)
	v.RemoveToken("tok_live")
	waitClosed(t, conn, true)
}
