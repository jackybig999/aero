package edge

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// startRelayTestEdge 启动本机 edge，并为 target 打开一条已建立的标准 CONNECT 流。
func startRelayTestEdge(t *testing.T, target string, tune func(*QUICServer)) *http3.RequestStream {
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

	ctx := context.Background()
	qConn, err := quic.DialAddr(ctx, srv.quicListener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}, DefaultQUICConfig())
	if err != nil {
		t.Fatalf("quic dial: %v", err)
	}
	t.Cleanup(func() { _ = qConn.CloseWithError(0, "") })
	h3 := (&http3.Transport{EnableDatagrams: true}).NewClientConn(qConn)
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "//"+target, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Proto = "HTTP/1.1"
	req.Header.Set("Authorization", "Bearer relay_token")
	req.Header.Set("Aero-Timestamp", strconv.FormatInt(time.Now().UnixMilli(), 10))
	req.Header.Set("Aero-Nonce", hex.EncodeToString(bytes.Repeat([]byte{0x4d}, 32)))
	str, err := h3.OpenRequestStream(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if err := str.SendRequestHeader(req); err != nil {
		t.Fatalf("send header: %v", err)
	}
	resp, err := str.ReadResponse()
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT failed: %v %v", resp, err)
	}
	return str
}

// readAllThenReply 模拟“读到 EOF 后才回复”的服务器（HTTP/1.0、nc、部分 RPC）。
func readAllThenReply(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				n, _ := io.Copy(io.Discard, c)
				_, _ = fmt.Fprintf(c, "received:%d", n)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// 回归：客户端关闭写端后，中继曾立即关闭两个方向，目标服务器的响应永远回不来。
func TestTCPRelayHalfCloseDeliversResponse(t *testing.T) {
	str := startRelayTestEdge(t, readAllThenReply(t), nil)

	payload := bytes.Repeat([]byte("x"), 5000)
	if _, err := str.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := str.Close(); err != nil { // 关闭客户端写端（半关闭）
		t.Fatalf("close write side: %v", err)
	}
	str.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, err := io.ReadAll(str)
	if err != nil {
		t.Fatalf("read response after half-close: %v", err)
	}
	if string(got) != "received:5000" {
		t.Fatalf("response = %q, want received:5000", got)
	}
}

// 只有上行流量（目标在上传期间不回数据）的连接不得被空闲判定切断；空闲按双向计算。
func TestTCPRelayUploadOnlyIsNotIdle(t *testing.T) {
	str := startRelayTestEdge(t, readAllThenReply(t), func(s *QUICServer) { s.tcpIdleTimeout = 300 * time.Millisecond })

	for i := 0; i < 12; i++ { // 约 1.2 秒，超过空闲上限 4 倍，期间目标不回任何数据
		if _, err := str.Write([]byte("chunk")); err != nil {
			t.Fatalf("upload write %d: %v (active upload was cut as idle)", i, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = str.Close()
	str.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, err := io.ReadAll(str)
	if err != nil || string(got) != "received:60" {
		t.Fatalf("response = %q (err %v), want received:60", got, err)
	}
}

// 双向都没有流量的连接在空闲上限后被关闭，资源有上界。
func TestTCPRelayTrulyIdleConnectionIsClosed(t *testing.T) {
	str := startRelayTestEdge(t, readAllThenReply(t), func(s *QUICServer) { s.tcpIdleTimeout = 200 * time.Millisecond })

	str.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err := io.ReadAll(str)
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("idle relay was not closed by the server within 3s")
	}
}
