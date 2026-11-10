package edge

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

const udpTriggerOversize = "trigger-oversize"

// 回归：上游一个超过 QUIC 数据报上限的 UDP 报文曾使 SendDatagram 报错并断开整条
// CONNECT-UDP 会话。超大报文必须被丢弃，会话继续工作。
func TestConnectUDPResilienceOversizedUpstreamDatagramKeepsSession(t *testing.T) {
	listenAddr, host := findTestAddr()
	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		t.Fatal(err)
	}
	upstream, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, rAddr, err := upstream.ReadFrom(buf)
			if err != nil {
				return
			}
			if string(buf[:n]) == udpTriggerOversize {
				_, _ = upstream.WriteTo(bytes.Repeat([]byte{0xAB}, 3000), rAddr) // 超过 QUIC 数据报上限
			}
			_, _ = upstream.WriteTo(buf[:n], rAddr)
		}
	}()

	edgeAddr, _ := findTestAddr()
	srv, err := NewServer(ServerConfig{Listen: edgeAddr, Domain: host, DataDir: t.TempDir(), Token: "udp_resilience_token", AllowSelfSignedCertForTest: true})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	qConn, err := quic.DialAddr(ctx, srv.quicListener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}, DefaultQUICConfig())
	if err != nil {
		t.Fatalf("quic dial: %v", err)
	}
	defer qConn.CloseWithError(0, "")
	masqueConn := masque.NewClientConn((&http3.Transport{EnableDatagrams: true}).NewClientConn(qConn))

	target := upstream.LocalAddr().String()
	mReq, err := masque.NewRequest(ctx, uritemplate.MustNew("https://"+host+"/.well-known/masque/udp/{target_host}/{target_port}/"), target)
	if err != nil {
		t.Fatalf("masque.NewRequest: %v", err)
	}
	mReq.Header().Set("Authorization", "Bearer udp_resilience_token")
	mReq.Header().Set("Aero-Timestamp", strconv.FormatInt(time.Now().UnixMilli(), 10))
	mReq.Header().Set("Aero-Nonce", hex.EncodeToString(bytes.Repeat([]byte{0x5a}, 32)))
	mConn, resp, err := masqueConn.Dial(mReq)
	if err != nil {
		t.Fatalf("masque dial: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("connect-udp rejected: %d", resp.StatusCode)
	}
	defer mConn.Close()

	rAddr, _ := net.ResolveUDPAddr("udp", target)
	expectEcho := func(payload string) {
		t.Helper()
		if _, err := mConn.WriteTo([]byte(payload), rAddr); err != nil {
			t.Fatalf("write %q: %v", payload, err)
		}
		buf := make([]byte, 4096)
		_ = mConn.SetReadDeadline(time.Now().Add(3 * time.Second))
		for {
			n, _, err := mConn.ReadFrom(buf)
			if err != nil {
				t.Fatalf("waiting for echo %q: %v (session closed by oversized datagram?)", payload, err)
			}
			if string(buf[:n]) == payload {
				return
			}
		}
	}
	expectEcho(udpTriggerOversize)
	expectEcho("still-alive-after-oversize")
}

// DoH 请求体超过 4096 字节必须拒绝（413），不得整体读入内存。
func TestDoHBodyLimitRejectsOversizedQuery(t *testing.T) {
	v := NewValidator()
	defer v.Close()
	s := NewQUICServer(v, nil, nil, nil, nil)
	defer s.Close()
	s.SetAllowLoopbackForTest(true) // 无 QUIC 连接上下文时走回退校验路径

	v.AddToken("doh_limit_token", "test", time.Hour)
	req := httptest.NewRequest(http.MethodPost, "/dns-query", strings.NewReader(strings.Repeat("A", 5000)))
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Authorization", "Bearer doh_limit_token")
	req.Header.Set("Aero-Timestamp", strconv.FormatInt(time.Now().UnixMilli(), 10))
	req.Header.Set("Aero-Nonce", hex.EncodeToString(bytes.Repeat([]byte{0x7b}, 32)))
	req.RemoteAddr = "203.0.113.5:4000"
	rec := httptest.NewRecorder()

	s.serveDoH(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized DoH status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
}
