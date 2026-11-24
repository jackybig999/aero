// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"node.test"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// classServer 模拟 edge 的 CONNECT-IP 入口：按 Aero-Class 选择模式，响应头与状态码可被测试改写。
type classServer struct {
	transportFor func(class string) (transport string, mode connectip.DataMode) // transport 为空表示不回该头（旧节点）
	status       int                                                            // 非 0 时直接以该状态拒绝
	proxyStatus  string
	seenClass    chan string
}

func startClassServer(t *testing.T, cs *classServer) *Session {
	t.Helper()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	template := uritemplate.MustNew("https://node.test/.well-known/masque/ip/*/*/")
	cs.seenClass = make(chan string, 8)
	srv := &http3.Server{
		EnableDatagrams: true,
		TLSConfig:       &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}, NextProtos: []string{"h3"}},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			class := r.Header.Get(headerClassName)
			cs.seenClass <- class
			if cs.status != 0 {
				if cs.proxyStatus != "" {
					w.Header().Set("Proxy-Status", cs.proxyStatus)
				}
				w.WriteHeader(cs.status)
				return
			}
			req, err := connectip.ParseProxyRequest(r, template)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			transport, mode := cs.transportFor(class)
			if transport != "" {
				w.Header().Set(headerTransport, transport)
			}
			conn, err := (&connectip.Proxy{}).ProxyWithMode(w, req, mode)
			if err != nil {
				return
			}
			defer conn.Close()
			_ = conn.AssignAddresses([]netip.Prefix{netip.MustParsePrefix("10.88.130.9/32")})
			<-r.Context().Done()
		}),
	}
	go func() { _ = srv.Serve(udp) }()
	t.Cleanup(func() { _ = srv.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	qc, err := quic.DialAddr(ctx, udp.LocalAddr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = qc.CloseWithError(0, "") })
	cc := connectip.NewClientConn((&http3.Transport{EnableDatagrams: true}).NewClientConn(qc))
	return &Session{connectIPConn: cc, token: "tok", addr: "node.test:443", sni: "node.test"}
}

func TestDialIPClassTransportNegotiation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	t.Run("ai gets capsule", func(t *testing.T) {
		cs := &classServer{transportFor: func(class string) (string, connectip.DataMode) {
			if class == "ai" {
				return "capsule", connectip.DataModeCapsule
			}
			return "datagram", connectip.DataModeDatagram
		}}
		s := startClassServer(t, cs)
		conn, prefixes, err := s.DialIPClass(ctx, classNameAI)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if got := <-cs.seenClass; got != "ai" {
			t.Fatalf("server saw class %q", got)
		}
		if conn.DataMode() != connectip.DataModeCapsule || len(prefixes) != 1 || prefixes[0].Addr() != netip.MustParseAddr("10.88.130.9") {
			t.Fatalf("mode=%v prefixes=%v", conn.DataMode(), prefixes)
		}
	})

	t.Run("default sends no class header and tolerates an old node", func(t *testing.T) {
		for _, answer := range []string{"", "datagram"} { // 旧节点不回 Aero-Transport
			cs := &classServer{transportFor: func(string) (string, connectip.DataMode) { return answer, connectip.DataModeDatagram }}
			s := startClassServer(t, cs)
			conn, _, err := s.DialIP(ctx)
			if err != nil {
				t.Fatalf("answer %q: %v", answer, err)
			}
			if got := <-cs.seenClass; got != "" {
				t.Fatalf("default session sent class %q", got)
			}
			conn.Close()
		}
	})

	t.Run("mismatch is an error and never used", func(t *testing.T) {
		cases := []struct {
			name, class, answer string
			mode                connectip.DataMode
		}{
			{"ai answered datagram", classNameAI, "datagram", connectip.DataModeDatagram},
			{"ai old node without header", classNameAI, "", connectip.DataModeDatagram},
			{"default answered capsule", "", "capsule", connectip.DataModeCapsule},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				cs := &classServer{transportFor: func(string) (string, connectip.DataMode) { return c.answer, c.mode }}
				s := startClassServer(t, cs)
				conn, _, err := s.DialIPClass(ctx, c.class)
				if !errors.Is(err, ErrTransportMismatch) || conn != nil {
					t.Fatalf("conn=%v err=%v, want ErrTransportMismatch", conn, err)
				}
			})
		}
	})

	t.Run("class rejections are recognized", func(t *testing.T) {
		for _, c := range []struct {
			status int
			ps     string
			code   string
		}{
			{http.StatusForbidden, `aero; error=class_not_allowed; details="EDGE_CLASS_NOT_ALLOWED"`, "class_not_allowed"},
			{http.StatusBadRequest, `aero; error=unsupported_class; details="EDGE_UNSUPPORTED_CLASS"`, "unsupported_class"},
		} {
			cs := &classServer{status: c.status, proxyStatus: c.ps}
			s := startClassServer(t, cs)
			_, _, err := s.DialIPClass(ctx, classNameAI)
			var rej *EdgeRejectError
			if !errors.As(err, &rej) || rej.Code != c.code || !rej.ClassRejected() || rej.AuthFailure() {
				t.Fatalf("status %d: err=%v", c.status, err)
			}
			if reason, permanent := aiReason(err); !permanent || reason == "" {
				t.Fatalf("aiReason(%v) = %q permanent=%v", err, reason, permanent)
			}
		}
	})

	t.Run("unknown class is refused locally", func(t *testing.T) {
		s := startClassServer(t, &classServer{transportFor: func(string) (string, connectip.DataMode) { return "datagram", connectip.DataModeDatagram }})
		if _, _, err := s.DialIPClass(ctx, "game"); err == nil {
			t.Fatal("a reserved class must not be dialed")
		}
	})
}

func TestServerConfigParsesTransports(t *testing.T) {
	sub := &Subscription{}
	err := json.Unmarshal([]byte(`{"version":"aero/3.0","servers":[
	  {"name":"a","host":"a.example.com","token":"t","sni":"a.example.com","protocol":"connect-ip","transports":["datagram","capsule"]},
	  {"name":"b","host":"b.example.com","token":"t","sni":"b.example.com","protocol":"connect-ip"}]}`), sub)
	if err != nil {
		t.Fatal(err)
	}
	if err := sub.ValidateAndNormalize(); err != nil {
		t.Fatal(err)
	}
	if got := sub.Servers[0].Transports; len(got) != 2 || got[1] != "capsule" {
		t.Fatalf("transports = %v", got)
	}
	if sub.Servers[1].Transports != nil {
		t.Fatalf("a node without the field must have none, got %v", sub.Servers[1].Transports)
	}
	applied, err := ApplySubscription(sub)
	if err != nil || len(applied.Servers[0].Transports) != 2 {
		t.Fatalf("Apply dropped the field: %v %v", applied, err)
	}
}

// ai 会话必须固定在承载 default CONNECT-IP 会话的同一个 Session 上：切换节点后旧会话处于排空期时，
// 不得改拨到新会话（那会让两条会话分处两处，并在 edge 上多占设备名额）。
func TestPinnedSessionStaysOnDefaultSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	mk := func() (*classServer, *Session) {
		cs := &classServer{transportFor: func(class string) (string, connectip.DataMode) {
			if class == classNameAI {
				return "capsule", connectip.DataModeCapsule
			}
			return "datagram", connectip.DataModeDatagram
		}}
		return cs, startClassServer(t, cs)
	}

	m := NewSessionManager()
	if m.pinnedSession() != nil {
		t.Fatal("还没有 default 会话时不应有登记")
	}
	if _, _, err := dialAIFn(ctx, nil); !errors.Is(err, errNoPinnedSession) {
		t.Fatalf("没有 Session 时应报 errNoPinnedSession: %v", err)
	}

	csA, sessA := mk()
	csB, sessB := mk()
	m.SetSession(sessA)
	connD, _, err := m.DialIP(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connD.Close()
	if got := <-csA.seenClass; got != "" {
		t.Fatalf("default 应不带类别头: %q", got)
	}
	if m.pinnedSession() != sessA {
		t.Fatal("DialIP 成功后应登记承载它的 Session")
	}

	// 切换节点：A 进入排空期，B 成为当前会话。登记仍是 A，ai 拨到 A。
	sessA.MarkDraining()
	m.SetSession(sessB)
	pinned := m.pinnedSession()
	if pinned != sessA {
		t.Fatal("排空期内登记应仍是 default 所在的 A")
	}
	connAI, _, err := dialAIFn(ctx, pinned)
	if err != nil {
		t.Fatalf("排空期内 ai 应仍能在 A 上建立: %v", err)
	}
	defer connAI.Close()
	select {
	case got := <-csA.seenClass:
		if got != classNameAI {
			t.Fatalf("A 收到的类别 %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ai 会话没有建立在 default 所在的 A 上")
	}
	select {
	case got := <-csB.seenClass:
		t.Fatalf("B 不应收到任何请求，却收到类别 %q", got)
	default:
	}

	// 承载 default 的 Session 关闭后：报错，不改拨到别处（default 也已断开，引擎重连会整体重建）。
	_ = sessA.Close()
	if _, _, err := dialAIFn(ctx, pinned); !errors.Is(err, errNoPinnedSession) {
		t.Fatalf("A 关闭后应报 errNoPinnedSession: %v", err)
	}
	select {
	case got := <-csB.seenClass:
		t.Fatalf("B 不应收到任何请求，却收到类别 %q", got)
	default:
	}

	// Reset 清掉登记。
	m.SetSession(sessB)
	if c, _, err := m.DialIP(ctx); err != nil {
		t.Fatal(err)
	} else {
		defer c.Close()
	}
	if m.pinnedSession() != sessB {
		t.Fatal("再次 DialIP 后登记应更新为 B")
	}
	m.Reset()
	if m.pinnedSession() != nil {
		t.Fatal("Reset 后应清除登记")
	}
}
