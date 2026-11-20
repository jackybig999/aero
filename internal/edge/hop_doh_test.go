package edge

import (
	"bytes"
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

const hopTestCred = "hop-doh-secret"

// startHopPair 起一个真实的出口与入口（HTTP/3、自签证书），返回两端；出口的 DoH 上游指向 egressUp。
func startHopPair(t *testing.T, egressUp, ingressUp *fakeDNS, ingressCred string) (egress, ingress *Server) {
	t.Helper()
	egressListen, egressHost := findTestAddr()
	egress, err := NewServer(ServerConfig{
		Listen: egressListen, Domain: egressHost, Role: "egress", HopCredential: hopTestCred,
		DataDir: t.TempDir(), AllowSelfSignedCertForTest: true,
	})
	if err != nil {
		t.Fatalf("NewServer egress: %v", err)
	}
	egress.quicServer.doh.upstreams = func() []string { return []string{egressUp.addr} }
	if err := egress.Start(); err != nil {
		t.Fatalf("egress Start: %v", err)
	}
	t.Cleanup(egress.Close)

	ingressListen, ingressHost := findTestAddr()
	ingress, err = NewServer(ServerConfig{
		Listen: ingressListen, Domain: ingressHost, Token: "client-user-token", Role: "ingress",
		HopCredential: ingressCred, NextHopAddr: egress.Addr(), DataDir: t.TempDir(), AllowSelfSignedCertForTest: true,
	})
	if err != nil {
		t.Fatalf("NewServer ingress: %v", err)
	}
	ingress.quicServer.doh.upstreams = func() []string { return []string{ingressUp.addr} }
	if err := ingress.Start(); err != nil {
		t.Fatalf("ingress Start: %v", err)
	}
	t.Cleanup(ingress.Close)
	return egress, ingress
}

func postDoHH3(t *testing.T, addr string, query []byte) (int, []byte) {
	t.Helper()
	tr := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}}
	defer tr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+addr+"/dns-query", bytes.NewReader(query))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Authorization", "Bearer client-user-token")
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		t.Fatalf("POST /dns-query: %v", err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.Bytes()
}

// 入口把 DoH 原样转给出口：应答来自出口的上游，入口自己的上游一次都不查（入口不出网）。
func TestIngressForwardsDoHToEgress(t *testing.T) {
	egressUp, ingressUp := startFakeDNS(t), startFakeDNS(t)
	_, ingress := startHopPair(t, egressUp, ingressUp, hopTestCred)

	for i, c := range []struct {
		name    string
		qtype   uint16
		rcode   byte
		answers int
	}{{"txt", 16, 0, 1}, {"nx", 1, 3, 0}, {"big", 1, 0, 20}} { // TXT、NXDOMAIN 保留、截断后经 TCP 取完整应答
		q := dnsQuery(uint16(0x2000+i), c.name, c.qtype)
		code, resp := postDoHH3(t, ingress.Addr(), q)
		if code != http.StatusOK || len(resp) < 12 {
			t.Fatalf("%s: http %d len %d", c.name, code, len(resp))
		}
		if rc, an := rcodeAndAnswers(resp); rc != c.rcode || an != c.answers || resp[0] != q[0] || resp[1] != q[1] {
			t.Errorf("%s: rcode=%d answers=%d id=%x, want %d/%d", c.name, rc, an, resp[:2], c.rcode, c.answers)
		}
	}
	if n := egressUp.queries.Load(); n == 0 {
		t.Error("egress upstream was never queried")
	}
	if n := ingressUp.queries.Load(); n != 0 {
		t.Errorf("ingress queried its own upstream %d times: DNS must leave from the egress", n)
	}
}

// 跳间凭证错误（出口拒绝）：入口回 SERVFAIL，不回退到自己的上游。
func TestIngressDoHServfailOnEgressRejection(t *testing.T) {
	egressUp, ingressUp := startFakeDNS(t), startFakeDNS(t)
	_, ingress := startHopPair(t, egressUp, ingressUp, "wrong-hop-credential")

	code, resp := postDoHH3(t, ingress.Addr(), dnsQuery(0x3001, "txt", 16))
	if code != http.StatusOK || len(resp) < 12 {
		t.Fatalf("http %d len %d", code, len(resp))
	}
	if rc, _ := rcodeAndAnswers(resp); rc != 2 {
		t.Errorf("rcode = %d, want 2 (SERVFAIL)", rc)
	}
	if egressUp.queries.Load() != 0 || ingressUp.queries.Load() != 0 {
		t.Errorf("no upstream may be queried: egress=%d ingress=%d", egressUp.queries.Load(), ingressUp.queries.Load())
	}
}

// 出口不可达：入口回 SERVFAIL（不伪造"无记录"）。
func TestIngressDoHServfailWhenEgressDown(t *testing.T) {
	egressUp, ingressUp := startFakeDNS(t), startFakeDNS(t)
	egress, ingress := startHopPair(t, egressUp, ingressUp, hopTestCred)
	egress.Close()

	code, resp := postDoHH3(t, ingress.Addr(), dnsQuery(0x3002, "txt", 16))
	if code != http.StatusOK || len(resp) < 12 {
		t.Fatalf("http %d len %d", code, len(resp))
	}
	if rc, _ := rcodeAndAnswers(resp); rc != 2 {
		t.Errorf("rcode = %d, want 2 (SERVFAIL)", rc)
	}
}

// 入口不建 TUN、不接 CONNECT-IP：返回 503 connect_ip_disabled，客户端按既有逻辑换节点。
func TestIngressConnectIPIsDisabled(t *testing.T) {
	_, ingress := startHopPair(t, startFakeDNS(t), startFakeDNS(t), hopTestCred)
	req := httptest.NewRequest(http.MethodConnect, "https://example.com/.well-known/masque/ip/*/*/", nil)
	req.Proto = "connect-ip"
	req.Header.Set("Authorization", "Bearer client-user-token")
	req.RemoteAddr = "203.0.113.9:4000"
	rec := httptest.NewRecorder()
	ingress.quicServer.serveConnectIP(rec, req)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Header().Get("Proxy-Status"), "connect_ip_disabled") {
		t.Fatalf("ingress CONNECT-IP: status %d, Proxy-Status %q", rec.Code, rec.Header().Get("Proxy-Status"))
	}
}

// 出口收到的 token 是跳间凭证（所有用户共用）：DoH 不按它限流，超过每秒 50 次也不返回 429。
func TestEgressDoHNotRateLimitedByHopCredential(t *testing.T) {
	up := startFakeDNS(t)
	egress, _ := startHopPair(t, up, startFakeDNS(t), hopTestCred)
	for i := 0; i < 80; i++ {
		req, _ := http.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(dnsQuery(uint16(i), "txt", 16)))
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Aero-Hop-Token", hopTestCred)
		req.RemoteAddr = "203.0.113.9:4000"
		rec := httptest.NewRecorder()
		egress.quicServer.serveDoH(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d rate limited at egress", i)
		}
	}
}

// 入口关闭之后转发 DoH 必须失败，且不能再新建到出口的 Transport（否则连接无人关闭）。
func TestIngressDoHForwardAfterCloseDoesNotLeak(t *testing.T) {
	_, ingress := startHopPair(t, startFakeDNS(t), startFakeDNS(t), hopTestCred)
	ingress.quicServer.Close()
	if _, err := ingress.quicServer.forwardDoHToNextHop(context.Background(), dnsQuery(0x4001, "txt", 16)); err == nil {
		t.Fatal("forward after Close must fail")
	}
	if ingress.quicServer.hopDoHc.tr != nil {
		t.Fatal("a Transport was created after Close")
	}
}

// 跳间凭证不得与用户 token 相同（契约 §8）。
func TestHopCredentialMustDifferFromUserToken(t *testing.T) {
	for _, role := range []string{"ingress", "egress"} {
		listen, host := findTestAddr()
		_, err := NewServer(ServerConfig{
			Listen: listen, Domain: host, Token: "same-secret", Role: role, HopCredential: "same-secret",
			NextHopAddr: "127.0.0.1:1", DataDir: t.TempDir(), AllowSelfSignedCertForTest: true,
		})
		if err == nil || !strings.Contains(err.Error(), "must differ") {
			t.Fatalf("%s: expected refusal, got %v", role, err)
		}
	}
}

// 出口收到的 token 都是同一个跳间凭证：按 token 的名额不能让一个用户占满整个入口。
// 出口的每 token 上限放宽到全局上限；单机（single）仍保持每 token 64 个 UDP 上下文。
func TestEgressPerTokenLimitsRelaxedForSharedHopCredential(t *testing.T) {
	listen, host := findTestAddr()
	egress, err := NewServer(ServerConfig{
		Listen: listen, Domain: host, Role: "egress", HopCredential: hopTestCred,
		DataDir: t.TempDir(), AllowSelfSignedCertForTest: true,
	})
	if err != nil {
		t.Fatalf("NewServer egress: %v", err)
	}
	t.Cleanup(egress.Close)
	q := egress.quicServer

	// UDP：超过单机的每 token 64 个仍能占到名额，直到全局上限。
	for i := 0; i < MaxUDPContextsPerToken+10; i++ {
		if !q.acquireUDPSlot(hopTestCred) {
			t.Fatalf("egress UDP slot %d rejected below global cap", i)
		}
	}
	// TCP：每 token 并发上限等于全局上限。
	if q.connLimiter.MaxPerTok() != q.connLimiter.MaxGlobal() {
		t.Fatalf("egress per-token conn cap %d != global %d", q.connLimiter.MaxPerTok(), q.connLimiter.MaxGlobal())
	}

	// single 角色保持原有每 token 上限。
	singleListen, singleHost := findTestAddr()
	single, err := NewServer(ServerConfig{
		Listen: singleListen, Domain: singleHost, Token: "u", DataDir: t.TempDir(), AllowSelfSignedCertForTest: true,
	})
	if err != nil {
		t.Fatalf("NewServer single: %v", err)
	}
	t.Cleanup(single.Close)
	sq := single.quicServer
	for i := 0; i < MaxUDPContextsPerToken; i++ {
		if !sq.acquireUDPSlot("u") {
			t.Fatalf("single UDP slot %d rejected", i)
		}
	}
	if sq.acquireUDPSlot("u") {
		t.Fatal("single role must keep the per-token UDP cap")
	}
	if sq.connLimiter.MaxPerTok() >= sq.connLimiter.MaxGlobal() {
		t.Fatal("single role must keep the per-token conn cap below the global cap")
	}
}
