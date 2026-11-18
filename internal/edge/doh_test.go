package edge

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// fakeDNS 是测试上游：按名称返回不同应答，UDP 与 TCP 同端口。
type fakeDNS struct {
	addr    string
	queries atomic.Int32
}

func dnsQuery(id uint16, name string, qtype uint16) []byte {
	q := binary.BigEndian.AppendUint16(nil, id)
	q = append(q, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0)
	q = append(q, encodeDNSName(name)...)
	return binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(q, qtype), 1)
}

// fakeAnswer 构造应答：rcode、ancount 与（可选）TC 标志，答案段用一个指向问题名的 TXT 记录。
func fakeAnswer(query []byte, rcode byte, answers int, tc bool) []byte {
	q, _ := dnsQuestionSection(query)
	r := append([]byte(nil), query[:2]...)
	flags := byte(0x81)
	if tc {
		flags |= 0x02
	}
	r = append(r, flags, 0x80|rcode, 0, 1, 0, byte(answers), 0, 0, 0, 0)
	r = append(r, q...)
	for i := 0; i < answers; i++ {
		r = append(r, 0xC0, 12, 0, 16, 0, 1, 0, 0, 0, 60, 0, 6, 5, 'h', 'e', 'l', 'l', 'o')
	}
	return r
}

func startFakeDNS(t *testing.T) *fakeDNS {
	t.Helper()
	// UDP 与 TCP 需要同一端口号：随机取 UDP 端口后该 TCP 端口可能已被占用，重试直到两者都绑定成功
	var pc net.PacketConn
	var ln net.Listener
	for i := 0; i < 20 && ln == nil; i++ {
		p, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		if l, err := net.Listen("tcp", p.LocalAddr().String()); err == nil {
			pc, ln = p, l
		} else {
			p.Close()
		}
	}
	if ln == nil {
		t.Fatal("could not bind a UDP+TCP port pair")
	}
	t.Cleanup(func() { pc.Close(); ln.Close() })
	f := &fakeDNS{addr: pc.LocalAddr().String()}
	answer := func(q []byte, tcp bool) [][]byte {
		f.queries.Add(1)
		name := string(q[13 : 13+int(q[12])])
		switch name {
		case "nx":
			return [][]byte{fakeAnswer(q, 3, 0, false)}
		case "big":
			if !tcp {
				return [][]byte{fakeAnswer(q, 0, 0, true)}
			}
			return [][]byte{fakeAnswer(q, 0, 20, false)}
		case "wrongid":
			bad := fakeAnswer(q, 0, 1, false)
			bad[0] ^= 0xFF
			return [][]byte{bad, fakeAnswer(q, 0, 1, false)}
		}
		return [][]byte{fakeAnswer(q, 0, 1, false)}
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, a, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			for _, r := range answer(append([]byte(nil), buf[:n]...), false) {
				_, _ = pc.WriteTo(r, a)
			}
		}
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				var l [2]byte
				if _, err := io.ReadFull(c, l[:]); err != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(l[:]))
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				r := answer(q, true)[0]
				_, _ = c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(r))), r...))
			}()
		}
	}()
	return f
}

func newDoHTestServer(t *testing.T, upstreams ...string) *QUICServer {
	t.Helper()
	v := NewValidator()
	v.AddToken("doh_token", "test", time.Hour)
	s := NewQUICServer(v, nil, nil, nil, nil)
	t.Cleanup(s.Close)
	s.SetAllowLoopbackForTest(true)
	s.doh.upstreams = func() []string { return upstreams }
	return s
}

func doDoH(t *testing.T, s *QUICServer, query []byte) (int, []byte) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(query))
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Authorization", "Bearer doh_token")
	req.RemoteAddr = "203.0.113.9:4000"
	rec := httptest.NewRecorder()
	s.serveDoH(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func rcodeAndAnswers(resp []byte) (byte, int) {
	return resp[3] & 0x0F, int(binary.BigEndian.Uint16(resp[6:8]))
}

// 原样转发：其他记录类型、NXDOMAIN、截断后改用 TCP、丢弃 ID 不符的应答。
func TestDoHForwardsVerbatim(t *testing.T) {
	up := startFakeDNS(t)
	s := newDoHTestServer(t, up.addr)
	cases := []struct {
		name    string
		qtype   uint16
		rcode   byte
		answers int
	}{
		{"txt", 16, 0, 1},    // TXT（旧实现对 A 以外的类型一律返回空）
		{"srv", 33, 0, 1},    // SRV
		{"nx", 1, 3, 0},      // NXDOMAIN 保留
		{"big", 1, 0, 20},    // UDP 截断 → TCP 取完整应答
		{"wrongid", 1, 0, 1}, // 先到的 ID 不符应答被丢弃
	}
	for i, c := range cases {
		q := dnsQuery(uint16(0x1000+i), c.name, c.qtype)
		code, resp := doDoH(t, s, q)
		if code != http.StatusOK || len(resp) < 12 {
			t.Fatalf("%s: http %d", c.name, code)
		}
		if rc, an := rcodeAndAnswers(resp); rc != c.rcode || an != c.answers || resp[0] != q[0] || resp[1] != q[1] {
			t.Errorf("%s: rcode=%d answers=%d id=%x, want %d/%d", c.name, rc, an, resp[:2], c.rcode, c.answers)
		}
	}
}

// 所有上游不可用：SERVFAIL（不是“无记录”）；第一个上游失败时用下一个。
func TestDoHServfailAndFailover(t *testing.T) {
	dead := func() string { // 立即拒绝的本地端口
		pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
		a := pc.LocalAddr().String()
		pc.Close()
		return a
	}
	s := newDoHTestServer(t, dead())
	q := dnsQuery(0x2222, "example", 1)
	_, resp := doDoH(t, s, q)
	if rc, an := rcodeAndAnswers(resp); rc != 2 || an != 0 || resp[2]&0x80 == 0 {
		t.Fatalf("all upstreams down: rcode=%d answers=%d", rc, an)
	}
	if qq, _ := dnsQuestionSection(q); !bytes.Contains(resp, qq) {
		t.Fatal("SERVFAIL must echo the question")
	}
	up := startFakeDNS(t)
	s2 := newDoHTestServer(t, dead(), up.addr)
	if _, resp := doDoH(t, s2, q); resp[3]&0x0F != 0 {
		t.Fatal("did not fail over to the second upstream")
	}
}

// 节点没有 IPv6 出口：AAAA 直接返回空应答，不查询上游。限流：每个 token 每秒 50 次。
func TestDoHAAAAPolicyAndRateLimit(t *testing.T) {
	up := startFakeDNS(t)
	s := newDoHTestServer(t, up.addr)
	if _, resp := doDoH(t, s, dnsQuery(0x3334, "v6", dnsTypeAAAA)); resp[7] != 1 || up.queries.Load() != 1 {
		t.Fatal("with IPv6 egress, AAAA must be forwarded")
	}
	s.ipv6Pool = nil // 生产环境没有公网 IPv6 前缀时不建地址池
	_, resp := doDoH(t, s, dnsQuery(0x3333, "v6", dnsTypeAAAA))
	if rc, an := rcodeAndAnswers(resp); rc != 0 || an != 0 || up.queries.Load() != 1 {
		t.Fatalf("AAAA without IPv6 egress: rcode=%d answers=%d upstream queries=%d", rc, an, up.queries.Load())
	}
	limited := false
	for i := 0; i < dohRatePerToken+10; i++ {
		if code, _ := doDoH(t, s, dnsQuery(uint16(i), "a", 1)); code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("rate limit not enforced")
	}
	if _, ok := dnsQueryType([]byte{0, 1, 0, 0, 0, 2}); ok {
		t.Fatal("malformed query accepted")
	}
}
