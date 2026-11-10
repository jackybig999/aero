package client

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
)

func dnsRcode(resp []byte) int       { return int(resp[3] & 0x0f) }
func dnsAnswerCount(resp []byte) int { return int(binary.BigEndian.Uint16(resp[6:8])) }
func dnsIsResponse(resp []byte) bool { return resp[2]&0x80 != 0 }

// 回归：DoH 失败时曾返回 198.18.x.x 假 IP。CONNECT-IP 数据面没有把假 IP 翻译回域名的
// 本地栈，edge 的目的地址 ACL 又丢弃 198.18/15，连接只会挂到超时。必须返回 SERVFAIL。
func TestDNSServfailWhenDoHFailsForProxiedDomain(t *testing.T) {
	h := NewDNSHandler(nil)
	h.SetDoHResolver(func(ctx context.Context, req []byte) ([]byte, error) {
		return nil, errors.New("doh unavailable")
	})

	resp := h.HandleQuery(buildDNSQuery("proxied.example.org", 1), net.IPv4(10, 88, 0, 2), 40000)

	if resp == nil || len(resp) < 12 {
		t.Fatalf("expected a DNS response, got %x", resp)
	}
	if !dnsIsResponse(resp) || dnsRcode(resp) != 2 || dnsAnswerCount(resp) != 0 {
		t.Fatalf("got qr=%v rcode=%d answers=%d, want SERVFAIL with no answers", dnsIsResponse(resp), dnsRcode(resp), dnsAnswerCount(resp))
	}
	if binary.BigEndian.Uint16(resp[0:2]) != 0x1234 {
		t.Fatal("response must echo the query ID")
	}
}

// 直连域名的物理 DNS 失败同样返回 SERVFAIL，而不是假 IP。
func TestDNSServfailWhenPhysicalDNSFailsForDirectDomain(t *testing.T) {
	h := NewDNSHandler(nil)
	h.SetPhysicalDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, errors.New("physical dns unreachable")
	})

	resp := h.HandleQuery(buildDNSQuery("www.example.cn", 1), net.IPv4(10, 88, 0, 2), 40000)

	if resp == nil || len(resp) < 12 || dnsRcode(resp) != 2 || dnsAnswerCount(resp) != 0 {
		t.Fatalf("direct-domain failure: got %x, want SERVFAIL with no answers", resp)
	}
}

// requireServFail 断言 resp 是不含答案的 SERVFAIL 应答（上游不可用时的约定行为）。
func requireServFail(t *testing.T, resp []byte, what string) {
	t.Helper()
	if len(resp) < 12 || !dnsIsResponse(resp) || dnsRcode(resp) != 2 || dnsAnswerCount(resp) != 0 {
		t.Fatalf("%s: want SERVFAIL with no answers, got %x", what, resp)
	}
}
