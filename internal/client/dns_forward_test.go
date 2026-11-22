// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testRR 是测试应答里的一条答案记录。
type testRR struct {
	typ   uint16
	ttl   uint32
	rdata []byte
}

// buildTestDNSResponse 以 query 为蓝本构造应答：ID 与问题段取自 query，答案名用压缩指针指向问题名。
func buildTestDNSResponse(query []byte, rcode byte, tc bool, rrs ...testRR) []byte {
	q, _ := dnsQuestionBytes(query)
	flags := byte(0x81)
	if tc {
		flags |= 0x02
	}
	r := append([]byte(nil), query[:2]...)
	r = append(r, flags, 0x80|rcode, 0, 1)
	r = binary.BigEndian.AppendUint16(r, uint16(len(rrs)))
	r = append(r, 0, 0, 0, 0)
	r = append(r, q...)
	for _, rr := range rrs {
		r = append(r, 0xC0, 12)
		r = binary.BigEndian.AppendUint16(r, rr.typ)
		r = append(r, 0, 1)
		r = binary.BigEndian.AppendUint32(r, rr.ttl)
		r = binary.BigEndian.AppendUint16(r, uint16(len(rr.rdata)))
		r = append(r, rr.rdata...)
	}
	return r
}

func buildTestQuery(id uint16, name string, qtype uint16) []byte {
	q := buildDNSQuery(name, qtype)
	binary.BigEndian.PutUint16(q[0:2], id)
	return q
}

func TestDNSSetEdgeConcurrentWithHandleQuery(t *testing.T) {
	h := NewDNSHandler(nil)
	h.SetDoHResolver(func(ctx context.Context, req []byte) ([]byte, error) {
		return buildTestDNSResponse(req, 0, false, testRR{1, 60, []byte{1, 2, 3, 4}}), nil
	})
	stop := make(chan struct{})
	var wg sync.WaitGroup
	// 写者：模拟切换节点、网络变化期间调用各 Set*
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			h.SetEdge(fmt.Sprintf("node%d.example.net", i%3), net.IPv4(10, 0, 0, byte(i)))
			h.SetPhysicalDNS("223.5.5.5:53")
			h.SetFakeIP(NewFakeIPTable("198.18.0.0/15"))
			h.SetTunnelResolver(nil)
			h.SetIPv6Available(i%2 == 0)
			h.Flush()
		}
	}()
	var readers sync.WaitGroup
	for g := 0; g < 4; g++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for i := 0; i < 300; i++ {
				h.HandleQuery(buildTestQuery(1, fmt.Sprintf("node%d.example.net", i%3), 1), nil, 0)
				h.HandleQuery(buildTestQuery(2, "other.example.org", 28), nil, 0)
				_ = h.FakeIP()
			}
		}()
	}
	readers.Wait()
	close(stop)
	wg.Wait()
}

func TestDNSForwardAllRecordTypesViaDoH(t *testing.T) {
	cases := []struct {
		name  string
		qtype uint16
		rr    testRR
	}{
		{"A", 1, testRR{1, 60, []byte{1, 2, 3, 4}}},
		{"AAAA", 28, testRR{28, 60, bytes.Repeat([]byte{0x20}, 16)}},
		{"HTTPS", 65, testRR{65, 60, []byte{0, 1, 0}}},
		{"TXT", 16, testRR{16, 60, []byte{5, 'h', 'e', 'l', 'l', 'o'}}},
		{"MX", 15, testRR{15, 60, []byte{0, 10, 0}}},
		{"SRV", 33, testRR{33, 60, []byte{0, 1, 0, 1, 1, 0xBB, 0}}},
		{"PTR", 12, testRR{12, 60, []byte{0}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := NewDNSHandler(nil)
			h.SetIPv6Available(true) // AAAA 也原样转发
			var calls atomic.Int32
			var gotReq []byte
			var want []byte
			h.SetDoHResolver(func(ctx context.Context, req []byte) ([]byte, error) {
				calls.Add(1)
				gotReq = append([]byte(nil), req...)
				resp := buildTestDNSResponse(req, 0, false, tc.rr)
				want = append([]byte(nil), resp...)
				resp[0], resp[1] = 0xBE, 0xEF // 上游 ID 不同，客户端应改回
				return resp, nil
			})
			req := buildTestQuery(0x4321, "proxied.example.org", tc.qtype)
			resp := h.HandleQuery(req, nil, 0)
			if calls.Load() != 1 {
				t.Fatalf("DoH calls = %d, want 1", calls.Load())
			}
			if !bytes.Equal(gotReq, req) {
				t.Fatalf("DoH request altered: %x vs %x", gotReq, req)
			}
			if !bytes.Equal(resp, want) {
				t.Fatalf("response not forwarded verbatim:\n got %x\nwant %x", resp, want)
			}
			if binary.BigEndian.Uint16(resp[0:2]) != 0x4321 {
				t.Fatal("transaction ID not restored")
			}
		})
	}
}

func TestDNSAAAAEmptyWhenIPv6Unavailable(t *testing.T) {
	var calls atomic.Int32
	h := NewDNSHandler(nil)
	h.SetDoHResolver(func(ctx context.Context, req []byte) ([]byte, error) {
		calls.Add(1)
		return buildTestDNSResponse(req, 0, false, testRR{28, 60, bytes.Repeat([]byte{0x20}, 16)}), nil
	})
	req := buildTestQuery(7, "proxied.example.org", 28)

	resp := h.HandleQuery(req, nil, 0)
	if resp == nil || dnsRcode(resp) != 0 || dnsAnswerCount(resp) != 0 || !dnsIsResponse(resp) {
		t.Fatalf("want empty NOERROR, got %x", resp)
	}
	if calls.Load() != 0 {
		t.Fatalf("AAAA must not reach DoH when IPv6 unavailable, calls=%d", calls.Load())
	}

	h.SetIPv6Available(true)
	resp = h.HandleQuery(req, nil, 0)
	if dnsAnswerCount(resp) != 1 || calls.Load() != 1 {
		t.Fatalf("AAAA should be forwarded with IPv6 available: answers=%d calls=%d", dnsAnswerCount(resp), calls.Load())
	}

	// 回到不可用：即使缓存里有 AAAA 也不得返回
	h.SetIPv6Available(false)
	if resp = h.HandleQuery(req, nil, 0); dnsAnswerCount(resp) != 0 {
		t.Fatalf("cached AAAA served while IPv6 unavailable: %x", resp)
	}
}

func TestDNSEdgeHostNonAGetsEmptyAnswer(t *testing.T) {
	h := NewDNSHandler(nil)
	h.SetEdge("Node.Example.com ", net.IPv4(1, 2, 3, 4))
	for _, qt := range []uint16{16, 28, 65} {
		resp := h.HandleQuery(buildTestQuery(1, "node.example.com", qt), nil, 0)
		if resp == nil || dnsAnswerCount(resp) != 0 || dnsRcode(resp) != 0 {
			t.Fatalf("qtype %d: want empty NOERROR, got %x", qt, resp)
		}
	}
	resp := h.HandleQuery(buildTestQuery(1, "a.node.example.com", 1), nil, 0)
	if got := extractFirstIPv4FromResponse(resp); !got.Equal(net.IPv4(1, 2, 3, 4)) {
		t.Fatalf("A for edge host: got %v", got)
	}
}

func TestDNSCacheFullResponseAndID(t *testing.T) {
	h := NewDNSHandler(nil)
	var calls atomic.Int32
	var upstream []byte
	h.SetDoHResolver(func(ctx context.Context, req []byte) ([]byte, error) {
		calls.Add(1)
		upstream = buildTestDNSResponse(req, 0, false,
			testRR{1, 120, []byte{1, 1, 1, 1}}, testRR{1, 300, []byte{2, 2, 2, 2}}, testRR{1, 90, []byte{3, 3, 3, 3}})
		return append([]byte(nil), upstream...), nil
	})
	r1 := h.HandleQuery(buildTestQuery(0x1111, "Cached.Example.org", 1), nil, 0)
	r2 := h.HandleQuery(buildTestQuery(0x2222, "cached.example.org", 1), nil, 0)
	if calls.Load() != 1 {
		t.Fatalf("DoH calls = %d, want 1 (second served from cache)", calls.Load())
	}
	if dnsAnswerCount(r2) != 3 {
		t.Fatalf("cache hit must return the full response, answers=%d", dnsAnswerCount(r2))
	}
	if binary.BigEndian.Uint16(r1[0:2]) != 0x1111 || binary.BigEndian.Uint16(r2[0:2]) != 0x2222 {
		t.Fatalf("IDs wrong: %x %x", r1[0:2], r2[0:2])
	}
	if !bytes.Equal(r2[2:], r1[2:]) {
		t.Fatal("cached body differs from original")
	}
	// 不同类型是不同缓存条目
	h.HandleQuery(buildTestQuery(3, "cached.example.org", 16), nil, 0)
	if calls.Load() != 2 {
		t.Fatalf("TXT must not hit the A entry, calls=%d", calls.Load())
	}
	// 命中副本被修改不影响缓存
	r2[20] ^= 0xFF
	r3 := h.HandleQuery(buildTestQuery(0x3333, "cached.example.org", 1), nil, 0)
	if !bytes.Equal(r3[2:], r1[2:]) {
		t.Fatal("cache entry was mutated through a returned slice")
	}
	// Flush 后重新走 DoH
	h.Flush()
	h.HandleQuery(buildTestQuery(4, "cached.example.org", 1), nil, 0)
	if calls.Load() != 3 {
		t.Fatalf("after Flush calls=%d, want 3", calls.Load())
	}
}

func TestDNSCacheSkipsNonAnswers(t *testing.T) {
	cases := []struct {
		name  string
		build func(q []byte) []byte
	}{
		{"nxdomain", func(q []byte) []byte { return buildTestDNSResponse(q, 3, false) }},
		{"nodata", func(q []byte) []byte { return buildTestDNSResponse(q, 0, false) }},
		{"servfail", func(q []byte) []byte { return buildTestDNSResponse(q, 2, false, testRR{1, 60, []byte{1, 1, 1, 1}}) }},
		{"truncated", func(q []byte) []byte { return buildTestDNSResponse(q, 0, true, testRR{1, 60, []byte{1, 1, 1, 1}}) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := NewDNSHandler(nil)
			var calls atomic.Int32
			h.SetDoHResolver(func(ctx context.Context, req []byte) ([]byte, error) {
				calls.Add(1)
				return tc.build(req), nil
			})
			for i := 0; i < 2; i++ {
				h.HandleQuery(buildTestQuery(1, "x.example.org", 1), nil, 0)
			}
			if calls.Load() != 2 {
				t.Fatalf("calls=%d, want 2 (not cached)", calls.Load())
			}
		})
	}
}

func TestDNSCacheTTLClamp(t *testing.T) {
	cases := []struct {
		name    string
		ttls    []uint32
		wantMin time.Duration
		wantMax time.Duration
	}{
		{"zero-clamped-up", []uint32{0}, 30 * time.Second, 31 * time.Second},
		{"below-min", []uint32{5}, 30 * time.Second, 31 * time.Second},
		{"in-range-min-of-many", []uint32{300, 100, 200}, 100 * time.Second, 101 * time.Second},
		{"above-max", []uint32{86400}, 10 * time.Minute, 10*time.Minute + time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := NewDNSHandler(nil)
			h.SetDoHResolver(func(ctx context.Context, req []byte) ([]byte, error) {
				var rrs []testRR
				for _, ttl := range tc.ttls {
					rrs = append(rrs, testRR{1, ttl, []byte{1, 2, 3, 4}})
				}
				return buildTestDNSResponse(req, 0, false, rrs...), nil
			})
			h.HandleQuery(buildTestQuery(1, "ttl.example.org", 1), nil, 0)
			h.cacheMu.Lock()
			e, ok := h.cache[dnsCacheKey{"ttl.example.org", 1}]
			h.cacheMu.Unlock()
			if !ok {
				t.Fatal("entry not cached")
			}
			d := time.Until(e.expiresAt)
			if d > tc.wantMax || d < tc.wantMin-2*time.Second {
				t.Fatalf("expiry in %v, want about [%v,%v]", d, tc.wantMin, tc.wantMax)
			}
		})
	}
}

func TestDNSCacheCapacityBounded(t *testing.T) {
	h := NewDNSHandler(nil)
	resp := buildTestDNSResponse(buildTestQuery(1, "a.example.org", 1), 0, false, testRR{1, 60, []byte{1, 2, 3, 4}})
	for i := 0; i < dnsCacheMaxEntries+500; i++ {
		h.cachePut(fmt.Sprintf("host%d.example.org", i), 1, resp, time.Minute)
	}
	h.cacheMu.Lock()
	n := len(h.cache)
	h.cacheMu.Unlock()
	if n != dnsCacheMaxEntries {
		t.Fatalf("cache size %d, want %d", n, dnsCacheMaxEntries)
	}
	// 更新已有条目不触发淘汰
	h.cacheMu.Lock()
	var existing dnsCacheKey
	for k := range h.cache {
		existing = k
		break
	}
	h.cacheMu.Unlock()
	h.cachePut(existing.name, existing.qtype, resp, time.Minute)
	h.cacheMu.Lock()
	n = len(h.cache)
	h.cacheMu.Unlock()
	if n != dnsCacheMaxEntries {
		t.Fatalf("cache size after refresh %d", n)
	}
}

func TestIsSystemProbeDomainDotBoundary(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"msftconnecttest.com", true},
		{"www.msftconnecttest.com", true},
		{"ipv6.msftncsi.com", true},
		{"MSFTNCSI.com", true},
		{"captive.apple.com", true},
		{"connectivitycheck.gstatic.com", true},
		{"xxxmsftncsi.com", false},
		{"evilmsftconnecttest.com", false},
		{"notcaptive.apple.com", false},
		{"xconnectivitycheck.gstatic.com", false},
		{"msftncsi.com.evil.org", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := isSystemProbeDomain(tc.host); got != tc.want {
			t.Errorf("isSystemProbeDomain(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

// fakePhysicalDNS 是测试用上游：UDP 与 TCP 同端口，应答由 answer 决定。
type fakePhysicalDNS struct {
	addr string
	udp  atomic.Int32
	tcp  atomic.Int32
}

func startFakePhysicalDNS(t *testing.T, answer func(q []byte, tcp bool) [][]byte) *fakePhysicalDNS {
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
	f := &fakePhysicalDNS{addr: pc.LocalAddr().String()}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, a, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			f.udp.Add(1)
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
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				var l [2]byte
				if _, err := io.ReadFull(c, l[:]); err != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(l[:]))
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				f.tcp.Add(1)
				rs := answer(q, true)
				if len(rs) == 0 {
					return
				}
				_, _ = c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(rs[0]))), rs[0]...))
			}()
		}
	}()
	return f
}

func newPhysicalTestHandler(f *fakePhysicalDNS) *DNSHandler {
	h := NewDNSHandler(nil)
	h.SetPhysicalDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	})
	h.SetPhysicalDNS(f.addr)
	return h
}

func TestQueryFastUDPDropsMismatchedReplies(t *testing.T) {
	good := testRR{1, 60, []byte{9, 9, 9, 9}}
	cases := []struct {
		name   string
		answer func(q []byte, tcp bool) [][]byte
		wantOK bool
	}{
		{"wrong-id-then-good", func(q []byte, tcp bool) [][]byte {
			bad := buildTestDNSResponse(q, 0, false, testRR{1, 60, []byte{6, 6, 6, 6}})
			bad[0] ^= 0xFF
			return [][]byte{bad, buildTestDNSResponse(q, 0, false, good)}
		}, true},
		{"wrong-question-then-good", func(q []byte, tcp bool) [][]byte {
			other := buildTestDNSResponse(buildTestQuery(binary.BigEndian.Uint16(q[:2]), "evil.cn", 1), 0, false, testRR{1, 60, []byte{6, 6, 6, 6}})
			return [][]byte{other, buildTestDNSResponse(q, 0, false, good)}
		}, true},
		{"wrong-qtype-then-good", func(q []byte, tcp bool) [][]byte {
			other := buildTestDNSResponse(buildTestQuery(binary.BigEndian.Uint16(q[:2]), "www.example.cn", 16), 0, false, testRR{16, 60, []byte{1, 'x'}})
			return [][]byte{other, buildTestDNSResponse(q, 0, false, good)}
		}, true},
		{"only-wrong-id", func(q []byte, tcp bool) [][]byte {
			bad := buildTestDNSResponse(q, 0, false, good)
			bad[1] ^= 0x01
			return [][]byte{bad}
		}, false},
		{"query-not-response", func(q []byte, tcp bool) [][]byte {
			r := buildTestDNSResponse(q, 0, false, good)
			r[2] &^= 0x80
			return [][]byte{r}
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := startFakePhysicalDNS(t, tc.answer)
			h := newPhysicalTestHandler(f)
			resp := h.queryFastUDP(buildTestQuery(0x0A0B, "www.example.cn", 1))
			if !tc.wantOK {
				if resp != nil {
					t.Fatalf("accepted a mismatched reply: %x", resp)
				}
				return
			}
			if resp == nil {
				t.Fatal("no response")
			}
			if ip := extractFirstIPv4FromResponse(resp); !ip.Equal(net.IPv4(9, 9, 9, 9)) {
				t.Fatalf("got %v, want the genuine reply 9.9.9.9", ip)
			}
		})
	}
}

func TestQueryFastUDPTruncatedFallsBackToTCP(t *testing.T) {
	f := startFakePhysicalDNS(t, func(q []byte, tcp bool) [][]byte {
		if !tcp {
			return [][]byte{buildTestDNSResponse(q, 0, true)}
		}
		return [][]byte{buildTestDNSResponse(q, 0, false, testRR{1, 60, []byte{7, 7, 7, 7}}, testRR{1, 60, []byte{8, 8, 8, 8}})}
	})
	h := newPhysicalTestHandler(f)
	resp := h.HandleQuery(buildTestQuery(0x5151, "www.example.cn", 1), nil, 0)
	if resp == nil || dnsAnswerCount(resp) != 2 || resp[2]&0x02 != 0 {
		t.Fatalf("want full TCP answer, got %x", resp)
	}
	if binary.BigEndian.Uint16(resp[0:2]) != 0x5151 {
		t.Fatal("ID mismatch")
	}
	if f.udp.Load() != 1 || f.tcp.Load() != 1 {
		t.Fatalf("udp=%d tcp=%d, want 1/1", f.udp.Load(), f.tcp.Load())
	}
}

func TestQueryFastUDPTruncatedTCPFailureIsServfail(t *testing.T) {
	f := startFakePhysicalDNS(t, func(q []byte, tcp bool) [][]byte {
		if !tcp {
			return [][]byte{buildTestDNSResponse(q, 0, true)}
		}
		return nil // TCP 上不回应答
	})
	h := newPhysicalTestHandler(f)
	resp := h.HandleQuery(buildTestQuery(1, "www.example.cn", 1), nil, 0)
	requireServFail(t, resp, "TC with TCP failure")
}
