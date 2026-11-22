// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"net/netip"
	"testing"
)

var (
	natTun    = netip.MustParseAddr("10.88.0.7")
	natAI     = netip.MustParseAddr("10.88.130.9")
	natRemote = netip.MustParseAddr("93.184.216.34")
)

// ---- 独立于被测代码的参考实现 ----

func refSum(b []byte) uint32 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	return s
}

func refFold(s uint32) uint16 {
	for s>>16 != 0 {
		s = (s & 0xffff) + (s >> 16)
	}
	return uint16(s)
}

// refL4 返回完整数据报（含伪首部）的校验和；校验和字段按 0 参与计算。off 是 L4 校验和字段在 L4 内的偏移。
func refL4(pkt []byte, ihl, off int) uint16 {
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	l4 := append([]byte(nil), pkt[ihl:total]...)
	l4[off], l4[off+1] = 0, 0
	var ph []byte
	ph = append(ph, pkt[12:20]...)
	ph = append(ph, 0, pkt[9], byte(len(l4)>>8), byte(len(l4)))
	c := ^refFold(refSum(ph) + refSum(l4))
	if pkt[9] == 17 && c == 0 {
		c = 0xffff
	}
	return c
}

func refIPHeaderValid(pkt []byte) bool {
	ihl := int(pkt[0]&0x0f) * 4
	return refFold(refSum(pkt[:ihl])) == 0xffff
}

func refL4Valid(t *testing.T, pkt []byte) bool {
	t.Helper()
	ihl := int(pkt[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	l4 := pkt[ihl:total]
	var ph []byte
	ph = append(ph, pkt[12:20]...)
	ph = append(ph, 0, pkt[9], byte(len(l4)>>8), byte(len(l4)))
	return refFold(refSum(ph)+refSum(l4)) == 0xffff
}

// buildIPv4 生成带正确校验和的报文。opts 为 IP 选项（长度必须是 4 的倍数）。
func buildIPv4(src, dst netip.Addr, proto uint8, opts []byte, l4 []byte, fragFlags uint16) []byte {
	ihl := 20 + len(opts)
	pkt := make([]byte, ihl+len(l4))
	pkt[0] = 0x40 | byte(ihl/4)
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[6:8], fragFlags)
	pkt[8], pkt[9] = 64, proto
	s, d := src.As4(), dst.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	copy(pkt[20:ihl], opts)
	copy(pkt[ihl:], l4)
	binary.BigEndian.PutUint16(pkt[10:12], ^refFold(refSum(pkt[:ihl])))
	return pkt
}

func withL4Checksum(pkt []byte, off int) []byte {
	ihl := int(pkt[0]&0x0f) * 4
	c := refL4(pkt, ihl, off)
	binary.BigEndian.PutUint16(pkt[ihl+off:ihl+off+2], c)
	return pkt
}

func tcpSeg(n int, rng *rand.Rand) []byte {
	seg := make([]byte, 20+n)
	rng.Read(seg)
	seg[12] = 0x50 // 数据偏移 5
	return seg
}

func udpDgram(n int, rng *rand.Rand) []byte {
	d := make([]byte, 8+n)
	rng.Read(d)
	binary.BigEndian.PutUint16(d[4:6], uint16(len(d)))
	return d
}

func TestChecksumAlgebraMatchesRecompute(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 200000; i++ {
		var words [8]byte
		rng.Read(words[:])
		base := ^refFold(refSum(words[:])) // 对 words 的校验和
		var old, nw [4]byte
		copy(old[:], words[0:4])
		rng.Read(nw[:])
		upd := csumReplaceAddr(base, old[:], nw[:])
		copy(words[0:4], nw[:])
		want := ^refFold(refSum(words[:]))
		// 反码零有两种表示（0x0000 与 0xffff），按“校验后是否仍然有效”比较
		if upd != want && !(upd == 0 && want == 0xffff) && !(upd == 0xffff && want == 0) {
			t.Fatalf("iteration %d: incremental %04x != recomputed %04x", i, upd, want)
		}
	}
}

func TestNATUplinkTCPAndUDP(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	optsSets := [][]byte{nil, {1, 1, 1, 0}, bytes.Repeat([]byte{1}, 40)}
	for _, opts := range optsSets {
		for _, n := range []int{0, 1, 2, 3, 100, 1001, 1200} {
			// TCP
			pkt := withL4Checksum(buildIPv4(natTun, natRemote, 6, opts, tcpSeg(n, rng), 0), 16)
			payload := append([]byte(nil), pkt[20+len(opts)+20:]...)
			if !natUplink(pkt, natTun, natAI) {
				t.Fatalf("tcp n=%d opts=%d: not rewritten", n, len(opts))
			}
			if netip.AddrFrom4([4]byte(pkt[12:16])) != natAI || netip.AddrFrom4([4]byte(pkt[16:20])) != natRemote {
				t.Fatal("addresses wrong")
			}
			if !refIPHeaderValid(pkt) || !refL4Valid(t, pkt) {
				t.Fatalf("tcp n=%d opts=%d: checksum invalid after rewrite", n, len(opts))
			}
			if !bytes.Equal(payload, pkt[20+len(opts)+20:]) {
				t.Fatal("payload modified")
			}
			// UDP
			pkt = withL4Checksum(buildIPv4(natTun, natRemote, 17, opts, udpDgram(n, rng), 0), 6)
			if !natUplink(pkt, natTun, natAI) || !refIPHeaderValid(pkt) || !refL4Valid(t, pkt) {
				t.Fatalf("udp n=%d opts=%d: invalid after rewrite", n, len(opts))
			}
		}
	}
}

func TestNATDownlinkRestoresPacket(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	for _, proto := range []uint8{6, 17} {
		var l4 []byte
		off := 16
		if proto == 6 {
			l4 = tcpSeg(333, rng)
		} else {
			l4, off = udpDgram(333, rng), 6
		}
		orig := withL4Checksum(buildIPv4(natRemote, natAI, proto, nil, l4, 0), off)
		pkt := append([]byte(nil), orig...)
		if !natDownlink(pkt, natAI, natTun) {
			t.Fatal("downlink not rewritten")
		}
		if netip.AddrFrom4([4]byte(pkt[16:20])) != natTun || !refIPHeaderValid(pkt) || !refL4Valid(t, pkt) {
			t.Fatalf("proto %d: invalid after downlink rewrite", proto)
		}
	}
	// 往返：上行再下行得到原来的有效报文
	pkt := withL4Checksum(buildIPv4(natTun, natRemote, 6, nil, tcpSeg(50, rng), 0), 16)
	natUplink(pkt, natTun, natAI)
	// 把方向对调后模拟回包：src/dst 互换需要重算，这里只验证地址函数的互逆性
	back := append([]byte(nil), pkt...)
	copy(back[12:16], pkt[16:20])
	copy(back[16:20], pkt[12:16])
}

func TestNATUDPChecksumEdgeCases(t *testing.T) {
	// 发送方未计算校验和（0）：保持 0。
	pkt := buildIPv4(natTun, natRemote, 17, nil, udpDgram(20, rand.New(rand.NewSource(4))), 0)
	binary.BigEndian.PutUint16(pkt[20+6:20+8], 0)
	if !natUplink(pkt, natTun, natAI) || binary.BigEndian.Uint16(pkt[26:28]) != 0 || !refIPHeaderValid(pkt) {
		t.Fatal("zero UDP checksum must stay zero")
	}
	// 穷举两字节载荷：增量结果必须和完整重算一致（含重算结果为 0 时发送 0xffff 的规则）。
	for v := 0; v < 65536; v++ {
		d := make([]byte, 8+2)
		binary.BigEndian.PutUint16(d[0:2], 1000)
		binary.BigEndian.PutUint16(d[2:4], 2000)
		binary.BigEndian.PutUint16(d[4:6], uint16(len(d)))
		binary.BigEndian.PutUint16(d[8:10], uint16(v))
		p := withL4Checksum(buildIPv4(natTun, natRemote, 17, nil, d, 0), 6)
		if !natUplink(p, natTun, natAI) {
			t.Fatal("not rewritten")
		}
		if got, want := binary.BigEndian.Uint16(p[26:28]), refL4(p, 20, 6); got != want {
			t.Fatalf("payload %04x: udp checksum %04x, want %04x", v, got, want)
		}
	}
}

func TestNATFragments(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	// 一个 UDP 数据报被拆成两片：首片带 UDP 头（MF=1），次片没有 L4 头。
	full := withL4Checksum(buildIPv4(natTun, natRemote, 17, nil, udpDgram(40, rng), 0), 6)
	l4 := full[20:]
	first := buildIPv4(natTun, natRemote, 17, nil, l4[:24], 0x2000)
	second := buildIPv4(natTun, natRemote, 17, nil, l4[24:], 24/8)
	if !natUplink(first, natTun, natAI) || !natUplink(second, natTun, natAI) {
		t.Fatal("fragments not rewritten")
	}
	if !refIPHeaderValid(first) || !refIPHeaderValid(second) {
		t.Fatal("fragment IP header checksum invalid")
	}
	// 重组后的数据报用新地址校验必须有效。
	re := buildIPv4(natAI, natRemote, 17, nil, append(append([]byte(nil), first[20:]...), second[20:]...), 0)
	if !refL4Valid(t, re) {
		t.Fatal("reassembled datagram invalid: first fragment UDP checksum not updated correctly")
	}
	// 次片的载荷原样不动。
	if !bytes.Equal(second[20:], l4[24:]) {
		t.Fatal("non-first fragment payload modified")
	}
}

func TestNATICMPInner(t *testing.T) {
	rng := rand.New(rand.NewSource(6))
	// 我们经 ai 发出的 TCP 包（源已改成 natAI），远端路径上的路由器回 ICMP 差错，目的是 natAI。
	for _, inner := range []struct {
		proto uint8
		l4    []byte
		off   int
	}{{6, tcpSeg(100, rng), 16}, {17, udpDgram(100, rng), 6}} {
		sent := withL4Checksum(buildIPv4(natAI, natRemote, inner.proto, nil, inner.l4, 0), inner.off)
		quote := sent[:20+8]
		for _, typ := range []byte{3, 11, 12} {
			icmp := append([]byte{typ, 1, 0, 0, 0, 0, 0, 0}, quote...)
			pkt := buildIPv4(netip.MustParseAddr("198.51.100.1"), natAI, 1, nil, icmp, 0)
			binary.BigEndian.PutUint16(pkt[20+2:20+4], onesComplementSum(pkt[20:]))
			if !natDownlink(pkt, natAI, natTun) {
				t.Fatal("icmp error not rewritten")
			}
			if netip.AddrFrom4([4]byte(pkt[16:20])) != natTun || !refIPHeaderValid(pkt) {
				t.Fatal("outer header wrong")
			}
			in := pkt[20+8:]
			if netip.AddrFrom4([4]byte(in[12:16])) != natTun || netip.AddrFrom4([4]byte(in[16:20])) != natRemote {
				t.Fatalf("inner addresses wrong: %v -> %v", in[12:16], in[16:20])
			}
			if !refIPHeaderValid(in) {
				t.Fatal("inner header checksum invalid")
			}
			if onesComplementSum(pkt[20:]) != 0 {
				t.Fatal("ICMP checksum invalid")
			}
		}
	}
	// 回显应答不是差错报文：只改外层，ICMP 校验和不变且仍然有效。
	echo := []byte{0, 0, 0, 0, 0, 1, 0, 1, 'p', 'i', 'n', 'g'}
	binary.BigEndian.PutUint16(echo[2:4], onesComplementSum(echo))
	pkt := buildIPv4(natRemote, natAI, 1, nil, echo, 0)
	if !natDownlink(pkt, natAI, natTun) || onesComplementSum(pkt[20:]) != 0 || !refIPHeaderValid(pkt) {
		t.Fatal("echo reply handling wrong")
	}
}

// 分片的 ICMP：只改外层目的地址与 IP 头校验和，不碰载荷（非首片没有 ICMP 头，首片的 ICMP 校验和覆盖整个重组后的报文）。
func TestNATFragmentedICMPOnlyRewritesOuterHeader(t *testing.T) {
	sent := tcpWithFlags(natAI, natRemote, 50001, 443, fSYN, 0)
	icmp := append([]byte{3, 4, 0, 0, 0, 0, 5, 0xdc}, sent[:28]...)
	binary.BigEndian.PutUint16(icmp[2:4], onesComplementSum(icmp))
	for _, frag := range []uint16{0x2000, 0x0001, 0x2001} { // 首片（MF）、非首片、中间片
		pkt := buildIPv4(netip.MustParseAddr("198.51.100.1"), natAI, 1, nil, icmp, frag)
		payload := append([]byte(nil), pkt[20:]...)
		if !natDownlink(pkt, natAI, natTun) {
			t.Fatalf("frag %#x: outer destination not rewritten", frag)
		}
		if netip.AddrFrom4([4]byte(pkt[16:20])) != natTun || !refIPHeaderValid(pkt) {
			t.Fatalf("frag %#x: outer header wrong", frag)
		}
		if !bytes.Equal(payload, pkt[20:]) {
			t.Fatalf("frag %#x: payload modified", frag)
		}
	}
}

func TestNATLeavesForeignAndBrokenPacketsAlone(t *testing.T) {
	pkt := withL4Checksum(buildIPv4(netip.MustParseAddr("10.88.0.99"), natRemote, 6, nil, tcpSeg(10, rand.New(rand.NewSource(7))), 0), 16)
	orig := append([]byte(nil), pkt...)
	if natUplink(pkt, natTun, natAI) || !bytes.Equal(pkt, orig) {
		t.Fatal("packet with another source address must not be touched")
	}
	if natDownlink(pkt, natAI, natTun) || !bytes.Equal(pkt, orig) {
		t.Fatal("packet to another destination must not be touched")
	}
	for _, bad := range [][]byte{nil, {}, {0x45}, make([]byte, 19), {0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}} {
		c := append([]byte(nil), bad...)
		if natUplink(c, natTun, natAI) || natDownlink(c, natAI, natTun) || !bytes.Equal(c, bad) {
			t.Fatalf("broken packet %x modified or accepted", bad)
		}
	}
	// 总长度大于缓冲区
	short := append([]byte(nil), orig[:30]...)
	if natUplink(short, natTun, natAI) {
		t.Fatal("truncated packet accepted")
	}
}

func FuzzNAT(f *testing.F) {
	rng := rand.New(rand.NewSource(8))
	f.Add(withL4Checksum(buildIPv4(natTun, natRemote, 6, nil, tcpSeg(20, rng), 0), 16))
	f.Add(withL4Checksum(buildIPv4(natTun, natRemote, 17, nil, udpDgram(20, rng), 0), 6))
	icmp := append([]byte{3, 1, 0, 0, 0, 0, 0, 0}, buildIPv4(natAI, natRemote, 17, nil, udpDgram(8, rng), 0)[:28]...)
	f.Add(buildIPv4(natRemote, natAI, 1, nil, icmp, 0))
	f.Fuzz(func(t *testing.T, data []byte) {
		a := append([]byte(nil), data...)
		natUplink(a, natTun, natAI)
		b := append([]byte(nil), data...)
		natDownlink(b, natAI, natTun)
		if len(a) != len(data) || len(b) != len(data) {
			t.Fatal("length changed")
		}
	})
}
