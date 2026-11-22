// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"encoding/binary"
	"net/netip"
)

// 源地址改写（ADR-0017 决定 3）：TUN 网卡只有 default 会话的地址（tunAddr）。经 ai 会话上行的包要把源地址
// 改成 ai 会话的地址（aiAddr），ai 会话下行的包再把目的地址改回 tunAddr。只处理 IPv4。
// 校验和一律增量更新（RFC 1624），不重算载荷；改写后的报文必须能被对端的校验和验证通过。

// csumReplace16 按 RFC 1624 式 3 把校验和 sum 中的一个 16 位字 old 换成 new。
func csumReplace16(sum, old, new uint16) uint16 {
	// HC' = ~(~HC + ~m + m')
	acc := uint32(^sum) + uint32(^old) + uint32(new)
	acc = (acc & 0xffff) + (acc >> 16)
	acc = (acc & 0xffff) + (acc >> 16)
	return ^uint16(acc)
}

// csumReplaceAddr 把校验和中的一个 IPv4 地址（两个 16 位字）换成新地址。
func csumReplaceAddr(sum uint16, old, new []byte) uint16 {
	sum = csumReplace16(sum, binary.BigEndian.Uint16(old[0:2]), binary.BigEndian.Uint16(new[0:2]))
	return csumReplace16(sum, binary.BigEndian.Uint16(old[2:4]), binary.BigEndian.Uint16(new[2:4]))
}

// ipv4Header 校验 IPv4 头并返回头长；不合法返回 0。pkt 可以比总长度长（尾部杂字节不处理）。
func ipv4Header(pkt []byte) int {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return 0
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return 0
	}
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if total < ihl || total > len(pkt) {
		return 0
	}
	return ihl
}

// setIPv4Addr 把 pkt 里 off（12 源、16 目的）处的地址改成 newAddr，同步更新 IP 头校验和与
// 第一个分片里的 TCP/UDP 校验和。成功返回旧地址；报文不合法返回 false。
func setIPv4Addr(pkt []byte, off int, newAddr [4]byte) (old [4]byte, ok bool) {
	ihl := ipv4Header(pkt)
	if ihl == 0 {
		return old, false
	}
	copy(old[:], pkt[off:off+4])
	if old == newAddr {
		return old, true
	}
	copy(pkt[off:off+4], newAddr[:])
	ipSum := binary.BigEndian.Uint16(pkt[10:12])
	binary.BigEndian.PutUint16(pkt[10:12], csumReplaceAddr(ipSum, old[:], newAddr[:]))

	// TCP/UDP 校验和覆盖伪首部（含地址），只存在于第一个分片；非首片没有 L4 头，只改 IP 头即可。
	if binary.BigEndian.Uint16(pkt[6:8])&0x1fff != 0 {
		return old, true
	}
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	switch pkt[9] {
	case 6: // TCP：校验和在偏移 16
		if total >= ihl+18 {
			s := binary.BigEndian.Uint16(pkt[ihl+16 : ihl+18])
			binary.BigEndian.PutUint16(pkt[ihl+16:ihl+18], csumReplaceAddr(s, old[:], newAddr[:]))
		}
	case 17: // UDP：校验和在偏移 6；0 表示发送方没有计算校验和，保持 0
		if total >= ihl+8 {
			s := binary.BigEndian.Uint16(pkt[ihl+6 : ihl+8])
			if s != 0 {
				ns := csumReplaceAddr(s, old[:], newAddr[:])
				if ns == 0 {
					ns = 0xffff // UDP 校验和结果为 0 时按规定发送 0xffff
				}
				binary.BigEndian.PutUint16(pkt[ihl+6:ihl+8], ns)
			}
		}
	}
	return old, true
}

// natUplink 把源地址 tunAddr 改成 aiAddr（经 ai 会话上行）。源地址不是 tunAddr 或报文不合法时不改动并返回 false。
func natUplink(pkt []byte, tunAddr, aiAddr netip.Addr) bool {
	if ipv4Header(pkt) == 0 || !tunAddr.Is4() || !aiAddr.Is4() {
		return false
	}
	if [4]byte(pkt[12:16]) != tunAddr.As4() {
		return false
	}
	_, ok := setIPv4Addr(pkt, 12, aiAddr.As4())
	return ok
}

// natDownlink 把目的地址 aiAddr 改回 tunAddr（ai 会话下行）。目的地址不是 aiAddr 时不改动并返回 false。
// ICMP 差错报文还要把内嵌的原报文头里的源地址 aiAddr 改回 tunAddr（原报文是我们改写后发出的）。
func natDownlink(pkt []byte, aiAddr, tunAddr netip.Addr) bool {
	ihl := ipv4Header(pkt)
	if ihl == 0 || !tunAddr.Is4() || !aiAddr.Is4() {
		return false
	}
	if [4]byte(pkt[16:20]) != aiAddr.As4() {
		return false
	}
	if _, ok := setIPv4Addr(pkt, 16, tunAddr.As4()); !ok {
		return false
	}
	// ICMP 差错报文的内嵌头只在未分片时改写：分片的 ICMP，非首片没有 ICMP 头，首片的校验和覆盖整个重组后的报文，
	// 无法只用本片重算。不改的后果只是系统匹配不到对应的套接字而忽略这条差错，无害。
	if pkt[9] == 1 && binary.BigEndian.Uint16(pkt[6:8])&0x3fff == 0 {
		natICMPInner(pkt, ihl, aiAddr.As4(), tunAddr.As4())
	}
	return true
}

// natICMPInner 在 ICMP 差错报文（目的不可达、源抑制、重定向、超时、参数错误）里，把内嵌 IPv4 头的
// 源地址 from 改成 to，并重算内嵌头校验和、内嵌 UDP 校验和（若引用到）与 ICMP 校验和。
func natICMPInner(pkt []byte, ihl int, from, to [4]byte) {
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if total < ihl+8+20 {
		return
	}
	switch pkt[ihl] { // ICMP 类型
	case 3, 4, 5, 11, 12:
	default:
		return
	}
	in := ihl + 8 // 内嵌的原报文
	if total < in+20 || pkt[in]>>4 != 4 {
		return
	}
	inIHL := int(pkt[in]&0x0f) * 4
	if inIHL < 20 || total < in+inIHL {
		return
	}
	if [4]byte(pkt[in+12:in+16]) != from {
		return
	}
	copy(pkt[in+12:in+16], to[:])
	// 内嵌 IP 头校验和
	hs := binary.BigEndian.Uint16(pkt[in+10 : in+12])
	binary.BigEndian.PutUint16(pkt[in+10:in+12], csumReplaceAddr(hs, from[:], to[:]))
	// 内嵌 UDP 头（若 ICMP 引用了前 8 字节）里的校验和覆盖伪首部；TCP 的校验和在偏移 16，不在被引用的 8 字节内。
	if pkt[in+9] == 17 && binary.BigEndian.Uint16(pkt[in+6:in+8])&0x1fff == 0 && total >= in+inIHL+8 {
		s := binary.BigEndian.Uint16(pkt[in+inIHL+6 : in+inIHL+8])
		if s != 0 {
			ns := csumReplaceAddr(s, from[:], to[:])
			if ns == 0 {
				ns = 0xffff
			}
			binary.BigEndian.PutUint16(pkt[in+inIHL+6:in+inIHL+8], ns)
		}
	}
	// ICMP 校验和覆盖整个 ICMP 报文，内容变了：按 ICMP 部分整体重算。
	pkt[ihl+2], pkt[ihl+3] = 0, 0
	binary.BigEndian.PutUint16(pkt[ihl+2:ihl+4], onesComplementSum(pkt[ihl:total]))
}

// onesComplementSum 返回 b 的 16 位反码和的反码（Internet 校验和）。
func onesComplementSum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
