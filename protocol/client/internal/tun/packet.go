// IP 包解析：纯函数，零状态
//
// 支持 IPv4/IPv6 header 解析 + TCP/UDP 端口提取
package tun

import (
	"encoding/binary"
	"fmt"
	"net"
)

// 协议号常量
const (
	IPProtoTCP = 6
	IPProtoUDP = 17
)

// IPv4Header 精简 IPv4 头
type IPv4Header struct {
	Version    uint8
	IHL        uint8 // 头长度（4字节单位）
	DSCP       uint8
	TotalLen   uint16
	ID         uint16
	Flags      uint8
	FragOffset uint16
	TTL        uint8
	Protocol   uint8
	Checksum   uint16
	SrcIP      net.IP
	DstIP      net.IP
}

// IPv6Header 精简 IPv6 头
type IPv6Header struct {
	Version      uint8
	TrafficClass uint8
	FlowLabel    uint32
	PayloadLen   uint16
	NextHeader   uint8
	HopLimit     uint8
	SrcIP        net.IP
	DstIP        net.IP
}

// ParseIPv4Header 解析 IPv4 头
func ParseIPv4Header(pkt []byte) (IPv4Header, error) {
	if len(pkt) < 20 {
		return IPv4Header{}, fmt.Errorf("packet too short: %d bytes", len(pkt))
	}
	h := IPv4Header{
		Version:    pkt[0] >> 4,
		IHL:        pkt[0] & 0x0F,
		DSCP:       pkt[1] >> 2,
		TotalLen:   binary.BigEndian.Uint16(pkt[2:4]),
		ID:         binary.BigEndian.Uint16(pkt[4:6]),
		Flags:      pkt[6] >> 5,
		FragOffset: binary.BigEndian.Uint16([]byte{pkt[6] & 0x1F, pkt[7]}),
		TTL:        pkt[8],
		Protocol:   pkt[9],
		Checksum:   binary.BigEndian.Uint16(pkt[10:12]),
		SrcIP:      net.IP(pkt[12:16]),
		DstIP:      net.IP(pkt[16:20]),
	}
	if h.Version != 4 {
		return h, fmt.Errorf("not IPv4: version=%d", h.Version)
	}
	return h, nil
}

// ParseIPv6Header 解析 IPv6 头
func ParseIPv6Header(pkt []byte) (IPv6Header, error) {
	if len(pkt) < 40 {
		return IPv6Header{}, fmt.Errorf("packet too short: %d bytes", len(pkt))
	}
	h := IPv6Header{
		Version:      pkt[0] >> 4,
		TrafficClass: (pkt[0]&0x0F)<<4 | pkt[1]>>4,
		FlowLabel:    binary.BigEndian.Uint32([]byte{0, pkt[1] & 0x0F, pkt[2], pkt[3]}),
		PayloadLen:   binary.BigEndian.Uint16(pkt[4:6]),
		NextHeader:   pkt[6],
		HopLimit:     pkt[7],
		SrcIP:        net.IP(pkt[8:24]),
		DstIP:        net.IP(pkt[24:40]),
	}
	if h.Version != 6 {
		return h, fmt.Errorf("not IPv6: version=%d", h.Version)
	}
	return h, nil
}

// TCPPorts 从 TCP 包中提取源端口和目标端口
func TCPPorts(pkt []byte, ipHdrLen int) (srcPort, dstPort uint16, err error) {
	if len(pkt) < ipHdrLen+20 {
		return 0, 0, fmt.Errorf("TCP header too short")
	}
	srcPort = binary.BigEndian.Uint16(pkt[ipHdrLen : ipHdrLen+2])
	dstPort = binary.BigEndian.Uint16(pkt[ipHdrLen+2 : ipHdrLen+4])
	return
}

// UDPPorts 从 UDP 包中提取源端口和目标端口
func UDPPorts(pkt []byte, ipHdrLen int) (srcPort, dstPort uint16, err error) {
	if len(pkt) < ipHdrLen+8 {
		return 0, 0, fmt.Errorf("UDP header too short")
	}
	srcPort = binary.BigEndian.Uint16(pkt[ipHdrLen : ipHdrLen+2])
	dstPort = binary.BigEndian.Uint16(pkt[ipHdrLen+2 : ipHdrLen+4])
	return
}

// TCPPayload 返回 TCP 包的应用层数据
func TCPPayload(pkt []byte, ipHdrLen int) []byte {
	tcpHdrLen := int((pkt[ipHdrLen+12] >> 4) * 4)
	offset := ipHdrLen + tcpHdrLen
	if offset >= len(pkt) {
		return nil
	}
	return pkt[offset:]
}

// UDPPayload 返回 UDP 包的应用层数据
func UDPPayload(pkt []byte, ipHdrLen int) []byte {
	offset := ipHdrLen + 8
	if offset >= len(pkt) {
		return nil
	}
	return pkt[offset:]
}

// IsTCP_SYN 判断是否为 TCP SYN 包（会话开始）
func IsTCP_SYN(pkt []byte, ipHdrLen int) bool {
	if len(pkt) < ipHdrLen+14 {
		return false
	}
	flags := pkt[ipHdrLen+13]
	return flags&0x02 != 0 && flags&0x10 == 0 // SYN=1, ACK=0
}

// IsTCP_RST 判断是否为 TCP RST 包
func IsTCP_RST(pkt []byte, ipHdrLen int) bool {
	if len(pkt) < ipHdrLen+14 {
		return false
	}
	return pkt[ipHdrLen+13]&0x04 != 0
}
