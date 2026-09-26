package tun

import (
	"net"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

// BuildIPv4TCPSYN builds a minimal SYN so gVisor will accept a new TCP.
func BuildIPv4TCPSYN(src, dst net.IP, sport, dport uint16) []byte {
	s4 := src.To4()
	d4 := dst.To4()
	srcAddr := tcpip.AddrFrom4Slice(s4)
	dstAddr := tcpip.AddrFrom4Slice(d4)
	pkt := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize)
	ip := header.IPv4(pkt[:header.IPv4MinimumSize])
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(pkt)),
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	th := header.TCP(pkt[header.IPv4MinimumSize:])
	th.Encode(&header.TCPFields{
		SrcPort:    sport,
		DstPort:    dport,
		SeqNum:     1,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: 65535,
	})
	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, srcAddr, dstAddr, uint16(len(th)))
	th.SetChecksum(^th.CalculateChecksum(xsum))
	return pkt
}

// BuildIPv4TCPACK completes the 3-way handshake after a SYN-ACK.
func BuildIPv4TCPACK(src, dst net.IP, sport, dport uint16, seq, ack uint32) []byte {
	s4 := src.To4()
	d4 := dst.To4()
	srcAddr := tcpip.AddrFrom4Slice(s4)
	dstAddr := tcpip.AddrFrom4Slice(d4)
	pkt := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize)
	ip := header.IPv4(pkt[:header.IPv4MinimumSize])
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(pkt)),
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	th := header.TCP(pkt[header.IPv4MinimumSize:])
	th.Encode(&header.TCPFields{
		SrcPort:    sport,
		DstPort:    dport,
		SeqNum:     seq,
		AckNum:     ack,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck,
		WindowSize: 65535,
	})
	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, srcAddr, dstAddr, uint16(len(th)))
	th.SetChecksum(^th.CalculateChecksum(xsum))
	return pkt
}

func ParseTCPSeqAck(pkt []byte) (seq, ack uint32, flags byte, ok bool) {
	if len(pkt) < 40 || pkt[0]>>4 != 4 || pkt[9] != 6 {
		return 0, 0, 0, false
	}
	ihl := int(pkt[0]&0x0F) * 4
	if len(pkt) < ihl+20 {
		return 0, 0, 0, false
	}
	th := pkt[ihl:]
	seq = uint32(th[4])<<24 | uint32(th[5])<<16 | uint32(th[6])<<8 | uint32(th[7])
	ack = uint32(th[8])<<24 | uint32(th[9])<<16 | uint32(th[10])<<8 | uint32(th[11])
	return seq, ack, th[13], true
}
