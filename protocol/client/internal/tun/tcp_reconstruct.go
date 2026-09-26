// TCP/IP 包头重建：将从目标服务器收到的裸数据重新封装为 IP/TCP 包
//
// 策略：
//  1. 保存 SYN 包的关键信息作为模板（IP 地址、端口、初始 SEQ）
//  2. 收到目标数据时，基于模板构建响应包
//  3. 交换 src/dst IP 和端口
//  4. 更新 SEQ/ACK 号
//  5. 重新计算 TCP checksum
package tun

import (
	"encoding/binary"
	"net"
)

// TCPState TCP 连接状态追踪（用于包头重建）
type TCPState struct {
	// 客户端侧（原始 SYN 中的值）
	ClientIP   net.IP
	ServerIP   net.IP
	ClientPort uint16
	ServerPort uint16
	ClientSeq  uint32 // 客户端初始 SEQ（ISN）
	ServerSeq  uint32 // 服务端初始 SEQ

	// 当前追踪值
	ClientSeqNext uint32 // 客户端下一个 SEQ
	ServerSeqNext uint32 // 服务端下一个 SEQ
	ClientAck     uint32 // 发往客户端的 ACK
	ServerAck     uint32 // 发往服务端的 ACK
}

// InitFromSYN 从客户端 SYN 包初始化 TCP 状态
func (s *TCPState) InitFromSYN(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq uint32) {
	s.ClientIP = make(net.IP, len(srcIP))
	copy(s.ClientIP, srcIP)
	s.ServerIP = make(net.IP, len(dstIP))
	copy(s.ServerIP, dstIP)
	s.ClientPort = srcPort
	s.ServerPort = dstPort
	s.ClientSeq = seq
	s.ClientSeqNext = seq + 1 // SYN 消耗 1 个 SEQ
	s.ClientAck = 0
	s.ServerAck = seq + 1
}

// RecordSYNACK 记录服务端 SYN-ACK
func (s *TCPState) RecordSYNACK(seq uint32) {
	s.ServerSeq = seq
	s.ServerSeqNext = seq + 1
	s.ServerAck = s.ClientSeqNext
}

// BuildResponseIPv4 构建发往客户端的 IPv4 + TCP 响应包
func (s *TCPState) BuildResponseIPv4(payload []byte, flags uint8) []byte {
	// IP 头 20 字节 + TCP 头 20 字节
	totalLen := 20 + 20 + len(payload)
	pkt := make([]byte, totalLen)

	// --- IPv4 Header ---
	pkt[0] = 0x45 // Version=4, IHL=5
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:6], 0x0001) // ID
	pkt[8] = 64                                  // TTL
	pkt[9] = 6                                   // Protocol=TCP
	copy(pkt[12:16], s.ServerIP.To4())           // Src = server
	copy(pkt[16:20], s.ClientIP.To4())           // Dst = client
	ipChecksum(pkt[:20])                         // checksum is written at 10:12

	// --- TCP Header ---
	tcpOff := 20
	binary.BigEndian.PutUint16(pkt[tcpOff:tcpOff+2], s.ServerPort)   // Src port
	binary.BigEndian.PutUint16(pkt[tcpOff+2:tcpOff+4], s.ClientPort) // Dst port
	binary.BigEndian.PutUint32(pkt[tcpOff+4:tcpOff+8], s.ServerSeqNext)
	binary.BigEndian.PutUint32(pkt[tcpOff+8:tcpOff+12], s.ClientAck)
	pkt[tcpOff+12] = 0x50                                        // Data offset=5 (20 bytes)
	pkt[tcpOff+13] = flags                                       // ACK + PSH etc
	binary.BigEndian.PutUint16(pkt[tcpOff+14:tcpOff+16], 0xFFFF) // Window
	copy(pkt[tcpOff+20:], payload)

	// TCP checksum
	tcpChecksum(pkt[tcpOff:], s.ServerIP.To4(), s.ClientIP.To4())

	// 更新序列号
	if len(payload) > 0 {
		s.ServerSeqNext += uint32(len(payload))
	}
	s.ClientAck = s.ClientSeqNext

	return pkt
}

// BuildSYNACK 构建 SYN-ACK 响应包
func (s *TCPState) BuildSYNACK() []byte {
	s.ServerSeq = 0x12345678
	s.ServerSeqNext = s.ServerSeq + 1
	s.ServerAck = s.ClientSeqNext
	s.ClientAck = s.ClientSeqNext // ACK field must be client_isn+1
	return s.BuildResponseIPv4(nil, 0x12)
}

// BuildRST 构建 RST 包
func (s *TCPState) BuildRST() []byte {
	return s.BuildResponseIPv4(nil, 0x04) // RST
}

// BuildFIN 构建 FIN 包
func (s *TCPState) BuildFIN() []byte {
	return s.BuildResponseIPv4(nil, 0x11) // FIN+ACK
}

// UpdateFromClientData 根据客户端发来的数据更新状态
func (s *TCPState) UpdateFromClientData(payloadLen int) {
	s.ClientSeqNext += uint32(payloadLen)
	s.ServerAck = s.ClientSeqNext
}

// --- Checksum helpers ---

func ipChecksum(hdr []byte) {
	hdr[10] = 0
	hdr[11] = 0
	sum := checksum(hdr[:20])
	binary.BigEndian.PutUint16(hdr[10:12], sum)
}

func tcpChecksum(tcpHdr []byte, srcIP, dstIP net.IP) {
	// Pseudo-header
	pseudoLen := 12 + len(tcpHdr)
	pseudo := make([]byte, pseudoLen)
	copy(pseudo[0:4], srcIP)
	copy(pseudo[4:8], dstIP)
	pseudo[8] = 0
	pseudo[9] = 6 // TCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcpHdr)))
	copy(pseudo[12:], tcpHdr)

	// Zero out existing checksum
	tcpHdr[16] = 0
	tcpHdr[17] = 0

	binary.BigEndian.PutUint16(tcpHdr[16:18], checksum(pseudo))
}

func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
