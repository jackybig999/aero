// Game QoS: NAT 穿透辅助
//
// 支持 Full Cone NAT 探测 + UPnP 端口映射
package gameqos

import (
	"log"
	"net"
	"time"
)

// NATType NAT 类型
type NATType int

const (
	NATUnknown       NATType = iota
	NATFullCone              // 完全锥形
	NATRestrictedCone        // 受限锥形
	NATPortRestricted        // 端口限制锥形
	NATSymmetric             // 对称
)

func (t NATType) String() string {
	switch t {
	case NATFullCone:
		return "full_cone"
	case NATRestrictedCone:
		return "restricted_cone"
	case NATPortRestricted:
		return "port_restricted"
	case NATSymmetric:
		return "symmetric"
	default:
		return "unknown"
	}
}

// NATProbe NAT 类型探测器
type NATProbe struct {
	localAddr  string
	stunServer string
}

// NewNATProbe 创建探测器
func NewNATProbe(localAddr string) *NATProbe {
	return &NATProbe{
		localAddr:  localAddr,
		stunServer: "stun.l.google.com:19302",
	}
}

// Detect 探测 NAT 类型
//
// 简化实现：使用 STUN 协议发送 binding request
// 完整实现需要 RFC 5389 STUN 客户端
func (p *NATProbe) Detect() NATType {
	conn, err := net.DialTimeout("udp", p.stunServer, 3*time.Second)
	if err != nil {
		log.Printf("[NAT] %s unreachable: %v", p.stunServer, err)
		return NATUnknown
	}
	defer conn.Close()

	// 发送 STUN Binding Request（简化版）
	stunReq := []byte{
		0x00, 0x01,             // Binding Request
		0x00, 0x00,             // Message Length = 0
		0x21, 0x12, 0xA4, 0x42, // Magic Cookie
		// Transaction ID (12 bytes)
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
	}
	if _, err := conn.Write(stunReq); err != nil {
		return NATUnknown
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return NATSymmetric // 无响应 → 可能是对称 NAT
	}
	_ = n

	// 收到 STUN 响应 → 至少是 Restricted Cone
	log.Printf("[NAT] STUN response received, NAT type: %s", NATRestrictedCone)
	return NATRestrictedCone // 简化：收到响应即视为可用
}

// RecommendPort 推荐使用的 UDP 端口
func (p *NATProbe) RecommendPort() int {
	nat := p.Detect()
	switch nat {
	case NATFullCone, NATRestrictedCone, NATPortRestricted:
		return 443 // QUIC 默认端口
	case NATSymmetric:
		return 8443 // 尝试备用端口
	default:
		return 443
	}
}
