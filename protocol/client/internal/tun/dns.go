// DNS 劫持处理
//
// 监听 TUN 内 53 端口的 UDP 包：
//   - 解析 DNS 查询 → 提取 Question Name
//   - 查分流规则决定策略
//   - DIRECT → 转发到系统 DNS
//   - PROXY/AI → 返回 fake IP
package tun

import (
	"log"
	"net"
)

// DNSHandler DNS 处理
type DNSHandler struct {
	servers []string
	fakeIP  *FakeIPTable
	split   SplitDecider
}

// NewDNSHandler 创建 DNS 处理器
func NewDNSHandler(servers []string) *DNSHandler {
	return &DNSHandler{
		servers: servers,
	}
}

// SetFakeIP 绑定 Fake-IP 表
func (h *DNSHandler) SetFakeIP(t *FakeIPTable) {
	h.fakeIP = t
}

// SetSplit 绑定分流决策器
func (h *DNSHandler) SetSplit(s SplitDecider) {
	h.split = s
}

// HandleQuery expects a raw DNS payload (not an IP packet).
// Full-traffic VPN: answer every public name with Fake-IP so TCP/UDP
// later hit the TUN engine and go out via AERO.
func (h *DNSHandler) HandleQuery(pkt []byte, srcIP net.IP, srcPort uint16) []byte {
	qname := extractDNSQuestion(pkt)
	if qname == "" {
		return nil
	}
	if h.fakeIP != nil {
		resp := h.fakeIP.FormatDNSResponse(qname)
		if len(pkt) >= 2 && len(resp) >= 2 {
			resp[0], resp[1] = pkt[0], pkt[1]
		}
		log.Printf("[DNS] fake-ip %s", qname)
		return resp
	}
	return nil
}

// extractDNSQuestion 提取 DNS 查询中的域名（简化实现）
func extractDNSQuestion(pkt []byte) string {
	// 跳过 12 字节 DNS header
	if len(pkt) <= 12 {
		return ""
	}
	offset := 12
	var name []byte
	for offset < len(pkt) {
		length := int(pkt[offset])
		if length == 0 {
			break
		}
		if length > 63 || offset+1+length > len(pkt) {
			return ""
		}
		if len(name) > 0 {
			name = append(name, '.')
		}
		name = append(name, pkt[offset+1:offset+1+length]...)
		offset += 1 + length
	}
	return string(name)
}

func (h *DNSHandler) forwardToUpstream(pkt []byte) []byte {
	conn, err := net.Dial("udp", net.JoinHostPort(h.servers[0], "53"))
	if err != nil {
		return nil
	}
	defer conn.Close()

	if _, err := conn.Write(pkt); err != nil {
		return nil
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return nil
	}
	return buf[:n]
}

func (h *DNSHandler) buildRealDNSResponse(query []byte, ip net.IP) []byte {
	// 简化：复用 query 的前 2 字节 Transaction ID
	resp := make([]byte, len(query))
	copy(resp, query)
	if len(resp) >= 4 {
		resp[2] = 0x81 // 标准响应标志
		resp[3] = 0x80
	}
	return resp
}
