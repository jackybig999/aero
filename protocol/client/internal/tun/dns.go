// Copyright 2026 AERO Protocol Contributors
//
// DNS 智能劫持与极速防污染解析引擎
//
// 监听 TUN 内 53 端口的 UDP 包：
//   - 解析 DNS 查询 → 提取 Question Name 与 Type (A / AAAA)
//   - 节点自身域名（VPS 公网域名）→ 返回真实 IP 响应（严禁 Fake-IP，杜绝自回环死锁）
//   - 本地局域网 / Windows NCSI 探针 → 放行直连
//   - 查分流规则决定策略：
//     - DIRECT（国内域名/各大平台）→ 优先 DoH (https://223.5.5.5/dns-query) + 本地 TTL 缓存 + UDP Fallback
//     - PROXY/AI（海外/被墙域名）：
//       - Type A (IPv4) → 返回 0ms Fake-IP (198.18.0.0/15) 引导进入 AERO 隧道
//       - Type AAAA (IPv6) → 返回 0ms 纯净空响应 (NOERROR, 0 answer)，阻止客户端 IPv6 超时卡顿

package tun

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type dnsCacheEntry struct {
	data      []byte
	expiresAt time.Time
}

// DNSHandler DNS 处理器
type DNSHandler struct {
	servers  []string
	fakeIP   *FakeIPTable
	split    SplitDecider
	edgeHost string
	edgeIP   net.IP

	dohClient *http.Client
	cacheMu   sync.RWMutex
	cache     map[string]dnsCacheEntry
}

// NewDNSHandler 创建 DNS 处理器
func NewDNSHandler(servers []string) *DNSHandler {
	// 创建物理直连 DoH 客户端，强制绑定物理网卡，彻底绕开 TUN 路由表
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return DialPhysicalDirect(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
		MaxIdleConns:        16,
		IdleConnTimeout:     60 * time.Second,
		DisableCompression: true,
	}

	return &DNSHandler{
		servers: servers,
		dohClient: &http.Client{
			Transport: transport,
			Timeout:   1200 * time.Millisecond,
		},
		cache: make(map[string]dnsCacheEntry),
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

// SetEdge 绑定当前激活节点的真实域名与真实 IP
func (h *DNSHandler) SetEdge(host string, ip net.IP) {
	h.edgeHost = strings.ToLower(strings.TrimSpace(host))
	h.edgeIP = ip
}

// HandleQuery 处理原始 DNS UDP Payload
func (h *DNSHandler) HandleQuery(pkt []byte, srcIP net.IP, srcPort uint16) []byte {
	qname, qtype := extractDNSQuestionAndType(pkt)
	if qname == "" {
		return nil
	}
	qnameLower := strings.ToLower(qname)

	// 1. 节点自身绝对白名单防护：绝不能将 Fake-IP 分配给节点自身（杜绝自回环黑洞）
	if h.edgeHost != "" && (qnameLower == h.edgeHost || strings.HasSuffix(qnameLower, "."+h.edgeHost)) {
		if h.edgeIP != nil {
			log.Printf("[DNS] edge node %s -> real ip %s", qname, h.edgeIP)
			return buildAResponse(pkt, qname, h.edgeIP)
		}
		return nil
	}

	// 2. 本地局域网与 Windows NCSI 连通性探针放行
	if isLocalOrSystemDomain(qnameLower) {
		return nil
	}

	// 3. 分流决策：如果规则库判定为 DIRECT 直连（国内域名、.cn、各大国内厂商）
	if h.split != nil && h.split.Decide(qname) == "direct" {
		if resp := h.forwardToUpstream(qnameLower, pkt); resp != nil {
			return resp
		}
		return nil
	}

	// 4. 国外 / 被墙域名 (PROXY / AI)
	// 如果是 Type AAAA (IPv6) 查询，快速返回空响应，避免客户端双栈等待 1-2 秒超时
	if qtype == 0x001C {
		return buildEmptyResponse(pkt, qname, qtype)
	}

	// Type A (IPv4)：0ms 下发 Fake-IP，免疫 DNS 污染并极速引导流量进入 AERO 隧道
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

func isLocalOrSystemDomain(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" || h == "localhost" || strings.HasSuffix(h, ".local") || strings.HasSuffix(h, ".lan") ||
		strings.HasSuffix(h, ".internal") || strings.HasSuffix(h, ".home.arpa") ||
		strings.HasSuffix(h, "msftconnecttest.com") || strings.HasSuffix(h, "msftncsi.com") {
		return true
	}
	return false
}

func buildAResponse(req []byte, host string, ip net.IP) []byte {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}
	resp := []byte{
		0x00, 0x00, // ID replaced from req
		0x81, 0x80, // Flags: Standard response, no error
		0x00, 0x01, // Questions: 1
		0x00, 0x01, // Answers: 1
		0x00, 0x00, // Authority: 0
		0x00, 0x00, // Additional: 0
	}
	if len(req) >= 2 {
		resp[0], resp[1] = req[0], req[1]
	}
	// Question: host
	resp = append(resp, encodeDNSName(host)...)
	resp = append(resp, 0x00, 0x01) // Type A
	resp = append(resp, 0x00, 0x01) // Class IN
	// Answer
	resp = append(resp, 0xC0, 0x0C)             // Pointer to name (offset 12)
	resp = append(resp, 0x00, 0x01)             // Type A
	resp = append(resp, 0x00, 0x01)             // Class IN
	resp = append(resp, 0x00, 0x00, 0x01, 0x2C) // TTL 300s
	resp = append(resp, 0x00, 0x04)             // Length 4
	resp = append(resp, ip4...)                 // IP
	return resp
}

// buildEmptyResponse 构建快速 NOERROR 空应答（Answers = 0），阻止客户端等待超时
func buildEmptyResponse(req []byte, host string, qtype uint16) []byte {
	resp := []byte{
		0x00, 0x00, // ID replaced from req
		0x81, 0x80, // Flags: Standard response, no error
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answers: 0
		0x00, 0x00, // Authority: 0
		0x00, 0x00, // Additional: 0
	}
	if len(req) >= 2 {
		resp[0], resp[1] = req[0], req[1]
	}
	resp = append(resp, encodeDNSName(host)...)
	resp = append(resp, byte(qtype>>8), byte(qtype))
	resp = append(resp, 0x00, 0x01) // Class IN
	return resp
}

// extractDNSQuestionAndType 提取 DNS 查询中的域名与 QTYPE (A: 0x0001, AAAA: 0x001C)
func extractDNSQuestionAndType(pkt []byte) (string, uint16) {
	if len(pkt) <= 12 {
		return "", 0
	}
	offset := 12
	var name []byte
	for offset < len(pkt) {
		length := int(pkt[offset])
		if length == 0 {
			offset++
			break
		}
		if length > 63 || offset+1+length > len(pkt) {
			return "", 0
		}
		if len(name) > 0 {
			name = append(name, '.')
		}
		name = append(name, pkt[offset+1:offset+1+length]...)
		offset += 1 + length
	}
	if offset+4 > len(pkt) {
		return string(name), 0x0001 // Default Type A
	}
	qtype := binary.BigEndian.Uint16(pkt[offset : offset+2])
	return string(name), qtype
}

// forwardToUpstream 向上游解析：优先查本地缓存 -> 查 DoH 加密信道 -> Fallback 明文 UDP
func (h *DNSHandler) forwardToUpstream(qname string, pkt []byte) []byte {
	// 1. 检查本地 TTL 缓存
	h.cacheMu.RLock()
	if entry, ok := h.cache[qname]; ok {
		if time.Now().Before(entry.expiresAt) {
			h.cacheMu.RUnlock()
			res := make([]byte, len(entry.data))
			copy(res, entry.data)
			if len(pkt) >= 2 && len(res) >= 2 {
				res[0], res[1] = pkt[0], pkt[1]
			}
			return res
		}
	}
	h.cacheMu.RUnlock()

	// 2. 优先通过 DoH (DNS-over-HTTPS) 阿里公共 DNS 请求（彻底防 DNS 污染与监听）
	resp := h.queryDoH(pkt)
	if resp == nil {
		// 3. Fallback 到多上游明文 UDP (223.5.5.5, 119.29.29.29)
		resp = h.queryUDP(pkt)
	}

	if resp != nil && len(resp) >= 12 {
		h.cacheMu.Lock()
		if len(h.cache) > 2000 {
			// 缓存淘汰：清除过期条目或截半
			for k, v := range h.cache {
				if time.Now().After(v.expiresAt) {
					delete(h.cache, k)
				}
				if len(h.cache) <= 1000 {
					break
				}
			}
		}
		h.cache[qname] = dnsCacheEntry{
			data:      resp,
			expiresAt: time.Now().Add(60 * time.Second),
		}
		h.cacheMu.Unlock()
	}
	return resp
}

// queryDoH 发起 RFC 8484 标准 DoH 请求
func (h *DNSHandler) queryDoH(pkt []byte) []byte {
	if h.dohClient == nil {
		return nil
	}
	req, err := http.NewRequest("POST", "https://223.5.5.5/dns-query", bytes.NewReader(pkt))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := h.dohClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil || len(data) < 12 {
		return nil
	}
	return data
}

// queryUDP 发起明文 UDP DNS 查询，支持多上游 fallback
func (h *DNSHandler) queryUDP(pkt []byte) []byte {
	upstreams := []string{"223.5.5.5:53", "119.29.29.29:53"}
	if len(h.servers) > 0 {
		upstreams = h.servers
	}

	for _, upstream := range upstreams {
		s := upstream
		if !strings.Contains(s, ":") {
			s = net.JoinHostPort(s, "53")
		}
		conn, err := net.DialTimeout("udp", s, 800*time.Millisecond)
		if err != nil {
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(1200 * time.Millisecond))
		if _, err := conn.Write(pkt); err != nil {
			conn.Close()
			continue
		}
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		conn.Close()
		if err == nil && n >= 12 {
			return buf[:n]
		}
	}
	return nil
}
