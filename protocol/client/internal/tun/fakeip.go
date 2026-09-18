// Fake-IP 映射表
//
// 原理：
//   1. DNS 查询 openai.com → TUN 返回 fake IP 198.18.0.5
//   2. APP 连接 198.18.0.5:443
//   3. TUN 从映射表反查真实域名 openai.com
//   4. 按分流规则决定 direct/proxy/ai
//
// 网段：198.18.0.0/15（IANA 保留，不会被公网路由）
package tun

import (
	"net"
	"sync"
	"sync/atomic"
)

// DefaultFakeIPTable 全局共享的 Fake-IP 映射表（用于 0ms DNS 解析与真实域名反查）
var DefaultFakeIPTable = NewFakeIPTable("198.18.0.0/15")

// FakeIPTable Fake-IP ↔ 域名映射表（线程安全）
type FakeIPTable struct {
	mu        sync.RWMutex
	ipToHost  map[string]string // fakeIP → realHost
	hostToIP  map[string]string // realHost → fakeIP
	cidr      *net.IPNet
	nextIP    net.IP
	counter   atomic.Uint64
}

// NewFakeIPTable 创建映射表
func NewFakeIPTable(cidrStr string) *FakeIPTable {
	_, cidr, err := net.ParseCIDR(cidrStr)
	if err != nil {
		cidr = &net.IPNet{
			IP:   net.IP{198, 18, 0, 0},
			Mask: net.CIDRMask(15, 32),
		}
	}
	nextIP := make(net.IP, len(cidr.IP))
	copy(nextIP, cidr.IP)
	// 从网段的第 2 个 IP 开始分配（第 1 个是网络地址）
	nextIP[len(nextIP)-1] = 2

	return &FakeIPTable{
		ipToHost: make(map[string]string),
		hostToIP: make(map[string]string),
		cidr:     cidr,
		nextIP:   nextIP,
	}
}

// Allocate 为域名分配 fake IP，已存在则返回已有 IP
func (t *FakeIPTable) Allocate(host string) net.IP {
	t.mu.Lock()
	defer t.mu.Unlock()

	if ipStr, ok := t.hostToIP[host]; ok {
		return net.ParseIP(ipStr)
	}

	ip := t.allocateIP()
	ipStr := ip.String()
	t.ipToHost[ipStr] = host
	t.hostToIP[host] = ipStr
	return ip
}

// Lookup 根据 fake IP 反查真实域名
func (t *FakeIPTable) Lookup(ip net.IP) (string, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	host, ok := t.ipToHost[ip.String()]
	return host, ok
}

// IsFakeIP 判断 IP 是否在 fake-ip 网段内
func (t *FakeIPTable) IsFakeIP(ip net.IP) bool {
	return t.cidr.Contains(ip)
}

func (t *FakeIPTable) allocateIP() net.IP {
	ip := make(net.IP, len(t.nextIP))
	copy(ip, t.nextIP)
	// 递增 IP（简化实现，不考虑溢出）
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
	// 确保不超出网段
	if !t.cidr.Contains(ip) {
		ip = make(net.IP, len(t.cidr.IP))
		copy(ip, t.cidr.IP)
		ip[len(ip)-1] = 2
	}
	copy(t.nextIP, ip)
	t.counter.Add(1)
	return ip
}

// Count 返回已分配的 fake IP 数量
func (t *FakeIPTable) Count() uint64 {
	return t.counter.Load()
}

// FormatDNSResponse 生成 DNS 响应（fake IP 的 A 记录）
func (t *FakeIPTable) FormatDNSResponse(host string) []byte {
	ip := t.Allocate(host)
	dnsResp := []byte{
		0x00, 0x00, // Transaction ID（简化）
		0x81, 0x80,       // Flags: response, no error
		0x00, 0x01,       // Questions: 1
		0x00, 0x01,       // Answers: 1
		0x00, 0x00,       // Authority: 0
		0x00, 0x00,       // Additional: 0
	}
	// Question: host
	dnsResp = append(dnsResp, encodeDNSName(host)...)
	dnsResp = append(dnsResp, 0x00, 0x01) // Type A
	dnsResp = append(dnsResp, 0x00, 0x01) // Class IN
	// Answer
	dnsResp = append(dnsResp, 0xC0, 0x0C) // Pointer to name
	dnsResp = append(dnsResp, 0x00, 0x01) // Type A
	dnsResp = append(dnsResp, 0x00, 0x01) // Class IN
	dnsResp = append(dnsResp, 0x00, 0x00, 0x00, 60) // TTL 60s
	dnsResp = append(dnsResp, 0x00, 0x04)            // Data length 4
	dnsResp = append(dnsResp, ip.To4()...)            // IP address
	return dnsResp
}

func encodeDNSName(name string) []byte {
	var result []byte
	for _, part := range splitDNSName(name) {
		result = append(result, byte(len(part)))
		result = append(result, part...)
	}
	result = append(result, 0x00) // terminator
	return result
}

func splitDNSName(name string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			parts = append(parts, name[start:i])
			start = i + 1
		}
	}
	if start < len(name) {
		parts = append(parts, name[start:])
	}
	return parts
}
