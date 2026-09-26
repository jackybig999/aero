// Fake-IP 映射表
//
// 原理：
//  1. DNS 查询 openai.com → TUN 返回 fake IP 198.18.0.5
//  2. APP 连接 198.18.0.5:443
//  3. TUN 从映射表反查真实域名 openai.com
//  4. 按分流规则决定 direct/proxy/ai
//
// 网段：198.18.0.0/15（IANA 保留，不会被公网路由）
package tun

import (
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
)

// DefaultMaxFakeIPSlots 强制 65535 槽位上限，防止内存无界泄漏 (Rule L5)
const DefaultMaxFakeIPSlots = 65535

// DefaultFakeIPTable 全局共享的 Fake-IP 映射表（用于 0ms DNS 解析与真实域名反查）
var DefaultFakeIPTable = NewFakeIPTable("198.18.0.0/15")

type lruNode struct {
	host string
	ip   uint32
	prev *lruNode
	next *lruNode
}

// FakeIPTable Fake-IP ↔ 域名双向紧凑映射表，内建 65535 槽位 LRU 自动淘汰机制 (Rule L5)
type FakeIPTable struct {
	mu         sync.Mutex
	hostToNode map[string]*lruNode
	ipToNode   map[uint32]*lruNode
	head       *lruNode // 最近使用 (MRU)
	tail       *lruNode // 最久未使用 (LRU)
	maxSlots   int
	cidr       *net.IPNet
	baseIP     uint32
	nextOffset uint32
	maxOffset  uint32
	counter    atomic.Uint64
}

// NewFakeIPTable 创建映射表，可自定义槽位上限（默认 65535）
func NewFakeIPTable(cidrStr string, maxSlots ...int) *FakeIPTable {
	_, cidr, err := net.ParseCIDR(cidrStr)
	if err != nil {
		cidr = &net.IPNet{
			IP:   net.IP{198, 18, 0, 0},
			Mask: net.CIDRMask(15, 32),
		}
	}
	baseIP := binary.BigEndian.Uint32(cidr.IP.To4())
	ones, bits := cidr.Mask.Size()
	total := uint32(1) << (bits - ones)
	maxOffset := total - 2
	if maxOffset < 2 {
		maxOffset = 65535
	}

	limit := DefaultMaxFakeIPSlots
	if len(maxSlots) > 0 && maxSlots[0] > 0 {
		limit = maxSlots[0]
	}

	return &FakeIPTable{
		hostToNode: make(map[string]*lruNode, 1024),
		ipToNode:   make(map[uint32]*lruNode, 1024),
		maxSlots:   limit,
		cidr:       cidr,
		baseIP:     baseIP,
		nextOffset: 1, // 从 .2 开始
		maxOffset:  maxOffset,
	}
}

func (t *FakeIPTable) moveToHead(node *lruNode) {
	if t.head == node {
		return
	}
	t.removeNode(node)
	t.addToHead(node)
}

func (t *FakeIPTable) addToHead(node *lruNode) {
	node.prev = nil
	node.next = t.head
	if t.head != nil {
		t.head.prev = node
	}
	t.head = node
	if t.tail == nil {
		t.tail = node
	}
}

func (t *FakeIPTable) removeNode(node *lruNode) {
	if node.prev != nil {
		node.prev.next = node.next
	} else {
		t.head = node.next
	}
	if node.next != nil {
		node.next.prev = node.prev
	} else {
		t.tail = node.prev
	}
	node.prev = nil
	node.next = nil
}

func (t *FakeIPTable) evictTail() {
	if t.tail == nil {
		return
	}
	old := t.tail
	t.removeNode(old)
	delete(t.hostToNode, old.host)
	delete(t.ipToNode, old.ip)
}

// Allocate 为域名分配 fake IP，已存在则命中 LRU 刷新并返回已有 IP；槽位达到上限时强制淘汰最老条目 (Rule L5)
func (t *FakeIPTable) Allocate(host string) net.IP {
	t.mu.Lock()
	defer t.mu.Unlock()

	if node, ok := t.hostToNode[host]; ok {
		t.moveToHead(node)
		return uint32ToIP(node.ip)
	}

	// 强制 65535 槽位 LRU 回收
	if len(t.hostToNode) >= t.maxSlots {
		t.evictTail()
	}

	ipUint := t.allocateIPUint()

	node := &lruNode{
		host: host,
		ip:   ipUint,
	}
	t.addToHead(node)
	t.hostToNode[host] = node
	t.ipToNode[ipUint] = node

	return uint32ToIP(ipUint)
}

// Lookup 根据 fake IP 反查真实域名并刷新 LRU
func (t *FakeIPTable) Lookup(ip net.IP) (string, bool) {
	ipUint, ok := ipToUint32(ip)
	if !ok {
		return "", false
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	node, ok := t.ipToNode[ipUint]
	if !ok {
		return "", false
	}
	t.moveToHead(node)
	return node.host, true
}

// IsFakeIP 判断 IP 是否在 fake-ip 网段内
func (t *FakeIPTable) IsFakeIP(ip net.IP) bool {
	return t.cidr.Contains(ip)
}

// Size 返回当前内存中活跃的映射条目数
func (t *FakeIPTable) Size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.hostToNode)
}

func (t *FakeIPTable) allocateIPUint() uint32 {
	t.nextOffset++
	if t.nextOffset > t.maxOffset {
		t.nextOffset = 2
	}
	t.counter.Add(1)
	return t.baseIP + t.nextOffset
}

func ipToUint32(ip net.IP) (uint32, bool) {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, false
	}
	return binary.BigEndian.Uint32(ip4), true
}

func uint32ToIP(u uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, u)
	return ip
}

// Count 返回累计分配的 fake IP 计数
func (t *FakeIPTable) Count() uint64 {
	return t.counter.Load()
}

// FormatDNSResponse 生成 DNS 响应（fake IP 的 A 记录）
func (t *FakeIPTable) FormatDNSResponse(host string) []byte {
	ip := t.Allocate(host)
	dnsResp := []byte{
		0x00, 0x00, // Transaction ID（简化）
		0x81, 0x80, // Flags: response, no error
		0x00, 0x01, // Questions: 1
		0x00, 0x01, // Answers: 1
		0x00, 0x00, // Authority: 0
		0x00, 0x00, // Additional: 0
	}
	// Question: host
	dnsResp = append(dnsResp, encodeDNSName(host)...)
	dnsResp = append(dnsResp, 0x00, 0x01) // Type A
	dnsResp = append(dnsResp, 0x00, 0x01) // Class IN
	// Answer
	dnsResp = append(dnsResp, 0xC0, 0x0C)           // Pointer to name
	dnsResp = append(dnsResp, 0x00, 0x01)           // Type A
	dnsResp = append(dnsResp, 0x00, 0x01)           // Class IN
	dnsResp = append(dnsResp, 0x00, 0x00, 0x00, 60) // TTL 60s
	dnsResp = append(dnsResp, 0x00, 0x04)           // Data length 4
	dnsResp = append(dnsResp, ip.To4()...)          // IP address
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
