// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultMaxFakeIPSlots 限制 65535 槽位上限
const DefaultMaxFakeIPSlots = 65535

type lruNode struct {
	host       string
	ip         uint32
	prev       *lruNode
	next       *lruNode
	refCount   atomic.Int32
	lastAccess atomic.Int64
}

// FakeIPTable Fake-IP ↔ 域名双向映射表，65535 槽位 LRU 自动淘汰
type FakeIPTable struct {
	mu         sync.RWMutex
	hostToNode map[string]*lruNode
	ipToNode   map[uint32]*lruNode
	head       *lruNode
	tail       *lruNode
	maxSlots   int
	cidr       *net.IPNet
	baseIP     uint32
	nextOffset uint32
	maxOffset  uint32
	counter    atomic.Uint64
}

// NewFakeIPTable 创建 Fake-IP 映射表
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
		nextOffset: 1,
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
}

func (t *FakeIPTable) findEvictableNode() *lruNode {
	curr := t.tail
	count := 0
	for curr != nil {
		if curr.refCount.Load() == 0 {
			t.removeNode(curr)
			return curr
		}
		count++
		if count >= 32 {
			if t.maxSlots < 131072 {
				t.maxSlots += 1024
				if t.maxSlots > 131072 {
					t.maxSlots = 131072
				}
			}
			return nil
		}
		curr = curr.prev
	}
	if t.maxSlots < 131072 {
		t.maxSlots += 1024
		if t.maxSlots > 131072 {
			t.maxSlots = 131072
		}
	}
	return nil
}

// Allocate 为域名分配或复用 Fake-IP
func (t *FakeIPTable) Allocate(host string) net.IP {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if node, ok := t.hostToNode[host]; ok {
		t.moveToHead(node)
		node.lastAccess.Store(time.Now().UnixNano())
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, node.ip)
		return ip
	}

	if len(t.hostToNode) >= t.maxSlots {
		if evicted := t.findEvictableNode(); evicted != nil {
			delete(t.hostToNode, evicted.host)
			delete(t.ipToNode, evicted.ip)
		}
	}

	var ipVal uint32
	for attempts := 0; attempts < int(t.maxOffset); attempts++ {
		t.nextOffset++
		if t.nextOffset > t.maxOffset {
			t.nextOffset = 1
		}
		cand := t.baseIP + t.nextOffset
		if _, exists := t.ipToNode[cand]; !exists {
			ipVal = cand
			break
		}
	}

	if ipVal == 0 {
		if evicted := t.findEvictableNode(); evicted != nil {
			ipVal = evicted.ip
			delete(t.hostToNode, evicted.host)
			delete(t.ipToNode, evicted.ip)
		}
	}

	if ipVal == 0 {
		return nil
	}

	node := &lruNode{host: host, ip: ipVal}
	node.lastAccess.Store(time.Now().UnixNano())
	t.hostToNode[host] = node
	t.ipToNode[ipVal] = node
	t.addToHead(node)

	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipVal)
	return ip
}

// Acquire 线程安全地借出 Fake-IP 对应的主机名，并增加引用计数；返回对应主机名与释放函数
func (t *FakeIPTable) Acquire(ip net.IP) (string, func()) {
	if t == nil || ip == nil {
		return "", func() {}
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return "", func() {}
	}
	ipVal := binary.BigEndian.Uint32(ip4)

	t.mu.RLock()
	defer t.mu.RUnlock()

	if node, ok := t.ipToNode[ipVal]; ok {
		node.refCount.Add(1)
		node.lastAccess.Store(time.Now().UnixNano())
		return node.host, func() {
			node.refCount.Add(-1)
		}
	}
	return "", func() {}
}

// Lookup 根据 Fake-IP 反查原始真实域名
func (t *FakeIPTable) Lookup(ip net.IP) string {
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}
	ipVal := binary.BigEndian.Uint32(ip4)

	t.mu.Lock()
	defer t.mu.Unlock()

	if node, ok := t.ipToNode[ipVal]; ok {
		t.moveToHead(node)
		node.lastAccess.Store(time.Now().UnixNano())
		return node.host
	}
	return ""
}

// Contains 检查是否属于 Fake-IP 网段
func (t *FakeIPTable) Contains(ip net.IP) bool {
	if t.cidr == nil || ip == nil {
		return false
	}
	return t.cidr.Contains(ip)
}

// FormatDNSResponse 格式化 DNS A 记录响应
func (t *FakeIPTable) FormatDNSResponse(host string) []byte {
	ip := t.Allocate(host)
	if ip == nil {
		return nil
	}
	return buildAResponse(nil, host, ip)
}

// DefaultFakeIPTable 全局 Fake-IP 表
var DefaultFakeIPTable = NewFakeIPTable("198.18.0.0/15")

type dnsCacheEntry struct {
	data      []byte
	expiresAt time.Time
}

// TunnelDNSResolver 隧道短流 DNS 解析函数类型
type TunnelDNSResolver func(ctx context.Context, domain string) (net.IP, error)

// DoHResolver DoH 解析函数类型 (POST /dns-query)
type DoHResolver func(ctx context.Context, dnsReq []byte) ([]byte, error)

// DNSHandler 两级 DNS 漏斗处理器
type DNSHandler struct {
	fakeIP         *FakeIPTable
	split          *SplitEngine
	edgeHost       string
	edgeIP         net.IP
	tunnelResolver TunnelDNSResolver
	dohResolver    DoHResolver
	physicalDNS    string
	physicalDialer func(ctx context.Context, network, addr string) (net.Conn, error)

	cacheMu sync.RWMutex
	cache   map[string]dnsCacheEntry
}

// NewDNSHandler 创建 DNS 处理器
func NewDNSHandler(split *SplitEngine) *DNSHandler {
	return &DNSHandler{
		fakeIP:      DefaultFakeIPTable,
		split:       split,
		physicalDNS: "223.5.5.5:53",
		cache:       make(map[string]dnsCacheEntry),
	}
}

// SetFakeIP 绑定 Fake-IP 表
func (h *DNSHandler) SetFakeIP(t *FakeIPTable) {
	h.fakeIP = t
}

// SetEdge 绑定当前节点域名与 IP
func (h *DNSHandler) SetEdge(host string, ip net.IP) {
	h.edgeHost = strings.ToLower(strings.TrimSpace(host))
	h.edgeIP = ip
}

// SetTunnelResolver 绑定隧道内短流解析器
func (h *DNSHandler) SetTunnelResolver(resolver TunnelDNSResolver) {
	h.tunnelResolver = resolver
}

// SetDoHResolver 绑定 HTTP/3 DoH 解析器
func (h *DNSHandler) SetDoHResolver(resolver DoHResolver) {
	h.dohResolver = resolver
}

// SetPhysicalDNS 设置物理直连 DNS 地址
func (h *DNSHandler) SetPhysicalDNS(addr string) {
	if addr != "" {
		if !strings.Contains(addr, ":") {
			addr = addr + ":53"
		}
		h.physicalDNS = addr
	}
}

// SetPhysicalDialer 允许在测试中注入物理 DNS 拨号器 (如内存通道)
func (h *DNSHandler) SetPhysicalDialer(dialer func(ctx context.Context, network, addr string) (net.Conn, error)) {
	h.physicalDialer = dialer
}

// HandleQuery 两级 DNS 漏斗核心入口：
// 阶段 1：.cn 直连 & 丢弃 AAAA；
// 阶段 2：其余走隧道短流；未建连/超时回退 198.18 假 IP；AAAA 始终空应答
func (h *DNSHandler) HandleQuery(pkt []byte, srcIP net.IP, srcPort uint16) []byte {
	qname, qtype := extractDNSQuestionAndType(pkt)
	if qname == "" {
		return nil
	}
	qnameLower := strings.ToLower(qname)

	// 本地/局域网探针放行
	if isLocalOrSystemDomain(qnameLower) {
		return nil
	}

	// 节点自身域名：返回真实 IP
	if h.edgeHost != "" && (qnameLower == h.edgeHost || strings.HasSuffix(qnameLower, "."+h.edgeHost)) {
		if h.edgeIP != nil {
			return buildAResponse(pkt, qname, h.edgeIP)
		}
		return nil
	}

	// 判定是否属于第一阶段漏斗：.cn 顶级域或分流规则判定的纯国内直连域名
	isChina := strings.HasSuffix(qnameLower, ".cn") || qnameLower == "cn"
	if !isChina && h.split != nil {
		isChina = h.split.Decide(qnameLower) == "direct"
	}

	if isChina {
		// 第一阶段：.cn 直连 & 丢弃 AAAA
		if qtype == 0x001C { // AAAA
			return buildEmptyResponse(pkt, qname, qtype)
		}
		// A 记录走直连物理 DNS
		return h.queryFastUDP(pkt)
	}

	// 第二阶段：其余境外站/非直连域名
	// 绝对不进入 queryFastUDP！杜绝 DNS 泄露
	if qtype == 0x001C { // AAAA 纯净空应答
		return buildEmptyResponse(pkt, qname, qtype)
	}

	// A 记录：优先尝试 DoH 解析 (POST /dns-query)
	if h.dohResolver != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
		respBytes, err := h.dohResolver(ctx, pkt)
		cancel()
		if err == nil && len(respBytes) >= 12 {
			if len(pkt) >= 2 {
				respBytes[0], respBytes[1] = pkt[0], pkt[1]
			}
			return respBytes
		}
	}

	// 其次尝试隧道内短流解析 (StreamType_CONTROL)
	if h.tunnelResolver != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
		realIP, err := h.tunnelResolver(ctx, qnameLower)
		cancel()
		if err == nil && realIP != nil && realIP.To4() != nil {
			return buildAResponse(pkt, qname, realIP)
		}
	}

	// 隧道未建连、超时或解析失败：0ms 下发 198.18 Fake-IP
	if h.fakeIP != nil {
		resp := h.fakeIP.FormatDNSResponse(qname)
		if len(pkt) >= 2 && len(resp) >= 2 {
			resp[0], resp[1] = pkt[0], pkt[1]
		}
		return resp
	}

	return nil
}

// queryFastUDP 仅用于 .cn 及国内直连域名向物理解析器发包
func (h *DNSHandler) queryFastUDP(pkt []byte) []byte {
	server := h.physicalDNS
	if server == "" {
		server = "223.5.5.5:53"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()

	var conn net.Conn
	var err error
	if h.physicalDialer != nil {
		conn, err = h.physicalDialer(ctx, "udp", server)
	} else {
		conn, err = DialPhysicalDirect(ctx, "udp", server)
	}
	if err != nil {
		return nil
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(1200 * time.Millisecond))
	if _, err := conn.Write(pkt); err != nil {
		return nil
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil || n <= 12 {
		return nil
	}
	return buf[:n]
}

func isLocalOrSystemDomain(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" || h == "localhost" || strings.HasSuffix(h, ".local") || strings.HasSuffix(h, ".lan") ||
		strings.HasSuffix(h, ".internal") || strings.HasSuffix(h, ".home.arpa") ||
		strings.HasSuffix(h, "msftconnecttest.com") || strings.HasSuffix(h, "msftncsi.com") ||
		strings.HasSuffix(h, "ipv6.msftncsi.com") || strings.HasSuffix(h, "captive.apple.com") ||
		strings.HasSuffix(h, "connectivitycheck.gstatic.com") {
		return true
	}
	return false
}

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
		return string(name), 0x0001
	}
	qtype := binary.BigEndian.Uint16(pkt[offset : offset+2])
	return string(name), qtype
}

func buildAResponse(req []byte, host string, ip net.IP) []byte {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}
	resp := []byte{
		0x00, 0x00,
		0x81, 0x80, // Flags: Standard response, no error
		0x00, 0x01, // Questions: 1
		0x00, 0x01, // Answers: 1
		0x00, 0x00, // Authority: 0
		0x00, 0x00, // Additional: 0
	}
	if len(req) >= 2 {
		resp[0], resp[1] = req[0], req[1]
	}
	resp = append(resp, encodeDNSName(host)...)
	resp = append(resp, 0x00, 0x01) // Type A
	resp = append(resp, 0x00, 0x01) // Class IN

	resp = append(resp, 0xC0, 0x0C)             // Pointer to name
	resp = append(resp, 0x00, 0x01)             // Type A
	resp = append(resp, 0x00, 0x01)             // Class IN
	resp = append(resp, 0x00, 0x00, 0x01, 0x2C) // TTL 300s
	resp = append(resp, 0x00, 0x04)             // Length 4
	resp = append(resp, ip4...)
	return resp
}

func buildEmptyResponse(req []byte, host string, qtype uint16) []byte {
	resp := []byte{
		0x00, 0x00,
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

func encodeDNSName(domain string) []byte {
	var buf []byte
	parts := strings.Split(domain, ".")
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		buf = append(buf, byte(len(part)))
		buf = append(buf, []byte(part)...)
	}
	buf = append(buf, 0x00)
	return buf
}
