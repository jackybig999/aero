// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
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

// DefaultFakeIPTable 全局 Fake-IP 表
var DefaultFakeIPTable = NewFakeIPTable("198.18.0.0/15")

// DNS 应答缓存参数：条目上限、TTL 钳制范围（取应答答案记录的最小 TTL）。
const (
	dnsCacheMaxEntries = 4096
	dnsCacheMinTTL     = 30 * time.Second
	dnsCacheMaxTTL     = 10 * time.Minute
	dnsCacheEvictProbe = 8 // 满时抽样淘汰：随机抽取若干条，淘汰最早过期者
)

type dnsCacheKey struct {
	name  string // 小写域名
	qtype uint16
}

// dnsCacheEntry 缓存完整的原始应答（命中时只改写事务 ID）。
type dnsCacheEntry struct {
	data      []byte
	expiresAt time.Time
}

// TunnelDNSResolver 隧道短流 DNS 解析函数类型
type TunnelDNSResolver func(ctx context.Context, domain string) (net.IP, error)

// DoHResolver DoH 解析函数类型 (POST /dns-query)
type DoHResolver func(ctx context.Context, dnsReq []byte) ([]byte, error)

// DNSHandler 两级 DNS 漏斗处理器
//
// 并发：Set* 方法在运行中可能被调用（切换节点、网络变化），HandleQuery 在 DNS 协程里并发读取，
// 因此配置字段统一由 cfgMu 保护，HandleQuery 每次入口取一份快照；缓存由 cacheMu 保护。
type DNSHandler struct {
	split *SplitEngine

	cfgMu          sync.RWMutex
	fakeIP         *FakeIPTable
	edgeHost       string
	edgeIP         net.IP
	tunnelResolver TunnelDNSResolver
	dohResolver    DoHResolver
	physicalDNS    string
	physicalDialer func(ctx context.Context, network, addr string) (net.Conn, error)

	// ipv6Available 为 true 表示 TUN 有可用的 IPv6 路由，此时 AAAA 才原样走 DoH；
	// 默认 false（客户端 TUN 不配内层 IPv6），AAAA 返回空 NOERROR 应答，应用直接用 IPv4。
	ipv6Available atomic.Bool

	cacheMu sync.Mutex
	cache   map[dnsCacheKey]dnsCacheEntry
}

// dnsConfig 是 HandleQuery 入口取得的配置快照。
type dnsConfig struct {
	edgeHost       string
	edgeIP         net.IP
	dohResolver    DoHResolver
	physicalDNS    string
	physicalDialer func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (h *DNSHandler) snapshot() dnsConfig {
	h.cfgMu.RLock()
	defer h.cfgMu.RUnlock()
	return dnsConfig{
		edgeHost:       h.edgeHost,
		edgeIP:         h.edgeIP,
		dohResolver:    h.dohResolver,
		physicalDNS:    h.physicalDNS,
		physicalDialer: h.physicalDialer,
	}
}

// NewDNSHandler 创建 DNS 处理器
func NewDNSHandler(split *SplitEngine) *DNSHandler {
	return &DNSHandler{
		fakeIP:      DefaultFakeIPTable,
		split:       split,
		physicalDNS: "223.5.5.5:53",
		cache:       make(map[dnsCacheKey]dnsCacheEntry),
	}
}

// FakeIP 获取绑定的 Fake-IP 表
func (h *DNSHandler) FakeIP() *FakeIPTable {
	if h == nil {
		return nil
	}
	h.cfgMu.RLock()
	defer h.cfgMu.RUnlock()
	return h.fakeIP
}

// SetFakeIP 绑定 Fake-IP 表
func (h *DNSHandler) SetFakeIP(t *FakeIPTable) {
	h.cfgMu.Lock()
	h.fakeIP = t
	h.cfgMu.Unlock()
}

// SetEdge 绑定当前节点域名与 IP（host 与 ip 在同一把锁内一起更新，读取方不会看到新旧混合）
func (h *DNSHandler) SetEdge(host string, ip net.IP) {
	host = strings.ToLower(strings.TrimSpace(host))
	var ipCopy net.IP
	if ip != nil {
		ipCopy = append(net.IP(nil), ip...)
	}
	h.cfgMu.Lock()
	h.edgeHost = host
	h.edgeIP = ipCopy
	h.cfgMu.Unlock()
}

// SetTunnelResolver 绑定隧道内短流解析器
func (h *DNSHandler) SetTunnelResolver(resolver TunnelDNSResolver) {
	h.cfgMu.Lock()
	h.tunnelResolver = resolver
	h.cfgMu.Unlock()
}

// SetDoHResolver 绑定 HTTP/3 DoH 解析器
func (h *DNSHandler) SetDoHResolver(resolver DoHResolver) {
	h.cfgMu.Lock()
	h.dohResolver = resolver
	h.cfgMu.Unlock()
}

// SetPhysicalDNS 设置物理直连 DNS 地址
func (h *DNSHandler) SetPhysicalDNS(addr string) {
	if addr != "" {
		if !strings.Contains(addr, ":") {
			addr = addr + ":53"
		}
		h.cfgMu.Lock()
		h.physicalDNS = addr
		h.cfgMu.Unlock()
	}
}

// SetPhysicalDialer 允许在测试中注入物理 DNS 拨号器 (如内存通道)
func (h *DNSHandler) SetPhysicalDialer(dialer func(ctx context.Context, network, addr string) (net.Conn, error)) {
	h.cfgMu.Lock()
	h.physicalDialer = dialer
	h.cfgMu.Unlock()
}

// SetIPv6Available 声明 TUN 是否有可用的 IPv6 路由。为 false（默认）时，经 DoH 解析的域名收到 AAAA 查询
// 一律返回空 NOERROR 应答，避免应用尝试走不通的 IPv6；为 true 时 AAAA 与其他类型一样原样转发。
func (h *DNSHandler) SetIPv6Available(ok bool) {
	h.ipv6Available.Store(ok)
}

// Flush 清空应答缓存。切换节点、网络变化后由 engine 调用，避免沿用旧出口/旧网络下解析出的结果。
func (h *DNSHandler) Flush() {
	h.cacheMu.Lock()
	h.cache = make(map[dnsCacheKey]dnsCacheEntry)
	h.cacheMu.Unlock()
}

// DNS 记录类型
const (
	dnsTypeA     = 0x0001
	dnsTypeAAAA  = 0x001C
	dnsTypeHTTPS = 0x0041
)

// HandleQuery 两级 DNS 漏斗核心入口：
// 阶段 1：.cn 与直连规则域名走物理 DNS（AAAA、HTTPS 返回空应答）；
// 阶段 2：AI 与其余非直连域名经 DoH 由 edge 原样转发，所有记录类型一视同仁，客户端只改回事务 ID；
// TUN 没有 IPv6 路由时 AAAA 返回空 NOERROR 应答；上游失败返回 SERVFAIL
func (h *DNSHandler) HandleQuery(pkt []byte, srcIP net.IP, srcPort uint16) []byte {
	qname, qtype := extractDNSQuestionAndType(pkt)
	if qname == "" {
		return nil
	}
	qnameLower := strings.ToLower(qname)
	cfg := h.snapshot()

	// 本地保留域：直接返回标准空应答，绝不黑洞丢弃导致系统 DNS 挂起超时
	if isLocalDomain(qnameLower) {
		return buildEmptyResponse(pkt, qname, qtype)
	}

	// 操作系统网络连通性探针放行 (Windows NCSI / Apple Captive / Android Probe)
	// A 记录走直连物理 DNS 快速校验，AAAA 记录返回纯净空应答
	if isSystemProbeDomain(qnameLower) {
		if qtype == dnsTypeAAAA {
			return buildEmptyResponse(pkt, qname, qtype)
		}
		return h.queryFastUDP(pkt)
	}

	// 节点自身域名：A 返回真实 IP；AAAA 立即返回空响应，防止操作系统解析器超时死等；
	// 其他类型返回空 NOERROR 应答（不能把 A 记录塞进非 A 问题的应答里）
	if cfg.edgeHost != "" && (qnameLower == cfg.edgeHost || strings.HasSuffix(qnameLower, "."+cfg.edgeHost)) {
		if qtype != dnsTypeA {
			return buildEmptyResponse(pkt, qname, qtype)
		}
		if cfg.edgeIP != nil {
			return buildAResponse(pkt, qname, cfg.edgeIP)
		}
		return nil
	}

	// TUN 无 IPv6 路由：AAAA 空 NOERROR 应答（直连与 DoH 路径一致），应用直接用 IPv4
	if qtype == dnsTypeAAAA && !h.ipv6Available.Load() {
		return buildEmptyResponse(pkt, qname, qtype)
	}

	// 命中本地 DNS 缓存：0ms 极速响应，消灭重复解析网络延迟（缓存的是 DoH 返回的完整应答）
	if resp := h.cacheGet(qnameLower, qtype, pkt); resp != nil {
		return resp
	}

	// 阶段一：AI 优先通道（走真·DoH 远程解析获取真实公网 IP，彻底消灭纯三层黑洞）
	if h.split != nil && h.split.Decide(qnameLower) == "ai" {
		return h.resolveViaDoH(cfg, pkt, qname, qnameLower, qtype)
	}

	// 阶段二：.cn 顶级域或分流规则判定的纯国内直连域名走直连物理 DNS
	isDirect := strings.HasSuffix(qnameLower, ".cn") || qnameLower == "cn"
	if !isDirect && h.split != nil {
		isDirect = h.split.Decide(qnameLower) == "direct"
	}

	if isDirect {
		// Type 65 HTTPS RR 零时延空应答，消灭 Edge/Chrome 浏览器等待超时
		if qtype == dnsTypeHTTPS {
			return buildEmptyResponse(pkt, qname, qtype)
		}
		// .cn 直连 & 丢弃 AAAA
		if qtype == dnsTypeAAAA {
			return buildEmptyResponse(pkt, qname, qtype)
		}
		// 其余类型走直连物理 DNS
		dnsResp := h.queryFastUDP(pkt)
		if dnsResp != nil {
			return dnsResp
		}
		// 物理 DNS 超时/失败：SERVFAIL，由系统解析器重试
		return buildServFailResponse(pkt, qname, qtype)
	}

	// 阶段三：境外站/非直连域名
	// 绝对不进入 queryFastUDP (严格防止 DNS 泄露 SEC-11)！所有记录类型（A、AAAA、HTTPS、TXT、MX、SRV、PTR…）
	// 都经 DoH 由 edge 原样转发（api/dataplane.md §6）。
	return h.resolveViaDoH(cfg, pkt, qname, qnameLower, qtype)
}

// resolveViaDoH 经 DoH 解析并原样返回；没有 DoH 或上游失败时返回 SERVFAIL，
// 不返回假 IP（CONNECT-IP 数据面无法翻译假 IP，只会黑洞）。
func (h *DNSHandler) resolveViaDoH(cfg dnsConfig, pkt []byte, qname, qnameLower string, qtype uint16) []byte {
	if cfg.dohResolver != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
		resp := h.queryDoH(ctx, cfg.dohResolver, pkt, qnameLower, qtype)
		cancel()
		if resp != nil {
			return resp
		}
	}
	return buildServFailResponse(pkt, qname, qtype)
}

// queryDoH 把查询报文原样交给 DoH，应答只改回事务 ID；符合条件的应答写入缓存。
func (h *DNSHandler) queryDoH(ctx context.Context, doh DoHResolver, pkt []byte, qnameLower string, qtype uint16) []byte {
	if doh == nil {
		return nil
	}
	resp, err := doh(ctx, pkt)
	if err == nil && len(resp) < 12 {
		err = fmt.Errorf("short DoH response (%d bytes)", len(resp))
	}
	if err != nil {
		logDoHFailure(err)
		return nil
	}
	// 不改动调用方返回的切片：复制后再改事务 ID
	resp = append([]byte(nil), resp...)
	if len(pkt) >= 2 {
		resp[0], resp[1] = pkt[0], pkt[1]
	}
	if ttl, ok := dnsAnswerMinTTL(resp); ok {
		h.cachePut(qnameLower, qtype, resp, ttl)
	}
	return resp
}

// cacheGet 命中时返回缓存的完整应答副本，事务 ID 改写为本次查询的 ID。
func (h *DNSHandler) cacheGet(qnameLower string, qtype uint16, pkt []byte) []byte {
	key := dnsCacheKey{qnameLower, qtype}
	h.cacheMu.Lock()
	defer h.cacheMu.Unlock()
	entry, ok := h.cache[key]
	if !ok {
		return nil
	}
	if !time.Now().Before(entry.expiresAt) {
		delete(h.cache, key)
		return nil
	}
	resp := append([]byte(nil), entry.data...)
	if len(pkt) >= 2 {
		resp[0], resp[1] = pkt[0], pkt[1]
	}
	return resp
}

// cachePut 写入缓存。TTL 取答案记录最小 TTL，钳在 [dnsCacheMinTTL, dnsCacheMaxTTL]；
// 条目数达到上限时抽样淘汰最早过期者（均摊 O(1)）。
func (h *DNSHandler) cachePut(qnameLower string, qtype uint16, resp []byte, ttl time.Duration) {
	if ttl < dnsCacheMinTTL {
		ttl = dnsCacheMinTTL
	}
	if ttl > dnsCacheMaxTTL {
		ttl = dnsCacheMaxTTL
	}
	key := dnsCacheKey{qnameLower, qtype}
	now := time.Now()
	h.cacheMu.Lock()
	defer h.cacheMu.Unlock()
	if h.cache == nil {
		h.cache = make(map[dnsCacheKey]dnsCacheEntry)
	}
	if _, exists := h.cache[key]; !exists && len(h.cache) >= dnsCacheMaxEntries {
		var victim dnsCacheKey
		var victimExp time.Time
		n := 0
		for k, e := range h.cache { // Go map 遍历起点随机，取前几条作为随机样本
			if n == 0 || e.expiresAt.Before(victimExp) {
				victim, victimExp = k, e.expiresAt
			}
			if n++; n >= dnsCacheEvictProbe || !now.Before(e.expiresAt) {
				break
			}
		}
		delete(h.cache, victim)
	}
	h.cache[key] = dnsCacheEntry{data: append([]byte(nil), resp...), expiresAt: now.Add(ttl)}
}

// dnsAnswerMinTTL 返回 NOERROR、未截断、含答案的应答中答案记录的最小 TTL。
// 无答案（NODATA/NXDOMAIN）、截断、报文畸形时返回 false（不缓存）。
func dnsAnswerMinTTL(resp []byte) (time.Duration, bool) {
	if len(resp) < 12 || resp[2]&0x80 == 0 || resp[2]&0x02 != 0 || resp[3]&0x0F != 0 {
		return 0, false
	}
	qdcount := int(binary.BigEndian.Uint16(resp[4:6]))
	ancount := int(binary.BigEndian.Uint16(resp[6:8]))
	if ancount == 0 {
		return 0, false
	}
	offset := 12
	for i := 0; i < qdcount; i++ {
		var ok bool
		if offset, ok = skipDNSName(resp, offset); !ok {
			return 0, false
		}
		offset += 4
		if offset > len(resp) {
			return 0, false
		}
	}
	minTTL := uint32(0)
	for i := 0; i < ancount; i++ {
		var ok bool
		if offset, ok = skipDNSName(resp, offset); !ok || offset+10 > len(resp) {
			return 0, false
		}
		ttl := binary.BigEndian.Uint32(resp[offset+4 : offset+8])
		rdlen := int(binary.BigEndian.Uint16(resp[offset+8 : offset+10]))
		offset += 10
		if offset+rdlen > len(resp) {
			return 0, false
		}
		offset += rdlen
		if i == 0 || ttl < minTTL {
			minTTL = ttl
		}
	}
	return time.Duration(minTTL) * time.Second, true
}

// DoH 失败日志限速：首次立即记录，之后每 30 秒最多一条，并带上期间被抑制的次数。
var dohFailLog struct {
	mu         sync.Mutex
	last       time.Time
	suppressed int
}

func logDoHFailure(err error) { // 不记录域名（访问记录属于隐私）
	dohFailLog.mu.Lock()
	defer dohFailLog.mu.Unlock()
	if !dohFailLog.last.IsZero() && time.Since(dohFailLog.last) < 30*time.Second {
		dohFailLog.suppressed++
		return
	}
	log.Printf("[DNS] DoH query failed: %v (%d similar failures suppressed)", err, dohFailLog.suppressed)
	dohFailLog.last, dohFailLog.suppressed = time.Now(), 0
}

// parseFirstIPv4FromDNSResponse 按 RFC 1035 标准解析 DNS 应答中的首个 A 记录
// 健壮处理普通标签、0xC0 压缩指针、CNAME 别名链，安全忽略 EDNS0 OPT 伪记录，100% 防越界与死循环
func parseFirstIPv4FromDNSResponse(resp []byte) net.IP {
	if len(resp) < 12 {
		return nil
	}
	ancount := binary.BigEndian.Uint16(resp[6:8])
	if ancount == 0 {
		return nil
	}
	qdcount := binary.BigEndian.Uint16(resp[4:6])

	offset := 12
	// 安全跳过所有 Question 记录
	for i := 0; i < int(qdcount); i++ {
		var ok bool
		offset, ok = skipDNSName(resp, offset)
		if !ok {
			return nil
		}
		offset += 4 // QTYPE(2) + QCLASS(2)
		if offset > len(resp) {
			return nil
		}
	}

	// 遍历 Answer 记录寻找首个有效 Type A 记录
	for i := 0; i < int(ancount); i++ {
		var ok bool
		offset, ok = skipDNSName(resp, offset)
		if !ok {
			return nil
		}
		if offset+10 > len(resp) {
			return nil
		}
		rtype := binary.BigEndian.Uint16(resp[offset : offset+2])
		rclass := binary.BigEndian.Uint16(resp[offset+2 : offset+4])
		// ttl := binary.BigEndian.Uint32(resp[offset+4 : offset+8])
		rdlen := int(binary.BigEndian.Uint16(resp[offset+8 : offset+10]))
		offset += 10
		if offset+rdlen > len(resp) {
			return nil
		}
		// Type A = 0x0001, Class IN = 0x0001, rdlen = 4
		if rtype == 0x0001 && rclass == 0x0001 && rdlen == 4 {
			ip := make(net.IP, 4)
			copy(ip, resp[offset:offset+4])
			return ip
		}
		offset += rdlen
	}
	return nil
}

// skipDNSName 跳过 DNS 名字区段，支持 RFC 1035 §4.1.4 压缩指针 (0xC0 开头)
func skipDNSName(pkt []byte, offset int) (int, bool) {
	steps := 0
	for offset < len(pkt) && steps < 128 {
		steps++
		b := pkt[offset]
		if b == 0 {
			return offset + 1, true
		}
		if b&0xC0 == 0xC0 { // 压缩指针，占 2 字节
			if offset+2 > len(pkt) {
				return offset, false
			}
			return offset + 2, true
		}
		if b > 63 { // 非法标签长度
			return offset, false
		}
		offset += 1 + int(b)
	}
	return offset, false
}

// queryFastUDP 仅用于 .cn 及国内直连域名向物理解析器发包。
// 只接受事务 ID 与问题段都和查询一致的应答（不一致的继续读直到超时）；应答被截断（TC）时
// 改用 TCP 向同一上游重试一次（同样经物理拨号器）。
func (h *DNSHandler) queryFastUDP(pkt []byte) []byte {
	cfg := h.snapshot()
	server := cfg.physicalDNS
	if server == "" {
		server = "223.5.5.5:53"
	}
	question, ok := dnsQuestionBytes(pkt)
	if !ok {
		return nil
	}

	resp := h.exchangePhysical(cfg, "udp", server, pkt, question, 1200*time.Millisecond)
	if resp == nil {
		return nil
	}
	if resp[2]&0x02 != 0 { // TC：UDP 应答被截断，改走 TCP
		return h.exchangePhysical(cfg, "tcp", server, pkt, question, 1500*time.Millisecond)
	}
	return resp
}

// exchangePhysical 在 network（udp/tcp）上发一次查询并返回通过校验的应答，失败返回 nil。
func (h *DNSHandler) exchangePhysical(cfg dnsConfig, network, server string, pkt, question []byte, timeout time.Duration) []byte {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var conn net.Conn
	var err error
	if cfg.physicalDialer != nil {
		conn, err = cfg.physicalDialer(ctx, network, server)
	} else {
		conn, err = DialPhysicalDirect(ctx, network, server)
	}
	if err != nil {
		return nil
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if network == "tcp" {
		msg := append(binary.BigEndian.AppendUint16(nil, uint16(len(pkt))), pkt...)
		if _, err := conn.Write(msg); err != nil {
			return nil
		}
		var lb [2]byte
		if _, err := io.ReadFull(conn, lb[:]); err != nil {
			return nil
		}
		n := int(binary.BigEndian.Uint16(lb[:]))
		if n <= 12 {
			return nil
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return nil
		}
		if !dnsReplyMatches(buf, pkt, question) {
			return nil
		}
		return buf
	}

	if _, err := conn.Write(pkt); err != nil {
		return nil
	}
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil // 超时或连接错误；期间收到的错配应答已被丢弃
		}
		if n > 12 && dnsReplyMatches(buf[:n], pkt, question) {
			return append([]byte(nil), buf[:n]...)
		}
	}
}

// dnsQuestionBytes 返回查询报文中首个问题段（名字+QTYPE+QCLASS）的原始字节。
func dnsQuestionBytes(pkt []byte) ([]byte, bool) {
	if len(pkt) <= 12 {
		return nil, false
	}
	end, ok := skipDNSName(pkt, 12)
	if !ok || end+4 > len(pkt) {
		return nil, false
	}
	return pkt[12 : end+4], true
}

// dnsReplyMatches 判断 resp 是否为 req 的应答：QR=1、事务 ID 相同、问题段一致（名字大小写不敏感）。
func dnsReplyMatches(resp, req, question []byte) bool {
	if len(resp) < 12+len(question) || resp[2]&0x80 == 0 || resp[0] != req[0] || resp[1] != req[1] {
		return false
	}
	if binary.BigEndian.Uint16(resp[4:6]) != binary.BigEndian.Uint16(req[4:6]) {
		return false
	}
	got := resp[12 : 12+len(question)]
	for i := range question {
		if asciiLower(got[i]) != asciiLower(question[i]) {
			return false
		}
	}
	return true
}

func asciiLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 'a' - 'A'
	}
	return b
}

// hasDomainSuffix 判断 host 等于 domain 或是其子域（按 "." 边界，xxxmsftncsi.com 不算）。
func hasDomainSuffix(host, domain string) bool {
	return host == domain || strings.HasSuffix(host, "."+domain)
}

func isSystemProbeDomain(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	for _, d := range []string{"msftconnecttest.com", "msftncsi.com", "captive.apple.com", "connectivitycheck.gstatic.com"} {
		if hasDomainSuffix(h, d) {
			return true
		}
	}
	return false
}

func isLocalDomain(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	return h == "" || h == "localhost" || strings.HasSuffix(h, ".local") || strings.HasSuffix(h, ".lan") ||
		strings.HasSuffix(h, ".internal") || strings.HasSuffix(h, ".home.arpa")
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

// buildServFailResponse 构造 SERVFAIL（RCODE=2）应答：上游解析失败时使用，
// 让系统解析器重试或让应用快速失败。
func buildServFailResponse(req []byte, host string, qtype uint16) []byte {
	resp := buildEmptyResponse(req, host, qtype)
	if len(req) >= 3 {
		resp[2] = 0x80 | (req[2] & 0x01) // QR=1，回显 RD
	}
	resp[3] = 0x80 | 0x02 // RA=1，RCODE=SERVFAIL
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

// extractFirstIPv4FromResponse 从 DNS wire 响应报文中解析第一条 A 记录的 IPv4 地址
func extractFirstIPv4FromResponse(resp []byte) net.IP {
	return parseFirstIPv4FromDNSResponse(resp)
}
