// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"container/list"
	"encoding/binary"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// 流量分类（ADR-0017 决定 4）：IP 包里没有域名，所以由 DNS 处理器在应答 AI 域名时登记“地址 → 过期时间”，
// 数据面按目的地址判断一条 TCP 流走哪个会话。分类错误只影响传输方式，不影响出口与安全属性。
//
//   - UDP、ICMP、其他协议：始终走 default 会话（QUIC/HTTP3 自带重传，放进可靠流是两层重传）；
//   - TCP：建立时按目的地址决定，之后整条流固定在这个会话上（两个会话的源地址不同，中途换会话会断流）。

type flowClass uint8

const (
	flowDefault flowClass = iota // default 会话（数据报）
	flowAI                       // ai 会话（DATAGRAM capsule）
)

const (
	// aiMinLinger：地址登记至少保留这么久，应用常在 DNS TTL 过期后继续使用同一地址（估算，待实测）。
	aiMinLinger = 5 * time.Minute
	// aiAddrMax 与 tcpFlowMax：条数上限（L0 §9.2），防止异常应答或扫描撑爆内存（估算，待实测）。
	aiAddrMax  = 8192
	tcpFlowMax = 65536
	// tcpFlowIdle：TCP 流空闲多久后从流表删除（估算，待实测）。
	tcpFlowIdle = 15 * time.Minute
)

// ---- AI 地址集合 ----

// aiAddrSet 是 AI 域名解析到的 IPv4 地址集合。线程安全。
type aiAddrSet struct {
	mu  sync.Mutex
	m   map[netip.Addr]time.Time
	max int
	now func() time.Time
}

func newAIAddrSet() *aiAddrSet {
	return &aiAddrSet{m: make(map[netip.Addr]time.Time), max: aiAddrMax, now: time.Now}
}

// Add 登记 addr，保留 max(ttl, aiMinLinger)。只接受公网单播 IPv4；同一地址再次登记只会延长。
func (s *aiAddrSet) Add(addr netip.Addr, ttl time.Duration) {
	addr = addr.Unmap()
	if !addr.Is4() || !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() {
		return
	}
	if ttl < aiMinLinger {
		ttl = aiMinLinger
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	until := now.Add(ttl)
	if old, ok := s.m[addr]; ok {
		if until.After(old) {
			s.m[addr] = until
		}
		return
	}
	if len(s.m) >= s.max {
		for a, t := range s.m {
			if !t.After(now) {
				delete(s.m, a)
			}
		}
		if len(s.m) >= s.max { // 仍然满：淘汰最早过期的一个
			var oldest netip.Addr
			var oldestT time.Time
			first := true
			for a, t := range s.m {
				if first || t.Before(oldestT) {
					oldest, oldestT, first = a, t, false
				}
			}
			delete(s.m, oldest)
		}
	}
	s.m[addr] = until
}

// Contains 报告 addr 是否在集合内且未过期。
func (s *aiAddrSet) Contains(addr netip.Addr) bool {
	addr = addr.Unmap()
	s.mu.Lock()
	defer s.mu.Unlock()
	until, ok := s.m[addr]
	if !ok {
		return false
	}
	if !until.After(s.now()) {
		delete(s.m, addr)
		return false
	}
	return true
}

// Len 返回登记的地址数（含已过期未清理的）。
func (s *aiAddrSet) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}

// dnsAnswerIPv4s 返回 NOERROR 应答里所有 A 记录的地址与最小 TTL（含 CNAME 链末端的 A 记录）。
func dnsAnswerIPv4s(resp []byte) (addrs []netip.Addr, ttl time.Duration, ok bool) {
	if len(resp) < 12 || resp[2]&0x80 == 0 || resp[3]&0x0F != 0 {
		return nil, 0, false
	}
	qd := int(binary.BigEndian.Uint16(resp[4:6]))
	an := int(binary.BigEndian.Uint16(resp[6:8]))
	off := 12
	for i := 0; i < qd; i++ {
		var good bool
		if off, good = skipDNSName(resp, off); !good {
			return nil, 0, false
		}
		off += 4
		if off > len(resp) {
			return nil, 0, false
		}
	}
	minTTL := uint32(0)
	for i := 0; i < an; i++ {
		var good bool
		if off, good = skipDNSName(resp, off); !good || off+10 > len(resp) {
			return nil, 0, false
		}
		rtype := binary.BigEndian.Uint16(resp[off : off+2])
		rclass := binary.BigEndian.Uint16(resp[off+2 : off+4])
		rttl := binary.BigEndian.Uint32(resp[off+4 : off+8])
		rdlen := int(binary.BigEndian.Uint16(resp[off+8 : off+10]))
		off += 10
		if off+rdlen > len(resp) {
			return nil, 0, false
		}
		if rtype == 1 && rclass == 1 && rdlen == 4 {
			addrs = append(addrs, netip.AddrFrom4([4]byte(resp[off:off+4])))
			if len(addrs) == 1 || rttl < minTTL {
				minTTL = rttl
			}
		}
		off += rdlen
	}
	if len(addrs) == 0 {
		return nil, 0, false
	}
	return addrs, time.Duration(minTTL) * time.Second, true
}

// ---- TCP 流表 ----

type tcpFlowKey struct {
	dst          netip.Addr
	dport, sport uint16 // 源地址始终是 TUN 地址，不进键
}

type tcpFlowEntry struct {
	key   tcpFlowKey
	class flowClass
	last  time.Time
}

// tcpFlowTable 记录每条 TCP 流选定的会话：最近最少使用淘汰，空闲超时删除。线程安全。
type tcpFlowTable struct {
	mu      sync.Mutex
	m       map[tcpFlowKey]*list.Element
	ll      *list.List // 前端最近使用
	max     int
	idle    time.Duration
	now     func() time.Time
	evicted atomic.Uint64 // 因表满被淘汰的、仍在有效期内的流数（诊断用）
}

func newTCPFlowTable() *tcpFlowTable {
	return &tcpFlowTable{m: make(map[tcpFlowKey]*list.Element), ll: list.New(), max: tcpFlowMax, idle: tcpFlowIdle, now: time.Now}
}

func (t *tcpFlowTable) lookup(k tcpFlowKey) (flowClass, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	el, ok := t.m[k]
	if !ok {
		return flowDefault, false
	}
	e := el.Value.(*tcpFlowEntry)
	now := t.now()
	if now.Sub(e.last) > t.idle {
		t.ll.Remove(el)
		delete(t.m, k)
		return flowDefault, false
	}
	e.last = now
	t.ll.MoveToFront(el)
	return e.class, true
}

func (t *tcpFlowTable) set(k tcpFlowKey, c flowClass) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	if el, ok := t.m[k]; ok {
		e := el.Value.(*tcpFlowEntry)
		e.class, e.last = c, now
		t.ll.MoveToFront(el)
		return
	}
	for t.ll.Len() >= t.max {
		back := t.ll.Back()
		if back == nil {
			break
		}
		e := back.Value.(*tcpFlowEntry)
		if now.Sub(e.last) <= t.idle {
			t.evicted.Add(1)
		}
		t.ll.Remove(back)
		delete(t.m, e.key)
	}
	t.m[k] = t.ll.PushFront(&tcpFlowEntry{key: k, class: c, last: now})
}

func (t *tcpFlowTable) remove(k tcpFlowKey) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if el, ok := t.m[k]; ok {
		t.ll.Remove(el)
		delete(t.m, k)
	}
}

func (t *tcpFlowTable) len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ll.Len()
}

// ---- 分类器 ----

// flowClassifier 决定每个上行 IPv4 包走哪个会话。线程安全；ai 集合由 DNS 处理器填充。
type flowClassifier struct {
	ai      *aiAddrSet
	flows   *tcpFlowTable
	enabled atomic.Bool // 用户关闭“AI 稳定通道”时为 false：一切走 default
}

func newFlowClassifier() *flowClassifier {
	c := &flowClassifier{ai: newAIAddrSet(), flows: newTCPFlowTable()}
	c.enabled.Store(true)
	return c
}

// classify 返回 pkt 应走的会话；newTCP 表示这是一个纯 SYN（新连接的第一个包）。
// 不是 IPv4 TCP 的一律 default，且不产生任何状态。
func (c *flowClassifier) classify(pkt []byte) (class flowClass, newTCP bool) {
	if !c.enabled.Load() {
		return flowDefault, false
	}
	ihl := ipv4Header(pkt)
	if ihl == 0 || pkt[9] != 6 {
		return flowDefault, false
	}
	dst := netip.AddrFrom4([4]byte(pkt[16:20]))
	if binary.BigEndian.Uint16(pkt[6:8])&0x3fff != 0 {
		// 任何分片（MF 置位或偏移非 0）一律 default 且不记录：非首片没有端口，首片若走 ai 而后续分片走 default，
		// 同一个报文会被拆到两条会话上无法重组。分片的 TCP 极少见。
		return flowDefault, false
	}
	if int(binary.BigEndian.Uint16(pkt[2:4])) < ihl+14 { // 总长度（ipv4Header 已保证不超过 len(pkt)）
		return flowDefault, false
	}
	key := tcpFlowKey{dst: dst, sport: binary.BigEndian.Uint16(pkt[ihl : ihl+2]), dport: binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])}
	flags := pkt[ihl+13]
	syn := flags&0x02 != 0 && flags&0x10 == 0
	if !syn {
		if cl, ok := c.flows.lookup(key); ok {
			if flags&0x04 != 0 { // RST：这条流结束
				c.flows.remove(key)
			}
			return cl, false
		}
	}
	if !syn {
		// 表里没有这条流的中途包（用户刚打开通道、条目过期或被淘汰）：永远走 default，不记录。
		// 只有纯 SYN 才能开始一条 ai 流；否则一条已经在 default 上的连接会因源地址突变而断流。
		return flowDefault, false
	}
	// 新连接（纯 SYN，也覆盖源端口复用）：按目的地址决定并记录。
	cl := flowDefault
	if c.ai.Contains(dst) {
		cl = flowAI
	}
	c.flows.set(key, cl)
	return cl, true
}
