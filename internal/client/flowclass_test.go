// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"context"
	"encoding/binary"
	"math/rand"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// newTestClassifier 返回“只有 AI 地址走 R”的分类器（等价于 AERO_TCP_RELIABLE=0），旧用例按这个语义写；
// 普通 TCP 也走 R 的行为见 TestClassifyReliable*。
func newTestClassifier() (*flowClassifier, *fakeClock) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	c := newFlowClassifier()
	c.reliableTCP.Store(false)
	c.ai.now = clk.now
	c.flows.now = clk.now
	return c, clk
}

// tcpPacket 构造一个最小的 IPv4 TCP 包（校验和不参与分类，不计算）。
func tcpPacket(src, dst netip.Addr, sport, dport uint16, flags byte) []byte {
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], 40)
	pkt[8], pkt[9] = 64, 6
	s, d := src.As4(), dst.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	binary.BigEndian.PutUint16(pkt[20:22], sport)
	binary.BigEndian.PutUint16(pkt[22:24], dport)
	pkt[20+12] = 0x50
	pkt[20+13] = flags
	return pkt
}

const (
	fSYN = 0x02
	fACK = 0x10
	fRST = 0x04
)

var (
	aiHost    = netip.MustParseAddr("104.18.7.192")
	otherHost = netip.MustParseAddr("151.101.1.69")
)

func TestAIAddrSet(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	s := newAIAddrSet()
	s.now = clk.now

	s.Add(aiHost, 30*time.Second) // TTL 短于最小保留时间：按最小保留时间
	clk.advance(aiMinLinger - time.Second)
	if !s.Contains(aiHost) {
		t.Fatal("entry expired before the minimum linger time")
	}
	clk.advance(2 * time.Second)
	if s.Contains(aiHost) {
		t.Fatal("entry still present after expiry")
	}
	// 长 TTL 优先；重复登记只会延长，不会缩短。
	s.Add(aiHost, time.Hour)
	s.Add(aiHost, time.Second)
	clk.advance(30 * time.Minute)
	if !s.Contains(aiHost) {
		t.Fatal("a later short registration shortened the entry")
	}
	// 只接受公网 IPv4。
	for _, bad := range []string{"10.0.0.1", "127.0.0.1", "0.0.0.0", "192.168.1.1", "169.254.1.1", "224.0.0.1", "2001:db8::1"} {
		s.Add(netip.MustParseAddr(bad), time.Hour)
		if s.Contains(netip.MustParseAddr(bad)) {
			t.Fatalf("%s must not be registered", bad)
		}
	}
	// IPv4-mapped IPv6 视同 IPv4。
	s.Add(netip.MustParseAddr("::ffff:104.18.7.193"), time.Hour)
	if !s.Contains(netip.MustParseAddr("104.18.7.193")) {
		t.Fatal("mapped address not normalized")
	}
}

func TestAIAddrSetCapacity(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	s := newAIAddrSet()
	s.now = clk.now
	s.max = 100
	for i := 0; i < 100; i++ {
		s.Add(netip.AddrFrom4([4]byte{104, 18, byte(i / 250), byte(i%250 + 1)}), time.Duration(i+1)*time.Hour)
	}
	if s.Len() != 100 {
		t.Fatalf("len = %d", s.Len())
	}
	// 满了：过期的先清；没有过期的则淘汰最早过期的那个，总数不超过上限。
	s.Add(netip.MustParseAddr("8.8.8.8"), 999*time.Hour)
	if s.Len() != 100 || !s.Contains(netip.MustParseAddr("8.8.8.8")) {
		t.Fatalf("len=%d contains new=%v", s.Len(), s.Contains(netip.MustParseAddr("8.8.8.8")))
	}
	if s.Contains(netip.AddrFrom4([4]byte{104, 18, 0, 1})) {
		t.Fatal("the entry expiring first should have been evicted")
	}
}

// ---- DNS 应答解析 ----

func dnsResponse(qname string, answers [][]byte) []byte {
	var b []byte
	b = append(b, 0x12, 0x34, 0x81, 0x80, 0, 1, 0, byte(len(answers)), 0, 0, 0, 0)
	for _, label := range splitLabels(qname) {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0, 0, 1, 0, 1)
	for _, a := range answers {
		b = append(b, a...)
	}
	return b
}

func splitLabels(n string) []string {
	var out []string
	cur := ""
	for _, c := range n {
		if c == '.' {
			out = append(out, cur)
			cur = ""
		} else {
			cur += string(c)
		}
	}
	return append(out, cur)
}

// rr 生成一条以压缩指针指向问题名的记录。
func rr(rtype uint16, ttl uint32, rdata []byte) []byte {
	b := []byte{0xc0, 0x0c, byte(rtype >> 8), byte(rtype), 0, 1}
	b = binary.BigEndian.AppendUint32(b, ttl)
	b = binary.BigEndian.AppendUint16(b, uint16(len(rdata)))
	return append(b, rdata...)
}

func TestDNSAnswerIPv4s(t *testing.T) {
	cname := rr(5, 300, []byte{3, 'f', 'o', 'o', 0})
	resp := dnsResponse("api.openai.com", [][]byte{cname, rr(1, 120, []byte{104, 18, 7, 192}), rr(1, 60, []byte{104, 18, 6, 192}), rr(28, 60, make([]byte, 16))})
	addrs, ttl, ok := dnsAnswerIPv4s(resp)
	if !ok || len(addrs) != 2 || addrs[0] != netip.MustParseAddr("104.18.7.192") || addrs[1] != netip.MustParseAddr("104.18.6.192") {
		t.Fatalf("addrs=%v ok=%v", addrs, ok)
	}
	if ttl != 60*time.Second {
		t.Fatalf("ttl = %v, want the minimum 60s", ttl)
	}
	// 无 A 记录、错误应答码、截断、畸形：一律不返回，不 panic。
	if _, _, ok := dnsAnswerIPv4s(dnsResponse("x.com", [][]byte{cname})); ok {
		t.Fatal("answer without A records accepted")
	}
	bad := append([]byte(nil), resp...)
	bad[3] |= 0x03 // NXDOMAIN
	if _, _, ok := dnsAnswerIPv4s(bad); ok {
		t.Fatal("NXDOMAIN accepted")
	}
	for n := 0; n < len(resp); n++ {
		dnsAnswerIPv4s(resp[:n]) // 任意截断都不能 panic
	}
}

func FuzzDNSAnswerIPv4s(f *testing.F) {
	f.Add(dnsResponse("a.b", [][]byte{rr(1, 1, []byte{1, 2, 3, 4})}))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) { dnsAnswerIPv4s(b) })
}

// ---- 分类 ----

func TestClassifyUDPAndICMPAlwaysDefault(t *testing.T) {
	c, _ := newTestClassifier()
	c.ai.Add(aiHost, time.Hour)
	udp := buildIPv4(natTun, aiHost, 17, nil, udpDgram(10, rand.New(rand.NewSource(1))), 0)
	icmp := buildIPv4(natTun, aiHost, 1, nil, []byte{8, 0, 0, 0, 0, 1, 0, 1}, 0)
	for _, p := range [][]byte{udp, icmp} {
		if cl, syn := c.classify(p); cl != flowDefault || syn {
			t.Fatalf("proto %d went to class %d", p[9], cl)
		}
	}
	if c.flows.len() != 0 {
		t.Fatal("non-TCP packets must not create flow state")
	}
}

func TestClassifyTCPPinsFlowForItsLifetime(t *testing.T) {
	c, clk := newTestClassifier()
	// AI 域名还没解析过：连到该地址的连接走 default，并固定。
	syn := tcpPacket(natTun, aiHost, 50000, 443, fSYN)
	if cl, isSYN := c.classify(syn); cl != flowDefault || !isSYN {
		t.Fatalf("before DNS: class=%d syn=%v", cl, isSYN)
	}
	c.ai.Add(aiHost, time.Hour) // 之后才解析到
	if cl, _ := c.classify(tcpPacket(natTun, aiHost, 50000, 443, fACK)); cl != flowDefault {
		t.Fatal("an established flow must not move to the ai session")
	}
	// 新连接（另一个源端口）走 ai。
	if cl, isSYN := c.classify(tcpPacket(natTun, aiHost, 50001, 443, fSYN)); cl != flowAI || !isSYN {
		t.Fatalf("new connection: class=%d syn=%v", cl, isSYN)
	}
	// 登记过期后，仍然活跃的 ai 流继续留在 ai（流表固定）：每 10 分钟有一个包，共 70 分钟，登记（1 小时）已过期。
	for i := 0; i < 7; i++ {
		clk.advance(10 * time.Minute)
		if cl, _ := c.classify(tcpPacket(natTun, aiHost, 50001, 443, fACK)); cl != flowAI {
			t.Fatalf("minute %d: an active ai flow left the ai session", (i+1)*10)
		}
	}
	if c.ai.Contains(aiHost) {
		t.Fatal("test setup: the registration should have expired")
	}
	// 空闲超过 tcpFlowIdle 的流被忘记；之后再来包按当前登记重新决定（登记已过期 → default）。
	clk.advance(tcpFlowIdle + time.Minute)
	if cl, _ := c.classify(tcpPacket(natTun, aiHost, 50001, 443, fACK)); cl != flowDefault {
		t.Fatal("an idle flow should be reclassified from the current registrations")
	}
	// 其他地址走 default。
	if cl, _ := c.classify(tcpPacket(natTun, otherHost, 50002, 443, fSYN)); cl != flowDefault {
		t.Fatal("unregistered destination went to ai")
	}
}

func TestClassifySYNRevisitsPortReuseAndRSTEnds(t *testing.T) {
	c, _ := newTestClassifier()
	k := tcpFlowKey{dst: aiHost, sport: 50010, dport: 443}
	c.classify(tcpPacket(natTun, aiHost, 50010, 443, fSYN)) // default
	c.ai.Add(aiHost, time.Hour)
	// 同一个源端口再次发纯 SYN（端口复用，新连接）：重新决定。
	if cl, _ := c.classify(tcpPacket(natTun, aiHost, 50010, 443, fSYN)); cl != flowAI {
		t.Fatal("a fresh SYN on a reused port must be classified again")
	}
	// SYN+ACK 位组合不算“新连接”（ACK 置位）；RST 结束并删除流表项。
	if cl, _ := c.classify(tcpPacket(natTun, aiHost, 50010, 443, fRST)); cl != flowAI {
		t.Fatal("RST must still use the flow's session")
	}
	if _, _, ok := c.flows.lookup(k); ok {
		t.Fatal("RST did not end the flow")
	}
}

func TestClassifyDisabledAndMalformed(t *testing.T) {
	c, _ := newTestClassifier()
	c.ai.Add(aiHost, time.Hour)
	c.enabled.Store(false)
	if cl, _ := c.classify(tcpPacket(natTun, aiHost, 50020, 443, fSYN)); cl != flowDefault {
		t.Fatal("disabled classifier must send everything to default")
	}
	if c.flows.len() != 0 {
		t.Fatal("disabled classifier recorded state")
	}
	c.enabled.Store(true)
	for _, bad := range [][]byte{nil, {0x45}, make([]byte, 30), {0x60, 0, 0, 0}, tcpPacket(natTun, aiHost, 1, 2, fSYN)[:30]} {
		if cl, syn := c.classify(bad); cl != flowDefault || syn {
			t.Fatalf("malformed packet %x classified as %d", bad, cl)
		}
	}
	// 任何分片（非首片、带 MF 的首片）一律 default，不记录状态；否则同一个报文会被拆到两条会话上。
	before := c.flows.len()
	for _, fragField := range []uint16{100, 0x2000, 0x2064} { // 非首片、首片(MF)、中间片
		frag := tcpPacket(natTun, aiHost, 50300, 443, fSYN)
		binary.BigEndian.PutUint16(frag[6:8], fragField)
		if cl, syn := c.classify(frag); cl != flowDefault || syn || c.flows.len() != before {
			t.Fatalf("fragment field %#x: class=%d syn=%v", fragField, cl, syn)
		}
	}
}

// 只有纯 SYN 才能开始一条 ai 流：没有流表项的中途包永远走 default 且不记录，
// 否则一条已经在 default 上的连接会因源地址突变而断流（用户刚打开通道、条目过期或被淘汰时）。
func TestClassifyMidFlowPacketsNeverJoinAI(t *testing.T) {
	c, _ := newTestClassifier()
	c.ai.Add(aiHost, time.Hour)
	for _, flags := range []byte{fACK, fACK | 0x08, 0x01 | fACK, fRST} { // ACK、PSH+ACK、FIN+ACK、RST
		before := c.flows.len()
		if cl, syn := c.classify(tcpPacket(natTun, aiHost, 50400, 443, flags)); cl != flowDefault || syn {
			t.Fatalf("flags %02x: class=%d syn=%v", flags, cl, syn)
		}
		if c.flows.len() != before {
			t.Fatalf("flags %02x: a mid-flow packet created flow state", flags)
		}
	}
	// 通道从关闭到打开：关闭期间建立的连接继续留在 default，新连接才走 ai。
	c.enabled.Store(false)
	c.classify(tcpPacket(natTun, aiHost, 50401, 443, fSYN))
	c.enabled.Store(true)
	if cl, _ := c.classify(tcpPacket(natTun, aiHost, 50401, 443, fACK)); cl != flowDefault {
		t.Fatal("a connection that started while the channel was off moved to ai after enabling")
	}
	if cl, _ := c.classify(tcpPacket(natTun, aiHost, 50402, 443, fSYN)); cl != flowAI {
		t.Fatal("a new connection after enabling should use ai")
	}
}

func TestTCPFlowTableIdleAndCapacity(t *testing.T) {
	c, clk := newTestClassifier()
	c.flows.max = 50
	c.ai.Add(aiHost, 100*time.Hour)
	for i := 0; i < 50; i++ {
		c.classify(tcpPacket(natTun, aiHost, uint16(40000+i), 443, fSYN))
	}
	if c.flows.len() != 50 {
		t.Fatalf("len = %d", c.flows.len())
	}
	c.classify(tcpPacket(natTun, aiHost, 41000, 443, fSYN)) // 第 51 条：淘汰最久未用的
	if c.flows.len() != 50 || c.flows.evicted.Load() != 1 {
		t.Fatalf("len=%d evicted=%d", c.flows.len(), c.flows.evicted.Load())
	}
	// 空闲超时：条目被视为不存在。
	clk.advance(tcpFlowIdle + time.Second)
	if _, _, ok := c.flows.lookup(tcpFlowKey{dst: aiHost, sport: 41000, dport: 443}); ok {
		t.Fatal("idle entry not expired")
	}
}

func TestClassifierConcurrent(t *testing.T) {
	c, _ := newTestClassifier()
	c.ai.Add(aiHost, time.Hour)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				c.classify(tcpPacket(natTun, aiHost, uint16(30000+g*100+i%100), 443, fSYN))
				c.classify(tcpPacket(natTun, otherHost, uint16(30000+g*100+i%100), 443, fACK))
				c.ai.Add(aiHost, time.Minute)
			}
		}(g)
	}
	wg.Wait()
}

// ---- DNS 处理器登记回调 ----

func TestDNSHandlerRecordsAIAnswers(t *testing.T) {
	split := NewSplitEngine()
	h := NewDNSHandler(split)
	var mu sync.Mutex
	got := map[netip.Addr]time.Duration{}
	h.SetAIRecorder(func(addrs []netip.Addr, ttl time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		for _, a := range addrs {
			got[a] = ttl
		}
	})
	calls := 0
	h.SetDoHResolver(func(ctx context.Context, req []byte) ([]byte, error) {
		calls++
		qname, _ := extractDNSQuestionAndType(req)
		return buildAResponse(req, qname, net.ParseIP("104.18.7.192").To4()), nil
	})
	ai := netip.MustParseAddr("104.18.7.192")

	// AI 域名的 A 查询：登记。
	if resp := h.HandleQuery(buildDNSQuery("api.openai.com", dnsTypeA), net.ParseIP("10.88.0.2"), 5000); resp == nil {
		t.Fatal("nil response")
	}
	mu.Lock()
	_, recorded := got[ai]
	mu.Unlock()
	if !recorded {
		t.Fatal("AI answer not recorded")
	}
	// 缓存命中也要续期登记。
	mu.Lock()
	delete(got, ai)
	mu.Unlock()
	h.HandleQuery(buildDNSQuery("api.openai.com", dnsTypeA), net.ParseIP("10.88.0.2"), 5000)
	mu.Lock()
	_, recorded = got[ai]
	mu.Unlock()
	if calls != 1 || !recorded {
		t.Fatalf("DoH calls=%d (want cache hit), recorded=%v on cache hit", calls, recorded)
	}
	// 非 AI 域名与 AAAA 查询不登记。
	mu.Lock()
	for k := range got {
		delete(got, k)
	}
	mu.Unlock()
	h.HandleQuery(buildDNSQuery("example.org", dnsTypeA), net.ParseIP("10.88.0.2"), 5000)
	h.HandleQuery(buildDNSQuery("claude.ai", dnsTypeAAAA), net.ParseIP("10.88.0.2"), 5000)
	mu.Lock()
	n := len(got)
	mu.Unlock()
	if n != 0 {
		t.Fatalf("recorded %d addresses for non-AI names or AAAA", n)
	}
	h.SetAIRecorder(nil) // 取消后不再回调
	h.HandleQuery(buildDNSQuery("claude.ai", dnsTypeA), net.ParseIP("10.88.0.2"), 5000)
}

func TestReliableTCPDefaultOnAndEnvOff(t *testing.T) {
	t.Setenv(ReliableTCPEnv, "")
	if !newFlowClassifier().reliableTCP.Load() {
		t.Fatal("ordinary TCP over R must be on by default")
	}
	for _, v := range []string{"0", "false", "OFF", " no "} {
		t.Setenv(ReliableTCPEnv, v)
		if newFlowClassifier().reliableTCP.Load() {
			t.Fatalf("%s=%q should turn it off", ReliableTCPEnv, v)
		}
	}
	t.Setenv(ReliableTCPEnv, "1")
	if !newFlowClassifier().reliableTCP.Load() {
		t.Fatal("1 should keep it on")
	}
}

func TestClassifyReliableOrdinaryTCPUsesRWhenUp(t *testing.T) {
	c, _ := newTestClassifier()
	c.reliableTCP.Store(true)
	// 普通 TCP 新连接：R 可用 → flowReliable，且整条流固定。
	if cl, syn := c.classifyR(tcpPacket(natTun, otherHost, 50100, 443, fSYN), true); cl != flowReliable || !syn {
		t.Fatalf("class=%d syn=%v", cl, syn)
	}
	for _, flags := range []byte{fACK, fACK | 0x08, fRST} {
		if cl, _ := c.classifyR(tcpPacket(natTun, otherHost, 50100, 443, flags), false); cl != flowReliable {
			t.Fatalf("flags %#x: an established R flow changed class to %d (R state must not matter mid-flow)", flags, cl)
		}
	}
	// R 不可用时的新连接留在 default，并固定在 default：之后 R 恢复也不迁移。
	if cl, _ := c.classifyR(tcpPacket(natTun, otherHost, 50101, 443, fSYN), false); cl != flowDefault {
		t.Fatalf("new flow while R is down: class=%d", cl)
	}
	if cl, _ := c.classifyR(tcpPacket(natTun, otherHost, 50101, 443, fACK), true); cl != flowDefault {
		t.Fatal("a flow started on default must stay there when R comes back")
	}
	// AI 地址优先于普通 TCP：仍是 flowAI（R 不可用时 fail-closed，不退到 default）。
	c.ai.Add(aiHost, time.Hour)
	if cl, _ := c.classifyR(tcpPacket(natTun, aiHost, 50102, 443, fSYN), false); cl != flowAI {
		t.Fatalf("AI address with R down: class=%d", cl)
	}
	// 不是 TCP 的流量始终 default，不产生状态。
	before := c.flows.len()
	if cl, _ := c.classifyR(udpPacket(natTun, otherHost), true); cl != flowDefault || c.flows.len() != before {
		t.Fatal("UDP must stay on default and leave no state")
	}
}

func TestClassifyReliableOffKeepsOrdinaryTCPOnDefault(t *testing.T) {
	c, _ := newTestClassifier() // reliableTCP=false
	if cl, _ := c.classifyR(tcpPacket(natTun, otherHost, 50110, 443, fSYN), true); cl != flowDefault {
		t.Fatalf("class=%d", cl)
	}
}

func TestClassifyDisabledOverridesReliable(t *testing.T) {
	c, _ := newTestClassifier()
	c.reliableTCP.Store(true)
	c.enabled.Store(false) // 用户关闭“AI 稳定通道”：一切走 default
	if cl, _ := c.classifyR(tcpPacket(natTun, otherHost, 50120, 443, fSYN), true); cl != flowDefault {
		t.Fatalf("class=%d", cl)
	}
}
