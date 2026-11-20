// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// realFormatSample 取自上游 direct-list.txt 的真实格式：无前缀域名（后缀）、full: 精确、regexp: 正则，
// 另含 CIDR（IPv4/IPv6）、单个 IP、注释与 "@cn" 属性。
const realFormatSample = `# 注释行
0.zone
baidu.com
full:a1.mzstatic.com
regexp:.+\.awsdns-cn-[0-9][0-9]\.(biz|com|net|top)$
domain:qq.com
taobao.com @cn
keyword:cdn-cn
203.0.113.0/24
198.51.100.42
240e::/18
2001:db8::1
`

func newGeoSplit(t *testing.T, data string) (*SplitEngine, int) {
	t.Helper()
	e := NewSplitEngine()
	n, err := e.ReloadRules([]byte(data))
	if err != nil {
		t.Fatalf("ReloadRules: %v", err)
	}
	return e, n
}

func TestReloadRulesRealFormat(t *testing.T) {
	e, n := newGeoSplit(t, realFormatSample)
	// 有效条数：0.zone baidu.com full:a1 qq.com taobao.com keyword + 2 个 CIDR(v4/v6) + 2 个 IP = 10；regexp 跳过
	if n != 10 {
		t.Fatalf("规则条数 = %d, 期望 10（regexp 不计）", n)
	}
	for _, d := range []string{"0.zone", "baidu.com", "www.baidu.com", "a.b.baidu.com", "WWW.QQ.COM", "taobao.com", "img.taobao.com", "a1.mzstatic.com", "x.cdn-cn.example.org"} {
		if got := e.MatchDomain(d); got != DIRECT {
			t.Errorf("%s 应直连，got %v", d, got)
		}
	}
	// full: 只精确匹配，不含子域；regexp 行不得被当作域名
	if got := e.MatchDomain("b.a1.mzstatic.com"); got != PROXY {
		t.Errorf("full: 不应匹配子域，got %v", got)
	}
	if got := e.MatchDomain("mzstatic.com"); got != PROXY {
		t.Errorf("full: 不应匹配父域，got %v", got)
	}
	// 后缀必须按“域名边界”匹配：notbaidu.com 不是 baidu.com 的子域
	for _, d := range []string{"notbaidu.com", "baidu.com.evil.org", "google.com", "github.com"} {
		if got := e.MatchDomain(d); got != PROXY {
			t.Errorf("%s 不应直连，got %v", d, got)
		}
	}
	// 网段：IPv4 CIDR、单 IP、IPv6 CIDR、单个 IPv6
	for _, ip := range []string{"203.0.113.77", "198.51.100.42", "240e:1::5", "2001:db8::1"} {
		if got := e.MatchIP(net.ParseIP(ip)); got != DIRECT {
			t.Errorf("%s 应直连，got %v", ip, got)
		}
	}
	for _, ip := range []string{"198.51.100.43", "8.8.8.8", "2001:db8::2"} {
		if got := e.MatchIP(net.ParseIP(ip)); got != PROXY {
			t.Errorf("%s 不应直连，got %v", ip, got)
		}
	}
}

// 内置的 AI 规则必须优先于下发的直连名单（名单里即使含 AI 域名也不得改走直连）。
func TestReloadRulesAIStillWins(t *testing.T) {
	e, _ := newGeoSplit(t, "openai.com\napi.openai.com\ngoogleapis.com\nbaidu.com\n")
	for _, d := range []string{"openai.com", "api.openai.com", "x.googleapis.com"} {
		if got := e.MatchDomain(d); got != AI {
			t.Errorf("%s 应保持 AI，got %v", d, got)
		}
	}
	if got := e.MatchDomain("baidu.com"); got != DIRECT {
		t.Errorf("baidu.com 应直连，got %v", got)
	}
}

// 重新加载整体替换旧规则，并清空匹配缓存（旧缓存里的“直连”不得残留）。
func TestReloadRulesReplacesAndClearsCache(t *testing.T) {
	e, _ := newGeoSplit(t, "first-only.example\n")
	if e.MatchDomain("first-only.example") != DIRECT {
		t.Fatal("第一次加载后应直连")
	}
	if _, err := e.ReloadRules([]byte("second-only.example\n")); err != nil {
		t.Fatal(err)
	}
	if got := e.MatchDomain("first-only.example"); got != PROXY {
		t.Errorf("旧规则应被替换，got %v", got)
	}
	if got := e.MatchDomain("second-only.example"); got != DIRECT {
		t.Errorf("新规则应生效，got %v", got)
	}
}

// 空数据、只有注释、全是不支持的行：不 panic，返回错误，且不改动现有规则（不能悄悄清空）。
func TestReloadRulesDegenerateInput(t *testing.T) {
	for name, data := range map[string]string{
		"empty": "", "comments": "# a\n# b\n", "regexp-only": "regexp:^a$\n", "garbage": "http://x/y\n??\n a/b \n",
	} {
		e, _ := newGeoSplit(t, "keep-me.example\n")
		if n, err := e.ReloadRules([]byte(data)); err == nil || n != 0 {
			t.Errorf("%s: 应返回错误且条数 0，got (%d,%v)", name, n, err)
		}
		if got := e.MatchDomain("keep-me.example"); got != DIRECT {
			t.Errorf("%s: 无效数据不得清空现有规则，got %v", name, got)
		}
		if got := e.MatchDomain("baidu.com"); got != DIRECT { // 内置 China Direct 仍在
			t.Errorf("%s: 内置直连规则不应受影响，got %v", name, got)
		}
	}
}

// 条数上限：超过 maxDirectRules 的部分被忽略。
func TestReloadRulesCap(t *testing.T) {
	var b strings.Builder
	for i := 0; i < maxDirectRules+50; i++ {
		fmt.Fprintf(&b, "d%d.example\n", i)
	}
	_, n := newGeoSplit(t, b.String())
	if n != maxDirectRules {
		t.Fatalf("条数 = %d, 期望封顶 %d", n, maxDirectRules)
	}
}

// 下发的 IPv4 网段并入 TUN 路由规划使用的直连网段，且保留内置快照。
func TestChinaCIDRsMergesDownloaded(t *testing.T) {
	e, _ := newGeoSplit(t, "203.0.113.0/24\n")
	var prefixes []netip.Prefix
	for _, s := range e.ChinaCIDRs() {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			t.Fatalf("非法 CIDR %q: %v", s, err)
		}
		prefixes = append(prefixes, p)
	}
	covered := func(ip string) bool {
		a := netip.MustParseAddr(ip)
		for _, p := range prefixes {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	if !covered("203.0.113.9") {
		t.Error("下发网段应并入路由规划的直连网段")
	}
	if !covered("1.1.8.9") { // 内置快照第一条 1.1.8.0/24
		t.Error("内置 APNIC 快照应保留")
	}
	if covered("8.8.8.8") {
		t.Error("境外地址不应被覆盖")
	}
	// 没有下发规则时与内置快照一致
	base := NewSplitEngine().ChinaCIDRs()
	if len(base) == 0 {
		t.Error("内置网段不应为空")
	}
}

// 读写并发：Match 与 ReloadRules 同时进行（配合 -race）。
func TestReloadRulesConcurrentWithMatch(t *testing.T) {
	e := NewSplitEngine()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				e.MatchDomain(fmt.Sprintf("h%d-%d.example", g, i%50))
				e.MatchIP(net.IPv4(203, 0, 113, byte(i)))
				_ = e.TotalRules()
			}
		}(g)
	}
	for i := 0; i < 30; i++ {
		if _, err := e.ReloadRules([]byte(fmt.Sprintf("h0-%d.example\n203.0.113.0/24\n", i))); err != nil {
			t.Error(err)
		}
		_ = e.ChinaCIDRs()
	}
	close(stop)
	wg.Wait()
}

func bigDirectList(n int) []byte {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "site%d.example%d.com\n", i, i%977)
	}
	b.WriteString("full:exact.example.org\n203.0.113.0/24\n")
	return []byte(b.String())
}

// 规模：与上游 direct-list.txt 同量级（11 万条）时，新域名的判定必须是“按层数”而非“按条数”的代价。
func TestReloadRulesLargeListIsFast(t *testing.T) {
	data := bigDirectList(110000)
	e := NewSplitEngine()
	start := time.Now()
	n, err := e.ReloadRules(data)
	if err != nil {
		t.Fatal(err)
	}
	if n < 110000 {
		t.Fatalf("条数 = %d", n)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("加载 11 万条耗时 %v，过慢", d)
	}
	start = time.Now()
	for i := 0; i < 2000; i++ { // 2000 个互不相同的新域名，绕开匹配缓存
		if e.MatchDomain(fmt.Sprintf("never-seen-%d.foreign.example", i)) != PROXY {
			t.Fatal("境外域名不应直连")
		}
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Errorf("2000 次未命中判定耗时 %v，说明仍在线性扫描", d)
	}
	if e.MatchDomain("a.site5.example5.com") != DIRECT || e.MatchDomain("exact.example.org") != DIRECT {
		t.Error("大名单中的条目应命中")
	}
}

func BenchmarkGeoMatchLargeList(b *testing.B) {
	e := NewSplitEngine()
	if _, err := e.ReloadRules(bigDirectList(110000)); err != nil {
		b.Fatal(err)
	}
	e.cacheSize = 0 // 不让缓存掩盖匹配本身的代价
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.MatchDomain("www.some-foreign-site.example")
	}
}

// ---- 对下发数据的独立设防（reviewer 审核意见）----

// 过宽网段（/0、/7、IPv6 /15）整行跳过，不让一行数据把全部流量判为直连；/8 与 /16 边界保留。
func TestReloadRulesRejectsOverWideRanges(t *testing.T) {
	e, n := newGeoSplit(t, "0.0.0.0/0\n1.0.0.0/7\n::/0\n8000::/15\n10.0.0.0/8\n2001::/16\n")
	if n != 2 {
		t.Fatalf("条数 = %d, 期望 2（只留 /8 与 IPv6 /16）", n)
	}
	for _, ip := range []string{"8.8.8.8", "1.2.3.4", "100.1.1.1", "2606:4700::1"} {
		if got := e.MatchIP(net.ParseIP(ip)); got != PROXY {
			t.Errorf("%s 不应因过宽网段而直连，got %v", ip, got)
		}
	}
	if e.MatchIP(net.ParseIP("10.9.9.9")) != DIRECT || e.MatchIP(net.ParseIP("2001:1::1")) != DIRECT {
		t.Error("边界宽度的网段应生效")
	}
	// TUN 路由规划使用的网段里也不能出现 /0
	for _, c := range e.ChinaCIDRs() {
		if strings.HasSuffix(c, "/0") || strings.HasSuffix(c, "/1") || strings.HasSuffix(c, "/7") {
			t.Errorf("路由规划网段过宽: %s", c)
		}
	}
}

// 通用顶级域不能当后缀下发；cn 与品牌词（真实名单里有 50 条这样的单段条目）照常。
func TestReloadRulesRejectsGenericTLDs(t *testing.T) {
	e, n := newGeoSplit(t, "com\nnet\norg\nio\ncn\nbaidu\nalipay\nfull:com\n")
	if n != 4 { // cn baidu alipay + full:com（精确匹配只命中 com 本身）
		t.Fatalf("条数 = %d, 期望 4", n)
	}
	for _, d := range []string{"example.com", "example.net", "wikipedia.org", "github.io"} {
		if got := e.MatchDomain(d); got != PROXY {
			t.Errorf("%s 不应因通用顶级域而直连，got %v", d, got)
		}
	}
	for _, d := range []string{"x.cn", "www.baidu", "pay.alipay"} {
		if got := e.MatchDomain(d); got != DIRECT {
			t.Errorf("%s 应直连，got %v", d, got)
		}
	}
}

// 关键字：过短的丢弃，数量封顶；IPv6 与 IPv4 行数封顶（超限整份拒绝，现有规则不变）。
func TestReloadRulesLimits(t *testing.T) {
	e, n := newGeoSplit(t, "keyword:e\nkeyword:com\nkeyword:cdn-cn\n")
	if n != 1 {
		t.Fatalf("条数 = %d, 期望只留 1 个关键字", n)
	}
	if e.MatchDomain("www.example.org") != PROXY {
		t.Error("过短关键字不应生效")
	}

	var b strings.Builder
	for i := 0; i < maxDirectKeywords+200; i++ {
		fmt.Fprintf(&b, "keyword:kw%05d\n", i)
	}
	if _, n := newGeoSplit(t, b.String()); n != maxDirectKeywords {
		t.Errorf("关键字条数 = %d, 期望封顶 %d", n, maxDirectKeywords)
	}

	b.Reset()
	for i := 0; i <= maxDirectV4Lines; i++ {
		fmt.Fprintf(&b, "%d.%d.%d.%d\n", 11+i/65536, (i/256)%256, i%256, 1)
	}
	idx := buildDirectIndex([]byte(b.String()))
	if idx.count != 0 || idx.rejected == "" {
		t.Errorf("IPv4 行数超限应整份拒绝，got count=%d rejected=%q", idx.count, idx.rejected)
	}
	b.Reset()
	for i := 0; i <= maxDirectV6Lines; i++ {
		fmt.Fprintf(&b, "2001:db8:%x::1\n", i)
	}
	if idx := buildDirectIndex([]byte(b.String())); idx.count != 0 || idx.rejected == "" {
		t.Errorf("IPv6 行数超限应整份拒绝，got count=%d rejected=%q", idx.count, idx.rejected)
	}
}

// 覆盖面总闸：合并后超过 25% 的 IPv4 地址空间，整份拒绝（逐行都合规也不行）。
func TestReloadRulesRejectsExcessiveCoverage(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 130; i++ { // 130 个 /9，各约 840 万地址，合计约 26%
		fmt.Fprintf(&b, "%d.%d.0.0/9\n", i, (i%2)*128)
	}
	idx := buildDirectIndex([]byte(b.String()))
	if idx.count != 0 || idx.rejected == "" {
		t.Fatalf("覆盖过大应整份拒绝，got count=%d rejected=%q", idx.count, idx.rejected)
	}
	// 被拒绝的数据不得改变已有规则
	e := NewSplitEngine()
	if _, err := e.ReloadRules([]byte("keep.example\n")); err != nil {
		t.Fatal(err)
	}
	if n, err := e.ReloadRules([]byte(b.String())); err == nil || n != 0 {
		t.Fatalf("覆盖过大的数据应被拒绝并返回错误，got (%d,%v)", n, err)
	}
	if e.MatchDomain("keep.example") != DIRECT {
		t.Error("被拒绝的数据不得清掉现有规则")
	}
	if e.MatchIP(net.ParseIP("8.8.8.8")) != PROXY {
		t.Error("被拒绝的网段不得生效")
	}

	// 真实量级（约 6 千条、约 8%）不触发总闸
	var ok strings.Builder
	for i := 0; i < 20; i++ {
		fmt.Fprintf(&ok, "%d.0.0.0/10\n", 20+i) // 20 × 4M ≈ 1.9%
	}
	if idx := buildDirectIndex([]byte(ok.String())); idx.count != 20 || idx.rejected != "" {
		t.Errorf("正常覆盖不应被拒，got count=%d rejected=%q", idx.count, idx.rejected)
	}
}

// 区间合并在 255.255.255.255 处不能回绕：240.0.0.0/4 与 250.0.0.0/8 合并后应是一个区间，二分查找不漏判。
func TestNormalizeDoesNotOverflowAtTopOfIPv4(t *testing.T) {
	m := &ChinaIPMatcher{}
	m.init("240.0.0.0/4\n250.0.0.0/8\n1.0.0.0/8\n255.255.255.255/32\n")
	if got := len(m.ranges); got != 2 {
		t.Fatalf("合并后区间数 = %d, 期望 2: %+v", got, m.ranges)
	}
	for _, ip := range []string{"240.0.0.1", "250.1.2.3", "255.255.255.255", "1.2.3.4"} {
		if !m.Contains(net.ParseIP(ip)) {
			t.Errorf("%s 应命中", ip)
		}
	}
	if m.Contains(net.ParseIP("2.0.0.1")) {
		t.Error("2.0.0.1 不应命中")
	}
}

// 同步互斥：已有同步在进行时，第二个直接返回“进行中”，不排队，也不改动状态。
func TestSyncGeoDataBusyReturnsImmediately(t *testing.T) {
	geoTestEnv(t)
	release := make(chan struct{})
	started := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("slow.example\n"))
	})
	eng := newGeoEngine(t, handler)
	done := make(chan error, 1)
	go func() {
		_, _, err := eng.SyncGeoData(context.Background())
		done <- err
	}()
	<-started
	t0 := time.Now()
	_, _, err := eng.SyncGeoData(context.Background())
	if err != errGeoBusy {
		t.Fatalf("err = %v, 期望 errGeoBusy", err)
	}
	if time.Since(t0) > time.Second {
		t.Error("第二个同步不应等待")
	}
	if ts, msg := eng.geoStatus(); ts != 0 || msg != "" {
		t.Errorf("忙碌返回不应改动状态，got (%d,%q)", ts, msg)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("第一个同步应成功: %v", err)
	}
	if ts, msg := eng.geoStatus(); ts == 0 || msg != "" {
		t.Errorf("第一个同步成功后状态 = (%d,%q)", ts, msg)
	}
}

// 国家/地区顶级域只放行 cn；真实名单里的品牌词、中文 gTLD、xn-- 顶级域照常接受。
func TestReloadRulesCountryTLDsAndRealSingleLabels(t *testing.T) {
	e, n := newGeoSplit(t, "tw\nhk\nca\nau\neu\nio\ncn\nwang\nyun\nxn--1qqw23a\nunicom\nshouji\n")
	if n != 6 { // cn wang yun xn--1qqw23a unicom shouji
		t.Fatalf("条数 = %d, 期望 6", n)
	}
	for _, d := range []string{"www.gov.tw", "a.com.hk", "x.ca", "x.com.au", "x.eu", "github.io"} {
		if got := e.MatchDomain(d); got != PROXY {
			t.Errorf("%s 不应因国家/地区顶级域而直连，got %v", d, got)
		}
	}
	for _, d := range []string{"x.cn", "shop.wang", "app.yun", "a.unicom"} {
		if got := e.MatchDomain(d); got != DIRECT {
			t.Errorf("%s 应直连，got %v", d, got)
		}
	}
}

// 关键字不得含点（e.com 之类会命中大量无关站点）。
func TestReloadRulesKeywordMustNotContainDot(t *testing.T) {
	e, n := newGeoSplit(t, "keyword:e.com\nkeyword:cdn-cn\n")
	if n != 1 {
		t.Fatalf("条数 = %d, 期望 1", n)
	}
	if e.MatchDomain("www.apple.com") != PROXY || e.MatchDomain("www.google.com") != PROXY {
		t.Error("带点的关键字不应生效")
	}
}

// 稀疏的小网段：补集路由会暴增，必须退回内置快照，保证 TUN 能起来；正常的下发网段则保留。
func TestTunRoutePlanFallsBackWhenDownloadedRangesBlowBudget(t *testing.T) {
	origDNS := systemDNSServersFn
	systemDNSServersFn = func() ([]netip.Addr, error) { return nil, nil }
	t.Cleanup(func() { systemDNSServersFn = origDNS })

	eng := NewEngine()
	defer eng.Close()
	builtin := len(eng.splitEngine.BuiltinChinaCIDRs())

	// 20000 个互不相邻的 /32（间隔 256）：行数与覆盖率都合规，但补集会拆出十几万条前缀
	var b strings.Builder
	for i := 0; i < maxDirectV4Lines; i++ {
		v := uint32(11<<24) + uint32(i)*256 + 1
		fmt.Fprintf(&b, "%d.%d.%d.%d\n", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
	if _, err := eng.splitEngine.ReloadRules([]byte(b.String())); err != nil {
		t.Fatalf("数据本身合规，应能加载: %v", err)
	}

	// 对照：不做回退直接规划，确实会超限（说明这个测试有意义）
	var raw RoutePlanInput
	for _, c := range eng.splitEngine.ChinaCIDRs() {
		if p, err := netip.ParsePrefix(c); err == nil {
			raw.Direct = append(raw.Direct, p)
		}
	}
	if _, err := PlanTUNRoutes(raw); err == nil {
		t.Fatal("对照组应超出路由上限，否则测试没有意义")
	}

	eng.mu.RLock()
	in := eng.tunPlanInputLocked()
	eng.mu.RUnlock()
	if _, err := PlanTUNRoutes(in); err != nil {
		t.Fatalf("回退后应能规划路由: %v", err)
	}
	if len(in.Direct) != builtin {
		t.Errorf("应退回内置快照（%d 条），got %d", builtin, len(in.Direct))
	}

	// 正常的下发网段不触发回退，并入路由规划
	if _, err := eng.splitEngine.ReloadRules([]byte("20.0.0.0/10\n21.0.0.0/10\n")); err != nil {
		t.Fatal(err)
	}
	eng.mu.RLock()
	in = eng.tunPlanInputLocked()
	eng.mu.RUnlock()
	found := false
	for _, p := range in.Direct {
		if p.Contains(netip.MustParseAddr("20.1.2.3")) {
			found = true
		}
	}
	if !found {
		t.Error("正常的下发网段应并入路由规划")
	}
}
