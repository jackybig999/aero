// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"context"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed china_ip.txt
var chinaIPData string

// Strategy 分流策略
type Strategy int

const (
	DIRECT Strategy = iota // 直连
	PROXY                  // 代理
	AI                     // AI 优先通道
)

func (s Strategy) String() string {
	switch s {
	case DIRECT:
		return "DIRECT"
	case PROXY:
		return "PROXY"
	case AI:
		return "AI"
	default:
		return "PROXY"
	}
}

// Rule 分流规则
type Rule struct {
	Name           string
	Strategy       Strategy
	DomainSuffixes []string
	DomainKeywords []string
	IPRanges       []string

	parsedIPNets []*net.IPNet
}

// ipRange 表示一个连续的 IPv4 地址闭区间 [start, end]
type ipRange struct {
	start uint32
	end   uint32
}

// ChinaIPMatcher 基于 APNIC 权威统计的高性能中国大陆 IPv4 判定器。
// 底层使用紧凑的闭区间数组与 O(log N) 二分查找，单次判定 ~10ns，零内存分配。
type ChinaIPMatcher struct {
	ranges []ipRange
}

// GlobalDefaultChinaMatcher 全局单例中国大陆 IP 匹配器
var GlobalDefaultChinaMatcher = NewChinaIPMatcher()

// NewChinaIPMatcher 创建并初始化中国大陆 IP 匹配器
func NewChinaIPMatcher() *ChinaIPMatcher {
	m := &ChinaIPMatcher{}
	m.init(chinaIPData)
	return m
}

func (m *ChinaIPMatcher) init(data string) {
	lines := strings.Split(data, "\n")
	ranges := make([]ipRange, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, ipNet, err := net.ParseCIDR(line)
		if err != nil || ipNet.IP.To4() == nil {
			continue
		}
		ip4 := ipNet.IP.To4()
		mask := ipNet.Mask
		start := binary.BigEndian.Uint32(ip4)
		maskVal := binary.BigEndian.Uint32(mask)
		end := start | (^maskVal)
		ranges = append(ranges, ipRange{start: start, end: end})
	}

	m.ranges = ranges
	m.normalize()
}

// normalize 按起点排序并合并相邻或重叠的区间。
func (m *ChinaIPMatcher) normalize() {
	ranges := m.ranges
	sort.Slice(ranges, func(i, j int) bool {
		return ranges[i].start < ranges[j].start
	})

	if len(ranges) > 0 {
		merged := make([]ipRange, 0, len(ranges))
		curr := ranges[0]
		for i := 1; i < len(ranges); i++ {
			// 用 64 位比较：curr.end 为 255.255.255.255 时 +1 会在 32 位里回绕成 0
			if uint64(ranges[i].start) <= uint64(curr.end)+1 {
				if ranges[i].end > curr.end {
					curr.end = ranges[i].end
				}
			} else {
				merged = append(merged, curr)
				curr = ranges[i]
			}
		}
		merged = append(merged, curr)
		ranges = merged
	}
	m.ranges = ranges
}

// TotalRanges 返回有效网段数量
func (m *ChinaIPMatcher) TotalRanges() int {
	return len(m.ranges)
}

// Contains 检查给定 IP 是否属于中国大陆 IP 网段。
func (m *ChinaIPMatcher) Contains(ip net.IP) bool {
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	v := binary.BigEndian.Uint32(ip4)
	idx := sort.Search(len(m.ranges), func(i int) bool {
		return m.ranges[i].end >= v
	})
	if idx < len(m.ranges) && m.ranges[idx].start <= v && v <= m.ranges[idx].end {
		return true
	}
	return false
}

// ExportCIDRs 将基于 APNIC 权威统计并经区间合并后的全部网段转换为标准 CIDR 前缀列表
func (m *ChinaIPMatcher) ExportCIDRs() []string {
	if m == nil {
		return nil
	}
	var res []string
	for _, r := range m.ranges {
		res = append(res, rangeToCIDRs(r.start, r.end)...)
	}
	return res
}

func rangeToCIDRs(start, end uint32) []string {
	var cidrs []string
	cur := start
	for cur <= end {
		// 寻找不越界且对齐于 cur 的最大 2 的幂
		maxSize := uint32(1)
		for {
			next := maxSize << 1
			if next == 0 {
				break
			}
			if cur+next-1 <= end && (cur&(next-1)) == 0 {
				maxSize = next
			} else {
				break
			}
		}
		prefixLen := 32
		for s := maxSize; s > 1; s >>= 1 {
			prefixLen--
		}
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, cur)
		cidrs = append(cidrs, fmt.Sprintf("%s/%d", ip.String(), prefixLen))
		if cur+maxSize < cur || cur+maxSize > end {
			break
		}
		cur += maxSize
	}
	return cidrs
}

// SplitEngine 智能分流规则引擎
type SplitEngine struct {
	mu              sync.RWMutex
	rules           []Rule
	chinaMatcher    *ChinaIPMatcher
	cache           map[string]Strategy
	cacheMu         sync.RWMutex
	cacheSize       int
	defaultStrategy Strategy

	// direct 是服务端下发的直连规则索引（域名哈希、IPv4 二分）。整体原子替换：
	// Match 只读取指针，ReloadRules 构建好新索引后一次性换入，匹配期间无需加锁拷贝。
	direct atomic.Pointer[directIndex]
}

// directIndex 是下发直连规则的只读索引，构建后不再修改。
type directIndex struct {
	suffix   map[string]struct{} // domain: 或无前缀：域名本身及全部子域
	full     map[string]struct{} // full: 仅精确匹配
	keywords []string            // keyword: 子串匹配
	v4       *ChinaIPMatcher     // IPv4 网段（合并后二分）
	v6       []*net.IPNet        // IPv6 网段（数量少，线性）
	count    int                 // 有效规则条数（界面显示用，去重前）
	rejected string              // 非空表示整份数据因异常被拒绝（此时 count=0），内容为原因
}

// matchDomain 判定 host（已小写、无端口、无尾点）是否命中：先精确，再逐级去掉最左一段查后缀，最后查关键字。
func (d *directIndex) matchDomain(host string) bool {
	if _, ok := d.full[host]; ok {
		return true
	}
	for h := host; ; {
		if _, ok := d.suffix[h]; ok {
			return true
		}
		i := strings.IndexByte(h, '.')
		if i < 0 {
			break
		}
		h = h[i+1:]
	}
	for _, k := range d.keywords {
		if strings.Contains(host, k) {
			return true
		}
	}
	return false
}

func (d *directIndex) matchIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		return d.v4 != nil && d.v4.Contains(ip4)
	}
	for _, n := range d.v6 {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// validDirectDomain 只接受由字母、数字、连字符、点与下划线组成的域名，拒绝带路径、端口、通配符等异常行。
func validDirectDomain(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' {
			continue
		}
		return false
	}
	return s[0] != '.' && s[len(s)-1] != '.'
}

// 下发规则的校验边界。数据来自服务端，但服务端又取自第三方上游，所以客户端仍要独立设防：
// 一行 0.0.0.0/0 或 com 就足以让大部分流量绕过隧道。取值参考真实数据（cn.txt 最宽 IPv4 /10、IPv6 /19，
// IPv4 约 6200 条、覆盖约 8% 地址空间），并留出余量。
const (
	maxDirectRules      = 600000  // 单次热加载接受的规则条数上限，防止异常数据撑爆内存
	minDirectV4Prefix   = 8       // 拒绝比 /8 更宽的 IPv4 网段
	minDirectV6Prefix   = 16      // 拒绝比 /16 更宽的 IPv6 网段
	maxDirectV4Lines    = 20000   // IPv4 网段行数上限；加内置快照与旁路仍远低于 maxTUNRoutes
	maxDirectV6Lines    = 20000   // IPv6 网段为线性扫描，需限数
	maxDirectKeywords   = 1000    // 关键字为线性子串扫描，需限数
	minDirectKeywordLen = 4       // 过短的关键字会命中大半域名
	maxDirectV4Coverage = 1 << 30 // IPv4 合并后覆盖超过 25% 地址空间：整份视为异常
)

// genericTLDs 是常见的通用顶级域。无前缀的单段条目会按“后缀”匹配该域下全部域名。
// 真实名单里的单段条目只有：cn、品牌词（baidu、alipay…）、中文 gTLD（wang、yun…）与 xn-- 开头的中文顶级域；
// 两位字母的国家/地区顶级域只放行 cn（见 addDomain），通用顶级域出现在名单里只可能是错误或投毒。
var genericTLDs = map[string]struct{}{
	"com": {}, "net": {}, "org": {}, "edu": {}, "gov": {}, "mil": {}, "int": {}, "info": {}, "biz": {},
	"name": {}, "pro": {}, "xyz": {}, "top": {}, "app": {}, "dev": {}, "site": {}, "online": {},
	"shop": {}, "vip": {}, "club": {}, "store": {}, "tech": {}, "link": {}, "asia": {}, "mobi": {},
	"cloud": {}, "live": {}, "news": {}, "blog": {}, "life": {}, "world": {}, "fun": {}, "icu": {},
	"work": {}, "ltd": {}, "win": {}, "bid": {}, "men": {}, "red": {}, "ren": {}, "xin": {},
	"mom": {}, "page": {}, "click": {},
}

// NewSplitEngine 创建分流引擎
func NewSplitEngine() *SplitEngine {
	e := &SplitEngine{
		rules:           make([]Rule, 0),
		chinaMatcher:    NewChinaIPMatcher(),
		cache:           make(map[string]Strategy),
		cacheSize:       10000,
		defaultStrategy: PROXY,
	}
	e.loadBuiltinRules()
	return e
}

// AddRule 添加规则
func (e *SplitEngine) AddRule(r Rule) {
	if len(r.parsedIPNets) == 0 && len(r.IPRanges) > 0 {
		r.parsedIPNets = make([]*net.IPNet, 0, len(r.IPRanges))
		for _, cidr := range r.IPRanges {
			if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
				r.parsedIPNets = append(r.parsedIPNets, ipNet)
			}
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, r)
}

// Match 匹配域名/IP
func (e *SplitEngine) Match(host string, ip net.IP) Strategy {
	e.cacheMu.RLock()
	if s, ok := e.cache[host]; ok {
		e.cacheMu.RUnlock()
		return s
	}
	e.cacheMu.RUnlock()

	hostOnly := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostOnly = h
	}
	hostOnly = strings.Trim(hostOnly, "[]")
	if ip == nil {
		ip = net.ParseIP(hostOnly)
	}

	if isLocalOrPrivateIP(hostOnly, ip) {
		e.setCache(host, DIRECT)
		return DIRECT
	}

	if ip != nil && e.chinaMatcher != nil && e.chinaMatcher.Contains(ip) {
		e.setCache(host, DIRECT)
		return DIRECT
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, rule := range e.rules {
		if matchSplitRule(rule, hostOnly, ip) {
			e.setCache(host, rule.Strategy)
			return rule.Strategy
		}
	}

	// 服务端下发的直连规则：排在内置规则（含 AI）之后，AI 域名不会被直连名单覆盖
	if d := e.direct.Load(); d != nil {
		hit := false
		if ip != nil {
			hit = d.matchIP(ip)
		} else {
			hit = d.matchDomain(strings.TrimSuffix(strings.ToLower(hostOnly), "."))
		}
		if hit {
			e.setCache(host, DIRECT)
			return DIRECT
		}
	}

	e.setCache(host, e.defaultStrategy)
	return e.defaultStrategy
}

// Decide 兼容外部接口：返回 "direct", "proxy", "ai"
func (e *SplitEngine) Decide(target string) string {
	s := e.Match(target, nil)
	switch s {
	case DIRECT:
		return "direct"
	case AI:
		return "ai"
	default:
		return "proxy"
	}
}

// MatchDomain 仅域名匹配
func (e *SplitEngine) MatchDomain(domain string) Strategy {
	return e.Match(domain, nil)
}

// MatchIP 仅 IP 匹配
func (e *SplitEngine) MatchIP(ip net.IP) Strategy {
	return e.Match(ip.String(), ip)
}

func matchSplitRule(r Rule, host string, ip net.IP) bool {
	hostLower := strings.ToLower(host)

	for _, suffix := range r.DomainSuffixes {
		s := strings.ToLower(suffix)
		if hostLower == s || strings.HasSuffix(hostLower, "."+s) {
			return true
		}
	}

	for _, keyword := range r.DomainKeywords {
		if strings.Contains(hostLower, strings.ToLower(keyword)) {
			return true
		}
	}

	if ip != nil {
		for _, ipNet := range r.parsedIPNets {
			if ipNet.Contains(ip) {
				return true
			}
		}
	}

	return false
}

func isLocalOrPrivateIP(host string, ip net.IP) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "localhost" || h == "localhost." {
		return true
	}
	if ip == nil && h != "" {
		ip = net.ParseIP(h)
	}
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 { // 100.64/10
			return true
		}
	}
	return false
}

func (e *SplitEngine) setCache(key string, s Strategy) {
	e.cacheMu.Lock()
	defer e.cacheMu.Unlock()
	if len(e.cache) >= e.cacheSize {
		for k := range e.cache {
			delete(e.cache, k)
			if len(e.cache) < e.cacheSize/2 {
				break
			}
		}
	}
	e.cache[key] = s
}

// ClearCache 清空缓存
func (e *SplitEngine) ClearCache() {
	e.cacheMu.Lock()
	defer e.cacheMu.Unlock()
	e.cache = make(map[string]Strategy)
}

// ReloadRules 热加载服务端下发的直连规则库，返回有效规则条数。
//
// 每行一条，取第一个空白前的字段（丢弃 "@cn" 之类属性）：
//   - IPv4/IPv6 的 CIDR 或单个 IP → 网段；
//   - full:域名 → 仅精确匹配；keyword:词 → 子串匹配；regexp:… → 不支持，跳过；
//   - domain:域名 或无前缀的域名 → 该域名及全部子域。
//
// 新索引完整构建后一次性替换旧索引；同时清空匹配缓存。
func (e *SplitEngine) ReloadRules(data []byte) (int, error) {
	idx := buildDirectIndex(data)
	if idx.count == 0 {
		// 空数据或被判定异常的数据不安装，保持现有规则不变（否则会悄悄清空已有规则）
		if idx.rejected != "" {
			return 0, fmt.Errorf("direct rules rejected: %s", idx.rejected)
		}
		return 0, errNoDirectRules
	}
	e.installDirect(idx)
	return idx.count, nil
}

var errNoDirectRules = errors.New("direct rules contain no valid entry")

// BuiltinChinaCIDRs 返回仅含内置 APNIC 快照的直连网段（不含服务端下发的）。
func (e *SplitEngine) BuiltinChinaCIDRs() []string {
	if e == nil || e.chinaMatcher == nil {
		return nil
	}
	return e.chinaMatcher.ExportCIDRs()
}

// hasDirectV4 报告是否有服务端下发的 IPv4 网段。
func (e *SplitEngine) hasDirectV4() bool {
	if e == nil {
		return false
	}
	d := e.direct.Load()
	return d != nil && d.v4 != nil && len(d.v4.ranges) > 0
}

// HasDirectRules 报告当前是否已有服务端下发的直连规则。
func (e *SplitEngine) HasDirectRules() bool {
	return e != nil && e.direct.Load() != nil
}

// DirectRuleCount 返回当前下发直连规则的条数（不含内置规则）。
func (e *SplitEngine) DirectRuleCount() int {
	if e == nil {
		return 0
	}
	if d := e.direct.Load(); d != nil {
		return d.count
	}
	return 0
}

// installDirect 用构建好的索引替换当前下发规则，并清空匹配缓存。
func (e *SplitEngine) installDirect(idx *directIndex) {
	e.mu.Lock()
	// 旧版本把下发规则放在 rules 里（名为 China Direct (Dynamic)）：若残留则移除
	filtered := e.rules[:0:0]
	for _, r := range e.rules {
		if r.Name != "China Direct (Dynamic)" {
			filtered = append(filtered, r)
		}
	}
	e.rules = filtered
	e.direct.Store(idx)
	e.mu.Unlock()

	e.ClearCache()
}

// buildDirectIndex 解析下发的规则文本，构建只读索引（不修改任何引擎状态）。
func buildDirectIndex(data []byte) *directIndex {
	idx := &directIndex{
		suffix: make(map[string]struct{}),
		full:   make(map[string]struct{}),
	}
	var v4 []string
	addDomain := func(m map[string]struct{}, d string, isSuffix bool) {
		d = strings.TrimSuffix(strings.ToLower(d), ".")
		if !validDirectDomain(d) {
			return
		}
		if isSuffix && !strings.Contains(d, ".") {
			if _, generic := genericTLDs[d]; generic {
				return
			}
			if len(d) == 2 && d != "cn" { // 其余国家/地区顶级域（tw、hk、ca、au…）不得整域直连
				return
			}
		}
		m[d] = struct{}{}
		idx.count++
	}
	reject := func(reason string) *directIndex {
		return &directIndex{suffix: map[string]struct{}{}, full: map[string]struct{}{}, rejected: reason}
	}

	for _, rawLine := range strings.Split(string(data), "\n") {
		if idx.count >= maxDirectRules {
			break
		}
		fields := strings.Fields(rawLine)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		line := fields[0]

		if _, ipNet, err := net.ParseCIDR(line); err == nil {
			ones, _ := ipNet.Mask.Size()
			if ipNet.IP.To4() != nil {
				if ones < minDirectV4Prefix { // 过宽（如 0.0.0.0/0）：跳过该行
					continue
				}
				if len(v4) >= maxDirectV4Lines {
					return reject(fmt.Sprintf("too many IPv4 ranges (> %d)", maxDirectV4Lines))
				}
				v4 = append(v4, ipNet.String())
			} else {
				if ones < minDirectV6Prefix {
					continue
				}
				if len(idx.v6) >= maxDirectV6Lines {
					return reject(fmt.Sprintf("too many IPv6 ranges (> %d)", maxDirectV6Lines))
				}
				idx.v6 = append(idx.v6, ipNet)
			}
			idx.count++
			continue
		}
		if ip := net.ParseIP(line); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				if len(v4) >= maxDirectV4Lines {
					return reject(fmt.Sprintf("too many IPv4 ranges (> %d)", maxDirectV4Lines))
				}
				v4 = append(v4, ip4.String()+"/32")
			} else {
				if len(idx.v6) >= maxDirectV6Lines {
					return reject(fmt.Sprintf("too many IPv6 ranges (> %d)", maxDirectV6Lines))
				}
				idx.v6 = append(idx.v6, &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)})
			}
			idx.count++
			continue
		}

		switch {
		case strings.HasPrefix(line, "regexp:"):
			// 正则规则不支持：直接跳过，不当作域名
		case strings.HasPrefix(line, "full:"):
			addDomain(idx.full, strings.TrimPrefix(line, "full:"), false)
		case strings.HasPrefix(line, "keyword:"):
			k := strings.ToLower(strings.TrimPrefix(line, "keyword:"))
			// 不得含点：形如 e.com 的“关键字”会命中大量无关站点
			if validDirectDomain(k) && !strings.Contains(k, ".") && len(k) >= minDirectKeywordLen && len(idx.keywords) < maxDirectKeywords {
				idx.keywords = append(idx.keywords, k)
				idx.count++
			}
		default:
			addDomain(idx.suffix, strings.TrimPrefix(line, "domain:"), true)
		}
	}
	if len(v4) > 0 {
		m := &ChinaIPMatcher{}
		m.init(strings.Join(v4, "\n"))
		var covered uint64
		for _, r := range m.ranges {
			covered += uint64(r.end) - uint64(r.start) + 1
		}
		if covered > maxDirectV4Coverage { // 覆盖面异常大：很可能是投毒或错误数据，整份拒绝
			return reject(fmt.Sprintf("IPv4 ranges cover %.0f%% of the address space", float64(covered)*100/float64(1<<32)))
		}
		idx.v4 = m
	}
	return idx
}

// ChinaCIDRs 返回直连网段（内置 APNIC 快照 ∪ 服务端下发的 IPv4 网段）的合并 CIDR 列表，供 TUN 路由规划使用。
func (e *SplitEngine) ChinaCIDRs() []string {
	if e == nil {
		return nil
	}
	merged := &ChinaIPMatcher{}
	if e.chinaMatcher != nil {
		merged.ranges = append(merged.ranges, e.chinaMatcher.ranges...)
	}
	if d := e.direct.Load(); d != nil && d.v4 != nil {
		merged.ranges = append(merged.ranges, d.v4.ranges...)
	}
	merged.normalize()
	return merged.ExportCIDRs()
}

// TotalRules 统计 APNIC 范围与所有 rules 的域名与 IP 范围总和
func (e *SplitEngine) TotalRules() int {
	e.mu.RLock()
	defer e.mu.RUnlock()

	total := 0
	if e.chinaMatcher != nil {
		total += e.chinaMatcher.TotalRanges()
	}
	if d := e.direct.Load(); d != nil {
		total += d.count
	}
	for _, r := range e.rules {
		total += len(r.DomainSuffixes)
		total += len(r.DomainKeywords)
		ipCount := len(r.parsedIPNets)
		if ipCount == 0 && len(r.IPRanges) > 0 {
			ipCount = len(r.IPRanges)
		}
		total += ipCount
	}
	return total
}

func (e *SplitEngine) loadBuiltinRules() {
	e.rules = append(e.rules, Rule{
		Name:           "AI Services",
		Strategy:       AI,
		DomainSuffixes: builtinAIDomains(),
	})

	e.rules = append(e.rules, Rule{
		Name:           "China Direct",
		Strategy:       DIRECT,
		DomainSuffixes: builtinChinaDomains(),
		// 国内 IP 判定只用 APNIC 数据（chinaMatcher）；此处不放手写网段，避免境外地址误直连
	})

	// 预解析 IPRanges
	for i := range e.rules {
		if len(e.rules[i].IPRanges) > 0 {
			e.rules[i].parsedIPNets = make([]*net.IPNet, 0, len(e.rules[i].IPRanges))
			for _, cidr := range e.rules[i].IPRanges {
				if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
					e.rules[i].parsedIPNets = append(e.rules[i].parsedIPNets, ipNet)
				}
			}
		}
	}
}

func builtinAIDomains() []string {
	return []string{
		"openai.com", "chatgpt.com", "api.openai.com",
		"anthropic.com", "claude.ai",
		"gemini.google.com", "aistudio.google.com", "generativelanguage.googleapis.com",
		"clients6.google.com", "googleapis.com", "deepmind.google", "deepmind.com",
		"api.groq.com", "api.perplexity.ai", "perplexity.ai", "api.cohere.ai",
		"api.together.xyz", "api.mistral.ai", "api.replicate.com",
		"api.deepseek.com", "platform.moonshot.cn", "api.siliconflow.cn",
		"api.qwen.ai", "api.baichuan-ai.com", "api.minimax.chat", "api.sparkdesk.cn",
		"huggingface.co", "api-inference.huggingface.co",
		"openrouter.ai", "api.fireworks.ai",
		"grok.com", "x.ai", "api.x.ai",
		"tavily.com", "api.tavily.com",
		"cursor.sh", "cursorapi.com", "anysphere.co",
	}
}

func builtinChinaDomains() []string {
	return []string{
		"cn", "qq.com", "weixin.qq.com", "wx.qq.com", "wechat.com", "tencent.com",
		"tenpay.com", "qcloud.com", "qpic.cn", "myqcloud.com", "gtimg.cn", "gtimg.com",
		"idqqimg.com", "sogou.com", "captcha.gtimg.com",
		"alibaba.com", "alicdn.com", "aliyun.com", "alipay.com", "taobao.com",
		"tmall.com", "mmstat.com", "aliyuncs.com", "cnzz.com",
		"baidu.com", "bdimg.com", "bdstatic.com",
		"bytedance.com", "douyin.com", "iesdouyin.com", "tiktokv.com", "byteimg.com",
		"163.com", "126.com", "netease.com",
		"jd.com", "360buyimg.com", "360.cn", "qhstatic.com", "qhimg.com",
		"msn.cn", "bing.cn",
		"bilibili.com", "hdslb.com", "zhihu.com", "weibo.com", "sina.com",
		"sinaimg.cn", "sina.cn", "douban.com", "doubanio.com",
		"xiaohongshu.com", "xhscdn.com", "gov.cn", "edu.cn", "org.cn",
		"icbc.com.cn", "icbc.com", "abchina.com", "abchina.com.cn",
		"boc.cn", "bankofchina.com", "ccb.com", "ccb.com.cn",
		"bankcomm.com", "95559.com.cn", "cmbchina.com", "cmbwinglung.com",
		"spdb.com.cn", "cmbc.com.cn", "cib.com.cn", "pingan.com", "pingan.com.cn",
		"citicbank.com", "ecitic.com", "cebbank.com", "hxb.com.cn", "psbc.com",
		"cgbchina.com.cn", "unionpay.com", "95516.com", "pbc.gov.cn",
		"sse.com.cn", "szse.cn", "bse.cn", "chinaclear.cn",
		// 视频、直播与媒体 CDN
		"bilivideo.com", "biliapi.net", "biliapi.com", "bilibili.tv",
		"iqiyi.com", "qiyi.com", "youku.com", "mgtv.com",
		"douyu.com", "huya.com", "kuaishou.com", "gifshow.com", "ixigua.com",
		// 云服务与骨干分发网络 CDN
		"aliyuncdn.com", "kunlungr.com", "tbcdn.cn", "tanx.com",
		"tencent-cloud.com", "baidubce.com", "bcebos.com",
		"upaiyun.com", "qiniu.com", "qiniucdn.com", "volces.com",
		"bytedns.net", "bytegoofy.com",
		// 开发者与技术社区
		"csdn.net", "csdnimg.cn", "v2ex.com", "segmentfault.com",
		"oschina.net", "gitee.com", "juejin.cn", "cnblogs.com", "runoob.com", "infoq.cn",
		// 门户、资讯与生活消费
		"toutiao.com", "toutiaocdn.com", "douyinpic.com", "snssdk.com", "pstatp.com",
		"sohu.com", "sina.com.cn", "163yun.com", "netease.im", "tieba.com",
		"meituan.com", "dianping.com", "ele.me", "alipayobjects.com", "suning.com",
		"pinduoduo.com", "yangkeduo.com", "jdcache.com",
		// 常用国民级应用与通信办公
		"amap.com", "gaode.com", "dingtalk.com", "yuque.com", "feishu.cn", "feishu.net",
		"10010.com", "10086.cn", "189.cn", "ctrip.com", "qunar.com", "fliggy.com",
		"autohome.com.cn", "dongchedi.com", "yiche.com", "58.com", "bosszhipin.com",
		"kugou.com", "kuwo.cn", "migu.cn", "miguvideo.com", "cctv.com", "cntv.cn",
		"xinhuanet.com", "people.com.cn", "tianyancha.com", "qcc.com", "eastmoney.com",
		"mi.com", "xiaomi.com", "huawei.com", "honor.com", "oppo.com", "vivo.com",
		// 公共 DNS、测速与诊断工具
		"alidns.com", "dnspod.cn", "114dns.com", "speedtest.cn", "ip138.com", "ip.cn", "chinaz.com",
	}
}

// ISPProbeTarget 运营商测速目标
type ISPProbeTarget struct {
	Code string
	Name string
	Addr string
}

// DefaultISPProbeTargets 预设各运营商骨干公共 DNS 探针
var DefaultISPProbeTargets = []ISPProbeTarget{
	{Code: "CT", Name: "中国电信", Addr: "218.2.135.1:53"},
	{Code: "CU", Name: "中国联通", Addr: "116.228.111.118:53"},
	{Code: "CM", Name: "中国移动", Addr: "211.136.192.6:53"},
}

// ISPProbeResult 运营商测速结果
type ISPProbeResult struct {
	BestISP string
	BestRTT time.Duration
	AllRTTs map[string]time.Duration
	ProbeAt time.Time
}

// DetectISP 执行轻量 DNS RTT 测速，快速判定客户端所处网络运营商
func DetectISP(ctx context.Context, timeout time.Duration) *ISPProbeResult {
	if timeout <= 0 {
		timeout = 800 * time.Millisecond
	}

	res := &ISPProbeResult{
		BestISP: "DEFAULT",
		BestRTT: 999 * time.Millisecond,
		AllRTTs: make(map[string]time.Duration),
		ProbeAt: time.Now(),
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, target := range DefaultISPProbeTargets {
		t := target
		wg.Add(1)
		go func() {
			defer wg.Done()
			rtt, err := probeTCPRTT(ctx, t.Addr, timeout)
			if err == nil && rtt > 0 {
				mu.Lock()
				res.AllRTTs[t.Code] = rtt
				if rtt < res.BestRTT {
					res.BestRTT = rtt
					res.BestISP = t.Code
				}
				mu.Unlock()
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
	case <-time.After(timeout):
	}

	return res
}

func probeTCPRTT(ctx context.Context, addr string, timeout time.Duration) (time.Duration, error) {
	d := net.Dialer{Timeout: timeout}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, err
	}
	rtt := time.Since(start)
	_ = conn.Close()
	return rtt, nil
}
