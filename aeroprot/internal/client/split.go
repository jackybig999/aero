// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"context"
	_ "embed"
	"encoding/binary"
	"net"
	"sort"
	"strings"
	"sync"
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

	sort.Slice(ranges, func(i, j int) bool {
		return ranges[i].start < ranges[j].start
	})

	if len(ranges) > 0 {
		merged := make([]ipRange, 0, len(ranges))
		curr := ranges[0]
		for i := 1; i < len(ranges); i++ {
			if ranges[i].start <= curr.end+1 {
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

// SplitEngine 智能分流规则引擎
type SplitEngine struct {
	mu              sync.RWMutex
	rules           []Rule
	chinaMatcher    *ChinaIPMatcher
	cache           map[string]Strategy
	cacheMu         sync.RWMutex
	cacheSize       int
	defaultStrategy Strategy
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

// SetDefaultStrategy 设置默认策略
func (e *SplitEngine) SetDefaultStrategy(s Strategy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.defaultStrategy = s
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
	if h == "" || h == "localhost" || h == "localhost." {
		return true
	}
	if ip == nil {
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

// ReloadRules 动态热加载直连分流规则库
func (e *SplitEngine) ReloadRules(data []byte) (int, error) {
	lines := strings.Split(string(data), "\n")
	var newDomains []string
	var newIPRanges []string

	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, _, err := net.ParseCIDR(line); err == nil {
			newIPRanges = append(newIPRanges, line)
		} else if ip := net.ParseIP(line); ip != nil {
			if ip.To4() != nil {
				newIPRanges = append(newIPRanges, line+"/32")
			} else {
				newIPRanges = append(newIPRanges, line+"/128")
			}
		} else {
			clean := strings.TrimPrefix(line, "domain:")
			clean = strings.TrimPrefix(clean, "full:")
			clean = strings.TrimSpace(clean)
			if clean != "" {
				newDomains = append(newDomains, clean)
			}
		}
	}

	newRule := Rule{
		Name:           "China Direct (Dynamic)",
		Strategy:       DIRECT,
		DomainSuffixes: newDomains,
		IPRanges:       newIPRanges,
	}

	e.mu.Lock()
	newRule.parsedIPNets = make([]*net.IPNet, 0, len(newRule.IPRanges))
	for _, cidr := range newRule.IPRanges {
		if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
			newRule.parsedIPNets = append(newRule.parsedIPNets, ipNet)
		}
	}

	filtered := make([]Rule, 0, len(e.rules)+1)
	for _, r := range e.rules {
		if r.Name == "China Direct" || r.Name == "China Direct (Dynamic)" {
			continue
		}
		filtered = append(filtered, r)
	}
	filtered = append(filtered, newRule)
	e.rules = filtered
	e.mu.Unlock()

	e.ClearCache()

	return len(newDomains) + len(newIPRanges), nil
}

// TotalRules 统计 APNIC 范围与所有 rules 的域名与 IP 范围总和
func (e *SplitEngine) TotalRules() int {
	e.mu.RLock()
	defer e.mu.RUnlock()

	total := 0
	if e.chinaMatcher != nil {
		total += e.chinaMatcher.TotalRanges()
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
		IPRanges:       builtinChinaIPRanges(),
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
		"api.groq.com", "api.perplexity.ai", "api.cohere.ai",
		"api.together.xyz", "api.mistral.ai", "api.replicate.com",
		"api.deepseek.com", "platform.moonshot.cn", "api.siliconflow.cn",
		"api.qwen.ai", "api.baichuan-ai.com", "api.minimax.chat", "api.sparkdesk.cn",
		"huggingface.co", "api-inference.huggingface.co",
		"openrouter.ai", "api.fireworks.ai",
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
		// 公共 DNS、测速与诊断工具
		"alidns.com", "dnspod.cn", "114dns.com", "speedtest.cn", "ip138.com", "ip.cn", "chinaz.com",
	}
}

func builtinChinaIPRanges() []string {
	return []string{
		"14.196.0.0/15", "36.128.0.0/10", "39.128.0.0/10", "42.96.0.0/11",
		"58.16.0.0/13", "58.240.0.0/12", "59.64.0.0/12", "60.160.0.0/11",
		"61.128.0.0/10", "101.64.0.0/13", "103.32.0.0/14", "106.32.0.0/12",
		"110.64.0.0/11", "111.0.0.0/10", "112.0.0.0/10", "113.64.0.0/10",
		"114.80.0.0/12", "115.24.0.0/13", "116.128.0.0/10", "117.128.0.0/10",
		"118.192.0.0/11", "119.32.0.0/11", "120.192.0.0/10", "121.32.0.0/14",
		"122.64.0.0/11", "123.64.0.0/11", "124.64.0.0/12", "125.64.0.0/11",
		"180.64.0.0/11", "182.32.0.0/13", "183.0.0.0/10", "202.96.0.0/12",
		"203.208.0.0/12", "210.32.0.0/12", "211.96.0.0/11", "218.0.0.0/11",
		"219.128.0.0/11", "220.128.0.0/11", "221.0.0.0/11", "222.0.0.0/11",
		"223.0.0.0/12",
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
