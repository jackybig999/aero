// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package split 实现智能分流规则引擎。
//
// 支持三种分流策略：
//   - DIRECT：直连，不经过代理（国内流量）
//   - PROXY：走 AERO 代理隧道（国外流量）
//   - AI：走 AI 优化通道（低延迟、首 Token 追踪）
//
// 规则优先级：AI 域名 > 国内域名 > IP 段 > 关键词 > 默认策略
package split

import (
	"net"
	"strings"
	"sync"
)

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
	Name     string
	Strategy Strategy
	// 匹配条件（OR 关系，任一匹配即生效）
	DomainSuffixes []string // 域名后缀匹配
	DomainKeywords []string // 域名关键词匹配
	IPRanges       []string // IP CIDR 匹配
	BundleIDs      []string // iOS Bundle ID 匹配（平台特定）

	// parsedIPNets 预解析的 IPNet 切片，消除热路径重复 ParseCIDR 开销
	parsedIPNets []*net.IPNet
}

// Engine 分流引擎
type Engine struct {
	mu sync.RWMutex

	// 规则列表（按优先级排序）
	rules []Rule

	// chinaMatcher 权威 APNIC 中国大陆 IP 数据库匹配器 (O(log N)，0 内存分配)
	chinaMatcher *ChinaIPMatcher

	// 缓存
	cache     map[string]Strategy
	cacheMu   sync.RWMutex
	cacheSize int

	// 默认策略
	defaultStrategy Strategy
}

// NewEngine 创建分流引擎
func NewEngine() *Engine {
	e := &Engine{
		rules:           make([]Rule, 0),
		chinaMatcher:    NewChinaIPMatcher(),
		cache:           make(map[string]Strategy),
		cacheSize:       10000,
		defaultStrategy: PROXY,
	}
	// 加载内置规则
	e.loadBuiltinRules()
	return e
}

// SetDefaultStrategy 设置默认策略
func (e *Engine) SetDefaultStrategy(s Strategy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.defaultStrategy = s
}

// AddRule 添加规则（对 IPRanges 进行一次性预解析，消除运行时开销）
func (e *Engine) AddRule(r Rule) {
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

// Match 根据域名/IP 匹配分流策略
func (e *Engine) Match(host string, ip net.IP) Strategy {
	// 检查缓存
	e.cacheMu.RLock()
	if s, ok := e.cache[host]; ok {
		e.cacheMu.RUnlock()
		return s
	}
	e.cacheMu.RUnlock()

	// host may be "host:port" from SOCKS/HTTP — strip port for IP parse
	hostOnly := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostOnly = h
	}
	hostOnly = strings.Trim(hostOnly, "[]")
	if ip == nil {
		ip = net.ParseIP(hostOnly)
	}
	// Never send loopback/private/link-local through edge (avoids proxy loops + SSRF waste)
	if isLocalOrPrivate(hostOnly, ip) {
		e.setCache(host, DIRECT)
		return DIRECT
	}

	// 核心加速：如果目标 IP 属于中国大陆 IP 网段，直接快速判定为 DIRECT（直连），绝对不推向海外 VPS！
	if ip != nil && e.chinaMatcher != nil && e.chinaMatcher.Contains(ip) {
		e.setCache(host, DIRECT)
		return DIRECT
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	// 按优先级匹配规则
	for _, rule := range e.rules {
		if matchRule(rule, hostOnly, ip) {
			e.setCache(host, rule.Strategy)
			return rule.Strategy
		}
	}

	// 默认策略
	e.setCache(host, e.defaultStrategy)
	return e.defaultStrategy
}

func isLocalOrPrivate(host string, ip net.IP) bool {
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
	// CGNAT / special-use
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 { // 100.64/10
			return true
		}
	}
	return false
}

// MatchDomain 仅根据域名匹配
func (e *Engine) MatchDomain(domain string) Strategy {
	return e.Match(domain, nil)
}

// MatchIP 仅根据 IP 匹配
func (e *Engine) MatchIP(ip net.IP) Strategy {
	return e.Match(ip.String(), ip)
}

func matchRule(r Rule, host string, ip net.IP) bool {
	hostLower := strings.ToLower(host)

	// 域名后缀匹配（foo.example.com 匹配 example.com，避免 evilmicrosoft.com 误匹配）
	for _, suffix := range r.DomainSuffixes {
		s := strings.ToLower(suffix)
		if hostLower == s || strings.HasSuffix(hostLower, "."+s) {
			return true
		}
	}

	// 域名关键词匹配
	for _, keyword := range r.DomainKeywords {
		if strings.Contains(hostLower, strings.ToLower(keyword)) {
			return true
		}
	}

	// IP 段匹配（优先使用预解析的 parsedIPNets，零内存分配）
	if ip != nil {
		if len(r.parsedIPNets) > 0 {
			for _, ipNet := range r.parsedIPNets {
				if ipNet.Contains(ip) {
					return true
				}
			}
		} else {
			for _, cidr := range r.IPRanges {
				_, ipNet, err := net.ParseCIDR(cidr)
				if err != nil {
					continue
				}
				if ipNet.Contains(ip) {
					return true
				}
			}
		}
	}

	return false
}

func (e *Engine) setCache(key string, s Strategy) {
	e.cacheMu.Lock()
	defer e.cacheMu.Unlock()
	if len(e.cache) >= e.cacheSize {
		// 简单淘汰：清空一半
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
func (e *Engine) ClearCache() {
	e.cacheMu.Lock()
	defer e.cacheMu.Unlock()
	e.cache = make(map[string]Strategy)
}

// loadBuiltinRules 加载内置规则
func (e *Engine) loadBuiltinRules() {
	// === AI 服务规则（最高优先级）===
	e.rules = append(e.rules, Rule{
		Name:           "AI Services",
		Strategy:       AI,
		DomainSuffixes: aiDomains(),
	})

	// === 国内直连规则 ===
	e.rules = append(e.rules, Rule{
		Name:           "China Direct",
		Strategy:       DIRECT,
		DomainSuffixes: chinaDomains(),
		IPRanges:       chinaIPRanges(),
	})

	// === 游戏平台规则 ===
	e.rules = append(e.rules, Rule{
		Name:           "Gaming",
		Strategy:       PROXY, // 游戏走代理但使用 Game QoS
		DomainSuffixes: gamingDomains(),
	})

	// === Apple 服务规则 ===
	e.rules = append(e.rules, Rule{
		Name:           "Apple Services",
		Strategy:       DIRECT,
		DomainSuffixes: appleDomains(),
	})
}

// aiDomains AI 服务域名列表
func aiDomains() []string {
	return []string{
		"openai.com",
		"chatgpt.com",
		"api.openai.com",
		"anthropic.com",
		"claude.ai",
		"gemini.google.com",
		"aistudio.google.com",
		"generativelanguage.googleapis.com",
		"api.groq.com",
		"api.perplexity.ai",
		"api.cohere.ai",
		"api.together.xyz",
		"api.mistral.ai",
		"api.replicate.com",
		"api.deepseek.com",
		"platform.moonshot.cn",
		"api.siliconflow.cn",
		"api.qwen.ai",
		"api.baichuan-ai.com",
		"api.minimax.chat",
		"api.sparkdesk.cn",
		"huggingface.co",
		"api-inference.huggingface.co",
		"openrouter.ai",
		"api.fireworks.ai",
	}
}

// chinaDomains 国内直连域名列表（后缀匹配）
// 注意：系统代理开启后，国内站若仍走 PROXY 会占满 edge 并发 → 503。
func chinaDomains() []string {
	return []string{
		// 腾讯
		"qq.com", "weixin.qq.com", "wx.qq.com", "wechat.com", "tencent.com",
		"tenpay.com", "qcloud.com", "qpic.cn", "myqcloud.com", "gtimg.cn", "gtimg.com",
		"idqqimg.com", "sogou.com", "captcha.gtimg.com",
		// 阿里
		"alibaba.com", "alicdn.com", "aliyun.com", "alipay.com", "taobao.com",
		"tmall.com", "mmstat.com", "aliyuncs.com", "cnzz.com",
		// 百度
		"baidu.com", "bdimg.com", "bdstatic.com",
		// 字节
		"bytedance.com", "douyin.com", "iesdouyin.com", "tiktokv.com", "byteimg.com",
		// 网易
		"163.com", "126.com", "netease.com",
		// 京东
		"jd.com", "360buyimg.com",
		// 360 / 广告监测（系统代理时常见噪声）
		"360.cn", "qhstatic.com", "qhimg.com", "fenxi.com", "mediav.com",
		// 微软 / 必应（cn.bing.com、www.bing.com 必须直连，否则占满隧道）
		"msn.cn", "bing.cn", "bing.com", "microsoft.com", "msn.com", "live.com",
		"office.com", "office365.com", "windows.com", "windowsupdate.com",
		"msftconnecttest.com", "msedge.net", "azureedge.net", "msecnd.net",
		"trafficmanager.net", "clarity.ms", "scorecardresearch.com",
		"microsoftpersonalcontent.com", "sharepoint.com", "onedrive.com",
		"akamaized.net", "edgeassetservice.azureedge.net",
		// 其他
		"bilibili.com", "hdslb.com", "zhihu.com", "weibo.com", "sina.com",
		"sinaimg.cn", "sina.cn", "douban.com", "doubanio.com",
		"xiaohongshu.com", "xhscdn.com",
		// 政府/教育
		"gov.cn", "edu.cn", "org.cn",
		// CDN
		"upaiyun.com", "chinanetcenter.com", "wangsu.com",
		// 银行
		"icbc.com.cn", "ccb.com", "boc.cn", "bankcomm.com", "cmbchina.com", "abchina.com",
	}
}

// chinaIPRanges 国内 IP 段（简化版，生产环境建议使用 APNIC/ CNNIC 准确数据）
func chinaIPRanges() []string {
	return []string{
		// 中国电信/联通/移动主要骨干网段（简化，不全）
		"14.196.0.0/15",
		"36.128.0.0/10",
		"39.128.0.0/10",
		"42.96.0.0/11",
		"58.16.0.0/13",
		"58.240.0.0/12",
		"59.64.0.0/12",
		"60.160.0.0/11",
		"61.128.0.0/10",
		"101.64.0.0/13",
		"103.32.0.0/14",
		"106.32.0.0/12",
		"110.64.0.0/11",
		"111.0.0.0/10",
		"112.0.0.0/10",
		"113.64.0.0/10",
		"114.80.0.0/12",
		"115.24.0.0/13",
		"116.128.0.0/10",
		"117.128.0.0/10",
		"118.192.0.0/11",
		"119.32.0.0/11",
		"120.192.0.0/10",
		"121.32.0.0/14",
		"122.64.0.0/11",
		"123.64.0.0/11",
		"124.64.0.0/12",
		"125.64.0.0/11",
		"180.64.0.0/11",
		"182.32.0.0/13",
		"183.0.0.0/10",
		"202.96.0.0/12",
		"203.208.0.0/12",
		"210.32.0.0/12",
		"211.96.0.0/11",
		"218.0.0.0/11",
		"219.128.0.0/11",
		"220.160.0.0/11",
		"221.192.0.0/11",
		"222.128.0.0/11",
		"223.64.0.0/11",
	}
}

// gamingDomains 游戏相关域名
func gamingDomains() []string {
	return []string{
		"steamcommunity.com",
		"steampowered.com",
		"steamgames.com",
		"epicgames.com",
		"unrealengine.com",
		"battle.net",
		"blizzard.com",
		"activision.com",
		"ea.com",
		"origin.com",
		"xbox.com",
		"xboxlive.com",
		"playstation.com",
		"sonyentertainmentnetwork.com",
		"nintendo.com",
		"nintendo.net",
		"riotgames.com",
		"valorant.com",
		"leagueoflegends.com",
		"pubg.com",
		"pubgmobile.com",
		"tencentgames.com",
		"igamecj.com",
		"supercell.com",
		"clashofclans.com",
		"fortnite.com",
		"pubgesports.com",
		"roblox.com",
		"minecraft.net",
		"mojang.com",
	}
}

// appleDomains Apple 服务域名
func appleDomains() []string {
	return []string{
		"apple.com",
		"icloud.com",
		"me.com",
		"mac.com",
		"apple-dns.net",
		"push-apple.com",
		"icloud-content.com",
	}
}

// IsAIFlow 检查是否为 AI 流量（快捷方法）
func (e *Engine) IsAIFlow(host string) bool {
	return e.MatchDomain(host) == AI
}

// IsDirect 检查是否直连
func (e *Engine) IsDirect(host string) bool {
	return e.MatchDomain(host) == DIRECT
}
