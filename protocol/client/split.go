// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"net"
	"strings"
	"sync"
)

// RouteAction 分流路由决策动作
type RouteAction int

const (
	RouteDirect RouteAction = iota // 直连（国内白名单、局域网、私有地址）
	RouteProxy                     // 代理（常规海外网站）
	RouteAI                        // AI 专线（OpenAI / Anthropic / Claude / Cursor 等）
)

func (a RouteAction) String() string {
	switch a {
	case RouteDirect:
		return "direct"
	case RouteProxy:
		return "proxy"
	case RouteAI:
		return "ai"
	default:
		return "proxy"
	}
}

// SplitEngine 分流路由决策引擎
type SplitEngine struct {
	mu           sync.RWMutex
	aiDomains    map[string]struct{}
	directSuffix []string
	privateCIDRs []*net.IPNet
}

// NewSplitEngine 创建默认分流引擎
func NewSplitEngine() *SplitEngine {
	e := &SplitEngine{
		aiDomains: make(map[string]struct{}),
		directSuffix: []string{
			".cn", ".edu.cn", ".gov.cn", ".org.cn", ".com.cn",
			".local", ".localhost", ".internal", ".lan",
			"baidu.com", "qq.com", "taobao.com", "alipay.com",
			"bilibili.com", "jd.com", "zhihu.com", "weibo.com",
		},
	}

	// AI 核心白名单域名
	aiList := []string{
		"openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com",
		"anthropic.com", "claude.ai",
		"cursor.sh", "cursorapi.com",
		"githubcopilot.com", "copilot-proxy.githubusercontent.com",
	}
	for _, d := range aiList {
		e.aiDomains[d] = struct{}{}
	}

	// 私网 CIDR
	cidrs := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7",
	}
	for _, c := range cidrs {
		if _, ipNet, err := net.ParseCIDR(c); err == nil {
			e.privateCIDRs = append(e.privateCIDRs, ipNet)
		}
	}

	return e
}

// MatchRoute 判断目标主机/IP 的分流走向
func (e *SplitEngine) MatchRoute(target string) RouteAction {
	e.mu.RLock()
	defer e.mu.RUnlock()

	host := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSpace(host))

	// 1. IP 形式判定
	if ip := net.ParseIP(host); ip != nil {
		for _, cidr := range e.privateCIDRs {
			if cidr.Contains(ip) {
				return RouteDirect
			}
		}
		return RouteProxy
	}

	// 2. AI 专线域名优先判定
	for aiDomain := range e.aiDomains {
		if host == aiDomain || strings.HasSuffix(host, "."+aiDomain) {
			return RouteAI
		}
	}

	// 3. 直连域名后缀判定
	for _, sfx := range e.directSuffix {
		if strings.HasSuffix(host, sfx) {
			return RouteDirect
		}
	}

	// 4. 其余默认常规海外代理
	return RouteProxy
}
