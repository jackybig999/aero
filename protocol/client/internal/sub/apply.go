// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package sub

import (
	"fmt"
	"net"
	"strings"
)

// Applied 应用到客户端运行时的扁平结果
type Applied struct {
	// EdgeAddresses 逗号分隔，兼容 edgepool.New
	EdgeAddresses string
	// PrimaryToken 首个节点 token
	PrimaryToken string
	// PrimarySNI 首个节点 SNI
	PrimarySNI string
	// PrimaryPins 首个节点 SPKI pins
	PrimaryPins []string
	// AllPins 包含所有有效节点的 SPKI pins
	AllPins []string
	// Tokens 地址 -> token（多节点）
	Tokens map[string]string
	// SNIs 地址 -> sni
	SNIs map[string]string
	// Servers 完整节点配置列表
	Servers []ServerConfig
}

// Apply 将订阅转为拨号参数
func Apply(s *Subscription) (*Applied, error) {
	if s == nil || len(s.Servers) == 0 {
		return nil, fmt.Errorf("empty subscription")
	}
	if s.IsExpired() {
		return nil, fmt.Errorf("subscription expired")
	}
	out := &Applied{
		Tokens: make(map[string]string),
		SNIs:   make(map[string]string),
	}
	var addrs []string
	var validServers []ServerConfig
	seenPins := make(map[string]bool)
	var allPins []string
	for _, srv := range s.Servers {
		addr := strings.TrimSpace(srv.Address)
		if addr == "" {
			continue
		}
		// 关键防护：如果节点地址是合法的公网域名且未配置自签 SPKI Pinning，
		// 严禁使用与证书域名不匹配的第三方伪装 SNI（如 edge.microsoft.com），
		// 必须自动修正为节点原生 host，保证标准 TLS 证书链校验 100% 通过！
		host, _, err := net.SplitHostPort(addr)
		if err == nil && net.ParseIP(host) == nil && host != "" {
			if srv.SNI == "" || srv.SNI == "cdn-aero.com" || srv.SNI == "edge.microsoft.com" || srv.SNI == "azureedge.net" || srv.SNI == "cloudflare.com" {
				srv.SNI = host
			}
		}
		validServers = append(validServers, srv)
		addrs = append(addrs, addr)
		out.Tokens[addr] = srv.Token
		if srv.SNI != "" {
			out.SNIs[addr] = srv.SNI
		}
		for _, p := range srv.PinSPKI {
			p = strings.TrimSpace(p)
			if p != "" && !seenPins[p] {
				seenPins[p] = true
				allPins = append(allPins, p)
			}
		}
	}
	if len(validServers) == 0 {
		return nil, fmt.Errorf("no valid server addresses")
	}
	out.EdgeAddresses = strings.Join(addrs, ",")
	out.PrimaryToken = validServers[0].Token
	out.PrimarySNI = validServers[0].SNI
	out.PrimaryPins = append([]string(nil), validServers[0].PinSPKI...)
	out.AllPins = allPins
	out.Servers = validServers
	return out, nil
}
