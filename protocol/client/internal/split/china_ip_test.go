// Copyright 2026 AERO Protocol Contributors
package split

import (
	"net"
	"testing"
)

func TestChinaIPMatcher_KnownIPs(t *testing.T) {
	m := NewChinaIPMatcher()
	if m.TotalRanges() < 1000 {
		t.Fatalf("Expected at least 1000 aggregated IP ranges, got %d", m.TotalRanges())
	}

	chinaIPs := []string{
		"114.114.114.114", // 114 DNS (Nanjing)
		"223.5.5.5",       // AliDNS (Hangzhou)
		"119.29.29.29",    // DNSPod (Shenzhen)
		"180.101.50.242",  // Baidu (Jiangsu)
		"123.125.114.144", // Baidu (Beijing)
		"14.215.177.39",   // Baidu (Guangdong)
		"36.152.44.95",    // Sina (Zhejiang)
		"111.13.101.208",  // Tencent (Beijing)
		"101.226.103.106", // Tencent (Shanghai)
		"117.136.0.1",     // China Mobile
	}

	for _, ipStr := range chinaIPs {
		ip := net.ParseIP(ipStr)
		if !m.Contains(ip) {
			t.Errorf("Expected China IP %s to be recognized as China, but got false", ipStr)
		}
	}

	overseasIPs := []string{
		"8.8.8.8",         // Google DNS
		"1.1.1.1",         // Cloudflare DNS
		"208.67.222.222",  // OpenDNS
		"140.82.112.4",    // GitHub
		"192.210.193.197", // Our VPS
		"104.244.42.1",    // Twitter
		"157.240.22.35",   // Facebook
		"127.0.0.1",       // Loopback
	}

	for _, ipStr := range overseasIPs {
		ip := net.ParseIP(ipStr)
		if m.Contains(ip) {
			t.Errorf("Expected Overseas IP %s to NOT be recognized as China, but got true", ipStr)
		}
	}
}

func BenchmarkChinaIPMatcher_Contains(b *testing.B) {
	m := NewChinaIPMatcher()
	ip := net.ParseIP("180.101.50.242")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = m.Contains(ip)
	}
}

func TestEngine_ChinaIPAndPreParsedRules(t *testing.T) {
	eng := NewEngine()

	// 1. Direct domestic IP
	s := eng.Match("223.5.5.5", net.ParseIP("223.5.5.5"))
	if s != DIRECT {
		t.Fatalf("Expected 223.5.5.5 to match DIRECT, got %v", s)
	}

	// 2. Direct domestic domain
	s = eng.MatchDomain("www.baidu.com")
	if s != DIRECT {
		t.Fatalf("Expected www.baidu.com to match DIRECT, got %v", s)
	}

	// 3. AI domain
	s = eng.MatchDomain("api.openai.com")
	if s != AI {
		t.Fatalf("Expected api.openai.com to match AI, got %v", s)
	}

	// 4. Overseas IP
	s = eng.Match("140.82.112.4", net.ParseIP("140.82.112.4"))
	if s != PROXY {
		t.Fatalf("Expected GitHub IP to match PROXY, got %v", s)
	}
}

