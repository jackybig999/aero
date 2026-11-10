// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
)

// TestDNS_DoH_RealPublicIP_Over_FakeIP 门禁: 验证开启 DoH 时返回真实公网 IP，彻底消灭 Fake-IP 黑洞
func TestDNS_DoH_RealPublicIP_Over_FakeIP(t *testing.T) {
	split := NewSplitEngine()
	dnsHandler := NewDNSHandler(split)

	var dohCalled atomic.Int32
	realGoogleIP := net.ParseIP("142.250.190.46").To4()

	dnsHandler.SetDoHResolver(func(ctx context.Context, dnsReq []byte) ([]byte, error) {
		dohCalled.Add(1)
		qname, _ := extractDNSQuestionAndType(dnsReq)
		return buildAResponse(dnsReq, qname, realGoogleIP), nil
	})

	// 1. 模拟浏览器请求 google.com Type A
	queryPkt := buildDNSQuery("google.com", 0x0001)
	resp := dnsHandler.HandleQuery(queryPkt, net.ParseIP("10.88.0.2"), 54321)
	if resp == nil {
		t.Fatal("HandleQuery returned nil response")
	}

	if dohCalled.Load() != 1 {
		t.Fatalf("expected dohResolver to be called once, got %d", dohCalled.Load())
	}

	firstIP := extractFirstAAnswer(resp)
	if firstIP == nil {
		t.Fatal("no A answer in DNS response")
	}

	// 核心断言: 必须为真实公网 IP 142.250.190.46，绝不可落入 198.18.0.0/15 Fake-IP 网段
	if !firstIP.Equal(realGoogleIP) {
		t.Fatalf("expected real IP %v, got %v", realGoogleIP, firstIP)
	}
	if dnsHandler.FakeIP().Contains(firstIP) {
		t.Fatalf("CRITICAL: returned IP %v is inside Fake-IP subnet 198.18.0.0/15!", firstIP)
	}

	// 2. 第二次请求: 必须命中 0ms 内存缓存，不再发起远程 DoH
	queryPkt2 := buildDNSQuery("google.com", 0x0001)
	resp2 := dnsHandler.HandleQuery(queryPkt2, net.ParseIP("10.88.0.2"), 54321)
	if resp2 == nil {
		t.Fatal("HandleQuery cached query returned nil")
	}

	if dohCalled.Load() != 1 {
		t.Fatalf("expected dohResolver NOT called again (cache hit), got %d", dohCalled.Load())
	}
	cachedIP := extractFirstAAnswer(resp2)
	if !cachedIP.Equal(realGoogleIP) {
		t.Fatalf("expected cached IP %v, got %v", realGoogleIP, cachedIP)
	}
}

// TestDNS_DoH_NilFallbackToFakeIP 门禁: 验证未提供 DoH 时向下兼容回退 Fake-IP
func TestDNS_DoH_NilResolverReturnsServFail(t *testing.T) {
	split := NewSplitEngine()
	dnsHandler := NewDNSHandler(split)
	dnsHandler.SetDoHResolver(nil) // 显式置空

	queryPkt := buildDNSQuery("openai.com", 0x0001)
	resp := dnsHandler.HandleQuery(queryPkt, net.ParseIP("10.88.0.2"), 54321)
	if resp == nil {
		t.Fatal("HandleQuery returned nil")
	}

	requireServFail(t, resp, "openai.com A with nil DoH resolver")
}

// TestDNS_ParseFirstIPv4_CNAME_And_EDNS0 门禁: 验证 RFC 1035 解析器跨越 CNAME 链、忽略 EDNS0 OPT 伪记录提取真实 IP
func TestDNS_ParseFirstIPv4_CNAME_And_EDNS0(t *testing.T) {
	// 构造含 CNAME + A + EDNS0 OPT 的真实 DNS 报文
	// Header: ID=0x1234, Flags=0x8180 (Response, NoError), QD=1, AN=2, NS=0, AR=1 (EDNS0)
	pkt := []byte{
		0x12, 0x34, 0x81, 0x80,
		0x00, 0x01, // QDCOUNT=1
		0x00, 0x02, // ANCOUNT=2
		0x00, 0x00, // NSCOUNT=0
		0x00, 0x01, // ARCOUNT=1
	}
	// Question: api.openai.com Type A Class IN
	pkt = append(pkt, encodeDNSName("api.openai.com")...)
	pkt = append(pkt, 0x00, 0x01, 0x00, 0x01)

	// Answer 1: CNAME prod-api.openai.com
	pkt = append(pkt, 0xC0, 0x0C)             // Name pointer to api.openai.com
	pkt = append(pkt, 0x00, 0x05)             // Type CNAME
	pkt = append(pkt, 0x00, 0x01)             // Class IN
	pkt = append(pkt, 0x00, 0x00, 0x01, 0x2C) // TTL 300
	cnameTarget := encodeDNSName("prod-api.openai.com")
	pkt = append(pkt, byte(len(cnameTarget)>>8), byte(len(cnameTarget)))
	pkt = append(pkt, cnameTarget...)

	// Answer 2: Type A 104.18.32.100
	pkt = append(pkt, 0xC0, 0x0C)             // Name pointer
	pkt = append(pkt, 0x00, 0x01)             // Type A
	pkt = append(pkt, 0x00, 0x01)             // Class IN
	pkt = append(pkt, 0x00, 0x00, 0x01, 0x2C) // TTL 300
	pkt = append(pkt, 0x00, 0x04)             // rdlength=4
	pkt = append(pkt, 104, 18, 32, 100)       // RDATA IPv4

	// Additional: EDNS0 OPT record (11 bytes)
	pkt = append(pkt, 0x00)                   // Root domain
	pkt = append(pkt, 0x00, 0x29)             // Type OPT (41)
	pkt = append(pkt, 0x10, 0x00)             // Payload size 4096
	pkt = append(pkt, 0x00, 0x00, 0x00, 0x00) // Flags
	pkt = append(pkt, 0x00, 0x00)             // RDLENGTH 0

	ip := parseFirstIPv4FromDNSResponse(pkt)
	if ip == nil {
		t.Fatal("expected IPv4 to be parsed from CNAME+A+EDNS0 packet, got nil")
	}
	expectedIP := net.IPv4(104, 18, 32, 100)
	if !ip.Equal(expectedIP) {
		t.Fatalf("expected parsed IP %v, got %v", expectedIP, ip)
	}
}

// TestDNS_ParseFirstIPv4_Malformed 门禁: 验证畸变、截断、死循环指针等异常报文零 panic
func TestDNS_ParseFirstIPv4_Malformed(t *testing.T) {
	testCases := [][]byte{
		nil,
		{},
		{0x01, 0x02, 0x03},
		// 截断头部
		{0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01},
		// 非法标签长度
		{0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x7F, 0x01, 0x02},
		// 指针越界
		{0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xC0},
		// rdlength 越界
		{0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF},
	}
	for i, tc := range testCases {
		ip := parseFirstIPv4FromDNSResponse(tc)
		if ip != nil {
			t.Errorf("case %d: expected nil for malformed packet, got %v", i, ip)
		}
	}
}
