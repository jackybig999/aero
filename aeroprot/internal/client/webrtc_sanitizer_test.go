// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

func TestDomesticIPv6Detection(t *testing.T) {
	cases := []struct {
		ip       string
		expected bool
	}{
		{"240e:398:1234::1", true},      // China Telecom
		{"2408:8000:1::1", true},        // China Unicom
		{"2409:8000:2::1", true},        // China Mobile
		{"2001:da8:1000::1", true},      // CERNET
		{"fd88::2", false},              // Virtual NIC IPv6
		{"2607:f8b0:4005::200e", false}, // Google IPv6
		{"2606:4700:4700::1111", false}, // Cloudflare IPv6
		{"192.168.1.1", false},          // IPv4
		{"127.0.0.1", false},            // IPv4
	}

	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("failed to parse IP %s", tc.ip)
		}
		got := IsDomesticIPv6(ip)
		if got != tc.expected {
			t.Errorf("IsDomesticIPv6(%s) = %v; want %v", tc.ip, got, tc.expected)
		}
	}
}

func TestSanitizeSDP(t *testing.T) {
	rawSDP := "v=0\r\n" +
		"o=- 123456 2 IN IP4 127.0.0.1\r\n" +
		"s=-\r\n" +
		"t=0 0\r\n" +
		"c=IN IP6 240e:398:1234::1\r\n" +
		"a=candidate:1 1 UDP 2130706431 240e:398:1234::1 54321 typ host\r\n" +
		"a=candidate:2 1 UDP 2130706431 2408:8000:1::1 54322 typ host\r\n" +
		"a=candidate:3 1 UDP 2130706431 fd88::2 54323 typ host\r\n" +
		"a=candidate:4 1 UDP 1694498815 198.51.100.1 54324 typ srflx\r\n" +
		"a=end-of-candidates\r\n"

	sanitized := SanitizeSDP(rawSDP)

	// Must strip China Telecom and China Unicom
	if strings.Contains(sanitized, "240e:398:1234::1") {
		t.Errorf("expected 240e: carrier IP stripped, found in sanitized: %s", sanitized)
	}
	if strings.Contains(sanitized, "2408:8000:1::1") {
		t.Errorf("expected 2408: carrier IP stripped, found in sanitized: %s", sanitized)
	}

	// Must preserve virtual IPv6 (fd88::2) and server reflexive IP (198.51.100.1)
	if !strings.Contains(sanitized, "fd88::2") {
		t.Errorf("expected virtual IPv6 fd88::2 preserved, missing: %s", sanitized)
	}
	if !strings.Contains(sanitized, "198.51.100.1") {
		t.Errorf("expected srflx IP 198.51.100.1 preserved, missing: %s", sanitized)
	}

	// c= line should be rewritten to virtual IPv6
	if !strings.Contains(sanitized, "c=IN IP6 fd88::2") {
		t.Errorf("expected c= line rewritten to fd88::2, got: %s", sanitized)
	}
}

func buildTestSTUNPacketWithIPv6(carrierIP net.IP) []byte {
	pkt := make([]byte, 20+24) // 20 header + 24 attribute (type=2, len=2, value=20)
	// Header: Binding Success Response (0x0101)
	binary.BigEndian.PutUint16(pkt[0:2], 0x0101)
	binary.BigEndian.PutUint16(pkt[2:4], 24) // msgLen
	// Magic cookie
	binary.BigEndian.PutUint32(pkt[4:8], 0x2112A442)
	// Transaction ID (12 bytes)
	for i := 8; i < 20; i++ {
		pkt[i] = byte(i)
	}

	// Attribute: XOR-MAPPED-ADDRESS (0x0020)
	binary.BigEndian.PutUint16(pkt[20:22], 0x0020)
	binary.BigEndian.PutUint16(pkt[22:24], 20) // 1 res + 1 fam + 2 port + 16 ip
	pkt[24] = 0x00
	pkt[25] = 0x02                                       // IPv6
	binary.BigEndian.PutUint16(pkt[26:28], 0x2112^54321) // XOR port

	cookieAndTID := pkt[4:20]
	ip16 := carrierIP.To16()
	for i := 0; i < 16; i++ {
		pkt[28+i] = ip16[i] ^ cookieAndTID[i]
	}

	return pkt
}

func TestSTUNSanitizer(t *testing.T) {
	carrierIP := net.ParseIP("240e:398:1234:5678::1")
	stunPkt := buildTestSTUNPacketWithIPv6(carrierIP)

	// 1. Verify detection
	if !ContainsDomesticSTUNCandidate(stunPkt) {
		t.Fatalf("expected ContainsDomesticSTUNCandidate to return true for 240e:")
	}

	// 2. Sanitize
	sanitized := SanitizeSTUNPacket(stunPkt)

	// After sanitization, it should NO LONGER contain domestic carrier IP
	if ContainsDomesticSTUNCandidate(sanitized) {
		t.Fatalf("expected ContainsDomesticSTUNCandidate to return false after sanitization")
	}

	// Check that the address in sanitized packet matches fd88::2
	cookieAndTID := sanitized[4:20]
	var recoveredIP net.IP = make(net.IP, 16)
	for i := 0; i < 16; i++ {
		recoveredIP[i] = sanitized[28+i] ^ cookieAndTID[i]
	}

	expectedIP := net.ParseIP("fd88::2")
	if !recoveredIP.Equal(expectedIP) {
		t.Fatalf("expected sanitized STUN IP to be %s, got %s", expectedIP, recoveredIP)
	}
}

func TestDNS_EdgeHost_AAAA_InstantEmptyResponse(t *testing.T) {
	split := NewSplitEngine()
	dnsHandler := NewDNSHandler(split)
	dnsHandler.SetEdge("us.myconsun.de5.net", net.ParseIP("198.51.100.1"))

	// A query returns A response with 198.51.100.1
	reqA := buildDNSQuery("us.myconsun.de5.net", 0x0001)
	respA := dnsHandler.HandleQuery(reqA, net.ParseIP("10.88.0.2"), 53)
	if respA == nil {
		t.Fatalf("expected non-nil A response for edgeHost")
	}

	// AAAA query (0x001C) must immediately return an empty NOERROR response (not nil!) to prevent 10s timeouts
	reqAAAA := buildDNSQuery("us.myconsun.de5.net", 0x001C)
	respAAAA := dnsHandler.HandleQuery(reqAAAA, net.ParseIP("10.88.0.2"), 53)
	if respAAAA == nil {
		t.Fatalf("expected non-nil empty response for edgeHost AAAA query to prevent 10s timeout, got nil")
	}
	ancount := binary.BigEndian.Uint16(respAAAA[6:8])
	if ancount != 0 {
		t.Fatalf("expected 0 answers for edgeHost AAAA response, got %d", ancount)
	}
	rcode := respAAAA[3] & 0x0F
	if rcode != 0 {
		t.Fatalf("expected NOERROR (0) rcode, got %d", rcode)
	}
}

func TestBDPStackBuffers(t *testing.T) {
	mockDev := newMockTunDevice()
	defer mockDev.Close()

	stackEng := NewStackEngine(mockDev, nil, nil)
	if err := stackEng.Start(); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	defer stackEng.Stop()

	if stackEng.gvStack == nil {
		t.Fatalf("expected gvStack to be initialized")
	}
}
