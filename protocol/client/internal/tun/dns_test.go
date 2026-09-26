// Copyright 2026 AERO Protocol Contributors
package tun

import (
	"encoding/binary"
	"net"
	"testing"
)

type mockSplitDecider struct {
	decisions map[string]string
}

func (m *mockSplitDecider) Decide(domain string) string {
	if res, ok := m.decisions[domain]; ok {
		return res
	}
	return "proxy"
}

func buildDNSQueryPacket(domain string, qtype uint16) []byte {
	pkt := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // Standard query
		0x00, 0x01, // 1 question
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	pkt = append(pkt, encodeDNSName(domain)...)
	pkt = append(pkt, byte(qtype>>8), byte(qtype))
	pkt = append(pkt, 0x00, 0x01) // Class IN
	return pkt
}

func TestDNSHandler_EdgeNodeProtection(t *testing.T) {
	h := NewDNSHandler([]string{"223.5.5.5"})
	h.SetEdge("edge.example.com", net.ParseIP("192.210.193.197"))

	fakeIP := NewFakeIPTable("198.18.0.0/15", 1000)
	h.SetFakeIP(fakeIP)

	query := buildDNSQueryPacket("edge.example.com", 0x0001)
	resp := h.HandleQuery(query, net.ParseIP("127.0.0.1"), 12345)
	if resp == nil {
		t.Fatalf("Expected response for edge node, got nil")
	}

	// Verify ID matches
	if resp[0] != 0x12 || resp[1] != 0x34 {
		t.Fatalf("Query ID mismatch")
	}

	// Verify returned IP is 192.210.193.197 (NOT in 198.18.0.0/15)
	ansIP := net.IP(resp[len(resp)-4:])
	if !ansIP.Equal(net.ParseIP("192.210.193.197")) {
		t.Fatalf("Expected edge real IP 192.210.193.197, got %v", ansIP)
	}
}

func TestDNSHandler_NCSIBypass(t *testing.T) {
	h := NewDNSHandler([]string{"223.5.5.5"})

	query := buildDNSQueryPacket("www.msftconnecttest.com", 0x0001)
	resp := h.HandleQuery(query, net.ParseIP("127.0.0.1"), 12345)
	if resp != nil {
		t.Fatalf("Expected NCSI domain to return nil (passthrough), got response")
	}
}

func TestDNSHandler_FakeIP_A_and_AAAA(t *testing.T) {
	h := NewDNSHandler([]string{"223.5.5.5"})
	fakeIP := NewFakeIPTable("198.18.0.0/15", 1000)
	h.SetFakeIP(fakeIP)
	h.SetSplit(&mockSplitDecider{decisions: map[string]string{
		"google.com": "proxy",
	}})

	// 1. Type A -> Should return Fake-IP in 198.18.0.0/15
	qA := buildDNSQueryPacket("google.com", 0x0001)
	respA := h.HandleQuery(qA, net.ParseIP("127.0.0.1"), 12345)
	if respA == nil {
		t.Fatalf("Expected Fake-IP response for google.com Type A")
	}
	ansIP := net.IP(respA[len(respA)-4:])
	_, fakeCIDR, _ := net.ParseCIDR("198.18.0.0/15")
	if !fakeCIDR.Contains(ansIP) {
		t.Fatalf("Expected IP in 198.18.0.0/15, got %v", ansIP)
	}

	// 2. Type AAAA (0x001C) -> Should return empty NOERROR response (0 answer)
	qAAAA := buildDNSQueryPacket("google.com", 0x001C)
	respAAAA := h.HandleQuery(qAAAA, net.ParseIP("127.0.0.1"), 12345)
	if respAAAA == nil {
		t.Fatalf("Expected empty NOERROR response for Type AAAA, got nil")
	}
	answers := binary.BigEndian.Uint16(respAAAA[6:8])
	if answers != 0 {
		t.Fatalf("Expected 0 answers for Type AAAA NOERROR, got %d", answers)
	}
}
