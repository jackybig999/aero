// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type mockIPv6TunDevice struct {
	inCh  chan []byte
	outCh chan []byte
}

func newMockIPv6TunDevice() *mockIPv6TunDevice {
	return &mockIPv6TunDevice{
		inCh:  make(chan []byte, 32),
		outCh: make(chan []byte, 32),
	}
}

func (m *mockIPv6TunDevice) Read(b []byte) (int, error) {
	pkt, ok := <-m.inCh
	if !ok {
		return 0, net.ErrClosed
	}
	n := copy(b, pkt)
	return n, nil
}

func (m *mockIPv6TunDevice) Write(b []byte) (int, error) {
	cp := make([]byte, len(b))
	copy(cp, b)
	m.outCh <- cp
	return len(b), nil
}

func (m *mockIPv6TunDevice) Close() error {
	return nil
}

func (m *mockIPv6TunDevice) Name() string {
	return "mock-ipv6-tun"
}

type mockIPv6PacketConn struct {
	inCh  chan []byte
	outCh chan []byte
}

func newMockIPv6PacketConn() *mockIPv6PacketConn {
	return &mockIPv6PacketConn{
		inCh:  make(chan []byte, 32),
		outCh: make(chan []byte, 32),
	}
}

func (m *mockIPv6PacketConn) ReadPacket(b []byte) (int, error) {
	pkt, ok := <-m.inCh
	if !ok {
		return 0, net.ErrClosed
	}
	n := copy(b, pkt)
	return n, nil
}

func (m *mockIPv6PacketConn) WritePacket(b []byte) ([]byte, error) {
	cp := make([]byte, len(b))
	copy(cp, b)
	m.outCh <- cp
	return nil, nil
}

func (m *mockIPv6PacketConn) Close() error {
	return nil
}

func TestIPv6UDPResponsePacket_Checksum(t *testing.T) {
	src := net.ParseIP("fd88::1")
	dst := net.ParseIP("fd88::2")
	payload := []byte("dns-reply-data")

	pkt := buildIPv6UDPResponsePacket(src, dst, 53, 12345, payload)
	if pkt == nil {
		t.Fatal("buildIPv6UDPResponsePacket returned nil")
	}

	if len(pkt) != 40+8+len(payload) {
		t.Fatalf("expected length %d, got %d", 40+8+len(payload), len(pkt))
	}

	// Verify IPv6 header
	if pkt[0]>>4 != 6 {
		t.Fatalf("expected version 6, got %d", pkt[0]>>4)
	}
	if pkt[6] != 17 {
		t.Fatalf("expected next header 17 (UDP), got %d", pkt[6])
	}
	if !bytes.Equal(pkt[8:24], src.To16()) {
		t.Fatalf("src IP mismatch: %v vs %v", pkt[8:24], src.To16())
	}
	if !bytes.Equal(pkt[24:40], dst.To16()) {
		t.Fatalf("dst IP mismatch: %v vs %v", pkt[24:40], dst.To16())
	}

	// Verify UDP header
	udp := pkt[40:]
	if binary.BigEndian.Uint16(udp[0:2]) != 53 {
		t.Fatalf("expected src port 53, got %d", binary.BigEndian.Uint16(udp[0:2]))
	}
	if binary.BigEndian.Uint16(udp[2:4]) != 12345 {
		t.Fatalf("expected dst port 12345, got %d", binary.BigEndian.Uint16(udp[2:4]))
	}

	// Verify RFC 2460 pseudo-header checksum
	csum := binary.BigEndian.Uint16(udp[6:8])
	if csum == 0 {
		t.Fatal("expected non-zero checksum for IPv6 UDP")
	}

	pseudo := make([]byte, 40)
	copy(pseudo[0:16], src.To16())
	copy(pseudo[16:32], dst.To16())
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(8+len(payload)))
	pseudo[39] = 17

	var sum uint32
	addWords := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	addWords(pseudo)
	addWords(udp)
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	if ^uint16(sum) != 0 {
		t.Fatalf("checksum verification failed: sum complement=0x%04x", ^uint16(sum))
	}
}

func TestTunnelPump_IPv6DataForwarding(t *testing.T) {
	tun := newMockIPv6TunDevice()
	conn := newMockIPv6PacketConn()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var killSw atomic.Bool
	pump := NewIPDataPump(ctx, tun, conn, &killSw, nil)
	pump.Start()
	defer pump.Close()

	// 1. Build a regular IPv6 UDP packet (port 443, external destination)
	src := net.ParseIP("fd88::2")
	dst := net.ParseIP("2606:4700::6810:1")
	udpPayload := []byte("regular-data-payload")
	pkt := buildIPv6UDPResponsePacket(src, dst, 54321, 443, udpPayload)

	// Inject into TUN
	tun.inCh <- pkt

	// Expect packet to be forwarded to remote CONNECT-IP tunnel
	select {
	case remotePkt := <-conn.outCh:
		if !bytes.Equal(remotePkt, pkt) {
			t.Fatal("forwarded packet does not match injected IPv6 packet")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for IPv6 packet forwarding to remote")
	}

	// 2. Test downlink: send IPv6 packet from remote to TUN
	downlinkPkt := buildIPv6UDPResponsePacket(dst, src, 443, 54321, []byte("downlink-reply"))
	conn.inCh <- downlinkPkt

	select {
	case tunPkt := <-tun.outCh:
		if !bytes.Equal(tunPkt, downlinkPkt) {
			t.Fatal("downlink packet does not match remote packet")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for IPv6 downlink packet on TUN")
	}
}

func TestTunnelPump_IPv6DNSInterception(t *testing.T) {
	tun := newMockIPv6TunDevice()
	conn := newMockIPv6PacketConn()

	split := NewSplitEngine()
	dnsH := NewDNSHandler(split)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var killSw atomic.Bool
	pump := NewIPDataPump(ctx, tun, conn, &killSw, dnsH)
	pump.Start()
	defer pump.Close()

	// Build an IPv6 DNS query (dstPort 53)
	src := net.ParseIP("fd88::2")
	dst := net.ParseIP("fd88::1")
	dnsReq := buildDNSQuery("api.openai.com", 0x0001)
	pkt := buildIPv6UDPResponsePacket(src, dst, 53535, 53, dnsReq)

	// Inject into TUN
	tun.inCh <- pkt

	// Expect local DNS response on TUN, not forwarded to remote
	select {
	case respPkt := <-tun.outCh:
		if len(respPkt) < 48 {
			t.Fatalf("DNS response too short: %d", len(respPkt))
		}
		if respPkt[0]>>4 != 6 {
			t.Fatalf("expected IPv6 response, got %d", respPkt[0]>>4)
		}
		udp := respPkt[40:]
		if binary.BigEndian.Uint16(udp[0:2]) != 53 {
			t.Fatalf("expected src port 53, got %d", binary.BigEndian.Uint16(udp[0:2]))
		}
		if binary.BigEndian.Uint16(udp[2:4]) != 53535 {
			t.Fatalf("expected dst port 53535, got %d", binary.BigEndian.Uint16(udp[2:4]))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for local IPv6 DNS response")
	}

	// Verify nothing was forwarded to remote
	select {
	case <-conn.outCh:
		t.Fatal("DNS query should not have been forwarded to remote")
	default:
	}
}

func TestTunnelPump_IPv6STUNDropping(t *testing.T) {
	tun := newMockIPv6TunDevice()
	conn := newMockIPv6PacketConn()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var killSw atomic.Bool
	pump := NewIPDataPump(ctx, tun, conn, &killSw, nil)
	pump.Start()
	defer pump.Close()

	// Build an IPv6 WebRTC STUN packet (contains 0x2112A442 magic cookie at offset 4..8 of UDP payload)
	stunPayload := make([]byte, 20)
	binary.BigEndian.PutUint16(stunPayload[0:2], 0x0001) // Binding Request
	binary.BigEndian.PutUint16(stunPayload[2:4], 0)
	binary.BigEndian.PutUint32(stunPayload[4:8], 0x2112A442) // Magic Cookie

	src := net.ParseIP("fd88::2")
	dst := net.ParseIP("2606:4700::1234")
	pkt := buildIPv6UDPResponsePacket(src, dst, 3478, 3478, stunPayload)

	tun.inCh <- pkt

	// STUN packet must be dropped silently; nothing forwarded to remote
	select {
	case <-conn.outCh:
		t.Fatal("WebRTC STUN packet should have been dropped")
	case <-time.After(300 * time.Millisecond):
		// Success: packet dropped
	}
}
