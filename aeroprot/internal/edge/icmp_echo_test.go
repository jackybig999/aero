// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestIPv6Pool_AllocationAndRelease(t *testing.T) {
	pool, err := NewIPv6Pool("fd88::/64")
	if err != nil {
		t.Fatalf("NewIPv6Pool failed: %v", err)
	}

	if !pool.Available() {
		t.Fatal("expected pool to be available")
	}

	p1, err := pool.Allocate()
	if err != nil {
		t.Fatalf("first allocate failed: %v", err)
	}
	if p1.Bits() != 128 {
		t.Fatalf("expected /128 prefix, got /%d", p1.Bits())
	}
	if !p1.Addr().Is6() {
		t.Fatalf("expected IPv6 address, got %v", p1.Addr())
	}

	p2, err := pool.Allocate()
	if err != nil {
		t.Fatalf("second allocate failed: %v", err)
	}
	if p1.Addr() == p2.Addr() {
		t.Fatalf("expected distinct addresses, got both %v", p1.Addr())
	}

	// Release p1 and reallocate
	pool.Release(p1)

	// Simulate exhaustion with small maxHost (hosts 2, 3, 4)
	smallPool, _ := NewIPv6Pool("fd88::/64")
	smallPool.mu.Lock()
	smallPool.maxHost = 5
	smallPool.mu.Unlock()

	var allocated []netip.Prefix
	for i := 0; i < 3; i++ {
		p, err := smallPool.Allocate()
		if err != nil {
			t.Fatalf("allocate %d failed: %v", i, err)
		}
		allocated = append(allocated, p)
	}

	_, err = smallPool.Allocate()
	if err == nil {
		t.Fatal("expected error on exhausted pool, got nil")
	}

	// Release one and allocate again
	smallPool.Release(allocated[0])
	if !smallPool.Available() {
		t.Fatal("expected smallPool to be available after release")
	}
	newP, err := smallPool.Allocate()
	if err != nil {
		t.Fatalf("allocate after release failed: %v", err)
	}
	if newP.Addr() != allocated[0].Addr() {
		t.Fatalf("expected reallocated address %v, got %v", allocated[0].Addr(), newP.Addr())
	}
}

func TestIPv6Pool_Concurrent(t *testing.T) {
	pool, err := NewIPv6Pool("fd88::/64")
	if err != nil {
		t.Fatalf("NewIPv6Pool failed: %v", err)
	}

	const workers = 32
	const iterations = 50
	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				p, err := pool.Allocate()
				if err != nil {
					t.Errorf("concurrent allocate failed: %v", err)
					return
				}
				time.Sleep(10 * time.Microsecond)
				pool.Release(p)
			}
		}()
	}

	wg.Wait()
}

func TestIPv6ICMPv6_Checksum(t *testing.T) {
	src := net.ParseIP("fd88::1")
	dst := net.ParseIP("2001:db8::2")

	// Construct Echo Request payload (Type 128, Code 0, Checksum 0, ID 0x1234, Seq 0x0001, Data "test")
	echoReq := make([]byte, 12)
	echoReq[0] = 128 // Type 128: Echo Request
	echoReq[1] = 0   // Code 0
	binary.BigEndian.PutUint16(echoReq[4:6], 0x1234)
	binary.BigEndian.PutUint16(echoReq[6:8], 0x0001)
	copy(echoReq[8:], "test")

	pkt := buildIPv6ICMPv6Packet(src, dst, echoReq)
	if pkt == nil {
		t.Fatal("buildIPv6ICMPv6Packet returned nil")
	}

	if len(pkt) != 40+len(echoReq) {
		t.Fatalf("expected packet length %d, got %d", 40+len(echoReq), len(pkt))
	}

	// Verify IPv6 header
	if pkt[0]>>4 != 6 {
		t.Fatalf("expected IPv6 version 6, got %d", pkt[0]>>4)
	}
	if pkt[6] != 58 {
		t.Fatalf("expected NextHeader 58 (ICMPv6), got %d", pkt[6])
	}
	if pkt[7] != 64 {
		t.Fatalf("expected HopLimit 64, got %d", pkt[7])
	}
	if !bytes.Equal(pkt[8:24], src.To16()) {
		t.Fatalf("src IP mismatch: got %v, expected %v", pkt[8:24], src.To16())
	}
	if !bytes.Equal(pkt[24:40], dst.To16()) {
		t.Fatalf("dst IP mismatch: got %v, expected %v", pkt[24:40], dst.To16())
	}

	// Verify Checksum is non-zero
	csum := binary.BigEndian.Uint16(pkt[42:44])
	if csum == 0 {
		t.Fatal("expected non-zero RFC 4443 checksum")
	}

	// Validate checksum by verifying sum with pseudo-header
	pseudo := make([]byte, 40)
	copy(pseudo[0:16], src.To16())
	copy(pseudo[16:32], dst.To16())
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(echoReq)))
	pseudo[39] = 58

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
	addWords(pkt[40:])
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	if ^uint16(sum) != 0 {
		t.Fatalf("RFC 4443 checksum verification failed, sum complement: 0x%04x", ^uint16(sum))
	}
}

func TestIPv6ICMPv6_PacketTooBig(t *testing.T) {
	gw := net.ParseIP("fd88::1")
	origSrc := net.ParseIP("fd88::2")
	origDst := net.ParseIP("2606:4700:4700::1111")

	// Construct an oversized 1400-byte IPv6 packet
	origPkt := make([]byte, 1400)
	origPkt[0] = 0x60
	binary.BigEndian.PutUint16(origPkt[4:6], 1360)
	origPkt[6] = 17 // UDP
	origPkt[7] = 64
	copy(origPkt[8:24], origSrc.To16())
	copy(origPkt[24:40], origDst.To16())

	ptbPkt := buildICMPv6PacketTooBig(origPkt, gw, 1360)
	if ptbPkt == nil {
		t.Fatal("buildICMPv6PacketTooBig returned nil")
	}

	// Verify IPv6 header of PTB message
	if ptbPkt[0]>>4 != 6 {
		t.Fatalf("expected IPv6 version 6, got %d", ptbPkt[0]>>4)
	}
	if ptbPkt[6] != 58 {
		t.Fatalf("expected NextHeader 58, got %d", ptbPkt[6])
	}
	if !bytes.Equal(ptbPkt[8:24], gw.To16()) {
		t.Fatalf("expected source to be gateway %v, got %v", gw, ptbPkt[8:24])
	}
	if !bytes.Equal(ptbPkt[24:40], origSrc.To16()) {
		t.Fatalf("expected destination to be original source %v, got %v", origSrc, ptbPkt[24:40])
	}

	// Verify ICMPv6 Type 2 Code 0
	icmp := ptbPkt[40:]
	if icmp[0] != 2 || icmp[1] != 0 {
		t.Fatalf("expected ICMPv6 Type 2 Code 0, got Type=%d Code=%d", icmp[0], icmp[1])
	}

	// Verify MTU field
	mtu := binary.BigEndian.Uint32(icmp[4:8])
	if mtu != 1360 {
		t.Fatalf("expected MTU 1360, got %d", mtu)
	}

	// Verify invoking packet snippet
	snippet := icmp[8:]
	if !bytes.Equal(snippet, origPkt[:len(snippet)]) {
		t.Fatal("invoking packet snippet in PTB does not match original packet")
	}
}

type mockNATPacketConn struct {
	inCh      chan []byte
	outCh     chan []byte
	closeOnce sync.Once
}

func newMockNATPacketConn() *mockNATPacketConn {
	return &mockNATPacketConn{
		inCh:  make(chan []byte, 16),
		outCh: make(chan []byte, 16),
	}
}

func (m *mockNATPacketConn) ReadPacket(b []byte) (int, error) {
	pkt, ok := <-m.inCh
	if !ok {
		return 0, net.ErrClosed
	}
	n := copy(b, pkt)
	return n, nil
}

func (m *mockNATPacketConn) WritePacket(b []byte) ([]byte, error) {
	cp := make([]byte, len(b))
	copy(cp, b)
	m.outCh <- cp
	return nil, nil
}

func (m *mockNATPacketConn) Close() error {
	m.closeOnce.Do(func() {
		close(m.inCh)
	})
	return nil
}

