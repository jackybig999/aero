// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestAdversarial_TunnelPump_InputValidation stress-tests IPDataPump against
// truncated packets, malformed version nibbles, corrupted NextHeaders, and malformed DNS/STUN payloads.
func TestAdversarial_TunnelPump_InputValidation(t *testing.T) {
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

	// 1. Non-IPv4/IPv6 Version Nibbles (0, 1, 2, 3, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15)
	// MUST be 100% dropped. None should reach conn.outCh.
	invalidVersions := []byte{0, 1, 2, 3, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	for _, ver := range invalidVersions {
		for _, length := range []int{20, 28, 40, 64, 128, 1500} {
			pkt := make([]byte, length)
			pkt[0] = ver << 4
			pkt[1] = 0xAA
			tun.inCh <- pkt
		}
	}

	// 2. Truncated IPv6 Packets (Version=6, Length 20..39)
	// MUST be 100% dropped. None should reach conn.outCh.
	for length := 20; length < 40; length++ {
		pkt := make([]byte, length)
		pkt[0] = 0x60 // IPv6
		pkt[6] = 17   // UDP
		tun.inCh <- pkt
	}

	// 3. Truncated IPv4 Packets where len(raw) < ihl
	// E.g. IHL = 10 (40 bytes header), packet length = 28 bytes.
	// MUST be dropped by `if len(raw) < ihl { continue }`.
	for ihl := 8; ihl <= 15; ihl++ {
		pkt := make([]byte, 28)
		pkt[0] = 0x40 | byte(ihl)
		pkt[9] = 17 // UDP
		tun.inCh <- pkt
	}

	// Verify none of the above invalid/truncated packets leaked to remote
	select {
	case p := <-conn.outCh:
		t.Fatalf("unexpected packet forwarded to remote: len=%d ver=%d", len(p), p[0]>>4)
	case <-time.After(200 * time.Millisecond):
		// Expected: all dropped
	}

	// 4. IPv6 NextHeader variations with valid lengths
	// TCP (NextHeader=6) -> Should be forwarded
	tcpPkt := make([]byte, 60)
	tcpPkt[0] = 0x60
	tcpPkt[6] = 6 // TCP
	tcpPkt[7] = 64
	copy(tcpPkt[8:24], net.ParseIP("fd88::2").To16())
	copy(tcpPkt[24:40], net.ParseIP("2606:4700::1").To16())
	tun.inCh <- tcpPkt

	select {
	case p := <-conn.outCh:
		if !bytes.Equal(p, tcpPkt) {
			t.Fatal("TCP packet corrupted during forward")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for IPv6 TCP packet forwarding")
	}

	// ICMPv6 (NextHeader=58) -> Should be forwarded
	icmpPkt := make([]byte, 48)
	icmpPkt[0] = 0x60
	icmpPkt[6] = 58 // ICMPv6
	icmpPkt[7] = 64
	copy(icmpPkt[8:24], net.ParseIP("fd88::2").To16())
	copy(icmpPkt[24:40], net.ParseIP("2606:4700::1").To16())
	tun.inCh <- icmpPkt

	select {
	case p := <-conn.outCh:
		if !bytes.Equal(p, icmpPkt) {
			t.Fatal("ICMPv6 packet corrupted during forward")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for ICMPv6 packet forwarding")
	}

	// 5. Truncated IPv6 UDP Header (NextHeader=17, Length 40..47 bytes)
	for l := 40; l < 48; l++ {
		shortUDP := make([]byte, l)
		shortUDP[0] = 0x60
		shortUDP[6] = 17 // UDP
		tun.inCh <- shortUDP

		select {
		case p := <-conn.outCh:
			if len(p) != l {
				t.Fatalf("expected forwarded truncated UDP length %d, got %d", l, len(p))
			}
		case <-time.After(1 * time.Second):
			t.Fatalf("timed out waiting for truncated UDP len=%d", l)
		}
	}

	// 6. Malformed IPv6 DNS Queries (NextHeader=17, dstPort=53)
	// 6a. Length 48 (UDP payload length = 0)
	emptyDNSPkt := make([]byte, 48)
	emptyDNSPkt[0] = 0x60
	emptyDNSPkt[6] = 17
	copy(emptyDNSPkt[8:24], net.ParseIP("fd88::2").To16())
	copy(emptyDNSPkt[24:40], net.ParseIP("fd88::1").To16())
	binary.BigEndian.PutUint16(emptyDNSPkt[40:42], 54321)
	binary.BigEndian.PutUint16(emptyDNSPkt[42:44], 53)
	tun.inCh <- emptyDNSPkt

	// 6b. Truncated DNS header (payload 1..11 bytes)
	for payloadLen := 1; payloadLen < 12; payloadLen++ {
		truncDNS := make([]byte, 48+payloadLen)
		truncDNS[0] = 0x60
		truncDNS[6] = 17
		copy(truncDNS[8:24], net.ParseIP("fd88::2").To16())
		copy(truncDNS[24:40], net.ParseIP("fd88::1").To16())
		binary.BigEndian.PutUint16(truncDNS[40:42], 54321)
		binary.BigEndian.PutUint16(truncDNS[42:44], 53)
		tun.inCh <- truncDNS
	}

	// 6c. Corrupted DNS question label pointer (points beyond buffer)
	corruptLabel := make([]byte, 70)
	corruptLabel[0] = 0x60
	corruptLabel[6] = 17
	copy(corruptLabel[8:24], net.ParseIP("fd88::2").To16())
	copy(corruptLabel[24:40], net.ParseIP("fd88::1").To16())
	binary.BigEndian.PutUint16(corruptLabel[40:42], 54321)
	binary.BigEndian.PutUint16(corruptLabel[42:44], 53)
	corruptLabel[48+12] = 0x3F // label length 63 when remaining is only 9 bytes
	tun.inCh <- corruptLabel

	// 7. Legitimate DNS query right after malformed flood -> must still succeed
	validDNS := buildIPv6UDPResponsePacket(
		net.ParseIP("fd88::2"), net.ParseIP("fd88::1"),
		55555, 53, buildDNSQuery("api.openai.com", 0x0001),
	)
	tun.inCh <- validDNS

	select {
	case resp := <-tun.outCh:
		if len(resp) < 48 || resp[0]>>4 != 6 {
			t.Fatalf("invalid DNS response after stress test: len=%d", len(resp))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for valid DNS response after malformed query flood")
	}

	// 8. Fuzz loop: 5,000 completely random byte packets between 20 and 1500 bytes
	// Launch background drainer so conn.outCh (buffer 32) does not block on forwarded fuzz packets.
	fuzzStopDrain := make(chan struct{})
	var drainedFuzzPackets atomic.Int64
	go func() {
		for {
			select {
			case <-conn.outCh:
				drainedFuzzPackets.Add(1)
			case <-tun.outCh:
			case <-fuzzStopDrain:
				return
			}
		}
	}()

	for i := 0; i < 5000; i++ {
		fuzzPkt := make([]byte, 20+(i%1000))
		fuzzPkt[0] = byte(i % 256)
		if len(fuzzPkt) > 6 {
			fuzzPkt[6] = byte((i * 17) % 256)
		}
		tun.inCh <- fuzzPkt
	}

	// Allow pump to finish processing fuzz packets
	time.Sleep(100 * time.Millisecond)
	close(fuzzStopDrain)

	// Ensure pump is alive and healthy after fuzzing
	probePkt := make([]byte, 50)
	probePkt[0] = 0x60
	probePkt[6] = 6 // TCP
	tun.inCh <- probePkt

	select {
	case p := <-conn.outCh:
		if len(p) != 50 {
			t.Fatalf("expected probe length 50, got %d", len(p))
		}
	case <-time.After(1 * time.Second):
		t.Fatal("pump died or hung after fuzz loop")
	}
}

// TestAdversarial_TunnelPump_DualStackConcurrency simulates simultaneous high-throughput
// IPv4 and IPv6 traffic to empirically prove that IPv4 traffic is never corrupted or starved.
func TestAdversarial_TunnelPump_DualStackConcurrency(t *testing.T) {
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

	const packetsPerWorker = 200
	const v4Workers = 10
	const v6Workers = 10

	var v4Sent atomic.Int64
	var v6Sent atomic.Int64
	var v4Received atomic.Int64
	var v6Received atomic.Int64

	v4Seen := make(map[uint32]bool)
	v6Seen := make(map[uint32]bool)
	var mapMu sync.Mutex

	// Collector goroutine: reads from conn.outCh and verifies integrity
	collectorDone := make(chan struct{})
	go func() {
		defer close(collectorDone)
		expectedTotal := int64(v4Workers*packetsPerWorker + v6Workers*packetsPerWorker)
		for {
			select {
			case p := <-conn.outCh:
				if len(p) < 20 {
					continue
				}
				ver := p[0] >> 4
				if ver == 4 {
					if len(p) != 60 {
						t.Errorf("IPv4 packet corrupted, len=%d", len(p))
						continue
					}
					seq := binary.BigEndian.Uint32(p[20:24])
					mapMu.Lock()
					if v4Seen[seq] {
						t.Errorf("duplicate IPv4 packet seq=%d", seq)
					}
					v4Seen[seq] = true
					mapMu.Unlock()
					v4Received.Add(1)
				} else if ver == 6 {
					if len(p) != 80 {
						t.Errorf("IPv6 packet corrupted, len=%d", len(p))
						continue
					}
					seq := binary.BigEndian.Uint32(p[40:44])
					mapMu.Lock()
					if v6Seen[seq] {
						t.Errorf("duplicate IPv6 packet seq=%d", seq)
					}
					v6Seen[seq] = true
					mapMu.Unlock()
					v6Received.Add(1)
				}

				if v4Received.Load()+v6Received.Load() >= expectedTotal {
					return
				}
			case <-time.After(10 * time.Second):
				return
			}
		}
	}()

	var wg sync.WaitGroup

	// Launch IPv4 data producers
	for w := 0; w < v4Workers; w++ {
		workerID := uint32(w)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < packetsPerWorker; i++ {
				seq := workerID*100000 + uint32(i)
				// IPv4 packet: 20-byte IP header + 40-byte payload
				pkt := make([]byte, 60)
				pkt[0] = 0x45 // IPv4, IHL 5
				binary.BigEndian.PutUint16(pkt[2:4], 60)
				pkt[9] = 6 // TCP
				copy(pkt[12:16], net.ParseIP("10.88.0.2").To4())
				copy(pkt[16:20], net.ParseIP("8.8.8.8").To4())
				binary.BigEndian.PutUint32(pkt[20:24], seq)
				for k := 24; k < 60; k++ {
					pkt[k] = byte(k & 0xFF)
				}

				tun.inCh <- pkt
				v4Sent.Add(1)
			}
		}()
	}

	// Launch IPv6 data producers concurrently
	for w := 0; w < v6Workers; w++ {
		workerID := uint32(w)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < packetsPerWorker; i++ {
				seq := workerID*100000 + uint32(i)
				// IPv6 packet: 40-byte IPv6 header + 40-byte payload
				pkt := make([]byte, 80)
				pkt[0] = 0x60 // IPv6
				binary.BigEndian.PutUint16(pkt[4:6], 40)
				pkt[6] = 6 // TCP
				copy(pkt[8:24], net.ParseIP("fd88::2").To16())
				copy(pkt[24:40], net.ParseIP("2606:4700::1").To16())
				binary.BigEndian.PutUint32(pkt[40:44], seq)
				for k := 44; k < 80; k++ {
					pkt[k] = byte(k & 0xFF)
				}

				tun.inCh <- pkt
				v6Sent.Add(1)
			}
		}()
	}

	wg.Wait()
	<-collectorDone

	// Assertions
	expectedV4 := int64(v4Workers * packetsPerWorker)
	expectedV6 := int64(v6Workers * packetsPerWorker)

	if v4Received.Load() != expectedV4 {
		t.Fatalf("IPv4 packet loss or starvation: sent=%d received=%d", expectedV4, v4Received.Load())
	}
	if v6Received.Load() != expectedV6 {
		t.Fatalf("IPv6 packet loss: sent=%d received=%d", expectedV6, v6Received.Load())
	}

	// Verify all sequence numbers were seen
	mapMu.Lock()
	defer mapMu.Unlock()
	if len(v4Seen) != int(expectedV4) {
		t.Fatalf("expected %d unique IPv4 packets, got %d", expectedV4, len(v4Seen))
	}
	if len(v6Seen) != int(expectedV6) {
		t.Fatalf("expected %d unique IPv6 packets, got %d", expectedV6, len(v6Seen))
	}
}
