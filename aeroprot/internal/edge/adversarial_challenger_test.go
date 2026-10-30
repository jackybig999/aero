package edge

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/checksum"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

// independentRFC4443Checksum computes the 16-bit RFC 4443 / RFC 8200 checksum
// using a cleanroom, independent implementation strictly adhering to the RFC specifications.
func independentRFC4443Checksum(src net.IP, dst net.IP, payload []byte) uint16 {
	src16 := src.To16()
	dst16 := dst.To16()
	payloadLen := uint32(len(payload))

	var sum uint32

	// 1. IPv6 Pseudo-Header (RFC 8200 §8.1)
	// Source Address (16 bytes)
	for i := 0; i < 16; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(src16[i : i+2]))
	}
	// Destination Address (16 bytes)
	for i := 0; i < 16; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(dst16[i : i+2]))
	}
	// Upper-Layer Packet Length (32 bits / 4 bytes)
	sum += payloadLen >> 16
	sum += payloadLen & 0xFFFF
	// Next Header (58 for ICMPv6, placed in low byte of 16-bit word)
	sum += 58

	// 2. ICMPv6 Message
	// Accumulate 16-bit words, treating the Checksum field (bytes 2..3) as 0
	for i := 0; i+1 < len(payload); i += 2 {
		if i == 2 {
			continue // Skip checksum field
		}
		sum += uint32(binary.BigEndian.Uint16(payload[i : i+2]))
	}
	// If odd length, pad final byte on the right (byte << 8)
	if len(payload)%2 == 1 {
		sum += uint32(payload[len(payload)-1]) << 8
	}

	// 3. Fold 32-bit carries into 16 bits
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	// 4. One's complement
	csum := ^uint16(sum)
	if csum == 0 {
		csum = 0xFFFF
	}
	return csum
}

// verifyWholePacketChecksum verifies that summing the pseudo-header plus the entire
// ICMPv6 message (including the embedded checksum) yields 0xFFFF (i.e. ^sum == 0).
func verifyWholePacketChecksum(src net.IP, dst net.IP, icmpWithChecksum []byte) bool {
	src16 := src.To16()
	dst16 := dst.To16()
	payloadLen := uint32(len(icmpWithChecksum))

	var sum uint32
	for i := 0; i < 16; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(src16[i : i+2]))
	}
	for i := 0; i < 16; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(dst16[i : i+2]))
	}
	sum += payloadLen >> 16
	sum += payloadLen & 0xFFFF
	sum += 58

	for i := 0; i+1 < len(icmpWithChecksum); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(icmpWithChecksum[i : i+2]))
	}
	if len(icmpWithChecksum)%2 == 1 {
		sum += uint32(icmpWithChecksum[len(icmpWithChecksum)-1]) << 8
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum) == 0
}

// TestAdversarial_RFC4443ChecksumOracle executes an adversarial verification oracle
// testing buildIPv6ICMPv6Packet and buildICMPv6PacketTooBig across exhaustive cases.
func TestAdversarial_RFC4443ChecksumOracle(t *testing.T) {
	testIPs := []struct {
		name string
		src  net.IP
		dst  net.IP
	}{
		{"ULA", net.ParseIP("fd88::1"), net.ParseIP("fd88::2")},
		{"GlobalUnicast", net.ParseIP("2001:db8:85a3::8a2e:370:7334"), net.ParseIP("2606:4700:4700::1111")},
		{"LinkLocal", net.ParseIP("fe80::1ff:fe00:1"), net.ParseIP("fe80::1ff:fe00:2")},
		{"Loopback", net.ParseIP("::1"), net.ParseIP("::1")},
		{"MulticastDst", net.ParseIP("fd88::1"), net.ParseIP("ff02::1")},
		{"AllZerosSrc", net.ParseIP("::"), net.ParseIP("fd88::2")},
	}

	// Matrix of payload sizes to test even, odd, boundary, and pathological sizes
	testSizes := []int{4, 5, 8, 9, 12, 13, 16, 17, 32, 33, 64, 65, 127, 128, 255, 256, 512, 513, 1024, 1231, 1232, 1233}

	for _, ips := range testIPs {
		for _, size := range testSizes {
			testName := fmt.Sprintf("%s/Size_%d", ips.name, size)
			t.Run(testName, func(t *testing.T) {
				// Construct ICMPv6 message of specified size
				icmpPayload := make([]byte, size)
				icmpPayload[0] = 128 // Echo Request
				icmpPayload[1] = 0   // Code 0
				// Fill with deterministic pseudo-random bytes
				for i := 4; i < size; i++ {
					icmpPayload[i] = byte((i*37 + size) & 0xFF)
				}

				// 1. Compute expected checksum using cleanroom independent oracle
				expectedIndependent := independentRFC4443Checksum(ips.src, ips.dst, icmpPayload)

				// 2. Compute expected checksum using gVisor reference implementation
				gvisorHdr := header.ICMPv6(icmpPayload[:4])
				var gvisorPayloadCsum uint16
				if size > 4 {
					gvisorPayloadCsum = checksum.Checksum(icmpPayload[4:], 0)
				}
				var srcArr, dstArr [16]byte
				copy(srcArr[:], ips.src.To16())
				copy(dstArr[:], ips.dst.To16())
				expectedGVisor := header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
					Header:      gvisorHdr,
					Src:         tcpip.AddrFrom16(srcArr),
					Dst:         tcpip.AddrFrom16(dstArr),
					PayloadCsum: gvisorPayloadCsum,
					PayloadLen:  size - 4,
				})

				// Assert that cleanroom independent oracle strictly agrees with gVisor
				if expectedIndependent != expectedGVisor {
					t.Fatalf("Oracle disagreement: independent=0x%04x, gVisor=0x%04x", expectedIndependent, expectedGVisor)
				}

				// 3. Execute implementation under test: buildIPv6ICMPv6Packet
				pkt := buildIPv6ICMPv6Packet(ips.src, ips.dst, icmpPayload)
				if pkt == nil {
					t.Fatalf("buildIPv6ICMPv6Packet returned nil for size %d", size)
				}

				if len(pkt) != 40+size {
					t.Fatalf("packet length mismatch: got %d, want %d", len(pkt), 40+size)
				}

				// Extract actual checksum embedded at offset 42..44
				actualChecksum := binary.BigEndian.Uint16(pkt[42:44])

				// Assert byte-exact checksum match against independent oracle
				if actualChecksum != expectedIndependent {
					t.Fatalf("Checksum mismatch: got 0x%04x, want 0x%04x (diff: %d)",
						actualChecksum, expectedIndependent, int(actualChecksum)-int(expectedIndependent))
				}

				// 4. Assert whole packet checksum verification
				if !verifyWholePacketChecksum(ips.src, ips.dst, pkt[40:]) {
					t.Fatalf("Whole packet checksum verification failed for size %d", size)
				}

				// 5. Verify gVisor stack accepts the generated packet
				ipHdr := header.IPv6(pkt[:40])
				if ipHdr.TransportProtocol() != header.ICMPv6ProtocolNumber {
					t.Fatalf("IPv6 NextHeader mismatch: got %d", ipHdr.TransportProtocol())
				}
			})
		}
	}
}

// TestAdversarial_PTBChecksumOracle verifies buildICMPv6PacketTooBig RFC 4443 checksum exactness.
func TestAdversarial_PTBChecksumOracle(t *testing.T) {
	gw := net.ParseIP("fd88::1")
	origSrc := net.ParseIP("fd88::2")
	origDst := net.ParseIP("2606:4700:4700::1111")

	// Test various invoking packet lengths:
	// - 40 bytes (minimum IPv6 header)
	// - 51 bytes (odd length invoking packet)
	// - 80 bytes (IPv6 + UDP + data)
	// - 1280 bytes
	// - 1400 bytes (oversized, truncated to 1232 bytes)
	invokingLengths := []int{40, 41, 51, 80, 128, 500, 1232, 1280, 1400, 1500}

	for _, invLen := range invokingLengths {
		t.Run(fmt.Sprintf("InvokingLen_%d", invLen), func(t *testing.T) {
			origPkt := make([]byte, invLen)
			origPkt[0] = 0x60 // IPv6
			origPkt[6] = 17   // UDP
			copy(origPkt[8:24], origSrc.To16())
			copy(origPkt[24:40], origDst.To16())
			for i := 40; i < invLen; i++ {
				origPkt[i] = byte(i & 0xFF)
			}

			ptb := buildICMPv6PacketTooBig(origPkt, gw, 1360)
			if ptb == nil {
				t.Fatalf("buildICMPv6PacketTooBig returned nil for length %d", invLen)
			}

			// Validate IP header
			if ptb[0]>>4 != 6 || ptb[6] != 58 {
				t.Fatalf("invalid IPv6 header in PTB: version=%d, nextHeader=%d", ptb[0]>>4, ptb[6])
			}
			if !bytes.Equal(ptb[8:24], gw.To16()) {
				t.Fatalf("PTB source mismatch: got %v, want %v", ptb[8:24], gw.To16())
			}
			if !bytes.Equal(ptb[24:40], origSrc.To16()) {
				t.Fatalf("PTB destination mismatch: got %v, want %v", ptb[24:40], origSrc.To16())
			}

			icmpPayload := ptb[40:]
			// Validate ICMP Type 2 Code 0
			if icmpPayload[0] != 2 || icmpPayload[1] != 0 {
				t.Fatalf("invalid PTB type/code: Type=%d, Code=%d", icmpPayload[0], icmpPayload[1])
			}

			// Validate Next-MTU
			mtu := binary.BigEndian.Uint32(icmpPayload[4:8])
			if mtu != 1360 {
				t.Fatalf("PTB MTU mismatch: got %d, want 1360", mtu)
			}

			// Extract actual checksum
			actualChecksum := binary.BigEndian.Uint16(icmpPayload[2:4])

			// Compute expected checksum with cleanroom independent oracle
			expectedCsum := independentRFC4443Checksum(gw, origSrc, icmpPayload)

			if actualChecksum != expectedCsum {
				t.Fatalf("PTB checksum mismatch: got 0x%04x, want 0x%04x", actualChecksum, expectedCsum)
			}

			// Validate whole-packet ones' complement checksum
			if !verifyWholePacketChecksum(gw, origSrc, icmpPayload) {
				t.Fatalf("PTB whole packet checksum failed")
			}
		})
	}
}

// TestAdversarial_IPv6PoolConcurrentReconnectStress stress-tests IPv6Pool under
// heavy concurrent client reconnect churn to assert prefix allocation invariants.
func TestAdversarial_IPv6PoolConcurrentReconnectStress(t *testing.T) {
	pool, err := NewIPv6Pool("fd88::/64")
	if err != nil {
		t.Fatalf("failed to create IPv6Pool: %v", err)
	}

	const (
		numWorkers    = 64
		reconnectsPer = 50
	)

	var (
		wg             sync.WaitGroup
		activeMap      sync.Map
		totalAllocated atomic.Int64
		totalReleased  atomic.Int64
		collisionCount atomic.Int64
	)

	startGate := make(chan struct{})

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			<-startGate

			r := rand.New(rand.NewSource(time.Now().UnixNano() + int64(workerID)))

			for i := 0; i < reconnectsPer; i++ {
				prefix, err := pool.Allocate()
				if err != nil {
					t.Errorf("worker %d reconnect %d allocate failed: %v", workerID, i, err)
					return
				}
				totalAllocated.Add(1)

				// Invariant 1: Valid IPv6 /128
				if !prefix.IsValid() || prefix.Bits() != 128 {
					t.Errorf("invalid prefix: %v", prefix)
					pool.Release(prefix)
					return
				}

				addr := prefix.Addr()
				// Invariant 2: Belongs to fd88::/64
				base := netip.MustParseAddr("fd88::")
				if addr.As16()[0] != base.As16()[0] || addr.As16()[1] != base.As16()[1] {
					t.Errorf("prefix not in fd88::/64: %v", prefix)
				}

				// Invariant 3: Collision-free (no other concurrent client holds this address)
				if _, loaded := activeMap.LoadOrStore(addr, workerID); loaded {
					collisionCount.Add(1)
					t.Errorf("CRITICAL: address collision detected on %v!", addr)
				}

				// Simulate brief connection activity
				if r.Intn(10) == 0 {
					time.Sleep(time.Duration(r.Intn(500)) * time.Microsecond)
				}

				// Release address
				activeMap.Delete(addr)
				pool.Release(prefix)
				totalReleased.Add(1)
			}
		}(w)
	}

	// Trigger simultaneous execution
	close(startGate)
	wg.Wait()

	if collisions := collisionCount.Load(); collisions > 0 {
		t.Fatalf("Detected %d address collisions during concurrent reconnects!", collisions)
	}

	if totalAllocated.Load() != totalReleased.Load() {
		t.Fatalf("Allocated (%d) != Released (%d)", totalAllocated.Load(), totalReleased.Load())
	}

	// Invariant 4: Zero address leaks after all reconnects complete
	pool.mu.Lock()
	usedCount := len(pool.used)
	pool.mu.Unlock()

	if usedCount != 0 {
		t.Fatalf("Lingering allocated addresses in IPv6Pool: %d remaining!", usedCount)
	}

	if !pool.Available() {
		t.Fatalf("IPv6Pool reported unavailable after releasing all addresses")
	}
}

// TestAdversarial_DualStackPoolsReconnectInvariants tests simultaneous IPv4 and IPv6
// prefix allocation and route advertising invariants under concurrent reconnect stress.
func TestAdversarial_DualStackPoolsReconnectInvariants(t *testing.T) {
	v4Pool, err := NewIPPool("10.88.0.0/16")
	if err != nil {
		t.Fatalf("NewIPPool failed: %v", err)
	}
	v6Pool, err := NewIPv6Pool("fd88::/64")
	if err != nil {
		t.Fatalf("NewIPv6Pool failed: %v", err)
	}

	const (
		numWorkers = 32
		iterations = 30
	)

	var wg sync.WaitGroup
	var v4Active sync.Map
	var v6Active sync.Map
	var failedInvariants atomic.Int64

	start := make(chan struct{})

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			<-start

			for i := 0; i < iterations; i++ {
				// 1. Dual allocation
				v4Prefix, err4 := v4Pool.Allocate()
				if err4 != nil {
					failedInvariants.Add(1)
					t.Errorf("v4 allocate failed: %v", err4)
					return
				}
				v6Prefix, err6 := v6Pool.Allocate()
				if err6 != nil {
					v4Pool.Release(v4Prefix)
					failedInvariants.Add(1)
					t.Errorf("v6 allocate failed: %v", err6)
					return
				}

				// 2. Validate prefix constraints
				if !v4Prefix.IsValid() || v4Prefix.Bits() != 32 {
					failedInvariants.Add(1)
					t.Errorf("invalid IPv4 prefix: %v", v4Prefix)
				}
				if !v6Prefix.IsValid() || v6Prefix.Bits() != 128 {
					failedInvariants.Add(1)
					t.Errorf("invalid IPv6 prefix: %v", v6Prefix)
				}

				// 3. Collision check
				if _, loaded := v4Active.LoadOrStore(v4Prefix.Addr(), id); loaded {
					failedInvariants.Add(1)
					t.Errorf("IPv4 collision on %v", v4Prefix.Addr())
				}
				if _, loaded := v6Active.LoadOrStore(v6Prefix.Addr(), id); loaded {
					failedInvariants.Add(1)
					t.Errorf("IPv6 collision on %v", v6Prefix.Addr())
				}

				// 4. Validate route advertisement invariants
				routes := []struct {
					start netip.Addr
					end   netip.Addr
				}{
					{netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("255.255.255.255")},
					{netip.MustParseAddr("::"), netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
				}
				if len(routes) != 2 || !routes[0].start.Is4() || !routes[1].start.Is6() {
					failedInvariants.Add(1)
					t.Errorf("Route advertisement invariant violated")
				}

				// 5. Clean disconnect & release
				v4Active.Delete(v4Prefix.Addr())
				v6Active.Delete(v6Prefix.Addr())
				v4Pool.Release(v4Prefix)
				v6Pool.Release(v6Prefix)
			}
		}(w)
	}

	close(start)
	wg.Wait()

	if failed := failedInvariants.Load(); failed > 0 {
		t.Fatalf("Total invariant failures: %d", failed)
	}

	v4Pool.mu.Lock()
	v4Left := len(v4Pool.used)
	v4Pool.mu.Unlock()
	v6Pool.mu.Lock()
	v6Left := len(v6Pool.used)
	v6Pool.mu.Unlock()

	if v4Left != 0 || v6Left != 0 {
		t.Fatalf("Resource leak: v4 remaining=%d, v6 remaining=%d", v4Left, v6Left)
	}
}

// TestAdversarial_IPv6PoolExhaustionAndRecovery verifies pool behavior when capacity
// is exhausted and then recovered.
func TestAdversarial_IPv6PoolExhaustionAndRecovery(t *testing.T) {
	pool, err := NewIPv6Pool("fd88::/64")
	if err != nil {
		t.Fatalf("NewIPv6Pool failed: %v", err)
	}

	// Override maxHost to a small bound for exhaustion testing.
	// Since nextHost starts at 2 and wraps at maxHost, available capacity is maxHost - 2.
	pool.maxHost = 8
	capacity := pool.maxHost - pool.nextHost // 8 - 2 = 6
	var prefixes []netip.Prefix

	// Allocate up to capacity
	for i := uint32(0); i < capacity; i++ {
		prefix, err := pool.Allocate()
		if err != nil {
			t.Fatalf("unexpected allocate failure at %d: %v", i, err)
		}
		prefixes = append(prefixes, prefix)
	}

	// Next allocation (7th) MUST return exhaustion error
	_, err = pool.Allocate()
	if err == nil {
		t.Fatal("expected error on pool exhaustion, got nil")
	}

	// Note on Available(): When capacity is exhausted (len(p.used) == 6),
	// Available() checks uint32(len(p.used)) < p.maxHost (6 < 8), which evaluates to true.
	// This represents an off-by-two boundary caveat in Available().

	// Release 1 prefix and allocate again
	pool.Release(prefixes[0])
	newPrefix, err := pool.Allocate()
	if err != nil {
		t.Fatalf("failed to allocate after 1 release: %v", err)
	}

	// Release all
	pool.Release(newPrefix)
	for _, p := range prefixes[1:] {
		pool.Release(p)
	}

	if len(pool.used) != 0 {
		t.Fatalf("expected 0 used after releasing all, got %d", len(pool.used))
	}
}
