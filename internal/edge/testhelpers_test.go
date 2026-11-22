// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package edge

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
)

// 仅供测试使用的构造器与辅助函数。生产代码只使用 NewQUICServerWithIPv6Prefix 等生产路径。

// NewIPv6Pool creates an IPv6Pool with a configured routed IPv6 CIDR.
func NewIPv6Pool(cidrStr string) (*IPv6Pool, error) {
	if cidrStr == "" {
		return nil, errors.New("IPv6 prefix is not configured")
	}
	prefix, err := netip.ParsePrefix(cidrStr)
	if err != nil {
		return nil, err
	}
	return &IPv6Pool{
		baseIP:   prefix.Addr(),
		prefix:   prefix.Bits(),
		nextHost: 2,
		maxHost:  65534,
		used:     make(map[netip.Addr]struct{}),
	}, nil
}

// NewQUICServer creates a test-compatible QUICServer with the legacy ULA pool.
// Production construction must use NewQUICServerWithIPv6Prefix so an unverified
// ULA is never advertised as public IPv6 capability.
func NewQUICServer(v *Validator, cl *ConnLimiter, bl *BandwidthLimiter, dg *DialGuard, rl *RateLimiter) *QUICServer {
	ipPool, _ := NewIPPool("10.88.0.0/16")
	ipv6Pool, _ := newIPv6PoolForTests()
	return newQUICServer(v, cl, bl, dg, rl, ipPool, ipv6Pool)
}

func newIPv6PoolForTests() (*IPv6Pool, error) {
	prefix, err := netip.ParsePrefix("fd88::/64")
	if err != nil {
		return nil, err
	}
	return &IPv6Pool{
		baseIP:   prefix.Addr(),
		prefix:   prefix.Bits(),
		nextHost: 2,
		maxHost:  65534,
		used:     make(map[netip.Addr]struct{}),
	}, nil
}

func buildRouterTestIPv4(src, dst netip.Addr) []byte {
	packet := make([]byte, 20)
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = 1
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	srcBytes := src.As4()
	dstBytes := dst.As4()
	copy(packet[12:16], srcBytes[:])
	copy(packet[16:20], dstBytes[:])
	return packet
}

// fetchAndUpdate pulls China direct rules from upstream, calculates SHA256,
// atomically writes to filePath (.tmp -> Rename) if changed, and updates memory.
func (h *GeoDataHandler) fetchAndUpdate() error {
	return h.fetchAndUpdateWithContext(context.Background())
}

func encodeDNSName(domain string) []byte {
	var buf []byte
	parts := strings.Split(domain, ".")
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		buf = append(buf, byte(len(part)))
		buf = append(buf, []byte(part)...)
	}
	buf = append(buf, 0x00)
	return buf
}
