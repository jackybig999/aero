// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"encoding/binary"
	"net"
	"strings"
)

var domesticCarrierIPv6Prefixes = []string{
	"240e:",     // China Telecom
	"2408:",     // China Unicom
	"2409:",     // China Mobile
	"2001:da8:", // CERNET / Education network
}

// IsDomesticIPv6 checks if an IP belongs to domestic carrier ranges:
// China Telecom (240e::/16), China Unicom (2408::/16), China Mobile (2409::/16), or CERNET (2001:da8::/32).
func IsDomesticIPv6(ip net.IP) bool {
	ip16 := ip.To16()
	if ip16 == nil || ip.To4() != nil {
		return false
	}
	if ip16[0] == 0x24 && (ip16[1] == 0x0e || ip16[1] == 0x08 || ip16[1] == 0x09) {
		return true
	}
	if ip16[0] == 0x20 && ip16[1] == 0x01 && ip16[2] == 0x0d && ip16[3] == 0xa8 {
		return true
	}
	return false
}

// hasDomesticIPv6 checks if a string contains any domestic carrier IPv6 prefix.
func hasDomesticIPv6(s string) bool {
	lower := strings.ToLower(s)
	for _, p := range domesticCarrierIPv6Prefixes {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// ContainsDomesticSTUNCandidate inspects a STUN packet attributes for domestic carrier IPv6 candidates.
func ContainsDomesticSTUNCandidate(payload []byte) bool {
	if !isSTUNPacket(payload) {
		return false
	}
	msgLen := int(binary.BigEndian.Uint16(payload[2:4]))
	if len(payload) < 20+msgLen {
		msgLen = len(payload) - 20
	}
	cookieAndTID := payload[4:20] // 4 bytes magic cookie (0x2112A442) + 12 bytes TID

	offset := 20
	for offset+4 <= 20+msgLen {
		attrType := binary.BigEndian.Uint16(payload[offset : offset+2])
		attrLen := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
		offset += 4
		if offset+attrLen > len(payload) {
			break
		}
		val := payload[offset : offset+attrLen]
		// XOR-MAPPED-ADDRESS (0x0020), XOR-PEER-ADDRESS (0x0012), XOR-RELAYED-ADDRESS (0x0016)
		if (attrType == 0x0020 || attrType == 0x0012 || attrType == 0x0016) && len(val) >= 20 {
			family := val[1]
			if family == 0x02 { // IPv6
				b0 := val[4] ^ cookieAndTID[0]
				b1 := val[5] ^ cookieAndTID[1]
				b2 := val[6] ^ cookieAndTID[2]
				b3 := val[7] ^ cookieAndTID[3]
				if b0 == 0x24 && (b1 == 0x0e || b1 == 0x08 || b1 == 0x09) {
					return true
				}
				if b0 == 0x20 && b1 == 0x01 && b2 == 0x0d && b3 == 0xa8 {
					return true
				}
			}
		}
		// MAPPED-ADDRESS (0x0001)
		if attrType == 0x0001 && len(val) >= 20 {
			family := val[1]
			if family == 0x02 { // IPv6
				b0 := val[4]
				b1 := val[5]
				b2 := val[6]
				b3 := val[7]
				if b0 == 0x24 && (b1 == 0x0e || b1 == 0x08 || b1 == 0x09) {
					return true
				}
				if b0 == 0x20 && b1 == 0x01 && b2 == 0x0d && b3 == 0xa8 {
					return true
				}
			}
		}
		pad := (4 - (attrLen % 4)) % 4
		offset += attrLen + pad
	}
	return false
}

// SanitizeSTUNPacket replaces any domestic carrier IPv6 in STUN attributes with virtual IPv6 (fd88::2).
func SanitizeSTUNPacket(payload []byte) []byte {
	if !isSTUNPacket(payload) {
		return payload
	}
	pkt := append([]byte(nil), payload...)
	msgLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if len(pkt) < 20+msgLen {
		msgLen = len(pkt) - 20
	}
	cookieAndTID := pkt[4:20]
	virtualIPv6 := [16]byte{0xfd, 0x88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}

	offset := 20
	for offset+4 <= 20+msgLen {
		attrType := binary.BigEndian.Uint16(pkt[offset : offset+2])
		attrLen := int(binary.BigEndian.Uint16(pkt[offset+2 : offset+4]))
		offset += 4
		if offset+attrLen > len(pkt) {
			break
		}
		val := pkt[offset : offset+attrLen]
		if (attrType == 0x0020 || attrType == 0x0012 || attrType == 0x0016) && len(val) >= 20 {
			family := val[1]
			if family == 0x02 { // IPv6
				b0 := val[4] ^ cookieAndTID[0]
				b1 := val[5] ^ cookieAndTID[1]
				b2 := val[6] ^ cookieAndTID[2]
				b3 := val[7] ^ cookieAndTID[3]
				if (b0 == 0x24 && (b1 == 0x0e || b1 == 0x08 || b1 == 0x09)) ||
					(b0 == 0x20 && b1 == 0x01 && b2 == 0x0d && b3 == 0xa8) {
					for i := 0; i < 16; i++ {
						val[4+i] = virtualIPv6[i] ^ cookieAndTID[i]
					}
				}
			}
		}
		if attrType == 0x0001 && len(val) >= 20 {
			family := val[1]
			if family == 0x02 { // IPv6
				b0 := val[4]
				b1 := val[5]
				b2 := val[6]
				b3 := val[7]
				if (b0 == 0x24 && (b1 == 0x0e || b1 == 0x08 || b1 == 0x09)) ||
					(b0 == 0x20 && b1 == 0x01 && b2 == 0x0d && b3 == 0xa8) {
					copy(val[4:20], virtualIPv6[:])
				}
			}
		}
		pad := (4 - (attrLen % 4)) % 4
		offset += attrLen + pad
	}
	return pkt
}

// SanitizeSDP filters domestic carrier IPv6 lines from WebRTC SDP offers/answers and ICE candidate payloads.
func SanitizeSDP(sdp string) string {
	if !hasDomesticIPv6(sdp) {
		return sdp
	}
	lines := strings.Split(sdp, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimRight(line, "\r")
		lower := strings.ToLower(trimmed)
		if hasDomesticIPv6(lower) {
			// Candidate lines with carrier IPv6 are dropped
			if strings.HasPrefix(lower, "a=candidate:") || strings.Contains(lower, "typ host") {
				continue
			}
			// Connection lines with carrier IPv6 are rewritten to virtual IPv6
			if strings.HasPrefix(lower, "c=in ip6 ") {
				out = append(out, "c=IN IP6 fd88::2")
				continue
			}
			// JSON ICE candidate wrapper
			if strings.Contains(lower, `"candidate"`) {
				continue
			}
			continue
		}
		out = append(out, trimmed)
	}
	sep := "\n"
	if strings.Contains(sdp, "\r\n") {
		sep = "\r\n"
	}
	return strings.Join(out, sep)
}

// SanitizeWebRTCPayload inspects arbitrary UDP/TCP payload and sanitizes STUN or SDP domestic carrier IPv6.
func SanitizeWebRTCPayload(payload []byte) []byte {
	if len(payload) == 0 {
		return payload
	}
	if isSTUNPacket(payload) {
		if ContainsDomesticSTUNCandidate(payload) {
			return SanitizeSTUNPacket(payload)
		}
		return payload
	}
	if hasDomesticIPv6(string(payload)) {
		s := string(payload)
		if strings.Contains(s, "candidate") || strings.Contains(s, "c=IN IP6") ||
			strings.Contains(s, "m=audio") || strings.Contains(s, "m=video") {
			return []byte(SanitizeSDP(s))
		}
	}
	return payload
}
