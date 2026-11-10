// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"encoding/binary"
	"log"
	"net"
	"strings"
	"time"
)

// forwardRealICMPEcho dials the target via raw ICMP (IPv4), sends the Echo Request, and waits for Echo Reply.
func forwardRealICMPEcho(target net.IP, reqPayload []byte, timeout time.Duration) ([]byte, error) {
	conn, err := net.DialTimeout("ip4:icmp", target.String(), timeout)
	if err != nil {
		errStr := strings.ToLower(err.Error())
		if strings.Contains(errStr, "permission denied") || strings.Contains(errStr, "operation not permitted") {
			log.Printf("[WARN] [NAT] ICMP echo raw socket permission denied (target=%s): %v. Deployment best practice: configure AmbientCapabilities=CAP_NET_RAW in systemd service or set sysctl -w net.ipv4.ping_group_range=\"0 2147483647\"", target.String(), err)
		}
		return nil, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	if _, err := conn.Write(reqPayload); err != nil {
		return nil, err
	}

	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		resp := buf[:n]
		if len(resp) >= 20 && resp[0]>>4 == 4 {
			ihl := int(resp[0]&0x0f) * 4
			if len(resp) >= ihl+8 {
				resp = resp[ihl:]
			}
		}
		if len(resp) >= 8 && resp[0] == 0 {
			if len(reqPayload) >= 8 {
				if resp[4] == reqPayload[4] && resp[5] == reqPayload[5] {
					reply := make([]byte, len(resp))
					copy(reply, resp)
					return reply, nil
				}
				continue
			}
			reply := make([]byte, len(resp))
			copy(reply, resp)
			return reply, nil
		}
	}
}

// buildIPv4ICMPPacket constructs a valid 20-byte IPv4 header followed by icmpPayload,
// computing both IPv4 header checksum and ICMP message checksum.
func buildIPv4ICMPPacket(src net.IP, dst net.IP, icmpPayload []byte) []byte {
	src4 := src.To4()
	dst4 := dst.To4()
	if src4 == nil || dst4 == nil {
		return nil
	}

	totalLen := 20 + len(icmpPayload)
	if totalLen > 65535 {
		return nil
	}

	pkt := make([]byte, totalLen)
	// 1. IPv4 Header (20 bytes)
	pkt[0] = 0x45 // Version 4, IHL 5 (20 bytes)
	pkt[1] = 0x00 // DSCP / ECN
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[4] = 0x00 // Identification
	pkt[5] = 0x00
	pkt[6] = 0x00 // Flags & Fragment Offset
	pkt[7] = 0x00
	pkt[8] = 64 // TTL
	pkt[9] = 1  // Protocol: ICMP
	copy(pkt[12:16], src4)
	copy(pkt[16:20], dst4)
	ipChk := calcChecksum(pkt[:20])
	binary.BigEndian.PutUint16(pkt[10:12], ipChk)

	// 2. ICMP Payload
	copy(pkt[20:], icmpPayload)
	if len(icmpPayload) >= 4 {
		// Zero out ICMP checksum field before computing
		pkt[22] = 0
		pkt[23] = 0
		icmpChk := calcChecksum(pkt[20:])
		binary.BigEndian.PutUint16(pkt[22:24], icmpChk)
	}

	return pkt
}

// buildIPv6ICMPv6Packet constructs a valid 40-byte IPv6 header followed by icmpPayload,
// computing the mandatory RFC 4443 checksum with the 40-byte IPv6 pseudo-header.
func buildIPv6ICMPv6Packet(src net.IP, dst net.IP, icmpPayload []byte) []byte {
	src16 := src.To16()
	dst16 := dst.To16()
	if src16 == nil || dst16 == nil {
		return nil
	}

	totalLen := 40 + len(icmpPayload)
	if totalLen > 65535 {
		return nil
	}

	pkt := make([]byte, totalLen)
	// 1. IPv6 Header (40 bytes)
	pkt[0] = 0x60 // Version 6, Traffic Class 0
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(icmpPayload)))
	pkt[6] = 58 // Next Header: ICMPv6 (0x3A)
	pkt[7] = 64 // Hop Limit
	copy(pkt[8:24], src16)
	copy(pkt[24:40], dst16)

	// 2. ICMPv6 Payload
	copy(pkt[40:], icmpPayload)
	if len(icmpPayload) >= 4 {
		// Zero out ICMPv6 checksum field before computing
		pkt[42] = 0
		pkt[43] = 0

		// 3. RFC 4443 Checksum with IPv6 Pseudo-Header
		pseudo := make([]byte, 40)
		copy(pseudo[0:16], src16)
		copy(pseudo[16:32], dst16)
		binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(icmpPayload)))
		pseudo[39] = 58 // Next Header

		var sum uint32
		calc := func(b []byte) {
			for i := 0; i+1 < len(b); i += 2 {
				sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
			}
			if len(b)%2 == 1 {
				sum += uint32(b[len(b)-1]) << 8
			}
		}
		calc(pseudo)
		calc(pkt[40:])
		for sum > 0xFFFF {
			sum = (sum & 0xFFFF) + (sum >> 16)
		}
		csum := ^uint16(sum)
		if csum == 0 {
			csum = 0xFFFF
		}
		binary.BigEndian.PutUint16(pkt[42:44], csum)
	}

	return pkt
}

// buildICMPv6PacketTooBig constructs an ICMPv6 Type 2 Code 0 (Packet Too Big) message
// adhering to RFC 4443 §3.2 and RFC 8201.
func buildICMPv6PacketTooBig(origPkt []byte, gwIPv6 net.IP, nextMTU uint32) []byte {
	if len(origPkt) < 40 {
		return nil
	}
	if nextMTU < 1280 {
		nextMTU = 1280
	}

	origSrcIP := origPkt[8:24]
	maxPayload := 1280 - 40 - 8 // 1232 bytes maximum
	payloadLen := len(origPkt)
	if payloadLen > maxPayload {
		payloadLen = maxPayload
	}

	icmpPayload := make([]byte, 8+payloadLen)
	icmpPayload[0] = 2 // Type 2: Packet Too Big
	icmpPayload[1] = 0 // Code 0
	binary.BigEndian.PutUint32(icmpPayload[4:8], nextMTU)
	copy(icmpPayload[8:], origPkt[:payloadLen])

	return buildIPv6ICMPv6Packet(gwIPv6, net.IP(origSrcIP), icmpPayload)
}
