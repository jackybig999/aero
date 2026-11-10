// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"
)

type inMemoryTunnelDevice struct {
	server    *QUICServer
	packets   chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

func newInMemoryTunnelDevice(server *QUICServer) *inMemoryTunnelDevice {
	return &inMemoryTunnelDevice{
		server:  server,
		packets: make(chan []byte, 1024),
		closed:  make(chan struct{}),
	}
}

func (d *inMemoryTunnelDevice) Read(b []byte) (int, error) {
	select {
	case pkt, ok := <-d.packets:
		if !ok {
			return 0, io.EOF
		}
		return copy(b, pkt), nil
	case <-d.closed:
		return 0, io.EOF
	}
}

func (d *inMemoryTunnelDevice) Write(pkt []byte) (int, error) {
	if len(pkt) < 20 {
		return len(pkt), nil
	}

	// IPv4 Packet handling
	if pkt[0]>>4 == 4 {
		proto := pkt[9]
		srcIP := net.IP(pkt[12:16])
		dstIP := net.IP(pkt[16:20])

		// 1. ICMP Echo Request handling
		if proto == 1 && len(pkt) >= 28 && pkt[20] == 8 {
			if d.server != nil && !d.server.allowLoopbackForTest {
				if blocked, _ := IsBlockedIP(dstIP); blocked {
					return len(pkt), nil
				}
			}
			echoReq := pkt[20:]
			if d.server != nil && d.server.icmpForwardHook != nil {
				if reply, err := d.server.icmpForwardHook(dstIP, echoReq); err == nil && len(reply) > 0 {
					respPkt := buildIPv4ICMPPacket(dstIP, srcIP, reply)
					if len(respPkt) > 0 {
						select {
						case d.packets <- respPkt:
						default:
						}
					}
				}
			} else if d.server != nil && d.server.allowLoopbackForTest {
				if reply, err := forwardRealICMPEcho(dstIP, echoReq, 2*time.Second); err == nil && len(reply) > 0 {
					respPkt := buildIPv4ICMPPacket(dstIP, srcIP, reply)
					if len(respPkt) > 0 {
						select {
						case d.packets <- respPkt:
						default:
						}
					}
				}
			}
			return len(pkt), nil
		}

		// 2. UDP Echo/Loopback handling for testing
		if proto == 17 && len(pkt) >= 28 {
			ihl := int(pkt[0]&0x0f) * 4
			if len(pkt) >= ihl+8 {
				srcPort := binary.BigEndian.Uint16(pkt[ihl : ihl+2])
				dstPort := binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
				payload := pkt[ihl+8:]
				// Construct Echo Reply
				replyPkt := make([]byte, 20+8+len(payload))
				replyPkt[0] = 0x45
				binary.BigEndian.PutUint16(replyPkt[2:4], uint16(len(replyPkt)))
				replyPkt[8] = 64
				replyPkt[9] = 17 // UDP
				copy(replyPkt[12:16], dstIP.To4())
				copy(replyPkt[16:20], srcIP.To4())
				ipChk := calcChecksum(replyPkt[:20])
				binary.BigEndian.PutUint16(replyPkt[10:12], ipChk)

				// UDP header
				binary.BigEndian.PutUint16(replyPkt[20:22], dstPort)
				binary.BigEndian.PutUint16(replyPkt[22:24], srcPort)
				binary.BigEndian.PutUint16(replyPkt[24:26], uint16(8+len(payload)))
				copy(replyPkt[28:], payload)
				select {
				case d.packets <- replyPkt:
				default:
				}
			}
			return len(pkt), nil
		}
	}
	return len(pkt), nil
}

func (d *inMemoryTunnelDevice) Close() error {
	d.closeOnce.Do(func() {
		close(d.closed)
	})
	return nil
}
