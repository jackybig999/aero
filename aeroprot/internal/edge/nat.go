// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/connect-ip-go"
	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv6"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/icmp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"
	"github.com/sagernet/gvisor/pkg/waiter"
)

const gvisorEdgeNICID = tcpip.NICID(1)

var natTCPBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32768)
		return &b
	},
}

var natUDPBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 65535)
		return &b
	},
}

// IPPacketConn abstracts bidirectional packet transport over CONNECT-IP (RFC 9484)
// and RFC 9297 Capsule Protocol.
type IPPacketConn interface {
	ReadPacket(b []byte) (int, error)
	WritePacket(b []byte) ([]byte, error)
	Close() error
}

// Compile-time static assertion: connectip.Conn naturally satisfies IPPacketConn
var _ IPPacketConn = (*connectip.Conn)(nil)

// UserSpaceNATRouter implements a real RFC 9484 CONNECT-IP user-space NAT router.
// It accepts client IP packets, routes them in user-space, dials real external
// internet targets, and re-encapsulates return packets back to the client.
type UserSpaceNATRouter struct {
	server     *QUICServer
	token      string
	clientIP   netip.Addr
	clientIPv6 netip.Addr
	conn       IPPacketConn
	gvEP       *channel.Endpoint
	gvStack    *stack.Stack
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

// NewUserSpaceNATRouter creates and starts a user-space NAT router for a CONNECT-IP session.
func NewUserSpaceNATRouter(parentCtx context.Context, server *QUICServer, token string, clientIP netip.Addr, conn IPPacketConn, clientIPv6 ...netip.Addr) (*UserSpaceNATRouter, error) {
	ctx, cancel := context.WithCancel(parentCtx)

	ep := channel.New(2048, 1420, "")
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocolWithOptions(ipv4.Options{
				AllowExternalLoopbackTraffic: true,
			}),
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
		HandleLocal: false,
	})

	if err := s.CreateNIC(gvisorEdgeNICID, ep); err != nil {
		cancel()
		ep.Close()
		return nil, fmt.Errorf("create gvisor edge nic: %s", err)
	}

	_ = s.SetPromiscuousMode(gvisorEdgeNICID, true)
	_ = s.SetSpoofing(gvisorEdgeNICID, true)
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: gvisorEdgeNICID},
		{Destination: header.IPv6EmptySubnet, NIC: gvisorEdgeNICID},
	})

	var v6 netip.Addr
	if len(clientIPv6) > 0 {
		v6 = clientIPv6[0]
	}

	r := &UserSpaceNATRouter{
		server:     server,
		token:      token,
		clientIP:   clientIP,
		clientIPv6: v6,
		conn:       conn,
		gvEP:       ep,
		gvStack:    s,
		ctx:        ctx,
		cancel:     cancel,
	}

	// 1. TCP Forwarder: real outbound TCP dialing
	tcpFwd := tcp.NewForwarder(s, 0, 2048, func(req *tcp.ForwarderRequest) {
		r.handleTCP(req)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	// 2. UDP Forwarder: real outbound UDP dialing
	udpFwd := udp.NewForwarder(s, func(req *udp.ForwarderRequest) bool {
		return r.handleUDP(req)
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	return r, nil
}

// Run pumps packets between the CONNECT-IP session and the user-space NAT stack.
func (r *UserSpaceNATRouter) Run() {
	r.wg.Add(2)
	go r.pumpInbound()
	go r.pumpOutbound()
	r.wg.Wait()
}

// Close terminates the router and frees resources.
func (r *UserSpaceNATRouter) Close() {
	r.cancel()
	if r.gvEP != nil {
		r.gvEP.Close()
	}
	if r.gvStack != nil {
		r.gvStack.Close()
		r.gvStack.Destroy()
	}
}

func (r *UserSpaceNATRouter) pumpInbound() {
	defer r.wg.Done()
	bufPtr := natUDPBufPool.Get().(*[]byte)
	defer natUDPBufPool.Put(bufPtr)
	buf := *bufPtr

	for {
		if r.ctx.Err() != nil {
			return
		}
		n, err := r.conn.ReadPacket(buf)
		if err != nil {
			r.cancel()
			return
		}
		if n < 20 || r.gvEP == nil {
			continue
		}

		if r.server.bandwidthLimiter != nil {
			r.server.bandwidthLimiter.Take(r.token, n)
		}

		raw := buf[:n]

		// Real ICMP Echo forwarding
		if raw[0]>>4 == 4 && len(raw) >= 28 {
			if raw[9] == 1 { // ICMPv4
				ihl := int(raw[0]&0x0f) * 4
				if len(raw) < ihl+8 {
					continue
				}
				icmpPayload := raw[ihl:]
				if icmpPayload[0] == 8 && icmpPayload[1] == 0 { // Echo Request
					dstIP := net.IP(raw[16:20])
					srcIP := net.IP(raw[12:16])
					if r.server != nil && !r.server.allowLoopbackForTest {
						if blocked, _ := IsBlockedIP(dstIP); blocked {
							continue
						}
					}

					dstIPCopy := make(net.IP, len(dstIP))
					copy(dstIPCopy, dstIP)
					srcIPCopy := make(net.IP, len(srcIP))
					copy(srcIPCopy, srcIP)
					payloadCopy := make([]byte, len(icmpPayload))
					copy(payloadCopy, icmpPayload)

					go func(dst, src net.IP, req []byte) {
						var replyPayload []byte
						var err error
						if r.server != nil && r.server.icmpForwardHook != nil {
							replyPayload, err = r.server.icmpForwardHook(dst, req)
						} else {
							replyPayload, err = forwardRealICMPEcho(dst, req, 2*time.Second)
						}
						if err == nil && len(replyPayload) >= 8 && replyPayload[0] == 0 {
							replyIPv4 := buildIPv4ICMPPacket(dst, src, replyPayload)
							if replyIPv4 != nil {
								if r.server != nil && r.server.bandwidthLimiter != nil {
									r.server.bandwidthLimiter.Take(r.token, len(replyIPv4))
								}
								_, _ = r.conn.WritePacket(replyIPv4)
							}
						}
					}(dstIPCopy, srcIPCopy, payloadCopy)
					continue
				}
			}
		}

		// IPv6 handling: ICMPv6 PTB, ICMPv6 Echo, NAT66
		if raw[0]>>4 == 6 {
			if len(raw) < 40 {
				continue
			}

			// 1. IPv6 PMTU Backpressure (RFC 8200 / RFC 4443 Packet Too Big, Type 2 Code 0)
			curMax := 1360
			if len(raw) > curMax {
				gwIPv6 := net.ParseIP("fd88::1")
				ptbPkt := buildICMPv6PacketTooBig(raw, gwIPv6, uint32(curMax))
				if len(ptbPkt) > 0 {
					_, _ = r.conn.WritePacket(ptbPkt)
				}
				continue // 超限包本地回送 PTB 反压，绝不进入网络栈
			}

			// 2. Real ICMPv6 Echo Forwarding (NextHeader 58, Type 128 Echo Request -> Type 129 Echo Reply)
			if len(raw) >= 48 && raw[6] == 58 {
				icmpPayload := raw[40:]
				if icmpPayload[0] == 128 && icmpPayload[1] == 0 { // Echo Request
					dstIP := net.IP(raw[24:40])
					srcIP := net.IP(raw[8:24])
					if r.server != nil && !r.server.allowLoopbackForTest {
						if blocked, _ := IsBlockedIP(dstIP); blocked {
							continue
						}
					}

					dstIPCopy := make(net.IP, len(dstIP))
					copy(dstIPCopy, dstIP)
					srcIPCopy := make(net.IP, len(srcIP))
					copy(srcIPCopy, srcIP)
					payloadCopy := make([]byte, len(icmpPayload))
					copy(payloadCopy, icmpPayload)

					go func(dst, src net.IP, req []byte) {
						var replyPayload []byte
						var err error
						if r.server != nil && r.server.icmpv6ForwardHook != nil {
							replyPayload, err = r.server.icmpv6ForwardHook(dst, req)
						} else if r.server != nil && r.server.icmpForwardHook != nil {
							replyPayload, err = r.server.icmpForwardHook(dst, req)
						} else {
							replyPayload, err = forwardRealICMPv6Echo(dst, req, 2*time.Second)
						}
						if err == nil && len(replyPayload) >= 8 && replyPayload[0] == 129 { // Echo Reply
							replyIPv6 := buildIPv6ICMPv6Packet(dst, src, replyPayload)
							if replyIPv6 != nil {
								if r.server != nil && r.server.bandwidthLimiter != nil {
									r.server.bandwidthLimiter.Take(r.token, len(replyIPv6))
								}
								_, _ = r.conn.WritePacket(replyIPv6)
							}
						}
					}(dstIPCopy, srcIPCopy, payloadCopy)
					continue
				}
			}
		}

		proto := header.IPv4ProtocolNumber
		if raw[0]>>4 == 6 {
			proto = header.IPv6ProtocolNumber
		}

		v := buffer.NewViewSize(n)
		copy(v.AsSlice(), raw)
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithView(v),
		})
		r.gvEP.InjectInbound(proto, pkt)
		pkt.DecRef()
	}
}

func (r *UserSpaceNATRouter) pumpOutbound() {
	defer r.wg.Done()
	for {
		if r.gvEP == nil || r.ctx.Err() != nil {
			return
		}
		pkt := r.gvEP.ReadContext(r.ctx)
		if pkt == nil {
			return
		}
		view := pkt.ToView()
		if view != nil {
			b := view.AsSlice()
			if len(b) > 0 {
				if r.server.bandwidthLimiter != nil {
					r.server.bandwidthLimiter.Take(r.token, len(b))
				}
				_, _ = r.conn.WritePacket(b)
			}
			view.Release()
		}
		pkt.DecRef()
	}
}

func (r *UserSpaceNATRouter) handleTCP(req *tcp.ForwarderRequest) {
	id := req.ID()
	dst := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))

	if !r.server.allowLoopbackForTest {
		if blocked, _ := IsBlockedTarget(dst); blocked {
			req.Complete(true)
			return
		}
	}

	if r.server.connLimiter != nil && !r.server.connLimiter.TryAcquire(r.token) {
		req.Complete(true)
		return
	}

	wq := waiter.Queue{}
	ep, err := req.CreateEndpoint(&wq)
	if err != nil {
		req.Complete(true)
		if r.server.connLimiter != nil {
			r.server.connLimiter.Release(r.token)
		}
		return
	}
	req.Complete(false)

	localConn := gonet.NewTCPConn(&wq, ep)

	go func() {
		defer localConn.Close()
		if r.server.connLimiter != nil {
			defer r.server.connLimiter.Release(r.token)
		}

		var remoteConn net.Conn
		var dialErr error
		if r.server.dialGuard != nil {
			remoteConn, dialErr = r.server.dialGuard.DialTimeout("tcp", dst, 10*time.Second)
		} else {
			remoteConn, dialErr = net.DialTimeout("tcp", dst, 10*time.Second)
		}
		if dialErr != nil {
			return
		}
		defer remoteConn.Close()

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			bufPtr := natTCPBufPool.Get().(*[]byte)
			defer natTCPBufPool.Put(bufPtr)
			buf := *bufPtr
			for {
				n, err := localConn.Read(buf)
				if n > 0 {
					if _, werr := remoteConn.Write(buf[:n]); werr != nil {
						break
					}
				}
				if err != nil {
					break
				}
			}
			_ = remoteConn.Close()
		}()
		go func() {
			defer wg.Done()
			bufPtr := natTCPBufPool.Get().(*[]byte)
			defer natTCPBufPool.Put(bufPtr)
			buf := *bufPtr
			for {
				n, err := remoteConn.Read(buf)
				if n > 0 {
					if _, werr := localConn.Write(buf[:n]); werr != nil {
						break
					}
				}
				if err != nil {
					break
				}
			}
			_ = localConn.Close()
		}()
		wg.Wait()
	}()
}

func (r *UserSpaceNATRouter) handleUDP(req *udp.ForwarderRequest) bool {
	id := req.ID()
	dst := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))

	if !r.server.allowLoopbackForTest {
		if blocked, _ := IsBlockedTarget(dst); blocked {
			return true
		}
	}

	if !r.server.acquireUDPSlot(r.token) {
		return true
	}

	wq := waiter.Queue{}
	ep, err := req.CreateEndpoint(&wq)
	if err != nil {
		r.server.releaseUDPSlot(r.token)
		return true
	}

	localConn := gonet.NewUDPConn(&wq, ep)

	go func() {
		defer localConn.Close()
		defer r.server.releaseUDPSlot(r.token)

		dstUDP, err := net.ResolveUDPAddr("udp", dst)
		if err != nil {
			return
		}
		if !r.server.allowLoopbackForTest {
			if blocked, _ := IsBlockedIP(dstUDP.IP); blocked {
				return
			}
		}
		remoteUDP, err := r.server.dialUDP("udp", nil, dstUDP)
		if err != nil {
			return
		}
		defer remoteUDP.Close()

		lastActive := atomic.Int64{}
		lastActive.Store(time.Now().UnixNano())
		done := make(chan struct{})
		go func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					return
				case <-ticker.C:
					if time.Since(time.Unix(0, lastActive.Load())) > 45*time.Second {
						_ = remoteUDP.Close()
						_ = localConn.Close()
						return
					}
				}
			}
		}()
		defer close(done)

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			bufPtr := natUDPBufPool.Get().(*[]byte)
			defer natUDPBufPool.Put(bufPtr)
			buf := *bufPtr
			for {
				n, err := localConn.Read(buf)
				if n > 0 {
					lastActive.Store(time.Now().UnixNano())
					_, _ = remoteUDP.Write(buf[:n])
				}
				if err != nil {
					break
				}
			}
		}()
		go func() {
			defer wg.Done()
			bufPtr := natUDPBufPool.Get().(*[]byte)
			defer natUDPBufPool.Put(bufPtr)
			buf := *bufPtr
			for {
				n, err := remoteUDP.Read(buf)
				if n > 0 {
					lastActive.Store(time.Now().UnixNano())
					_, _ = localConn.Write(buf[:n])
				}
				if err != nil {
					break
				}
			}
		}()
		wg.Wait()
	}()

	return true
}

// forwardRealICMPEcho dials the target via raw ICMP, sends the Echo Request, and waits for Echo Reply.
// Best practice note for Linux unprivileged deployment:
// Raw ICMP ("ip4:icmp") requires raw socket permissions on Linux.
// To allow unprivileged execution without root, configure systemd service with:
//
//	AmbientCapabilities=CAP_NET_RAW
//
// Or configure sysctl ping_group_range:
//
//	sysctl -w net.ipv4.ping_group_range="0 2147483647"
//
// If permission is denied, forwardRealICMPEcho logs a friendly warning and returns an error without panicking.
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

// forwardRealICMPv6Echo dials the target via raw ICMPv6, sends the Echo Request, and waits for Echo Reply.
// Best practice note for Linux unprivileged deployment:
// Raw ICMPv6 ("ip6:ipv6-icmp") requires raw socket permissions on Linux.
// To allow unprivileged execution without root, configure systemd service with:
//
//	AmbientCapabilities=CAP_NET_RAW
//
// If permission is denied, forwardRealICMPv6Echo logs a friendly warning and returns an error without panicking.
func forwardRealICMPv6Echo(target net.IP, reqPayload []byte, timeout time.Duration) ([]byte, error) {
	conn, err := net.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		conn, err = net.ListenPacket("ip6:58", "::")
	}
	if err != nil {
		conn2, err2 := net.DialTimeout("ip6:ipv6-icmp", target.String(), timeout)
		if err2 != nil {
			conn2, err2 = net.DialTimeout("ip6:58", target.String(), timeout)
		}
		if err2 != nil {
			errStr := strings.ToLower(err2.Error())
			if strings.Contains(errStr, "permission denied") || strings.Contains(errStr, "operation not permitted") {
				log.Printf("[WARN] [NAT] ICMPv6 echo raw socket permission denied (target=%s): %v. Deployment best practice: configure AmbientCapabilities=CAP_NET_RAW in systemd service", target.String(), err2)
			}
			return nil, err2
		}
		defer conn2.Close()

		if err := conn2.SetDeadline(time.Now().Add(timeout)); err != nil {
			return nil, err
		}
		if _, err := conn2.Write(reqPayload); err != nil {
			return nil, err
		}

		buf := make([]byte, 65535)
		for {
			n, err := conn2.Read(buf)
			if err != nil {
				return nil, err
			}
			resp := buf[:n]
			if len(resp) >= 8 && resp[0] == 129 { // Type 129: ICMPv6 Echo Reply
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
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	dstAddr := &net.IPAddr{IP: target}
	if _, err := conn.WriteTo(reqPayload, dstAddr); err != nil {
		return nil, err
	}

	buf := make([]byte, 65535)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			return nil, err
		}
		if fromIP, ok := from.(*net.IPAddr); ok {
			if !fromIP.IP.Equal(target) {
				continue
			}
		}
		resp := buf[:n]
		if len(resp) >= 8 && resp[0] == 129 { // Type 129: ICMPv6 Echo Reply
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
