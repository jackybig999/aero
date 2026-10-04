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

// UserSpaceNATRouter implements a real RFC 9484 CONNECT-IP user-space NAT router.
// It accepts client IP packets, routes them in user-space, dials real external
// internet targets, and re-encapsulates return packets back to the client.
type UserSpaceNATRouter struct {
	server   *QUICServer
	token    string
	clientIP netip.Addr
	conn     *connectip.Conn
	gvEP     *channel.Endpoint
	gvStack  *stack.Stack
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

// NewUserSpaceNATRouter creates and starts a user-space NAT router for a CONNECT-IP session.
func NewUserSpaceNATRouter(parentCtx context.Context, server *QUICServer, token string, clientIP netip.Addr, conn *connectip.Conn) (*UserSpaceNATRouter, error) {
	ctx, cancel := context.WithCancel(parentCtx)

	ep := channel.New(512, 1420, "")
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

	r := &UserSpaceNATRouter{
		server:   server,
		token:    token,
		clientIP: clientIP,
		conn:     conn,
		gvEP:     ep,
		gvStack:  s,
		ctx:      ctx,
		cancel:   cancel,
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
	buf := make([]byte, 65535)

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
			buf := make([]byte, 32768)
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
			buf := make([]byte, 32768)
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
			buf := make([]byte, 65535)
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
			buf := make([]byte, 65535)
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
