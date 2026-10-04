// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
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
			ipv4.NewProtocol,
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

		// Local ICMP echo fallback for diagnostic ping
		if raw[0]>>4 == 4 && raw[9] == 1 && n >= 28 {
			ihl := int(raw[0]&0x0F) * 4
			if n >= ihl+8 && raw[ihl] == 8 { // Echo Request
				reply := make([]byte, n)
				copy(reply, raw)
				copy(reply[12:16], raw[16:20])
				copy(reply[16:20], raw[12:16])
				reply[ihl] = 0
				reply[ihl+1] = 0
				reply[10] = 0
				reply[11] = 0
				ipChk := calcChecksum(reply[:ihl])
				reply[10] = byte(ipChk >> 8)
				reply[11] = byte(ipChk & 0xff)
				reply[ihl+2] = 0
				reply[ihl+3] = 0
				icmpChk := calcChecksum(reply[ihl:])
				reply[ihl+2] = byte(icmpChk >> 8)
				reply[ihl+3] = byte(icmpChk & 0xff)
				_, _ = r.conn.WritePacket(reply)
				continue
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
		remoteUDP, err := net.DialUDP("udp", nil, dstUDP)
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
