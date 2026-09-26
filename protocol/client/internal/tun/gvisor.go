package tun

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

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

const nicID = tcpip.NICID(1)

// startGvisor replaces the homemade TCP reconstruct path with the same
// userspace stack Clash/sing-box use. Outbound still goes through Dialer (AERO).
func (e *Engine) startGvisor() error {
	mtu := uint32(e.mtu)
	if mtu < 1280 {
		mtu = 1420
	}
	ep := channel.New(512, mtu, "")
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
	if err := s.CreateNIC(nicID, ep); err != nil {
		ep.Close()
		return fmt.Errorf("gvisor nic: %s", err)
	}
	_ = s.SetPromiscuousMode(nicID, true)
	_ = s.SetSpoofing(nicID, true)
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})
	protoAddr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4([4]byte{10, 88, 0, 2}),
			PrefixLen: 24,
		},
	}
	if err := s.AddProtocolAddress(nicID, protoAddr, stack.AddressProperties{}); err != nil {
		log.Printf("[TUN] gvisor addr: %s", err)
	}

	tcpFwd := tcp.NewForwarder(s, 0, 2048, func(r *tcp.ForwarderRequest) {
		e.handleGvisorTCP(r)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	udpFwd := udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		return e.handleGvisorUDP(r)
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	e.gvEP = ep
	e.gvStack = s

	e.wg.Add(2)
	go e.pumpTunToStack()
	go e.pumpStackToTun()
	log.Printf("[TUN] gVisor stack on %s mtu=%d (Clash/sing-box class)", e.device.Name(), mtu)
	return nil
}

func (e *Engine) destroyGvisor() {
	if e.gvEP != nil {
		e.gvEP.Close()
		e.gvEP = nil
	}
	if e.gvStack != nil {
		e.gvStack.Close()
		e.gvStack.Destroy()
		e.gvStack = nil
	}
}

func (e *Engine) pumpTunToStack() {
	defer e.wg.Done()
	buf := make([]byte, e.mtu+80)
	for {
		if e.ctx.Err() != nil {
			return
		}
		n, err := e.device.Read(buf)
		if e.ctx.Err() != nil {
			return
		}
		if err != nil {
			if n == 0 {
				select {
				case <-e.ctx.Done():
					return
				case <-time.After(20 * time.Millisecond):
				}
				continue
			}
			log.Printf("[TUN] read: %v", err)
			continue
		}
		if n == 0 {
			select {
			case <-e.ctx.Done():
				return
			case <-time.After(20 * time.Millisecond):
			}
			continue
		}
		if n < 20 || e.gvEP == nil {
			continue
		}
		raw := append([]byte(nil), buf[:n]...)
		proto := header.IPv4ProtocolNumber
		if raw[0]>>4 == 6 {
			proto = header.IPv6ProtocolNumber
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(raw),
		})
		e.gvEP.InjectInbound(proto, pkt)
		pkt.DecRef()
	}
}

func (e *Engine) pumpStackToTun() {
	defer e.wg.Done()
	for {
		if e.gvEP == nil {
			return
		}
		pkt := e.gvEP.ReadContext(e.ctx)
		if pkt == nil {
			return
		}
		view := pkt.ToView()
		if view != nil {
			b := view.AsSlice()
			if len(b) > 0 {
				if _, err := e.device.Write(b); err != nil {
					log.Printf("[TUN] gvisor write: %v", err)
				}
			}
			view.Release()
		}
		pkt.DecRef()
	}
}

func (e *Engine) handleGvisorTCP(r *tcp.ForwarderRequest) {
	// CreateEndpoint must not run on the stack's inject goroutine (deadlock).
	id := r.ID()
	dst := joinAddr(id.LocalAddress, id.LocalPort)
	if bypassTUNAddr(id.LocalAddress) {
		r.Complete(true)
		return
	}
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		wq := waiter.Queue{}
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			log.Printf("[TUN] gvisor TCP create %s: %s", dst, err)
			r.Complete(true)
			return
		}
		r.Complete(false)
		local := gonet.NewTCPConn(&wq, ep)
		defer local.Close()
		ctx, cancel := context.WithTimeout(e.ctx, 15*time.Second)
		remote, derr := e.dialer.DialTCP(ctx, dst)
		cancel()
		if derr != nil {
			log.Printf("[TUN] gvisor TCP %s: %v", dst, derr)
			return
		}
		defer remote.Close()
		relay(local, remote)
	}()
}

func (e *Engine) handleGvisorUDP(r *udp.ForwarderRequest) bool {
	id := r.ID()
	dst := joinAddr(id.LocalAddress, id.LocalPort)
	if bypassTUNAddr(id.LocalAddress) {
		if r.Packet() != nil {
			r.Packet().DecRef()
		}
		return true
	}

	// 1. WebRTC STUN 物理防泄露装甲：静默丢弃探针，彻底防止真实 IP 旁路泄露
	if id.LocalPort == 3478 || id.LocalPort == 19302 || id.LocalPort == 5349 {
		if r.Packet() != nil {
			r.Packet().DecRef()
		}
		return true
	}

	// 2. DNS (UDP 53) 本地 0ms 拦截：通过 Fake-IP 即时返回，根治 Edge/Chrome 卡死与公网 DNS 污染
	if id.LocalPort == 53 && e.dns != nil {
		wq := waiter.Queue{}
		ep, err := r.CreateEndpoint(&wq)
		if err == nil {
			local := gonet.NewUDPConn(&wq, ep)
			e.wg.Add(1)
			go func() {
				defer e.wg.Done()
				defer local.Close()
				buf := make([]byte, 1500)
				_ = local.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
				n, err := local.Read(buf)
				if err == nil && n > 0 {
					srcIP := net.ParseIP(id.RemoteAddress.String())
					if resp := e.dns.HandleQuery(buf[:n], srcIP, id.RemotePort); resp != nil {
						_, _ = local.Write(resp)
						return
					}
				}
				// 兜底：若 Fake-IP 未处理，回退到远程 UDP 代理隧道
				ctx, cancel := context.WithTimeout(e.ctx, 5*time.Second)
				remote, derr := e.dialer.DialUDP(ctx, dst)
				cancel()
				if derr != nil {
					return
				}
				defer remote.Close()
				relayIdle(local, remote, 3*time.Second)
			}()
			return true
		}
	}

	// One gVisor endpoint per 4-tuple. Duplicate packets before register
	// used to log "port is in use" and drop game/DNS bursts.
	key := joinAddr(id.RemoteAddress, id.RemotePort) + ">" + dst
	if _, loaded := e.udpSess.LoadOrStore(key, true); loaded {
		if r.Packet() != nil {
			r.Packet().DecRef()
		}
		return true
	}
	pkt := r.Packet()
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		defer e.udpSess.Delete(key)
		if pkt != nil {
			defer pkt.DecRef()
		}
		wq := waiter.Queue{}
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			log.Printf("[TUN] gvisor UDP create %s: %s", dst, err)
			return
		}
		local := gonet.NewUDPConn(&wq, ep)
		defer local.Close()
		ctx, cancel := context.WithTimeout(e.ctx, 10*time.Second)
		remote, derr := e.dialer.DialUDP(ctx, dst)
		cancel()
		if derr != nil {
			log.Printf("[TUN] gvisor UDP %s: %v", dst, derr)
			return
		}
		defer remote.Close()
		idleTimeout := 2 * time.Minute
		if strings.HasSuffix(dst, ":53") {
			idleTimeout = 3 * time.Second
		}
		relayIdle(local, remote, idleTimeout)
	}()
	return true
}

func joinAddr(addr tcpip.Address, port uint16) string {
	ip := net.ParseIP(addr.String())
	if ip == nil {
		return net.JoinHostPort(addr.String(), strconv.Itoa(int(port)))
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
}

func bypassTUNAddr(addr tcpip.Address) bool {
	ip := net.ParseIP(addr.String())
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
		return true
	}
	// Keep RFC1918 / link-local on the physical LAN (more-specific OS routes).
	if ip.IsPrivate() && !ip.To4().Equal(net.IPv4(10, 88, 0, 2)) {
		// 10.88.0.0/24 is the TUN itself; other private nets stay off AERO.
		if v4 := ip.To4(); v4 != nil && v4[0] == 10 && v4[1] == 88 {
			return true
		}
		return true
	}
	return false
}

func relay(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	copyClose := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		_ = dst.SetDeadline(time.Now())
	}
	go copyClose(a, b)
	go copyClose(b, a)
	wg.Wait()
}

var gvRelayBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 64*1024)
		return &b
	},
}

func relayIdle(a, b net.Conn, idle time.Duration) {
	var wg sync.WaitGroup
	wg.Add(2)
	copyIdle := func(dst, src net.Conn) {
		defer wg.Done()
		bp := gvRelayBufPool.Get().(*[]byte)
		defer gvRelayBufPool.Put(bp)
		buf := *bp
		for {
			_ = src.SetReadDeadline(time.Now().Add(idle))
			n, err := src.Read(buf)
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}
	go copyIdle(a, b)
	go copyIdle(b, a)
	wg.Wait()
}
