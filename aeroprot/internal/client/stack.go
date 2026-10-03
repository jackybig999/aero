// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
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

const gvisorNICID = tcpip.NICID(1)

// TunDevice 虚拟网卡接口
type TunDevice interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
	Name() string
}

// StackEngine 封装 gVisor 虚拟网络协议栈
type StackEngine struct {
	ctx                context.Context
	cancel             context.CancelFunc
	device             TunDevice
	gvEP               *channel.Endpoint
	gvStack            *stack.Stack
	dialer             *TunnelClient
	dns                *DNSHandler
	gatewayIP          net.IP
	wg                 sync.WaitGroup
	udpSess            sync.Map
	killSwitch         atomic.Bool
	webrtcRelayEnabled atomic.Bool
}

// NewStackEngine 创建网络栈引擎
func NewStackEngine(dev TunDevice, dialer *TunnelClient, dnsHandler *DNSHandler) *StackEngine {
	ctx, cancel := context.WithCancel(context.Background())
	return &StackEngine{
		ctx:       ctx,
		cancel:    cancel,
		device:    dev,
		dialer:    dialer,
		dns:       dnsHandler,
		gatewayIP: net.ParseIP("10.88.0.1"),
	}
}

// Start 启动 gVisor 协议栈
// 规则：Channel MTU >= 1280 (设为 1420 保证内部 buffer 充裕)
func (e *StackEngine) Start() error {
	mtu := uint32(1420)
	ep := channel.New(4096, mtu, "")
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

	if err := s.CreateNIC(gvisorNICID, ep); err != nil {
		ep.Close()
		return fmt.Errorf("create gvisor nic: %s", err)
	}

	_ = s.SetPromiscuousMode(gvisorNICID, true)
	_ = s.SetSpoofing(gvisorNICID, true)
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: gvisorNICID},
		{Destination: header.IPv6EmptySubnet, NIC: gvisorNICID},
	})

	protoAddr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4([4]byte{10, 88, 0, 2}),
			PrefixLen: 24,
		},
	}
	_ = s.AddProtocolAddress(gvisorNICID, protoAddr, stack.AddressProperties{})

	tcpFwd := tcp.NewForwarder(s, 0, 2048, func(r *tcp.ForwarderRequest) {
		e.handleTCP(r)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	udpFwd := udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		return e.handleUDP(r)
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	e.gvEP = ep
	e.gvStack = s

	e.wg.Add(2)
	go e.pumpTunToStack()
	go e.pumpStackToTun()

	log.Printf("[STACK] gVisor stack started on %s (MTU=%d)", e.device.Name(), mtu)
	return nil
}

// Stop 停止协议栈
func (e *StackEngine) Stop() {
	e.cancel()
	if e.gvEP != nil {
		e.gvEP.Close()
	}
	if e.gvStack != nil {
		e.gvStack.Close()
		e.gvStack.Destroy()
	}
	if e.device != nil {
		_ = e.device.Close()
	}
	e.wg.Wait()
}

// SetKillSwitch 激活或关闭纯内存 Kill Switch
func (e *StackEngine) SetKillSwitch(active bool) {
	e.killSwitch.Store(active)
}

// KillSwitch 返回当前 Kill Switch 激活状态
func (e *StackEngine) KillSwitch() bool {
	return e.killSwitch.Load()
}

// SetWebRTCActive 设置 WebRTC 中继转发激活状态
func (e *StackEngine) SetWebRTCActive(active bool) {
	e.webrtcRelayEnabled.Store(active)
}

// WebRTCActive 返回 WebRTC 中继转发是否已激活
func (e *StackEngine) WebRTCActive() bool {
	return e.webrtcRelayEnabled.Load()
}

// pumpTunToStack 从虚拟网卡读包注入网络栈
// 规则：在栈入口读取 IPv4 头 DF 标志：
// 若 len(packet) > currentMaxDatagramSize + 24：
//   - 若 DF 置位：构造 ICMP Type 3 Code 4 回写本地虚拟网卡（Next-MTU = currentMaxDatagramSize + 24，初始 1224，源 IP 为网关，目的 IP 为原源 IP，payload 为原 IPv4 头+8 字节，只写回本地网卡绝不发 VPS）；
//   - 若 DF 未置位：静默丢弃！
func (e *StackEngine) pumpTunToStack() {
	defer e.wg.Done()
	buf := make([]byte, 65535)

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
			continue
		}
		if n < 20 || e.gvEP == nil {
			continue
		}

		raw := buf[:n]

		// 检查 IPv4 数据报
		if raw[0]>>4 == 4 {
			curMax := GetCurrentMaxDatagramSize() + 24 // 初始 1200 + 24 = 1224
			if n > curMax {
				// 读取 DF (Don't Fragment) 标志：byte 6 bit 6 (0x40)
				df := (raw[6] & 0x40) != 0
				if df {
					icmpReply := buildICMPFragNeeded(raw, e.gatewayIP, uint16(curMax))
					if len(icmpReply) > 0 {
						_, _ = e.device.Write(icmpReply)
					}
				}
				// 无论是否回送 ICMP，超限包本身都绝不进入网络栈
				continue
			}
		}

		proto := header.IPv4ProtocolNumber
		if raw[0]>>4 == 6 {
			proto = header.IPv6ProtocolNumber
		}

		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(append([]byte(nil), raw...)),
		})
		e.gvEP.InjectInbound(proto, pkt)
		pkt.DecRef()
	}
}

func (e *StackEngine) pumpStackToTun() {
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
				_, _ = e.device.Write(b)
			}
			view.Release()
		}
		pkt.DecRef()
	}
}

// isSTUNPacket 检查载荷是否为 WebRTC STUN 协议报文 (RFC 5389/8489)
func isSTUNPacket(payload []byte) bool {
	return len(payload) >= 20 &&
		(payload[0]&0xC0 == 0) &&
		binary.BigEndian.Uint32(payload[4:8]) == 0x2112A442
}

// prefixedUDPConn 包装带有首包缓存的 UDP 连接，用于实现首包无损回放
type prefixedUDPConn struct {
	first []byte
	net.Conn
}

func (c *prefixedUDPConn) Read(b []byte) (int, error) {
	if len(c.first) > 0 {
		n := copy(b, c.first)
		c.first = c.first[n:]
		if len(c.first) == 0 {
			c.first = nil
		}
		return n, nil
	}
	return c.Conn.Read(b)
}

func (e *StackEngine) handleTCP(r *tcp.ForwarderRequest) {
	if e.killSwitch.Load() {
		r.Complete(true)
		return
	}
	id := r.ID()
	dst := joinHostPort(id.LocalAddress, id.LocalPort)
	if isPrivateOrLoopbackAddr(id.LocalAddress) {
		r.Complete(true)
		return
	}

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()

		target := dst
		localIP := net.ParseIP(id.LocalAddress.String())
		if localIP != nil && e.dns != nil && e.dns.fakeIP != nil && e.dns.fakeIP.Contains(localIP) {
			domain, release := e.dns.fakeIP.Acquire(localIP)
			if domain == "" {
				log.Printf("[STACK] orphan fake-ip rejected for TCP: %s", localIP)
				r.Complete(true)
				return
			}
			defer release()
			target = net.JoinHostPort(domain, strconv.Itoa(int(id.LocalPort)))
		}

		wq := waiter.Queue{}
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)

		local := gonet.NewTCPConn(&wq, ep)
		defer local.Close()

		var strat Strategy = PROXY
		host, _, splitErr := net.SplitHostPort(target)
		if splitErr != nil {
			host = target
		}
		hostIP := net.ParseIP(host)
		if hostIP == nil {
			hostIP = localIP
		}

		if e.dialer != nil && e.dialer.splitEngine != nil {
			strat = e.dialer.splitEngine.Match(host, hostIP)
		}

		if strat == DIRECT {
			ctx, cancel := context.WithTimeout(e.ctx, 15*time.Second)
			remote, derr := DialPhysicalDirect(ctx, "tcp", target)
			cancel()
			if derr != nil {
				return
			}
			defer remote.Close()
			relayTraffic(local, remote)
			return
		}

		ctx, cancel := context.WithTimeout(e.ctx, 15*time.Second)
		remote, derr := e.dialer.DialTCP(ctx, target)
		cancel()
		if derr != nil {
			return
		}
		defer remote.Close()

		relayTraffic(local, remote)
	}()
}

func (e *StackEngine) handleUDP(r *udp.ForwarderRequest) bool {
	if e.killSwitch.Load() {
		if r.Packet() != nil {
			r.Packet().DecRef()
		}
		return true
	}
	id := r.ID()
	dst := joinHostPort(id.LocalAddress, id.LocalPort)
	if isPrivateOrLoopbackAddr(id.LocalAddress) {
		if r.Packet() != nil {
			r.Packet().DecRef()
		}
		return true
	}

	// 1. WebRTC STUN 物理防泄露：阶段一未激活时静默丢弃 3478 / 19302 / 5349
	if id.LocalPort == 3478 || id.LocalPort == 19302 || id.LocalPort == 5349 {
		if !e.webrtcRelayEnabled.Load() {
			if r.Packet() != nil {
				r.Packet().DecRef()
			}
			return true
		}
	}

	// 2. 拦截端口 53 DNS 查询：
	// 规则：彻底删除端口 53 返回 nil 后的 DialUDP 兜底（直接栈内 DecRef() 丢弃）！
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
				// 核心铁律：返回 nil 时绝对不触发 DialUDP！直接静默退出
			}()
			return true
		}
	}

	// 3. 普通 UDP 业务数据报（第一包登记 Context，后续包排队写入同一 Context）
	key := joinHostPort(id.RemoteAddress, id.RemotePort) + ">" + dst
	if _, loaded := e.udpSess.LoadOrStore(key, true); loaded {
		if r.Packet() != nil {
			r.Packet().DecRef()
		}
		return true
	}

	wq := waiter.Queue{}
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
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

		local := gonet.NewUDPConn(&wq, ep)
		defer local.Close()

		var activeLocal net.Conn = local
		if !e.webrtcRelayEnabled.Load() && id.LocalPort != 3478 && id.LocalPort != 19302 && id.LocalPort != 5349 {
			peekBuf := make([]byte, 65535)
			_ = local.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
			n, err := local.Read(peekBuf)
			_ = local.SetReadDeadline(time.Time{})
			if err == nil && n > 0 {
				if isSTUNPacket(peekBuf[:n]) {
					log.Printf("[STACK] blocked deep WebRTC STUN packet to %s", dst)
					return
				}
				activeLocal = &prefixedUDPConn{
					first: append([]byte(nil), peekBuf[:n]...),
					Conn:  local,
				}
			}
		}

		targetHost := id.LocalAddress.String()
		targetPort := uint32(id.LocalPort)
		localIP := net.ParseIP(targetHost)
		if localIP != nil && e.dns != nil && e.dns.fakeIP != nil && e.dns.fakeIP.Contains(localIP) {
			domain, release := e.dns.fakeIP.Acquire(localIP)
			if domain == "" {
				log.Printf("[STACK] orphan fake-ip rejected for UDP: %s", localIP)
				return
			}
			defer release()
			targetHost = domain
		}

		target := fmt.Sprintf("%s:%d", targetHost, targetPort)

		var strat Strategy = PROXY
		hostIP := localIP
		if e.dialer != nil && e.dialer.splitEngine != nil {
			strat = e.dialer.splitEngine.Match(targetHost, hostIP)
		}

		if strat == DIRECT {
			ctx, cancel := context.WithTimeout(e.ctx, 15*time.Second)
			remote, derr := DialPhysicalDirect(ctx, "udp", target)
			cancel()
			if derr != nil {
				return
			}
			defer remote.Close()
			relayTraffic(activeLocal, remote)
			return
		}

		if e.dialer != nil && e.dialer.sessionMgr != nil {
			ctx, cancel := context.WithTimeout(e.ctx, 10*time.Second)
			remote, err := e.dialer.sessionMgr.DialUDP(ctx, target)
			cancel()
			if err != nil {
				return
			}
			defer remote.Close()
			relayTraffic(activeLocal, remote)
			return
		}

		contextID := contextIDCounter.Add(1)
		ctx, cancel := context.WithTimeout(e.ctx, 5*time.Second)
		regErr := e.dialer.RegisterUDPContext(ctx, contextID, targetHost, targetPort)
		cancel()
		if regErr != nil {
			return
		}

		// 注册入站回包分发
		RegisterInboundDatagramHandler(contextID, func(payload []byte) {
			_, _ = activeLocal.Write(payload)
		})
		defer UnregisterInboundDatagramHandler(contextID)

		// 出站读循环向远端发送数据报
		buf := make([]byte, 65535)
		for {
			_ = activeLocal.SetReadDeadline(time.Now().Add(45 * time.Second))
			n, err := activeLocal.Read(buf)
			if err != nil {
				return
			}
			if n > 0 {
				_ = e.dialer.SendDatagram(contextID, buf[:n])
			}
		}
	}()

	return true
}

func joinHostPort(addr tcpip.Address, port uint16) string {
	ip := net.ParseIP(addr.String())
	if ip == nil {
		return net.JoinHostPort(addr.String(), strconv.Itoa(int(port)))
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
}

func isPrivateOrLoopbackAddr(addr tcpip.Address) bool {
	ip := net.ParseIP(addr.String())
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
		return true
	}
	v4 := ip.To4()
	if v4 != nil {
		if ip.IsPrivate() && !v4.Equal(net.IPv4(10, 88, 0, 2)) {
			return true
		}
		return false
	}
	return ip.IsPrivate()
}

func isLoopbackHost(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

var (
	physicalDialerHookMu sync.RWMutex
	physicalDialerHook   func(ctx context.Context, network, addr string) (net.Conn, error)
)

// SetPhysicalDialerHook 允许单元测试注入物理直连拨号钩子（彻底隔离宿主机防火墙与第三方 TUN 干扰）
func SetPhysicalDialerHook(fn func(ctx context.Context, network, addr string) (net.Conn, error)) {
	physicalDialerHookMu.Lock()
	physicalDialerHook = fn
	physicalDialerHookMu.Unlock()
}

func getPhysicalDialerHook() func(ctx context.Context, network, addr string) (net.Conn, error) {
	physicalDialerHookMu.RLock()
	defer physicalDialerHookMu.RUnlock()
	return physicalDialerHook
}

func relayTraffic(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	pipe := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		_ = dst.SetDeadline(time.Now())
	}
	go pipe(a, b)
	go pipe(b, a)
	wg.Wait()
}

// buildICMPFragNeeded 构造 ICMP Type 3 Code 4 (Fragmentation Needed and DF Set)
// 目的 IP 为原包源 IP，源 IP 为虚拟网卡网关，Next-MTU 为 nextMTU
func buildICMPFragNeeded(origPkt []byte, gwIP net.IP, nextMTU uint16) []byte {
	if len(origPkt) < 20 {
		return nil
	}
	ihl := int(origPkt[0]&0x0F) * 4
	if ihl < 20 || ihl > len(origPkt) {
		return nil
	}
	payloadLen := ihl + 8
	if payloadLen > len(origPkt) {
		payloadLen = len(origPkt)
	}

	origSrcIP := origPkt[12:16]
	gw4 := gwIP.To4()
	if gw4 == nil {
		gw4 = []byte{10, 88, 0, 1}
	}

	icmpLen := 8 + payloadLen
	ipTotalLen := 20 + icmpLen

	pkt := make([]byte, ipTotalLen)

	// 1. IPv4 Header (20 bytes)
	pkt[0] = 0x45
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], uint16(ipTotalLen))
	pkt[4] = 0x00
	pkt[5] = 0x00
	pkt[6] = 0x00
	pkt[7] = 0x00
	pkt[8] = 64 // TTL
	pkt[9] = 1  // Protocol: ICMP
	// Checksum at 10:12 calculated later
	copy(pkt[12:16], gw4)
	copy(pkt[16:20], origSrcIP)
	ipChecksum := calcChecksum(pkt[:20])
	binary.BigEndian.PutUint16(pkt[10:12], ipChecksum)

	// 2. ICMP Header (8 bytes)
	icmpData := pkt[20:]
	icmpData[0] = 3 // Type: Destination Unreachable
	icmpData[1] = 4 // Code: Fragmentation Needed and DF Set
	// Checksum at 2:4
	icmpData[4] = 0x00
	icmpData[5] = 0x00
	binary.BigEndian.PutUint16(icmpData[6:8], nextMTU) // Next-Hop MTU

	// 3. ICMP Payload (Original IPv4 header + 8 bytes of original datagram)
	copy(icmpData[8:], origPkt[:payloadLen])
	icmpChecksum := calcChecksum(icmpData)
	binary.BigEndian.PutUint16(icmpData[2:4], icmpChecksum)

	return pkt
}

func calcChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
