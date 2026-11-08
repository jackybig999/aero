// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// TunDevice 虚拟网卡接口
type TunDevice interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
	Name() string
}

// TunnelEngine 统一抽象客户端隧道门面接口 (方案 §2.1)
type TunnelEngine interface {
	Start() error
	Stop()
	SetKillSwitch(bool)
	KillSwitch() bool
	SetWebRTCActive(bool)
	WebRTCActive() bool
	SetDNSOnlyMode(bool)
	DNSOnlyMode() bool
	SetICMPOutboundHookForTest(func([]byte))
}

var _ TunnelEngine = (*StackEngine)(nil)

// StackEngine 原生数据面引擎 (彻底下线 gVisor，全面由 IPDataPump 独占驱动)
type StackEngine struct {
	ctx                context.Context
	cancel             context.CancelFunc
	device             TunDevice
	conn               IPPacketConn
	pump               *IPDataPump
	dialer             *TunnelClient
	dns                *DNSHandler
	gatewayIP          net.IP
	closeDevice        bool
	killSwitch         atomic.Bool
	dnsOnlyMode        atomic.Bool
	webrtcRelayEnabled atomic.Bool
	icmpOutboundHook   func(pkt []byte)
	onDisconnect       func(error)
	wg                 sync.WaitGroup
	mu                 sync.Mutex
}

// NewStackEngine 创建网络栈引擎 (兼容原有接口，但内部零 gVisor 依赖)
func NewStackEngine(dev TunDevice, dialer *TunnelClient, dnsHandler *DNSHandler) *StackEngine {
	ctx, cancel := context.WithCancel(context.Background())
	return &StackEngine{
		ctx:         ctx,
		cancel:      cancel,
		device:      dev,
		dialer:      dialer,
		dns:         dnsHandler,
		gatewayIP:   net.ParseIP("10.88.0.1"),
		closeDevice: true,
	}
}

// NewStackEngineWithConn 基于协商成功的 CONNECT-IP 隧道连接创建原生数据面
func NewStackEngineWithConn(dev TunDevice, conn IPPacketConn, dnsHandler *DNSHandler) *StackEngine {
	ctx, cancel := context.WithCancel(context.Background())
	return &StackEngine{
		ctx:         ctx,
		cancel:      cancel,
		device:      dev,
		conn:        conn,
		dns:         dnsHandler,
		gatewayIP:   net.ParseIP("10.88.0.1"),
		closeDevice: false,
	}
}

func (e *StackEngine) SetOnDisconnect(cb func(error)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.onDisconnect = cb
	if e.pump != nil {
		e.pump.SetOnDisconnect(cb)
	}
}

func (e *StackEngine) RestartWithConn(newConn IPPacketConn, prefixes []netip.Prefix) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.pump != nil {
		_ = e.pump.Close()
		e.pump = nil
	}

	e.conn = newConn
	if newConn != nil && e.device != nil {
		e.pump = NewIPDataPump(e.ctx, e.device, e.conn, &e.killSwitch, e.dns)
		e.pump.SetWebRTCActive(e.webrtcRelayEnabled.Load())
		if e.onDisconnect != nil {
			e.pump.SetOnDisconnect(e.onDisconnect)
		}
		e.pump.Start()
		log.Printf("[STACK] RestartWithConn: IPDataPump restored on %s", e.device.Name())
	}
	return nil
}

func (e *StackEngine) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.conn != nil && e.device != nil {
		e.pump = NewIPDataPump(e.ctx, e.device, e.conn, &e.killSwitch, e.dns)
		e.pump.SetWebRTCActive(e.webrtcRelayEnabled.Load())
		if e.onDisconnect != nil {
			e.pump.SetOnDisconnect(e.onDisconnect)
		}
		e.pump.Start()
		log.Printf("[STACK] CONNECT-IP data plane started on %s (MTU=1224, Zero-gVisor)", e.device.Name())
		return nil
	}

	if e.device != nil {
		e.wg.Add(1)
		go e.runLegacyDispatcher()
	}

	log.Printf("[STACK] native data plane initialized (mode=standalone)")
	return nil
}

func (e *StackEngine) Stop() {
	e.mu.Lock()
	if e.cancel != nil {
		e.cancel()
	}
	if e.pump != nil {
		_ = e.pump.Close()
		e.pump = nil
	}
	if e.closeDevice && e.device != nil {
		_ = e.device.Close()
	}
	e.mu.Unlock()

	e.wg.Wait()

	e.mu.Lock()
	if e.closeDevice {
		e.device = nil
	}
	e.mu.Unlock()
}

func (e *StackEngine) SetKillSwitch(active bool) {
	e.killSwitch.Store(active)
	if e.pump != nil && e.pump.killSwitch != nil {
		e.pump.killSwitch.Store(active)
	}
}

func (e *StackEngine) KillSwitch() bool {
	return e.killSwitch.Load()
}

func (e *StackEngine) SetWebRTCActive(active bool) {
	e.webrtcRelayEnabled.Store(active)
	e.mu.Lock()
	pump := e.pump
	e.mu.Unlock()
	if pump != nil {
		pump.SetWebRTCActive(active)
	}
}

func (e *StackEngine) WebRTCActive() bool {
	return e.webrtcRelayEnabled.Load()
}

func (e *StackEngine) SetDNSOnlyMode(active bool) {
	e.dnsOnlyMode.Store(active)
}

func (e *StackEngine) DNSOnlyMode() bool {
	return e.dnsOnlyMode.Load()
}

func (e *StackEngine) SetICMPOutboundHookForTest(hook func(pkt []byte)) {
	e.icmpOutboundHook = hook
}

// runLegacyDispatcher 单测兼容纯 Go 报文分发器 (无需 gVisor)
func (e *StackEngine) runLegacyDispatcher() {
	defer e.wg.Done()
	e.mu.Lock()
	dev := e.device
	e.mu.Unlock()
	if dev == nil {
		return
	}
	buf := make([]byte, 65535)

	for {
		if e.ctx.Err() != nil {
			return
		}
		n, err := dev.Read(buf)
		if err != nil {
			return
		}
		if n < 20 || e.killSwitch.Load() {
			continue
		}

		raw := buf[:n]
		if (raw[0] >> 4) != 4 {
			continue // 仅处理 IPv4 测试流
		}
		ihl := int(raw[0]&0x0F) * 4
		if ihl < 20 || n < ihl {
			continue
		}

		proto := raw[9]
		srcIP := net.IP(raw[12:16])
		dstIP := net.IP(raw[16:20])

		if proto == 17 && n >= ihl+8 { // UDP
			srcPort := binary.BigEndian.Uint16(raw[ihl : ihl+2])
			dstPort := binary.BigEndian.Uint16(raw[ihl+2 : ihl+4])
			payload := raw[ihl+8:]

			// 1. DNS 拦截
			if dstPort == 53 && e.dns != nil {
				if resp := e.dns.HandleQuery(payload, srcIP, srcPort); resp != nil {
					respPkt := buildIPv4UDPPacket(dstIP, srcIP, dstPort, srcPort, resp)
					_, _ = e.device.Write(respPkt)
				}
				continue
			}

			// 2. WebRTC STUN 阻断与放行
			isSTUN := (dstPort == 3478 || dstPort == 19302 || dstPort == 5349 || isSTUNPacket(payload))
			if isSTUN && !e.WebRTCActive() {
				continue // 阶段一防泄漏丢弃
			}

			// 3. Fake-IP 查找与生命周期 Acquire
			targetAddr := dstIP.String() + ":" + strconv.Itoa(int(dstPort))
			targetHost := dstIP.String()
			var fakeRelease func()
			if e.dns != nil && e.dns.FakeIP() != nil && e.dns.FakeIP().Contains(dstIP) {
				domain, rel := e.dns.FakeIP().Acquire(dstIP)
				if domain == "" {
					continue // 孤儿 Fake-IP 熔断阻断
				}
				targetHost = domain
				targetAddr = domain + ":" + strconv.Itoa(int(dstPort))
				fakeRelease = rel
			}

			// 4. 发起拨号与中继 (优先使用 PhysicalDialerHook)
			hook := getPhysicalDialerHook()
			if hook != nil {
				go func(target string, data []byte, rel func()) {
					if rel != nil {
						defer rel()
					}
					conn, dErr := hook(e.ctx, "udp", target)
					if dErr == nil && conn != nil {
						defer conn.Close()
						_, _ = conn.Write(data)
					}
				}(targetAddr, payload, fakeRelease)
			} else if e.dialer != nil {
				go func(host string, port uint32, rel func()) {
					if rel != nil {
						defer rel()
					}
					_ = e.dialer.RegisterUDPContext(e.ctx, 1, host, port)
				}(targetHost, uint32(dstPort), fakeRelease)
			}
		} else if proto == 6 && n >= ihl+20 { // TCP
			dstPort := binary.BigEndian.Uint16(raw[ihl+2 : ihl+4])
			targetAddr := dstIP.String() + ":" + strconv.Itoa(int(dstPort))
			var fakeRelease func()
			if e.dns != nil && e.dns.FakeIP() != nil && e.dns.FakeIP().Contains(dstIP) {
				domain, rel := e.dns.FakeIP().Acquire(dstIP)
				if domain == "" {
					continue // 孤儿 Fake-IP 熔断阻断
				}
				targetAddr = domain + ":" + strconv.Itoa(int(dstPort))
				fakeRelease = rel
			}
			hook := getPhysicalDialerHook()
			if hook != nil {
				go func(target string, rel func()) {
					if rel != nil {
						defer rel()
					}
					conn, dErr := hook(e.ctx, "tcp", target)
					if dErr == nil && conn != nil {
						defer conn.Close()
					}
				}(targetAddr, fakeRelease)
			} else if e.dialer != nil {
				go func(target string, rel func()) {
					if rel != nil {
						defer rel()
					}
					conn, _ := e.dialer.DialTCP(e.ctx, target)
					if conn != nil {
						_ = conn.Close()
					}
				}(targetAddr, fakeRelease)
			}
		} else if proto == 1 && n >= ihl+8 { // ICMP
			if !dstIP.Equal(net.IPv4(10, 88, 0, 2)) && !dstIP.Equal(net.IPv4(10, 88, 0, 1)) && e.icmpOutboundHook != nil {
				e.icmpOutboundHook(raw)
			}
		}
	}
}

// --- 纯净网络工具函数 (零外部 gVisor 依赖) ---

func buildIPv4UDPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	totalLen := 20 + 8 + len(payload)
	b := make([]byte, totalLen)

	// IPv4 Header (20 bytes)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(totalLen))
	b[8] = 64
	b[9] = 17 // UDP
	copy(b[12:16], srcIP.To4())
	copy(b[16:20], dstIP.To4())
	var ipCsum uint32
	for i := 0; i < 20; i += 2 {
		ipCsum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	for ipCsum > 0xffff {
		ipCsum = (ipCsum & 0xffff) + (ipCsum >> 16)
	}
	binary.BigEndian.PutUint16(b[10:12], ^uint16(ipCsum))

	// UDP Header (8 bytes)
	binary.BigEndian.PutUint16(b[20:22], srcPort)
	binary.BigEndian.PutUint16(b[22:24], dstPort)
	binary.BigEndian.PutUint16(b[24:26], uint16(8+len(payload)))
	copy(b[28:], payload)
	return b
}

func isSTUNPacket(payload []byte) bool {
	return len(payload) >= 20 &&
		(payload[0]&0xC0 == 0) &&
		binary.BigEndian.Uint32(payload[4:8]) == 0x2112A442
}

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

func joinHostPort(host string, port uint16) string {
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

func isPrivateOrLoopbackAddr(v any) bool {
	if v == nil {
		return false
	}
	var ip net.IP
	switch val := v.(type) {
	case net.IP:
		ip = val
	case string:
		ip = net.ParseIP(val)
	default:
		if s, ok := v.(interface{ String() string }); ok {
			ip = net.ParseIP(s.String())
		}
	}
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
		return true
	}
	v4 := ip.To4()
	if v4 != nil {
		if ip.IsPrivate() && !v4.Equal(net.IPv4(10, 88, 0, 2)) && !v4.Equal(net.IPv4(10, 88, 0, 1)) {
			return true
		}
		return false
	}
	if ip.IsPrivate() {
		if ip.Equal(net.ParseIP("fd88::2")) || ip.Equal(net.ParseIP("fd88::1")) {
			return false
		}
		return true
	}
	return false
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

func SetPhysicalDialerHook(fn func(ctx context.Context, network, addr string) (net.Conn, error)) {
	physicalDialerHookMu.Lock()
	defer physicalDialerHookMu.Unlock()
	physicalDialerHook = fn
}

func getPhysicalDialerHook() func(ctx context.Context, network, addr string) (net.Conn, error) {
	physicalDialerHookMu.RLock()
	defer physicalDialerHookMu.RUnlock()
	return physicalDialerHook
}

func isUDPConn(c net.Conn) bool {
	if c == nil {
		return false
	}
	if _, ok := c.(*net.UDPConn); ok {
		return true
	}
	if pref, ok := c.(*prefixedUDPConn); ok {
		return isUDPConn(pref.Conn)
	}
	if la := c.LocalAddr(); la != nil && strings.HasPrefix(strings.ToLower(la.Network()), "udp") {
		return true
	}
	if ra := c.RemoteAddr(); ra != nil && strings.HasPrefix(strings.ToLower(ra.Network()), "udp") {
		return true
	}
	return false
}

type closeWriter interface {
	CloseWrite() error
}

var relayBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 64*1024)
		return &b
	},
}

func relayTraffic(a, b net.Conn, ctxs ...context.Context) {
	var ctx context.Context
	if len(ctxs) > 0 && ctxs[0] != nil {
		ctx = ctxs[0]
	} else {
		ctx = context.Background()
	}

	isUDP := isUDPConn(a) || isUDPConn(b)

	ctxDone := make(chan struct{})
	defer close(ctxDone)
	if ctx.Done() != nil {
		go func() {
			select {
			case <-ctx.Done():
				_ = a.Close()
				_ = b.Close()
			case <-ctxDone:
			}
		}()
	}

	if isUDP {
		lastActive := atomic.Int64{}
		lastActive.Store(time.Now().UnixNano())
		idleDone := make(chan struct{})
		go func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-idleDone:
					return
				case <-ticker.C:
					if time.Since(time.Unix(0, lastActive.Load())) > 45*time.Second {
						_ = a.Close()
						_ = b.Close()
						return
					}
				}
			}
		}()
		defer close(idleDone)

		var wg sync.WaitGroup
		wg.Add(2)
		pipeUDP := func(dst, src net.Conn) {
			defer wg.Done()
			defer func() {
				_ = dst.Close()
				_ = src.Close()
			}()
			bufPtr := relayBufPool.Get().(*[]byte)
			defer relayBufPool.Put(bufPtr)
			buf := *bufPtr

			for {
				n, err := src.Read(buf)
				if n > 0 {
					lastActive.Store(time.Now().UnixNano())
					payload := SanitizeWebRTCPayload(buf[:n])
					if _, werr := dst.Write(payload); werr != nil {
						break
					}
				}
				if err != nil {
					break
				}
			}
		}
		go pipeUDP(a, b)
		go pipeUDP(b, a)
		wg.Wait()
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	pipe := func(dst, src net.Conn) {
		defer wg.Done()
		bufPtr := relayBufPool.Get().(*[]byte)
		defer relayBufPool.Put(bufPtr)
		buf := *bufPtr

		for {
			_ = src.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, err := src.Read(buf)
			if n > 0 {
				_ = src.SetReadDeadline(time.Now().Add(60 * time.Second))
				payload := buf[:n]
				if bytes.Contains(payload, []byte("candidate")) || bytes.Contains(payload, []byte("c=IN IP6")) || isSTUNPacket(payload) {
					payload = SanitizeWebRTCPayload(payload)
				}
				if _, werr := dst.Write(payload); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.SetDeadline(time.Now().Add(30 * time.Second))
		}
	}
	go pipe(a, b)
	go pipe(b, a)
	wg.Wait()
}

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

	// IPv4 Header (20 bytes)
	pkt[0] = 0x45
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], uint16(ipTotalLen))
	pkt[8] = 64
	pkt[9] = 1 // ICMP
	copy(pkt[12:16], gw4)
	copy(pkt[16:20], origSrcIP)
	ipChecksum := calcChecksum(pkt[:20])
	binary.BigEndian.PutUint16(pkt[10:12], ipChecksum)

	// ICMP Header (8 bytes)
	icmpData := pkt[20:]
	icmpData[0] = 3 // Destination Unreachable
	icmpData[1] = 4 // Fragmentation Needed and DF Set
	binary.BigEndian.PutUint16(icmpData[6:8], nextMTU)

	// ICMP Payload
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

func isPublicDoHEndpoint(ipStr string, port uint16) bool {
	if port != 443 && port != 853 {
		return false
	}
	switch ipStr {
	case "1.1.1.1", "1.0.0.1",
		"8.8.8.8", "8.8.4.4",
		"9.9.9.9", "149.112.112.112",
		"208.67.222.222", "208.67.220.220",
		"223.5.5.5", "223.6.6.6",
		"119.29.29.29", "180.76.76.76":
		return true
	}
	return false
}
