// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/connect-ip-go"
)

// IPPacketConn 抽象底层 IP 数据包传输连接（严格匹配 *connectip.Conn 导出方法）
type IPPacketConn interface {
	ReadPacket([]byte) (int, error)
	WritePacket([]byte) ([]byte, error)
	Close() error
}

// 编译期静态断言：保证与 connectip.Conn 接口对齐，同时满足规范 §4.4 并消除 unused import 报错
var _ IPPacketConn = (*connectip.Conn)(nil)

// IPDataPump 负责在 Wintun 虚拟网卡 (TunDevice) 与远端 CONNECT-IP 隧道 (IPPacketConn) 之间双向转发数据
type IPDataPump struct {
	dev            TunDevice
	conn           IPPacketConn
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	closed         atomic.Bool
	disconnectOnce sync.Once
	onDisconnect   atomic.Pointer[func(error)]
	killSwitch     *atomic.Bool
	dnsHandler     *DNSHandler
	bytesIn        atomic.Uint64
	bytesOut       atomic.Uint64
	currentMTU     atomic.Int32
	ipv6Blackhole  atomic.Bool
}

// SetOnDisconnect registers the single asynchronous disconnect callback.
func (p *IPDataPump) SetOnDisconnect(callback func(error)) {
	if callback == nil {
		p.onDisconnect.Store(nil)
		return
	}
	p.onDisconnect.Store(&callback)
}

func (p *IPDataPump) notifyDisconnect(err error) {
	p.disconnectOnce.Do(func() {
		callback := p.onDisconnect.Load()
		if callback == nil || *callback == nil {
			return
		}
		go func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					log.Printf("[PUMP] disconnect callback panic: %v", recovered)
				}
			}()
			(*callback)(err)
		}()
	})
}

// NewIPDataPump 创建数据泵实例
func NewIPDataPump(parentCtx context.Context, dev TunDevice, conn IPPacketConn, killSwitch *atomic.Bool, dnsHandler *DNSHandler) *IPDataPump {
	ctx, cancel := context.WithCancel(parentCtx)
	p := &IPDataPump{
		dev:        dev,
		conn:       conn,
		ctx:        ctx,
		cancel:     cancel,
		killSwitch: killSwitch,
		dnsHandler: dnsHandler,
	}
	p.currentMTU.Store(1224)
	return p
}

// CurrentMTU 返回当前路径收缩后生效的虚拟网卡 MTU
func (p *IPDataPump) CurrentMTU() int {
	return int(p.currentMTU.Load())
}

// SetKillSwitch 动态设置纯内存 Kill Switch 状态
func (p *IPDataPump) SetKillSwitch(active bool) {
	if p.killSwitch != nil {
		p.killSwitch.Store(active)
	}
}

// KillSwitch 返回当前 Kill Switch 激活状态
func (p *IPDataPump) KillSwitch() bool {
	if p.killSwitch != nil {
		return p.killSwitch.Load()
	}
	return false
}

// SetIPv6Blackhole 动态设置第 3 重 IPv6 黑洞防泄漏拦截状态 (方案 §3.2)
func (p *IPDataPump) SetIPv6Blackhole(active bool) {
	p.ipv6Blackhole.Store(active)
}

// IPv6Blackhole 返回当前 IPv6 黑洞防泄漏状态
func (p *IPDataPump) IPv6Blackhole() bool {
	return p.ipv6Blackhole.Load()
}

// Start 启动双向转发 Goroutine
func (p *IPDataPump) Start() {
	p.wg.Add(2)
	go p.pumpTunToRemote()
	go p.pumpRemoteToTun()
	log.Printf("[PUMP] IPDataPump started (dev: %s)", p.dev.Name())
}

// pumpTunToRemote 从本地 Wintun 网卡读取 IPv4 报文并送入 CONNECT-IP 隧道
func (p *IPDataPump) pumpTunToRemote() {
	defer p.wg.Done()
	defer p.cancel()

	buf := make([]byte, 65535)
	for {
		if p.ctx.Err() != nil || p.closed.Load() {
			return
		}

		n, err := p.dev.Read(buf)
		if err != nil {
			if !p.closed.Load() && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				log.Printf("[PUMP] read tun error: %v", err)
			}
			p.notifyDisconnect(err)
			return
		}
		if n < 20 {
			continue // 忽略小于 IPv4 最小头部的杂包
		}

		// 1. Fail-Closed 纯内存断网检查
		if p.killSwitch != nil && p.killSwitch.Load() {
			continue
		}

		raw := buf[:n]

		// 检查版本：转发 IPv4 (4) 与 IPv6 (6) 报文
		version := raw[0] >> 4
		if version != 4 && version != 6 {
			continue
		}

		if version == 4 {
			ihl := int(raw[0]&0x0F) * 4
			if len(raw) < ihl {
				continue
			}

			// 2. 本地虚拟网关 DNS 旁路拦截：若目的端口为 53 (如 10.88.0.1:53 或任何发往 DNS 端口的 UDP 报文)
			if len(raw) >= ihl+8 && raw[9] == 17 {
				dstPort := binary.BigEndian.Uint16(raw[ihl+2 : ihl+4])
				if dstPort == 53 && p.dnsHandler != nil {
					srcPort := binary.BigEndian.Uint16(raw[ihl : ihl+2])
					srcIP := net.IP(raw[12:16])
					dstIP := net.IP(raw[16:20])
					dnsPayload := raw[ihl+8:]
					if resp := p.dnsHandler.HandleQuery(dnsPayload, srcIP, srcPort); resp != nil {
						respPkt := buildIPv4UDPResponsePacket(dstIP, srcIP, dstPort, srcPort, resp)
						if len(respPkt) > 0 {
							_, _ = p.dev.Write(respPkt)
						}
					}
					continue
				}

				// 3. 阻断 WebRTC STUN 穿透报文 (IPv4 Protocol 17 = UDP)
				if isSTUNPacket(raw[ihl+8:]) {
					continue
				}
			}
		} else if version == 6 {
			if len(raw) < 40 {
				continue
			}

			// IPv6 Next Header 检查 (raw[6])：17 = UDP
			if raw[6] == 17 && len(raw) >= 48 {
				dstPort := binary.BigEndian.Uint16(raw[42:44])
				if dstPort == 53 && p.dnsHandler != nil {
					srcPort := binary.BigEndian.Uint16(raw[40:42])
					srcIP := net.IP(raw[8:24])
					dstIP := net.IP(raw[24:40])
					dnsPayload := raw[48:]
					if resp := p.dnsHandler.HandleQuery(dnsPayload, srcIP, srcPort); resp != nil {
						respPkt := buildIPv6UDPResponsePacket(dstIP, srcIP, dstPort, srcPort, resp)
						if len(respPkt) > 0 {
							_, _ = p.dev.Write(respPkt)
						}
					}
					continue
				}

				// 阻断 IPv6 WebRTC STUN 穿透报文
				if isSTUNPacket(raw[48:]) {
					continue
				}
			}

			// 第 3 重防泄漏 (方案 §3.2)：若开启 IPv6 黑洞模式，拒绝非 DNS 的 IPv6 报文，原生回写 ICMPv6 Type 1 Code 3
			if p.ipv6Blackhole.Load() {
				if unreach := buildICMPv6AddressUnreachable(raw); len(unreach) > 0 {
					_, _ = p.dev.Write(unreach)
				}
				continue
			}
		}

		// 4. 发送至远端 CONNECT-IP 隧道（原生透传所有 TCP、游戏 UDP 与 QUIC 443 报文）
		icmpPkt, werr := p.conn.WritePacket(raw)
		if len(icmpPkt) > 0 {
			// 回写本地虚拟网卡 (使操作系统/上层应用收到 Destination Unreachable / PTB 差错)
			_, _ = p.dev.Write(icmpPkt)
			if nextMTU := parseICMPNextHopMTU(icmpPkt); nextMTU > 0 {
				p.applyNextHopMTU(nextMTU)
			}
		}
		if werr != nil {
			if !p.closed.Load() {
				log.Printf("[PUMP] write remote error: %v", werr)
			}
			p.notifyDisconnect(werr)
			return
		}
		p.bytesOut.Add(uint64(n))
	}
}

// pumpRemoteToTun 从远端 CONNECT-IP 隧道读取 IP 报文并写入本地 Wintun 网卡
func (p *IPDataPump) pumpRemoteToTun() {
	defer p.wg.Done()
	defer p.cancel()

	buf := make([]byte, 65535) // 强制 65535，彻底杜绝大包截断
	for {
		if p.ctx.Err() != nil || p.closed.Load() {
			return
		}

		n, err := p.conn.ReadPacket(buf)
		if err != nil {
			if !p.closed.Load() && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				log.Printf("[PUMP] read remote error: %v", err)
			}
			p.notifyDisconnect(err)
			return
		}
		if n < 20 {
			continue
		}

		raw := buf[:n]

		// 写入 Wintun 虚拟网卡
		_, werr := p.dev.Write(raw)
		if werr != nil {
			if !p.closed.Load() {
				log.Printf("[PUMP] write tun error: %v", werr)
			}
			p.notifyDisconnect(werr)
			return
		}
		p.bytesIn.Add(uint64(n))
	}
}

// Close 安全关闭数据泵，等待 Goroutine 退出（带 300ms 超时保护防止网卡读阻塞挂死）
func (p *IPDataPump) Close() error {
	if !p.closed.CompareAndSwap(false, true) {
		return nil
	}
	p.cancel()
	closeErr := p.conn.Close()

	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(300 * time.Millisecond):
		log.Printf("[PUMP] IPDataPump close wait timeout, forcing shutdown (RX: %d, TX: %d)", p.bytesIn.Load(), p.bytesOut.Load())
		return closeErr
	}

	log.Printf("[PUMP] IPDataPump stopped. Total RX: %d bytes, TX: %d bytes", p.bytesIn.Load(), p.bytesOut.Load())
	return closeErr
}

// buildIPv4UDPResponsePacket 原生构造 IPv4/UDP 应答报文（回写虚拟网卡，零额外依赖）
func buildIPv4UDPResponsePacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	src4 := srcIP.To4()
	dst4 := dstIP.To4()
	if src4 == nil || dst4 == nil {
		return nil
	}

	udpLen := 8 + len(payload)
	ipTotalLen := 20 + udpLen
	pkt := make([]byte, ipTotalLen)

	// 1. IPv4 首部 (20 字节)
	pkt[0] = 0x45 // Version=4, IHL=5
	pkt[1] = 0x00 // DSCP/ECN
	binary.BigEndian.PutUint16(pkt[2:4], uint16(ipTotalLen))
	pkt[4] = 0x00
	pkt[5] = 0x00
	pkt[6] = 0x40 // Flags: DF=1
	pkt[7] = 0x00
	pkt[8] = 64 // TTL
	pkt[9] = 17 // Protocol: UDP
	copy(pkt[12:16], src4)
	copy(pkt[16:20], dst4)
	csum := calcChecksum(pkt[:20])
	binary.BigEndian.PutUint16(pkt[10:12], csum)

	// 2. UDP 首部 (8 字节)
	udpData := pkt[20:]
	binary.BigEndian.PutUint16(udpData[0:2], srcPort)
	binary.BigEndian.PutUint16(udpData[2:4], dstPort)
	binary.BigEndian.PutUint16(udpData[4:6], uint16(udpLen))
	binary.BigEndian.PutUint16(udpData[6:8], 0) // RFC 768: Checksum 0 表示不计算

	// 3. 载荷
	copy(udpData[8:], payload)
	return pkt
}

// buildIPv6UDPResponsePacket 原生构造 IPv6/UDP 应答报文（RFC 2460 伪首部强制校验和）
func buildIPv6UDPResponsePacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	src16 := srcIP.To16()
	dst16 := dstIP.To16()
	if src16 == nil || dst16 == nil {
		return nil
	}

	udpLen := 8 + len(payload)
	ipTotalLen := 40 + udpLen
	if ipTotalLen > 65535 {
		return nil
	}
	pkt := make([]byte, ipTotalLen)

	// 1. IPv6 首部 (40 字节)
	pkt[0] = 0x60 // Version=6, Traffic Class=0
	binary.BigEndian.PutUint16(pkt[4:6], uint16(udpLen))
	pkt[6] = 17 // Next Header: UDP
	pkt[7] = 64 // Hop Limit
	copy(pkt[8:24], src16)
	copy(pkt[24:40], dst16)

	// 2. UDP 首部 (8 字节)
	udpData := pkt[40:]
	binary.BigEndian.PutUint16(udpData[0:2], srcPort)
	binary.BigEndian.PutUint16(udpData[2:4], dstPort)
	binary.BigEndian.PutUint16(udpData[4:6], uint16(udpLen))
	copy(udpData[8:], payload)

	// 3. RFC 2460 IPv6 UDP 伪首部校验和 (IPv6 下 UDP 校验和强制计算)
	pseudo := make([]byte, 40)
	copy(pseudo[0:16], src16)
	copy(pseudo[16:32], dst16)
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(udpLen))
	pseudo[39] = 17

	var sum uint32
	addWords := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	addWords(pseudo)
	addWords(udpData)
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	csum := ^uint16(sum)
	if csum == 0 {
		csum = 0xFFFF
	}
	binary.BigEndian.PutUint16(udpData[6:8], csum)

	return pkt
}

// parseICMPNextHopMTU 从完整的 L3 ICMP 差错报文中精准提取 Next-Hop MTU (方案 §2.4)
func parseICMPNextHopMTU(pkt []byte) int {
	if len(pkt) < 28 {
		return 0
	}
	version := pkt[0] >> 4
	if version == 4 {
		ihl := int(pkt[0]&0x0F) * 4
		if len(pkt) < ihl+8 {
			return 0
		}
		// 校验 Protocol == 1 (ICMP), Type == 3 (Dest Unreachable), Code == 4 (Fragmentation Needed)
		if pkt[9] == 1 && pkt[ihl] == 3 && pkt[ihl+1] == 4 {
			// Next-Hop MTU 位于 ICMP 首部字节 6~7 (大端 uint16)
			return int(binary.BigEndian.Uint16(pkt[ihl+6 : ihl+8]))
		}
	} else if version == 6 {
		if len(pkt) < 40+8 {
			return 0
		}
		// 校验 Next Header == 58 (ICMPv6), Type == 2 (Packet Too Big), Code == 0
		if pkt[6] == 58 && pkt[40] == 2 && pkt[41] == 0 {
			// MTU 位于 ICMPv6 首部字节 4~7 (大端 uint32)
			return int(binary.BigEndian.Uint32(pkt[44:48]))
		}
	}
	return 0
}

func (p *IPDataPump) applyNextHopMTU(newMTU int) {
	if newMTU < 1224 || newMTU > 1500 {
		return // 越界异常值丢弃
	}
	for {
		cur := p.currentMTU.Load()
		if int32(newMTU) >= cur {
			break // 仅单调向下收缩，已小于等于当前 MTU 则忽略
		}
		if p.currentMTU.CompareAndSwap(cur, int32(newMTU)) {
			log.Printf("[PUMP] Path MTU clamped down to %d, updating virtual NIC", newMTU)
			_ = SetInterfaceMTU(p.dev.Name(), newMTU)
			break
		}
	}
}

// buildICMPv6AddressUnreachable 构造 ICMPv6 Type 1 Code 3 (Address Unreachable) (方案 §3.2)
func buildICMPv6AddressUnreachable(origPkt []byte) []byte {
	if len(origPkt) < 40 {
		return nil
	}
	origPayload := origPkt
	if len(origPayload) > 1232 {
		origPayload = origPayload[:1232]
	}
	payloadLen := 8 + len(origPayload)
	resp := make([]byte, 40+payloadLen)

	// 1. IPv6 首部
	resp[0] = 0x60
	binary.BigEndian.PutUint16(resp[4:6], uint16(payloadLen))
	resp[6] = 58 // Next Header: ICMPv6
	resp[7] = 64 // Hop Limit
	copy(resp[8:24], origPkt[24:40]) // Src = 原 Dst
	copy(resp[24:40], origPkt[8:24]) // Dst = 原 Src

	// 2. ICMPv6 首部
	icmp := resp[40:]
	icmp[0] = 1 // Type: Destination Unreachable
	icmp[1] = 3 // Code: Address Unreachable
	copy(icmp[8:], origPayload)

	// 3. 计算并填充 RFC 4443 ICMPv6 伪首部校验和
	pseudo := make([]byte, 40)
	copy(pseudo[0:16], resp[8:24])
	copy(pseudo[16:32], resp[24:40])
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(payloadLen))
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
	calc(icmp)
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	csum := ^uint16(sum)
	if csum == 0 {
		csum = 0xFFFF
	}
	binary.BigEndian.PutUint16(icmp[2:4], csum)
	return resp
}
