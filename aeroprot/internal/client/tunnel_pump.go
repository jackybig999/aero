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
	dev        TunDevice
	conn       IPPacketConn
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	closed     atomic.Bool
	killSwitch *atomic.Bool
	dnsHandler *DNSHandler
	bytesIn    atomic.Uint64
	bytesOut   atomic.Uint64
}

// NewIPDataPump 创建数据泵实例
func NewIPDataPump(parentCtx context.Context, dev TunDevice, conn IPPacketConn, killSwitch *atomic.Bool, dnsHandler *DNSHandler) *IPDataPump {
	ctx, cancel := context.WithCancel(parentCtx)
	return &IPDataPump{
		dev:        dev,
		conn:       conn,
		ctx:        ctx,
		cancel:     cancel,
		killSwitch: killSwitch,
		dnsHandler: dnsHandler,
	}
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

		// 检查版本：仅转发 IPv4 报文 (版本号 4)
		if raw[0]>>4 != 4 {
			continue
		}

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

		// 4. 发送至远端 CONNECT-IP 隧道（原生透传所有 TCP、游戏 UDP 与 QUIC 443 报文）
		_, werr := p.conn.WritePacket(raw)
		if werr != nil {
			if !p.closed.Load() {
				log.Printf("[PUMP] write remote error: %v", werr)
			}
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
	_ = p.conn.Close()

	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(300 * time.Millisecond):
		log.Printf("[PUMP] IPDataPump close wait timeout, forcing shutdown (RX: %d, TX: %d)", p.bytesIn.Load(), p.bytesOut.Load())
		return nil
	}

	log.Printf("[PUMP] IPDataPump stopped. Total RX: %d bytes, TX: %d bytes", p.bytesIn.Load(), p.bytesOut.Load())
	return nil
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
