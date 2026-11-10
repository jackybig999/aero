// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"runtime/debug"
	"sync"
	"sync/atomic"

	"github.com/quic-go/connect-ip-go"
)

var (
	globalMobileDNSHandler   atomic.Pointer[DNSHandler]
	globalMobileWebRTCActive atomic.Bool
)

// SetGlobalMobileDNSHandler 设置供移动端 TUN 隧道拦截使用的全局 DNS 处理器
func SetGlobalMobileDNSHandler(h *DNSHandler) {
	globalMobileDNSHandler.Store(h)
}

// GetGlobalMobileDNSHandler 获取移动端全局 DNS 处理器
func GetGlobalMobileDNSHandler() *DNSHandler {
	return globalMobileDNSHandler.Load()
}

// SetGlobalMobileWebRTCActive 设置供移动端 TUN 隧道拦截使用的全局 WebRTC 激活门控
func SetGlobalMobileWebRTCActive(active bool) {
	globalMobileWebRTCActive.Store(active)
}

// GetGlobalMobileWebRTCActive 获取移动端全局 WebRTC 激活门控
func GetGlobalMobileWebRTCActive() bool {
	return globalMobileWebRTCActive.Load()
}

// mobileBufPool provides a zero-heap-allocation 1500-byte buffer pool for mobile TUN processing.
var mobileBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 1500)
		return &b
	},
}

// InitMobileRuntime optimizes Go runtime memory and GC parameters for constrained mobile environments
// balancing iOS Network Extension Jetsam budget and high-throughput GC efficiency.
func InitMobileRuntime() {
	debug.SetMemoryLimit(20 * 1024 * 1024)
	debug.SetGCPercent(50)
}

// MobileTunnelController manages the lifecycle of a mobile TUN tunnel.
type MobileTunnelController struct {
	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{}
	err      error
	stopOnce sync.Once
}

// Stop gracefully stops the mobile tunnel and releases both endpoints.
func (c *MobileTunnelController) Stop() error {
	c.stopOnce.Do(func() {
		c.cancel()
	})
	<-c.done
	return c.err
}

// Done returns the channel that is closed when the tunnel completes teardown.
func (c *MobileTunnelController) Done() <-chan struct{} {
	return c.done
}

// Err returns the exit error of the tunnel, if any.
func (c *MobileTunnelController) Err() error {
	return c.err
}

// StartMobileTunnel starts a mobile TUN tunnel with lifecycle control.
// When ctx is canceled or Stop() is called, both tun and ipConn are closed
// and all background goroutines are cleanly reaped within 100ms.
func StartMobileTunnel(ctx context.Context, tun io.ReadWriteCloser, ipConn io.ReadWriteCloser) *MobileTunnelController {
	if ctx == nil {
		ctx = context.Background()
	}
	cCtx, cancel := context.WithCancel(ctx)
	ctrl := &MobileTunnelController{
		ctx:    cCtx,
		cancel: cancel,
		done:   make(chan struct{}),
	}

	go func() {
		defer close(ctrl.done)
		ctrl.err = CopyTunnel(cCtx, tun, ipConn)
	}()

	return ctrl
}

// CopyTunnel 负责在 TUN 虚拟网卡与上层传输通道之间双向流转 IP 数据包
// 核心逻辑：双向无损流转，支持上下文取消与错误传播，自动关闭两端并回收资源
func CopyTunnel(ctx context.Context, tun io.ReadWriteCloser, ipConn io.ReadWriteCloser) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 2)
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = tun.Close()
			_ = ipConn.Close()
		})
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// 1. tun -> ipConn
	go func() {
		defer wg.Done()
		bufPtr := mobileBufPool.Get().(*[]byte)
		defer mobileBufPool.Put(bufPtr)
		buf := *bufPtr
		for {
			n, err := tun.Read(buf)
			if n > 0 {
				if _, werr := ipConn.Write(buf[:n]); werr != nil {
					select {
					case errCh <- werr:
					default:
					}
					return
				}
			}
			if err != nil {
				select {
				case errCh <- err:
				default:
				}
				return
			}
		}
	}()

	// 2. ipConn -> tun
	go func() {
		defer wg.Done()
		bufPtr := mobileBufPool.Get().(*[]byte)
		defer mobileBufPool.Put(bufPtr)
		buf := *bufPtr
		for {
			n, err := ipConn.Read(buf)
			if n > 0 {
				if _, werr := tun.Write(buf[:n]); werr != nil {
					select {
					case errCh <- werr:
					default:
					}
					return
				}
			}
			if err != nil {
				select {
				case errCh <- err:
				default:
				}
				return
			}
		}
	}()

	// 3. 监听上下文取消
	ctxDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			closeBoth()
		case <-ctxDone:
		}
	}()

	var retErr error
	select {
	case <-ctx.Done():
		retErr = ctx.Err()
	case err := <-errCh:
		retErr = err
	}

	closeBoth()
	close(ctxDone)
	wg.Wait()

	if errors.Is(retErr, io.EOF) || errors.Is(retErr, io.ErrClosedPipe) || errors.Is(retErr, net.ErrClosed) || errors.Is(retErr, context.Canceled) {
		return nil
	}
	return retErr
}

// clampTCPMSS 检查是否为 TCP SYN/SYN-ACK 报文 (IPv4 或 IPv6)，若 MSS 选项大于 maxMSS 则原子原地缩减并更新增量校验和 (RFC 1624)
func clampTCPMSS(raw []byte, maxMSS uint16) []byte {
	if len(raw) < 40 {
		return raw
	}
	ver := raw[0] >> 4
	var tcpHdr []byte

	if ver == 4 {
		if raw[9] != 6 {
			return raw
		}
		ihl := int(raw[0]&0x0F) * 4
		if len(raw) < ihl+20 {
			return raw
		}
		tcpHdr = raw[ihl:]
	} else if ver == 6 {
		if raw[6] != 6 { // Next Header == 6 (TCP)
			return raw
		}
		if len(raw) < 40+20 {
			return raw
		}
		tcpHdr = raw[40:]
	} else {
		return raw
	}

	tcpFlags := tcpHdr[13]
	if (tcpFlags & 0x02) == 0 { // 仅 SYN 或 SYN+ACK 携带 MSS 选项
		return raw
	}
	dataOffset := int(tcpHdr[12]>>4) * 4
	if dataOffset < 20 || len(tcpHdr) < dataOffset {
		return raw
	}
	optIdx := 20
	for optIdx < dataOffset {
		kind := tcpHdr[optIdx]
		if kind == 0 {
			break
		}
		if kind == 1 {
			optIdx++
			continue
		}
		if optIdx+1 >= dataOffset {
			break
		}
		length := int(tcpHdr[optIdx+1])
		if length < 2 || optIdx+length > dataOffset {
			break
		}
		if kind == 2 && length == 4 { // MSS 选项 (Kind=2, Length=4)
			currentMSS := binary.BigEndian.Uint16(tcpHdr[optIdx+2 : optIdx+4])
			if currentMSS > maxMSS {
				binary.BigEndian.PutUint16(tcpHdr[optIdx+2:optIdx+4], maxMSS)
				// RFC 1624 增量校验和公式：~C' = ~(~C + ~m + m')
				oldCsum := binary.BigEndian.Uint16(tcpHdr[16:18])
				sum := uint32(^oldCsum) + uint32(^currentMSS) + uint32(maxMSS)
				for sum > 0xFFFF {
					sum = (sum & 0xFFFF) + (sum >> 16)
				}
				newCsum := ^uint16(sum)
				if newCsum == 0 {
					newCsum = 0xFFFF
				}
				binary.BigEndian.PutUint16(tcpHdr[16:18], newCsum)
			}
			break
		}
		optIdx += length
	}
	return raw
}

// CopyCONNECTIPTunnel bridges an OS TUN device (io.ReadWriteCloser) directly with an RFC 9484 CONNECT-IP tunnel.
func CopyCONNECTIPTunnel(ctx context.Context, tun io.ReadWriteCloser, ipConn *connectip.Conn) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 2)
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = tun.Close()
			_ = ipConn.Close()
		})
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// 1. tun -> connectip
	go func() {
		defer wg.Done()
		bufPtr := mobileBufPool.Get().(*[]byte)
		defer mobileBufPool.Put(bufPtr)
		buf := *bufPtr
		for {
			n, err := tun.Read(buf)
			if n > 0 {
				raw := buf[:n]
				// 移动端安全与国内流量防御性下沉拦截
				if n >= 20 && raw[0]>>4 == 4 {
					ihl := int(raw[0]&0x0F) * 4
					if len(raw) >= ihl+8 && raw[9] == 17 {
						dstPort := binary.BigEndian.Uint16(raw[ihl+2 : ihl+4])
						if dstPort == 53 {
							dnsH := globalMobileDNSHandler.Load()
							if dnsH != nil {
								srcPort := binary.BigEndian.Uint16(raw[ihl : ihl+2])
								srcIP := net.IP(raw[12:16])
								dstIP := net.IP(raw[16:20])
								dnsPayload := raw[ihl+8:]
								if resp := dnsH.HandleQuery(dnsPayload, srcIP, srcPort); resp != nil {
									respPkt := buildIPv4UDPResponsePacket(dstIP, srcIP, dstPort, srcPort, resp)
									if len(respPkt) > 0 {
										_, _ = tun.Write(respPkt)
									}
								}
								continue
							}
						}
						if isSTUNPacket(raw[ihl+8:]) && !globalMobileWebRTCActive.Load() {
							continue
						}
					}
					dstIP := net.IP(raw[16:20])
					if isLocalOrPrivateIP("", dstIP) {
						continue
					}
				} else if n >= 40 && raw[0]>>4 == 6 {
					// 移动端 IPv6 双栈防御拦截 (RFC 8200)
					if len(raw) >= 48 && raw[6] == 17 { // Next Header == 17 (UDP)
						dstPort := binary.BigEndian.Uint16(raw[42:44])
						if dstPort == 53 {
							dnsH := globalMobileDNSHandler.Load()
							if dnsH != nil {
								srcPort := binary.BigEndian.Uint16(raw[40:42])
								srcIP := net.IP(raw[8:24])
								dstIP := net.IP(raw[24:40])
								dnsPayload := raw[48:]
								if resp := dnsH.HandleQuery(dnsPayload, srcIP, srcPort); resp != nil {
									respPkt := buildIPv6UDPResponsePacket(dstIP, srcIP, dstPort, srcPort, resp)
									if len(respPkt) > 0 {
										_, _ = tun.Write(respPkt)
									}
								}
								continue
							}
						}
						if isSTUNPacket(raw[48:]) && !globalMobileWebRTCActive.Load() {
							continue
						}
					}
					dstIP := net.IP(raw[24:40])
					if isLocalOrPrivateIP("", dstIP) {
						continue
					}
				}
				raw = clampTCPMSS(raw, 1200)
				if _, werr := ipConn.WritePacket(raw); werr != nil {
					select {
					case errCh <- werr:
					default:
					}
					return
				}
			}
			if err != nil {
				select {
				case errCh <- err:
				default:
				}
				return
			}
		}
	}()

	// 2. connectip -> tun
	go func() {
		defer wg.Done()
		bufPtr := mobileBufPool.Get().(*[]byte)
		defer mobileBufPool.Put(bufPtr)
		buf := *bufPtr
		for {
			n, err := ipConn.ReadPacket(buf)
			if n > 0 {
				pkt := clampTCPMSS(buf[:n], 1200)
				if _, werr := tun.Write(pkt); werr != nil {
					select {
					case errCh <- werr:
					default:
					}
					return
				}
			}
			if err != nil {
				select {
				case errCh <- err:
				default:
				}
				return
			}
		}
	}()

	// 3. 监听上下文取消
	ctxDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			closeBoth()
		case <-ctxDone:
		}
	}()

	var retErr error
	select {
	case <-ctx.Done():
		retErr = ctx.Err()
	case err := <-errCh:
		retErr = err
	}

	closeBoth()
	close(ctxDone)
	wg.Wait()

	if errors.Is(retErr, io.EOF) || errors.Is(retErr, io.ErrClosedPipe) || errors.Is(retErr, net.ErrClosed) || errors.Is(retErr, context.Canceled) {
		return nil
	}
	return retErr
}
