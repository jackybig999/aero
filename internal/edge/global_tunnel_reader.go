package edge

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"sync"
)

// GlobalTunnelDevice is the minimal server-side TUN contract. Opening and
// platform-specific configuration are intentionally outside this reader.
type GlobalTunnelDevice interface {
	Read([]byte) (int, error)
	Close() error
}

type globalTunnelDeviceWriter interface {
	Write([]byte) (int, error)
}

func packetSource(packet []byte) (netip.Addr, error) {
	if len(packet) < 20 {
		return netip.Addr{}, errors.New("IP packet is shorter than the minimum header")
	}
	switch packet[0] >> 4 {
	case 4:
		ihl := int(packet[0]&0x0f) * 4
		if ihl < 20 || len(packet) < ihl {
			return netip.Addr{}, errors.New("invalid IPv4 header length")
		}
		var source [4]byte
		copy(source[:], packet[12:16])
		return netip.AddrFrom4(source), nil
	case 6:
		if len(packet) < 40 {
			return netip.Addr{}, errors.New("IPv6 packet is shorter than the minimum header")
		}
		var source [16]byte
		copy(source[:], packet[8:24])
		return netip.AddrFrom16(source), nil
	default:
		return netip.Addr{}, errors.New("unsupported IP packet version")
	}
}

var tunnelBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 65535)
		return &buf
	},
}

// GlobalTunnelReader owns exactly one read loop and dispatches packets to the
// connection selected by GlobalTunnelRouter. It never creates per-session NAT.
type GlobalTunnelReader struct {
	device        GlobalTunnelDevice
	router        *GlobalTunnelRouter
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	startOnce     sync.Once
	closeOnce     sync.Once
	closeErr      error
	bindingMu     sync.Mutex
	bindingCancel map[uint64]context.CancelFunc
	bindingWG     sync.WaitGroup
}

func NewGlobalTunnelReader(parent context.Context, device GlobalTunnelDevice, router *GlobalTunnelRouter) (*GlobalTunnelReader, error) {
	if device == nil {
		return nil, errors.New("global tunnel reader requires a device")
	}
	if router == nil {
		return nil, errors.New("global tunnel reader requires a router")
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	return &GlobalTunnelReader{device: device, router: router, ctx: ctx, cancel: cancel, bindingCancel: make(map[uint64]context.CancelFunc)}, nil
}

// StartBinding starts the reverse direction for one registered CONNECT-IP
// binding. The packet source is checked before it is written to the shared
// device, preventing a session from injecting another client's address.
func (r *GlobalTunnelReader) StartBinding(parent context.Context, binding GlobalTunnelBinding) error {
	writer, ok := r.device.(globalTunnelDeviceWriter)
	if !ok {
		return errors.New("global tunnel device does not support packet writes")
	}
	if binding.Conn == nil || binding.Generation == 0 {
		return errors.New("global tunnel binding is incomplete")
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	r.bindingMu.Lock()
	if r.ctx.Err() != nil {
		r.bindingMu.Unlock()
		cancel()
		return errors.New("global tunnel reader is closed")
	}
	r.bindingCancel[binding.Generation] = cancel
	r.bindingMu.Unlock()
	r.bindingWG.Add(1)
	go func() {
		defer r.bindingWG.Done()
		defer cancel()
		defer func() {
			r.bindingMu.Lock()
			delete(r.bindingCancel, binding.Generation)
			r.bindingMu.Unlock()
		}()
		workerDone := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				_ = binding.Conn.Close()
			case <-workerDone:
			}
		}()
		defer close(workerDone)
		bufPtr := tunnelBufPool.Get().(*[]byte)
		defer tunnelBufPool.Put(bufPtr)
		buffer := *bufPtr
		for {
			n, err := binding.Conn.ReadPacket(buffer)
			if n > 0 {
				packet := buffer[:n]
				if source, parseErr := packetSource(packet); parseErr == nil && r.router.IsCurrent(binding) && r.router.ValidateSource(binding, source) == nil {
					// 统一目的地址 ACL：私网、元数据、本机、其他用户地址池、出站 SMTP 一律丢弃。
					// 不记录目的地址（PROJECT_RULES：edge 不记录用户访问的目的地址）。
					if !clientPacketAllowed(packet) {
						continue
					}
					if len(packet) > 1360 && packet[0]>>4 == 6 {
						gwIPv6 := net.ParseIP("fd88::1")
						ptbPkt := buildICMPv6PacketTooBig(packet, gwIPv6, 1360)
						if len(ptbPkt) > 0 {
							_, _ = binding.Conn.WritePacket(ptbPkt)
						}
						continue
					}
					if _, writeErr := writer.Write(packet); writeErr != nil {
						return
					}
				}
			}
			if err != nil || ctx.Err() != nil {
				return
			}
		}
	}()
	return nil
}

func (r *GlobalTunnelReader) Start() {
	r.startOnce.Do(func() {
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.run()
		}()
	})
}

func (r *GlobalTunnelReader) run() {
	bufPtr := tunnelBufPool.Get().(*[]byte)
	defer tunnelBufPool.Put(bufPtr)
	buffer := *bufPtr
	for {
		if r.ctx.Err() != nil {
			return
		}
		n, err := r.device.Read(buffer)
		if n > 0 {
			packet := buffer[:n]
			binding, _, routeErr := r.router.RoutePacket(packet)
			if routeErr != nil {
				continue
			}
			icmpPkt, writeErr := binding.Conn.WritePacket(packet)
			if len(icmpPkt) > 0 {
				if writer, ok := r.device.(globalTunnelDeviceWriter); ok {
					_, _ = writer.Write(icmpPkt)
				}
			}
			if writeErr != nil && !errors.Is(writeErr, net.ErrClosed) {
				log.Printf("[TUN] shared reader write packet failed: %v", writeErr)
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && r.ctx.Err() == nil {
				log.Printf("[TUN] shared reader read failed: %v", err)
			}
			return
		}
	}
}

func (r *GlobalTunnelReader) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		r.cancel()
		r.bindingMu.Lock()
		for _, cancel := range r.bindingCancel {
			cancel()
		}
		r.bindingMu.Unlock()
		r.closeErr = r.device.Close()
	})
	r.wg.Wait()
	r.bindingWG.Wait()
	return r.closeErr
}

// packetDestination 解析客户端报文的目的地址、传输层协议与目的端口。
// IPv6 会跳过常见扩展头（逐跳、路由、分片、目的选项），防止借扩展头绕过端口策略。
// 非首分片或无端口协议时 port 为 0。ok 为 false 表示报文无法解析，调用方必须丢弃。
func packetDestination(packet []byte) (dst netip.Addr, proto uint8, port uint16, ok bool) {
	if len(packet) < 20 {
		return netip.Addr{}, 0, 0, false
	}
	var l4 int
	switch packet[0] >> 4 {
	case 4:
		ihl := int(packet[0]&0x0f) * 4
		if ihl < 20 || len(packet) < ihl {
			return netip.Addr{}, 0, 0, false
		}
		dst = netip.AddrFrom4([4]byte{packet[16], packet[17], packet[18], packet[19]})
		proto = packet[9]
		if binary.BigEndian.Uint16(packet[6:8])&0x1fff != 0 { // 非首分片
			return dst, proto, 0, true
		}
		l4 = ihl
	case 6:
		if len(packet) < 40 {
			return netip.Addr{}, 0, 0, false
		}
		var d [16]byte
		copy(d[:], packet[24:40])
		dst = netip.AddrFrom16(d)
		next := packet[6]
		off := 40
		for i := 0; i < 8; i++ { // 扩展头数量上限，防止构造的长链消耗 CPU
			switch next {
			case 0, 43, 60: // 逐跳、路由、目的选项
				if len(packet) < off+8 {
					return netip.Addr{}, 0, 0, false
				}
				next = packet[off]
				off += (int(packet[off+1]) + 1) * 8
			case 44: // 分片
				if len(packet) < off+8 {
					return netip.Addr{}, 0, 0, false
				}
				fragOffset := binary.BigEndian.Uint16(packet[off+2:off+4]) >> 3
				next = packet[off]
				off += 8
				if fragOffset != 0 {
					return dst, next, 0, true
				}
			default:
				proto, l4 = next, off
				goto ports
			}
		}
		return netip.Addr{}, 0, 0, false // 扩展头过多
	default:
		return netip.Addr{}, 0, 0, false
	}
ports:
	if (proto == 6 || proto == 17) && len(packet) >= l4+4 {
		port = binary.BigEndian.Uint16(packet[l4+2 : l4+4])
	}
	return dst, proto, port, true
}

// clientPacketAllowed 判定客户端经 CONNECT-IP 发出的报文能否写入共享 TUN。
func clientPacketAllowed(packet []byte) bool {
	dst, proto, port, ok := packetDestination(packet)
	if !ok {
		return false
	}
	if blocked, _ := destinationBlocked(dst, edgeLocalAddrs()); blocked {
		return false
	}
	if blocked, _ := destinationPortBlocked(proto, port); blocked {
		return false
	}
	return true
}
