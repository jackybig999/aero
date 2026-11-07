package edge

import (
	"context"
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
