package edge

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
)

var errGlobalTunnelRouterClosed = errors.New("global tunnel router is closed")

// IPPacketConn abstracts the MASQUE CONNECT-IP tunnel packet stream.
type IPPacketConn interface {
	ReadPacket([]byte) (int, error)
	WritePacket([]byte) ([]byte, error)
	Close() error
}

type GlobalTunnelBinding struct {
	Token      string
	IPv4       netip.Addr
	IPv6       netip.Addr
	Generation uint64
	Conn       IPPacketConn
	usage      *usageCell // C6 计量（nil 表示不计量）
}

// GlobalTunnelRouter is the shared address-to-CONNECT-IP binding table.
// Packet I/O is performed by the single GlobalTunnelReader; this table only
// owns address lookup and generation-safe binding lifecycle.
type GlobalTunnelRouter struct {
	mu       sync.RWMutex
	bindings map[netip.Addr]GlobalTunnelBinding
	nextGen  atomic.Uint64
	closed   atomic.Bool
}

func NewGlobalTunnelRouter() *GlobalTunnelRouter {
	return &GlobalTunnelRouter{bindings: make(map[netip.Addr]GlobalTunnelBinding)}
}

func (r *GlobalTunnelRouter) Register(binding GlobalTunnelBinding) (uint64, error) {
	if r == nil {
		return 0, errors.New("global tunnel router is nil")
	}
	if r.closed.Load() {
		return 0, errGlobalTunnelRouterClosed
	}
	if binding.Conn == nil || !binding.IPv4.IsValid() || !binding.IPv4.Is4() {
		return 0, errors.New("global tunnel binding requires a valid IPv4 address and connection")
	}
	if binding.IPv6.IsValid() && !binding.IPv6.Is6() {
		return 0, errors.New("global tunnel binding has invalid IPv6 address")
	}

	binding.Generation = r.nextGen.Add(1)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed.Load() {
		return 0, errGlobalTunnelRouterClosed
	}
	if previous, exists := r.bindings[binding.IPv4]; exists {
		if previous.IPv6.IsValid() {
			delete(r.bindings, previous.IPv6)
		}
	}
	r.bindings[binding.IPv4] = binding
	if binding.IPv6.IsValid() {
		r.bindings[binding.IPv6] = binding
	}
	return binding.Generation, nil
}

func (r *GlobalTunnelRouter) Unregister(ip netip.Addr, generation uint64) bool {
	if r == nil || !ip.IsValid() || generation == 0 {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	binding, ok := r.bindings[ip]
	if !ok || binding.Generation != generation {
		return false
	}
	delete(r.bindings, binding.IPv4)
	if binding.IPv6.IsValid() {
		delete(r.bindings, binding.IPv6)
	}
	return true
}

func (r *GlobalTunnelRouter) LookupDestination(ip netip.Addr) (GlobalTunnelBinding, bool) {
	if r == nil || !ip.IsValid() || r.closed.Load() {
		return GlobalTunnelBinding{}, false
	}
	r.mu.RLock()
	binding, ok := r.bindings[ip]
	r.mu.RUnlock()
	return binding, ok
}

func (r *GlobalTunnelRouter) ValidateSource(binding GlobalTunnelBinding, source netip.Addr) error {
	if !source.IsValid() || (source != binding.IPv4 && source != binding.IPv6) {
		return fmt.Errorf("source address %s is not assigned to tunnel generation %d", source, binding.Generation)
	}
	return nil
}

func (r *GlobalTunnelRouter) IsCurrent(binding GlobalTunnelBinding) bool {
	if r == nil || binding.Generation == 0 || r.closed.Load() {
		return false
	}
	current, ok := r.LookupDestination(binding.IPv4)
	return ok && current.Generation == binding.Generation && current.Conn == binding.Conn
}

// RoutePacket validates an IP packet against the current address binding.
// It does not perform I/O; the shared TUN reader will call this before writing
// the packet to the selected CONNECT-IP connection.
func (r *GlobalTunnelRouter) RoutePacket(packet []byte) (GlobalTunnelBinding, netip.Addr, error) {
	if len(packet) < 20 {
		return GlobalTunnelBinding{}, netip.Addr{}, errors.New("IP packet is shorter than the minimum header")
	}
	var source, destination netip.Addr
	switch packet[0] >> 4 {
	case 4:
		ihl := int(packet[0]&0x0f) * 4
		if ihl < 20 || len(packet) < ihl {
			return GlobalTunnelBinding{}, netip.Addr{}, errors.New("invalid IPv4 header length")
		}
		var src, dst [4]byte
		copy(src[:], packet[12:16])
		copy(dst[:], packet[16:20])
		source = netip.AddrFrom4(src)
		destination = netip.AddrFrom4(dst)
	case 6:
		if len(packet) < 40 {
			return GlobalTunnelBinding{}, netip.Addr{}, errors.New("IPv6 packet is shorter than the minimum header")
		}
		var src, dst [16]byte
		copy(src[:], packet[8:24])
		copy(dst[:], packet[24:40])
		source = netip.AddrFrom16(src)
		destination = netip.AddrFrom16(dst)
	default:
		return GlobalTunnelBinding{}, netip.Addr{}, errors.New("unsupported IP packet version")
	}
	binding, ok := r.LookupDestination(destination)
	if !ok {
		return GlobalTunnelBinding{}, source, fmt.Errorf("no tunnel binding for destination %s", destination)
	}
	return binding, source, nil
}

func (r *GlobalTunnelRouter) Close() {
	if r == nil || !r.closed.CompareAndSwap(false, true) {
		return
	}
	r.mu.Lock()
	clear(r.bindings)
	r.mu.Unlock()
}

func (r *GlobalTunnelRouter) Size() int {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	size := len(r.bindings)
	r.mu.RUnlock()
	return size
}
