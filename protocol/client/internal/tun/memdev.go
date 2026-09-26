package tun

import (
	"sync"
	"sync/atomic"
	"time"
)

// MemDevice is a TUN stand-in for simulation. No wintun, no routes, no DNS.
type MemDevice struct {
	in       chan []byte
	closed   atomic.Bool
	mu       sync.Mutex
	out      [][]byte
	onPacket func([]byte)
}

func NewMemDevice() *MemDevice {
	return &MemDevice{in: make(chan []byte, 64)}
}

func (d *MemDevice) SetOnPacket(fn func([]byte)) {
	d.mu.Lock()
	d.onPacket = fn
	d.mu.Unlock()
}

func (d *MemDevice) Inject(pkt []byte) {
	if d.closed.Load() {
		return
	}
	cp := append([]byte(nil), pkt...)
	select {
	case d.in <- cp:
	default:
	}
}

func (d *MemDevice) Read(p []byte) (int, error) {
	if d.closed.Load() {
		return 0, nil
	}
	select {
	case pkt := <-d.in:
		return copy(p, pkt), nil
	case <-time.After(30 * time.Millisecond):
		return 0, nil
	}
}

func (d *MemDevice) Write(p []byte) (int, error) {
	d.mu.Lock()
	d.out = append(d.out, append([]byte(nil), p...))
	fn := d.onPacket
	d.mu.Unlock()
	if fn != nil {
		fn(append([]byte(nil), p...))
	}
	return len(p), nil
}

func (d *MemDevice) Close() error {
	d.closed.Store(true)
	return nil
}

func (d *MemDevice) Name() string { return "mem0" }
func (d *MemDevice) MTU() int     { return 1420 }

func (d *MemDevice) Outbound() [][]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.out
}
