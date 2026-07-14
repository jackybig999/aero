// Package dialguard 限制同时拨号数，保护小 VPS 的 fd/CPU。
// 仅限制 Dial 瞬间并发，连接建立后立即释放槽位。
package dialguard

import (
	"fmt"
	"net"
	"time"
)

// Guard 并发 dial 闸门。
type Guard struct {
	sem chan struct{}
}

// New maxConcurrent≤0 时默认 256。
func New(maxConcurrent int) *Guard {
	if maxConcurrent <= 0 {
		maxConcurrent = 256
	}
	return &Guard{sem: make(chan struct{}, maxConcurrent)}
}

// DialTimeout 占用槽位拨号，返回后释放槽（无论成败）。
func (g *Guard) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	if g == nil || g.sem == nil {
		return net.DialTimeout(network, address, timeout)
	}
	select {
	case g.sem <- struct{}{}:
		defer func() { <-g.sem }()
	case <-time.After(timeout):
		return nil, fmt.Errorf("dial queue full")
	}
	return net.DialTimeout(network, address, timeout)
}

// Cap 并发上限。
func (g *Guard) Cap() int {
	if g == nil || g.sem == nil {
		return 0
	}
	return cap(g.sem)
}
