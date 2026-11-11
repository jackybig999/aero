package client

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// reconnectHarness 以桩替换 TUN、路由与 CONNECT-IP 拨号，驱动真实的 Engine.Start。
type reconnectHarness struct {
	mu       sync.Mutex
	conns    []*mockIPPacketConn
	prefixes []string // 第 i 次拨号返回的地址
	dials    atomic.Int32
	hosts    *fakeTunHosts
	eng      *Engine
}

// addrSets 返回重连期间对网卡地址的全部替换（tunHost.SetIPv4）。
func (h *reconnectHarness) addrSets() []netip.Prefix {
	_, addrs, _ := h.hosts.last().snapshot()
	return addrs
}

func (h *reconnectHarness) conn(i int) *mockIPPacketConn {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.conns[i]
}

func startReconnectHarness(t *testing.T, prefixes ...string) *reconnectHarness {
	t.Helper()
	h := &reconnectHarness{prefixes: prefixes}
	eng := NewEngine()
	eng.SetMode("tun")
	if err := eng.Apply(&Applied{
		Servers: []ServerConfig{{Name: "N1", Address: "198.51.100.1:443", Token: "tok", SNI: "n1.example.com"}},
		Tokens:  map[string]string{"198.51.100.1:443": "tok"},
		SNIs:    map[string]string{"198.51.100.1:443": "n1.example.com"},
	}); err != nil {
		t.Fatalf("apply: %v", err)
	}

	h.hosts = useFakeTunHost(t, nil)
	origDial, origMin := dialIPFn, reconnectMinBackoff
	t.Cleanup(func() {
		dialIPFn, reconnectMinBackoff = origDial, origMin
		SetQUICDialHook(nil)
	})
	reconnectMinBackoff = 10 * time.Millisecond
	SetQUICDialHook(func(context.Context, net.PacketConn, net.Addr, *tls.Config, *quic.Config) (*quic.Conn, error) {
		return nil, nil
	})
	dialIPFn = func(ctx context.Context, m *SessionManager) (IPPacketConn, string, error) {
		i := int(h.dials.Add(1)) - 1
		c := newMockIPPacketConn()
		h.mu.Lock()
		h.conns = append(h.conns, c)
		p := h.prefixes[len(h.prefixes)-1]
		if i < len(h.prefixes) {
			p = h.prefixes[i]
		}
		h.mu.Unlock()
		return c, p, nil
	}

	if err := eng.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	h.eng = eng
	return h
}

func waitDials(t *testing.T, h *reconnectHarness, want int32) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for h.dials.Load() < want {
		if time.Now().After(deadline) {
			t.Fatalf("dials = %d, want %d: tunnel was not re-established after a disconnect", h.dials.Load(), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// 回归（M2-9）：CONNECT-IP 只在 Start 时建立一次，断线后数据泵退出、TUN 与路由仍在，
// 全机流量进黑洞直到手动重启。断线后必须自动重建并恢复数据泵。
func TestEngineReconnectAfterTunnelDrop(t *testing.T) {
	h := startReconnectHarness(t, "10.88.0.2/32")
	defer h.eng.Stop()

	h.conn(0).Close() // edge 断开（网络切换、edge 重启等）
	waitDials(t, h, 2)

	// 新连接接管数据泵；同一地址不改 TUN 地址
	deadline := time.Now().Add(2 * time.Second)
	for {
		h.eng.lifecycleMu.Lock()
		cur := h.eng.stackEngine.currentConn()
		h.eng.lifecycleMu.Unlock()
		if cur == IPPacketConn(h.conn(1)) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("data pump not restarted on the new CONNECT-IP connection")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if sets := len(h.addrSets()); sets != 0 {
		t.Fatalf("TUN address changed %d times although the edge returned the same address", sets)
	}

	// 关闭旧泵不得再次触发重连（防死循环）
	time.Sleep(200 * time.Millisecond)
	if got := h.dials.Load(); got != 2 {
		t.Fatalf("dials = %d after a single disconnect, want 2 (reconnect loop?)", got)
	}
}

// 重连拿到不同地址时，只替换 TUN 地址。
func TestEngineReconnectUpdatesTunAddressWhenItChanges(t *testing.T) {
	h := startReconnectHarness(t, "10.88.0.2/32", "10.88.7.9/32")
	defer h.eng.Stop()

	h.conn(0).Close()
	waitDials(t, h, 2)
	deadline := time.Now().Add(2 * time.Second)
	for {
		sets := h.addrSets()
		if len(sets) == 1 && sets[0] == netip.MustParsePrefix("10.88.7.9/16") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("TUN address updates = %v, want [10.88.7.9/16]", sets)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// 停止后不再重连。
func TestEngineReconnectStopsAfterStop(t *testing.T) {
	h := startReconnectHarness(t, "10.88.0.2/32")
	if err := h.eng.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	before := h.dials.Load()
	h.conn(0).Close()
	time.Sleep(200 * time.Millisecond)
	if got := h.dials.Load(); got != before {
		t.Fatalf("dials after Stop = %d, want %d", got, before)
	}
}
