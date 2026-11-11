package client

import (
	"sync"
	"testing"
	"time"
)

// captureTunDevice 在 mockTunDevice 之上记录写回网卡的报文。
type captureTunDevice struct {
	*mockTunDevice
	mu     sync.Mutex
	writes [][]byte
}

func (c *captureTunDevice) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, append([]byte(nil), b...))
	c.mu.Unlock()
	return c.mockTunDevice.Write(b)
}

func (c *captureTunDevice) written() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.writes...)
}

// 回归：SetIPv6Blackhole 从未在生产路径调用。IPv6 进入 TUN 后被送往 edge 丢弃，应用只能等超时。
// 数据面（含重连新建的泵）必须把非 DNS 的 IPv6 留在本地并回 ICMPv6 不可达。
func TestStackEngineBlackholesIPv6(t *testing.T) {
	dev := &captureTunDevice{mockTunDevice: newMockTunDevice()}
	conn := newMockIPPacketConn()
	sent := make(chan []byte, 4)
	conn.writeHook = func(b []byte) ([]byte, error) {
		sent <- append([]byte(nil), b...)
		return nil, nil
	}
	stack := NewStackEngineWithConn(dev, conn, nil)
	if err := stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Stop()

	check := func(stage string) {
		t.Helper()
		g6 := [16]byte{0x20, 0x01, 0x48, 0x60, 15: 0x88}
		pkt := ipv6Pkt(64, g6)
		pkt[6] = 6                              // TCP
		pkt[8], pkt[9], pkt[23] = 0x20, 0x01, 2 // 源 2001::2
		// 重连后旧泵的读协程仍阻塞在共享设备上，会取走（并丢弃）一个报文；按真实行为重发直到有回应。
		deadline := time.Now().Add(2 * time.Second)
		for len(dev.written()) == 0 && time.Now().Before(deadline) {
			dev.readCh <- pkt
			time.Sleep(100 * time.Millisecond)
		}
		select {
		case b := <-sent:
			t.Fatalf("%s: IPv6 packet sent into the tunnel (%d bytes)", stage, len(b))
		default:
		}
		w := dev.written()
		if len(w) == 0 || w[len(w)-1][0]>>4 != 6 || w[len(w)-1][40] != 1 {
			t.Fatalf("%s: no ICMPv6 Destination Unreachable written back", stage)
		}
	}
	check("initial pump")

	newConn := newMockIPPacketConn()
	newConn.writeHook = conn.writeHook
	if err := stack.RestartWithConn(newConn); err != nil {
		t.Fatal(err)
	}
	dev.mu.Lock()
	dev.writes = nil
	dev.mu.Unlock()
	check("pump after reconnect")
}
