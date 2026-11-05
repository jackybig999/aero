package edge

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type routerTestConn struct{}

func (routerTestConn) ReadPacket([]byte) (int, error)     { return 0, nil }
func (routerTestConn) WritePacket([]byte) ([]byte, error) { return nil, nil }
func (routerTestConn) Close() error                       { return nil }

type readerTestConn struct {
	writes chan []byte
}

func (c *readerTestConn) ReadPacket([]byte) (int, error) { return 0, nil }
func (c *readerTestConn) WritePacket(packet []byte) ([]byte, error) {
	c.writes <- append([]byte(nil), packet...)
	return nil, nil
}
func (c *readerTestConn) Close() error { return nil }

type reverseReaderConn struct {
	packets chan []byte
	closed  chan struct{}
	once    sync.Once
}

func (c *reverseReaderConn) ReadPacket(buffer []byte) (int, error) {
	select {
	case packet := <-c.packets:
		return copy(buffer, packet), nil
	case <-c.closed:
		return 0, net.ErrClosed
	}
}
func (c *reverseReaderConn) WritePacket([]byte) ([]byte, error) { return nil, nil }
func (c *reverseReaderConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

type readerTestDevice struct {
	packets   chan []byte
	closed    chan struct{}
	closeOnce sync.Once
	writes    chan []byte
}

func (d *readerTestDevice) Read(buffer []byte) (int, error) {
	select {
	case packet := <-d.packets:
		return copy(buffer, packet), nil
	case <-d.closed:
		return 0, net.ErrClosed
	}
}
func (d *readerTestDevice) Close() error {
	d.closeOnce.Do(func() { close(d.closed) })
	return nil
}
func (d *readerTestDevice) Write(packet []byte) (int, error) {
	if d.writes != nil {
		d.writes <- append([]byte(nil), packet...)
	}
	return len(packet), nil
}

func TestGlobalTunnelRouter(t *testing.T) {
	router := NewGlobalTunnelRouter()
	conn := routerTestConn{}
	v4 := netip.MustParseAddr("10.88.0.2")
	v6 := netip.MustParseAddr("2001:db8:1234:5678::2")
	generation, err := router.Register(GlobalTunnelBinding{Token: "masked-test-token", IPv4: v4, IPv6: v6, Conn: conn})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	binding, ok := router.LookupDestination(v6)
	if !ok || binding.Generation != generation {
		t.Fatalf("lookup returned %+v, ok=%t", binding, ok)
	}
	if err := router.ValidateSource(binding, v4); err != nil {
		t.Fatalf("valid source rejected: %v", err)
	}
	if err := router.ValidateSource(binding, netip.MustParseAddr("10.88.0.99")); err == nil {
		t.Fatal("unassigned source accepted")
	}

	newGeneration, err := router.Register(GlobalTunnelBinding{Token: "next-token", IPv4: v4, Conn: conn})
	if err != nil {
		t.Fatalf("register replacement: %v", err)
	}
	if router.Unregister(v4, generation) {
		t.Fatal("stale generation removed replacement")
	}
	if !router.Unregister(v4, newGeneration) || router.Size() != 0 {
		t.Fatal("current generation was not removed")
	}

	router.Close()
	if _, err := router.Register(GlobalTunnelBinding{Token: "closed", IPv4: v4, Conn: conn}); err == nil {
		t.Fatal("closed router accepted registration")
	}
}

func TestGlobalTunnelRouterPacket(t *testing.T) {
	router := NewGlobalTunnelRouter()
	conn := routerTestConn{}
	source := netip.MustParseAddr("10.88.0.2")
	destination := netip.MustParseAddr("10.88.0.3")
	if _, err := router.Register(GlobalTunnelBinding{IPv4: destination, Conn: conn}); err != nil {
		t.Fatalf("register: %v", err)
	}
	binding, gotSource, err := router.RoutePacket(buildRouterTestIPv4(source, destination))
	if err != nil {
		t.Fatalf("route packet: %v", err)
	}
	if binding.IPv4 != destination || gotSource != source {
		t.Fatalf("binding=%+v source=%s", binding, gotSource)
	}
	if err := router.ValidateSource(binding, netip.MustParseAddr("10.88.0.9")); err == nil {
		t.Fatal("spoofed source accepted by source validator")
	}
}

func TestGlobalTunnelRouterRejectsStaleBinding(t *testing.T) {
	router := NewGlobalTunnelRouter()
	ip := netip.MustParseAddr("10.88.0.8")
	oldConn := routerTestConn{}
	oldGen, err := router.Register(GlobalTunnelBinding{IPv4: ip, Conn: oldConn})
	if err != nil {
		t.Fatalf("register old binding: %v", err)
	}
	newConn := routerTestConn{}
	newGen, err := router.Register(GlobalTunnelBinding{IPv4: ip, Conn: newConn})
	if err != nil {
		t.Fatalf("register new binding: %v", err)
	}
	if router.IsCurrent(GlobalTunnelBinding{IPv4: ip, Generation: oldGen, Conn: oldConn}) {
		t.Fatal("stale binding reported as current")
	}
	if !router.IsCurrent(GlobalTunnelBinding{IPv4: ip, Generation: newGen, Conn: newConn}) {
		t.Fatal("current binding rejected")
	}
}

func TestGlobalTunnelReaderDispatchAndClose(t *testing.T) {
	router := NewGlobalTunnelRouter()
	conn := &readerTestConn{writes: make(chan []byte, 1)}
	destination := netip.MustParseAddr("10.88.0.3")
	if _, err := router.Register(GlobalTunnelBinding{IPv4: destination, Conn: conn}); err != nil {
		t.Fatalf("register: %v", err)
	}
	device := &readerTestDevice{packets: make(chan []byte, 1), closed: make(chan struct{})}
	reader, err := NewGlobalTunnelReader(nil, device, router)
	if err != nil {
		t.Fatalf("new reader: %v", err)
	}
	reader.Start()
	device.packets <- buildRouterTestIPv4(netip.MustParseAddr("192.0.2.10"), destination)
	select {
	case <-conn.writes:
	case <-time.After(time.Second):
		t.Fatal("reader did not dispatch packet")
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close reader: %v", err)
	}
}

func TestGlobalTunnelReaderReverseDispatchValidatesSource(t *testing.T) {
	router := NewGlobalTunnelRouter()
	clientIP := netip.MustParseAddr("10.88.0.4")
	conn := &reverseReaderConn{packets: make(chan []byte, 2), closed: make(chan struct{})}
	generation, err := router.Register(GlobalTunnelBinding{IPv4: clientIP, Conn: conn})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	device := &readerTestDevice{packets: make(chan []byte), closed: make(chan struct{}), writes: make(chan []byte, 1)}
	reader, err := NewGlobalTunnelReader(nil, device, router)
	if err != nil {
		t.Fatalf("new reader: %v", err)
	}
	if err := reader.StartBinding(nil, GlobalTunnelBinding{IPv4: clientIP, Generation: generation, Conn: conn}); err != nil {
		t.Fatalf("start reverse binding: %v", err)
	}
	conn.packets <- buildRouterTestIPv4(clientIP, netip.MustParseAddr("8.8.8.8"))
	select {
	case <-device.writes:
	case <-time.After(time.Second):
		t.Fatal("reverse reader did not write valid packet")
	}
	conn.packets <- buildRouterTestIPv4(netip.MustParseAddr("10.88.0.99"), netip.MustParseAddr("8.8.8.8"))
	select {
	case <-device.writes:
		t.Fatal("reverse reader accepted spoofed source")
	case <-time.After(50 * time.Millisecond):
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close reader: %v", err)
	}
}

func TestQUICServerGlobalTunnelLifecycle(t *testing.T) {
	server := NewQUICServer(nil, nil, nil, nil, nil)
	device := &readerTestDevice{packets: make(chan []byte, 1), closed: make(chan struct{})}
	if err := server.AttachGlobalTunnelDevice(nil, device); err != nil {
		t.Fatalf("attach reader: %v", err)
	}
	server.Close()
	select {
	case <-device.closed:
	case <-time.After(time.Second):
		t.Fatal("server close did not close shared TUN device")
	}
	if server.globalRouter.Size() != 0 {
		t.Fatalf("router still has %d bindings after server close", server.globalRouter.Size())
	}
}
