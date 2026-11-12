package edge

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
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

// buildACLTestIPv4TCP 构造 IPv4/TCP 报文（仅头部），用于 ACL 测试。
func buildACLTestIPv4TCP(src, dst netip.Addr, dstPort uint16) []byte {
	packet := buildRouterTestIPv4(src, dst)
	packet[9] = 6
	packet = append(packet, make([]byte, 20)...)
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[20:22], 40000)
	binary.BigEndian.PutUint16(packet[22:24], dstPort)
	return packet
}

// buildACLTestIPv6 构造 IPv6 报文；hopByHop 为真时在 TCP 头前插入 8 字节逐跳选项扩展头。
func buildACLTestIPv6TCP(src, dst netip.Addr, dstPort uint16, hopByHop bool) []byte {
	packet := make([]byte, 40)
	packet[0] = 0x60
	packet[7] = 64
	s, d := src.As16(), dst.As16()
	copy(packet[8:24], s[:])
	copy(packet[24:40], d[:])
	if hopByHop {
		packet[6] = 0 // Hop-by-Hop
		packet = append(packet, 6, 0, 1, 4, 0, 0, 0, 0)
	} else {
		packet[6] = 6
	}
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], 40000)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	packet = append(packet, tcp...)
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)-40))
	return packet
}

func TestPacketDestinationParsesPortsThroughIPv6ExtensionHeaders(t *testing.T) {
	src := netip.MustParseAddr("2001:4860::5")
	dst := netip.MustParseAddr("2606:4700::1")
	for _, hbh := range []bool{false, true} {
		got, proto, port, ok := packetDestination(buildACLTestIPv6TCP(src, dst, 25, hbh))
		if !ok || got != dst || proto != 6 || port != 25 {
			t.Fatalf("hopByHop=%v: got (%v,%d,%d,%v), want (%v,6,25,true)", hbh, got, proto, port, ok, dst)
		}
	}
	got, proto, port, ok := packetDestination(buildACLTestIPv4TCP(netip.MustParseAddr("10.88.0.4"), netip.MustParseAddr("1.1.1.1"), 443))
	if !ok || got != netip.MustParseAddr("1.1.1.1") || proto != 6 || port != 443 {
		t.Fatalf("ipv4: got (%v,%d,%d,%v)", got, proto, port, ok)
	}
}

// 回归（审查 P0-2）：CONNECT-IP 客户端报文曾不经任何目的地址检查直接写入 TUN。
func TestGlobalTunnelReaderReverseDispatchEnforcesDestinationACL(t *testing.T) {
	router := NewGlobalTunnelRouter()
	clientIP := netip.MustParseAddr("10.88.0.4")
	clientIPv6 := netip.MustParseAddr("2001:4860::5")
	conn := &reverseReaderConn{packets: make(chan []byte, 8), closed: make(chan struct{})}
	generation, err := router.Register(GlobalTunnelBinding{IPv4: clientIP, IPv6: clientIPv6, Conn: conn})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	device := &readerTestDevice{packets: make(chan []byte), closed: make(chan struct{}), writes: make(chan []byte, 8)}
	reader, err := NewGlobalTunnelReader(nil, device, router)
	if err != nil {
		t.Fatalf("new reader: %v", err)
	}
	if err := reader.StartBinding(nil, GlobalTunnelBinding{IPv4: clientIP, IPv6: clientIPv6, Generation: generation, Conn: conn}); err != nil {
		t.Fatalf("start reverse binding: %v", err)
	}
	defer func() {
		if err := reader.Close(); err != nil {
			t.Fatalf("close reader: %v", err)
		}
	}()

	denied := map[string][]byte{
		"metadata":          buildRouterTestIPv4(clientIP, netip.MustParseAddr("169.254.169.254")),
		"other client":      buildRouterTestIPv4(clientIP, netip.MustParseAddr("10.88.0.9")),
		"edge gateway":      buildRouterTestIPv4(clientIP, netip.MustParseAddr("10.88.0.1")),
		"vpc private":       buildRouterTestIPv4(clientIP, netip.MustParseAddr("172.31.0.10")),
		"loopback":          buildRouterTestIPv4(clientIP, netip.MustParseAddr("127.0.0.1")),
		"multicast":         buildRouterTestIPv4(clientIP, netip.MustParseAddr("224.0.0.251")),
		"tcp/25 ipv4":       buildACLTestIPv4TCP(clientIP, netip.MustParseAddr("1.1.1.1"), 25),
		"tcp/25 ipv6 ext":   buildACLTestIPv6TCP(clientIPv6, netip.MustParseAddr("2606:4700::1"), 25, true),
		"ipv6 unique-local": buildACLTestIPv6TCP(clientIPv6, netip.MustParseAddr("fd00:ec2::254"), 80, false),
	}
	for name, packet := range denied {
		conn.packets <- packet
		select {
		case <-device.writes:
			t.Fatalf("%s: denied packet was written to the shared TUN", name)
		case <-time.After(30 * time.Millisecond):
		}
	}

	conn.packets <- buildACLTestIPv4TCP(clientIP, netip.MustParseAddr("1.1.1.1"), 443)
	select {
	case <-device.writes:
	case <-time.After(time.Second):
		t.Fatal("allowed public packet was not written")
	}
}

// blockingTestConn 的 WritePacket 一直阻塞，模拟 SendDatagram 队列已满的拥塞客户端；
// 与真实 CONNECT-IP 连接一样，Close 会让阻塞中的写入返回。
type blockingTestConn struct {
	release   chan struct{}
	started   chan struct{}
	once      sync.Once
	closeOnce sync.Once
}

func (c *blockingTestConn) ReadPacket([]byte) (int, error) { return 0, nil }
func (c *blockingTestConn) WritePacket([]byte) ([]byte, error) {
	c.once.Do(func() { close(c.started) })
	<-c.release
	return nil, net.ErrClosed
}
func (c *blockingTestConn) Close() error {
	c.closeOnce.Do(func() { close(c.release) })
	return nil
}

// 回归（审查 P0-6）：共享 TUN 读循环同步调用 WritePacket，一个拥塞客户端会卡住所有用户的下行。
func TestGlobalTunnelReaderSlowClientDoesNotBlockOthers(t *testing.T) {
	router := NewGlobalTunnelRouter()
	slowIP := netip.MustParseAddr("10.88.0.20")
	fastIP := netip.MustParseAddr("10.88.0.21")
	slow := &blockingTestConn{release: make(chan struct{}), started: make(chan struct{})}
	defer func() { _ = slow.Close() }()
	fast := &readerTestConn{writes: make(chan []byte, 4)}
	if _, err := router.Register(GlobalTunnelBinding{IPv4: slowIP, Conn: slow}); err != nil {
		t.Fatalf("register slow: %v", err)
	}
	if _, err := router.Register(GlobalTunnelBinding{IPv4: fastIP, Conn: fast}); err != nil {
		t.Fatalf("register fast: %v", err)
	}
	device := &readerTestDevice{packets: make(chan []byte, 512), closed: make(chan struct{})}
	reader, err := NewGlobalTunnelReader(nil, device, router)
	if err != nil {
		t.Fatalf("new reader: %v", err)
	}
	reader.Start()
	defer func() { _ = reader.Close() }()

	internet := netip.MustParseAddr("1.1.1.1")
	device.packets <- buildRouterTestIPv4(internet, slowIP)
	select {
	case <-slow.started:
	case <-time.After(time.Second):
		t.Fatal("slow client never received its first packet")
	}
	// 再塞满慢客户端的队列，读循环仍必须继续工作。
	for i := 0; i < 300; i++ {
		device.packets <- buildRouterTestIPv4(internet, slowIP)
	}
	device.packets <- buildRouterTestIPv4(internet, fastIP)
	select {
	case <-fast.writes:
	case <-time.After(time.Second):
		t.Fatal("fast client starved by a congested client on the shared TUN")
	}
}

// 有拥塞客户端时，reader 仍必须能在限定时间内关闭（服务端优雅退出）。
func TestGlobalTunnelReaderCloseWithCongestedClient(t *testing.T) {
	router := NewGlobalTunnelRouter()
	slowIP := netip.MustParseAddr("10.88.0.30")
	slow := &blockingTestConn{release: make(chan struct{}), started: make(chan struct{})}
	if _, err := router.Register(GlobalTunnelBinding{IPv4: slowIP, Conn: slow}); err != nil {
		t.Fatalf("register: %v", err)
	}
	device := &readerTestDevice{packets: make(chan []byte, 8), closed: make(chan struct{})}
	reader, err := NewGlobalTunnelReader(nil, device, router)
	if err != nil {
		t.Fatalf("new reader: %v", err)
	}
	reader.Start()
	device.packets <- buildRouterTestIPv4(netip.MustParseAddr("1.1.1.1"), slowIP)
	select {
	case <-slow.started:
	case <-time.After(time.Second):
		t.Fatal("slow client never received its packet")
	}
	done := make(chan struct{})
	go func() {
		_ = reader.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("reader.Close hung behind a congested client")
	}
}

// 会话从路由表注销后，其下行发送协程必须自行退出，不得遗留。
// 使用 testing/synctest 的虚拟时钟，结果确定且不真实等待（L0 §13.1）。
func TestGlobalTunnelReaderDownlinkExitsAfterUnregister(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		router := NewGlobalTunnelRouter()
		ip := netip.MustParseAddr("10.88.0.40")
		conn := &readerTestConn{writes: make(chan []byte, 4)}
		generation, err := router.Register(GlobalTunnelBinding{IPv4: ip, Conn: conn})
		if err != nil {
			t.Fatalf("register: %v", err)
		}
		device := &readerTestDevice{packets: make(chan []byte, 4), closed: make(chan struct{})}
		reader, err := NewGlobalTunnelReader(nil, device, router)
		if err != nil {
			t.Fatalf("new reader: %v", err)
		}
		reader.Start()
		defer func() { _ = reader.Close() }()

		device.packets <- buildRouterTestIPv4(netip.MustParseAddr("1.1.1.1"), ip)
		<-conn.writes
		router.Unregister(ip, generation)

		time.Sleep(2 * downlinkLivenessInterval) // 虚拟时间
		synctest.Wait()

		reader.downMu.Lock()
		n := len(reader.downlinks)
		reader.downMu.Unlock()
		if n != 0 {
			t.Fatalf("downlinks after unregister = %d, want 0", n)
		}
	})
}

// C6：CONNECT-IP 会话的上下行按 IP 报文长度计入 binding 的计量单元。
func TestGlobalTunnelReaderMetersUsage(t *testing.T) {
	cell := &usageCell{uid: "user_meter01", iss: "sub"}
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("%s: up=%d down=%d", what, cell.up.Load(), cell.down.Load())
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	router := NewGlobalTunnelRouter()
	device := &readerTestDevice{packets: make(chan []byte, 1), closed: make(chan struct{}), writes: make(chan []byte, 1)}
	reader, err := NewGlobalTunnelReader(nil, device, router)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	reader.Start()

	// 下行：TUN → 会话
	downIP := netip.MustParseAddr("10.88.0.5")
	downConn := &readerTestConn{writes: make(chan []byte, 1)}
	if _, err := router.Register(GlobalTunnelBinding{IPv4: downIP, Conn: downConn, usage: cell}); err != nil {
		t.Fatal(err)
	}
	down := buildRouterTestIPv4(netip.MustParseAddr("192.0.2.10"), downIP)
	device.packets <- down
	<-downConn.writes
	waitFor("downlink", func() bool { return cell.down.Load() == int64(len(down)) })

	// 上行：会话 → TUN
	upIP := netip.MustParseAddr("10.88.0.6")
	upConn := &reverseReaderConn{packets: make(chan []byte, 1), closed: make(chan struct{})}
	b := GlobalTunnelBinding{IPv4: upIP, Conn: upConn, usage: cell}
	if b.Generation, err = router.Register(b); err != nil {
		t.Fatal(err)
	}
	if err := reader.StartBinding(nil, b); err != nil {
		t.Fatal(err)
	}
	up := buildRouterTestIPv4(upIP, netip.MustParseAddr("8.8.8.8"))
	upConn.packets <- up
	<-device.writes
	waitFor("uplink", func() bool { return cell.up.Load() == int64(len(up)) })
}
