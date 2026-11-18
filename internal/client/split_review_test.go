package client

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// ---- 1. 内置 China Direct 规则不再带手写 IP 网段 ----

func TestSplitMatchNonAPNICAddressNotDirect(t *testing.T) {
	e := NewSplitEngine()
	for _, s := range []string{"220.130.1.1", "122.116.1.1", "211.100.1.1", "203.208.1.1", "14.196.1.1", "103.32.1.1"} {
		ip := net.ParseIP(s)
		if e.chinaMatcher.Contains(ip) {
			t.Skipf("%s 位于 APNIC 中国段，测试前提不成立", s)
		}
		if got := e.Match(s, nil); got == DIRECT {
			t.Errorf("Match(%s) = DIRECT，非 APNIC 中国段地址不得直连", s)
		}
	}
}

func TestSplitMatchAPNICAddressStillDirect(t *testing.T) {
	var cidr string
	for _, line := range strings.Split(chinaIPData, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") && strings.Contains(line, ".") {
			cidr = line
			break
		}
	}
	if cidr == "" {
		t.Fatal("china_ip.txt 没有可用网段")
	}
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}
	ip := make(net.IP, 4)
	copy(ip, n.IP.To4())
	ip[3] |= 1
	if got := NewSplitEngine().Match(ip.String(), nil); got != DIRECT {
		t.Errorf("Match(%s) = %v，APNIC 段 %s 内地址应为 DIRECT", ip, got, cidr)
	}
}

func TestBuiltinChinaDirectRuleHasNoIPRanges(t *testing.T) {
	e := NewSplitEngine()
	for _, r := range e.rules {
		if len(r.IPRanges) != 0 || len(r.parsedIPNets) != 0 {
			t.Errorf("内置规则 %q 不应携带手写 IP 网段", r.Name)
		}
	}
}

// ---- 2. SetKillSwitch 与 Stop/RestartWithConn 并发 ----

func TestStackSetKillSwitchConcurrentWithRestartAndStop(t *testing.T) {
	dev := newMockTunDevice()
	stack := NewStackEngineWithConn(dev, newMockIPPacketConn(), nil)
	if err := stack.Start(); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			stack.SetKillSwitch(i%2 == 0)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			_ = stack.RestartWithConn(newMockIPPacketConn())
		}
	}()
	time.Sleep(50 * time.Millisecond)
	stack.Stop()
	close(stop)
	wg.Wait()

	stack.SetKillSwitch(true)
	if !stack.KillSwitch() {
		t.Fatal("SetKillSwitch(true) 后 KillSwitch() 应为 true")
	}
}

func TestStackKillSwitchSharedWithPump(t *testing.T) {
	stack := NewStackEngineWithConn(newMockTunDevice(), newMockIPPacketConn(), nil)
	if err := stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Stop()
	stack.mu.Lock()
	shared := stack.pump != nil && stack.pump.killSwitch == &stack.killSwitch
	stack.mu.Unlock()
	if !shared {
		t.Fatal("数据泵必须与 StackEngine 共用同一个 killSwitch 原子量")
	}
}

// ---- 3. 混合代理：只允许回环、握手 deadline ----

func TestRequireLoopbackListenAddr(t *testing.T) {
	ok := []string{"127.0.0.1:0", "127.0.0.2:1080", "[::1]:0", "localhost:55555", "LOCALHOST:1"}
	bad := []string{"0.0.0.0:0", "[::]:0", ":55555", "192.0.2.1:80", "example.com:80", "noport"}
	for _, a := range ok {
		if err := requireLoopbackListenAddr(a); err != nil {
			t.Errorf("%q 应被接受: %v", a, err)
		}
	}
	for _, a := range bad {
		if err := requireLoopbackListenAddr(a); err == nil {
			t.Errorf("%q 应被拒绝", a)
		}
	}
}

func TestStartResidentMixedProxyRejectsNonLoopback(t *testing.T) {
	eng := NewEngine()
	defer eng.Close()
	before := eng.listenAddr
	if err := eng.StartResidentMixedProxy("0.0.0.0:0"); err == nil {
		t.Fatal("0.0.0.0:0 应被拒绝")
	}
	if eng.mixedListener != nil {
		t.Fatal("被拒绝后不应存在监听器")
	}
	if eng.listenAddr != before {
		t.Fatalf("被拒绝后 listenAddr 不应改变: %q -> %q", before, eng.listenAddr)
	}
	// 拒绝后仍可正常启动回环监听
	if err := eng.StartResidentMixedProxy("127.0.0.1:0"); err != nil {
		t.Fatalf("回环地址应可启动: %v", err)
	}
	if eng.mixedListener == nil {
		t.Fatal("回环监听应已建立")
	}
}

func TestServeMixedConnHandshakeDeadlineClosesSlowConn(t *testing.T) {
	cases := []struct {
		name  string
		first []byte // 慢速连接已发出的部分握手字节
		reply int    // 期望读到的服务端应答字节数
	}{
		{"silent", nil, 0},
		{"socks5-greeting-then-stall", []byte{0x05, 0x01, 0x00}, 2},
		{"http-partial-request", []byte("CONNECT example.com:443 HTTP/1.1\r\n"), 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			eng := NewEngine()
			eng.mixedHandshakeTimeout = 100 * time.Millisecond
			cli, srv := net.Pipe()
			defer cli.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				eng.serveMixedConn(srv)
			}()
			if len(c.first) > 0 {
				go func() { _, _ = cli.Write(c.first) }()
			}
			if c.reply > 0 {
				buf := make([]byte, c.reply)
				_ = cli.SetReadDeadline(time.Now().Add(2 * time.Second))
				if _, err := cli.Read(buf); err != nil {
					t.Fatalf("读取握手应答失败: %v", err)
				}
			}
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("握手 deadline 到期后 serveMixedConn 仍未返回")
			}
		})
	}
}

// deadlineRecordingConn 记录 SetReadDeadline 的调用序列。
type deadlineRecordingConn struct {
	net.Conn
	mu        sync.Mutex
	deadlines []time.Time
}

func (c *deadlineRecordingConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadlines = append(c.deadlines, t)
	c.mu.Unlock()
	return c.Conn.SetReadDeadline(t)
}

func TestServeMixedConnClearsDeadlineAfterHandshake(t *testing.T) {
	eng := NewEngine()
	stubUpstreamDialFail(t, eng)
	cli, srvRaw := net.Pipe()
	defer cli.Close()
	srv := &deadlineRecordingConn{Conn: srvRaw}
	done := make(chan struct{})
	go func() {
		defer close(done)
		eng.serveMixedConn(srv)
		_ = srv.Close()
	}()
	go func() {
		_, _ = cli.Write([]byte("CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n"))
	}()
	go func() { _, _ = bufio.NewReader(cli).ReadString('\n') }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("serveMixedConn 未返回")
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.deadlines) < 2 {
		t.Fatalf("应至少设置并清除一次 deadline，实际 %d 次", len(srv.deadlines))
	}
	if srv.deadlines[0].IsZero() {
		t.Fatal("握手开始时应设置非零 deadline")
	}
	if !srv.deadlines[len(srv.deadlines)-1].IsZero() {
		t.Fatal("握手完成后应清除 deadline")
	}
}

// stubUpstreamDialFail 让握手后的上游拨号立即失败，避免测试依赖真实网络。
func stubUpstreamDialFail(t *testing.T, eng *Engine) {
	t.Helper()
	SetPhysicalDialerHook(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, net.ErrClosed
	})
	t.Cleanup(func() { SetPhysicalDialerHook(nil) })
}

// ---- 4. geodata 响应体上限 ----

func TestSyncGeoDataRejectsOversizedBody(t *testing.T) {
	t.Setenv("AERO_DATA_DIR", t.TempDir())
	big := make([]byte, geoDataMaxBytes+1)
	for i := range big {
		big[i] = 'a'
		if i%64 == 63 {
			big[i] = '\n'
		}
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(big)
	})
	SetPhysicalDialerHook(newInMemHTTPDialer(handler))
	defer SetPhysicalDialerHook(nil)

	eng := NewEngine()
	eng.SetGeoDataURL("http://geodata.example.com/geodata_direct.txt")
	before := eng.splitEngine.TotalRules()

	_, updated, err := eng.SyncGeoData(context.Background())
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("超限响应应报错，got err=%v", err)
	}
	if updated {
		t.Fatal("超限时不应报告 updated")
	}
	if after := eng.splitEngine.TotalRules(); after != before {
		t.Fatalf("超限时不应替换现有规则: %d -> %d", before, after)
	}
	if _, statErr := os.Stat(filepath.Join(GetDataDir(), "geodata_direct.txt")); statErr == nil {
		t.Fatal("超限时不应落盘")
	}
}

// ---- 5. alt_ports 赛跑：落选连接必须被关闭 ----

func TestDialAltPortsRaceClosesLosingConns(t *testing.T) {
	ln, err := quic.ListenAddr("127.0.0.1:0", dialLeakTestTLS(t), &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func() { <-c.Context().Done() }()
		}
	}()
	srvAddr := ln.Addr().(*net.UDPAddr)

	const nPorts = 3
	var (
		mu      sync.Mutex
		dialed  []*quic.Conn
		arrived atomic.Int32
	)
	barrier := make(chan struct{})
	setQUICRaceDialHookForTest(func(ctx context.Context, port int) (*quic.Conn, error) {
		// 等所有端口都已发起拨号后再同时返回成功，模拟多个端口同时握手成功
		if arrived.Add(1) == nPorts {
			close(barrier)
		}
		select {
		case <-barrier:
		case <-time.After(5 * time.Second):
			return nil, context.DeadlineExceeded
		}
		c, err := quic.DialAddr(context.Background(), srvAddr.String(),
			&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}},
			&quic.Config{EnableDatagrams: true, KeepAlivePeriod: time.Second})
		if err != nil {
			return nil, err
		}
		mu.Lock()
		dialed = append(dialed, c)
		mu.Unlock()
		return c, nil
	})
	defer setQUICRaceDialHookForTest(nil)

	cfg := DefaultTransportConfig(srvAddr.String(), "localhost")
	cfg.TLSConfig = &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}
	cfg.RemoteUDPAddr = &net.UDPAddr{IP: srvAddr.IP, Port: srvAddr.Port}
	cfg.AltPorts = []int{srvAddr.Port + 1, srvAddr.Port + 2}
	cfg.PacketConnFactory = func(ctx context.Context, network string) (net.PacketConn, error) {
		return net.ListenPacket("udp4", "127.0.0.1:0")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cl, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cl.Close()

	// 等所有拨号完成
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(dialed)
		mu.Unlock()
		if n == nPorts {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("只有 %d 个端口拨号成功", n)
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	conns := append([]*quic.Conn(nil), dialed...)
	mu.Unlock()
	for _, c := range conns {
		if c == cl.Conn() {
			select {
			case <-c.Context().Done():
				t.Fatal("赢家连接不应被关闭")
			default:
			}
			continue
		}
		select {
		case <-c.Context().Done():
		case <-time.After(3 * time.Second):
			t.Fatal("落选连接未被关闭（泄漏）")
		}
	}
}
