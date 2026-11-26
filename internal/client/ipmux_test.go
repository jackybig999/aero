// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeConn 是可控的 IPPacketConn：测试往 in 里放“收到的包”，从 out 里取“发出的包”。
type fakeConn struct {
	in         chan []byte
	out        chan []byte
	closed     chan struct{}
	once       sync.Once
	readErr    chan error    // 往里放一个错误，ReadPacket 返回它
	blockWrite chan struct{} // 非 nil 时 WritePacket 阻塞，直到它被关闭或连接关闭
	writeErr   atomic.Pointer[error]
	closeCalls atomic.Int32
}

func newFakeConn() *fakeConn {
	return &fakeConn{in: make(chan []byte, 1024), out: make(chan []byte, 4096), closed: make(chan struct{}), readErr: make(chan error, 1)}
}

func (f *fakeConn) ReadPacket(b []byte) (int, error) {
	select {
	case p := <-f.in:
		return copy(b, p), nil
	case err := <-f.readErr:
		return 0, err
	case <-f.closed:
		return 0, net.ErrClosed
	}
}

func (f *fakeConn) WritePacket(b []byte) ([]byte, error) {
	if f.blockWrite != nil {
		select {
		case <-f.blockWrite:
		case <-f.closed:
			return nil, net.ErrClosed
		}
	}
	if e := f.writeErr.Load(); e != nil {
		return nil, *e
	}
	select {
	case <-f.closed:
		return nil, net.ErrClosed
	default:
	}
	f.out <- append([]byte(nil), b...)
	return nil, nil
}

func (f *fakeConn) Close() error {
	f.closeCalls.Add(1)
	f.once.Do(func() { close(f.closed) })
	return nil
}

func (f *fakeConn) recv(t *testing.T) []byte {
	t.Helper()
	select {
	case p := <-f.out:
		return p
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for a packet")
		return nil
	}
}

func (f *fakeConn) expectNothing(t *testing.T) {
	t.Helper()
	select {
	case p := <-f.out:
		t.Fatalf("unexpected packet % x", p[:20])
	case <-time.After(60 * time.Millisecond):
	}
}

// tcpWithFlags 生成校验和正确的 IPv4 TCP 包，flags 与端口可控。
func tcpWithFlags(src, dst netip.Addr, sport, dport uint16, flags byte, payload int) []byte {
	seg := make([]byte, 20+payload)
	binary.BigEndian.PutUint16(seg[0:2], sport)
	binary.BigEndian.PutUint16(seg[2:4], dport)
	seg[12], seg[13] = 0x50, flags
	for i := 20; i < len(seg); i++ {
		seg[i] = byte(i)
	}
	return withL4Checksum(buildIPv4(src, dst, 6, nil, seg, 0), 16)
}

func udpPacket(src, dst netip.Addr) []byte {
	d := make([]byte, 8+10)
	binary.BigEndian.PutUint16(d[0:2], 4000)
	binary.BigEndian.PutUint16(d[2:4], 5000)
	binary.BigEndian.PutUint16(d[4:6], uint16(len(d)))
	return withL4Checksum(buildIPv4(src, dst, 17, nil, d, 0), 6)
}

type muxFixture struct {
	m   *ipMux
	d   *fakeConn
	cls *flowClassifier
}

func newMuxFixture(t *testing.T) *muxFixture {
	t.Helper()
	cls := newFlowClassifier()
	cls.reliableTCP.Store(false) // 旧用例按“只有 AI 地址走 R”写；普通 TCP 走 R 见 TestMuxReliable*
	cls.ai.Add(aiHost, time.Hour)
	d := newFakeConn()
	m := newIPMux(d, natTun, cls)
	t.Cleanup(func() { _ = m.Close() })
	return &muxFixture{m: m, d: d, cls: cls}
}

func (f *muxFixture) attachAI(t *testing.T) *fakeConn {
	t.Helper()
	a := newFakeConn()
	if err := f.m.AttachAI(a, natAI); err != nil {
		t.Fatal(err)
	}
	return a
}

func readOne(t *testing.T, m *ipMux) []byte {
	t.Helper()
	type res struct {
		b   []byte
		err error
	}
	ch := make(chan res, 1)
	go func() {
		buf := make([]byte, 65535)
		n, err := m.ReadPacket(buf)
		ch <- res{append([]byte(nil), buf[:max(n, 0)]...), err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("ReadPacket: %v", r.err)
		}
		return r.b
	case <-time.After(3 * time.Second):
		t.Fatal("timed out in ReadPacket")
		return nil
	}
}

func TestMuxUDPAndNonAIGoToDefaultUntouched(t *testing.T) {
	f := newMuxFixture(t)
	a := f.attachAI(t)
	udp := udpPacket(natTun, aiHost) // 即使目的地址在 AI 集合里，UDP 也走 default
	orig := append([]byte(nil), udp...)
	if _, err := f.m.WritePacket(udp); err != nil {
		t.Fatal(err)
	}
	got := f.d.recv(t)
	if string(got) != string(orig) {
		t.Fatal("default packet was modified")
	}
	other := tcpWithFlags(natTun, otherHost, 50000, 443, fSYN, 0)
	if _, err := f.m.WritePacket(other); err != nil {
		t.Fatal(err)
	}
	f.d.recv(t)
	a.expectNothing(t)
}

func TestMuxAITCPUsesAISessionWithRewrittenSource(t *testing.T) {
	f := newMuxFixture(t)
	a := f.attachAI(t)
	syn := tcpWithFlags(natTun, aiHost, 50001, 443, fSYN, 0)
	if icmp, err := f.m.WritePacket(syn); err != nil || icmp != nil {
		t.Fatalf("icmp=%v err=%v", icmp, err)
	}
	got := a.recv(t)
	if netip.AddrFrom4([4]byte(got[12:16])) != natAI || netip.AddrFrom4([4]byte(got[16:20])) != aiHost {
		t.Fatalf("addresses %v -> %v", got[12:16], got[16:20])
	}
	if !refIPHeaderValid(got) || !refL4Valid(t, got) {
		t.Fatal("rewritten packet has invalid checksums")
	}
	f.d.expectNothing(t)
	// 同一条流的后续包（含载荷）继续走 ai。
	f.m.WritePacket(tcpWithFlags(natTun, aiHost, 50001, 443, fACK, 700))
	if got := a.recv(t); !refL4Valid(t, got) {
		t.Fatal("data packet invalid")
	}
}

func TestMuxDownlinkMergesBothSessions(t *testing.T) {
	f := newMuxFixture(t)
	a := f.attachAI(t)
	// ai 下行：目的地址是 ai 会话地址，交给泵时必须是 TUN 地址且校验和有效。
	a.in <- tcpWithFlags(aiHost, natAI, 443, 50001, fSYN|fACK, 100)
	f.d.in <- udpPacket(otherHost, natTun)
	var gotAI, gotD bool
	for i := 0; i < 2; i++ {
		p := readOne(t, f.m)
		if netip.AddrFrom4([4]byte(p[16:20])) != natTun || !refIPHeaderValid(p) || !refL4Valid(t, p) {
			t.Fatalf("delivered packet invalid: dst=%v", p[16:20])
		}
		if p[9] == 6 {
			gotAI = true
		} else {
			gotD = true
		}
	}
	if !gotAI || !gotD {
		t.Fatalf("ai=%v default=%v", gotAI, gotD)
	}
	// 目的地址不是 ai 会话地址的下行包被丢弃并计数。
	a.in <- tcpWithFlags(aiHost, netip.MustParseAddr("10.88.130.200"), 443, 50001, fACK, 0)
	a.in <- tcpWithFlags(aiHost, natAI, 443, 50001, fACK, 5)
	p := readOne(t, f.m)
	if len(p) != 20+20+5 {
		t.Fatalf("got the wrong packet, len=%d", len(p))
	}
	if f.m.stats.aiRxBadDest.Load() != 1 {
		t.Fatalf("aiRxBadDest = %d", f.m.stats.aiRxBadDest.Load())
	}
}

func TestMuxICMPErrorFromAIGetsInnerAddressRestored(t *testing.T) {
	f := newMuxFixture(t)
	a := f.attachAI(t)
	sent := tcpWithFlags(natAI, aiHost, 50001, 443, fSYN, 0)
	icmp := append([]byte{3, 4, 0, 0, 0, 0, 5, 0xdc}, sent[:28]...)
	pkt := buildIPv4(netip.MustParseAddr("198.51.100.1"), natAI, 1, nil, icmp, 0)
	binary.BigEndian.PutUint16(pkt[22:24], onesComplementSum(pkt[20:]))
	a.in <- pkt
	p := readOne(t, f.m)
	in := p[28:]
	if netip.AddrFrom4([4]byte(in[12:16])) != natTun || !refIPHeaderValid(in) || onesComplementSum(p[20:]) != 0 {
		t.Fatal("ICMP error not translated back")
	}
}

// ai 会话不可用：新连接得到 ICMP 不可达（应用立即失败），已有连接的包静默丢弃，default 不受影响，绝不改走 default。
func TestMuxFailClosedWhenAIUnavailable(t *testing.T) {
	f := newMuxFixture(t)
	syn := tcpWithFlags(natTun, aiHost, 50002, 443, fSYN, 0)
	icmp, err := f.m.WritePacket(syn)
	if err != nil || icmp == nil {
		t.Fatalf("expected an ICMP unreachable, got %v %v", icmp, err)
	}
	if icmp[9] != 1 || icmp[20] != 3 || icmp[21] != icmpHostUnreachable ||
		netip.AddrFrom4([4]byte(icmp[12:16])) != aiHost || netip.AddrFrom4([4]byte(icmp[16:20])) != natTun ||
		!refIPHeaderValid(icmp) || onesComplementSum(icmp[20:]) != 0 {
		t.Fatalf("bad ICMP: % x", icmp)
	}
	if string(icmp[28:28+28]) != string(syn[:28]) {
		t.Fatal("ICMP does not quote the original header + 8 bytes")
	}
	if icmp2, err := f.m.WritePacket(tcpWithFlags(natTun, aiHost, 50002, 443, fACK, 100)); err != nil || icmp2 != nil {
		t.Fatalf("data packet of a dead ai flow: icmp=%v err=%v", icmp2, err)
	}
	f.d.expectNothing(t) // 绝不改走 default
	if f.m.stats.aiUnavailable.Load() != 2 {
		t.Fatalf("aiUnavailable = %d", f.m.stats.aiUnavailable.Load())
	}
	if _, err := f.m.WritePacket(udpPacket(natTun, otherHost)); err != nil {
		t.Fatal(err)
	}
	f.d.recv(t)
}

// ai 会话的写被反压卡住：绝不阻塞 default 的上行；ai 队列满后丢尾。
func TestMuxAIBackpressureNeverBlocksDefault(t *testing.T) {
	f := newMuxFixture(t)
	a := newFakeConn()
	a.blockWrite = make(chan struct{})
	if err := f.m.AttachAI(a, natAI); err != nil {
		t.Fatal(err)
	}
	f.m.WritePacket(tcpWithFlags(natTun, aiHost, 50003, 443, fSYN, 0)) // 只有 SYN 才能开始一条 ai 流
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 5000; i++ {
			f.m.WritePacket(tcpWithFlags(natTun, aiHost, 50003, 443, fACK, 1000))
			if i%100 == 0 {
				f.m.WritePacket(udpPacket(natTun, otherHost))
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("WritePacket blocked while the ai session was back-pressured")
	}
	if f.m.stats.aiTxDropped.Load() == 0 {
		t.Fatal("expected tail drops on the ai queue")
	}
	udpSeen := 0
	for len(f.d.out) > 0 {
		<-f.d.out
		udpSeen++
	}
	if udpSeen != 50 {
		t.Fatalf("default packets delivered = %d, want 50", udpSeen)
	}
}

// ai 会话读写失败：只降级，泵看不到错误，default 照常；回调只触发一次；可以重新接入。
func TestMuxAIFailureDegradesOnly(t *testing.T) {
	for _, mode := range []string{"read", "write"} {
		t.Run(mode, func(t *testing.T) {
			f := newMuxFixture(t)
			var calls atomic.Int32
			downErr := make(chan error, 4)
			f.m.SetAIDownHandler(func(err error) { calls.Add(1); downErr <- err })
			a := f.attachAI(t)
			boom := errors.New("ai stream reset")
			if mode == "read" {
				a.readErr <- boom
			} else {
				a.writeErr.Store(&boom)
				f.m.WritePacket(tcpWithFlags(natTun, aiHost, 50004, 443, fSYN, 0))
			}
			select {
			case err := <-downErr:
				if !errors.Is(err, boom) {
					t.Fatalf("onAIDown err = %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("onAIDown not called")
			}
			if f.m.AIAvailable() || a.closeCalls.Load() == 0 {
				t.Fatal("failed ai link not torn down")
			}
			// default 不受影响：上行、下行都正常，ReadPacket 没有返回错误。
			f.m.WritePacket(udpPacket(natTun, otherHost))
			f.d.recv(t)
			f.d.in <- udpPacket(otherHost, natTun)
			readOne(t, f.m)
			// 重新接入后恢复。
			a2 := f.attachAI(t)
			if !f.m.AIAvailable() {
				t.Fatal("not available after reattach")
			}
			f.m.WritePacket(tcpWithFlags(natTun, aiHost, 50005, 443, fSYN, 0))
			a2.recv(t)
			time.Sleep(50 * time.Millisecond)
			if calls.Load() != 1 {
				t.Fatalf("onAIDown called %d times", calls.Load())
			}
		})
	}
}

func TestMuxAttachReplacesAndDetachIsSilent(t *testing.T) {
	f := newMuxFixture(t)
	var calls atomic.Int32
	f.m.SetAIDownHandler(func(error) { calls.Add(1) })
	a1 := f.attachAI(t)
	a2 := f.attachAI(t) // 替换：旧的被关闭，不触发回调
	time.Sleep(50 * time.Millisecond)
	if a1.closeCalls.Load() == 0 {
		t.Fatal("replaced link was not closed")
	}
	f.m.WritePacket(tcpWithFlags(natTun, aiHost, 50006, 443, fSYN, 0))
	a2.recv(t)
	f.m.DetachAI()
	time.Sleep(50 * time.Millisecond)
	if f.m.AIAvailable() || a2.closeCalls.Load() == 0 || calls.Load() != 0 {
		t.Fatalf("detach: available=%v closed=%d callbacks=%d", f.m.AIAvailable(), a2.closeCalls.Load(), calls.Load())
	}
}

// default 会话失败就是整条隧道失败：ReadPacket 返回那个错误；Close 可重复，关闭两个会话。
func TestMuxDefaultFailureAndClose(t *testing.T) {
	f := newMuxFixture(t)
	a := f.attachAI(t)
	boom := errors.New("quic connection lost")
	f.d.readErr <- boom
	buf := make([]byte, 2000)
	if _, err := f.m.ReadPacket(buf); !errors.Is(err, boom) {
		t.Fatalf("ReadPacket err = %v", err)
	}
	if err := f.m.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.m.Close(); err != nil {
		t.Fatal("second Close failed")
	}
	if f.d.closeCalls.Load() != 1 || a.closeCalls.Load() == 0 {
		t.Fatalf("closes: default=%d ai=%d", f.d.closeCalls.Load(), a.closeCalls.Load())
	}
	if err := f.m.AttachAI(newFakeConn(), natAI); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("attach after close: %v", err)
	}
	if _, err := f.m.ReadPacket(buf); !errors.Is(err, boom) {
		t.Fatalf("ReadPacket after close keeps the first error, got %v", err)
	}
}

func TestMuxCloseUnblocksReaderAndLeaksNoGoroutines(t *testing.T) {
	runtime.GC()
	before := runtime.NumGoroutine()
	for i := 0; i < 20; i++ {
		d := newFakeConn()
		m := newIPMux(d, natTun, newFlowClassifier())
		a := newFakeConn()
		a.blockWrite = make(chan struct{})
		_ = m.AttachAI(a, natAI)
		m.cls.ai.Add(aiHost, time.Hour)
		m.WritePacket(tcpWithFlags(natTun, aiHost, 50007, 443, fSYN, 0))
		for j := 0; j < 300; j++ {
			m.WritePacket(tcpWithFlags(natTun, aiHost, 50007, 443, fACK, 100))
		}
		errCh := make(chan error, 1)
		go func() { _, err := m.ReadPacket(make([]byte, 2000)); errCh <- err }()
		time.Sleep(5 * time.Millisecond)
		_ = m.Close()
		select {
		case err := <-errCh:
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("blocked ReadPacket returned %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("Close did not unblock ReadPacket")
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > before+2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > before+2 {
		t.Fatalf("goroutines leaked: before=%d after=%d", before, after)
	}
}

// -race 下并发：多个写者、一个读者、反复接入/断开/失败。
func TestMuxConcurrentStress(t *testing.T) {
	f := newMuxFixture(t)
	f.m.SetAIDownHandler(func(error) {})
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				f.m.WritePacket(tcpWithFlags(natTun, aiHost, uint16(51000+g*10+i%10), 443, fSYN, 0))
				f.m.WritePacket(udpPacket(natTun, otherHost))
			}
		}(g)
	}
	wg.Add(1)
	go func() { // 排空 default 的上行记录，避免 fake 的 out 通道写满
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			case <-f.d.out:
			}
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 2000)
		for {
			select {
			case <-stop:
				return
			default:
			}
			f.d.in <- udpPacket(otherHost, natTun)
			f.m.ReadPacket(buf)
		}
	}()
	for i := 0; i < 50; i++ {
		a := newFakeConn()
		if err := f.m.AttachAI(a, natAI); err != nil {
			t.Fatal(err)
		}
		a.in <- tcpWithFlags(aiHost, natAI, 443, 51000, fACK, 10)
		switch i % 3 {
		case 0:
			f.m.DetachAI()
		case 1:
			boom := errors.New("x")
			a.readErr <- boom
		}
		time.Sleep(2 * time.Millisecond)
	}
	close(stop)
	wg.Wait()
}

func TestBuildICMPUnreachable(t *testing.T) {
	if buildICMPv4Unreachable(nil, 1) != nil || buildICMPv4Unreachable([]byte{0x45}, 1) != nil {
		t.Fatal("broken input must give nil")
	}
	icmpIn := buildIPv4(natRemote, natTun, 1, nil, []byte{8, 0, 0, 0, 0, 1, 0, 1}, 0)
	if buildICMPv4Unreachable(icmpIn, 1) != nil {
		t.Fatal("never answer ICMP with ICMP")
	}
	// 载荷短于 8 字节：只引用已有部分。
	short := buildIPv4(natTun, aiHost, 6, nil, []byte{1, 2, 3}, 0)
	p := buildICMPv4Unreachable(short, 1)
	if p == nil || len(p) != 20+8+len(short) || onesComplementSum(p[20:]) != 0 || !refIPHeaderValid(p) {
		t.Fatalf("short packet quote wrong: len=%d", len(p))
	}
}

// 普通 TCP（非 AI 地址）在 R 可用时走 R，源地址改写正确；UDP 仍走 default。
func TestMuxReliableOrdinaryTCPUsesR(t *testing.T) {
	f := newMuxFixture(t)
	f.cls.reliableTCP.Store(true)
	a := f.attachAI(t)
	syn := tcpWithFlags(natTun, otherHost, 51000, 443, fSYN, 0)
	if r, err := f.m.WritePacket(syn); err != nil || r != nil {
		t.Fatalf("reply=%v err=%v", r, err)
	}
	got := a.recv(t)
	if netip.AddrFrom4([4]byte(got[12:16])) != natAI || netip.AddrFrom4([4]byte(got[16:20])) != otherHost {
		t.Fatalf("addresses %v -> %v", got[12:16], got[16:20])
	}
	if !refIPHeaderValid(got) || !refL4Valid(t, got) {
		t.Fatal("rewritten packet has invalid checksums")
	}
	f.d.expectNothing(t)
	f.m.WritePacket(tcpWithFlags(natTun, otherHost, 51000, 443, fACK, 900))
	if got := a.recv(t); !refL4Valid(t, got) {
		t.Fatal("data packet invalid")
	}
	// UDP（即使目的地址相同）与 ICMP 仍走 default，不被改写。
	udp := udpPacket(natTun, otherHost)
	if _, err := f.m.WritePacket(udp); err != nil {
		t.Fatal(err)
	}
	if string(f.d.recv(t)) != string(udp) {
		t.Fatal("UDP packet was modified")
	}
	a.expectNothing(t)
}

// R 不可用：普通 TCP 新连接留在 default（不丢弃、不回 ICMP）；AI 新连接仍然 fail-closed。
func TestMuxReliableFallsBackToDefaultWhenRDown(t *testing.T) {
	f := newMuxFixture(t)
	f.cls.reliableTCP.Store(true)
	syn := tcpWithFlags(natTun, otherHost, 51010, 443, fSYN, 0)
	orig := append([]byte(nil), syn...)
	if r, err := f.m.WritePacket(syn); err != nil || r != nil {
		t.Fatalf("reply=%v err=%v", r, err)
	}
	if got := f.d.recv(t); string(got) != string(orig) {
		t.Fatal("the SYN must reach default untouched")
	}
	// 同一条流的后续包继续走 default；R 随后恢复也不迁移这条流。
	a := f.attachAI(t)
	ack := tcpWithFlags(natTun, otherHost, 51010, 443, fACK, 300)
	if _, err := f.m.WritePacket(ack); err != nil {
		t.Fatal(err)
	}
	f.d.recv(t)
	a.expectNothing(t)
	// 新连接此时走 R。
	f.m.WritePacket(tcpWithFlags(natTun, otherHost, 51011, 443, fSYN, 0))
	a.recv(t)
	// AI 地址在 R 断开时仍 fail-closed（ICMP 不可达，不改走 default）。
	f.m.DetachAI()
	icmp, err := f.m.WritePacket(tcpWithFlags(natTun, aiHost, 51012, 443, fSYN, 0))
	if err != nil || icmp == nil || icmp[9] != 1 {
		t.Fatalf("AI SYN with R down: %v %v", icmp, err)
	}
	f.d.expectNothing(t)
	if got := f.m.stats.reliableFallbackD.Load(); got != 1 {
		t.Fatalf("reliableFallbackD = %d", got)
	}
}

// 已固定在 R 上的普通 TCP 流，R 丢失后收到 RST（立即失败，不静默挂起），数据不会改走 default。
func TestMuxReliableFlowGetsResetWhenRLost(t *testing.T) {
	f := newMuxFixture(t)
	f.cls.reliableTCP.Store(true)
	a := f.attachAI(t)
	f.m.WritePacket(tcpWithFlags(natTun, otherHost, 51020, 443, fSYN, 0))
	a.recv(t)
	f.m.DetachAI()
	data := tcpWithFlags(natTun, otherHost, 51020, 443, fACK, 500)
	binary.BigEndian.PutUint32(data[20+4:20+8], 1000) // seq
	binary.BigEndian.PutUint32(data[20+8:20+12], 777) // ack
	rst, err := f.m.WritePacket(data)
	if err != nil || rst == nil {
		t.Fatalf("expected a RST, got %v %v", rst, err)
	}
	f.d.expectNothing(t)
	if netip.AddrFrom4([4]byte(rst[12:16])) != otherHost || netip.AddrFrom4([4]byte(rst[16:20])) != natTun {
		t.Fatalf("RST addresses %v -> %v", rst[12:16], rst[16:20])
	}
	if !refIPHeaderValid(rst) || !refL4Valid(t, rst) {
		t.Fatal("RST has invalid checksums")
	}
	if rst[20+13] != 0x04 || binary.BigEndian.Uint32(rst[20+4:20+8]) != 777 {
		t.Fatalf("RST flags/seq: %#x %d (want RST, seq = the packet's ack number)", rst[20+13], binary.BigEndian.Uint32(rst[20+4:20+8]))
	}
	if binary.BigEndian.Uint16(rst[20:22]) != 443 || binary.BigEndian.Uint16(rst[22:24]) != 51020 {
		t.Fatal("RST ports are not swapped")
	}
	if f.m.stats.reliableReset.Load() != 1 {
		t.Fatalf("reliableReset = %d", f.m.stats.reliableReset.Load())
	}
}

func TestBuildTCPReset(t *testing.T) {
	// 没有 ACK 的包（如 SYN）：RST|ACK，序号 0，确认号 = 对方序号 + 1。
	syn := tcpWithFlags(natTun, otherHost, 52000, 443, fSYN, 0)
	binary.BigEndian.PutUint32(syn[20+4:20+8], 4000)
	r := buildTCPReset(syn)
	if r == nil || !refIPHeaderValid(r) || !refL4Valid(t, r) {
		t.Fatalf("bad RST: % x", r)
	}
	if r[20+13] != 0x14 || binary.BigEndian.Uint32(r[20+4:20+8]) != 0 || binary.BigEndian.Uint32(r[20+8:20+12]) != 4001 {
		t.Fatalf("RST|ACK fields wrong: flags %#x seq %d ack %d", r[20+13], binary.BigEndian.Uint32(r[20+4:20+8]), binary.BigEndian.Uint32(r[20+8:20+12]))
	}
	// 带载荷、没有 ACK 位的包：确认号 = 序号 + 载荷长度。
	d := tcpWithFlags(natTun, otherHost, 52001, 443, 0, 40)
	binary.BigEndian.PutUint32(d[20+4:20+8], 10)
	if r := buildTCPReset(d); r == nil || binary.BigEndian.Uint32(r[20+8:20+12]) != 50 {
		t.Fatalf("ack number for a data packet: % x", r)
	}
	// 不对 RST 回 RST；非 TCP、截断的包返回 nil。
	if buildTCPReset(tcpWithFlags(natTun, otherHost, 52002, 443, fRST, 0)) != nil {
		t.Fatal("must not answer a RST with a RST")
	}
	if buildTCPReset(udpPacket(natTun, otherHost)) != nil || buildTCPReset(syn[:25]) != nil || buildTCPReset(nil) != nil {
		t.Fatal("non-TCP or truncated input must give nil")
	}
}

// R 重拨换了新地址：固定在旧链路上的流收到 RST，不会改用新源地址续传；新连接正常走新链路。
func TestMuxReliableFlowResetAfterRReplaced(t *testing.T) {
	f := newMuxFixture(t)
	f.cls.reliableTCP.Store(true)
	a1 := f.attachAI(t)
	f.m.WritePacket(tcpWithFlags(natTun, otherHost, 53000, 443, fSYN, 0))
	a1.recv(t)
	// 链路被替换（新地址）。
	a2 := newFakeConn()
	newAddr := netip.MustParseAddr("10.88.128.9")
	if err := f.m.AttachAI(a2, newAddr); err != nil {
		t.Fatal(err)
	}
	rst, err := f.m.WritePacket(tcpWithFlags(natTun, otherHost, 53000, 443, fACK, 200))
	if err != nil || rst == nil || rst[20+13]&0x04 == 0 {
		t.Fatalf("expected RST for the stale flow, got %v %v", rst, err)
	}
	a1.expectNothing(t)
	a2.expectNothing(t) // 旧流的包不得用新地址发出
	f.d.expectNothing(t)
	// 新连接走新链路，源地址是新地址。
	f.m.WritePacket(tcpWithFlags(natTun, otherHost, 53001, 443, fSYN, 0))
	got := a2.recv(t)
	if netip.AddrFrom4([4]byte(got[12:16])) != newAddr {
		t.Fatalf("new flow source %v", got[12:16])
	}
	// AI 地址的旧流同样如此。
	if f.m.stats.reliableReset.Load() != 1 {
		t.Fatalf("reliableReset = %d", f.m.stats.reliableReset.Load())
	}
}

// 用户关闭“AI 稳定通道”（先关分类、再断开 R）：已固定在 R 上的流立即收到 RST；新连接走 default；
// 重新打开后，关闭期间在同一四元组上重新建立的 default 流不会被旧表项当成 R 流。
func TestMuxReliableFlowsResetWhenChannelDisabled(t *testing.T) {
	f := newMuxFixture(t)
	f.cls.reliableTCP.Store(true)
	a := f.attachAI(t)
	f.m.WritePacket(tcpWithFlags(natTun, otherHost, 53010, 443, fSYN, 0))
	a.recv(t)
	f.cls.enabled.Store(false)
	f.m.DetachAI()
	rst, err := f.m.WritePacket(tcpWithFlags(natTun, otherHost, 53010, 443, fACK, 300))
	if err != nil || rst == nil || rst[20+13]&0x04 == 0 {
		t.Fatalf("expected RST, got %v %v", rst, err)
	}
	f.d.expectNothing(t)
	// 同一四元组的新连接（SYN）走 default，并清掉旧 R 表项。
	syn := tcpWithFlags(natTun, otherHost, 53010, 443, fSYN, 0)
	if _, err := f.m.WritePacket(syn); err != nil {
		t.Fatal(err)
	}
	f.d.recv(t)
	f.cls.enabled.Store(true)
	a2 := f.attachAI(t)
	if _, err := f.m.WritePacket(tcpWithFlags(natTun, otherHost, 53010, 443, fACK, 100)); err != nil {
		t.Fatal(err)
	}
	f.d.recv(t)         // 这条流在关闭期间已经是 default 流，继续走 default
	a2.expectNothing(t) // 不会因旧表项被改写成 R 地址
}

// WritePacket 与 AttachAI/DetachAI 并发（-race）：不 panic、不死锁，包要么进 R、要么进 default、要么得到 RST/ICMP。
func TestMuxReliableConcurrentWritesAndLinkChanges(t *testing.T) {
	f := newMuxFixture(t)
	f.cls.reliableTCP.Store(true)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	// 排空 default 与 R 的输出，避免 fake 通道写满。
	drain := func(c *fakeConn) {
		defer wg.Done()
		for {
			select {
			case <-c.out:
			case <-stop:
				return
			}
		}
	}
	wg.Add(1)
	go drain(f.d)
	var links []*fakeConn
	var lmu sync.Mutex
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 60; i++ {
			c := newFakeConn()
			lmu.Lock()
			links = append(links, c)
			lmu.Unlock()
			wg.Add(1)
			go drain(c)
			_ = f.m.AttachAI(c, netip.MustParseAddr("10.88.128.7"))
			time.Sleep(time.Millisecond)
			if i%3 == 0 {
				f.m.DetachAI()
			}
		}
	}()
	var writers sync.WaitGroup
	for g := 0; g < 4; g++ {
		writers.Add(1)
		go func(g int) {
			defer writers.Done()
			for i := 0; i < 400; i++ {
				port := uint16(54000 + g*1000 + i%50)
				flags := byte(fACK)
				if i%50 == 0 {
					flags = fSYN
				}
				if _, err := f.m.WritePacket(tcpWithFlags(natTun, otherHost, port, 443, flags, 100)); err != nil {
					t.Errorf("WritePacket: %v", err)
					return
				}
			}
		}(g)
	}
	writers.Wait()
	close(stop)
	wg.Wait()
}

// 带 IP 选项（ihl>20）、TCP 选项（数据偏移>5）、FIN 不带 ACK、总长度恰好等于 ihl+20 的包，RST 的字段与校验和都正确。
func TestBuildTCPResetVariants(t *testing.T) {
	base := tcpWithFlags(natTun, otherHost, 55000, 443, 0x01 /*FIN*/, 0)
	binary.BigEndian.PutUint32(base[20+4:20+8], 500)
	r := buildTCPReset(base)
	if r == nil || !refL4Valid(t, r) || r[20+13] != 0x14 || binary.BigEndian.Uint32(r[20+8:20+12]) != 501 {
		t.Fatalf("FIN without ACK: % x", r)
	}
	// TCP 选项：数据偏移 8（32 字节头）+ 10 字节载荷，确认号 = seq + 10。
	seg := make([]byte, 32+10)
	binary.BigEndian.PutUint16(seg[0:2], 55001)
	binary.BigEndian.PutUint16(seg[2:4], 443)
	binary.BigEndian.PutUint32(seg[4:8], 1000)
	seg[12], seg[13] = 0x80, fACK|0x08
	opt := withL4Checksum(buildIPv4(natTun, otherHost, 6, nil, seg, 0), 16)
	ro := buildTCPReset(opt)
	if ro == nil || !refL4Valid(t, ro) || ro[20+13] != 0x04 {
		t.Fatalf("TCP options: % x", ro)
	}
	// 没有 ACK 位 + TCP 选项：确认号只算载荷（不把选项当载荷）。
	seg[13] = 0x08
	opt2 := withL4Checksum(buildIPv4(natTun, otherHost, 6, nil, seg, 0), 16)
	if r2 := buildTCPReset(opt2); r2 == nil || binary.BigEndian.Uint32(r2[20+8:20+12]) != 1010 {
		t.Fatalf("ack number with TCP options: % x", r2)
	}
	// IP 选项：ihl=24。
	ipopt := buildIPv4(natTun, otherHost, 6, []byte{1, 1, 1, 0}, seg[:20], 0)
	if rr := buildTCPReset(withL4Checksum(ipopt, 16)); rr == nil || !refL4Valid(t, rr) || rr[20+13]&0x04 == 0 || rr[0] != 0x45 {
		t.Fatalf("IP options (ihl=24): bad RST % x", rr)
	}
	// 总长度 = ihl+20 = 40，包长恰好 40：刚好够。总长度 < ihl+20 或包截断：nil。
	exact := tcpWithFlags(natTun, otherHost, 55002, 443, fACK, 0)
	if buildTCPReset(exact) == nil {
		t.Fatal("a header-only TCP packet must get a RST")
	}
	short := append([]byte(nil), exact[:30]...)
	binary.BigEndian.PutUint16(short[2:4], 30) // total=len=30 < ihl+20
	if buildTCPReset(short) != nil {
		t.Fatal("a TCP header cut short must give nil")
	}
}
