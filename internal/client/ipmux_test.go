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
