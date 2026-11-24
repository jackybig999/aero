// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

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

type aiHarness struct {
	eng     *Engine
	dev     *mockTunDevWithCapture
	mu      sync.Mutex
	dConns  []*fakeConn
	aiConns []*fakeConn
	aiDials atomic.Int32
	aiErr   atomic.Pointer[error] // 非空时 dialAIFn 返回该错误
	aiAddr  netip.Addr
	// aiHook 非空时替代默认的 ai 拨号行为。后台重拨协程在并发读 dialAIFn：测试不能改写这个全局变量，只能换钩子。
	aiHook atomic.Pointer[func(context.Context) (IPPacketConn, netip.Addr, error)]
	// dSess[i] 是第 i 次 default 拨号所在的 Session；aiSess 按顺序记录每次 ai 拨号收到的 Session。
	dSess  []*Session
	aiSess []*Session
}

func (h *aiHarness) lastAI() *fakeConn {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.aiConns) == 0 {
		return nil
	}
	return h.aiConns[len(h.aiConns)-1]
}

func (h *aiHarness) lastD() *fakeConn {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.dConns[len(h.dConns)-1]
}

func (h *aiHarness) setAIErr(err error) {
	if err == nil {
		h.aiErr.Store(nil)
		return
	}
	h.aiErr.Store(&err)
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for: %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (h *aiHarness) waitState(t *testing.T, want string) {
	t.Helper()
	waitUntil(t, "AI channel state "+want, func() bool { s, _ := h.eng.AIChannel(); return s == want })
}

// startAIHarness 用假会话驱动真实的 Engine.Start。transports 是节点在订阅里声明的传输方式。
func startAIHarness(t *testing.T, transports []string, enabled bool) *aiHarness {
	t.Helper()
	return startAIHarnessErr(t, transports, enabled, nil)
}

// startAIHarnessErr 让 ai 会话的拨号在启动时就返回 aiErr（nil 表示成功）。
func startAIHarnessErr(t *testing.T, transports []string, enabled bool, aiErr error) *aiHarness {
	t.Helper()
	h := &aiHarness{aiAddr: natAI, dev: newMockTunDevWithCapture()}
	h.setAIErr(aiErr)
	eng := NewEngine()
	eng.SetMode("tun")
	eng.ai.enabled.Store(enabled)
	if err := eng.Apply(&Applied{
		Servers: []ServerConfig{{Name: "N1", Address: "198.51.100.1:443", Token: "tok", SNI: "n1.example.com", Transports: transports}},
		Tokens:  map[string]string{"198.51.100.1:443": "tok"},
		SNIs:    map[string]string{"198.51.100.1:443": "n1.example.com"},
	}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	useFakeTunHost(t, h.dev)
	origDial, origAI, origMin, origMax, origBack := dialIPFn, dialAIFn, aiRedialMin, aiRedialMax, reconnectMinBackoff
	t.Cleanup(func() {
		dialIPFn, dialAIFn, aiRedialMin, aiRedialMax, reconnectMinBackoff = origDial, origAI, origMin, origMax, origBack
		SetQUICDialHook(nil)
	})
	aiRedialMin, aiRedialMax, reconnectMinBackoff = 10*time.Millisecond, 40*time.Millisecond, 10*time.Millisecond
	SetQUICDialHook(func(context.Context, net.PacketConn, net.Addr, *tls.Config, *quic.Config) (*quic.Conn, error) {
		return nil, nil
	})
	dialIPFn = func(ctx context.Context, m *SessionManager) (IPPacketConn, string, error) {
		c := newFakeConn()
		h.mu.Lock()
		h.dConns = append(h.dConns, c)
		// 与真实的 SessionManager.DialIP 一致：每次 default 拨号都登记承载它的 Session。
		sess := &Session{addr: "198.51.100.1:443"}
		h.dSess = append(h.dSess, sess)
		h.mu.Unlock()
		m.mu.Lock()
		m.ipSession = sess
		m.mu.Unlock()
		return c, "10.88.0.2/32", nil
	}
	dialAIFn = func(ctx context.Context, sess *Session) (IPPacketConn, netip.Addr, error) {
		h.aiDials.Add(1)
		h.mu.Lock()
		h.aiSess = append(h.aiSess, sess)
		h.mu.Unlock()
		if hk := h.aiHook.Load(); hk != nil {
			return (*hk)(ctx)
		}
		if e := h.aiErr.Load(); e != nil {
			return nil, netip.Addr{}, *e
		}
		c := newFakeConn()
		h.mu.Lock()
		h.aiConns = append(h.aiConns, c)
		h.mu.Unlock()
		return c, h.aiAddr, nil
	}
	if err := eng.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	h.eng = eng
	t.Cleanup(func() { _ = eng.Stop() })
	return h
}

var bothTransports = []string{"datagram", "capsule"}

func TestAIChannelUpWhenNodeSupportsCapsule(t *testing.T) {
	h := startAIHarness(t, bothTransports, true)
	h.waitState(t, AIChannelUp)
	if _, ok := h.eng.stackEngine.currentConn().(*ipMux); !ok {
		t.Fatalf("data pump uses %T, want the multiplexer", h.eng.stackEngine.currentConn())
	}
	st := h.eng.GetState()
	if st.AIChannel != AIChannelUp || !st.AIChannelEnabled || st.AIChannelReason != "" {
		t.Fatalf("state: %+v", st)
	}

	// 完整数据路径：AI 域名解析后，从 TUN 注入对该地址的新连接，只会出现在 ai 会话上，源地址已改写；
	// UDP 走 default。
	h.eng.aiCls.ai.Add(aiHost, time.Hour)
	h.dev.readCh <- tcpWithFlags(natTunAddrForHarness, aiHost, 50100, 443, fSYN, 0)
	got := h.lastAI().recv(t)
	if netip.AddrFrom4([4]byte(got[12:16])) != natAI || !refL4Valid(t, got) || !refIPHeaderValid(got) {
		t.Fatalf("ai session got a bad packet: src=%v", got[12:16])
	}
	h.dev.readCh <- udpPacket(natTunAddrForHarness, aiHost)
	if u := h.lastD().recv(t); u[9] != 17 {
		t.Fatalf("default session got proto %d", u[9])
	}
	// 下行：ai 会话的包回到 TUN，目的地址改回 TUN 地址。
	h.lastAI().in <- tcpWithFlags(aiHost, natAI, 443, 50100, fSYN|fACK, 0)
	select {
	case p := <-h.dev.writeCh:
		if netip.AddrFrom4([4]byte(p[16:20])) != natTunAddrForHarness || !refL4Valid(t, p) {
			t.Fatalf("TUN received dst=%v", p[16:20])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no packet written to the TUN")
	}
}

var natTunAddrForHarness = netip.MustParseAddr("10.88.0.2")

func TestAIChannelUnsupportedNodeKeepsPlainPath(t *testing.T) {
	for _, tr := range [][]string{nil, {"datagram"}} {
		h := startAIHarness(t, tr, true)
		h.waitState(t, AIChannelUnsupported)
		if _, ok := h.eng.stackEngine.currentConn().(*ipMux); ok {
			t.Fatalf("transports %v: multiplexer created for a node without capsule", tr)
		}
		if h.aiDials.Load() != 0 {
			t.Fatalf("transports %v: ai session dialed on a node without capsule", tr)
		}
		_ = h.eng.Stop()
	}
}

func TestAIChannelDisabledAndLiveToggle(t *testing.T) {
	h := startAIHarness(t, bothTransports, false)
	h.waitState(t, AIChannelOff)
	if h.aiDials.Load() != 0 {
		t.Fatal("ai session dialed while the channel is off")
	}
	// 关闭时 AI 地址的 TCP 走 default（不 fail-closed，这是用户的选择）。
	h.eng.aiCls.ai.Add(aiHost, time.Hour)
	h.dev.readCh <- tcpWithFlags(natTunAddrForHarness, aiHost, 50101, 443, fSYN, 0)
	if p := h.lastD().recv(t); netip.AddrFrom4([4]byte(p[12:16])) != natTunAddrForHarness {
		t.Fatal("source rewritten while the channel is off")
	}

	h.eng.SetAIChannel(true) // 运行中打开
	h.waitState(t, AIChannelUp)
	h.dev.readCh <- tcpWithFlags(natTunAddrForHarness, aiHost, 50102, 443, fSYN, 0)
	h.lastAI().recv(t)

	ai := h.lastAI()
	h.eng.SetAIChannel(false) // 运行中关闭：断开 ai 会话，回到 default
	h.waitState(t, AIChannelOff)
	waitUntil(t, "ai session closed", func() bool { return ai.closeCalls.Load() > 0 })
	h.dev.readCh <- tcpWithFlags(natTunAddrForHarness, aiHost, 50103, 443, fSYN, 0)
	h.lastD().recv(t)
	if st := h.eng.GetState(); st.AIChannelEnabled {
		t.Fatal("state still reports the channel as enabled")
	}
}

// 类别被拒绝：状态 unavailable，原因码明确，不重试；该类别的新连接得到 ICMP 不可达，不会走 default。
func TestAIChannelClassRejectedIsPermanentAndFailClosed(t *testing.T) {
	h := startAIHarnessErr(t, bothTransports, true,
		&EdgeRejectError{Op: "connect-ip", Status: 403, Code: "class_not_allowed", Details: "EDGE_CLASS_NOT_ALLOWED"})
	h.waitState(t, AIChannelUnavailable)
	if _, reason := h.eng.AIChannel(); reason != "EDGE_CLASS_NOT_ALLOWED" {
		t.Fatalf("reason = %q", reason)
	}
	before := h.aiDials.Load()
	time.Sleep(150 * time.Millisecond) // 重拨间隔只有 10ms：永久性错误不能被重试
	if h.aiDials.Load() != before {
		t.Fatalf("a rejected class was retried (%d -> %d)", before, h.aiDials.Load())
	}
	h.eng.aiCls.ai.Add(aiHost, time.Hour)
	h.dev.readCh <- tcpWithFlags(natTunAddrForHarness, aiHost, 50104, 443, fSYN, 0)
	select {
	case p := <-h.dev.writeCh: // ICMP 不可达写回 TUN
		if p[9] != 1 || p[20] != 3 {
			t.Fatalf("TUN got proto %d type %d, want ICMP unreachable", p[9], p[20])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no ICMP unreachable for a new AI connection")
	}
	h.lastD().expectNothing(t)
}

// 暂时性错误（节点连接数满）：退避重试直到成功。
func TestAIChannelTransientFailureRetries(t *testing.T) {
	h := startAIHarnessErr(t, bothTransports, true,
		&EdgeRejectError{Op: "connect-ip", Status: 503, Code: "connection_limit_exceeded"})
	h.waitState(t, AIChannelUnavailable)
	waitUntil(t, "retries", func() bool { return h.aiDials.Load() >= 4 })
	h.setAIErr(nil)
	h.waitState(t, AIChannelUp)
}

// ai 会话中途失败：只降级并重拨；default 与泵不受影响。
func TestAIChannelLinkLossRedialsWithoutTouchingDefault(t *testing.T) {
	h := startAIHarness(t, bothTransports, true)
	h.waitState(t, AIChannelUp)
	d := h.lastD()
	first := h.lastAI()
	first.readErr <- context.DeadlineExceeded // ai 会话读失败
	waitUntil(t, "second ai session", func() bool { return h.lastAI() != first })
	h.waitState(t, AIChannelUp)
	if d.closeCalls.Load() != 0 {
		t.Fatal("default session was closed because of an ai failure")
	}
	h.eng.aiCls.ai.Add(aiHost, time.Hour)
	h.dev.readCh <- tcpWithFlags(natTunAddrForHarness, aiHost, 50105, 443, fSYN, 0)
	h.lastAI().recv(t)
	h.mu.Lock()
	n := len(h.dConns)
	h.mu.Unlock()
	if n != 1 {
		t.Fatalf("the tunnel was re-dialed %d times because of an ai failure", n)
	}
}

// default 会话断线重连：新隧道同样带 ai 会话，旧复用层连同 ai 会话一起关闭；AI 地址登记跨重连保留。
func TestAIChannelSurvivesTunnelReconnect(t *testing.T) {
	h := startAIHarness(t, bothTransports, true)
	h.waitState(t, AIChannelUp)
	h.eng.aiCls.ai.Add(aiHost, time.Hour)
	oldD, oldAI := h.lastD(), h.lastAI()
	oldD.readErr <- net.ErrClosed // default 会话断开
	waitUntil(t, "new default session", func() bool { return h.lastD() != oldD })
	waitUntil(t, "new ai session", func() bool { return h.lastAI() != oldAI })
	h.waitState(t, AIChannelUp)
	waitUntil(t, "old ai session closed", func() bool { return oldAI.closeCalls.Load() > 0 })
	if !h.eng.aiCls.ai.Contains(aiHost) {
		t.Fatal("learned AI addresses were lost on reconnect")
	}
	// 旧数据泵里还卡在 dev.Read 的协程会吃掉重连后的第一个包（已有行为，TCP 会重传）：像 TCP 一样重试。
	ai := h.lastAI()
	waitUntil(t, "a retransmitted SYN to reach the new ai session", func() bool {
		select {
		case h.dev.readCh <- tcpWithFlags(natTunAddrForHarness, aiHost, 50106, 443, fSYN, 0):
		default:
		}
		select {
		case p := <-ai.out:
			return netip.AddrFrom4([4]byte(p[12:16])) == natAI
		case <-time.After(50 * time.Millisecond):
			return false
		}
	})
}

func TestAIChannelStopResetsState(t *testing.T) {
	h := startAIHarness(t, bothTransports, true)
	h.waitState(t, AIChannelUp)
	ai := h.lastAI()
	if err := h.eng.Stop(); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "ai session closed on stop", func() bool { return ai.closeCalls.Load() > 0 })
	if s, r := h.eng.AIChannel(); s != "" || r != "" {
		t.Fatalf("state after Stop: %q %q", s, r)
	}
	if !h.eng.AIChannelEnabled() {
		t.Fatal("Stop must keep the user's switch")
	}
}

// DNS 处理器登记的 AI 地址进入引擎的分类器（端到端接线）。
func TestEngineDNSFeedsAIClassifier(t *testing.T) {
	eng := NewEngine()
	eng.dnsHandler.SetDoHResolver(func(ctx context.Context, req []byte) ([]byte, error) {
		qname, _ := extractDNSQuestionAndType(req)
		return buildAResponse(req, qname, net.ParseIP("104.18.7.192").To4()), nil
	})
	if eng.aiCls.ai.Contains(aiHost) {
		t.Fatal("setup")
	}
	eng.dnsHandler.HandleQuery(buildDNSQuery("api.openai.com", dnsTypeA), net.ParseIP("10.88.0.2"), 5000)
	if !eng.aiCls.ai.Contains(aiHost) {
		t.Fatal("AI answer did not reach the engine classifier")
	}
}

// ---- 审核发现的竞态与时序 ----

// 重拨成功后新链路立刻失败：不能丢掉这次失败（单飞窗口），最终必须有一条存活的链路且状态一致。
func TestAIChannelRedialDoesNotLoseAFailureRightAfterAttach(t *testing.T) {
	h := startAIHarnessErr(t, bothTransports, true, &EdgeRejectError{Op: "connect-ip", Status: 503, Code: "connection_limit_exceeded"})
	h.waitState(t, AIChannelUnavailable)
	// 之后的前 8 条 ai 会话一建立就读失败，随后才稳定：每次失败都必须触发新的重拨。
	var made, inflight, maxInflight atomic.Int32
	hook := func(ctx context.Context) (IPPacketConn, netip.Addr, error) {
		n := inflight.Add(1)
		defer inflight.Add(-1)
		for {
			cur := maxInflight.Load()
			if n <= cur || maxInflight.CompareAndSwap(cur, n) {
				break
			}
		}
		time.Sleep(3 * time.Millisecond) // 让并发的拨号有机会重叠
		c := newFakeConn()
		if made.Add(1) <= 8 {
			c.readErr <- net.ErrClosed
		}
		h.mu.Lock()
		h.aiConns = append(h.aiConns, c)
		h.mu.Unlock()
		return c, natAI, nil
	}
	h.aiHook.Store(&hook)
	h.waitState(t, AIChannelUp)
	waitUntil(t, "a stable ai link", func() bool {
		h.eng.ai.mu.Lock()
		m := h.eng.ai.mux
		h.eng.ai.mu.Unlock()
		s, _ := h.eng.AIChannel()
		return m != nil && m.AIAvailable() && s == AIChannelUp && made.Load() > 8
	})
	if got := maxInflight.Load(); got != 1 {
		t.Fatalf("up to %d concurrent ai dials for one multiplexer, want exactly 1 at a time", got)
	}
	// 稳定之后状态与链路保持一致，不会漂移。
	time.Sleep(100 * time.Millisecond)
	h.eng.ai.mu.Lock()
	m := h.eng.ai.mux
	h.eng.ai.mu.Unlock()
	if s, _ := h.eng.AIChannel(); s != AIChannelUp || !m.AIAvailable() {
		t.Fatalf("inconsistent: state=%s available=%v", s, m.AIAvailable())
	}
}

// Stop 之后，仍在运行的重拨协程不能再改状态或重拨。
func TestAIChannelStopSilencesRedial(t *testing.T) {
	h := startAIHarnessErr(t, bothTransports, true, &EdgeRejectError{Op: "connect-ip", Status: 503, Code: "connection_limit_exceeded"})
	h.waitState(t, AIChannelUnavailable)
	if err := h.eng.Stop(); err != nil {
		t.Fatal(err)
	}
	dials := h.aiDials.Load()
	for i := 0; i < 20; i++ {
		if s, r := h.eng.AIChannel(); s != "" || r != "" {
			t.Fatalf("state written after Stop: %q %q", s, r)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := h.aiDials.Load(); got > dials+1 { // 正在进行的那一次可以完成，之后不得再拨
		t.Fatalf("ai redial kept running after Stop (%d -> %d)", dials, got)
	}
}

// 拨号期间用户关闭了通道：拨号完成后链路必须被断开，状态为 off。
func TestAIChannelDisabledDuringDialEndsDetached(t *testing.T) {
	gate := make(chan struct{})
	h := startAIHarnessErr(t, bothTransports, true, &EdgeRejectError{Op: "connect-ip", Status: 503, Code: "connection_limit_exceeded"})
	h.waitState(t, AIChannelUnavailable)
	entered := make(chan struct{})
	var once sync.Once
	hook := func(ctx context.Context) (IPPacketConn, netip.Addr, error) {
		once.Do(func() { close(entered) })
		<-gate // 卡在拨号中
		c := newFakeConn()
		h.mu.Lock()
		h.aiConns = append(h.aiConns, c)
		h.mu.Unlock()
		return c, natAI, nil
	}
	h.aiHook.Store(&hook)
	select {
	case <-entered: // 确认拨号已经开始，再关开关
	case <-time.After(5 * time.Second):
		t.Fatal("the redial never reached the dial function")
	}
	h.eng.SetAIChannel(false)
	close(gate)
	h.waitState(t, AIChannelOff)
	waitUntil(t, "no ai link", func() bool {
		h.eng.ai.mu.Lock()
		m := h.eng.ai.mux
		h.eng.ai.mu.Unlock()
		return m != nil && !m.AIAvailable()
	})
	time.Sleep(50 * time.Millisecond)
	if s, _ := h.eng.AIChannel(); s != AIChannelOff {
		t.Fatalf("state drifted to %s", s)
	}
}

// retire 只撤销当前复用层；旧复用层的撤销不能影响新隧道。
func TestAIChannelRetireOnlyAffectsCurrentMux(t *testing.T) {
	var a aiChannel
	oldM := &ipMux{}
	newM := &ipMux{}
	a.mux = oldM
	a.mux = newM // 新隧道发布了自己的复用层
	a.state = AIChannelUp
	a.retire(oldM) // 旧隧道的中止路径迟到
	if a.mux != newM || a.state != AIChannelUp {
		t.Fatal("retiring a stale mux disturbed the current one")
	}
	if a.setFor(oldM, AIChannelUnavailable, "X") || a.state != AIChannelUp {
		t.Fatal("a stale mux wrote the state")
	}
	a.retire(newM)
	if a.mux != nil || a.state != "" {
		t.Fatal("retire did not clear the current mux")
	}
}

func (a *aiChannel) redialingCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.redialing)
}

// ---- aiChannel 单元：令牌、发布、状态写入的前置条件 ----

func TestAIChannelRedialTokenDoesNotRemoveALaterRegistration(t *testing.T) {
	var a aiChannel
	m := &ipMux{}
	a.mux = m
	first := a.register(m)
	if first == nil || a.register(m) != nil {
		t.Fatal("a second goroutine was registered for the same mux")
	}
	a.release(m, first) // 第一个协程放开单飞
	second := a.register(m)
	if second == nil {
		t.Fatal("registration after release failed")
	}
	a.release(m, first) // 第一个协程的 defer 迟到：不能删掉第二个的登记
	if a.register(m) != nil {
		t.Fatal("a stale release removed a later registration: two goroutines could dial for one mux")
	}
	a.release(m, second)
	if a.register(m) == nil {
		t.Fatal("registration not released by its owner")
	}
	if (&aiChannel{}).register(m) != nil {
		t.Fatal("registered a mux that is not current")
	}
}

func TestAIChannelPublishRespectsCancellation(t *testing.T) {
	var a aiChannel
	mNew, mOld := &ipMux{}, &ipMux{}
	if !a.publish(context.Background(), mNew) || a.mux != mNew {
		t.Fatal("publish with a live context failed")
	}
	// 旧重连协程在 Stop、Start 之后才发布：它的 ctx 已取消，不能覆盖新隧道的复用层。
	dead, cancel := context.WithCancel(context.Background())
	cancel()
	if a.publish(dead, mOld) || a.mux != mNew {
		t.Fatal("a cancelled tunnel setup overwrote the current multiplexer")
	}
	if a.publish(dead, nil) || a.mux != mNew {
		t.Fatal("a cancelled tunnel setup cleared the current multiplexer")
	}
}

func TestAIChannelStateWritesNeedTheirPreconditions(t *testing.T) {
	var a aiChannel
	m := &ipMux{}
	a.mux = m
	// 用户已关闭：拨号失败记为 off，而不是 unavailable。
	a.setUnavailable(m, "EDGE_X", false)
	if a.state != AIChannelOff || a.reason != "" {
		t.Fatalf("disabled + failure: %q %q", a.state, a.reason)
	}
	a.setUnavailable(m, "EDGE_X", true)
	if a.state != AIChannelUnavailable || a.reason != "EDGE_X" {
		t.Fatalf("enabled + failure: %q %q", a.state, a.reason)
	}
	// 链路不存在时不写 up（接入后立刻失败的情形）。
	if a.setUp(m) || a.state != AIChannelUnavailable {
		t.Fatal("up was written without a live ai link")
	}
	if a.setUnavailable(&ipMux{}, "Y", true) {
		t.Fatal("a stale mux wrote the state")
	}
}

// ai 会话必须建在承载同一代 default 会话的 Session 上：重连后新复用层用新 Session，
// 旧复用层的重拨协程不会读到新连接的 Session。
func TestAIChannelDialsOnTheSessionCarryingDefault(t *testing.T) {
	h := startAIHarness(t, bothTransports, true)
	h.waitState(t, AIChannelUp)
	h.mu.Lock()
	if len(h.dSess) != 1 || len(h.aiSess) != 1 || h.aiSess[0] != h.dSess[0] {
		h.mu.Unlock()
		t.Fatalf("首次 ai 拨号应使用 default 所在的 Session: d=%d ai=%d", len(h.dSess), len(h.aiSess))
	}
	first := h.dSess[0]
	h.mu.Unlock()

	oldD, oldAI := h.lastD(), h.lastAI()
	oldD.readErr <- net.ErrClosed
	waitUntil(t, "new default session", func() bool { return h.lastD() != oldD })
	waitUntil(t, "new ai session", func() bool { return h.lastAI() != oldAI })
	h.waitState(t, AIChannelUp)

	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.dSess) < 2 {
		t.Fatalf("重连后应有第二个 default Session: %d", len(h.dSess))
	}
	last := h.dSess[len(h.dSess)-1]
	got := h.aiSess[len(h.aiSess)-1]
	if got != last || got == first {
		t.Fatalf("重连后的 ai 拨号应使用新的 default Session（got=%p last=%p first=%p）", got, last, first)
	}
}

// 重连窗口：管理器里的登记已被新 default 会话改成新 Session，旧复用层的重拨协程还在跑时，
// 它必须仍然用自己绑定的 Session（复用层创建时承载 default 会话的那个），不能读到新连接的 Session。
func TestAIChannelRedialUsesTheSessionBoundToItsMux(t *testing.T) {
	h := startAIHarness(t, bothTransports, true)
	h.waitState(t, AIChannelUp)
	h.mu.Lock()
	bound := h.dSess[0]
	h.mu.Unlock()

	other := &Session{addr: "203.0.113.9:443"}
	h.eng.sessionMgr.mu.Lock()
	h.eng.sessionMgr.ipSession = other // 模拟新的 default 会话刚登记
	h.eng.sessionMgr.mu.Unlock()

	first := h.lastAI()
	first.readErr <- context.DeadlineExceeded // 旧复用层的 ai 会话断开 → 重拨
	waitUntil(t, "second ai session", func() bool { return h.lastAI() != first })

	h.mu.Lock()
	defer h.mu.Unlock()
	for i, s := range h.aiSess {
		if s != bound {
			t.Fatalf("第 %d 次 ai 拨号用了别的 Session（应一直是复用层绑定的那个）", i)
		}
	}
}
