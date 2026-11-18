package client

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/quic-go/quic-go"
)

// newCloseTestEngine 构造可用假网卡与假 CONNECT-IP 完整启动的 tun 模式引擎；
// 本地代理端口用临时端口，测试结束自动 Close。
func newCloseTestEngine(t *testing.T, hosts *fakeTunHosts) *Engine {
	t.Helper()
	eng := NewEngine()
	eng.SetMode("tun")
	eng.SetListenAddr("127.0.0.1:0")
	if err := eng.Apply(&Applied{
		Servers: []ServerConfig{{Name: "N1", Address: "198.51.100.1:443", Token: "tok", SNI: "n1.example.com"}},
		Tokens:  map[string]string{"198.51.100.1:443": "tok"},
		SNIs:    map[string]string{"198.51.100.1:443": "n1.example.com"},
	}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	t.Cleanup(func() { _ = eng.Close() })
	return eng
}

// stubCloseTestDial 以桩替换 QUIC 拨号与 CONNECT-IP 拨号，测试结束恢复。
func stubCloseTestDial(t *testing.T, dial func(ctx context.Context, m *SessionManager) (IPPacketConn, string, error)) {
	t.Helper()
	origDial := dialIPFn
	t.Cleanup(func() {
		dialIPFn = origDial
		SetQUICDialHook(nil)
	})
	SetQUICDialHook(func(context.Context, net.PacketConn, net.Addr, *tls.Config, *quic.Config) (*quic.Conn, error) {
		return nil, nil
	})
	dialIPFn = dial
}

func okCloseTestDial(context.Context, *SessionManager) (IPPacketConn, string, error) {
	return newMockIPPacketConn(), "10.88.0.2/32", nil
}

// assertNoDataPlane 断言引擎处于 stopped，且没有残留的网卡、数据面与会话。
func assertNoDataPlane(t *testing.T, eng *Engine, hosts *fakeTunHosts) {
	t.Helper()
	if got := eng.state.Load(); got != stateStopped {
		t.Errorf("state = %d, want stopped", got)
	}
	if eng.running.Load() {
		t.Error("running = true")
	}
	eng.mu.RLock()
	host := eng.tunHost
	eng.mu.RUnlock()
	if host != nil {
		t.Error("tunHost left behind")
	}
	if eng.stackEngine != nil {
		t.Error("stackEngine left behind")
	}
	if eng.sessionMgr != nil {
		eng.sessionMgr.mu.Lock()
		sess := eng.sessionMgr.currentSession
		eng.sessionMgr.mu.Unlock()
		if sess != nil {
			t.Error("session left behind")
		}
	}
	if hosts != nil {
		hosts.mu.Lock()
		defer hosts.mu.Unlock()
		for i, h := range hosts.hosts {
			if closed, _, _ := h.snapshot(); !closed {
				t.Errorf("fake TUN host %d not closed", i)
			}
		}
	}
}

func TestEngineCloseRejectsStart(t *testing.T) {
	hosts := useFakeTunHost(t, nil)
	stubCloseTestDial(t, okCloseTestDial)
	eng := newCloseTestEngine(t, hosts)

	preTicket := eng.RequestStart() // Close 之前签发、尚未使用的票据
	if preTicket == 0 {
		t.Fatal("RequestStart before Close returned 0")
	}
	if err := eng.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !eng.IsClosed() {
		t.Fatal("IsClosed = false after Close")
	}

	if err := eng.StartWith(preTicket); !errors.Is(err, ErrEngineClosed) {
		t.Fatalf("StartWith(pre-close ticket) = %v, want ErrEngineClosed", err)
	}
	if got := eng.RequestStart(); got != 0 {
		t.Fatalf("RequestStart after Close = %d, want 0", got)
	}
	if err := eng.StartWith(0); !errors.Is(err, ErrEngineClosed) {
		t.Fatalf("StartWith(0) after Close = %v, want ErrEngineClosed", err)
	}
	if err := eng.Start(); !errors.Is(err, ErrEngineClosed) {
		t.Fatalf("Start after Close = %v, want ErrEngineClosed", err)
	}
	if err := eng.Restart(preTicket); !errors.Is(err, ErrEngineClosed) {
		t.Fatalf("Restart after Close = %v, want ErrEngineClosed", err)
	}
	if err := eng.StartResidentMixedProxy("127.0.0.1:0"); !errors.Is(err, ErrEngineClosed) {
		t.Fatalf("StartResidentMixedProxy after Close = %v, want ErrEngineClosed", err)
	}
	if need, tk := eng.PrepareModeSwitch("sysproxy"); need || tk != 0 {
		t.Fatalf("PrepareModeSwitch after Close = %v, %d; want false, 0", need, tk)
	}
	if n := len(hosts.hosts); n != 0 {
		t.Fatalf("%d TUN hosts created after Close", n)
	}
	assertNoDataPlane(t, eng, hosts)

	// 幂等：重复 Close 安全
	for i := 0; i < 3; i++ {
		if err := eng.Close(); err != nil {
			t.Fatalf("repeated Close #%d: %v", i, err)
		}
	}
}

func TestEngineCloseStopsRunningAndIsIdempotent(t *testing.T) {
	hosts := useFakeTunHost(t, nil)
	stubCloseTestDial(t, okCloseTestDial)
	eng := newCloseTestEngine(t, hosts)

	if err := eng.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !eng.IsRunning() {
		t.Fatal("engine not running after Start")
	}
	if err := eng.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := eng.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	assertNoDataPlane(t, eng, hosts)
	if err := eng.Start(); !errors.Is(err, ErrEngineClosed) {
		t.Fatalf("Start after Close = %v, want ErrEngineClosed", err)
	}
}

func TestEngineCloseConcurrentWithStartWith(t *testing.T) {
	for i := 0; i < 30; i++ {
		hosts := useFakeTunHost(t, nil)
		stubCloseTestDial(t, okCloseTestDial)
		eng := newCloseTestEngine(t, hosts)
		ticket := eng.RequestStart()

		var wg sync.WaitGroup
		var startErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			startErr = eng.StartWith(ticket)
		}()
		go func() {
			defer wg.Done()
			_ = eng.Close()
		}()
		wg.Wait()

		if startErr != nil && !errors.Is(startErr, ErrEngineClosed) && !errors.Is(startErr, ErrStartAborted) {
			t.Fatalf("iter %d: StartWith = %v", i, startErr)
		}
		assertNoDataPlane(t, eng, hosts)
	}
}

// 在途启动期间 Close：Close 必须取消启动并等其退出，之后不留数据面。
func TestEngineCloseDuringStartInFlight(t *testing.T) {
	hosts := useFakeTunHost(t, nil)
	inDial := make(chan struct{})
	stubCloseTestDial(t, func(ctx context.Context, m *SessionManager) (IPPacketConn, string, error) {
		close(inDial)
		<-ctx.Done() // 等待启动被取消
		return nil, "", ctx.Err()
	})
	eng := newCloseTestEngine(t, hosts)
	ticket := eng.RequestStart()

	done := make(chan error, 1)
	go func() { done <- eng.StartWith(ticket) }()
	<-inDial
	if err := eng.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := <-done; err == nil {
		t.Fatal("in-flight StartWith succeeded despite Close")
	}
	assertNoDataPlane(t, eng, hosts)
}

// 回归：底层库返回的 context.Canceled 不是停止流程引起的，状态必须回到 stopped 并清 startPending，
// 不得停在 Starting。
func TestEngineStartForeignCanceledRollsBack(t *testing.T) {
	hosts := useFakeTunHost(t, nil)
	stubCloseTestDial(t, func(context.Context, *SessionManager) (IPPacketConn, string, error) {
		return nil, "", context.Canceled // 非 Stop/Restart/BeginStop 引起
	})
	eng := newCloseTestEngine(t, hosts)

	ticket := eng.RequestStart()
	err := eng.StartWith(ticket)
	if err == nil {
		t.Fatal("StartWith succeeded")
	}
	if errors.Is(err, ErrStartAborted) {
		t.Fatalf("foreign Canceled treated as stop-initiated abort: %v", err)
	}
	if eng.startPending.Load() {
		t.Error("startPending still true")
	}
	if st := eng.GetState(); st.Starting {
		t.Error("AppState.Starting still true")
	}
	assertNoDataPlane(t, eng, hosts)
	if eng.GetState().LastError == "" {
		t.Error("LastError empty after failed start")
	}

	// 回滚后可重新启动
	stubCloseTestDial(t, okCloseTestDial)
	if err := eng.Start(); err != nil {
		t.Fatalf("restart after rollback: %v", err)
	}
}

// 对照：由 Stop 流程取消的启动仍走 abort（状态交给停止流程收尾）。
func TestEngineStartCancelledByStopStillAborts(t *testing.T) {
	hosts := useFakeTunHost(t, nil)
	inDial := make(chan struct{})
	stubCloseTestDial(t, func(ctx context.Context, m *SessionManager) (IPPacketConn, string, error) {
		close(inDial)
		<-ctx.Done()
		return nil, "", ctx.Err()
	})
	eng := newCloseTestEngine(t, hosts)
	ticket := eng.RequestStart()

	done := make(chan error, 1)
	go func() { done <- eng.StartWith(ticket) }()
	<-inDial
	_ = eng.Stop()
	if err := <-done; !errors.Is(err, ErrStartAborted) {
		t.Fatalf("StartWith = %v, want ErrStartAborted", err)
	}
	assertNoDataPlane(t, eng, hosts)
}
