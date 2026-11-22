// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// newRunningEngineWithNodes 构造一个“已运行”的假引擎：订阅已应用，状态置为 running。
// 不建 TUN、不拨号，足以验证哨兵不会 Stop 引擎。
func newRunningEngineWithNodes(t *testing.T, addrs ...string) *Engine {
	t.Helper()
	eng := NewEngine()
	applied := newTestApplied(addrs...)
	if err := eng.Apply(applied); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	eng.state.Store(stateRunning)
	eng.running.Store(true)
	return eng
}

func newTestApplied(addrs ...string) *Applied {
	a := &Applied{
		Tokens: map[string]string{},
		SNIs:   map[string]string{},
	}
	for i, addr := range addrs {
		tok := "tok" + string(rune('1'+i))
		sni := "node" + string(rune('1'+i)) + ".example.com"
		a.Servers = append(a.Servers, ServerConfig{Name: "Node-" + string(rune('1'+i)), Address: addr, Token: tok, SNI: sni})
		a.Tokens[addr] = tok
		a.SNIs[addr] = sni
	}
	return a
}

// H1：单节点、探测连续失败 -> 引擎不被 Stop，错误可见；探测恢复后错误清除、failureCount 归零。
func TestSentinelNoStopWhenAllCandidatesFail(t *testing.T) {
	eng := newRunningEngineWithNodes(t, "192.0.2.1:443")
	sentinel := newNodeSentinel(eng)
	var healthy atomic.Bool
	sentinel.dialFn = func(ctx context.Context, cfg *TransportConfig) (*Client, error) {
		if healthy.Load() {
			return &Client{}, nil
		}
		return nil, errors.New("timeout")
	}
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if !sentinel.check(ctx) {
			t.Fatalf("check #%d returned false: sentinel must keep running", i+1)
		}
	}
	if !eng.IsRunning() || eng.state.Load() != stateRunning {
		t.Fatalf("engine must stay running, running=%v state=%d", eng.IsRunning(), eng.state.Load())
	}
	st := eng.GetState()
	if !st.Connected {
		t.Fatalf("state must stay connected")
	}
	if st.LastError == "" || st.ErrorCode != "CONNECT_ERROR" {
		t.Fatalf("error must be visible, got err=%q code=%q", st.LastError, st.ErrorCode)
	}
	sentinel.mu.Lock()
	idx, cnt := sentinel.backoffIdx, sentinel.failureCount
	sentinel.mu.Unlock()
	if idx == 0 || cnt < 3 {
		t.Fatalf("expected backoff engaged, backoffIdx=%d failureCount=%d", idx, cnt)
	}

	healthy.Store(true)
	if !sentinel.check(ctx) {
		t.Fatalf("check returned false after recovery")
	}
	st = eng.GetState()
	if st.LastError != "" || st.ErrorCode != "" {
		t.Fatalf("error must be cleared after recovery, got err=%q code=%q", st.LastError, st.ErrorCode)
	}
	sentinel.mu.Lock()
	idx, cnt = sentinel.backoffIdx, sentinel.failureCount
	sentinel.mu.Unlock()
	if idx != 0 || cnt != 0 {
		t.Fatalf("expected counters reset, backoffIdx=%d failureCount=%d", idx, cnt)
	}
}

// 哨兵只清除自己写入的错误：重连协程写入的 edge 拒绝错误不能被探测成功清掉。
func TestSentinelKeepsForeignError(t *testing.T) {
	eng := newRunningEngineWithNodes(t, "192.0.2.1:443")
	sentinel := newNodeSentinel(eng)
	sentinel.dialFn = func(ctx context.Context, cfg *TransportConfig) (*Client, error) {
		return &Client{}, nil
	}
	eng.setRejection(&EdgeRejectError{Status: 503, Code: "address_pool_exhausted"})
	sentinel.check(context.Background())
	if got := eng.GetState().ErrorCode; got != "EDGE_POOL_EXHAUSTED" {
		t.Fatalf("foreign error must be kept, got code %q", got)
	}
}

// 退避间隔按 backoffDurations 递增并封顶（只测间隔函数，不 sleep）。
func TestSentinelBackoffCapNextInterval(t *testing.T) {
	s := newNodeSentinel(NewEngine())
	base := 10 * time.Second
	want := []time.Duration{base, 30 * time.Second, 60 * time.Second, 120 * time.Second, 120 * time.Second, 120 * time.Second}
	for idx, w := range want {
		s.backoffIdx = idx
		if got := s.nextInterval(base); got != w {
			t.Fatalf("backoffIdx=%d: want %v, got %v", idx, w, got)
		}
	}
	// 注入的间隔表同样封顶
	s.backoffDurations = []time.Duration{time.Millisecond, 2 * time.Millisecond}
	s.backoffIdx = 9
	if got := s.nextInterval(base); got != 2*time.Millisecond {
		t.Fatalf("injected durations: want 2ms, got %v", got)
	}
}

// 失败级别随 failover 失败逐级升高，并在最后一档封顶。
func TestSentinelBackoffCapEscalation(t *testing.T) {
	eng := newRunningEngineWithNodes(t, "192.0.2.1:443")
	sentinel := newNodeSentinel(eng)
	sentinel.backoffDurations = []time.Duration{10 * time.Millisecond, 30 * time.Millisecond, 60 * time.Millisecond, 120 * time.Millisecond}
	sentinel.dialFn = func(ctx context.Context, cfg *TransportConfig) (*Client, error) {
		return nil, errors.New("down")
	}
	ctx := context.Background()
	var got []time.Duration
	for i := 0; i < 8; i++ {
		sentinel.check(ctx)
		if i >= 2 {
			got = append(got, sentinel.nextInterval(time.Hour))
		}
	}
	want := []time.Duration{30, 60, 120, 120, 120, 120}
	for i := range want {
		if got[i] != want[i]*time.Millisecond {
			t.Fatalf("interval[%d]: want %v, got %v (all=%v)", i, want[i]*time.Millisecond, got[i], got)
		}
	}
}

// run 循环：全部候选失败后继续运行并按退避重试，不停止引擎；恢复后清除错误。
func TestSentinelRunKeepsRetryingAndRecovers(t *testing.T) {
	eng := newRunningEngineWithNodes(t, "192.0.2.1:443")
	sentinel := newNodeSentinel(eng)
	sentinel.checkInterval = 2 * time.Millisecond
	sentinel.backoffDurations = []time.Duration{2 * time.Millisecond, 3 * time.Millisecond, 4 * time.Millisecond, 5 * time.Millisecond}
	var healthy atomic.Bool
	var dials atomic.Int32
	sentinel.dialFn = func(ctx context.Context, cfg *TransportConfig) (*Client, error) {
		dials.Add(1)
		if healthy.Load() {
			return &Client{}, nil
		}
		return nil, errors.New("down")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { sentinel.run(ctx); close(done) }()
	defer func() {
		cancel()
		<-done
	}()

	waitFor(t, "sentinel keeps retrying after failover failure", func() bool { return dials.Load() >= 12 })
	if !eng.IsRunning() || eng.GetState().LastError == "" {
		t.Fatalf("engine must keep running with visible error, running=%v err=%q", eng.IsRunning(), eng.GetState().LastError)
	}
	select {
	case <-done:
		t.Fatalf("sentinel run must not exit while candidates are down")
	default:
	}

	healthy.Store(true)
	waitFor(t, "error cleared after recovery", func() bool { return eng.GetState().LastError == "" })
	sentinel.mu.Lock()
	cnt := sentinel.failureCount
	sentinel.mu.Unlock()
	if cnt != 0 {
		t.Fatalf("failureCount must be 0 after recovery, got %d", cnt)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for: %s", what)
}

// M4：活动节点仍在新订阅中 -> 不切换，token 就地更新。
func TestApplyKeepsActiveNodeWhenStillSubscribed(t *testing.T) {
	eng := NewEngine()
	if err := eng.Apply(newTestApplied("192.0.2.1:443", "192.0.2.2:443", "192.0.2.3:443")); err != nil {
		t.Fatal(err)
	}
	if err := eng.SwitchActiveNode("192.0.2.2:443"); err != nil {
		t.Fatal(err)
	}

	next := newTestApplied("192.0.2.1:443", "192.0.2.2:443", "192.0.2.3:443")
	next.Servers[1].Token = "tok-refreshed"
	next.Tokens["192.0.2.2:443"] = "tok-refreshed"
	next.Servers[1].SNI = "node2-new.example.com"
	if err := eng.Apply(next); err != nil {
		t.Fatal(err)
	}

	eng.mu.RLock()
	addr, tok, sni := eng.activeAddr, eng.activeToken, eng.activeSNI
	eng.mu.RUnlock()
	if addr != "192.0.2.2:443" {
		t.Fatalf("active node must not switch, got %s", addr)
	}
	if tok != "tok-refreshed" || sni != "node2-new.example.com" {
		t.Fatalf("credentials not refreshed in place: tok=%q sni=%q", tok, sni)
	}
	if _, gtok, gsni, _ := getActiveEdge(); gtok != "tok-refreshed" || gsni != "node2-new.example.com" {
		t.Fatalf("active edge not refreshed: tok=%q sni=%q", gtok, gsni)
	}
}

// M4：活动节点被移出订阅 -> 切到第一个不在冷却中的节点。
func TestApplySwitchesToFirstNonCoolingWhenActiveRemoved(t *testing.T) {
	eng := NewEngine()
	if err := eng.Apply(newTestApplied("192.0.2.1:443", "192.0.2.9:443")); err != nil {
		t.Fatal(err)
	}
	eng.markNodeUnavailable("192.0.2.2:443")

	next := newTestApplied("192.0.2.2:443", "192.0.2.3:443", "192.0.2.4:443")
	if err := eng.Apply(next); err != nil {
		t.Fatal(err)
	}
	eng.mu.RLock()
	addr, tok := eng.activeAddr, eng.activeToken
	eng.mu.RUnlock()
	if addr != "192.0.2.3:443" || tok != "tok2" {
		t.Fatalf("expected first non-cooling node 192.0.2.3:443/tok2, got %s/%s", addr, tok)
	}

	// 全部冷却时退回订阅第一个节点
	eng2 := NewEngine()
	eng2.markNodeUnavailable("192.0.2.5:443")
	eng2.markNodeUnavailable("192.0.2.6:443")
	if err := eng2.Apply(newTestApplied("192.0.2.5:443", "192.0.2.6:443")); err != nil {
		t.Fatal(err)
	}
	eng2.mu.RLock()
	got := eng2.activeAddr
	eng2.mu.RUnlock()
	if got != "192.0.2.5:443" {
		t.Fatalf("all cooling: expected first server, got %s", got)
	}
}

// M9：解析期间 e.mu 不被持有（GetState 立即返回）；解析完成后正常提交。
func TestSwitchActiveNodeResolvesOutsideLock(t *testing.T) {
	eng := NewEngine()
	started := make(chan struct{})
	release := make(chan struct{})
	eng.resolveIPv4 = func(host string) (net.IP, error) {
		close(started)
		<-release
		return net.ParseIP("192.0.2.77").To4(), nil
	}

	applyErr := make(chan error, 1)
	go func() { applyErr <- eng.Apply(newTestApplied("node.example.com:443")) }()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("resolver not invoked")
	}
	stateDone := make(chan AppState, 1)
	go func() { stateDone <- eng.GetState() }()
	select {
	case <-stateDone:
	case <-time.After(2 * time.Second):
		t.Fatal("GetState blocked while resolving: e.mu is held across network resolve")
	}

	close(release)
	if err := <-applyErr; err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	eng.mu.RLock()
	addr := eng.activeAddr
	eng.mu.RUnlock()
	if addr != "node.example.com:443" {
		t.Fatalf("expected switch committed, got %s", addr)
	}
	if _, _, _, ip := getActiveEdge(); ip == nil || ip.String() != "192.0.2.77" {
		t.Fatalf("active edge IP not committed: %v", ip)
	}
}

// M9：解析期间状态被改动 -> 放弃本次结果。
func TestSwitchActiveNodeAbandonedWhenStateChanged(t *testing.T) {
	eng := NewEngine()
	if err := eng.Apply(newTestApplied("192.0.2.1:443", "node.example.com:443", "192.0.2.2:443")); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	eng.resolveIPv4 = func(host string) (net.IP, error) {
		close(started)
		<-release
		return net.ParseIP("192.0.2.77").To4(), nil
	}

	switchErr := make(chan error, 1)
	go func() { switchErr <- eng.SwitchActiveNode("node.example.com:443") }()
	<-started
	// 解析期间另一调用先完成切换
	if err := eng.SwitchActiveNode("192.0.2.2:443"); err != nil {
		t.Fatalf("concurrent switch: %v", err)
	}
	close(release)
	if err := <-switchErr; !errors.Is(err, errNodeSwitchSuperseded) {
		t.Fatalf("expected errNodeSwitchSuperseded, got %v", err)
	}
	eng.mu.RLock()
	addr := eng.activeAddr
	eng.mu.RUnlock()
	if addr != "192.0.2.2:443" {
		t.Fatalf("abandoned switch must not override newer state, got %s", addr)
	}
}
