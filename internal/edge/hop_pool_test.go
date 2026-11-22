// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// startEchoTCP 起一个 TCP 回显服务，返回地址。
func startEchoTCP(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

// connectViaIngress 经入口发一次 TCP CONNECT；成功时回显一段数据并校验，返回 HTTP 状态。
func connectViaIngress(ingressAddr, target string) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	qc, err := quic.DialAddr(ctx, ingressAddr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}, DefaultQUICConfig())
	if err != nil {
		return 0, err
	}
	defer qc.CloseWithError(0, "done")
	h3c := (&http3.Transport{EnableDatagrams: true}).NewClientConn(qc)
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "//"+target, nil)
	if err != nil {
		return 0, err
	}
	req.Proto = "HTTP/1.1"
	req.Header.Set("Authorization", "Bearer client-user-token")
	st, err := h3c.OpenRequestStream(ctx)
	if err != nil {
		return 0, err
	}
	if err := st.SendRequestHeader(req); err != nil {
		return 0, err
	}
	resp, err := st.ReadResponse()
	if err != nil {
		return 0, err
	}
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil
	}
	msg := []byte("hop-pool-echo")
	if _, err := st.Write(msg); err != nil {
		return 0, err
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(st, buf); err != nil {
		return 0, err
	}
	if string(buf) != string(msg) {
		return 0, errors.New("echo mismatch")
	}
	_ = st.Close()
	return resp.StatusCode, nil
}

// 并发 TCP CONNECT 共用入口到出口的同一条 QUIC 连接：不再每个请求握手一次。
func TestIngressTCPReusesOneQUICConnection(t *testing.T) {
	echo := startEchoTCP(t)
	_, ingress := startHopPair(t, startFakeDNS(t), startFakeDNS(t), hopTestCred)

	const n = 20
	var wg sync.WaitGroup
	var bad atomic.Int64
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if code, err := connectViaIngress(ingress.Addr(), echo); err != nil || code != http.StatusOK {
				t.Errorf("connect via ingress: code=%d err=%v", code, err)
				bad.Add(1)
			}
		}()
	}
	wg.Wait()
	if bad.Load() == 0 {
		if got := ingress.quicServer.hopDials.Load(); got != 1 {
			t.Fatalf("入口向出口新建了 %d 条 QUIC 连接，期望 1（共享）", got)
		}
	}
}

// 共享连接被对端关闭后，下一个请求自动重建，不需要人工干预。
func TestIngressTCPRedialsAfterSharedConnDies(t *testing.T) {
	echo := startEchoTCP(t)
	_, ingress := startHopPair(t, startFakeDNS(t), startFakeDNS(t), hopTestCred)

	if code, err := connectViaIngress(ingress.Addr(), echo); err != nil || code != http.StatusOK {
		t.Fatalf("first connect: code=%d err=%v", code, err)
	}
	pool := &ingress.quicServer.hopPool
	pool.mu.Lock()
	var cur *hopPooledConn
	if e := pool.m["client-user-token"]; e != nil {
		cur = e.cur
	}
	pool.mu.Unlock()
	if cur == nil {
		t.Fatal("共享连接应已建立")
	}
	_ = cur.q.CloseWithError(0, "test: kill shared conn")

	if code, err := connectViaIngress(ingress.Addr(), echo); err != nil || code != http.StatusOK {
		t.Fatalf("connect after shared conn died: code=%d err=%v", code, err)
	}
	if got := ingress.quicServer.hopDials.Load(); got != 2 {
		t.Fatalf("hopDials=%d，期望 2（重建一次）", got)
	}
}

// 出口拒绝一个请求（目标连不上）只结束这个流，不关共享连接，后面的请求继续复用。
func TestIngressTCPRejectionKeepsSharedConn(t *testing.T) {
	echo := startEchoTCP(t)
	_, ingress := startHopPair(t, startFakeDNS(t), startFakeDNS(t), hopTestCred)

	// 取一个刚释放、没有监听的本机端口作为“连不上”的目标。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().String()
	_ = ln.Close()
	if code, err := connectViaIngress(ingress.Addr(), closed); err != nil || code != http.StatusBadGateway {
		t.Fatalf("connect to closed port: code=%d err=%v, want 502", code, err)
	}
	if code, err := connectViaIngress(ingress.Addr(), echo); err != nil || code != http.StatusOK {
		t.Fatalf("connect after rejection: code=%d err=%v", code, err)
	}
	if got := ingress.quicServer.hopDials.Load(); got != 1 {
		t.Fatalf("hopDials=%d，期望 1：拒绝不应使共享连接重建", got)
	}
}

// 单飞拨号：并发等待者共用一次拨号与同一个错误，不会各自串行重试。
func TestHopConnPoolSingleFlightSharesError(t *testing.T) {
	var p hopConnPool
	var dials atomic.Int64
	release := make(chan struct{})
	dialErr := errors.New("egress unreachable")
	dial := func() (*hopPooledConn, error) {
		dials.Add(1)
		<-release
		return nil, dialErr
	}

	const n = 8
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			_, err := p.get(context.Background(), "u", dial)
			errs <- err
		}()
	}
	// 确定性等待：所有等待者都已取得租约（active==n）才放行拨号。
	waitPoolActive(t, &p, "u", n)
	close(release)
	for i := 0; i < n; i++ {
		if err := <-errs; !errors.Is(err, dialErr) {
			t.Fatalf("waiter %d: err=%v, want shared dial error", i, err)
		}
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("dial 被调用 %d 次，期望 1", got)
	}

	// 关闭后 get 一律失败，不再拨号。
	p.close()
	if _, err := p.get(context.Background(), "u", dial); !errors.Is(err, errHopPoolClosed) {
		t.Fatalf("closed pool: err=%v, want errHopPoolClosed", err)
	}
}

// poolDial 返回一个到 egress 的真实拨号函数（测试用）。
func poolDial(ingress, egress *Server) func() (*hopPooledConn, error) {
	return func() (*hopPooledConn, error) { return ingress.quicServer.dialHopConn(egress.Addr()) }
}

// 不同用户各用各的连接（慢流只影响自己）；同一用户共用一条。
func TestHopConnPoolIsolatesUsers(t *testing.T) {
	egress, ingress := startHopPair(t, startFakeDNS(t), startFakeDNS(t), hopTestCred)
	p := &ingress.quicServer.hopPool
	ctx := context.Background()

	a1, err := p.get(ctx, "alice", poolDial(ingress, egress))
	if err != nil {
		t.Fatal(err)
	}
	a2, err := p.get(ctx, "alice", poolDial(ingress, egress))
	if err != nil {
		t.Fatal(err)
	}
	b1, err := p.get(ctx, "bob", poolDial(ingress, egress))
	if err != nil {
		t.Fatal(err)
	}
	if a1.conn != a2.conn {
		t.Fatal("同一用户应共用一条连接")
	}
	if a1.conn == b1.conn {
		t.Fatal("不同用户不得共用连接：一个用户的慢流会拖住其他用户")
	}
	if got := ingress.quicServer.hopDials.Load(); got != 2 {
		t.Fatalf("hopDials=%d，期望 2（每用户一条）", got)
	}
	// 一个用户的连接被关闭不影响另一个用户。
	p.invalidate(a1)
	if !b1.conn.alive() {
		t.Fatal("alice 的连接失效不应影响 bob")
	}
	a1.release()
	a2.release()
	b1.release()
}

// 没有流的条目在空闲时间后回收并关闭连接；有租约的不回收。
func TestHopConnPoolIdleReclaim(t *testing.T) {
	old := hopPoolIdleTTL
	hopPoolIdleTTL = 100 * time.Millisecond
	t.Cleanup(func() { hopPoolIdleTTL = old })

	egress, ingress := startHopPair(t, startFakeDNS(t), startFakeDNS(t), hopTestCred)
	p := &ingress.quicServer.hopPool

	l, err := p.get(context.Background(), "alice", poolDial(ingress, egress))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if p.size() != 1 || !l.conn.alive() {
		t.Fatal("持有租约期间不得回收")
	}
	conn := l.conn
	l.release()
	deadline := time.Now().Add(3 * time.Second)
	for p.size() != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if p.size() != 0 {
		t.Fatal("空闲条目应被回收")
	}
	// 连接在解锁之后才关（不在 p.mu 内做网络操作），所以要等一下。
	for conn.alive() && time.Now().Before(deadline.Add(3*time.Second)) {
		time.Sleep(20 * time.Millisecond)
	}
	if conn.alive() {
		t.Fatal("回收时应关闭连接")
	}
	l.release() // 幂等：重复归还不得破坏计数
}

// 池满：有空闲条目就回收它来腾位置；全部有租约时返回 errHopPoolFull（调用方改用独立连接）。
func TestHopConnPoolFullEvictsIdleOrFallsBack(t *testing.T) {
	old := hopPoolMaxConns
	hopPoolMaxConns = 1
	t.Cleanup(func() { hopPoolMaxConns = old })

	egress, ingress := startHopPair(t, startFakeDNS(t), startFakeDNS(t), hopTestCred)
	p := &ingress.quicServer.hopPool
	ctx := context.Background()

	a, err := p.get(ctx, "alice", poolDial(ingress, egress))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.get(ctx, "bob", poolDial(ingress, egress)); !errors.Is(err, errHopPoolFull) {
		t.Fatalf("池满且无空闲条目: err=%v, want errHopPoolFull", err)
	}
	a.release() // alice 变空闲（计时未到），bob 可以回收她
	b, err := p.get(ctx, "bob", poolDial(ingress, egress))
	if err != nil {
		t.Fatalf("池满但有空闲条目应回收: %v", err)
	}
	if a.conn.alive() {
		t.Fatal("被回收条目的连接应已关闭")
	}
	b.release()
}

// 池满时 TCP 请求退回独立连接：照常成功，且结束后不留连接。
func TestIngressTCPFallsBackToDedicatedConnWhenPoolFull(t *testing.T) {
	old := hopPoolMaxConns
	hopPoolMaxConns = 1
	t.Cleanup(func() { hopPoolMaxConns = old })

	echo := startEchoTCP(t)
	egress, ingress := startHopPair(t, startFakeDNS(t), startFakeDNS(t), hopTestCred)
	// 另一个用户持有唯一的池条目。
	hold, err := ingress.quicServer.hopPool.get(context.Background(), "other-user", poolDial(ingress, egress))
	if err != nil {
		t.Fatal(err)
	}
	defer hold.release()

	if code, err := connectViaIngress(ingress.Addr(), echo); err != nil || code != http.StatusOK {
		t.Fatalf("pool full fallback: code=%d err=%v", code, err)
	}
	if got := ingress.quicServer.hopPool.size(); got != 1 {
		t.Fatalf("池条目数=%d，期望仍为 1（回退的独立连接不入池）", got)
	}
}

// 流结束后租约归还：条目的 active 回到 0（否则永远不会被回收）。
func TestIngressTCPStreamCloseReleasesLease(t *testing.T) {
	echo := startEchoTCP(t)
	_, ingress := startHopPair(t, startFakeDNS(t), startFakeDNS(t), hopTestCred)
	if code, err := connectViaIngress(ingress.Addr(), echo); err != nil || code != http.StatusOK {
		t.Fatalf("connect: code=%d err=%v", code, err)
	}
	p := &ingress.quicServer.hopPool
	deadline := time.Now().Add(5 * time.Second)
	for {
		p.mu.Lock()
		e := p.m["client-user-token"]
		active := -1
		if e != nil {
			active = e.active
		}
		p.mu.Unlock()
		if active == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("流结束后租约未归还: active=%d", active)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// waitPoolActive 等到 key 的条目持有 want 个租约。
func waitPoolActive(t *testing.T, p *hopConnPool, key string, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		p.mu.Lock()
		got := -1
		if e := p.m[key]; e != nil {
			got = e.active
		}
		p.mu.Unlock()
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("条目 %q 的租约数=%d，期望 %d", key, got, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// 等待者的 ctx 取消后立即退出并归还租约，不影响进行中的拨号。
func TestHopConnPoolWaiterCtxCancel(t *testing.T) {
	var p hopConnPool
	release := make(chan struct{})
	dialDone := make(chan error, 1)
	go func() {
		_, err := p.get(context.Background(), "u", func() (*hopPooledConn, error) {
			<-release
			return nil, errors.New("dial failed")
		})
		dialDone <- err
	}()
	waitPoolActive(t, &p, "u", 1)

	ctx, cancel := context.WithCancel(context.Background())
	waiterErr := make(chan error, 1)
	go func() {
		_, err := p.get(ctx, "u", func() (*hopPooledConn, error) { t.Error("等待者不应再拨号"); return nil, nil })
		waiterErr <- err
	}()
	waitPoolActive(t, &p, "u", 2)
	cancel()
	if err := <-waiterErr; !errors.Is(err, context.Canceled) {
		t.Fatalf("waiter err=%v, want context.Canceled", err)
	}
	waitPoolActive(t, &p, "u", 1) // 等待者已归还租约
	close(release)
	if err := <-dialDone; err == nil {
		t.Fatal("拨号应失败")
	}
	if p.size() != 0 {
		t.Fatalf("拨号失败后条目应删除，size=%d", p.size())
	}
}

// 拨号进行中关闭池：拨号成功的连接要被关闭，不泄漏。
func TestHopConnPoolCloseDuringDial(t *testing.T) {
	egress, ingress := startHopPair(t, startFakeDNS(t), startFakeDNS(t), hopTestCred)
	var p hopConnPool
	proceed := make(chan struct{})
	var dialed *hopPooledConn
	errc := make(chan error, 1)
	go func() {
		_, err := p.get(context.Background(), "u", func() (*hopPooledConn, error) {
			<-proceed
			c, err := poolDial(ingress, egress)()
			dialed = c
			return c, err
		})
		errc <- err
	}()
	waitPoolActive(t, &p, "u", 1)
	p.close()
	close(proceed)
	if err := <-errc; !errors.Is(err, errHopPoolClosed) {
		t.Fatalf("err=%v, want errHopPoolClosed", err)
	}
	if dialed == nil || dialed.alive() {
		t.Fatal("池已关闭，拨号得到的连接应被关闭")
	}
}
