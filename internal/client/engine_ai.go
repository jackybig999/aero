// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// AI 稳定通道（ADR-0017）：在 default 会话之外，再开一条 ai 会话（DATAGRAM capsule，流上可靠传输），
// AI 域名的 TCP 连接走它。节点必须在订阅里声明 capsule；ai 会话的任何问题都只让 ai 降级，不影响整条隧道。

// AI 通道状态（对外，界面据此显示）。
const (
	AIChannelOff         = "off"         // 用户关闭
	AIChannelUnsupported = "unsupported" // 当前节点没有声明 capsule（旧节点、或订阅不带 transports）
	AIChannelConnecting  = "connecting"  // 正在建立或重建
	AIChannelUp          = "up"          // 已建立
	AIChannelUnavailable = "unavailable" // 不可用（AI 新连接被拒绝，fail-closed），原因见 reason
)

// 重拨节奏（测试中会缩短）。
var (
	aiDialTimeout = 5 * time.Second
	aiRedialMin   = 2 * time.Second
	aiRedialMax   = 2 * time.Minute
)

const transportCap = "capsule"

// dialAIFn 在 sess（承载 default 会话的 Session）上建立 ai 会话并返回它分到的 IPv4 地址；可在测试中替换。
var dialAIFn = func(ctx context.Context, sess *Session) (IPPacketConn, netip.Addr, error) {
	if sess == nil || !sess.IsAlive() {
		return nil, netip.Addr{}, errNoPinnedSession
	}
	conn, prefixes, err := sess.DialIPClass(ctx, classNameAI)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	for _, p := range prefixes {
		if p.IsValid() && p.Addr().Is4() {
			if !tunPool.Contains(p.Addr()) {
				_ = conn.Close()
				return nil, netip.Addr{}, fmt.Errorf("ai session address %v is outside the tunnel pool %v", p.Addr(), tunPool)
			}
			return conn, p.Addr(), nil
		}
	}
	_ = conn.Close()
	return nil, netip.Addr{}, errors.New("ai session response has no valid IPv4 prefix")
}

// aiChannel 是引擎里与 ai 通道有关的状态。
type aiChannel struct {
	enabled atomic.Bool // 用户开关，默认开

	mu        sync.Mutex
	state     string
	reason    string
	mux       *ipMux                  // 当前隧道的复用层；节点不支持 capsule 或没有隧道时为 nil
	redialing map[*ipMux]*redialToken // 正在重拨的复用层及其协程的令牌（每个复用层最多一个重拨协程）
}

// redialToken 标识一个重拨协程：协程退出时只删除自己登记的项，不会误删后来者。
type redialToken struct{ _ byte }

// publish 在 ctx 仍有效时把 m 登记为当前复用层（m 为 nil 表示当前隧道没有复用层）。
// 检查与登记在同一把锁内：Stop 先取消 ctx 再 resetAIState，迟到的重连协程要么在取消之前登记（随即被重置清掉），
// 要么看到 ctx 已取消而不登记，不会把新隧道的复用层覆盖掉。
func (a *aiChannel) publish(ctx context.Context, m *ipMux) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if ctx.Err() != nil {
		return false
	}
	a.mux = m
	return true
}

// register 为 m 登记一个重拨协程；m 已失效或已有协程时返回 nil。
func (a *aiChannel) register(m *ipMux) *redialToken {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.mux != m {
		return nil
	}
	if a.redialing == nil {
		a.redialing = make(map[*ipMux]*redialToken)
	}
	if _, running := a.redialing[m]; running {
		return nil
	}
	tok := &redialToken{}
	a.redialing[m] = tok
	return tok
}

// release 只在登记项仍是 tok 时删除它。
func (a *aiChannel) release(m *ipMux, tok *redialToken) {
	a.mu.Lock()
	if a.redialing[m] == tok {
		delete(a.redialing, m)
	}
	a.mu.Unlock()
}

// setUnavailable 记录 ai 不可用；用户开关已关闭时记为 off（拨号失败与 SetAIChannel(false) 并发时不显示不可用）。
func (a *aiChannel) setUnavailable(m *ipMux, reason string, enabled bool) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.mux != m {
		return false
	}
	if !enabled {
		a.state, a.reason = AIChannelOff, ""
		return true
	}
	a.state, a.reason = AIChannelUnavailable, reason
	return true
}

// setUp 只在链路确实存在时写 up：链路在接入后、写状态之前就失败时，由 aiLinkLost 记为不可用，这里不能盖掉。
// 持 a.mu 时读取 m 的链路状态（锁顺序 a.mu → m.mu；ipMux 从不在持 m.mu 时回调引擎）。
func (a *aiChannel) setUp(m *ipMux) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.mux != m || !m.AIAvailable() {
		return false
	}
	a.state, a.reason = AIChannelUp, ""
	return true
}

// set 无条件写状态：只用于没有复用层的场景（节点不支持、用户关闭且没有隧道）。
func (a *aiChannel) set(state, reason string) {
	a.mu.Lock()
	a.state, a.reason = state, reason
	a.mu.Unlock()
}

// setFor 只在 m 仍是当前复用层时写状态：Stop、重连之后，旧复用层的协程不能覆盖新隧道的状态。
func (a *aiChannel) setFor(m *ipMux, state, reason string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.mux != m {
		return false
	}
	a.state, a.reason = state, reason
	return true
}

// retire 在 m 仍是当前复用层时撤销它并清空状态；无论如何都不再把它当作重拨对象。
func (a *aiChannel) retire(m *ipMux) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.mux == m {
		a.mux = nil
		a.state, a.reason = "", ""
	}
	delete(a.redialing, m)
}

func (a *aiChannel) snapshot() (state, reason string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.state, a.reason
}

// AIChannel 返回 AI 稳定通道的状态与原因（隧道未建立时状态为空）。
func (e *Engine) AIChannel() (state, reason string) { return e.ai.snapshot() }

// AIChannelEnabled 返回用户开关。
func (e *Engine) AIChannelEnabled() bool { return e.ai.enabled.Load() }

// SetAIChannel 打开或关闭 AI 稳定通道，对正在运行的隧道立即生效。
// 关闭后所有 TCP 都走 default 会话；已经建立在 ai 会话上的连接因源地址改变会中断，这是用户的显式操作。
func (e *Engine) SetAIChannel(enabled bool) {
	e.ai.enabled.Store(enabled)
	e.ai.mu.Lock()
	m := e.ai.mux
	e.ai.mu.Unlock()
	if m == nil { // 没有隧道，或节点不支持：下次建立隧道时按开关决定
		if !enabled {
			if st, _ := e.ai.snapshot(); st != "" {
				e.ai.set(AIChannelOff, "")
			}
		}
		return
	}
	if !enabled {
		e.aiCls.enabled.Store(false)
		m.DetachAI()
		e.ai.setFor(m, AIChannelOff, "")
		return
	}
	e.aiCls.enabled.Store(true)
	if !m.AIAvailable() {
		e.ai.setFor(m, AIChannelConnecting, "")
		e.startAIRedial(m, 0)
	}
}

// activeNodeSupports 报告当前节点是否在订阅里声明了某种传输方式。
func (e *Engine) activeNodeSupports(transport string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.appliedSub == nil {
		return false
	}
	srv, ok := findActiveServer(e.appliedSub, e.activeAddr)
	return ok && slices.Contains(srv.Transports, transport)
}

// wrapAI 在 default 会话 d 之外按需接入 ai 会话，返回交给数据泵的连接：
// 节点支持 capsule 时是复用层，否则原样返回 d（零额外开销，行为与引入 ai 通道之前完全一致）。
// ai 会话建立失败不影响隧道：状态记为 unavailable，后台按退避重试。调用方不得持有 e.mu 或 lifecycleMu 以外的长锁。
func (e *Engine) wrapAI(ctx context.Context, d IPPacketConn, prefix netip.Prefix) IPPacketConn {
	if e.sessionMgr == nil || !e.activeNodeSupports(transportCap) {
		if !e.ai.publish(ctx, nil) { // 隧道建立已被取消（Stop）：不碰状态
			return d
		}
		if e.ai.enabled.Load() {
			e.ai.set(AIChannelUnsupported, "")
		} else {
			e.ai.set(AIChannelOff, "")
		}
		return d
	}
	m := newIPMux(d, prefix.Addr(), e.aiCls)
	// 此刻刚建立完 default 会话（调用方串行），管理器里记着的就是承载它的 Session；绑定后不再读管理器。
	// 在 publish 之前设置：重拨协程经 publish 的锁才能看到复用层。
	m.carrier = e.sessionMgr.pinnedSession()
	m.SetAIDownHandler(func(err error) { e.aiLinkLost(m, err) })
	if !e.ai.publish(ctx, m) { // 已取消：不登记也不拨号，交给调用方的中止路径关闭
		return m
	}
	if !e.ai.enabled.Load() {
		e.aiCls.enabled.Store(false)
		e.ai.setFor(m, AIChannelOff, "")
		return m
	}
	e.aiCls.enabled.Store(true)
	e.ai.setFor(m, AIChannelConnecting, "")
	tr := e.startTr.Load()
	if err := e.dialAIOnce(ctx, m); err != nil {
		reason, _ := aiReason(err)
		tr.note("ai=failed(%s)", reason)
		e.aiDialFailed(m, err)
	} else {
		tr.note("ai=up")
		e.aiAttached(m)
	}
	return m
}

// aiAttached 在 ai 会话接入后更新状态。用户开关可能在拨号期间被关闭：先写状态再复查，
// 无论与 SetAIChannel(false) 怎样交错，最终都是“已断开且状态为 off”。
func (e *Engine) aiAttached(m *ipMux) {
	if !e.ai.enabled.Load() {
		m.DetachAI()
		e.ai.setFor(m, AIChannelOff, "")
		return
	}
	e.ai.setUp(m)
	if !e.ai.enabled.Load() {
		m.DetachAI()
		e.ai.setFor(m, AIChannelOff, "")
	}
}

// retireAIConn 在隧道建立中止时撤销（若是）复用层，避免它占着当前复用层的位置。
func (e *Engine) retireAIConn(conn IPPacketConn) {
	if m, ok := conn.(*ipMux); ok {
		e.ai.retire(m)
	}
}

// dialAIOnce 建立一次 ai 会话并接入复用层。
func (e *Engine) dialAIOnce(ctx context.Context, m *ipMux) error {
	dctx, cancel := context.WithTimeout(ctx, aiDialTimeout)
	defer cancel()
	conn, addr, err := dialAIFn(dctx, m.carrier)
	if err != nil {
		return err
	}
	return m.AttachAI(conn, addr)
}

// aiReason 把拨号错误归为状态里的原因码。permanent 表示重试没有意义（类别被拒绝、传输方式不符），
// 需等到下次建立隧道时再试。
func aiReason(err error) (reason string, permanent bool) {
	var rej *EdgeRejectError
	switch {
	case errors.Is(err, ErrTransportMismatch):
		return "CLIENT_TRANSPORT_MISMATCH", true
	case errors.As(err, &rej):
		switch rej.Code {
		case "class_not_allowed":
			return "EDGE_CLASS_NOT_ALLOWED", true
		case "unsupported_class":
			return "EDGE_UNSUPPORTED_CLASS", true
		case "connection_limit_exceeded", "address_pool_exhausted", "connect_ip_disabled":
			return "EDGE_" + upperSnake(rej.Code), false
		}
		if rej.AuthFailure() {
			return "EDGE_AUTH", false
		}
		return fmt.Sprintf("EDGE_HTTP_%d", rej.Status), false
	}
	return "AI_DIAL_FAILED", false
}

func upperSnake(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}

// aiDialFailed 记录 ai 会话建立失败：状态 unavailable；非永久性错误则后台重试。
func (e *Engine) aiDialFailed(m *ipMux, err error) {
	reason, permanent := aiReason(err)
	log.Printf("[AI] session dial failed (reason=%s, permanent=%v): %v", reason, permanent, err)
	if !e.ai.setUnavailable(m, reason, e.ai.enabled.Load()) { // 复用层已失效（Stop、重连）：不写状态、不重拨
		return
	}
	if permanent || !e.ai.enabled.Load() {
		return
	}
	e.startAIRedial(m, aiRedialMin)
}

// aiLinkLost 是复用层的回调：ai 会话在运行中失败。
func (e *Engine) aiLinkLost(m *ipMux, err error) {
	e.ai.mu.Lock()
	current := e.ai.mux == m
	e.ai.mu.Unlock()
	if !current || !e.ai.enabled.Load() {
		return
	}
	e.aiDialFailed(m, err)
}

// startAIRedial 为复用层 m 启动后台重拨（同一个 m 同一时刻只有一个协程）。first 是第一次尝试前的等待。
func (e *Engine) startAIRedial(m *ipMux, first time.Duration) {
	tok := e.ai.register(m)
	if tok == nil { // m 已失效，或已有协程在重拨
		return
	}
	go func() {
		defer e.ai.release(m, tok)
		// 拨号随复用层关闭而取消：Stop 之后不必再等 aiDialTimeout。
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			select {
			case <-m.closeCh:
				cancel()
			case <-ctx.Done():
			}
		}()
		wait, backoff := first, aiRedialMin
		for {
			if wait > 0 {
				select {
				case <-m.closeCh:
					return
				case <-time.After(wait/2 + rand.N(wait/2+1)): // 抖动：避免节点重启后大量客户端同时重拨
				}
			}
			select {
			case <-m.closeCh:
				return
			default:
			}
			e.ai.mu.Lock()
			current := e.ai.mux == m
			e.ai.mu.Unlock()
			if !current || !e.ai.enabled.Load() || m.AIAvailable() {
				return
			}
			err := e.dialAIOnce(ctx, m)
			if err == nil {
				// 先放开单飞再复查：拨号成功到这里之间新链路若已失败，aiLinkLost 看到“正在重拨”会直接返回，
				// 不放开就会永远断着。放开用本协程的令牌，之后 defer 里的 release 不会误删后来者的登记。
				e.ai.release(m, tok)
				if !m.AIAvailable() {
					e.startAIRedial(m, aiRedialMin)
					return
				}
				e.aiAttached(m)
				return
			}
			reason, permanent := aiReason(err)
			if !e.ai.setUnavailable(m, reason, e.ai.enabled.Load()) || permanent || !e.ai.enabled.Load() {
				return
			}
			wait = backoff
			backoff = min(backoff*2, aiRedialMax)
		}
	}()
}

// resetAIState 在隧道释放时清除 ai 通道的运行状态（保留用户开关）。
func (e *Engine) resetAIState() {
	e.ai.mu.Lock()
	e.ai.mux = nil
	e.ai.state, e.ai.reason = "", ""
	e.ai.redialing = nil
	e.ai.mu.Unlock()
}
