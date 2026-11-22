// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"time"
)

// 断线恢复（M2-9）：CONNECT-IP 数据泵断开（网络切换、edge 重启、故障切换、NAT 变化）后，
// 带退避重新建立隧道并恢复数据泵。路由与 TUN 保持不变，断线期间流量不会从物理网卡漏出；
// edge 按 token 粘性分配地址，地址通常不变，变化时只替换 TUN 地址（tunHost.SetIPv4，路由保持）。

var (
	reconnectMinBackoff  = 500 * time.Millisecond
	reconnectMaxBackoff  = 15 * time.Second
	reconnectDialTimeout = 8 * time.Second
)

var errReconnectAborted = errors.New("engine stopped during reconnect")

// startReconnector 注册数据泵断线回调并启动重连协程；协程随 ctx（rootCtx）退出。
func (e *Engine) startReconnector(ctx context.Context, stack *StackEngine, host tunHost, prefix netip.Prefix) {
	trigger := make(chan struct{}, 1)
	stack.SetOnDisconnect(func(err error) {
		if ctx.Err() != nil {
			return
		}
		log.Printf("[ENGINE] tunnel down (%v); reconnecting", err)
		select {
		case trigger <- struct{}{}:
		default:
		}
	})
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-trigger:
			}
			backoff := reconnectMinBackoff
			for {
				p, err := e.reconnectOnce(ctx, stack, host, prefix)
				if err == nil {
					prefix = p
					log.Printf("[ENGINE] tunnel restored (%s)", prefix)
					break
				}
				if ctx.Err() != nil || errors.Is(err, errReconnectAborted) {
					return
				}
				// 抖动避免 edge 重启后大量客户端同时重连
				wait := backoff/2 + rand.N(backoff/2+1)
				if rej, ok := asRejection(err); ok {
					wait = e.rejectionWait(ctx, rej, wait)
				}
				log.Printf("[ENGINE] reconnect failed: %v; retry in ~%v", err, wait)
				select {
				case <-ctx.Done():
					return
				case <-time.After(wait):
				}
				backoff = min(backoff*2, reconnectMaxBackoff)
			}
		}
	}()
}

// reconnectOnce 拨号不持锁（不阻塞 Stop）；切换时持 lifecycleMu 并确认引擎仍在运行，
// 否则关闭新连接。返回新的地址前缀。
func (e *Engine) reconnectOnce(ctx context.Context, stack *StackEngine, host tunHost, cur netip.Prefix) (netip.Prefix, error) {
	dctx, cancel := context.WithTimeout(ctx, reconnectDialTimeout)
	conn, prefixStr, err := dialIPFn(dctx, e.sessionMgr)
	cancel()
	if err != nil {
		return cur, err
	}
	p, err := netip.ParsePrefix(prefixStr)
	if err == nil {
		p, err = tunAddress(p)
	}
	if err != nil {
		_ = conn.Close()
		return cur, fmt.Errorf("assigned prefix %q: %w", prefixStr, err)
	}

	// ai 会话在持锁之前建立（最长 aiDialTimeout），不阻塞 Stop；中止路径关闭的是复用层，两个会话一起关。
	conn = e.wrapAI(ctx, conn, p)

	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	if ctx.Err() != nil || !e.running.Load() || e.stackEngine != stack {
		e.retireAIConn(conn)
		_ = conn.Close()
		return cur, errReconnectAborted
	}
	if p != cur {
		if err := host.SetIPv4(p); err != nil {
			e.retireAIConn(conn)
			_ = conn.Close()
			return cur, fmt.Errorf("update TUN address to %s: %w", p, err)
		}
	}
	if err := stack.RestartWithConn(conn); err != nil {
		e.retireAIConn(conn) // RestartWithConn 失败时没有人接管 conn：关闭它（含 ai 会话），不留泄漏
		_ = conn.Close()
		return p, err
	}
	return p, nil
}

// 被 edge 明确拒绝时的重试节奏（C1 §5）：
//   - 401：换 token（refreshAfterAuthFailure）；两次尝试至少间隔 authRetryMin，保证每分钟少于 5 次，
//     不触发 edge 的防爆破封禁（5 次/分钟 → 封禁 15 分钟）；
//   - 429：按 Retry-After 等待；
//   - 节点不可用（关闭 CONNECT-IP、地址池耗尽、连接数满）：至少等待 nodeUnavailableRetry。
const (
	authRetryMin           = 15 * time.Second
	nodeUnavailableRetry   = time.Minute
	nodeUnavailableCooling = 10 * time.Minute // 不可用节点在此期间不作为换节点的候选
)

// markNodeUnavailable 记录节点暂不可用；nodeUnavailable 报告是否仍在冷却期。
func (e *Engine) markNodeUnavailable(addr string) {
	if addr == "" {
		return
	}
	e.unavailableMu.Lock()
	defer e.unavailableMu.Unlock()
	if e.unavailableNodes == nil {
		e.unavailableNodes = make(map[string]time.Time)
	}
	now := time.Now()
	for a, until := range e.unavailableNodes {
		if now.After(until) {
			delete(e.unavailableNodes, a)
		}
	}
	e.unavailableNodes[addr] = now.Add(nodeUnavailableCooling)
}

func (e *Engine) nodeUnavailable(addr string) bool {
	e.unavailableMu.Lock()
	defer e.unavailableMu.Unlock()
	until, ok := e.unavailableNodes[addr]
	return ok && time.Now().Before(until)
}

func (e *Engine) rejectionWait(ctx context.Context, r *EdgeRejectError, wait time.Duration) time.Duration {
	e.setRejection(r)
	switch {
	case r.AuthFailure():
		e.refreshAfterAuthFailure()
		return max(wait, authRetryMin)
	case r.Status == http.StatusTooManyRequests:
		return max(wait, r.RetryAfter, authRetryMin)
	case r.NodeUnavailable():
		// 本节点不能提供服务：记入冷却名单并换到其他可达节点；换成功则立即重连
		e.mu.RLock()
		cur, sentinel := e.activeAddr, e.sentinel
		e.mu.RUnlock()
		e.markNodeUnavailable(cur)
		if sentinel != nil && sentinel.failover(ctx) {
			return reconnectMinBackoff
		}
		return max(wait, nodeUnavailableRetry)
	}
	return wait
}
