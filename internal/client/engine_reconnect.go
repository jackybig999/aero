package client

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"net/netip"
	"time"
)

// 断线恢复（M2-9）：CONNECT-IP 数据泵断开（网络切换、edge 重启、故障切换、NAT 变化）后，
// 带退避重新建立隧道并恢复数据泵。路由与 TUN 保持不变，断线期间流量不会从物理网卡漏出；
// edge 按 token 粘性分配地址，地址通常不变，变化时只替换 TUN 地址。

var (
	reconnectMinBackoff  = 500 * time.Millisecond
	reconnectMaxBackoff  = 15 * time.Second
	reconnectDialTimeout = 8 * time.Second
	setTunIPv4Fn         = setTunIPv4
)

var errReconnectAborted = errors.New("engine stopped during reconnect")

// startReconnector 注册数据泵断线回调并启动重连协程；协程随 ctx（rootCtx）退出。
func (e *Engine) startReconnector(ctx context.Context, stack *StackEngine, dev TunDevice, prefix netip.Prefix) {
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
				p, err := e.reconnectOnce(ctx, stack, dev, prefix)
				if err == nil {
					prefix = p
					log.Printf("[ENGINE] tunnel restored (%s)", prefix)
					break
				}
				if ctx.Err() != nil || errors.Is(err, errReconnectAborted) {
					return
				}
				log.Printf("[ENGINE] reconnect failed: %v; retry in ~%v", err, backoff)
				// 抖动避免 edge 重启后大量客户端同时重连
				wait := backoff/2 + rand.N(backoff/2+1)
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
func (e *Engine) reconnectOnce(ctx context.Context, stack *StackEngine, dev TunDevice, cur netip.Prefix) (netip.Prefix, error) {
	dctx, cancel := context.WithTimeout(ctx, reconnectDialTimeout)
	conn, prefixStr, err := dialIPFn(dctx, e.sessionMgr)
	cancel()
	if err != nil {
		return cur, err
	}
	p, err := netip.ParsePrefix(prefixStr)
	if err != nil {
		_ = conn.Close()
		return cur, fmt.Errorf("parse assigned prefix %q: %w", prefixStr, err)
	}

	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	if ctx.Err() != nil || !e.running.Load() || e.stackEngine != stack {
		_ = conn.Close()
		return cur, errReconnectAborted
	}
	if p != cur {
		if err := setTunIPv4Fn(dev.Name(), p); err != nil {
			_ = conn.Close()
			return cur, fmt.Errorf("update TUN address to %s: %w", p, err)
		}
	}
	return p, stack.RestartWithConn(conn)
}
