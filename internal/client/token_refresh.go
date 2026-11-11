package client

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"strings"
	"time"
)

// C3 签名 token 的到期刷新（api/token.md §4：有效期 24 小时，剩余 25% 时刷新）。客户端不验签，
// 只读取载荷中的 iat/exp 决定何时重新拉取订阅。拿到新 token 后关闭旧会话：数据泵检测到断线，
// 既有重连逻辑以新 token 重建 CONNECT-IP；edge 按 uid 租约分配地址，隧道地址不变。

var (
	tokenRefreshMinRetry = 30 * time.Second
	tokenRefreshMaxRetry = 10 * time.Minute
	tokenRefreshIdle     = 10 * time.Minute // 没有签名 token 时的复查间隔
	tokenRefreshNow      = time.Now
)

// tokenLifetime 读取 aero1 token 的签发与到期时间；非签名 token 或格式错误时 ok=false。
func tokenLifetime(tok string) (iat, exp time.Time, ok bool) {
	rest, found := strings.CutPrefix(tok, "aero1.")
	if !found {
		return time.Time{}, time.Time{}, false
	}
	payload, _, found := strings.Cut(rest, ".")
	if !found {
		return time.Time{}, time.Time{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return time.Time{}, time.Time{}, false
	}
	var c struct {
		Iat int64 `json:"iat"`
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(raw, &c) != nil || c.Exp <= c.Iat || c.Iat <= 0 {
		return time.Time{}, time.Time{}, false
	}
	return time.Unix(c.Iat, 0), time.Unix(c.Exp, 0), true
}

// nextTokenRefresh 返回应刷新的时刻：有效期过去 75% 时。
func nextTokenRefresh(tok string) (time.Time, bool) {
	iat, exp, ok := tokenLifetime(tok)
	if !ok {
		return time.Time{}, false
	}
	return iat.Add(exp.Sub(iat) * 3 / 4), true
}

// kickTokenRefresh 通知刷新协程重新计算（订阅已应用）；首次调用时启动刷新协程（没有订阅的引擎不需要它）。
func (e *Engine) kickTokenRefresh() {
	e.tokenRefreshOnce.Do(func() { go e.runTokenRefresher() })
	select {
	case e.tokenRefreshKick <- struct{}{}:
	default:
	}
}

// runTokenRefresher 随 daemonCtx 运行到引擎关闭。
func (e *Engine) runTokenRefresher() {
	retry := tokenRefreshMinRetry
	for {
		_, tok, _, _ := getActiveEdge()
		e.mu.RLock()
		src := e.savedSubURL
		e.mu.RUnlock()

		wait := tokenRefreshIdle
		at, signed := nextTokenRefresh(tok)
		if signed && src != "" {
			wait = max(at.Sub(tokenRefreshNow()), 0)
		}
		timer := time.NewTimer(wait)
		select {
		case <-e.daemonCtx.Done():
			timer.Stop()
			return
		case <-e.tokenRefreshKick:
			timer.Stop()
			retry = tokenRefreshMinRetry
			continue
		case <-timer.C:
		}
		if !signed || src == "" {
			continue
		}
		if _, err := e.LoadAndApplySubscription(src); err != nil {
			log.Printf("[TOKEN] refresh failed: %v; retry in %v", err, retry)
			select {
			case <-e.daemonCtx.Done():
				return
			case <-time.After(retry):
			}
			retry = min(retry*2, tokenRefreshMaxRetry)
			continue
		}
		retry = tokenRefreshMinRetry
		if _, newTok, _, _ := getActiveEdge(); newTok != tok {
			log.Printf("[TOKEN] refreshed; rotating session to the new token")
			if e.sessionMgr != nil {
				e.sessionMgr.Reset() // 先关旧连接再以新 token 重建，edge 按 uid 归还同一隧道地址
			}
		}
	}
}
