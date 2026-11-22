// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"strings"
	"sync/atomic"
	"time"
)

// C3 签名 token 的到期刷新（api/token.md §4：有效期 24 小时，剩余 25% 时刷新）。客户端不验签，
// 只读取载荷中的 iat/exp 决定何时重新拉取订阅。拿到新 token 后关闭旧会话：数据泵检测到断线，
// 既有重连逻辑以新 token 重建 CONNECT-IP；edge 按 uid 租约分配地址，隧道地址不变。

var (
	tokenRefreshIdle = 10 * time.Minute // 没有签名 token 时的复查间隔
	// tokenRefreshMaxWait：计时器按单调时钟计时，系统休眠期间不走；每次最多等这么久就按实际时间重新判断，
	// 避免休眠一夜醒来后仍用过期 token。
	tokenRefreshMaxWait    = 5 * time.Minute
	authRefreshMinInterval = time.Minute // 因 401 强制刷新订阅的最小间隔
	tokenRefreshNow        = time.Now
)

// 刷新失败后的退避下限与上限（纳秒）。用原子量，测试可在引擎协程运行时安全地缩短。
var (
	tokenRefreshMinRetryNs atomic.Int64
	tokenRefreshMaxRetryNs atomic.Int64
)

func init() {
	tokenRefreshMinRetryNs.Store(int64(30 * time.Second))
	tokenRefreshMaxRetryNs.Store(int64(10 * time.Minute))
}

func tokenRefreshMinRetry() time.Duration { return time.Duration(tokenRefreshMinRetryNs.Load()) }
func tokenRefreshMaxRetry() time.Duration { return time.Duration(tokenRefreshMaxRetryNs.Load()) }

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
	retry := tokenRefreshMinRetry()
	for {
		_, tok, _, _ := getActiveEdge()
		e.mu.RLock()
		src := e.savedSubURL
		e.mu.RUnlock()

		wait := tokenRefreshIdle
		at, signed := nextTokenRefresh(tok)
		if signed && src != "" {
			wait = min(max(at.Sub(tokenRefreshNow()), 0), tokenRefreshMaxWait)
		}
		timer := time.NewTimer(wait)
		select {
		case <-e.daemonCtx.Done():
			timer.Stop()
			return
		case <-e.tokenRefreshKick:
			timer.Stop()
			retry = tokenRefreshMinRetry()
			continue
		case <-timer.C:
		}
		if !signed || src == "" || tokenRefreshNow().Before(at) {
			continue // 尚未到刷新时刻（等待被截断为 tokenRefreshMaxWait）
		}
		applied, err := e.LoadAndApplySubscription(src)
		// Apply 会 kick 本协程；那是自己引起的，不是新订阅。不清掉的话下一轮会重置退避并立刻重拉（空转）。
		e.drainTokenRefreshKick()
		_, newTok, _, _ := getActiveEdge()
		var failure string
		switch {
		case err != nil:
			failure = err.Error()
		case applied != nil && applied.FromCache:
			failure = "subscription service unreachable, only the cached copy is available" // 缓存里的 token 不是新签发的
		case newTok == tok:
			failure = "subscription still carries the old token"
		}
		if failure != "" {
			// 失败、来自缓存、token 未变都按退避重试，且不重置 retry；否则离线或订阅服务 5xx 时会空转。
			log.Printf("[TOKEN] refresh failed: %s; retry in %v", failure, retry)
			backoff := time.NewTimer(retry)
			select {
			case <-e.daemonCtx.Done():
				backoff.Stop()
				return
			case <-e.tokenRefreshKick:
				// 退避期间有新的订阅被应用（自己的 kick 已在上面清掉）：重置退避，立即按新状态重试
				backoff.Stop()
				retry = tokenRefreshMinRetry()
				continue
			case <-backoff.C:
			}
			retry = min(retry*2, tokenRefreshMaxRetry())
			continue
		}
		retry = tokenRefreshMinRetry()
		log.Printf("[TOKEN] refreshed; rotating session to the new token")
		if e.sessionMgr != nil {
			e.sessionMgr.Reset() // 先关旧连接再以新 token 重建，edge 按 uid 归还同一隧道地址
		}
	}
}

// drainTokenRefreshKick 丢弃挂起的 kick（刷新协程自己的 Apply 产生的）。
func (e *Engine) drainTokenRefreshKick() {
	select {
	case <-e.tokenRefreshKick:
	default:
	}
}

// refreshAfterAuthFailure：edge 以 401 拒绝了当前 token（被吊销、过期、或订阅已更换）。立即重新拉取订阅换 token；
// 至多每分钟一次。拿到不同的 token 后重置会话，以新 token 重建；token 未变则保持被拒状态，由重连节奏决定何时再试。
func (e *Engine) refreshAfterAuthFailure() {
	e.authRefreshMu.Lock()
	if now := time.Now(); now.Sub(e.lastAuthRefresh) < authRefreshMinInterval {
		e.authRefreshMu.Unlock()
		return
	} else {
		e.lastAuthRefresh = now
	}
	e.authRefreshMu.Unlock()
	e.mu.RLock()
	src := e.savedSubURL
	e.mu.RUnlock()
	if src == "" {
		return
	}
	go func() {
		_, oldTok, _, _ := getActiveEdge()
		applied, err := e.LoadAndApplySubscription(src)
		if err != nil {
			log.Printf("[TOKEN] refresh after authentication failure failed: %v", err)
			return
		}
		if applied != nil && applied.FromCache {
			// 拿到的是缓存（订阅服务不可达），不能据此判断 token 是否被吊销，也不是新签发的 token；
			// 缓存的 Apply 产生的 kick 也不是新订阅，清掉以免刷新协程跳过退避立刻重拉。
			e.drainTokenRefreshKick()
			log.Printf("[TOKEN] refresh after authentication failure failed: subscription service unreachable, only the cached copy is available")
			return
		}
		if _, newTok, _, _ := getActiveEdge(); newTok != oldTok {
			log.Printf("[TOKEN] edge rejected the token; switched to the token from the refreshed subscription")
			if e.sessionMgr != nil {
				e.sessionMgr.Reset()
			}
			return
		}
		log.Printf("[TOKEN] edge rejected the token and the subscription still carries it (revoked, expired or suspended subscription)")
	}()
}
