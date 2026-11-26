// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"context"
	"log"
	"net"
	"sync/atomic"
	"time"
)

// 本机代理（127.0.0.1:55555 的 SOCKS5 / HTTP CONNECT）的逐连接监控（只读诊断，不改数据）。
// 指纹浏览器、AI 命令行工具通常把代理指到这里，不经过 TUN，所以 flowmeter.go 看不到它们。
// 每条连接结束时输出 [PROXY]：目标、拨号耗时、首字节耗时（发出第一个请求字节到收到第一个响应字节）、
// 字节数与平均速率；超过 proxyProgress 仍在传输的大连接每 proxyProgress 输出一次进行中。
// 小而快的连接不输出；拨号失败或慢的、没有响应的连接一定输出。AERO_FLOWLOG=0 关闭。

const (
	proxyQuietBytes = 32 * 1024
	proxyProgress   = 10 * time.Second
	proxySlowDial   = time.Second
	proxySlowTTFB   = time.Second
)

// countConn 统计经过 remote 的字节与首字节时间；其余行为（含 CloseWrite）原样转发。
type countConn struct {
	net.Conn
	up, down atomic.Uint64
	firstW   atomic.Int64 // 第一次写入的时间（UnixNano）
	firstR   atomic.Int64 // 写入之后第一次读到数据的时间
}

func (c *countConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.down.Add(uint64(n))
		if c.firstW.Load() != 0 {
			c.firstR.CompareAndSwap(0, time.Now().UnixNano())
		}
	}
	return n, err
}

func (c *countConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.up.Add(uint64(n))
		c.firstW.CompareAndSwap(0, time.Now().UnixNano())
	}
	return n, err
}

func (c *countConn) CloseWrite() error {
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}

// relayMetered 在 relayTraffic 外面加监控；开关关闭时与 relayTraffic 完全一样。
func relayMetered(kind, target string, dial time.Duration, a, b net.Conn, ctx context.Context) {
	if !flowLogEnabled() {
		relayTraffic(a, b, ctx)
		return
	}
	cc := &countConn{Conn: b}
	start := time.Now()
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(proxyProgress)
		defer t.Stop()
		var last uint64
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if d := cc.down.Load(); d-last >= 256*1024 {
					log.Printf("[PROXY] 进行中 %s %s 已%.0fs 下行%dKB 近%.0fs平均%.0fKB/s", kind, target, time.Since(start).Seconds(), d/1024,
						proxyProgress.Seconds(), float64(d-last)/1024/proxyProgress.Seconds())
					last = d
				}
			}
		}
	}()
	relayTraffic(a, cc, ctx)
	close(done)

	dur := time.Since(start)
	up, down := cc.up.Load(), cc.down.Load()
	ttfb := time.Duration(-1)
	if w, r := cc.firstW.Load(), cc.firstR.Load(); w != 0 && r != 0 {
		ttfb = time.Duration(r - w)
	}
	quiet := up+down < proxyQuietBytes && dial < proxySlowDial && (ttfb >= 0 && ttfb < proxySlowTTFB)
	if quiet {
		return
	}
	secs := max(dur.Seconds(), 0.001)
	log.Printf("[PROXY] 结束 %s %s 拨号%dms 首字节%dms 用时%.1fs 上行%dKB 下行%dKB 平均下行%.0fKB/s",
		kind, target, dial.Milliseconds(), ttfb.Milliseconds(), dur.Seconds(), up/1024, down/1024, float64(down)/1024/secs)
}

// logProxyDialFailed 记录本机代理拨号失败（目标、耗时、原因）。
func logProxyDialFailed(kind, target string, dial time.Duration, err error) {
	if flowLogEnabled() {
		log.Printf("[PROXY] 拨号失败 %s %s 用时%dms: %v", kind, target, dial.Milliseconds(), err)
	}
}
