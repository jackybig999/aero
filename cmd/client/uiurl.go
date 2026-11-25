// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package main

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"time"
)

// uiNonceHeader 是本进程在每个响应里带的随机标记；窗口加载前用它确认对端就是自己的服务，
// 而不是别的程序先占了这个端口（那样窗口会加载到别人的页面，还带着 goClientAPI 绑定）。
const uiNonceHeader = "X-Aero-UI"

// uiNonce 每个进程一个随机值。
var uiNonce = func() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "" // 取不到随机数：就绪探测永远不通过，窗口退回内嵌页面
	}
	return hex.EncodeToString(b)
}()

// uiNonceMiddleware 给所有响应加上本进程的随机标记。
func uiNonceMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if uiNonce != "" {
			w.Header().Set(uiNonceHeader, uiNonce)
		}
		next.ServeHTTP(w, r)
	})
}

// uiURLFor 由 -api 监听地址得到窗口加载界面用的本机地址；监听在非回环地址时返回空串（窗口退回内嵌页面）。
//
// 为什么 Windows 窗口要从本机 HTTP 服务加载界面：用 SetHtml（NavigateToString）加载的页面不是安全上下文，
// navigator.mediaDevices 不存在，扫码调不起相机；http://127.0.0.1 属于安全上下文。
func uiURLFor(apiAddr string) string {
	host, port, err := net.SplitHostPort(apiAddr)
	if err != nil || port == "" {
		return ""
	}
	switch {
	case host == "" || host == "0.0.0.0" || host == "::":
		host = "127.0.0.1" // 监听全部地址时，本机仍可经回环访问
	case host == "localhost":
		host = "127.0.0.1"
	default:
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return ""
		}
	}
	return "http://" + net.JoinHostPort(host, port) + "/"
}

// waitUIServer 等本机服务能返回界面首页（HTTP 200、HTML，且带本进程的随机标记 nonce），最多等 total；就绪返回 true。
// 不就绪（含对端不是本进程）时调用方应退回内嵌页面，不能让窗口停在连接失败的页面上。
func waitUIServer(url, nonce string, total time.Duration) bool {
	if nonce == "" {
		return false
	}
	client := &http.Client{Timeout: 700 * time.Millisecond}
	deadline := time.Now().Add(total)
	for {
		if resp, err := client.Get(url); err == nil {
			ok := resp.StatusCode == http.StatusOK &&
				strings.Contains(resp.Header.Get("Content-Type"), "text/html") &&
				resp.Header.Get(uiNonceHeader) == nonce
			_ = resp.Body.Close()
			if ok {
				return true
			}
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(150 * time.Millisecond)
	}
}
