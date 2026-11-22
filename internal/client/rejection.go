// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// EdgeRejectError 是 edge 对隧道请求的明确拒绝（C1 §5）：HTTP 状态、Proxy-Status 的 error 与 details、Retry-After。
// 重连逻辑据此区分“换 token”“等待”“换节点”，而不是一律快速重试（快速重试无效 token 会触发 edge 的防爆破封禁）。
type EdgeRejectError struct {
	Op         string // connect、connect-udp、connect-ip
	Status     int
	Code       string // Proxy-Status 的 error 参数，如 proxy_authorization_required
	Details    string // Proxy-Status 的 details 参数，如 EDGE_AUTH_TOKEN_EXPIRED
	RetryAfter time.Duration
}

func (e *EdgeRejectError) Error() string {
	msg := fmt.Sprintf("%s rejected by edge: %d", e.Op, e.Status)
	if e.Code != "" {
		msg += " " + e.Code
	}
	if e.Details != "" {
		msg += " (" + e.Details + ")"
	}
	return msg
}

// AuthFailure 报告是否为认证失败（需要新的 token）。
func (e *EdgeRejectError) AuthFailure() bool { return e.Status == http.StatusUnauthorized }

// NodeUnavailable 报告本节点暂时不能提供该服务（应换节点）：关闭了 CONNECT-IP、地址池耗尽、连接数已满。
func (e *EdgeRejectError) NodeUnavailable() bool {
	switch e.Code {
	case "connect_ip_disabled", "address_pool_exhausted", "connection_limit_exceeded", "udp_slot_limit_exceeded":
		return true
	}
	return false
}

// rejectionFrom 由 edge 的响应构造拒绝错误；resp 为 nil 时返回 nil。
func rejectionFrom(op string, resp *http.Response) *EdgeRejectError {
	if resp == nil {
		return nil
	}
	r := &EdgeRejectError{Op: op, Status: resp.StatusCode}
	r.Code, r.Details = parseProxyStatus(resp.Header.Get("Proxy-Status"))
	if v := strings.TrimSpace(resp.Header.Get("Retry-After")); v != "" {
		if sec, err := strconv.Atoi(v); err == nil && sec > 0 {
			r.RetryAfter = time.Duration(sec) * time.Second
		}
	}
	return r
}

// parseProxyStatus 解析 RFC 9209 Proxy-Status 第一个成员的 error 与 details 参数。details 是带引号的字符串，
// 可能含逗号与分号（edge 会放入拨号错误），因此按引号感知的方式切分。
func parseProxyStatus(v string) (code, details string) {
	params := splitUnquoted(firstUnquoted(v, ','), ';')
	for _, p := range params[1:] {
		k, val, ok := strings.Cut(strings.TrimSpace(p), "=")
		if !ok {
			continue
		}
		if uq, err := strconv.Unquote(val); err == nil {
			val = uq
		}
		switch k {
		case "error":
			code = val
		case "details":
			details = val
		}
	}
	return code, details
}

// splitUnquoted 按 sep 切分，忽略双引号内（含 \ 转义）的分隔符。
func splitUnquoted(s string, sep byte) []string {
	var out []string
	start, inQuote := 0, false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case inQuote && c == '\\':
			i++
		case c == '"':
			inQuote = !inQuote
		case !inQuote && c == sep:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func firstUnquoted(s string, sep byte) string { return splitUnquoted(s, sep)[0] }

// asRejection 取出错误链中的 edge 拒绝。
func asRejection(err error) (*EdgeRejectError, bool) {
	var r *EdgeRejectError
	ok := errors.As(err, &r)
	return r, ok
}
