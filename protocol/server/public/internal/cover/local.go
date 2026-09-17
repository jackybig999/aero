// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package cover

import (
	"net"
	"net/http"
	"strings"
)

// IsLoopback 是否本机探活（用于 /health /metrics 限制）
func IsLoopback(r *http.Request) bool {
	if r == nil {
		return false
	}
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
