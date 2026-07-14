// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package main

import (
	"net"
	"strings"
	"time"

	aeroproto "github.com/aero-protocol/proto"
)

// detectStreamType 根据目标地址判断流量类型（无日志，热路径）
func detectStreamType(target string) aeroproto.StreamType {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		portStr = ""
	}
	port := 0
	if portStr != "" {
		for _, c := range portStr {
			if c < '0' || c > '9' {
				port = 0
				break
			}
			port = port*10 + int(c-'0')
		}
	}

	aiDomains := []string{
		"openai.com", "anthropic.com", "claude.ai",
		"gemini.google.com", "chatgpt.com", "copilot.microsoft.com",
	}
	for _, d := range aiDomains {
		if strings.Contains(host, d) {
			return aeroproto.StreamType_AI
		}
	}

	switch port {
	case 3074, 25565, 27015, 27016, 3478, 3479, 5222, 9339:
		return aeroproto.StreamType_UDP
	case 80, 443, 0:
		return aeroproto.StreamType_BROWSER
	default:
		return aeroproto.StreamType_GENERAL
	}
}

// applyStreamQoS 设置 socket 选项；无日志。
func applyStreamQoS(conn net.Conn, streamType aeroproto.StreamType) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tcp.SetKeepAlive(true)
	switch streamType {
	case aeroproto.StreamType_AI, aeroproto.StreamType_UDP, aeroproto.StreamType_CONTROL:
		_ = tcp.SetNoDelay(true)
		_ = tcp.SetKeepAlivePeriod(30 * time.Second)
	default:
		_ = tcp.SetKeepAlivePeriod(60 * time.Second)
	}
	// 适度缓冲：多隧道时避免默认过小导致 syscall 频繁
	_ = tcp.SetReadBuffer(128 * 1024)
	_ = tcp.SetWriteBuffer(128 * 1024)
}
