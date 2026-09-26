// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package public

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
		"deepseek.com", "groq.com", "cursor.com", "cursor.sh",
		"mistral.ai", "together.ai", "together.xyz", "cohere.com",
		"perplexity.ai", "poe.com", "openrouter.ai", "huggingface.co",
		"replicate.com", "midjourney.com",
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
	// 全连接禁用 Nagle 算法，消除 40ms 延迟抖动
	_ = tcp.SetNoDelay(true)
	_ = tcp.SetKeepAlive(true)
	switch streamType {
	case aeroproto.StreamType_AI:
		// AI 深度思考长会话（如 R1/o1）：15 秒密集保活探针，防 NAT 表超时释放
		_ = tcp.SetKeepAlivePeriod(15 * time.Second)
	case aeroproto.StreamType_UDP, aeroproto.StreamType_CONTROL:
		_ = tcp.SetKeepAlivePeriod(20 * time.Second)
	default:
		_ = tcp.SetKeepAlivePeriod(30 * time.Second)
	}
	// 适度缓冲：多隧道时避免默认过小导致 syscall 频繁
	_ = tcp.SetReadBuffer(128 * 1024)
	_ = tcp.SetWriteBuffer(128 * 1024)
}
