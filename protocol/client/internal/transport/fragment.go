// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package transport

import (
	"math/rand"
	"net"
	"sync"
	"time"
)

// ClientHelloSplitter 拦截并拆分 TLS Client Hello，对抗深度包检测 (DPI)
type ClientHelloSplitter struct {
	net.Conn
	mu       sync.Mutex
	buf      []byte
	sent     bool
	fragSize int
	minDelay time.Duration
	maxDelay time.Duration
}

// NewSplitter 创建 TLS Client Hello 分片器
// fragSize: 第一个分片的大小（字节）
// minDelay/maxDelay: 分片之间的随机延迟
func NewSplitter(conn net.Conn, fragSize int, minDelay, maxDelay time.Duration) net.Conn {
	return &ClientHelloSplitter{
		Conn:     conn,
		fragSize: fragSize,
		minDelay: minDelay,
		maxDelay: maxDelay,
	}
}

// Write 拦截 TLS Client Hello 并分片发送
func (s *ClientHelloSplitter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 如果不是 Client Hello（不以 TLS Record Layer 0x16 开头），直接发送
	if len(p) < 3 || p[0] != 0x16 || p[1] != 0x03 {
		return s.Conn.Write(p)
	}

	// 已经分片过，直接发送
	if s.sent {
		return s.Conn.Write(p)
	}

	// 分片发送
	s.sent = true

	// 第一个分片
	if s.fragSize > len(p) {
		s.fragSize = len(p) / 2
	}
	first := p[:s.fragSize]
	n1, err := s.Conn.Write(first)
	if err != nil {
		return n1, err
	}

	// 随机延迟（避免 Int63n(0) panic）
	if s.maxDelay > s.minDelay {
		delay := s.minDelay + time.Duration(rand.Int63n(int64(s.maxDelay-s.minDelay)))
		time.Sleep(delay)
	} else if s.minDelay > 0 {
		time.Sleep(s.minDelay)
	}

	// 第二个分片（剩余数据）
	rest := p[s.fragSize:]
	n2, err := s.Conn.Write(rest)
	written := s.fragSize + len(rest)
	if n1 < len(first) || n2 < len(rest) {
		return written, err
	}
	return written, err
}
