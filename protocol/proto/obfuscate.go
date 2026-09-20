// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package aero

import (
	"crypto/rand"
	"io"
	"math/big"
	"time"
)

// ObfuscateWriter 混淆写入器（包大小随机化与延迟抖动）
type ObfuscateWriter struct {
	w        io.Writer
	minDelay time.Duration
	maxDelay time.Duration
	minChunk int
	maxChunk int
	enabled  bool
}

// NewObfuscateWriter 创建混淆写入器
func NewObfuscateWriter(w io.Writer, minDelay, maxDelay time.Duration, minChunk, maxChunk int) *ObfuscateWriter {
	return &ObfuscateWriter{
		w:        w,
		minDelay: minDelay,
		maxDelay: maxDelay,
		minChunk: minChunk,
		maxChunk: maxChunk,
		enabled:  true,
	}
}

// SetEnabled 启用/禁用混淆
func (ow *ObfuscateWriter) SetEnabled(v bool) {
	ow.enabled = v
}

// Write 写入数据，应用混淆策略
func (ow *ObfuscateWriter) Write(p []byte) (int, error) {
	if !ow.enabled || len(p) <= ow.minChunk {
		return ow.w.Write(p)
	}

	totalWritten := 0
	for len(p) > 0 {
		chunkSize := ow.RandomChunkSize()
		if chunkSize > len(p) {
			chunkSize = len(p)
		}

		n, err := ow.w.Write(p[:chunkSize])
		totalWritten += n
		if err != nil {
			return totalWritten, err
		}

		p = p[chunkSize:]

		if len(p) > 0 {
			ow.RandomDelay()
		}
	}

	return totalWritten, nil
}

// RandomChunkSize 返回随机分包大小 [minChunk, maxChunk]
func (ow *ObfuscateWriter) RandomChunkSize() int {
	diff := ow.maxChunk - ow.minChunk
	if diff <= 0 {
		return ow.minChunk
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(diff)+1))
	if err != nil {
		return ow.minChunk
	}
	return ow.minChunk + int(n.Int64())
}

// RandomDelay 随机延迟 [minDelay, maxDelay]
func (ow *ObfuscateWriter) RandomDelay() {
	diff := ow.maxDelay - ow.minDelay
	if diff <= 0 {
		time.Sleep(ow.minDelay)
		return
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(diff)+1))
	if err != nil {
		time.Sleep(ow.minDelay)
		return
	}
	delay := ow.minDelay + time.Duration(n.Int64())
	time.Sleep(delay)
}

// ObfuscateReadWriter 同时包装读写的混淆器
type ObfuscateReadWriter struct {
	*ObfuscateWriter
	r io.Reader
}

// NewObfuscateReadWriter 创建读写混淆器
func NewObfuscateReadWriter(rw io.ReadWriter, minDelay, maxDelay time.Duration, minChunk, maxChunk int) *ObfuscateReadWriter {
	return &ObfuscateReadWriter{
		ObfuscateWriter: NewObfuscateWriter(rw, minDelay, maxDelay, minChunk, maxChunk),
		r:               rw,
	}
}

func (rw *ObfuscateReadWriter) Read(p []byte) (int, error) {
	return rw.r.Read(p)
}
