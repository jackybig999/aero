// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package main

import (
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

const (
	tokenFilePrefix = "session-"
	tokenFileSuffix = ".token"
)

// ownTokenPath 是本进程写出的 session token 文件路径；空串表示尚未写出。
var (
	ownTokenMu   sync.Mutex
	ownTokenPath string
)

func setOwnTokenPath(p string) {
	ownTokenMu.Lock()
	ownTokenPath = p
	ownTokenMu.Unlock()
}

// removeOwnToken 删除本进程的 token 文件，可重复调用；文件不存在不算错误。
func removeOwnToken() {
	ownTokenMu.Lock()
	p := ownTokenPath
	ownTokenMu.Unlock()
	if p == "" {
		return
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		log.Printf("[CLIENT] remove session token failed: %v", err)
	}
}

// fatalf 先清理本进程 token 文件再退出，避免 log.Fatalf 路径留下残留文件。
func fatalf(format string, args ...any) {
	removeOwnToken()
	log.Fatalf(format, args...)
}

// newOnceShutdown 包装 shutdown：多处（托盘、信号、系统关机消息）可并发调用，
// 但只执行一次；后到的调用会等待首次执行完成后返回。
func newOnceShutdown(f func()) func() {
	var once sync.Once
	return func() { once.Do(f) }
}

// cleanOrphanTokens 删除 dir 下 session-<PID>.token 中 PID 已不存在的文件。
// 跳过自身 PID 与无法解析的文件名；alive 由调用方注入以便测试。
func cleanOrphanTokens(dir string, selfPID int, alive func(pid int) bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, tokenFilePrefix) || !strings.HasSuffix(name, tokenFileSuffix) {
			continue
		}
		pidStr := strings.TrimSuffix(strings.TrimPrefix(name, tokenFilePrefix), tokenFileSuffix)
		pid, err := strconv.Atoi(pidStr)
		if err != nil || pid <= 0 || pid == selfPID {
			continue
		}
		if alive(pid) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !os.IsNotExist(err) {
			log.Printf("[CLIENT] remove orphan token %s failed: %v", name, err)
		}
	}
}
