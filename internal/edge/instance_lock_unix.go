//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package edge

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

// instanceLock 是数据目录上的独占锁，保证同一数据目录只有一个 edge 实例（ADR-0005）。
type instanceLock struct{ f *os.File }

// errInstanceLockBusy 表示数据目录的实例锁已被另一个 edge 实例持有（区别于打开/加锁的其他失败）。
var errInstanceLockBusy = errors.New("instance lock busy")

func acquireInstanceLock(dir string) (*instanceLock, error) {
	path := filepath.Join(dir, "edge.lock")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open instance lock %s: %w", path, err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("another edge instance is already using data dir %s: %w", dir, errInstanceLockBusy)
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	// 写入 PID 仅供排查；锁本身由 flock 保证。
	if err := f.Truncate(0); err == nil {
		_, _ = f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0)
	}
	return &instanceLock{f: f}, nil
}

// release 释放锁（关闭文件即释放 flock）。锁文件保留，避免删除与新实例加锁之间的竞态。
func (l *instanceLock) release() error {
	if l == nil || l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}
