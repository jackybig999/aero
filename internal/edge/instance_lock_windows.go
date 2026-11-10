//go:build windows

package edge

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// instanceLock 是数据目录上的独占锁，保证同一数据目录只有一个 edge 实例（ADR-0005）。
type instanceLock struct{ f *os.File }

func acquireInstanceLock(dir string) (*instanceLock, error) {
	path := filepath.Join(dir, "edge.lock")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open instance lock %s: %w", path, err)
	}
	var ol windows.Overlapped
	err = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &ol)
	if err != nil {
		_ = f.Close()
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, fmt.Errorf("another edge instance is already using data dir %s", dir)
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return &instanceLock{f: f}, nil
}

// release 释放锁（关闭句柄即释放）。锁文件保留。
func (l *instanceLock) release() error {
	if l == nil || l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}
