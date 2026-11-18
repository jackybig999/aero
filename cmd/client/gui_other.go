//go:build !windows

package main

import (
	"errors"
	"log"
	"net/http"
	"os"
	"syscall"
)

// isProcessAlive 判断 PID 是否存在；无权限（EPERM）说明进程存在。
func isProcessAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = p.Signal(syscall.Signal(0))
	return err == nil || errors.Is(err, syscall.EPERM)
}

func runClientWindow(htmlUI string, handler http.Handler, shutdown func()) {
	log.Println("[CLIENT] Native GUI window is only supported on Windows. Running in headless mode.")
	runHeadless(shutdown)
}

func UpdateTrayIcon(mode string, connected bool) {}
