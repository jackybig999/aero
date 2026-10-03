//go:build windows

// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

func main() {
	pid := flag.Int("pid", 0, "parent process PID to monitor")
	flag.Parse()

	if *pid <= 0 {
		fmt.Println("Usage: aero-guard.exe -pid <PID>")
		os.Exit(2)
	}

	log.Printf("[GUARD] watching PID %d...", *pid)

	for processAlive(*pid) {
		time.Sleep(1 * time.Second)
	}

	log.Printf("[GUARD] parent PID %d exited, cleaning aero0 routes...", *pid)
	time.Sleep(200 * time.Millisecond)

	cleanAero0Routes()
	log.Printf("[GUARD] cleanup completed, guard exiting.")
}

func processAlive(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	return code == 259 // STILL_ACTIVE
}

func cleanAero0Routes() {
	// 唯一职责：仅删除属于 aero0 的 0.0.0.0/1 和 128.0.0.0/1，关闭 aero0
	// 彻底剔除全局 route delete 盲删，避免误拔第三方 VPN (如 Clash TUN) 路由
	quiet("netsh", "interface", "ipv4", "delete", "route", "0.0.0.0/1", "aero0")
	quiet("netsh", "interface", "ipv4", "delete", "route", "128.0.0.0/1", "aero0")

	// 禁用并关闭 aero0 网卡
	quiet("netsh", "interface", "set", "interface", "name=aero0", "admin=DISABLED")
}

func quiet(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	_ = cmd.Run()
}
