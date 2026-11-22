//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package edge

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// inNetns 让会修改网络状态的测试在独立用户 + 网络命名空间中运行（iptables、ip_forward、TUN 均为该
// 命名空间私有），不触碰宿主。外层以相同 -test.run 重新执行本测试二进制并断言内层通过，返回 false；
// 内层（AERO_NETNS=1）返回 true，调用方继续执行。
func inNetns(t *testing.T) bool {
	t.Helper()
	if os.Getenv("AERO_NETNS") == "1" {
		return true
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		envSkip(t, "unshare not available")
	}
	// -m -p -f --mount-proc：在新的挂载与 PID 命名空间里挂载新的 /proc，使本命名空间的 /proc/sys/net 可写
	// （部分容器把外层 /proc/sys 挂为只读）；仍然只影响该命名空间。
	out, err := exec.Command("unshare", "-rnmpf", "--mount-proc", "env", "AERO_NETNS=1", os.Args[0],
		"-test.run=^"+t.Name()+"$", "-test.count=1", "-test.v").CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "Operation not permitted") || strings.Contains(string(out), "unshare failed") {
			envSkip(t, "user/net namespaces not permitted: %s", out)
		}
		t.Fatalf("netns run failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "--- PASS: "+t.Name()) {
		t.Fatalf("netns run did not pass:\n%s", out)
	}
	return false
}

// envSkip 在环境不支持时跳过；CI 设置 AERO_REQUIRE_NETNS=1 时改为失败，避免命名空间测试被静默跳过。
func envSkip(t *testing.T, format string, a ...any) {
	t.Helper()
	if os.Getenv("AERO_REQUIRE_NETNS") == "1" {
		t.Fatalf("required environment missing (AERO_REQUIRE_NETNS=1): "+format, a...)
	}
	t.Skipf(format, a...)
}
