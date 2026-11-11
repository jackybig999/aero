//go:build linux

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
		t.Skip("unshare not available")
	}
	out, err := exec.Command("unshare", "-rn", "env", "AERO_NETNS=1", os.Args[0],
		"-test.run=^"+t.Name()+"$", "-test.count=1", "-test.v").CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "Operation not permitted") || strings.Contains(string(out), "unshare failed") {
			t.Skipf("user/net namespaces not permitted: %s", out)
		}
		t.Fatalf("netns run failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "--- PASS: "+t.Name()) {
		t.Fatalf("netns run did not pass:\n%s", out)
	}
	return false
}
