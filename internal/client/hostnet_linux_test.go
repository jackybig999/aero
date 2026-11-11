//go:build linux && !android

package client

import (
	"bufio"
	"context"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"
)

// 真实网卡测试一律在独立的用户 + 网络命名空间（unshare -rn）中运行，不触碰宿主网络。
// 外层测试以相同 -test.run 重新执行本测试二进制；内层通过 AERO_NETNS=1 识别自己。
// 返回 true 表示当前就在命名空间内，调用方继续执行；返回 false 表示外层已完成（内层通过），调用方直接 return。
func inNetns(t *testing.T) bool {
	t.Helper()
	if os.Getenv("AERO_NETNS") == "1" {
		return true
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("unshare not available")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("iproute2 not available")
	}
	cmd := exec.Command("unshare", "-rn", os.Args[0], "-test.run=^"+t.Name()+"$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), "AERO_NETNS=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "unshare failed") || strings.Contains(string(out), "Operation not permitted") {
			t.Skipf("user/net namespaces not permitted here: %s", out)
		}
		t.Fatalf("test in netns failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "--- PASS: "+t.Name()) {
		t.Fatalf("test in netns did not pass:\n%s", out)
	}
	return false
}

func ipOut(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("ip %v: %v: %s", args, err, out)
	}
	return string(out)
}

// routeDev 返回到达 addr 的出接口；无路由时返回空串（命名空间内没有默认路由）。
func routeDev(addr string) string {
	out, err := exec.Command("ip", "-o", "route", "get", addr).CombinedOutput()
	if err != nil {
		return ""
	}
	f := strings.Fields(string(out))
	if i := slices.Index(f, "dev"); i >= 0 && i+1 < len(f) {
		return f[i+1]
	}
	return ""
}

func linkExists(name string) bool {
	return exec.Command("ip", "link", "show", "dev", name).Run() == nil
}

func countRoutes(t *testing.T, family, dev string) int {
	t.Helper()
	out := strings.TrimSpace(ipOut(t, family, "route", "show", "dev", dev))
	if out == "" {
		return 0
	}
	return len(strings.Split(out, "\n"))
}

func testPlan(t *testing.T, bypass ...string) RoutePlan {
	t.Helper()
	in := RoutePlanInput{
		Direct:  mustPrefixes("1.0.0.0/8"),
		Capture: []netip.Addr{netip.MustParseAddr("192.168.77.1")},
	}
	for _, b := range bypass {
		in.Bypass = append(in.Bypass, netip.MustParseAddr(b))
	}
	plan, err := PlanTUNRoutes(in)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestTunHostLinuxLifecycle(t *testing.T) {
	if !inNetns(t) {
		return
	}
	cfg := tunHostConfig{Name: "aero0", MTU: 1224, IPv4: netip.MustParsePrefix("10.88.0.2/16"), Plan: testPlan(t, "9.9.9.9")}
	h, err := openTunHost(cfg)
	if err != nil {
		t.Fatalf("openTunHost: %v", err)
	}
	defer h.Close()

	link := ipOut(t, "link", "show", "dev", "aero0")
	if !strings.Contains(link, "UP") {
		t.Fatalf("link not up: %s", link)
	}
	if ipv6EnabledOn("aero0") {
		// IPv6 必须进入 TUN（隧道或黑洞），不得从物理网卡泄漏；网卡 MTU 需 ≥ 1280
		if !strings.Contains(link, "mtu 1280") {
			t.Fatalf("link mtu with IPv6 enabled: %s", link)
		}
		if got := routeDev("2001:4860::8888"); got != "aero0" {
			t.Errorf("IPv6 route via %q, want aero0", got)
		}
		if got := countRoutes(t, "-6", "aero0"); got < 1 {
			t.Errorf("no IPv6 routes on aero0")
		}
	} else if !strings.Contains(link, "mtu 1224") {
		t.Fatalf("link mtu without IPv6: %s", link)
	}
	// IPv4 仍按隧道 MTU 1224（路由 MTU）
	if out := ipOut(t, "-o", "route", "get", "8.8.8.8"); !strings.Contains(out, "mtu 1224") && !strings.Contains(link, "mtu 1224") {
		t.Fatalf("IPv4 path MTU is not 1224: %s", out)
	}
	for addr, want := range map[string]string{
		"8.8.8.8": "aero0", "192.168.77.1": "aero0", "10.88.0.1": "aero0",
		"9.9.9.9": "", "1.2.3.4": "", "192.168.77.2": "",
	} {
		if got := routeDev(addr); got != want {
			t.Errorf("route to %s via %q, want %q", addr, got, want)
		}
	}
	// 规划路由 + 地址池网段；内核另有 local 表路由，不在 main 表计数内
	if got, want := countRoutes(t, "-4", "aero0"), len(cfg.Plan.IPv4)+1; got != want {
		t.Errorf("IPv4 routes on aero0 = %d, want %d", got, want)
	}

	// 增量调整：8.8.8.8 改为 bypass
	if err := h.ApplyRoutes(testPlan(t, "9.9.9.9", "8.8.8.8")); err != nil {
		t.Fatalf("ApplyRoutes: %v", err)
	}
	if got := routeDev("8.8.8.8"); got != "" {
		t.Errorf("8.8.8.8 still via %q after bypass", got)
	}
	if got := routeDev("8.8.8.9"); got != "aero0" {
		t.Errorf("8.8.8.9 via %q, want aero0", got)
	}

	// 换地址：路由必须全部保留（删除最后一个地址会清空网卡路由）
	before := countRoutes(t, "-4", "aero0")
	if err := h.SetIPv4(netip.MustParsePrefix("10.88.5.9/16")); err != nil {
		t.Fatalf("SetIPv4: %v", err)
	}
	addrs := ipOut(t, "-4", "addr", "show", "dev", "aero0")
	if !strings.Contains(addrs, "10.88.5.9/32") || strings.Contains(addrs, "10.88.0.2") {
		t.Fatalf("addresses after SetIPv4: %s", addrs)
	}
	if after := countRoutes(t, "-4", "aero0"); after != before {
		t.Fatalf("routes after SetIPv4 = %d, want %d", after, before)
	}

	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if linkExists("aero0") {
		t.Fatal("aero0 still exists after Close")
	}
	if err := h.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := h.ApplyRoutes(cfg.Plan); err != errTunHostClosed {
		t.Fatalf("ApplyRoutes after Close = %v, want errTunHostClosed", err)
	}
	if got := routeDev("8.8.8.9"); got != "" {
		t.Fatalf("route to 8.8.8.9 still via %q after Close", got)
	}
}

// 配置失败时已创建的网卡必须被撤销。
func TestTunHostLinuxRollbackOnFailure(t *testing.T) {
	if !inNetns(t) {
		return
	}
	orig := ipBatch
	defer func() { ipBatch = orig }()
	ipBatch = func(ctx context.Context, lines []string) error {
		return orig(ctx, append(lines, "route replace not-a-prefix dev aero0"))
	}
	if _, err := openTunHost(tunHostConfig{Name: "aero0", MTU: 1224, IPv4: netip.MustParsePrefix("10.88.0.2/16"), Plan: testPlan(t)}); err == nil {
		t.Fatal("openTunHost succeeded with a failing batch")
	}
	if linkExists("aero0") {
		t.Fatal("aero0 left behind after failed configuration")
	}
}

// 进程被强杀（kill -9）后，网卡与其上的全部路由必须消失。
func TestTunHostLinuxNoResidueAfterKill(t *testing.T) {
	if os.Getenv("AERO_TUNHOST_CHILD") == "1" {
		h, err := openTunHost(tunHostConfig{Name: "aero0", MTU: 1224, IPv4: netip.MustParsePrefix("10.88.0.2/16"), Plan: testPlan(t)})
		if err != nil {
			t.Fatalf("child openTunHost: %v", err)
		}
		_ = h
		os.Stdout.WriteString("READY\n")
		select {} // 等待被杀
	}
	if !inNetns(t) {
		return
	}
	child := exec.Command(os.Args[0], "-test.run=^TestTunHostLinuxNoResidueAfterKill$", "-test.count=1")
	child.Env = append(os.Environ(), "AERO_TUNHOST_CHILD=1")
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "READY\n" {
		_ = child.Process.Kill()
		_ = child.Wait()
		t.Fatalf("child did not become ready: %q %v", line, err)
	}
	if !linkExists("aero0") || routeDev("8.8.8.8") != "aero0" {
		_ = child.Process.Kill()
		_ = child.Wait()
		t.Fatal("child did not configure aero0")
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()

	// 内核在释放 fd 时注销网卡；以条件轮询兜底，不用固定 sleep。
	deadline := time.Now().Add(5 * time.Second)
	for linkExists("aero0") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if linkExists("aero0") {
		t.Fatal("aero0 still exists after the owning process was killed")
	}
	if got := routeDev("8.8.8.8"); got != "" {
		t.Fatalf("route to 8.8.8.8 via %q after kill", got)
	}
}

func TestParseResolvConf(t *testing.T) {
	got := parseResolvConf([]byte("# comment\nnameserver 127.0.0.53\nnameserver 192.168.1.1\nsearch lan\nnameserver fe80::1%eth0\nnameserver bad\noptions edns0\n"))
	want := []string{"127.0.0.53", "192.168.1.1", "fe80::1%eth0"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Errorf("got[%d] = %v, want %s", i, got[i], want[i])
		}
	}
}
