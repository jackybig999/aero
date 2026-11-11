//go:build windows

package client

import (
	"bufio"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Windows 没有网络命名空间，本测试会在宿主上临时创建自有网卡 aerotest0（结束即删除）。
// 只在显式设置 AERO_HOST_TUN_TEST=1 且以管理员身份运行时执行：
//
//	set AERO_HOST_TUN_TEST=1
//	go test -count=1 -run TunHostWindows -v ./internal/client
const winTestTun = "aerotest0"

func requireHostTunTest(t *testing.T) {
	t.Helper()
	if os.Getenv("AERO_HOST_TUN_TEST") != "1" {
		t.Skip("set AERO_HOST_TUN_TEST=1 (administrator) to run the real adapter test")
	}
}

func winTestPlan(t *testing.T) RoutePlan {
	t.Helper()
	plan, err := PlanTUNRoutes(RoutePlanInput{
		Direct:  mustPrefixes("1.0.0.0/8"),
		Bypass:  []netip.Addr{netip.MustParseAddr("9.9.9.9")},
		Capture: []netip.Addr{netip.MustParseAddr("192.168.77.1")},
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func adapterExists(name string) bool {
	_, err := net.InterfaceByName(name)
	return err == nil
}

func hasRoute(luid winipcfg.LUID, p string) bool {
	pfx := netip.MustParsePrefix(p)
	_, err := luid.Route(pfx, unspecifiedFor(pfx))
	return err == nil
}

func TestTunHostWindowsLifecycle(t *testing.T) {
	requireHostTunTest(t)
	cfg := tunHostConfig{Name: winTestTun, MTU: 1224, IPv4: netip.MustParsePrefix("10.88.0.2/16"), Plan: winTestPlan(t)}
	start := time.Now()
	th, err := openTunHost(cfg)
	if err != nil {
		t.Fatalf("openTunHost: %v", err)
	}
	t.Logf("adapter + %d routes configured in %v", len(cfg.Plan.IPv4)+len(cfg.Plan.IPv6)+1, time.Since(start))
	h := th.(*windowsTunHost)
	defer h.Close()

	if !adapterExists(winTestTun) {
		t.Fatal("adapter not visible")
	}
	if row, err := h.luid.IPInterface(windows.AF_INET); err != nil || row.NLMTU != 1224 {
		t.Fatalf("IPv4 MTU = %v, err %v; want 1224", row, err)
	}
	if h.ipv6 {
		if row, err := h.luid.IPInterface(windows.AF_INET6); err != nil || row.NLMTU != 1280 {
			t.Fatalf("IPv6 MTU err %v; want 1280", err)
		}
		if !hasRoute(h.luid, "2000::/3") {
			t.Error("IPv6 route 2000::/3 missing")
		}
	}
	for p, want := range map[string]bool{"10.88.0.0/16": true, "192.168.77.1/32": true, "8.0.0.0/7": true} {
		if got := hasRoute(h.luid, p); got != want {
			t.Errorf("route %s present = %v, want %v", p, got, want)
		}
	}

	if err := h.ApplyRoutes(RoutePlan{IPv4: mustPrefixes("8.8.8.0/24")}); err != nil {
		t.Fatalf("ApplyRoutes: %v", err)
	}
	if !hasRoute(h.luid, "8.8.8.0/24") || hasRoute(h.luid, "8.0.0.0/7") {
		t.Fatal("incremental route update not applied")
	}
	if err := h.SetIPv4(netip.MustParsePrefix("10.88.5.9/16")); err != nil {
		t.Fatalf("SetIPv4: %v", err)
	}
	if _, err := h.luid.IPAddress(netip.MustParseAddr("10.88.5.9")); err != nil {
		t.Fatalf("new address missing: %v", err)
	}
	if _, err := h.luid.IPAddress(netip.MustParseAddr("10.88.0.2")); err == nil {
		t.Fatal("old address still present")
	}

	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if adapterExists(winTestTun) {
		t.Fatal("adapter still exists after Close")
	}
}

// 进程被强杀后网卡及其路由必须消失（wintun 网卡生命周期绑定创建它的进程）。
func TestTunHostWindowsNoResidueAfterKill(t *testing.T) {
	if os.Getenv("AERO_TUNHOST_CHILD") == "1" {
		if _, err := openTunHost(tunHostConfig{Name: winTestTun, MTU: 1224, IPv4: netip.MustParsePrefix("10.88.0.2/16"), Plan: winTestPlan(t)}); err != nil {
			t.Fatalf("child openTunHost: %v", err)
		}
		os.Stdout.WriteString("READY\n")
		select {}
	}
	requireHostTunTest(t)
	child := exec.Command(os.Args[0], "-test.run=^TestTunHostWindowsNoResidueAfterKill$", "-test.count=1")
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
	if !adapterExists(winTestTun) {
		_ = child.Process.Kill()
		_ = child.Wait()
		t.Fatal("child did not create the adapter")
	}
	if err := child.Process.Kill(); err != nil { // TerminateProcess，等同强杀
		t.Fatal(err)
	}
	_ = child.Wait()
	deadline := time.Now().Add(10 * time.Second)
	for adapterExists(winTestTun) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if adapterExists(winTestTun) {
		t.Fatal("adapter still exists 10s after the owning process was killed")
	}
}
