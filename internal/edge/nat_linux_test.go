//go:build linux

package edge

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// 宿主状态测试（ADR-0012）在独立网络命名空间中使用真实 iptables 与 ip_forward；宿主不受影响。

const testTun, testOutIf = "aero-tun0", "eth9"

func useTestOutIf(t *testing.T) {
	t.Helper()
	prev := defaultOutInterfaceFn
	defaultOutInterfaceFn = func() string { return testOutIf }
	t.Cleanup(func() { defaultOutInterfaceFn = prev })
}

func setIPForward(t *testing.T, v string) {
	t.Helper()
	if err := os.WriteFile(ipForwardPath, []byte(v+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func ipForward(t *testing.T) string {
	t.Helper()
	v, err := readIPForward()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// rulesWith 返回所有 edge 相关链中包含 substr 的规则行。
func rulesWith(t *testing.T, substr string) []string {
	t.Helper()
	var out []string
	for _, c := range edgeRuleChains {
		s, err := hostCmd(c.tool, "-t", c.table, "-S", c.chain)
		if err != nil {
			if c.tool == "ip6tables" {
				continue
			}
			t.Fatal(err)
		}
		for _, l := range strings.Split(s, "\n") {
			if strings.Contains(l, substr) {
				out = append(out, c.tool+" "+c.table+" "+l)
			}
		}
	}
	return out
}

func requireIptables(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("iptables"); err != nil {
		t.Skip("iptables not available")
	}
}

func TestHostStateLifecycleForwardingOff(t *testing.T) {
	if !inNetns(t) {
		return
	}
	requireIptables(t)
	useTestOutIf(t)
	dir := t.TempDir()
	setIPForward(t, "0")
	// 不属于 edge 的规则：任何时候都不得被改动
	if err := runHostCmd("iptables", "-A", "FORWARD", "-i", "docker0", "-j", "ACCEPT"); err != nil {
		t.Fatal(err)
	}

	if err := PrepareHostForTunnel(dir, testTun); err != nil {
		t.Fatalf("PrepareHostForTunnel: %v", err)
	}
	if got := ipForward(t); got != "1" {
		t.Fatalf("ip_forward = %s after prepare, want 1", got)
	}
	if j, ok, err := readHostState(dir); err != nil || !ok || j.IPv4Forward != "0" {
		t.Fatalf("journal = %+v ok=%v err=%v, want original 0", j, ok, err)
	}
	tagged := rulesWith(t, edgeFirewallTag)
	joined := strings.Join(tagged, "\n")
	for _, want := range []string{"MASQUERADE", "TCPMSS", "-j DROP", "-i " + testTun + " -o " + testOutIf} {
		if !strings.Contains(joined, want) {
			t.Errorf("rule containing %q missing:\n%s", want, joined)
		}
	}
	for _, l := range tagged { // 每条规则都必须限定在本 TUN 或本地址池
		if !strings.Contains(l, testTun) && !strings.Contains(l, edgeIPv4PoolCIDR) && !strings.Contains(l, edgeIPv6PoolCIDR) {
			t.Errorf("rule not scoped to the tunnel or pool: %s", l)
		}
	}

	// 模拟崩溃：不还原就再次启动。日志必须保留原值 0（当前读到的 1 是上次写入的），规则不得重复。
	if err := PrepareHostForTunnel(dir, testTun); err != nil {
		t.Fatalf("second PrepareHostForTunnel: %v", err)
	}
	if j, _, _ := readHostState(dir); j.IPv4Forward != "0" {
		t.Fatalf("journal original overwritten to %s after restart", j.IPv4Forward)
	}
	if again := rulesWith(t, edgeFirewallTag); len(again) != len(tagged) {
		t.Fatalf("rules after restart = %d, want %d (no duplicates)", len(again), len(tagged))
	}

	if err := RestoreHost(dir); err != nil {
		t.Fatalf("RestoreHost: %v", err)
	}
	if got := ipForward(t); got != "0" {
		t.Fatalf("ip_forward = %s after restore, want 0", got)
	}
	if left := rulesWith(t, edgeFirewallTag); len(left) != 0 {
		t.Fatalf("tagged rules left after restore:\n%s", strings.Join(left, "\n"))
	}
	if _, err := os.Stat(filepath.Join(dir, hostStateFile)); !os.IsNotExist(err) {
		t.Fatalf("journal still present after restore (err=%v)", err)
	}
	if len(rulesWith(t, "docker0")) != 1 {
		t.Fatal("foreign rule was modified")
	}
	if err := RestoreHost(dir); err != nil { // 幂等
		t.Fatalf("second RestoreHost: %v", err)
	}
}

// 宿主原本已开启转发（如运行 docker）：不得添加隔离规则，还原后仍为 1。
func TestHostStateLifecycleForwardingOn(t *testing.T) {
	if !inNetns(t) {
		return
	}
	requireIptables(t)
	useTestOutIf(t)
	dir := t.TempDir()
	setIPForward(t, "1")
	if err := PrepareHostForTunnel(dir, testTun); err != nil {
		t.Fatalf("PrepareHostForTunnel: %v", err)
	}
	if drops := rulesWith(t, "-j DROP"); len(drops) != 0 {
		t.Fatalf("isolation rule added although forwarding was already on:\n%s", strings.Join(drops, "\n"))
	}
	if err := RestoreHost(dir); err != nil {
		t.Fatal(err)
	}
	if got := ipForward(t); got != "1" {
		t.Fatalf("ip_forward = %s after restore, want original 1", got)
	}
}

// 旧版本（≤1.2.40）遗留的不限接口 MSS 规则同样带本标记，启动回收时一并删除。
func TestHostStateRemovesLegacyRules(t *testing.T) {
	if !inNetns(t) {
		return
	}
	requireIptables(t)
	useTestOutIf(t)
	if err := runHostCmd("iptables", "-t", "mangle", "-A", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS", "--set-mss", "1200", "-m", "comment", "--comment", edgeFirewallTag); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := PrepareHostForTunnel(dir, testTun); err != nil {
		t.Fatal(err)
	}
	for _, l := range rulesWith(t, "TCPMSS") {
		if !strings.Contains(l, testTun) {
			t.Fatalf("legacy host-wide MSS rule survived: %s", l)
		}
	}
	if err := RestoreHost(dir); err != nil {
		t.Fatal(err)
	}
}

// edge 运行中（实例锁被占用）时 cleanup-host 必须拒绝，不得删除运行中实例的规则。
func TestCleanupHostRefusesWhileRunning(t *testing.T) {
	dir := t.TempDir()
	lock, err := acquireInstanceLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.release()
	if err := CleanupHost(dir); err == nil || !strings.Contains(err.Error(), "running") {
		t.Fatalf("CleanupHost with lock held = %v, want refusal", err)
	}
}

func TestHostStateJournalValidation(t *testing.T) {
	dir := t.TempDir()
	if _, ok, err := readHostState(dir); ok || err != nil {
		t.Fatalf("missing journal: ok=%v err=%v", ok, err)
	}
	if err := os.WriteFile(filepath.Join(dir, hostStateFile), []byte(`{"ipv4_forward":"7"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readHostState(dir); err == nil {
		t.Fatal("corrupt journal accepted")
	}
}

func TestHasTag(t *testing.T) {
	for line, want := range map[string]bool{
		"-A FORWARD -i aero-tun0 -m comment --comment aero_edge_default -j ACCEPT":   true,
		`-A FORWARD -i aero-tun0 -m comment --comment "aero_edge_default" -j ACCEPT`: true,
		"-A FORWARD -i docker0 -j ACCEPT":                                            false,
		"-A FORWARD -m comment --comment aero_edge_default_other -j ACCEPT":          false,
	} {
		if got := hasTag(strings.Fields(line)); got != want {
			t.Errorf("hasTag(%q) = %v, want %v", line, got, want)
		}
	}
}
