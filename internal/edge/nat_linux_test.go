//go:build linux

package edge

import (
	"errors"
	"strings"
	"sync"
	"testing"
)

// fakeLinuxCmds 记录 edge 想要执行的宿主命令，不触碰真实宿主。
type fakeLinuxCmds struct {
	mu       sync.Mutex
	calls    []string
	existing map[string]bool // "-C" 检查时视为已存在的规则（去掉 -C/-I/-A/-D 与链名后的规格）
	failAdd  bool
}

func (f *fakeLinuxCmds) run(name string, args ...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	line := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, line)
	for i, a := range args {
		switch a {
		case "-C":
			if f.existing[ruleKey(name, args, i)] {
				return nil
			}
			return errors.New("rule not found")
		case "-I", "-A":
			if f.failAdd {
				return errors.New("iptables: permission denied")
			}
			return nil
		case "-D":
			delete(f.existing, ruleKey(name, args, i))
			return nil
		}
	}
	return nil
}

// ruleKey 用工具名、表名与规则规格标识一条规则，与操作符（-C/-I/-A/-D）无关。
func ruleKey(name string, args []string, opIndex int) string {
	table := ""
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-t" {
			table = args[i+1]
		}
	}
	spec := args[opIndex+1:]
	return name + "|" + table + "|" + strings.Join(spec, " ")
}

func (f *fakeLinuxCmds) snapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func installFakeLinuxCmds(t *testing.T, f *fakeLinuxCmds) {
	t.Helper()
	prevRunner, prevOut := linuxCmdRunner, defaultOutInterfaceFn
	linuxCmdRunner = f.run
	defaultOutInterfaceFn = func() string { return "eth0" }
	resetAppliedFirewallForTest()
	t.Cleanup(func() {
		linuxCmdRunner, defaultOutInterfaceFn = prevRunner, prevOut
		resetAppliedFirewallForTest()
	})
}

// 未在本进程应用过规则时，Cleanup 不得执行任何宿主命令（测试、未启用 TUN 的进程）。
func TestEdgeFirewallCleanupWithoutApplyTouchesNothing(t *testing.T) {
	f := &fakeLinuxCmds{existing: map[string]bool{}}
	installFakeLinuxCmds(t, f)

	CleanupEdgeFirewall("aero-tun0")
	CleanupEdgeFirewall("")

	if calls := f.snapshot(); len(calls) != 0 {
		t.Fatalf("cleanup without apply ran host commands: %v", calls)
	}
}

// 每条新增规则都必须限定在 edge 的 TUN 接口或 edge 地址池并带标记，不得影响其他服务。
func TestEdgeFirewallRulesAreScopedToTunnelInterface(t *testing.T) {
	f := &fakeLinuxCmds{existing: map[string]bool{}}
	installFakeLinuxCmds(t, f)

	if err := ApplyEdgeFirewall("aero-tun0"); err != nil {
		t.Fatalf("ApplyEdgeFirewall: %v", err)
	}
	adds := 0
	for _, c := range f.snapshot() {
		if !strings.Contains(c, " -I ") && !strings.Contains(c, " -A ") {
			continue
		}
		adds++
		if !strings.Contains(c, "aero-tun0") && !strings.Contains(c, "-s "+edgeIPv4PoolCIDR) && !strings.Contains(c, "-s "+edgeIPv6PoolCIDR) {
			t.Errorf("rule not scoped to aero-tun0 or the edge address pool: %s", c)
		}
		if !strings.Contains(c, "--comment aero_edge_default") {
			t.Errorf("rule missing ownership tag: %s", c)
		}
	}
	if adds == 0 {
		t.Fatal("no rules were added")
	}
}

// 旧版本留下的全局 MSS 钳制规则（不限接口）会影响宿主所有转发连接，必须被移除。
func TestEdgeFirewallRemovesLegacyHostWideMSSRule(t *testing.T) {
	legacy := "FORWARD " + strings.Join(legacyHostWideMSSRule, " ")
	f := &fakeLinuxCmds{existing: map[string]bool{"iptables|mangle|" + legacy: true}}
	installFakeLinuxCmds(t, f)

	if err := ApplyEdgeFirewall("aero-tun0"); err != nil {
		t.Fatalf("ApplyEdgeFirewall: %v", err)
	}
	if f.existing["iptables|mangle|"+legacy] {
		t.Fatal("legacy host-wide MSS rule still present")
	}
}

// 规则添加失败必须返回错误，不得静默报告成功。
func TestEdgeFirewallReportsRuleFailures(t *testing.T) {
	f := &fakeLinuxCmds{existing: map[string]bool{}, failAdd: true}
	installFakeLinuxCmds(t, f)

	if err := ApplyEdgeFirewall("aero-tun0"); err == nil {
		t.Fatal("ApplyEdgeFirewall returned nil although every rule failed")
	}
}

// Apply 之后的 Cleanup 只删除本进程添加的规则，且同样限定在 TUN 接口。
func TestEdgeFirewallCleanupAfterApplyOnlyTouchesOwnRules(t *testing.T) {
	f := &fakeLinuxCmds{existing: map[string]bool{}}
	installFakeLinuxCmds(t, f)

	if err := ApplyEdgeFirewall("aero-tun0"); err != nil {
		t.Fatalf("ApplyEdgeFirewall: %v", err)
	}
	before := len(f.snapshot())
	CleanupEdgeFirewall("")
	for _, c := range f.snapshot()[before:] {
		if strings.Contains(c, " -D ") && !strings.Contains(c, "aero_edge_default") {
			t.Errorf("cleanup deleted an untagged rule: %s", c)
		}
	}
	if len(f.snapshot()) == before {
		t.Fatal("cleanup after apply ran no commands")
	}
}
