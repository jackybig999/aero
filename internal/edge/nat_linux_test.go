//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package edge

import (
	"errors"
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

// useNftBackend 让测试走 nft 后端（模拟没有 iptables 的宿主，如 Debian 13 默认）。
func useNftBackend(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not available")
	}
	prev := lookPath
	lookPath = func(name string) (string, error) {
		if name == "iptables" || name == "ip6tables" {
			return "", exec.ErrNotFound
		}
		return exec.LookPath(name)
	}
	t.Cleanup(func() { lookPath = prev })
}

func nftTable(t *testing.T) string {
	t.Helper()
	out, _ := hostCmd("nft", "list", "table", "inet", edgeNftTable)
	return out
}

// 无 iptables 的宿主：规则只在自有表 inet aero_edge 中；还原删除整表并还原 ip_forward；
// 宿主自己的 nft 表不受影响；崩溃后重启不重复。
func TestHostStateLifecycleNftOnly(t *testing.T) {
	if !inNetns(t) {
		return
	}
	useNftBackend(t)
	useTestOutIf(t)
	dir := t.TempDir()
	setIPForward(t, "0")
	if err := runHostCmd("nft", "add", "table", "inet", "host_own"); err != nil {
		t.Fatal(err)
	}
	if err := PrepareHostForTunnel(dir, testTun); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	tbl := nftTable(t)
	for _, want := range []string{"masquerade", "maxseg size set 1200", `iifname "aero-tun0" oifname "eth9" accept`, "drop", edgeIPv4PoolCIDR} {
		if !strings.Contains(tbl, want) {
			t.Errorf("table missing %q:\n%s", want, tbl)
		}
	}
	if ipForward(t) != "1" {
		t.Fatal("ip_forward not enabled")
	}
	if err := PrepareHostForTunnel(dir, testTun); err != nil { // 模拟崩溃后重启
		t.Fatal(err)
	}
	if again := nftTable(t); strings.Count(again, "masquerade") != strings.Count(tbl, "masquerade") {
		t.Fatalf("rules duplicated after restart:\n%s", again)
	}
	if err := RestoreHost(dir); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if nftTable(t) != "" || ipForward(t) != "0" {
		t.Fatalf("not restored: table=%q ip_forward=%s", nftTable(t), ipForward(t))
	}
	if out, err := hostCmd("nft", "list", "table", "inet", "host_own"); err != nil || out == "" {
		t.Fatal("host's own nft table was touched")
	}
	if err := RestoreHost(dir); err != nil {
		t.Fatalf("second restore: %v", err)
	}
}

// 宿主原本开启转发：nft 后端不添加隔离 drop。
func TestHostStateNftNoIsolationWhenForwardingOn(t *testing.T) {
	if !inNetns(t) {
		return
	}
	useNftBackend(t)
	useTestOutIf(t)
	dir := t.TempDir()
	setIPForward(t, "1")
	if err := PrepareHostForTunnel(dir, testTun); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(nftTable(t), "drop") {
		t.Fatal("isolation added although forwarding was on")
	}
	if err := RestoreHost(dir); err != nil || ipForward(t) != "1" {
		t.Fatalf("restore: %v ip_forward=%s", err, ipForward(t))
	}
}

func TestValidIfName(t *testing.T) {
	for n, want := range map[string]bool{"eth0": true, "aero-tun0": true, "ens3.100": true, "": false, `a"b`: false, "a b": false, "abcdefghijklmnop": false} {
		if validIfName(n) != want {
			t.Errorf("%q", n)
		}
	}
}

// useBootID 把 boot_id 来源换成临时文件；id 为空表示文件不存在（读取失败）。
func useBootID(t *testing.T, id string) {
	t.Helper()
	prev := bootIDPath
	bootIDPath = filepath.Join(t.TempDir(), "boot_id")
	if id != "" {
		if err := os.WriteFile(bootIDPath, []byte(id+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { bootIDPath = prev })
}

// 宿主在 edge 运行期间重启（断电/内核崩溃）：ip_forward 已由宿主自己重新设置，RestoreHost 不得改回
// 日志里的原值；edge 自己的规则与日志照常清理。
func TestRestoreHostAfterRebootKeepsIPForward(t *testing.T) {
	if !inNetns(t) {
		return
	}
	requireIptables(t)
	useTestOutIf(t)
	useBootID(t, "boot-A")
	dir := t.TempDir()
	setIPForward(t, "0")
	if err := PrepareHostForTunnel(dir, testTun); err != nil {
		t.Fatal(err)
	}
	if j, ok, err := readHostState(dir); err != nil || !ok || j.BootID != "boot-A" || j.IPv4Forward != "0" {
		t.Fatalf("journal = %+v ok=%v err=%v", j, ok, err)
	}
	// 重启后：宿主 sysctl/docker 把转发设为 1，boot_id 变了；edge 的规则假定仍在（此处未被重置）
	useBootID(t, "boot-B")
	setIPForward(t, "1")
	if err := RestoreHost(dir); err != nil {
		t.Fatalf("RestoreHost: %v", err)
	}
	if got := ipForward(t); got != "1" {
		t.Fatalf("ip_forward = %s after restore across reboot, want host value 1 untouched", got)
	}
	if left := rulesWith(t, edgeFirewallTag); len(left) != 0 {
		t.Fatalf("tagged rules left:\n%s", strings.Join(left, "\n"))
	}
	if _, err := os.Stat(filepath.Join(dir, hostStateFile)); !os.IsNotExist(err) {
		t.Fatalf("journal still present (err=%v)", err)
	}
}

// 同一次启动内（崩溃后重启 edge）、旧版本日志（无 boot_id）、boot_id 读不到：仍按日志还原原值。
func TestRestoreHostRestoresIPForwardWhenBootUnchangedOrUnknown(t *testing.T) {
	if !inNetns(t) {
		return
	}
	requireIptables(t)
	useTestOutIf(t)
	for name, tc := range map[string]struct{ journalBoot, nowBoot string }{
		"same boot":          {"boot-A", "boot-A"},
		"legacy journal":     {"", "boot-B"},
		"boot id unreadable": {"boot-A", ""},
	} {
		dir := t.TempDir()
		useBootID(t, tc.nowBoot)
		setIPForward(t, "1")
		raw := `{"ipv4_forward":"0"}`
		if tc.journalBoot != "" {
			raw = `{"ipv4_forward":"0","boot_id":"` + tc.journalBoot + `"}`
		}
		if err := os.WriteFile(filepath.Join(dir, hostStateFile), []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := RestoreHost(dir); err != nil {
			t.Fatalf("%s: RestoreHost: %v", name, err)
		}
		if got := ipForward(t); got != "0" {
			t.Errorf("%s: ip_forward = %s, want restored 0", name, got)
		}
	}
}

func TestWaitArgsForVersion(t *testing.T) {
	for out, want := range map[string]string{
		"iptables v1.8.11 (nf_tables)\n": "-w 5",
		"ip6tables v1.8.4 (legacy)":      "-w 5",
		"iptables v1.6.0":                "-w 5",
		"iptables v1.4.21":               "-w",
		"iptables v1.4.20":               "-w",
		"iptables v1.4.7":                "",
		"garbage":                        "-w 5",
	} {
		if got := strings.Join(waitArgsForVersion(out), " "); got != want {
			t.Errorf("waitArgsForVersion(%q) = %q, want %q", out, got, want)
		}
	}
}

// fakeHostTools 替换 hostCmd 与 lookPath（全部不触碰宿主）：installed 列出“已安装”的工具，
// handler 返回对应命令的输出与错误；返回收集到的调用记录。
func fakeHostTools(t *testing.T, installed []string, handler func(name string, args []string) (string, error)) *[]string {
	t.Helper()
	prevCmd, prevLook := hostCmd, lookPath
	var calls []string
	hostCmd = func(name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return handler(name, args)
	}
	lookPath = func(name string) (string, error) {
		for _, n := range installed {
			if n == name {
				return "/fake/" + name, nil
			}
		}
		return "", exec.ErrNotFound
	}
	xtWaitMu.Lock()
	xtWaitCache = map[string][]string{}
	xtWaitMu.Unlock()
	t.Cleanup(func() {
		hostCmd, lookPath = prevCmd, prevLook
		xtWaitMu.Lock()
		xtWaitCache = map[string][]string{}
		xtWaitMu.Unlock()
	})
	return &calls
}

// 所有 iptables/ip6tables 调用都带 -w 5，宿主上其他程序持有 xtables 锁时等待而不是立即失败。
func TestRestoreHostUsesXtablesWait(t *testing.T) {
	calls := fakeHostTools(t, []string{"iptables", "ip6tables"}, func(name string, args []string) (string, error) {
		if len(args) > 0 && args[len(args)-1] == "--version" {
			return name + " v1.8.11 (nf_tables)\n", nil
		}
		if args[len(args)-2] == "-S" && args[len(args)-1] == "FORWARD" && args[len(args)-3] == "filter" {
			return "-P FORWARD ACCEPT\n-A FORWARD -i aero-tun0 -m comment --comment aero_edge_default -j ACCEPT\n", nil
		}
		return "", nil
	})
	if err := RestoreHost(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	deletes := 0
	for _, c := range *calls {
		if strings.HasSuffix(c, "--version") {
			continue
		}
		if !strings.HasPrefix(c, "iptables -w 5 ") && !strings.HasPrefix(c, "ip6tables -w 5 ") {
			t.Errorf("call without -w 5: %s", c)
		}
		if strings.Contains(c, " -D ") {
			deletes++
		}
	}
	if deletes != 2 { // iptables 与 ip6tables 的 filter/FORWARD 各一条
		t.Fatalf("delete calls = %d, want 2: %v", deletes, *calls)
	}
}

// ip6tables 已安装但还原失败必须报告；未安装则跳过。
func TestRestoreHostReportsIp6tablesFailure(t *testing.T) {
	fail := func(name string, args []string) (string, error) {
		if name == "ip6tables" && len(args) >= 2 && args[len(args)-2] == "-S" {
			return "", errors.New("ip6tables: exit status 4 (Resource temporarily unavailable)")
		}
		return "", nil
	}
	fakeHostTools(t, []string{"iptables", "ip6tables"}, fail)
	err := RestoreHost(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "ip6tables") {
		t.Fatalf("RestoreHost = %v, want ip6tables failure reported", err)
	}
	fakeHostTools(t, []string{"iptables"}, fail)
	if err := RestoreHost(t.TempDir()); err != nil {
		t.Fatalf("RestoreHost without ip6tables installed = %v, want nil", err)
	}
}

// 全新安装：数据目录不存在时 cleanup-host 视为无需还原 ip_forward，不报错、不创建目录，
// 但仍调用 RestoreHost 回收可能残留的规则。
func TestCleanupHostMissingDataDir(t *testing.T) {
	calls := fakeHostTools(t, []string{"iptables"}, func(name string, args []string) (string, error) {
		return "", nil
	})
	dir := filepath.Join(t.TempDir(), "never-created")
	if err := CleanupHost(dir); err != nil {
		t.Fatalf("CleanupHost on missing dir = %v, want nil", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("CleanupHost created the data dir (err=%v)", err)
	}
	if len(*calls) == 0 {
		t.Fatal("tagged rules scan was skipped for a missing data dir")
	}
}

// 内核禁用 IPv6：ip6tables 已安装但 -S 必然失败，这不应使 RestoreHost（进而 edge 启动/cleanup）失败；
// IPv6 可用时同样的失败仍报告；删除（-D）失败始终报告。
func TestRestoreHostIp6tablesListFailureWithIPv6Disabled(t *testing.T) {
	listFail := func(name string, args []string) (string, error) {
		if name == "ip6tables" && len(args) >= 2 && args[len(args)-2] == "-S" {
			return "", errors.New("ip6tables: can't initialize ip6tables table `filter'")
		}
		return "", nil
	}
	prev := ipv6ProcPaths
	t.Cleanup(func() { ipv6ProcPaths = prev })
	missing := filepath.Join(t.TempDir(), "no-ipv6")
	present := t.TempDir()

	ipv6ProcPaths = []string{missing, present}
	fakeHostTools(t, []string{"iptables", "ip6tables"}, listFail)
	if err := RestoreHost(t.TempDir()); err != nil {
		t.Fatalf("IPv6 disabled + ip6tables -S failure: RestoreHost = %v, want nil", err)
	}

	ipv6ProcPaths = []string{present, present}
	fakeHostTools(t, []string{"iptables", "ip6tables"}, listFail)
	if err := RestoreHost(t.TempDir()); err == nil || !strings.Contains(err.Error(), "ip6tables") {
		t.Fatalf("IPv6 available + ip6tables -S failure: RestoreHost = %v, want error", err)
	}

	// 删除失败：即使 IPv6 不可用也必须报告
	ipv6ProcPaths = []string{missing, present}
	fakeHostTools(t, []string{"ip6tables"}, func(name string, args []string) (string, error) {
		switch {
		case len(args) > 0 && args[len(args)-1] == "--version":
			return "ip6tables v1.8.11 (nf_tables)", nil
		case len(args) >= 2 && args[len(args)-2] == "-S":
			return "-A FORWARD -m comment --comment aero_edge_default -j ACCEPT\n", nil
		}
		return "", errors.New("delete failed")
	})
	if err := RestoreHost(t.TempDir()); err == nil {
		t.Fatal("ip6tables -D failure swallowed")
	}
}
