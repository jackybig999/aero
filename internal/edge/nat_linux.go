//go:build linux

// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// 宿主状态（ADR-0012，PROJECT_RULES“宿主全局状态”）。edge 对宿主的修改只有三类，且都可还原：
//   - iptables 规则：一律带 aero_edge_default 标记、限定在自身 TUN 或自身地址池；
//   - net.ipv4.ip_forward：修改前把原值写入数据目录下的状态日志；
//   - TUN 网卡：非持久，进程退出即由内核删除。
// 还原（RestoreHost）按标记扫描删除规则、按日志还原 ip_forward，不依赖进程内存，因此同时用于
// 正常退出、崩溃后的 systemd ExecStopPost（aero-edge cleanup-host）与下次启动前的残留回收。

const (
	edgeFirewallTag  = "aero_edge_default"
	edgeIPv4PoolCIDR = "10.88.0.0/16"
	edgeIPv6PoolCIDR = "fd88:ae80::/64"
	hostStateFile    = "host-state.json"
)

// edgeRuleChains 是 edge 可能写入规则的全部 (工具, 表, 链)；还原时只扫描这些链。
var edgeRuleChains = []struct{ tool, table, chain string }{
	{"iptables", "filter", "FORWARD"},
	{"iptables", "mangle", "FORWARD"},
	{"iptables", "nat", "POSTROUTING"},
	{"ip6tables", "filter", "FORWARD"},
	{"ip6tables", "nat", "POSTROUTING"},
}

var (
	// 以下入口可在测试中替换。
	hostCmd = func(name string, args ...string) (string, error) {
		cmd := exec.Command(name, args...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			return stdout.String(), fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
		}
		return stdout.String(), nil
	}
	defaultOutInterfaceFn = detectDefaultOutInterface
	ipForwardPath         = "/proc/sys/net/ipv4/ip_forward"
)

func runHostCmd(name string, args ...string) error {
	_, err := hostCmd(name, args...)
	return err
}

// hostStateJournal 是修改前的宿主值。
type hostStateJournal struct {
	IPv4Forward string `json:"ipv4_forward"`
}

// PrepareHostForTunnel 为 CONNECT-IP 准备宿主：先回收上次运行（含崩溃）的残留，再记录 ip_forward 原值、
// 开启 IPv4 转发并下发规则。原值为 0 时额外添加一条只放行本 TUN 的规则，宿主其余接口之间的转发
// 保持原来的“不转发”语义。不开启 IPv6 转发：net.ipv6.conf.all.forwarding=1 会使宿主忽略路由器
// 通告，依赖 SLAAC 的主机可能失去整机 IPv6（内层 IPv6 默认关闭，ADR-0007）。
func PrepareHostForTunnel(dataDir, devName string) error {
	if devName == "" {
		return errors.New("prepare host: empty device name")
	}
	outIf := defaultOutInterfaceFn()
	if outIf == "" || outIf == devName {
		return fmt.Errorf("prepare host: no physical outbound interface detected (outIf=%q)", outIf)
	}
	if err := RestoreHost(dataDir); err != nil {
		return fmt.Errorf("prepare host: reclaim previous state: %w", err)
	}
	orig, err := readIPForward()
	if err != nil {
		return fmt.Errorf("prepare host: %w", err)
	}
	if err := writeHostState(dataDir, hostStateJournal{IPv4Forward: orig}); err != nil {
		return fmt.Errorf("prepare host: %w", err)
	}
	if orig != "1" {
		if err := os.WriteFile(ipForwardPath, []byte("1\n"), 0o644); err != nil {
			return errors.Join(fmt.Errorf("enable ipv4 forwarding: %w", err), RestoreHost(dataDir))
		}
	}
	if err := applyEdgeRules(devName, outIf, orig != "1"); err != nil {
		return errors.Join(err, RestoreHost(dataDir))
	}
	log.Printf("[EDGE-NET] Host prepared for %s -> %s (ip_forward was %s; rules tagged %s)", devName, outIf, orig, edgeFirewallTag)
	return nil
}

// applyEdgeRules 下发转发放行、NAT 与 MSS 钳制，全部限定在 devName 或 edge 地址池。
// isolate 为真时追加：非本 TUN 的转发一律丢弃（宿主原本未开启转发）。IPv6 规则失败只记录。
func applyEdgeRules(devName, outIf string, isolate bool) error {
	tagged := func(spec ...string) []string {
		return append(spec, "-m", "comment", "--comment", edgeFirewallTag)
	}
	mss := func(dir string) []string {
		return tagged(dir, devName, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", "1200")
	}
	type rule struct {
		tool, table, op, chain string
		spec                   []string
	}
	v4 := []rule{
		{"iptables", "mangle", "-I", "FORWARD", mss("-i")},
		{"iptables", "mangle", "-I", "FORWARD", mss("-o")},
		{"iptables", "filter", "-I", "FORWARD", tagged("-i", devName, "-o", outIf, "-j", "ACCEPT")},
		{"iptables", "filter", "-I", "FORWARD", tagged("-i", outIf, "-o", devName, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")},
		{"iptables", "nat", "-A", "POSTROUTING", tagged("-s", edgeIPv4PoolCIDR, "-o", outIf, "-j", "MASQUERADE")},
	}
	if isolate {
		v4 = append(v4, rule{"iptables", "filter", "-A", "FORWARD", tagged("!", "-i", devName, "!", "-o", devName, "-j", "DROP")})
	}
	v6 := []rule{
		{"ip6tables", "filter", "-I", "FORWARD", tagged("-i", devName, "-o", outIf, "-j", "ACCEPT")},
		{"ip6tables", "filter", "-I", "FORWARD", tagged("-i", outIf, "-o", devName, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")},
		{"ip6tables", "nat", "-A", "POSTROUTING", tagged("-s", edgeIPv6PoolCIDR, "-o", outIf, "-j", "MASQUERADE")},
	}
	add := func(r rule) error {
		return runHostCmd(r.tool, append([]string{"-t", r.table, r.op, r.chain}, r.spec...)...)
	}
	var errs []error
	for _, r := range v4 {
		if err := add(r); err != nil {
			errs = append(errs, err)
		}
	}
	for _, r := range v6 {
		if err := add(r); err != nil {
			log.Printf("[EDGE-NET] [WARN] IPv6 rule not applied (inner IPv6 stays disabled): %v", err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("apply edge rules for %s: %w", devName, errors.Join(errs...))
	}
	return nil
}

// RestoreHost 删除全部带本标记的规则，按状态日志还原 ip_forward 并删除日志。幂等；没有日志也没有
// 本标记规则时不修改宿主。ip6tables 不可用时忽略（宿主无 IPv6 防火墙即无本标记规则）。
func RestoreHost(dataDir string) error {
	var errs []error
	removed := 0
	for _, c := range edgeRuleChains {
		n, err := removeTaggedRules(c.tool, c.table, c.chain)
		removed += n
		if err != nil && c.tool == "iptables" {
			errs = append(errs, err)
		}
	}
	j, ok, err := readHostState(dataDir)
	switch {
	case err != nil:
		errs = append(errs, err)
	case ok:
		if cur, rerr := readIPForward(); rerr != nil || cur != j.IPv4Forward {
			if werr := os.WriteFile(ipForwardPath, []byte(j.IPv4Forward+"\n"), 0o644); werr != nil {
				errs = append(errs, fmt.Errorf("restore ipv4 forwarding to %s: %w", j.IPv4Forward, werr))
			}
		}
		if len(errs) == 0 {
			if rerr := os.Remove(filepath.Join(dataDir, hostStateFile)); rerr != nil && !os.IsNotExist(rerr) {
				errs = append(errs, rerr)
			}
		}
	}
	if removed > 0 || ok {
		log.Printf("[EDGE-NET] Host restored: %d tagged rule(s) removed, ip_forward restored=%v", removed, ok)
	}
	return errors.Join(errs...)
}

// removeTaggedRules 按 `-S` 输出删除链中所有带本标记的规则，返回删除条数。
func removeTaggedRules(tool, table, chain string) (int, error) {
	out, err := hostCmd(tool, "-t", table, "-S", chain)
	if err != nil {
		return 0, err
	}
	n := 0
	var errs []error
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "-A" || !hasTag(f) {
			continue
		}
		args := append([]string{"-t", table, "-D"}, f[1:]...)
		if err := runHostCmd(tool, args...); err != nil {
			errs = append(errs, err)
			continue
		}
		n++
	}
	return n, errors.Join(errs...)
}

func hasTag(fields []string) bool {
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "--comment" && strings.Trim(fields[i+1], `"`) == edgeFirewallTag {
			return true
		}
	}
	return false
}

func readIPForward() (string, error) {
	b, err := os.ReadFile(ipForwardPath)
	if err != nil {
		return "", fmt.Errorf("read ipv4 forwarding: %w", err)
	}
	v := strings.TrimSpace(string(b))
	if v != "0" && v != "1" {
		return "", fmt.Errorf("unexpected ip_forward value %q", v)
	}
	return v, nil
}

// writeHostState 原子写入状态日志（0600）。日志已存在时保留原值：那是上次运行修改前的真实原值，
// 当前读到的可能正是上次运行写入的 1。
func writeHostState(dataDir string, j hostStateJournal) error {
	if prev, ok, err := readHostState(dataDir); err != nil {
		return err
	} else if ok {
		j = prev
	}
	b, err := json.Marshal(j)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dataDir, hostStateFile+".tmp-*")
	if err != nil {
		return fmt.Errorf("write host state: %w", err)
	}
	_, werr := tmp.Write(b)
	if werr == nil {
		werr = tmp.Chmod(0o600)
	}
	if werr == nil {
		werr = tmp.Sync()
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(tmp.Name(), filepath.Join(dataDir, hostStateFile))
	}
	if werr != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("write host state: %w", werr)
	}
	return nil
}

func readHostState(dataDir string) (hostStateJournal, bool, error) {
	var j hostStateJournal
	b, err := os.ReadFile(filepath.Join(dataDir, hostStateFile))
	if os.IsNotExist(err) {
		return j, false, nil
	}
	if err != nil {
		return j, false, fmt.Errorf("read host state: %w", err)
	}
	if err := json.Unmarshal(b, &j); err != nil || (j.IPv4Forward != "0" && j.IPv4Forward != "1") {
		return j, false, fmt.Errorf("corrupt host state %s: %q", hostStateFile, b)
	}
	return j, true, nil
}

// ConfigureGlobalTunnelDevice 为服务端全局 TUN 网卡配置双栈 IP 地址、MTU 并将其置为 UP 状态
func ConfigureGlobalTunnelDevice(devName string, ipv4CIDR, ipv6CIDR string, mtu int) error {
	if devName == "" {
		return fmt.Errorf("device name is empty")
	}
	if mtu <= 0 {
		mtu = 1360
	}

	if ipv4CIDR != "" {
		_ = runHostCmd("ip", "addr", "replace", ipv4CIDR, "dev", devName)
	}
	if ipv6CIDR != "" {
		_ = runHostCmd("ip", "-6", "addr", "replace", ipv6CIDR, "dev", devName)
	}
	if err := runHostCmd("ip", "link", "set", "dev", devName, "mtu", strconv.Itoa(mtu), "up"); err != nil {
		return fmt.Errorf("set dev %s mtu and up: %w", devName, err)
	}
	// 关闭 offload 优化，确保大包分片透明处理
	_ = runHostCmd("ethtool", "-K", devName, "gro", "off", "gso", "off", "tso", "off")

	log.Printf("[EDGE-NET] Configured %s (IPv4=%s, IPv6=%s, MTU=%d)", devName, ipv4CIDR, ipv6CIDR, mtu)
	return nil
}

// detectDefaultOutInterface 自动探测宿主机物理默认出站网卡
func detectDefaultOutInterface() string {
	out, err := exec.Command("ip", "route", "show", "default").CombinedOutput()
	if err == nil {
		fields := strings.Fields(string(out))
		for i, f := range fields {
			if f == "dev" && i+1 < len(fields) {
				return fields[i+1]
			}
		}
	}
	out4, err4 := exec.Command("ip", "-4", "route", "get", "8.8.8.8").CombinedOutput()
	if err4 == nil {
		fields := strings.Fields(string(out4))
		for i, f := range fields {
			if f == "dev" && i+1 < len(fields) {
				return fields[i+1]
			}
		}
	}
	return ""
}
