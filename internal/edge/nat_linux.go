//go:build linux

// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

// 宿主状态（PROJECT_RULES §8.10 清单）：edge 只添加带 aero_edge_default 标记、
// 且限定在自身 TUN 接口或自身地址池的规则；只清理本进程实际添加过的规则。
const (
	edgeFirewallTag  = "aero_edge_default"
	edgeIPv4PoolCIDR = "10.88.0.0/16"
	edgeIPv6PoolCIDR = "fd88:ae80::/64"
)

// legacyHostWideMSSRule 是 v1.2.40 及以前添加到 mangle/FORWARD 的不限接口 MSS 钳制，
// 会改写宿主上所有转发连接（如 docker）的 MSS，升级后需要移除。
var legacyHostWideMSSRule = []string{"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", "1200", "-m", "comment", "--comment", edgeFirewallTag}

type firewallRule struct {
	tool, table, chain string
	spec               []string
}

var (
	appliedFirewallMu    sync.Mutex
	appliedFirewallRules []firewallRule

	// linuxCmdRunner 与 defaultOutInterfaceFn 可在测试中替换，避免触碰真实宿主。
	linuxCmdRunner        = runLinuxCmdExec
	defaultOutInterfaceFn = detectDefaultOutInterface
)

func runLinuxCmd(name string, args ...string) error {
	return linuxCmdRunner(name, args...)
}

func runLinuxCmdExec(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %v: %w (%s)", name, args, err, strings.TrimSpace(stderr.String()))
	}
	return nil
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
		_ = runLinuxCmd("ip", "addr", "replace", ipv4CIDR, "dev", devName)
	}
	if ipv6CIDR != "" {
		_ = runLinuxCmd("ip", "-6", "addr", "replace", ipv6CIDR, "dev", devName)
	}
	if err := runLinuxCmd("ip", "link", "set", "dev", devName, "mtu", strconv.Itoa(mtu), "up"); err != nil {
		return fmt.Errorf("set dev %s mtu and up: %w", devName, err)
	}
	// 关闭 offload 优化，确保大包分片透明处理
	_ = runLinuxCmd("ethtool", "-K", devName, "gro", "off", "gso", "off", "tso", "off")

	log.Printf("[EDGE-NET] Configured %s (IPv4=%s, IPv6=%s, MTU=%d)", devName, ipv4CIDR, ipv6CIDR, mtu)
	return nil
}

// EnableKernelForwarding 检查并启用 Linux 内核 IPv4 与 IPv6 报文转发能力
func EnableKernelForwarding() error {
	var errs []string
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644); err != nil {
		errs = append(errs, fmt.Sprintf("ipv4 forward: %v", err))
	}
	if err := os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1\n"), 0644); err != nil {
		errs = append(errs, fmt.Sprintf("ipv6 forward: %v", err))
	}
	if len(errs) > 0 {
		return fmt.Errorf("enable forwarding: %s", strings.Join(errs, "; "))
	}
	return nil
}

// TuneKernelPerformance 自主检查并启用 BBR 拥塞控制，并自适应优化内核 socket 缓冲区到 16MB
func TuneKernelPerformance() {
	if cc, err := os.ReadFile("/proc/sys/net/ipv4/tcp_congestion_control"); err == nil {
		if !strings.Contains(string(cc), "bbr") {
			_ = exec.Command("modprobe", "tcp_bbr").Run()
			_ = os.WriteFile("/proc/sys/net/core/default_qdisc", []byte("fq\n"), 0644)
			_ = os.WriteFile("/proc/sys/net/ipv4/tcp_congestion_control", []byte("bbr\n"), 0644)
		}
	}
	_ = os.WriteFile("/proc/sys/net/core/rmem_max", []byte("16777216\n"), 0644)
	_ = os.WriteFile("/proc/sys/net/core/wmem_max", []byte("16777216\n"), 0644)
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

func ruleArgs(r firewallRule, op string) []string {
	var args []string
	if r.table != "" {
		args = append(args, "-t", r.table)
	}
	args = append(args, op, r.chain)
	return append(args, r.spec...)
}

// ensureRule 仅在规则不存在时添加（幂等），返回添加失败的错误。
func ensureRule(r firewallRule, addOp string) error {
	if err := runLinuxCmd(r.tool, ruleArgs(r, "-C")...); err == nil {
		return nil
	}
	return runLinuxCmd(r.tool, ruleArgs(r, addOp)...)
}

// deleteRuleIfExists 删除规则的全部重复副本（上限 5 次，防止无限循环）。
func deleteRuleIfExists(r firewallRule) {
	for i := 0; i < 5; i++ {
		if err := runLinuxCmd(r.tool, ruleArgs(r, "-C")...); err != nil {
			return
		}
		if err := runLinuxCmd(r.tool, ruleArgs(r, "-D")...); err != nil {
			return
		}
	}
}

func tagged(spec ...string) []string {
	return append(spec, "-m", "comment", "--comment", edgeFirewallTag)
}

// ApplyEdgeFirewall 为 edge 的 TUN 配置转发放行、NAT 与 MSS 钳制。全部规则限定在
// devName 或 edge 地址池，不改变宿主其他流量。IPv4 规则失败返回错误；IPv6 规则失败
// 只记录（内层 IPv6 默认关闭，见 ADR-0007）。
func ApplyEdgeFirewall(devName string) error {
	if devName == "" {
		return fmt.Errorf("apply edge firewall: empty device name")
	}
	appliedFirewallMu.Lock()
	defer appliedFirewallMu.Unlock()

	outIf := defaultOutInterfaceFn()
	if outIf == "" || outIf == devName {
		return fmt.Errorf("apply edge firewall: no physical outbound interface detected (outIf=%q)", outIf)
	}

	// 移除旧版本遗留的全局 MSS 钳制，它会影响宿主上所有转发连接。
	deleteRuleIfExists(firewallRule{tool: "iptables", table: "mangle", chain: "FORWARD", spec: legacyHostWideMSSRule})

	mss := func(dir string) []string {
		return tagged(dir, devName, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", "1200")
	}
	v4 := []struct {
		rule firewallRule
		op   string
	}{
		{firewallRule{"iptables", "mangle", "FORWARD", mss("-i")}, "-I"},
		{firewallRule{"iptables", "mangle", "FORWARD", mss("-o")}, "-I"},
		{firewallRule{"iptables", "", "FORWARD", tagged("-i", devName, "-o", outIf, "-j", "ACCEPT")}, "-I"},
		{firewallRule{"iptables", "", "FORWARD", tagged("-i", outIf, "-o", devName, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")}, "-I"},
		{firewallRule{"iptables", "nat", "POSTROUTING", tagged("-s", edgeIPv4PoolCIDR, "-o", outIf, "-j", "MASQUERADE")}, "-A"},
	}
	v6 := []struct {
		rule firewallRule
		op   string
	}{
		{firewallRule{"ip6tables", "", "FORWARD", tagged("-i", devName, "-o", outIf, "-j", "ACCEPT")}, "-I"},
		{firewallRule{"ip6tables", "", "FORWARD", tagged("-i", outIf, "-o", devName, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")}, "-I"},
		{firewallRule{"ip6tables", "nat", "POSTROUTING", tagged("-s", edgeIPv6PoolCIDR, "-o", outIf, "-j", "MASQUERADE")}, "-A"},
	}

	var errs []error
	for _, r := range v4 {
		if err := ensureRule(r.rule, r.op); err != nil {
			errs = append(errs, err)
			continue
		}
		appliedFirewallRules = append(appliedFirewallRules, r.rule)
	}
	for _, r := range v6 {
		if err := ensureRule(r.rule, r.op); err != nil {
			log.Printf("[EDGE-NET] [WARN] IPv6 rule not applied (inner IPv6 stays disabled): %v", err)
			continue
		}
		appliedFirewallRules = append(appliedFirewallRules, r.rule)
	}
	if len(errs) > 0 {
		return fmt.Errorf("apply edge firewall for %s: %w", devName, errors.Join(errs...))
	}
	log.Printf("[EDGE-NET] Firewall rules applied for %s -> %s (scoped to the tunnel interface and edge pools)", devName, outIf)
	return nil
}

// CleanupEdgeFirewall 删除本进程通过 ApplyEdgeFirewall 添加的规则。本进程未添加过
// 规则时不执行任何宿主命令。devName 参数保留以兼容非 Linux 占位签名。
func CleanupEdgeFirewall(devName string) {
	_ = devName
	appliedFirewallMu.Lock()
	defer appliedFirewallMu.Unlock()
	if len(appliedFirewallRules) == 0 {
		return
	}
	for i := len(appliedFirewallRules) - 1; i >= 0; i-- {
		deleteRuleIfExists(appliedFirewallRules[i])
	}
	appliedFirewallRules = nil
	log.Printf("[EDGE-NET] Firewall rules added by this process were removed")
}

// resetAppliedFirewallForTest 清空本进程的规则记录（仅测试使用）。
func resetAppliedFirewallForTest() {
	appliedFirewallMu.Lock()
	appliedFirewallRules = nil
	appliedFirewallMu.Unlock()
}
