//go:build linux

// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

var (
	appliedFirewallMu sync.Mutex
	appliedFirewallDev string
	appliedOutInterface string
)

func runLinuxCmd(name string, args ...string) error {
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

// ensureRule 仅在规则不存在时才添加，保证严格幂等，避免重复添加
func ensureRule(tool string, table string, addFlag string, chain string, spec ...string) {
	var checkArgs []string
	if table != "" {
		checkArgs = append(checkArgs, "-t", table)
	}
	checkArgs = append(checkArgs, "-C", chain)
	checkArgs = append(checkArgs, spec...)

	if err := runLinuxCmd(tool, checkArgs...); err != nil {
		var addArgs []string
		if table != "" {
			addArgs = append(addArgs, "-t", table)
		}
		addArgs = append(addArgs, addFlag, chain)
		addArgs = append(addArgs, spec...)
		_ = runLinuxCmd(tool, addArgs...)
	}
}

// deleteRuleIfExists 删除指定规则（循环直至全部删除，防止历史残留重复项）
func deleteRuleIfExists(tool string, table string, chain string, spec ...string) {
	for i := 0; i < 5; i++ {
		var checkArgs []string
		if table != "" {
			checkArgs = append(checkArgs, "-t", table)
		}
		checkArgs = append(checkArgs, "-C", chain)
		checkArgs = append(checkArgs, spec...)
		if err := runLinuxCmd(tool, checkArgs...); err != nil {
			break
		}
		var delArgs []string
		if table != "" {
			delArgs = append(delArgs, "-t", table)
		}
		delArgs = append(delArgs, "-D", chain)
		delArgs = append(delArgs, spec...)
		_ = runLinuxCmd(tool, delArgs...)
	}
}

// ApplyEdgeFirewall 为服务端 TUN 虚拟网卡配置双栈 MASQUERADE、转发放行与 TCP MSS 钳制
func ApplyEdgeFirewall(devName string) error {
	appliedFirewallMu.Lock()
	defer appliedFirewallMu.Unlock()

	outIf := detectDefaultOutInterface()
	if outIf == "" || outIf == devName {
		log.Printf("[EDGE-NET] [WARN] Could not detect valid physical outbound interface (outIf=%q)", outIf)
		return nil
	}

	appliedFirewallDev = devName
	appliedOutInterface = outIf

	// 1. TCP MSS 双向钳制至 1200
	ensureRule("iptables", "mangle", "-I", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", "1200", "-m", "comment", "--comment", "aero_edge_default")

	// 2. IPv4 转发与 MASQUERADE
	ensureRule("iptables", "", "-I", "FORWARD", "-i", devName, "-o", outIf, "-m", "comment", "--comment", "aero_edge_default", "-j", "ACCEPT")
	ensureRule("iptables", "", "-I", "FORWARD", "-i", outIf, "-o", devName, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-m", "comment", "--comment", "aero_edge_default", "-j", "ACCEPT")
	ensureRule("iptables", "nat", "-A", "POSTROUTING", "-s", "10.88.0.0/16", "-o", outIf, "-m", "comment", "--comment", "aero_edge_default", "-j", "MASQUERADE")

	// 3. IPv6 转发与 MASQUERADE (解决双栈黑洞)
	ensureRule("ip6tables", "", "-I", "FORWARD", "-i", devName, "-o", outIf, "-m", "comment", "--comment", "aero_edge_default", "-j", "ACCEPT")
	ensureRule("ip6tables", "", "-I", "FORWARD", "-i", outIf, "-o", devName, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-m", "comment", "--comment", "aero_edge_default", "-j", "ACCEPT")
	ensureRule("ip6tables", "nat", "-A", "POSTROUTING", "-s", "fd88:ae80::/64", "-o", outIf, "-m", "comment", "--comment", "aero_edge_default", "-j", "MASQUERADE")

	log.Printf("[EDGE-NET] Applied dual-stack firewall for %s -> %s (IPv4+IPv6 MASQUERADE, MSS=1200)", devName, outIf)
	return nil
}

// CleanupEdgeFirewall 服务端退出时对称清理注入的防火墙与 NAT 规则
func CleanupEdgeFirewall(devName string) {
	appliedFirewallMu.Lock()
	defer appliedFirewallMu.Unlock()

	outIf := appliedOutInterface
	if outIf == "" {
		outIf = detectDefaultOutInterface()
	}
	if devName == "" {
		devName = appliedFirewallDev
	}
	if devName == "" {
		devName = "aero-tun0"
	}

	if outIf != "" {
		deleteRuleIfExists("iptables", "", "FORWARD", "-i", devName, "-o", outIf, "-m", "comment", "--comment", "aero_edge_default", "-j", "ACCEPT")
		deleteRuleIfExists("iptables", "", "FORWARD", "-i", outIf, "-o", devName, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-m", "comment", "--comment", "aero_edge_default", "-j", "ACCEPT")
		deleteRuleIfExists("iptables", "nat", "POSTROUTING", "-s", "10.88.0.0/16", "-o", outIf, "-m", "comment", "--comment", "aero_edge_default", "-j", "MASQUERADE")

		deleteRuleIfExists("ip6tables", "", "FORWARD", "-i", devName, "-o", outIf, "-m", "comment", "--comment", "aero_edge_default", "-j", "ACCEPT")
		deleteRuleIfExists("ip6tables", "", "FORWARD", "-i", outIf, "-o", devName, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-m", "comment", "--comment", "aero_edge_default", "-j", "ACCEPT")
		deleteRuleIfExists("ip6tables", "nat", "POSTROUTING", "-s", "fd88:ae80::/64", "-o", outIf, "-m", "comment", "--comment", "aero_edge_default", "-j", "MASQUERADE")
	}
	deleteRuleIfExists("iptables", "mangle", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", "1200", "-m", "comment", "--comment", "aero_edge_default")

	log.Printf("[EDGE-NET] Cleaned up firewall rules for %s dev %s", outIf, devName)
}
