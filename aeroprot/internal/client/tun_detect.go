// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"fmt"
	"net"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

var utunRecordPath = func() string {
	if runtime.GOOS == "darwin" {
		return filepath.Join(GetDataDir(), "utun.name")
	}
	return ""
}

// ErrConflictingTUN 表示检测到第三方 TUN VPN 冲突
type ErrConflictingTUN struct {
	VPNName string
}

func (e *ErrConflictingTUN) Error() string {
	name := e.VPNName
	if name == "" {
		name = "第三方 VPN"
	}
	return fmt.Sprintf("检测到正在运行其他 VPN 的 TUN 模式【%s】，操作系统不支持两款 TUN 同时开启", name)
}

// ifaceSummary 抽象网卡特征（纯内存可测）
type ifaceSummary struct {
	Name        string
	Description string // 驱动描述，如 "Wintun Userspace Tunnel", "TAP-Windows Adapter V9"
	IfType      uint32 // NDIS 接口类型：53 (虚拟), 131 (隧道), 6 (以太网), 71 (Wi-Fi), 23 (PPP)
	IsUp        bool
	IsLoopback  bool
	IPs         []net.IP
}

// isVirtualAdapter 判定是否属于虚拟/TUN/VPN网卡（排除 aero0 自身）
func isVirtualAdapter(ifi ifaceSummary) bool {
	if strings.EqualFold(ifi.Name, "aero0") {
		return false
	}

	desc := strings.ToLower(ifi.Description)
	name := strings.ToLower(ifi.Name)

	// 1. 物理网络、宽带与本地虚拟交换机豁免白名单（绝不误伤）
	if strings.Contains(desc, "wi-fi direct") || strings.Contains(desc, "wifi direct") ||
		strings.Contains(desc, "pppoe") || strings.Contains(name, "pppoe") ||
		strings.Contains(desc, "hyper-v") || strings.Contains(name, "vethernet") {
		return false
	}

	// 2. NDIS 官方定义的虚拟/隧道接口类型 (Wintun, WireGuard, sing-box)
	if ifi.IfType == 53 /* IF_TYPE_PROP_VIRTUAL */ || ifi.IfType == 131 /* IF_TYPE_TUNNEL */ {
		return true
	}

	// 3. PPP 类型 (Type 23)：除 PPPoE 外，全部确定为 Windows 自带 IKEv2/L2TP/SSTP/PPTP VPN！
	if ifi.IfType == 23 /* IF_TYPE_PPP */ {
		return true
	}

	// 4. 驱动描述与网卡名关键词精准匹配（覆盖以太网 Type 6、SoftEther、Cisco、Pulse Secure、深信服、Check Point、TAP-Windows 等）
	vpnKeywords := []string{
		"vpn", "wintun", "wireguard", "tap-windows", "tap0901", "tap v9", "tap-win", "openvpn",
		"cisco", "anyconnect", "globalprotect", "fortinet", "forticlient",
		"tailscale", "zerotier", "softether", "pulse secure", "juniper",
		"sangfor", "easyconnect", "atrust", "checkpoint", "array networks",
		"wan miniport", "tun", "tap",
	}
	for _, kw := range vpnKeywords {
		if matchTokenWord(desc, kw) || matchTokenWord(name, kw) {
			return true
		}
	}

	return false
}

func matchTokenWord(s, token string) bool {
	if strings.Contains(token, "-") || strings.Contains(token, " ") {
		return strings.Contains(s, token)
	}
	if len(token) > 3 {
		return strings.Contains(s, token)
	}
	// 针对短词 ("tun", "tap", "vpn") 进行词边界检查，防止误伤 "tuning" 等正常英文单词
	idx := strings.Index(s, token)
	for idx != -1 {
		leftOK := (idx == 0) || !isLetter(s[idx-1])
		rightEnd := idx + len(token)
		rightOK := (rightEnd == len(s)) || !isLetter(s[rightEnd])
		if leftOK && rightOK {
			return true
		}
		next := strings.Index(s[idx+1:], token)
		if next == -1 {
			break
		}
		idx += 1 + next
	}
	return false
}

func isLetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// evaluateThirdPartyTUN 纯函数判定
func evaluateThirdPartyTUN(ifaces []ifaceSummary, routeTableText string) (bool, string) {
	// 条件 1：扫描活跃网卡是否持有 198.18.0.0/15 (Clash / 透明代理 Fake-IP 保留段)
	for _, ifi := range ifaces {
		if !ifi.IsUp || ifi.IsLoopback || strings.EqualFold(ifi.Name, "aero0") {
			continue
		}
		for _, ip := range ifi.IPs {
			ip4 := ip.To4()
			if ip4 != nil && ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19) {
				name := ifi.Name
				if name == "" {
					name = "Clash/透明代理"
				}
				return true, name
			}
		}
	}

	ipToIface := make(map[string]ifaceSummary)
	for _, ifi := range ifaces {
		for _, ip := range ifi.IPs {
			if ip4 := ip.To4(); ip4 != nil {
				ipToIface[ip4.String()] = ifi
			}
		}
	}

	lines := strings.Split(routeTableText, "\n")

	// 截取 Active Routes 部分，遇到 Persistent Routes 立即中止
	var activeLines []string
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "persistent routes") || strings.Contains(line, "永久路由") || strings.Contains(line, "持久路由") {
			break
		}
		activeLines = append(activeLines, line)
	}

	// 条件 2a：任何非 aero0 的 0.0.0.0/1 或 128.0.0.0/1 路由
	for _, line := range activeLines {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		dest := fields[0]
		mask := fields[1]
		ifIP := fields[3]

		if (dest == "0.0.0.0" && mask == "128.0.0.0") || (dest == "128.0.0.0" && mask == "128.0.0.0") {
			if ifIP == "10.88.0.2" {
				continue
			}
			if ifi, ok := ipToIface[ifIP]; ok {
				if strings.EqualFold(ifi.Name, "aero0") {
					continue
				}
				name := ifi.Name
				if name == "" {
					name = "第三方 TUN"
				}
				return true, name
			}
			// 孤儿 /1 路由未映射到网卡表，同样绝不放行！
			return true, ifIP
		}
	}

	// 条件 2b：0.0.0.0/0 默认路由若由虚拟网卡（isVirtualAdapter）持有，100% 判定为 VPN 接管
	for _, line := range activeLines {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
			ifIP := fields[3]
			if ifIP == "10.88.0.2" {
				continue
			}
			ifi, ok := ipToIface[ifIP]
			if !ok {
				// 未在网卡表中找到的孤儿 /0 忽略，防止 DHCP 换 IP 瞬间误伤
				continue
			}
			if isVirtualAdapter(ifi) {
				name := ifi.Name
				if name == "" {
					name = ifIP
				}
				return true, name
			}
		}
	}

	return false, ""
}

type ipv4Default struct {
	gw      string
	ifaceIP net.IP
	metric  int
}

// physicalDefaultGatewayWithInput 纯函数支持内存桩回测与边界断言
func physicalDefaultGatewayWithInput(summaries []ifaceSummary, routeText string, ifIndexGetter func(net.IP) string) (gw, ifIndex string, err error) {
	ipToIface := make(map[string]ifaceSummary)
	for _, ifi := range summaries {
		for _, ip := range ifi.IPs {
			if ip4 := ip.To4(); ip4 != nil {
				ipToIface[ip4.String()] = ifi
			}
		}
	}

	var best ipv4Default
	bestIdx := ""
	found := false
	for _, line := range strings.Split(routeText, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] != "0.0.0.0" || fields[1] != "0.0.0.0" {
			continue
		}
		cand := fields[2]
		isOnLink := strings.EqualFold(cand, "on-link") || cand == "在链路上"
		candIP := net.ParseIP(cand)
		if candIP == nil && !isOnLink {
			continue
		}
		ifIP := net.ParseIP(fields[3])
		if ifIP == nil || ifIP.To4() == nil {
			continue
		}
		// 若为点对点/在链路直连（如光猫 PPPoE 拨号），物理出口下一跳使用网卡自身 IP 充当
		if isOnLink {
			cand = ifIP.String()
			candIP = ifIP
		}
		isBlacklisted := func(ipStr string) bool {
			return strings.HasPrefix(ipStr, "198.18.") ||
				strings.HasPrefix(ipStr, "198.19.") ||
				strings.HasPrefix(ipStr, "10.88.") ||
				strings.HasPrefix(ipStr, "127.") ||
				strings.HasPrefix(ipStr, "169.254.")
		}
		if isBlacklisted(cand) || isBlacklisted(ifIP.String()) {
			continue
		}
		// 关键防污染判定：持有该默认路由的接口若为虚拟/VPN 网卡，坚决排除！
		if ifi, ok := ipToIface[ifIP.String()]; ok && isVirtualAdapter(ifi) {
			continue
		}
		metric := 9999
		if len(fields) >= 5 {
			if n, err := strconv.Atoi(fields[4]); err == nil {
				metric = n
			}
		}
		idx := ""
		if ifIndexGetter != nil {
			idx = ifIndexGetter(ifIP.To4())
		}
		if idx == "" {
			continue
		}
		if !found || metric < best.metric {
			best = ipv4Default{gw: cand, ifaceIP: ifIP.To4(), metric: metric}
			bestIdx = idx
			found = true
		}
	}
	if !found {
		return "", "", fmt.Errorf("no physical default gateway")
	}
	return best.gw, bestIdx, nil
}
