// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"fmt"
	"net"
	"net/netip"
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
	Index       uint32 // 接口编号（路由条目按它关联网卡）
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

// ipv4Route 是一条 IPv4 活动路由（Windows 经 GetIPForwardTable2 读取：与系统语言无关，不启动外部进程）。
type ipv4Route struct {
	Dest    netip.Prefix
	NextHop netip.Addr // 无效或 0.0.0.0 表示“在链路上”（如 PPPoE）
	IfIndex uint32     // 0 或不在网卡表中表示孤儿路由
	Metric  uint32     // 路由跃点 + 接口跃点
}

var (
	halfLow  = netip.MustParsePrefix("0.0.0.0/1")
	halfHigh = netip.MustParsePrefix("128.0.0.0/1")
	defRoute = netip.MustParsePrefix("0.0.0.0/0")
)

// ifaceIPv4 返回网卡的第一个 IPv4 地址字符串。
func ifaceIPv4(ifi ifaceSummary) string {
	for _, ip := range ifi.IPs {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String()
		}
	}
	return ""
}

// evaluateThirdPartyTUN 纯函数判定：是否有第三方 TUN/VPN 正在接管流量。
func evaluateThirdPartyTUN(ifaces []ifaceSummary, routes []ipv4Route) (bool, string) {
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
	byIndex := make(map[uint32]ifaceSummary, len(ifaces))
	for _, ifi := range ifaces {
		byIndex[ifi.Index] = ifi
	}

	// 条件 2a：任何非 aero0 的 0.0.0.0/1 或 128.0.0.0/1 路由（孤儿路由同样拦截）
	for _, r := range routes {
		if r.Dest != halfLow && r.Dest != halfHigh {
			continue
		}
		ifi, ok := byIndex[r.IfIndex]
		if !ok || r.IfIndex == 0 {
			return true, "未知网卡"
		}
		if strings.EqualFold(ifi.Name, "aero0") || isAeroTunAddr(ifaceIPv4(ifi)) {
			continue
		}
		if ifi.Name != "" {
			return true, ifi.Name
		}
		return true, "第三方 TUN"
	}

	// 条件 2b：0.0.0.0/0 默认路由若由虚拟网卡（isVirtualAdapter）持有，判定为 VPN 接管
	for _, r := range routes {
		if r.Dest != defRoute {
			continue
		}
		ifi, ok := byIndex[r.IfIndex]
		if !ok || r.IfIndex == 0 || isAeroTunAddr(ifaceIPv4(ifi)) {
			continue // 孤儿 /0 忽略，防止 DHCP 换 IP 瞬间误伤
		}
		if isVirtualAdapter(ifi) {
			if ifi.Name != "" {
				return true, ifi.Name
			}
			return true, ifaceIPv4(ifi)
		}
	}
	return false, ""
}

// physicalDefaultGateway 从路由条目中选出物理默认网关（排除虚拟/VPN 网卡、本程序与保留地址），取跃点最小者。
// “在链路上”的默认路由（如 PPPoE）以网卡自身地址作为下一跳。返回下一跳与接口编号。
func physicalDefaultGateway(ifaces []ifaceSummary, routes []ipv4Route) (gw, ifIndex string, err error) {
	byIndex := make(map[uint32]ifaceSummary, len(ifaces))
	for _, ifi := range ifaces {
		byIndex[ifi.Index] = ifi
	}
	isBlacklisted := func(ipStr string) bool {
		return strings.HasPrefix(ipStr, "198.18.") ||
			strings.HasPrefix(ipStr, "198.19.") ||
			strings.HasPrefix(ipStr, "10.88.") ||
			strings.HasPrefix(ipStr, "127.") ||
			strings.HasPrefix(ipStr, "169.254.")
	}
	var best ipv4Route
	bestGW, found := "", false
	for _, r := range routes {
		ifi, ok := byIndex[r.IfIndex]
		if r.Dest != defRoute || !ok || r.IfIndex == 0 || isVirtualAdapter(ifi) {
			continue
		}
		ifIP := ifaceIPv4(ifi)
		cand := ifIP
		if r.NextHop.IsValid() && !r.NextHop.IsUnspecified() {
			cand = r.NextHop.String()
		}
		if ifIP == "" || isBlacklisted(cand) || isBlacklisted(ifIP) {
			continue
		}
		if !found || r.Metric < best.Metric {
			best, bestGW, found = r, cand, true
		}
	}
	if !found {
		return "", "", fmt.Errorf("no physical default gateway")
	}
	return bestGW, strconv.FormatUint(uint64(best.IfIndex), 10), nil
}
