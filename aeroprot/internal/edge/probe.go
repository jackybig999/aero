// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"fmt"
	"net"
	"net/netip"
)

// ProbeHostPublicIPv6 检索宿主机物理出口网卡上的真实全局可路由 IPv6 前缀 (方案 §3.1)
func ProbeHostPublicIPv6() (netip.Prefix, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return netip.Prefix{}, err
	}
	for _, a := range addrs {
		if ipNet, ok := a.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() == nil {
				addr, ok := netip.AddrFromSlice(ipNet.IP)
				if !ok {
					continue
				}
				// 必须是全球单播地址且排除私有/ULA (fc00::/7) 与链路本地 (fe80::/10)
				if addr.IsGlobalUnicast() && !addr.IsPrivate() && !addr.IsLinkLocalUnicast() {
					ones, _ := ipNet.Mask.Size()
					if ones >= 48 && ones <= 64 {
						return netip.PrefixFrom(addr, ones), nil
					}
				}
			}
		}
	}
	return netip.Prefix{}, fmt.Errorf("no public routed IPv6 detected on host")
}
