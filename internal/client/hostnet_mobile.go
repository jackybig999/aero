//go:build android || ios

package client

import (
	"errors"
	"net/netip"
)

// 移动端由系统 VPN API（VpnService、NetworkExtension）创建与配置 TUN，经 StartTunnel(fd) 进入，
// 不走 Engine 的桌面 TUN 路径。
func openTunHost(tunHostConfig) (tunHost, error) {
	return nil, errors.New("desktop TUN is not available on mobile; the OS VPN API owns the tunnel")
}

func systemDNSServers() ([]netip.Addr, error) { return nil, nil }
