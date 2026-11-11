//go:build darwin && !ios

package client

import (
	"errors"
	"net/netip"
)

// macOS 的 tunHost（utun + 路由 socket + SCDynamicStore 会话键，ADR-0014）尚未实现（C4）。
// 旧实现用 networksetup 改系统 DNS、在物理网卡上加路由，违反 ADR-0012，不再使用；
// 在此之前 TUN 模式明确失败（fail-closed），本地代理模式不受影响。
var errTunHostDarwinPending = errors.New("TUN mode on macOS is pending the ADR-0014 implementation; use local proxy mode")

func openTunHost(tunHostConfig) (tunHost, error) { return nil, errTunHostDarwinPending }

func systemDNSServers() ([]netip.Addr, error) { return nil, nil }
