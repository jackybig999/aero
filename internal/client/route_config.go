package client

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
)

// RouteConfig is the platform-neutral route contract for a client TUN.
// IPv6 is disabled unless a verified routed prefix is explicitly supplied.
type RouteConfig struct {
	IPv4                netip.Prefix
	IPv6                netip.Prefix
	EnableIPv6          bool
	EnableIPv6Blackhole bool
	InitialMTU          int
	ExcludedCIDRs       []string
}

var activeRouteConfig struct {
	sync.RWMutex
	byDevice map[string]RouteConfig
}

func init() {
	activeRouteConfig.byDevice = make(map[string]RouteConfig)
}

func NewRouteConfig(ipv4 string, ipv6 *netip.Prefix, initialMTU int) (RouteConfig, error) {
	prefix, err := netip.ParsePrefix(ipv4)
	if err != nil || !prefix.IsValid() || !prefix.Addr().Is4() {
		if err == nil {
			err = fmt.Errorf("not an IPv4 prefix")
		}
		return RouteConfig{}, fmt.Errorf("parse IPv4 route prefix %q: %w", ipv4, err)
	}
	if initialMTU <= 0 {
		initialMTU = 1224
	}
	if initialMTU < 576 {
		return RouteConfig{}, fmt.Errorf("initial TUN MTU too small: %d", initialMTU)
	}

	cfg := RouteConfig{IPv4: prefix, InitialMTU: initialMTU}
	if ipv6 == nil {
		cfg.EnableIPv6Blackhole = true
		return cfg, nil
	}
	if !ipv6.IsValid() || !ipv6.Addr().Is6() || !ipv6.Addr().IsGlobalUnicast() || ipv6.Addr().IsPrivate() || ipv6.Addr().IsLinkLocalUnicast() {
		return RouteConfig{}, fmt.Errorf("IPv6 route prefix is not globally routable: %v", ipv6)
	}
	cfg.IPv6 = ipv6.Masked()
	cfg.EnableIPv6 = true
	return cfg, nil
}

func legacyRouteConfig(ipv4 string) RouteConfig {
	prefix, err := netip.ParsePrefix(ipv4)
	if err != nil || !prefix.IsValid() || !prefix.Addr().Is4() {
		prefix = netip.MustParsePrefix("10.88.0.2/24")
	}
	return RouteConfig{
		IPv4:       prefix,
		IPv6:       netip.MustParsePrefix("fd88::/64"),
		EnableIPv6: true,
		InitialMTU: 1224,
	}
}

func setActiveRouteConfig(devName string, cfg RouteConfig) {
	activeRouteConfig.Lock()
	activeRouteConfig.byDevice[devName] = cfg
	activeRouteConfig.Unlock()
}

func getActiveRouteConfig(devName string) RouteConfig {
	activeRouteConfig.RLock()
	cfg, ok := activeRouteConfig.byDevice[devName]
	activeRouteConfig.RUnlock()
	if ok {
		return cfg
	}
	return legacyRouteConfig("")
}

func deleteActiveRouteConfig(devName string) {
	activeRouteConfig.Lock()
	delete(activeRouteConfig.byDevice, devName)
	activeRouteConfig.Unlock()
}

func clientIPv6Addr(prefix netip.Prefix) (netip.Addr, error) {
	if !prefix.IsValid() || !prefix.Addr().Is6() {
		return netip.Addr{}, fmt.Errorf("invalid IPv6 client prefix: %s", prefix)
	}
	base := prefix.Masked().Addr().As16()
	base[15] = 2
	return netip.AddrFrom16(base), nil
}

func gatewayIPv6Addr(prefix netip.Prefix) (netip.Addr, error) {
	if !prefix.IsValid() || !prefix.Addr().Is6() {
		return netip.Addr{}, fmt.Errorf("invalid IPv6 gateway prefix: %s", prefix)
	}
	base := prefix.Masked().Addr().As16()
	base[15] = 1
	return netip.AddrFrom16(base), nil
}

// tunPool 是 edge 为 CONNECT-IP 会话分配地址的池（edge 侧 NewIPPool 默认值），网关为 .1。
// edge 按 token 哈希在整个池内分配 /32，客户端不得假设固定地址或 /24。
var tunPool = netip.MustParsePrefix("10.88.0.0/16")

// isAeroTunAddr 判断 ip 是否属于隧道地址池（用于识别本程序自己的虚拟网卡）。
func isAeroTunAddr(ip string) bool {
	a, err := netip.ParseAddr(ip)
	return err == nil && tunPool.Contains(a)
}

// tunPoolMask 返回地址池的点分掩码，保证网关 10.88.0.1 对池内任意地址都在同一网段。
func tunPoolMask() string {
	m := net.CIDRMask(tunPool.Bits(), 32)
	return net.IP(m).String()
}
