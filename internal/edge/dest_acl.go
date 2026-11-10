package edge

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// 统一目的地址 ACL（PROJECT_RULES“收紧项”）：TCP CONNECT、CONNECT-UDP 与
// CONNECT-IP 三条路径共用，任何一条都不得比另一条宽松。判定完全在进程内完成，
// 不修改宿主防火墙，不影响宿主上的其他进程与服务。

type blockedPrefix struct {
	prefix netip.Prefix
	reason string
}

var blockedDestinationPrefixes = func() []blockedPrefix {
	list := []struct{ cidr, reason string }{
		// IPv4
		{"0.0.0.0/8", "this-network"},
		{"10.0.0.0/8", "private"},
		{"100.64.0.0/10", "cgnat"},
		{"127.0.0.0/8", "loopback"},
		{"169.254.0.0/16", "link-local"},
		{"172.16.0.0/12", "private"},
		{"192.0.0.0/24", "ietf-protocol"},
		{"192.0.2.0/24", "documentation"},
		{"192.88.99.0/24", "6to4-relay"},
		{"192.168.0.0/16", "private"},
		{"198.18.0.0/15", "benchmark"},
		{"198.51.100.0/24", "documentation"},
		{"203.0.113.0/24", "documentation"},
		{"224.0.0.0/4", "multicast"},
		{"240.0.0.0/4", "reserved"},
		// IPv6
		{"::/128", "unspecified"},
		{"::1/128", "loopback"},
		{"64:ff9b:1::/48", "nat64-local"},
		{"100::/64", "discard"},
		{"2001:db8::/32", "documentation"},
		{"fc00::/7", "unique-local"},
		{"fe80::/10", "link-local"},
		{"fec0::/10", "site-local"},
		{"ff00::/8", "multicast"},
	}
	out := make([]blockedPrefix, 0, len(list))
	for _, p := range list {
		out = append(out, blockedPrefix{prefix: netip.MustParsePrefix(p.cidr), reason: p.reason})
	}
	return out
}()

var (
	nat64WellKnown = netip.MustParsePrefix("64:ff9b::/96")
	sixToFour      = netip.MustParsePrefix("2002::/16")
)

// destinationBlocked 判定 dst 是否禁止作为客户端流量的目的地址。own 为 edge
// 本机地址集合（为 nil 时不检查）。
func destinationBlocked(dst netip.Addr, own map[netip.Addr]struct{}) (bool, string) {
	if !dst.IsValid() {
		return true, "invalid"
	}
	dst = dst.WithZone("")
	if dst.Is4In6() {
		dst = dst.Unmap()
	}
	for _, b := range blockedDestinationPrefixes {
		if b.prefix.Contains(dst) {
			return true, b.reason
		}
	}
	if dst.Is6() {
		if embedded, ok := embeddedIPv4(dst); ok {
			if blocked, why := destinationBlocked(embedded, own); blocked {
				return true, "embedded-" + why
			}
		}
	}
	if own != nil {
		if _, ok := own[dst]; ok {
			return true, "edge-local"
		}
	}
	return false, ""
}

// embeddedIPv4 取出 NAT64（64:ff9b::/96）与 6to4（2002::/16）地址中内嵌的 IPv4。
func embeddedIPv4(a netip.Addr) (netip.Addr, bool) {
	b := a.As16()
	switch {
	case nat64WellKnown.Contains(a):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case sixToFour.Contains(a):
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	}
	return netip.Addr{}, false
}

// destinationPortBlocked 判定传输层目的端口策略：禁止出站 SMTP（tcp/25），
// 避免节点被用于发送垃圾邮件而遭服务商停机。
func destinationPortBlocked(proto uint8, port uint16) (bool, string) {
	if proto == 6 && port == 25 {
		return true, "smtp"
	}
	return false, ""
}

// edgeLocalAddrs 返回 edge 本机全部接口地址。数据路径每包调用，读取走原子指针，
// 只有缓存过期（30 秒）时由一个调用方加锁刷新。
type edgeLocalAddrSnapshot struct {
	addrs   map[netip.Addr]struct{}
	fetched time.Time
}

var (
	edgeLocalAddrCache     atomic.Pointer[edgeLocalAddrSnapshot]
	edgeLocalAddrRefreshMu sync.Mutex
)

const edgeLocalAddrTTL = 30 * time.Second

func edgeLocalAddrs() map[netip.Addr]struct{} {
	if snap := edgeLocalAddrCache.Load(); snap != nil && time.Since(snap.fetched) < edgeLocalAddrTTL {
		return snap.addrs
	}
	edgeLocalAddrRefreshMu.Lock()
	defer edgeLocalAddrRefreshMu.Unlock()
	prev := edgeLocalAddrCache.Load()
	if prev != nil && time.Since(prev.fetched) < edgeLocalAddrTTL {
		return prev.addrs
	}
	ifAddrs, err := net.InterfaceAddrs()
	if err != nil {
		// 查询失败：沿用上一份结果并延后重试；首次失败用空集合，其余网段规则仍然生效。
		addrs := map[netip.Addr]struct{}{}
		if prev != nil {
			addrs = prev.addrs
		}
		edgeLocalAddrCache.Store(&edgeLocalAddrSnapshot{addrs: addrs, fetched: time.Now()})
		return addrs
	}
	addrs := make(map[netip.Addr]struct{}, len(ifAddrs))
	for _, a := range ifAddrs {
		if ipNet, ok := a.(*net.IPNet); ok {
			if addr, ok := netip.AddrFromSlice(ipNet.IP); ok {
				addrs[addr.Unmap()] = struct{}{}
			}
		}
	}
	edgeLocalAddrCache.Store(&edgeLocalAddrSnapshot{addrs: addrs, fetched: time.Now()})
	return addrs
}
