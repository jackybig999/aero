package edge

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"
)

const defaultIPv6ProbeTarget = "[2606:4700:4700::1111]:443"

// probeLocalIPv6Route checks whether the host can select a global IPv6 source
// address for an outbound route. UDP connect does not create application data;
// the result is only a route candidate and is not a delegated-prefix proof.
func probeLocalIPv6Route(ctx context.Context, target string) (netip.Prefix, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if target == "" {
		target = defaultIPv6ProbeTarget
	}
	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(ctx, "udp6", target)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("probe IPv6 route to %s: %w", target, err)
	}
	defer func() {
		_ = conn.Close()
	}()

	udpAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || udpAddr.IP == nil {
		return netip.Prefix{}, fmt.Errorf("IPv6 route probe returned invalid local address %v", conn.LocalAddr())
	}
	addr, ok := netip.AddrFromSlice(udpAddr.IP)
	if !ok {
		return netip.Prefix{}, fmt.Errorf("IPv6 route probe returned unparseable local address %q", udpAddr.IP.String())
	}
	return routedIPv6PrefixFromAddr(addr)
}

func routedIPv6PrefixFromAddr(addr netip.Addr) (netip.Prefix, error) {
	if !addr.Is6() || !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLinkLocalUnicast() {
		return netip.Prefix{}, fmt.Errorf("local address is not globally routable IPv6: %s", addr)
	}
	return netip.PrefixFrom(addr, 64).Masked(), nil
}
