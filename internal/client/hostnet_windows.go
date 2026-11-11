//go:build windows

package client

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Windows 实现（ADR-0013、ADR-0014）：wintun 网卡 + IP Helper API（winipcfg），不调用 netsh、route、
// PowerShell，不写 NRPT，不改其他网卡的 DNS。地址、路由、DNS 都挂在自有网卡的 LUID 上；
// DNS 防泄漏用 WFP 动态会话（wfp_windows.go）。网卡删除或进程终止时由系统一并清除。
//
// 网卡使用固定 GUID：Windows 按 GUID 保存接口参数，随机 GUID 每次运行都会留下一份孤儿配置。

var aeroTunGUID = windows.GUID{Data1: 0x56640e9c, Data2: 0x92ec, Data3: 0x4b63, Data4: [8]byte{0x8e, 0x27, 0x04, 0xd6, 0x91, 0xb4, 0x8c, 0x28}}

const (
	wintunTunnelType   = "AERO"
	wintunRingCapacity = 0x800000 // 8 MiB
	// wintun 关闭后立即重建会与驱动注销环形缓冲区竞争（旧实现观察到 0xC0000005），留出排空时间。
	wintunReopenSettle = 200 * time.Millisecond
)

type windowsTunHost struct {
	mu     sync.Mutex
	dev    *windowsDevice
	guard  *dnsGuard
	luid   winipcfg.LUID
	ipv4   netip.Prefix
	plan   RoutePlan
	routes []netip.Prefix
	ipv6   bool
	broken bool
	closed bool
}

func openTunHost(cfg tunHostConfig) (tunHost, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if err := ensureWintunDLL(); err != nil {
		return nil, err
	}
	dev, err := createWintunDevice(cfg.Name)
	if err != nil {
		return nil, err
	}
	h := &windowsTunHost{dev: dev, luid: winipcfg.LUID(dev.adapter.LUID())}
	if err := h.configure(cfg); err != nil {
		return nil, errors.Join(fmt.Errorf("configure %s: %w", cfg.Name, err), h.teardown())
	}
	return h, nil
}

// createWintunDevice 新建自有网卡；同名网卡已存在（另一实例正在运行）时报错，不接管。
func createWintunDevice(name string) (*windowsDevice, error) {
	wintunLifecycleMu.Lock()
	defer wintunLifecycleMu.Unlock()
	if !lastWintunCloseTime.IsZero() {
		if wait := wintunReopenSettle - time.Since(lastWintunCloseTime); wait > 0 {
			time.Sleep(wait)
		}
	}
	guid := aeroTunGUID
	adapter, err := wintun.CreateAdapter(name, wintunTunnelType, &guid)
	if err != nil {
		return nil, fmt.Errorf("create wintun adapter %s (another instance running?): %w", name, err)
	}
	session, err := adapter.StartSession(wintunRingCapacity)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("start wintun session: %w", err), adapter.Close())
	}
	d := &windowsDevice{name: name, adapter: adapter, session: session}
	d.sessionOK.Store(true)
	return d, nil
}

func (h *windowsTunHost) configure(cfg tunHostConfig) error {
	// IPv4：接口 MTU 即隧道 MTU；关闭路由器发现与 DAD，避免系统在本网卡上自行配置。
	if err := h.setInterface(windows.AF_INET, cfg.MTU); err != nil {
		return fmt.Errorf("IPv4 interface: %w", err)
	}
	// IPv6：宿主或网卡禁用 IPv6 时接口不存在，此时宿主也不会发出 IPv6，跳过即可。
	switch err := h.setInterface(windows.AF_INET6, max(cfg.MTU, minIPv6MTU)); {
	case err == nil:
		h.ipv6 = true
	case errors.Is(err, windows.ERROR_NOT_FOUND):
	default:
		return fmt.Errorf("IPv6 interface: %w", err)
	}
	if err := h.luid.AddIPAddress(hostAddr(cfg.IPv4)); err != nil {
		return fmt.Errorf("add address %s: %w", hostAddr(cfg.IPv4), err)
	}
	routes := h.filterFamily(tunRoutes(cfg.IPv4, cfg.Plan))
	if err := h.addRoutes(routes); err != nil {
		return err
	}
	h.ipv4, h.plan, h.routes = cfg.IPv4, cfg.Plan, routes

	// DNS（ADR-0014）：只设置本网卡自己的 DNS；其余网卡的 53 端口由 WFP 动态会话屏蔽。
	if err := h.luid.SetDNS(windows.AF_INET, []netip.Addr{cfg.DNS}, nil); err != nil {
		return fmt.Errorf("set DNS on %s: %w", cfg.Name, err)
	}
	guard, err := startDNSGuard(uint64(h.luid))
	if err != nil {
		return fmt.Errorf("DNS leak guard: %w", err)
	}
	h.guard = guard
	return nil
}

func (h *windowsTunHost) setInterface(family winipcfg.AddressFamily, mtu int) error {
	row, err := h.luid.IPInterface(family)
	if err != nil {
		return err
	}
	row.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
	row.DadTransmits = 0
	row.ManagedAddressConfigurationSupported = false
	row.OtherStatefulConfigurationSupported = false
	row.NLMTU = uint32(mtu)
	return row.Set()
}

func (h *windowsTunHost) Device() TunDevice { return h.dev }

func (h *windowsTunHost) SetIPv4(p netip.Prefix) error {
	if !p.IsValid() || !p.Addr().Is4() {
		return fmt.Errorf("tun IPv4 %v is not an IPv4 prefix", p)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.usable(); err != nil {
		return err
	}
	if p == h.ipv4 {
		return nil
	}
	err := func() error {
		if p.Addr() != h.ipv4.Addr() {
			if err := h.luid.AddIPAddress(hostAddr(p)); err != nil && !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
				return fmt.Errorf("add address %s: %w", hostAddr(p), err)
			}
			if err := h.luid.DeleteIPAddress(hostAddr(h.ipv4)); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
				return fmt.Errorf("delete address %s: %w", hostAddr(h.ipv4), err)
			}
		}
		return h.applyLocked(p, h.plan)
	}()
	if err != nil {
		h.broken = true
		return err
	}
	h.ipv4 = p
	return nil
}

func (h *windowsTunHost) ApplyRoutes(plan RoutePlan) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.usable(); err != nil {
		return err
	}
	if err := h.applyLocked(h.ipv4, plan); err != nil {
		h.broken = true
		return err
	}
	h.plan = plan
	return nil
}

// applyLocked 先增后删，把网卡路由调整为 ipv4 + plan 对应的集合。
func (h *windowsTunHost) applyLocked(ipv4 netip.Prefix, plan RoutePlan) error {
	want := h.filterFamily(tunRoutes(ipv4, plan))
	add, del := diffPrefixes(h.routes, want)
	if err := h.addRoutes(add); err != nil {
		return err
	}
	for _, p := range del {
		if err := h.luid.DeleteRoute(p, unspecifiedFor(p)); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
			return fmt.Errorf("delete route %s: %w", p, err)
		}
	}
	h.routes = want
	return nil
}

func (h *windowsTunHost) addRoutes(ps []netip.Prefix) error {
	for _, p := range ps {
		if err := h.luid.AddRoute(p, unspecifiedFor(p), 0); err != nil && !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
			return fmt.Errorf("add route %s: %w", p, err)
		}
	}
	return nil
}

func (h *windowsTunHost) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil
	}
	h.closed = true
	return h.teardown()
}

// teardown 按依赖逆序拆除：WFP 规则 → 本网卡 DNS → 网卡（其上地址与路由由系统一并清除）。
// 清空 DNS 使正常退出不在本网卡 GUID 名下留下配置；崩溃时 WFP 规则与网卡由系统删除。
func (h *windowsTunHost) teardown() error {
	return errors.Join(
		h.guard.Close(),
		ignoreNotFound(h.luid.FlushDNS(windows.AF_INET)),
		h.dev.Close(),
	)
}

func ignoreNotFound(err error) error {
	if errors.Is(err, windows.ERROR_NOT_FOUND) {
		return nil
	}
	return err
}

func (h *windowsTunHost) usable() error {
	switch {
	case h.closed:
		return errTunHostClosed
	case h.broken:
		return errTunHostBroken
	}
	return nil
}

func (h *windowsTunHost) filterFamily(ps []netip.Prefix) []netip.Prefix {
	if h.ipv6 {
		return ps
	}
	out := make([]netip.Prefix, 0, len(ps))
	for _, p := range ps {
		if p.Addr().Is4() {
			out = append(out, p)
		}
	}
	return out
}

func unspecifiedFor(p netip.Prefix) netip.Addr {
	if p.Addr().Is4() {
		return netip.IPv4Unspecified()
	}
	return netip.IPv6Unspecified()
}

// systemDNSServers 只读获取处于工作状态的网卡上配置的 DNS 服务器。
func systemDNSServers() ([]netip.Addr, error) {
	adapters, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC,
		winipcfg.GAAFlagSkipUnicast|winipcfg.GAAFlagSkipAnycast|winipcfg.GAAFlagSkipMulticast|winipcfg.GAAFlagSkipFriendlyName)
	if err != nil {
		return nil, fmt.Errorf("GetAdaptersAddresses: %w", err)
	}
	var out []netip.Addr
	for _, a := range adapters {
		if a.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}
		for d := a.FirstDNSServerAddress; d != nil; d = d.Next {
			if addr, ok := netip.AddrFromSlice(d.Address.IP()); ok {
				out = append(out, addr.Unmap())
			}
		}
	}
	return uniqueAddrs(out), nil
}
