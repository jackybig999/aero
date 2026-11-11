//go:build linux && !android

package client

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Linux 实现（ADR-0013）：非持久 TUN 在 fd 关闭时由内核销毁，网卡上的地址与路由随之消失，
// 进程退出或被强杀都不会留下残留。所有修改经 `ip -batch`，每条命令都限定 `dev <tun>`。

const ipBatchTimeout = 30 * time.Second

type linuxTunHost struct {
	mu     sync.Mutex
	dev    *linuxDevice
	name   string
	ipv4   netip.Prefix
	plan   RoutePlan
	routes []netip.Prefix // 实际下发的路由（含地址池网段）
	ipv6   bool           // 网卡是否启用 IPv6（宿主禁用 IPv6 时不下发 v6 路由，宿主本身也不会发出 IPv6）
	v4MTU  int            // 隧道承载的 IPv4 内层 MTU
	devMTU int            // 网卡 MTU：启用 IPv6 时至少 1280
	broken bool
	closed bool
}

// ipBatch 是可替换的执行入口（测试用）。
var ipBatch = func(ctx context.Context, lines []string) error {
	if len(lines) == 0 {
		return nil
	}
	cmd := exec.CommandContext(ctx, "ip", "-batch", "-")
	cmd.Stdin = strings.NewReader(strings.Join(lines, "\n") + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip -batch: %w: %s", err, bytes.TrimSpace(out))
	}
	return nil
}

func openTunHost(cfg tunHostConfig) (tunHost, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	d, err := OpenTunDevice(cfg.Name, cfg.MTU)
	if err != nil {
		return nil, err
	}
	h := &linuxTunHost{dev: d.(*linuxDevice), name: d.Name(), v4MTU: cfg.MTU}
	h.ipv6 = ipv6EnabledOn(h.name) // 须在设置 MTU 前读取：MTU < 1280 时内核撤掉网卡的 IPv6
	devMTU := cfg.MTU
	if h.ipv6 {
		devMTU = max(devMTU, minIPv6MTU)
	}
	h.devMTU = devMTU

	lines := []string{
		fmt.Sprintf("link set dev %s mtu %d up", h.name, devMTU),
		fmt.Sprintf("addr add %s dev %s", hostAddr(cfg.IPv4), h.name),
	}
	routes := h.filterFamily(tunRoutes(cfg.IPv4, cfg.Plan))
	for _, p := range routes {
		lines = append(lines, h.routeLine(p))
	}
	if err := h.run(lines); err != nil {
		return nil, errors.Join(fmt.Errorf("configure %s: %w", h.name, err), h.dev.Close())
	}
	h.ipv4, h.plan, h.routes = cfg.IPv4, cfg.Plan, routes
	if err := configureLinkDNS(h.name, cfg.DNS); err != nil {
		return nil, errors.Join(fmt.Errorf("DNS on %s: %w", h.name, err), h.dev.Close())
	}
	return h, nil
}

// DNS（ADR-0014）：使用 systemd-resolved 的本地桩时，resolved 会把查询 socket 绑定到各链路发出，
// 路由捕获无效；此时只对本网卡设置链路 DNS 与 "~." 路由域，网卡消失时 resolved 自动丢弃该配置。
// 其他情况下 glibc 直接按路由发出查询，系统 DNS 服务器已由 Capture 路由进 TUN。
//
// 两个入口可替换：命名空间测试与宿主共享 /etc/resolv.conf 和 resolved 的 D-Bus，按网卡名换算出的
// 序号属于测试命名空间，真实调用会改到宿主上序号相同的另一张网卡，因此测试必须替换。
var (
	resolvedStubInUse = func() bool {
		servers, err := readResolvConf("/etc/resolv.conf")
		if err != nil {
			return false
		}
		for _, a := range servers {
			if a == netip.MustParseAddr("127.0.0.53") || a == netip.MustParseAddr("127.0.0.54") {
				return true
			}
		}
		return false
	}
	resolvectl = func(ctx context.Context, args ...string) error {
		out, err := exec.CommandContext(ctx, "resolvectl", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("resolvectl %s: %w: %s", strings.Join(args, " "), err, bytes.TrimSpace(out))
		}
		return nil
	}
)

func configureLinkDNS(dev string, dns netip.Addr) error {
	if !resolvedStubInUse() {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), ipBatchTimeout)
	defer cancel()
	if err := resolvectl(ctx, "dns", dev, dns.String()); err != nil {
		return err
	}
	return resolvectl(ctx, "domain", dev, "~.")
}

func (h *linuxTunHost) Device() TunDevice { return h.dev }

func (h *linuxTunHost) SetIPv4(p netip.Prefix) error {
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
	// 先加新地址再删旧地址，网卡上始终至少有一个 IPv4 地址：删除最后一个地址时内核会清空该网卡的
	// 全部 IPv4 路由（fib_disable_ip）。地址用 /32，彼此不构成 primary/secondary，删除旧地址不会连带新地址。
	lines := []string{fmt.Sprintf("addr add %s dev %s", hostAddr(p), h.name)}
	if h.ipv4.Addr() != p.Addr() {
		lines = append(lines, fmt.Sprintf("addr del %s dev %s", hostAddr(h.ipv4), h.name))
	} else {
		lines = lines[:0]
	}
	want := h.filterFamily(tunRoutes(p, h.plan))
	add, del := diffPrefixes(h.routes, want)
	for _, r := range add {
		lines = append(lines, h.routeLine(r))
	}
	for _, r := range del {
		lines = append(lines, fmt.Sprintf("route del %s dev %s", r, h.name))
	}
	if err := h.run(lines); err != nil {
		h.broken = true
		return err
	}
	h.ipv4, h.routes = p, want
	return nil
}

func (h *linuxTunHost) ApplyRoutes(plan RoutePlan) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.usable(); err != nil {
		return err
	}
	want := h.filterFamily(tunRoutes(h.ipv4, plan))
	add, del := diffPrefixes(h.routes, want)
	lines := make([]string, 0, len(add)+len(del))
	for _, p := range add {
		lines = append(lines, h.routeLine(p))
	}
	for _, p := range del {
		lines = append(lines, fmt.Sprintf("route del %s dev %s", p, h.name))
	}
	if err := h.run(lines); err != nil {
		h.broken = true
		return err
	}
	h.routes, h.plan = want, plan
	return nil
}

func (h *linuxTunHost) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil
	}
	h.closed = true
	return h.dev.Close()
}

// routeLine 生成挂在本网卡上的路由命令。网卡 MTU 因 IPv6 抬到 1280 时，IPv4 路由带 mtu 属性，
// 使内核与 TCP MSS 仍按隧道可承载的 IPv4 MTU 计算。
func (h *linuxTunHost) routeLine(p netip.Prefix) string {
	if p.Addr().Is4() && h.v4MTU < h.devMTU {
		return fmt.Sprintf("route replace %s dev %s mtu %d", p, h.name, h.v4MTU)
	}
	return fmt.Sprintf("route replace %s dev %s", p, h.name)
}

func (h *linuxTunHost) usable() error {
	switch {
	case h.closed:
		return errTunHostClosed
	case h.broken:
		return errTunHostBroken
	}
	return nil
}

func (h *linuxTunHost) run(lines []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), ipBatchTimeout)
	defer cancel()
	return ipBatch(ctx, lines)
}

func (h *linuxTunHost) filterFamily(ps []netip.Prefix) []netip.Prefix {
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

func ipv6EnabledOn(dev string) bool {
	b, err := os.ReadFile("/proc/sys/net/ipv6/conf/" + dev + "/disable_ipv6")
	return err == nil && strings.TrimSpace(string(b)) == "0"
}

// systemDNSServers 只读获取系统 DNS 服务器；本地桩解析器（systemd-resolved 的 127.0.0.53）
// 无法用路由捕获，改读其上游列表。
func systemDNSServers() ([]netip.Addr, error) {
	servers, err := readResolvConf("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	for _, a := range servers {
		if a.IsLoopback() {
			if up, err := readResolvConf("/run/systemd/resolve/resolv.conf"); err == nil {
				servers = append(servers, up...)
			}
			break
		}
	}
	return uniqueAddrs(servers), nil
}

func readResolvConf(path string) ([]netip.Addr, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseResolvConf(b), nil
}

func parseResolvConf(b []byte) []netip.Addr {
	var out []netip.Addr
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 && f[0] == "nameserver" {
			if a, err := netip.ParseAddr(f[1]); err == nil {
				out = append(out, a.Unmap())
			}
		}
	}
	return out
}
