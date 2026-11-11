package client

import (
	"errors"
	"fmt"
	"net/netip"
)

// 客户端宿主网络契约（ADR-0013）。
//
// 实现只允许创建与修改“属于自有 TUN 网卡”的状态：网卡本身、网卡上的地址、出接口为该网卡的路由。
// 禁止：系统或其他网卡的 DNS 设置、NRPT、注册表、防火墙、物理网卡上的路由、系统配置文件。
// Close 销毁网卡，地址与路由由操作系统一并清除；因此任何失败的回滚方式都是 Close。

// tunHostConfig 是创建 TUN 时的完整配置。
type tunHostConfig struct {
	Name string
	// MTU 是隧道可承载的 IPv4 内层 MTU。IPv6 要求链路 MTU ≥ 1280，网卡 MTU 低于 1280 时操作系统会
	// 撤掉该网卡的 IPv6，IPv6 流量将无法进入 TUN 而从物理网卡泄漏；因此实现必须让网卡 MTU ≥ 1280，
	// 并以路由 MTU（或按地址族的接口 MTU）把 IPv4 限制在本值。
	MTU  int
	IPv4 netip.Prefix // 本机隧道地址，如 10.88.0.2/16
	Plan RoutePlan
}

func (c tunHostConfig) validate() error {
	switch {
	case c.Name == "":
		return errors.New("tun name is empty")
	case c.MTU < 576 || c.MTU > 9000:
		return fmt.Errorf("tun MTU %d out of range 576..9000", c.MTU)
	case !c.IPv4.IsValid() || !c.IPv4.Addr().Is4():
		return fmt.Errorf("tun IPv4 %v is not an IPv4 prefix", c.IPv4)
	}
	return nil
}

// tunHost 是一张已配置好的自有 TUN 网卡。
//
// SetIPv4 与 ApplyRoutes 失败后网卡状态不确定，调用方必须 Close（之后的调用均返回 errTunHostBroken）。
type tunHost interface {
	Device() TunDevice
	// SetIPv4 替换隧道地址（重连后地址池分配变化）。
	SetIPv4(p netip.Prefix) error
	// ApplyRoutes 把网卡上的路由调整为 plan（增量：先增后删，不出现空窗）。
	ApplyRoutes(plan RoutePlan) error
	// Close 销毁网卡；幂等。
	Close() error
}

const minIPv6MTU = 1280

var (
	errTunHostClosed = errors.New("tun host closed")
	errTunHostBroken = errors.New("tun host in unknown state after a failed change; close it")
)

// diffPrefixes 返回从 cur 变为 want 需要新增与删除的前缀（结果按输入顺序，去重）。
func diffPrefixes(cur, want []netip.Prefix) (add, del []netip.Prefix) {
	have := make(map[netip.Prefix]bool, len(cur))
	for _, p := range cur {
		have[p] = true
	}
	need := make(map[netip.Prefix]bool, len(want))
	for _, p := range want {
		if need[p] {
			continue
		}
		need[p] = true
		if !have[p] {
			add = append(add, p)
		}
	}
	for _, p := range cur {
		if !need[p] {
			del = append(del, p)
			need[p] = true // 去重
		}
	}
	return add, del
}

// planPrefixes 合并两族路由。
func planPrefixes(p RoutePlan) []netip.Prefix {
	return append(append(make([]netip.Prefix, 0, len(p.IPv4)+len(p.IPv6)), p.IPv4...), p.IPv6...)
}

// hostAddr 是配置到 TUN 上的本机地址（/32）。不用地址池前缀长度：同网段地址会形成 primary/secondary，
// 替换地址时删除 primary 会连带删除 secondary。
func hostAddr(p netip.Prefix) netip.Prefix {
	return netip.PrefixFrom(p.Addr(), p.Addr().BitLen())
}

// tunRoutes 是网卡上应有的全部路由：地址池网段（隧道内互访与虚拟网关）加规划路由。
func tunRoutes(ipv4 netip.Prefix, plan RoutePlan) []netip.Prefix {
	return append([]netip.Prefix{ipv4.Masked()}, planPrefixes(plan)...)
}
