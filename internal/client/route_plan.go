package client

import (
	"fmt"
	"math/bits"
	"net/netip"
	"sort"
)

// TUN 路由规划（ADR-0013）：客户端的全部路由都挂在自有 TUN 上，物理网卡上不加任何路由。
//
//	IPv4 = 全部地址 − 特殊用途网段 − 直连网段 − Bypass，再加 Capture 的 /32
//	IPv6 = 2000::/3 − Bypass，再加 Capture 中的 ULA /128
//
// IPv6 不扣除直连网段：PROJECT_RULES 规定 IPv6 只能进隧道或黑洞，不得走物理网卡。
// Bypass 优先级最高（edge 外层地址必须走物理网卡，否则形成回环）；
// Capture（系统 DNS 服务器）高于直连与特殊网段，使系统 DNS 查询进入 TUN 被端口 53 拦截。

// RoutePlanInput 是规划输入。
type RoutePlanInput struct {
	Direct  []netip.Prefix // 直连网段（仅 IPv4 生效）
	Bypass  []netip.Addr   // 必须走物理网卡的地址：edge 外层地址
	Capture []netip.Addr   // 必须进 TUN 的地址：系统 DNS 服务器
}

// RoutePlan 是挂在 TUN 上的路由集合，各族内有序且互不重叠。
type RoutePlan struct {
	IPv4 []netip.Prefix
	IPv6 []netip.Prefix
}

// maxTUNRoutes 防止异常直连名单导致下发数十万条路由。
const maxTUNRoutes = 50000

var (
	// 不经隧道的 IPv4 特殊用途网段（RFC 6890 等）：本机、私有、共享、链路本地、文档、基准测试、组播、保留。
	reservedIPv4 = mustPrefixes(
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	)
	globalUnicastIPv6 = netip.MustParsePrefix("2000::/3")
	ulaIPv6           = netip.MustParsePrefix("fc00::/7")
	allIPv4           = netip.MustParsePrefix("0.0.0.0/0")
)

// PlanTUNRoutes 生成挂在 TUN 上的路由集合。
func PlanTUNRoutes(in RoutePlanInput) (RoutePlan, error) {
	var bypass4, bypass6, capture4, capture6 []netip.Prefix
	for _, a := range in.Bypass {
		if !a.IsValid() || a.IsUnspecified() {
			return RoutePlan{}, fmt.Errorf("invalid bypass address %v", a)
		}
		a = a.Unmap()
		if a.Is4() {
			bypass4 = append(bypass4, netip.PrefixFrom(a, 32))
		} else {
			bypass6 = append(bypass6, netip.PrefixFrom(a.WithZone(""), 128))
		}
	}
	for _, a := range in.Capture {
		if !a.IsValid() {
			return RoutePlan{}, fmt.Errorf("invalid capture address %v", a)
		}
		a = a.Unmap()
		// 本机回环、链路本地、组播、未指定地址无法用路由捕获（如 127.0.0.53），跳过。
		if a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() {
			continue
		}
		if a.Is4() {
			capture4 = append(capture4, netip.PrefixFrom(a, 32))
		} else if globalUnicastIPv6.Contains(a) || ulaIPv6.Contains(a) {
			capture6 = append(capture6, netip.PrefixFrom(a.WithZone(""), 128))
		}
	}
	for _, p := range in.Direct {
		if !p.IsValid() {
			return RoutePlan{}, fmt.Errorf("invalid direct prefix %v", p)
		}
	}

	v4 := newRangeSet(32, []netip.Prefix{allIPv4}).
		subtract(newRangeSet(32, reservedIPv4)).
		subtract(newRangeSet(32, only4(in.Direct))).
		union(newRangeSet(32, capture4)).
		subtract(newRangeSet(32, bypass4))
	v6 := newRangeSet(128, []netip.Prefix{globalUnicastIPv6}).
		union(newRangeSet(128, capture6)).
		subtract(newRangeSet(128, bypass6))

	plan := RoutePlan{IPv4: v4.prefixes(), IPv6: v6.prefixes()}
	if n := len(plan.IPv4) + len(plan.IPv6); n > maxTUNRoutes {
		return RoutePlan{}, fmt.Errorf("route plan has %d routes, limit %d", n, maxTUNRoutes)
	}
	return plan, nil
}

func only4(ps []netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ps))
	for _, p := range ps {
		if p.Addr().Is4() {
			out = append(out, p)
		}
	}
	return out
}

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// ---- 128 位区间集合 ----

type u128 struct{ hi, lo uint64 }

func (x u128) cmp(y u128) int {
	switch {
	case x.hi != y.hi:
		if x.hi < y.hi {
			return -1
		}
		return 1
	case x.lo != y.lo:
		if x.lo < y.lo {
			return -1
		}
		return 1
	}
	return 0
}

func (x u128) or(y u128) u128 { return u128{x.hi | y.hi, x.lo | y.lo} }

func (x u128) addOne() (u128, bool) {
	lo := x.lo + 1
	hi := x.hi
	if lo == 0 {
		hi++
		if hi == 0 {
			return u128{}, true
		}
	}
	return u128{hi, lo}, false
}

func (x u128) subOne() u128 {
	if x.lo == 0 {
		return u128{x.hi - 1, ^uint64(0)}
	}
	return u128{x.hi, x.lo - 1}
}

// lowOnes 返回低 n 位全 1 的值（0 ≤ n ≤ 128）。
func lowOnes(n int) u128 {
	switch {
	case n <= 0:
		return u128{}
	case n < 64:
		return u128{0, 1<<uint(n) - 1}
	case n == 64:
		return u128{0, ^uint64(0)}
	case n < 128:
		return u128{1<<uint(n-64) - 1, ^uint64(0)}
	}
	return u128{^uint64(0), ^uint64(0)}
}

func (x u128) trailingZeros() int {
	if x.lo != 0 {
		return bits.TrailingZeros64(x.lo)
	}
	if x.hi != 0 {
		return 64 + bits.TrailingZeros64(x.hi)
	}
	return 128
}

type addrSpan struct{ start, end u128 } // 闭区间

// rangeSet 是同一地址族（width=32 或 128）内有序、不重叠、不相邻的闭区间集合。
type rangeSet struct {
	width  int
	ranges []addrSpan
}

func addrValue(a netip.Addr, width int) u128 {
	if width == 32 {
		b := a.As4()
		return u128{0, uint64(b[0])<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3])}
	}
	b := a.As16()
	var hi, lo uint64
	for i := 0; i < 8; i++ {
		hi = hi<<8 | uint64(b[i])
		lo = lo<<8 | uint64(b[8+i])
	}
	return u128{hi, lo}
}

func valueAddr(v u128, width int) netip.Addr {
	if width == 32 {
		return netip.AddrFrom4([4]byte{byte(v.lo >> 24), byte(v.lo >> 16), byte(v.lo >> 8), byte(v.lo)})
	}
	var b [16]byte
	for i := 0; i < 8; i++ {
		b[7-i] = byte(v.hi >> (8 * i))
		b[15-i] = byte(v.lo >> (8 * i))
	}
	return netip.AddrFrom16(b)
}

func newRangeSet(width int, ps []netip.Prefix) rangeSet {
	rs := make([]addrSpan, 0, len(ps))
	for _, p := range ps {
		p = p.Masked()
		start := addrValue(p.Addr(), width)
		rs = append(rs, addrSpan{start, start.or(lowOnes(width - p.Bits()))})
	}
	return rangeSet{width: width, ranges: normalizeRanges(rs)}
}

// normalizeRanges 排序并合并重叠或相邻的区间。
func normalizeRanges(rs []addrSpan) []addrSpan {
	if len(rs) == 0 {
		return nil
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].start.cmp(rs[j].start) < 0 })
	out := rs[:1]
	for _, r := range rs[1:] {
		last := &out[len(out)-1]
		next, overflow := last.end.addOne()
		if overflow || r.start.cmp(next) <= 0 {
			if r.end.cmp(last.end) > 0 {
				last.end = r.end
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

func (s rangeSet) union(o rangeSet) rangeSet {
	all := append(append([]addrSpan(nil), s.ranges...), o.ranges...)
	return rangeSet{width: s.width, ranges: normalizeRanges(all)}
}

func (s rangeSet) subtract(o rangeSet) rangeSet {
	var out []addrSpan
	j := 0
	for _, r := range s.ranges {
		cur := r
		for j < len(o.ranges) && o.ranges[j].end.cmp(cur.start) < 0 {
			j++
		}
		done := false
		for k := j; k < len(o.ranges) && o.ranges[k].start.cmp(cur.end) <= 0; k++ {
			cut := o.ranges[k]
			if cut.start.cmp(cur.start) > 0 {
				out = append(out, addrSpan{cur.start, cut.start.subOne()})
			}
			if cut.end.cmp(cur.end) >= 0 {
				done = true // 剩余部分被完全扣除
				break
			}
			cur.start, _ = cut.end.addOne() // cut.end < cur.end，不会溢出
		}
		if !done {
			out = append(out, cur)
		}
	}
	return rangeSet{width: s.width, ranges: out}
}

// prefixes 把区间集合转换为最少数量的 CIDR。
func (s rangeSet) prefixes() []netip.Prefix {
	var out []netip.Prefix
	for _, r := range s.ranges {
		cur := r.start
		for {
			k := min(cur.trailingZeros(), s.width)
			for ; k > 0; k-- {
				if cur.or(lowOnes(k)).cmp(r.end) <= 0 {
					break
				}
			}
			end := cur.or(lowOnes(k))
			out = append(out, netip.PrefixFrom(valueAddr(cur, s.width), s.width-k))
			if end.cmp(r.end) >= 0 {
				break
			}
			cur, _ = end.addOne()
		}
	}
	return out
}
