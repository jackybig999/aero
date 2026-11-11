package client

import (
	"bufio"
	"math/rand/v2"
	"net/netip"
	"os"
	"strings"
	"testing"
)

func prefixesContain(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// expectTUN 是规则的直接表述（判定函数），与区间运算实现相互独立。
func expectTUN(in RoutePlanInput, a netip.Addr) bool {
	for _, b := range in.Bypass {
		if b == a {
			return false
		}
	}
	for _, c := range in.Capture {
		if c == a && !c.IsLoopback() && !c.IsLinkLocalUnicast() && !c.IsMulticast() && !c.IsUnspecified() {
			if a.Is4() || globalUnicastIPv6.Contains(a) || ulaIPv6.Contains(a) {
				return true
			}
		}
	}
	if a.Is6() {
		return globalUnicastIPv6.Contains(a)
	}
	return !prefixesContain(reservedIPv4, a) && !prefixesContain(in.Direct, a)
}

// 输出必须有序、互不重叠，且同一地址族内不存在可合并的相邻兄弟前缀（最少条数）。
func checkPlanShape(t *testing.T, ps []netip.Prefix) {
	t.Helper()
	for i := 1; i < len(ps); i++ {
		prev, cur := ps[i-1], ps[i]
		if prev.Overlaps(cur) {
			t.Fatalf("overlapping prefixes %v and %v", prev, cur)
		}
		if cur.Addr().Less(prev.Addr()) {
			t.Fatalf("prefixes out of order: %v before %v", prev, cur)
		}
		if prev.Bits() == cur.Bits() && prev.Bits() > 0 {
			parent, _ := prev.Addr().Prefix(prev.Bits() - 1)
			if parent.Contains(cur.Addr()) {
				t.Fatalf("mergeable siblings %v and %v", prev, cur)
			}
		}
	}
}

func randAddr4(r *rand.Rand) netip.Addr {
	v := r.Uint32()
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func TestPlanTUNRoutesNoDirect(t *testing.T) {
	plan, err := PlanTUNRoutes(RoutePlanInput{})
	if err != nil {
		t.Fatal(err)
	}
	checkPlanShape(t, plan.IPv4)
	checkPlanShape(t, plan.IPv6)
	for addr, want := range map[string]bool{
		"8.8.8.8": true, "1.1.1.1": true, "223.255.255.255": true,
		"10.1.2.3": false, "192.168.1.1": false, "172.16.0.1": false, "127.0.0.1": false,
		"169.254.1.1": false, "100.64.0.1": false, "224.0.0.251": false, "255.255.255.255": false, "0.1.2.3": false,
		"2001:4860::8888": true, "fe80::1": false, "fd00::1": false, "ff02::1": false, "::1": false,
	} {
		if got := prefixesContain(append(plan.IPv4, plan.IPv6...), netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s in TUN = %v, want %v", addr, got, want)
		}
	}
	if len(plan.IPv6) != 1 || plan.IPv6[0] != globalUnicastIPv6 {
		t.Errorf("IPv6 plan = %v, want [2000::/3]", plan.IPv6)
	}
}

func TestPlanTUNRoutesPrecedence(t *testing.T) {
	in := RoutePlanInput{
		Direct: mustPrefixes("1.0.0.0/8", "45.0.0.0/8"),
		Bypass: []netip.Addr{
			netip.MustParseAddr("45.1.2.3"), // 已在直连内：仍不进 TUN
			netip.MustParseAddr("8.8.4.4"),  // edge：从 TUN 中扣除
			netip.MustParseAddr("1.0.0.53"), // 同时是 Capture：Bypass 优先
			netip.MustParseAddr("2001:db8::1"),
		},
		Capture: []netip.Addr{
			netip.MustParseAddr("192.168.1.1"), // 局域网 DNS：进 TUN
			netip.MustParseAddr("1.0.0.1"),     // 直连网段内的 DNS：进 TUN
			netip.MustParseAddr("1.0.0.53"),
			netip.MustParseAddr("127.0.0.53"), // 回环：无法捕获，忽略
			netip.MustParseAddr("fe80::1"),    // 链路本地：忽略
			netip.MustParseAddr("fd12::53"),   // ULA DNS：进 TUN
		},
	}
	plan, err := PlanTUNRoutes(in)
	if err != nil {
		t.Fatal(err)
	}
	checkPlanShape(t, plan.IPv4)
	checkPlanShape(t, plan.IPv6)
	all := append(plan.IPv4, plan.IPv6...)
	for addr, want := range map[string]bool{
		"192.168.1.1": true, "192.168.1.2": false,
		"1.0.0.1": true, "1.0.0.2": false, "1.0.0.53": false,
		"45.1.2.3": false, "8.8.4.4": false, "8.8.4.3": true, "8.8.4.5": true,
		"127.0.0.53": false, "fd12::53": true, "fd12::54": false,
		"2001:db8::1": false, "2001:db8::2": true,
	} {
		if got := prefixesContain(all, netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s in TUN = %v, want %v", addr, got, want)
		}
	}
}

// 随机对照：规划结果对任意地址的覆盖情况与判定函数一致。
func TestPlanTUNRoutesMatchesOracle(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for round := 0; round < 20; round++ {
		var in RoutePlanInput
		for i := 0; i < 50; i++ {
			p, _ := randAddr4(r).Prefix(8 + r.IntN(25))
			in.Direct = append(in.Direct, p)
		}
		for i := 0; i < 10; i++ {
			in.Bypass = append(in.Bypass, randAddr4(r))
			in.Capture = append(in.Capture, randAddr4(r))
		}
		// 让部分 Capture/Bypass 落在直连网段内与边界上
		for _, p := range in.Direct[:5] {
			in.Capture = append(in.Capture, p.Addr())
			in.Bypass = append(in.Bypass, p.Addr().Next())
		}
		plan, err := PlanTUNRoutes(in)
		if err != nil {
			t.Fatal(err)
		}
		checkPlanShape(t, plan.IPv4)
		probes := append([]netip.Addr(nil), in.Bypass...)
		probes = append(probes, in.Capture...)
		for _, p := range in.Direct {
			probes = append(probes, p.Addr(), p.Addr().Prev(), lastAddr(p), lastAddr(p).Next())
		}
		for i := 0; i < 2000; i++ {
			probes = append(probes, randAddr4(r))
		}
		for _, a := range probes {
			if !a.IsValid() {
				continue
			}
			if got, want := prefixesContain(plan.IPv4, a), expectTUN(in, a); got != want {
				t.Fatalf("round %d: %v in TUN = %v, want %v", round, a, got, want)
			}
		}
	}
}

func lastAddr(p netip.Prefix) netip.Addr {
	w := p.Addr().BitLen()
	start := addrValue(p.Masked().Addr(), w)
	return valueAddr(start.or(lowOnes(w-p.Bits())), w)
}

// 真实直连名单：条数在合理范围内，且名单内地址不进 TUN、名单外公网地址进 TUN。
func TestPlanTUNRoutesChinaList(t *testing.T) {
	f, err := os.Open("china_ip.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var direct []netip.Prefix
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, err := netip.ParsePrefix(line)
		if err != nil {
			t.Fatalf("parse %q: %v", line, err)
		}
		direct = append(direct, p)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	plan, err := PlanTUNRoutes(RoutePlanInput{Direct: direct})
	if err != nil {
		t.Fatal(err)
	}
	checkPlanShape(t, plan.IPv4)
	if n := len(plan.IPv4); n < 1000 || n > 3*len(direct) {
		t.Fatalf("IPv4 routes = %d for %d direct prefixes", n, len(direct))
	}
	for _, p := range direct[:200] {
		if prefixesContain(plan.IPv4, p.Addr()) {
			t.Fatalf("direct address %v routed into TUN", p.Addr())
		}
	}
	if !prefixesContain(plan.IPv4, netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("8.8.8.8 not routed into TUN")
	}
	t.Logf("direct=%d -> TUN IPv4 routes=%d", len(direct), len(plan.IPv4))
}

func TestPlanTUNRoutesRejectsInvalidInput(t *testing.T) {
	for name, in := range map[string]RoutePlanInput{
		"bypass unspecified": {Bypass: []netip.Addr{netip.IPv4Unspecified()}},
		"bypass zero":        {Bypass: []netip.Addr{{}}},
		"capture zero":       {Capture: []netip.Addr{{}}},
		"direct zero":        {Direct: []netip.Prefix{{}}},
	} {
		if _, err := PlanTUNRoutes(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// 区间运算边界：全空间、端点、溢出。
func TestRangeSetEdges(t *testing.T) {
	full := newRangeSet(32, mustPrefixes("0.0.0.0/0"))
	if got := full.prefixes(); len(got) != 1 || got[0] != netip.MustParsePrefix("0.0.0.0/0") {
		t.Fatalf("full = %v", got)
	}
	if got := full.subtract(full).prefixes(); len(got) != 0 {
		t.Fatalf("full - full = %v", got)
	}
	got := full.subtract(newRangeSet(32, mustPrefixes("0.0.0.0/32", "255.255.255.255/32"))).prefixes()
	if prefixesContain(got, netip.MustParseAddr("0.0.0.0")) || prefixesContain(got, netip.MustParseAddr("255.255.255.255")) ||
		!prefixesContain(got, netip.MustParseAddr("0.0.0.1")) || !prefixesContain(got, netip.MustParseAddr("255.255.255.254")) {
		t.Fatalf("endpoint subtraction wrong: %v", got)
	}
	v6 := newRangeSet(128, mustPrefixes("::/0")).subtract(newRangeSet(128, mustPrefixes("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128")))
	if n := len(v6.prefixes()); n != 128 {
		t.Fatalf("::/0 minus last address = %d prefixes, want 128", n)
	}
	merged := newRangeSet(32, mustPrefixes("10.0.0.0/25", "10.0.0.128/25"))
	if got := merged.prefixes(); len(got) != 1 || got[0] != netip.MustParsePrefix("10.0.0.0/24") {
		t.Fatalf("adjacent halves not merged: %v", got)
	}
}
