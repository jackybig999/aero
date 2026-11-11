package client

import (
	"net/netip"
	"slices"
	"testing"
)

func TestDiffPrefixes(t *testing.T) {
	p := netip.MustParsePrefix
	cur := []netip.Prefix{p("1.0.0.0/8"), p("2.0.0.0/8"), p("3.0.0.0/8")}
	want := []netip.Prefix{p("2.0.0.0/8"), p("4.0.0.0/8"), p("4.0.0.0/8"), p("5.0.0.0/8")}
	add, del := diffPrefixes(cur, want)
	if !slices.Equal(add, []netip.Prefix{p("4.0.0.0/8"), p("5.0.0.0/8")}) {
		t.Errorf("add = %v", add)
	}
	if !slices.Equal(del, []netip.Prefix{p("1.0.0.0/8"), p("3.0.0.0/8")}) {
		t.Errorf("del = %v", del)
	}
	if add, del := diffPrefixes(want, want); len(add) != 0 || len(del) != 0 {
		t.Errorf("identical sets: add=%v del=%v", add, del)
	}
}

func TestTunHostConfigValidate(t *testing.T) {
	ok := tunHostConfig{Name: "aero0", MTU: 1224, IPv4: netip.MustParsePrefix("10.88.0.2/16"), DNS: netip.MustParseAddr("10.88.0.1")}
	if err := ok.validate(); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]tunHostConfig{
		"no name":  {MTU: 1224, IPv4: ok.IPv4, DNS: ok.DNS},
		"mtu low":  {Name: "aero0", MTU: 500, IPv4: ok.IPv4, DNS: ok.DNS},
		"mtu high": {Name: "aero0", MTU: 9001, IPv4: ok.IPv4, DNS: ok.DNS},
		"no ipv4":  {Name: "aero0", MTU: 1224, DNS: ok.DNS},
		"ipv6":     {Name: "aero0", MTU: 1224, IPv4: netip.MustParsePrefix("fd00::2/64"), DNS: ok.DNS},
		"no dns":   {Name: "aero0", MTU: 1224, IPv4: ok.IPv4},
		"dns out":  {Name: "aero0", MTU: 1224, IPv4: ok.IPv4, DNS: netip.MustParseAddr("8.8.8.8")},
		"dns self": {Name: "aero0", MTU: 1224, IPv4: ok.IPv4, DNS: ok.IPv4.Addr()},
	} {
		if c.validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
