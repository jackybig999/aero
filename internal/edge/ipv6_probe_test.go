package edge

import (
	"net/netip"
	"testing"
)

func TestRoutedIPv6PrefixFromAddr(t *testing.T) {
	tests := []struct {
		name    string
		address string
		want    string
		ok      bool
	}{
		{name: "global", address: "2001:db8:1234:5678::10", want: "2001:db8:1234:5678::/64", ok: true},
		{name: "ula", address: "fd88::10", ok: false},
		{name: "link-local", address: "fe80::10", ok: false},
		{name: "ipv4", address: "192.0.2.10", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := routedIPv6PrefixFromAddr(netip.MustParseAddr(tt.address))
			if !tt.ok {
				if err == nil {
					t.Fatalf("expected address rejection, got %s", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.String() != tt.want {
				t.Fatalf("prefix = %s, want %s", got, tt.want)
			}
		})
	}
}
