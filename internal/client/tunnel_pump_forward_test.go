package client

import "testing"

func ipv4Pkt(ttl byte, dst [4]byte) []byte {
	p := make([]byte, 20)
	p[0], p[8] = 0x45, ttl
	copy(p[12:16], []byte{10, 88, 0, 6})
	copy(p[16:20], dst[:])
	return p
}

func ipv6Pkt(hop byte, dst [16]byte) []byte {
	p := make([]byte, 40)
	p[0], p[7] = 0x60, hop
	copy(p[24:40], dst[:])
	return p
}

// 链路本地组播与 TTL/Hop Limit ≤ 1 的报文不进隧道（Windows 新网卡上的 LLMNR、MLD、SSDP 等）。
func TestForwardable(t *testing.T) {
	ff02 := [16]byte{0xff, 0x02, 15: 0x16}
	fe80 := [16]byte{0xfe, 0x80, 15: 1}
	g6 := [16]byte{0x20, 0x01, 0x48, 0x60, 15: 0x88}
	cases := []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"v4 unicast", ipv4Pkt(64, [4]byte{8, 8, 8, 8}), true},
		{"v4 ttl 1", ipv4Pkt(1, [4]byte{8, 8, 8, 8}), false},
		{"v4 ttl 0", ipv4Pkt(0, [4]byte{8, 8, 8, 8}), false},
		{"v4 llmnr", ipv4Pkt(1, [4]byte{224, 0, 0, 252}), false},
		{"v4 ssdp ttl 4", ipv4Pkt(4, [4]byte{239, 255, 255, 250}), false},
		{"v4 broadcast", ipv4Pkt(64, [4]byte{255, 255, 255, 255}), false},
		{"v6 unicast", ipv6Pkt(64, g6), true},
		{"v6 hop 1", ipv6Pkt(1, g6), false},
		{"v6 mld", ipv6Pkt(1, ff02), false},
		{"v6 multicast hop 255", ipv6Pkt(255, ff02), false},
		{"v6 link-local", ipv6Pkt(255, fe80), false},
	}
	for _, c := range cases {
		if got := forwardable(c.pkt); got != c.want {
			t.Errorf("%s: forwardable = %v, want %v", c.name, got, c.want)
		}
	}
}
