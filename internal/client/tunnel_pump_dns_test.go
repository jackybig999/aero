package client

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// 回归（审查 P0-7）：未命中缓存的 DNS 查询在数据泵读循环内同步等待 DoH（最长 2.5 秒），
// 期间整机上行全部停顿。DNS 必须异步处理，其他流量不受影响。
func TestPumpDNSDoesNotBlockOtherTraffic(t *testing.T) {
	release := make(chan struct{})
	dns := NewDNSHandler(nil)
	dns.SetDoHResolver(func(ctx context.Context, req []byte) ([]byte, error) {
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		resp := append([]byte(nil), req...)
		resp[2], resp[3] = 0x81, 0x80 // QR=1, RD, RA, NOERROR
		return resp, nil
	})

	dev := newMockIPv6TunDevice()
	conn := newMockIPv6PacketConn()
	pump := NewIPDataPump(context.Background(), dev, conn, nil, dns)
	pump.Start()
	defer func() { _ = pump.Close() }()

	client := net.IPv4(10, 88, 0, 2)
	gateway := net.IPv4(10, 88, 0, 1)
	query := buildDNSQuery("slow-doh.example", 1)
	dev.inCh <- buildIPv4UDPResponsePacket(client, gateway, 40000, 53, query)

	app := buildIPv4UDPResponsePacket(client, net.IPv4(1, 1, 1, 1), 40001, 443, []byte("quic-payload"))
	dev.inCh <- app

	select {
	case got := <-conn.outCh:
		if binary.BigEndian.Uint16(got[22:24]) != 443 {
			t.Fatalf("unexpected packet forwarded: %x", got[:28])
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("application traffic stalled behind a pending DNS query")
	}

	close(release)
	select {
	case resp := <-dev.outCh:
		if len(resp) < 28 || resp[9] != 17 || binary.BigEndian.Uint16(resp[20:22]) != 53 {
			t.Fatalf("expected a DNS response to the client, got %x", resp)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("DNS response was never written back")
	}
}
