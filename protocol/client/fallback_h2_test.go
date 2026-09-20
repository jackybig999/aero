package client_test

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aero-protocol/aero-ech"
)

func TestProtocolCache_TTL(t *testing.T) {
	cache := client.NewProtocolCache()
	endpoint := "edge1.aero.net:443"

	// 1. 设置偏好
	cache.Set(endpoint, "h3", 100*time.Millisecond)
	if cache.Get(endpoint) != "h3" {
		t.Fatalf("expected h3 from cache")
	}

	// 2. 超时过期
	time.Sleep(120 * time.Millisecond)
	if cache.Get(endpoint) != "" {
		t.Fatalf("expected cache to expire after TTL")
	}
}

func TestFallbackRacer_H3FastWin(t *testing.T) {
	cache := client.NewProtocolCache()
	racer := client.NewFallbackRacer(cache, 100*time.Millisecond)

	dialH3 := func(ctx context.Context) (net.Conn, error) {
		time.Sleep(20 * time.Millisecond)
		p1, p2 := net.Pipe()
		defer p2.Close()
		return p1, nil
	}

	dialH2 := func(ctx context.Context) (net.Conn, error) {
		time.Sleep(200 * time.Millisecond)
		p1, p2 := net.Pipe()
		defer p2.Close()
		return p1, nil
	}

	conn, proto, err := racer.Dial(context.Background(), "fast-edge:443", dialH3, dialH2)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	if proto != "h3" {
		t.Fatalf("expected h3 to win, got %s", proto)
	}
	if cache.Get("fast-edge:443") != "h3" {
		t.Fatalf("expected cache to store h3")
	}
}

func TestFallbackRacer_H3Blocked_H2Fallback(t *testing.T) {
	cache := client.NewProtocolCache()
	racer := client.NewFallbackRacer(cache, 50*time.Millisecond)

	dialH3 := func(ctx context.Context) (net.Conn, error) {
		// 模拟 UDP 443 被运营商静默丢包或超时
		time.Sleep(300 * time.Millisecond)
		return nil, errors.New("udp blocked / i/o timeout")
	}

	dialH2 := func(ctx context.Context) (net.Conn, error) {
		// H2 TCP 握手成功
		time.Sleep(20 * time.Millisecond)
		p1, p2 := net.Pipe()
		defer p2.Close()
		return p1, nil
	}

	conn, proto, err := racer.Dial(context.Background(), "blocked-udp-edge:443", dialH3, dialH2)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	if proto != "h2" {
		t.Fatalf("expected h2 fallback to win, got %s", proto)
	}
	if cache.Get("blocked-udp-edge:443") != "h2" {
		t.Fatalf("expected cache to store h2")
	}
}

func TestFallbackRacer_CachedH2_DirectSkip(t *testing.T) {
	cache := client.NewProtocolCache()
	endpoint := "known-h2-edge:443"
	cache.Set(endpoint, "h2", 24*time.Hour)

	racer := client.NewFallbackRacer(cache, 100*time.Millisecond)

	var h3Called atomic.Bool
	dialH3 := func(ctx context.Context) (net.Conn, error) {
		h3Called.Store(true)
		return nil, errors.New("should not be called")
	}

	dialH2 := func(ctx context.Context) (net.Conn, error) {
		p1, p2 := net.Pipe()
		defer p2.Close()
		return p1, nil
	}

	conn, proto, err := racer.Dial(context.Background(), endpoint, dialH3, dialH2)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	if proto != "h2" {
		t.Fatalf("expected h2, got %s", proto)
	}
	if h3Called.Load() {
		t.Fatalf("MASQUE dialer should NOT be called when H2 is cached for 24h")
	}
}
