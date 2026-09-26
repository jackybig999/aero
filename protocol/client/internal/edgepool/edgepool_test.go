package edgepool

import (
	"testing"
	"time"
)

func TestNewFromServersAndFind(t *testing.T) {
	cfgs := []ServerConfig{
		{
			Name:     "Tokyo-01",
			Address:  "tokyo.edge.com:443",
			Token:    "token-tokyo",
			SNI:      "tokyo.edge.com",
			PinSPKI:  []string{"pin-tokyo-1"},
			Protocol: "aero_h2",
		},
		{
			Name:     "HK-02",
			Address:  "hk.edge.com:443",
			Token:    "token-hk",
			SNI:      "hk.edge.com",
			PinSPKI:  []string{"pin-hk-1", "pin-hk-2"},
			Protocol: "aero_h2",
		},
	}

	pool, err := NewFromServers(cfgs)
	if err != nil {
		t.Fatalf("NewFromServers failed: %v", err)
	}

	if pool.Count() != 2 {
		t.Fatalf("expected 2 servers, got %d", pool.Count())
	}

	s1 := pool.FindServer("tokyo.edge.com:443")
	if s1 == nil {
		t.Fatalf("expected to find Tokyo-01")
	}
	if s1.Token != "token-tokyo" || s1.SNI != "tokyo.edge.com" || len(s1.PinSPKI) != 1 {
		t.Fatalf("unexpected Tokyo server data: %+v", s1)
	}

	s2 := pool.FindServer("hk.edge.com:443")
	if s2 == nil {
		t.Fatalf("expected to find HK-02")
	}
	if s2.Token != "token-hk" || s2.SNI != "hk.edge.com" || len(s2.PinSPKI) != 2 {
		t.Fatalf("unexpected HK server data: %+v", s2)
	}

	sNon := pool.FindServer("nonexistent:443")
	if sNon != nil {
		t.Fatalf("expected nil for nonexistent server")
	}
}

func TestBestNodeSelection(t *testing.T) {
	cfgs := []ServerConfig{
		{
			Name:    "Server-A",
			Address: "1.1.1.1:443",
		},
		{
			Name:    "Server-B",
			Address: "2.2.2.2:443",
		},
	}
	pool, err := NewFromServers(cfgs)
	if err != nil {
		t.Fatalf("NewFromServers: %v", err)
	}

	// Initially neither reachable, Best() returns first
	best := pool.Best()
	if best == nil || best.Address != "1.1.1.1:443" {
		t.Fatalf("expected fallback to first server, got %+v", best)
	}

	// Update RTT
	pool.SetProbeResult("1.1.1.1:443", true, 200*time.Millisecond)
	pool.SetProbeResult("2.2.2.2:443", true, 50*time.Millisecond)

	best = pool.Best()
	if best == nil || best.Address != "2.2.2.2:443" {
		t.Fatalf("expected lowest latency Server-B (50ms), got %+v", best)
	}
}
