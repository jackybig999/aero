package service

import (
	"testing"

	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/aero/iface"
)

func TestParseHarvest_StandardAndCustomPorts(t *testing.T) {
	cred := &iface.Cred{
		VPSID:  101,
		Name:   "TestNode",
		Domain: "edge.example.com",
		IP:     "1.2.3.4",
	}

	// 1. Port 443 (default standard)
	out443 := "ADMIN_KEY=adm123\nAERO_TOKEN=tok123\nADVERTISE=edge.example.com\nPORT=443\nSUB_SECRET=sec443\nSERVICE=active\n"
	ep443 := parseHarvest(out443, cred)
	if ep443.Port != 443 {
		t.Fatalf("expected port 443, got %d", ep443.Port)
	}
	expectedURL443 := "https://edge.example.com/sub/sec443"
	if ep443.SubURL != expectedURL443 {
		t.Fatalf("expected SubURL %s, got %s", expectedURL443, ep443.SubURL)
	}

	// 2. Port 8443 (auto-switched candidate port)
	out8443 := "ADMIN_KEY=adm123\nAERO_TOKEN=tok123\nADVERTISE=edge.example.com\nPORT=8443\nSUB_SECRET=sec8443\nSERVICE=active\n"
	ep8443 := parseHarvest(out8443, cred)
	if ep8443.Port != 8443 {
		t.Fatalf("expected port 8443, got %d", ep8443.Port)
	}
	expectedURL8443 := "https://edge.example.com:8443/sub/sec8443"
	if ep8443.SubURL != expectedURL8443 {
		t.Fatalf("expected SubURL %s, got %s", expectedURL8443, ep8443.SubURL)
	}

	// 3. Port 2053 (Cloudflare standard candidate port)
	out2053 := "ADMIN_KEY=adm123\nAERO_TOKEN=tok123\nADVERTISE=edge.example.com\nPORT=2053\nSUB_SECRET=sec2053\nSERVICE=active\n"
	ep2053 := parseHarvest(out2053, cred)
	if ep2053.Port != 2053 {
		t.Fatalf("expected port 2053, got %d", ep2053.Port)
	}
	expectedURL2053 := "https://edge.example.com:2053/sub/sec2053"
	if ep2053.SubURL != expectedURL2053 {
		t.Fatalf("expected SubURL %s, got %s", expectedURL2053, ep2053.SubURL)
	}
}

func TestEndpointStore_UpsertCustomPort(t *testing.T) {
	s := &Service{}
	_ = s
	ep := parseHarvest("ADMIN_KEY=adm\nPORT=8443\nSUB_SECRET=abc\nADVERTISE=edge.example.com\nSERVICE=active\n", &iface.Cred{
		VPSID: 1, Domain: "edge.example.com",
	})
	if ep.Port != 8443 {
		t.Fatalf("expected 8443, got %d", ep.Port)
	}
	if ep.SubURL != "https://edge.example.com:8443/sub/abc" {
		t.Fatalf("unexpected SubURL: %s", ep.SubURL)
	}
}
