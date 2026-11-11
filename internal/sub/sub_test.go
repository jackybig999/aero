// Copyright 2026 AERO Protocol Contributors
// Authoritative Zero-Port Subscription Wire Contract Regression Test
package sub

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestZeroPortSubscription_StrictMandate strictly verifies the zero-port mandate
// per PROJECT_RULES.md, AGENTS.md Rule 11/Rule 22, and GEMINI.md P8/P20.
// Subscription distribution URLs must exclusively use standard 443 HTTPS without
// any port segment (https://domain/sub/slug), while data-plane address and alt_ports
// configurations must retain their configured ports (e.g. 8443, 2083, 2087).
func TestZeroPortSubscription_StrictMandate(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "zero_port_mandate_test_*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	uDB := NewMemoryUserStore()
	uSvc := NewUserService(uDB, "test-secret-mandate-salt-999")

	// 1. Register a standard user
	userTom, err := uSvc.Register(CreateUserParams{
		Username: "tom",
		Password: "password999",
		Email:    "tom@aero-test.com",
	})
	if err != nil {
		t.Fatalf("register tom: %v", err)
	}

	// 2. Setup endpoints with non-standard ports (8443, 2083, 2087) and alternate ports
	epFile := filepath.Join(tempDir, "endpoints_zero_port.json")
	epStore, err := NewEndpointStore(epFile)
	if err != nil {
		t.Fatalf("epStore: %v", err)
	}

	ep1 := EndpointInfo{
		VPSID:     1,
		Name:      "Node-Non443-8443",
		Host:      "edge8443.aero-net.com",
		IP:        "103.88.1.1",
		Port:      8443,
		SubSecret: "sec_edge_8443",
		Installed: true,
	}
	ep2 := EndpointInfo{
		VPSID:     2,
		Name:      "Node-Non443-2083",
		Host:      "edge2083.aero-net.com",
		IP:        "103.88.1.2",
		Port:      2083,
		SubSecret: "sec_edge_2083",
		Installed: true,
	}
	ep3 := EndpointInfo{
		VPSID:     3,
		Name:      "Node-Non443-2087",
		Host:      "edge2087.aero-net.com",
		IP:        "103.88.1.3",
		Port:      2087,
		SubSecret: "sec_edge_2087",
		Installed: true,
	}

	_ = epStore.Upsert(ep1)
	_ = epStore.Upsert(ep2)
	_ = epStore.Upsert(ep3)

	sniMgr := NewSNIMatrixManager("")
	subBuilder := NewSubBuilder(uDB, epStore, nil, sniMgr)

	mux := http.NewServeMux()
	subBuilder.RegisterRoutes(mux)

	// Subtest A: Regular User Subscription Document & Data Plane Preservation
	t.Run("RegularUser_ZeroPortURL_And_DataPlanePreserved", func(t *testing.T) {
		doc, status, buildErr := subBuilder.BuildSubscriptionDoc(userTom, "", "", false)
		if buildErr != nil || status != http.StatusOK {
			t.Fatalf("BuildSubscriptionDoc failed status=%d err=%v", status, buildErr)
		}

		subUrl, ok := doc["sub_url"].(string)
		if !ok || subUrl == "" {
			t.Fatalf("doc[sub_url] missing or empty")
		}
		subUrlCamel, okCamel := doc["subUrl"].(string)
		if !okCamel || subUrlCamel != subUrl {
			t.Fatalf("doc[subUrl] (%s) != doc[sub_url] (%s)", subUrlCamel, subUrl)
		}

		u, parseErr := url.Parse(subUrl)
		if parseErr != nil {
			t.Fatalf("parse subUrl %s: %v", subUrl, parseErr)
		}
		if u.Scheme != "https" {
			t.Errorf("expected https scheme, got %s", u.Scheme)
		}
		if u.Port() != "" {
			t.Errorf("VIOLATION: sub_url contains port: %s (parsed port: %s)", subUrl, u.Port())
		}
		if strings.Contains(subUrl, ":8443") || strings.Contains(subUrl, ":2083") || strings.Contains(subUrl, ":2087") || strings.Contains(subUrl, ":443") || strings.Contains(subUrl, ":18080") {
			t.Errorf("VIOLATION: sub_url contains forbidden port token: %s", subUrl)
		}
		validHosts := map[string]bool{
			ep1.Host: true,
			ep2.Host: true,
			ep3.Host: true,
		}
		if !validHosts[u.Hostname()] {
			t.Errorf("sub_url hostname %q is not in expected endpoints", u.Hostname())
		}
		expectedPath := "/sub/" + userTom.SubSlug
		if u.Path != expectedPath {
			t.Errorf("expected sub_url path %s, got %s", expectedPath, u.Path)
		}

		// Verify Data Plane Preservation (Criterion e)
		servers, ok := doc["servers"].([]map[string]any)
		if !ok || len(servers) != 3 {
			t.Fatalf("expected 3 servers in data plane doc, got %d", len(servers))
		}

		serverByHost := make(map[string]map[string]any)
		for _, s := range servers {
			if h, ok := s["host"].(string); ok {
				serverByHost[h] = s
			}
		}

		for _, ep := range []EndpointInfo{ep1, ep2, ep3} {
			srv, exists := serverByHost[ep.Host]
			if !exists {
				t.Fatalf("expected server for host %s in servers list", ep.Host)
			}
			expectedAddr := fmt.Sprintf("%s:%d", ep.Host, ep.Port)
			if srv["address"] != expectedAddr {
				t.Errorf("data plane address mutated! expected %s, got %v", expectedAddr, srv["address"])
			}
			if srv["ip"] != ep.IP {
				t.Errorf("expected ip %s, got %v", ep.IP, srv["ip"])
			}
			if srv["serverName"] != ep.Host {
				t.Errorf("expected serverName %s, got %v", ep.Host, srv["serverName"])
			}
			altPorts, ok := srv["alt_ports"].([]int)
			if !ok || len(altPorts) == 0 {
				t.Fatalf("expected srv %s alt_ports to be []int, got %v", ep.Host, srv["alt_ports"])
			}
			has443 := false
			for _, p := range altPorts {
				if p == 443 {
					has443 = true
				}
				if p == ep.Port {
					t.Errorf("alt_ports should not contain primary port %d, got %v", ep.Port, altPorts)
				}
			}
			if ep.Port != 443 && !has443 {
				t.Errorf("expected alt_ports for %s to include fallback port 443, got %v", ep.Host, altPorts)
			}
		}
	})

	// Subtest B: 固定名称的管理员入口不存在
	t.Run("NoFixedAdminEntry", func(t *testing.T) {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sub/superadmin", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404 for /sub/superadmin, got %d", rec.Code)
		}
	})

	// Subtest C: HTTP Request with Non-Standard Host Header Does Not Bleed Port
	t.Run("HTTPHostHeader_ZeroPortStripping", func(t *testing.T) {
		// Non-standard port in Host header
		reqWithPort := httptest.NewRequest(http.MethodGet, "/sub/"+userTom.SubSlug, nil)
		reqWithPort.Host = "custom-proxy.aero-infra.com:8443"
		recWithPort := httptest.NewRecorder()
		mux.ServeHTTP(recWithPort, reqWithPort)

		if recWithPort.Code != http.StatusOK {
			t.Fatalf("expected 200 for host-with-port request, got %d", recWithPort.Code)
		}

		var docHostPort map[string]any
		if err := json.Unmarshal(recWithPort.Body.Bytes(), &docHostPort); err != nil {
			t.Fatalf("unmarshal doc: %v", err)
		}
		subUrlHost := docHostPort["sub_url"].(string)
		uHost, err := url.Parse(subUrlHost)
		if err != nil {
			t.Fatalf("parse url %q: %v", subUrlHost, err)
		}
		if uHost.Port() != "" {
			t.Errorf("VIOLATION: non-standard Host header bled port into sub_url: %s", subUrlHost)
		}
		expectedHostURL := "https://custom-proxy.aero-infra.com/sub/" + userTom.SubSlug
		if subUrlHost != expectedHostURL {
			t.Errorf("expected sub_url=%s, got=%s", expectedHostURL, subUrlHost)
		}

		// Non-standard port in X-Forwarded-Host header
		reqFwd := httptest.NewRequest(http.MethodGet, "/sub/"+userTom.SubSlug, nil)
		reqFwd.Header.Set("X-Forwarded-Host", "fwd-gateway.aero-infra.com:2087")
		recFwd := httptest.NewRecorder()
		mux.ServeHTTP(recFwd, reqFwd)

		if recFwd.Code != http.StatusOK {
			t.Fatalf("expected 200 for X-Forwarded-Host request, got %d", recFwd.Code)
		}
		var docFwd map[string]any
		if err := json.Unmarshal(recFwd.Body.Bytes(), &docFwd); err != nil {
			t.Fatalf("unmarshal fwd doc: %v", err)
		}
		subUrlFwd := docFwd["sub_url"].(string)
		uFwd, err := url.Parse(subUrlFwd)
		if err != nil {
			t.Fatalf("parse fwd url %q: %v", subUrlFwd, err)
		}
		if uFwd.Port() != "" {
			t.Errorf("VIOLATION: X-Forwarded-Host bled port into sub_url: %s", subUrlFwd)
		}
		expectedFwdURL := "https://fwd-gateway.aero-infra.com/sub/" + userTom.SubSlug
		if subUrlFwd != expectedFwdURL {
			t.Errorf("expected sub_url=%s, got=%s", expectedFwdURL, subUrlFwd)
		}

		// Chained non-standard proxies in X-Forwarded-Host header
		reqChained := httptest.NewRequest(http.MethodGet, "/sub/"+userTom.SubSlug, nil)
		reqChained.Header.Set("X-Forwarded-Host", "first-proxy.aero-infra.com:8443, second-proxy.aero-infra.com:2083")
		recChained := httptest.NewRecorder()
		mux.ServeHTTP(recChained, reqChained)

		if recChained.Code != http.StatusOK {
			t.Fatalf("expected 200 for chained X-Forwarded-Host request, got %d", recChained.Code)
		}
		var docChained map[string]any
		if err := json.Unmarshal(recChained.Body.Bytes(), &docChained); err != nil {
			t.Fatalf("unmarshal chained doc: %v", err)
		}
		subUrlChained := docChained["sub_url"].(string)
		uChained, err := url.Parse(subUrlChained)
		if err != nil {
			t.Fatalf("parse chained fwd url %q: %v", subUrlChained, err)
		}
		if uChained.Port() != "" {
			t.Errorf("VIOLATION: chained X-Forwarded-Host bled port into sub_url: %s", subUrlChained)
		}
		if strings.Contains(subUrlChained, ",") || strings.Contains(subUrlChained, ":8443") || strings.Contains(subUrlChained, ":2083") {
			t.Errorf("VIOLATION: chained X-Forwarded-Host leaked comma or port: %s", subUrlChained)
		}
		expectedChainedURL := "https://first-proxy.aero-infra.com/sub/" + userTom.SubSlug
		if subUrlChained != expectedChainedURL {
			t.Errorf("expected sub_url=%s, got=%s", expectedChainedURL, subUrlChained)
		}
	})

	// Subtest D: EndpointInfo Zero-Port Mandate（旧 /etc/aero/env 采集已删除）
	t.Run("ProbeHarvest_And_VPSService_ZeroPortMandate", func(t *testing.T) {
		// VPSService.UpdateDomain zero-port test
		memVPS := NewMemoryVPSStore()
		box, err := NewSecretBox()
		if err != nil {
			t.Fatalf("NewSecretBox: %v", err)
		}
		epStoreTest, err := NewEndpointStore(filepath.Join(tempDir, "ep_vps_svc.json"))
		if err != nil {
			t.Fatalf("epStoreTest: %v", err)
		}
		createdHost, err := memVPS.Create(CreateVPSParams{
			IP:      "10.0.0.1",
			SSHPort: 22,
			Name:    "VPS-10",
		})
		if err != nil {
			t.Fatalf("memVPS.Create: %v", err)
		}
		testEP := EndpointInfo{
			VPSID:     createdHost.ID,
			Name:      "Node-VPS-10",
			Host:      "initial.aero-net.com",
			Port:      8443,
			SubSecret: "secret_vps_10",
			Installed: true,
		}
		_ = epStoreTest.Upsert(testEP)

		vpsSvc := NewVPSService(memVPS, box, epStoreTest)
		updateErr := vpsSvc.UpdateDomain(createdHost.ID, "new-domain.aero-net.com:8443")
		if updateErr != nil {
			t.Fatalf("UpdateDomain failed: %v", updateErr)
		}
		updatedEP, ok := epStoreTest.Get(createdHost.ID)
		if !ok {
			t.Fatalf("endpoint 10 not found in store")
		}
		if updatedEP.Port != 8443 {
			t.Errorf("data plane Port was lost after UpdateDomain! expected 8443, got %d", updatedEP.Port)
		}
		if updatedEP.Host != "new-domain.aero-net.com" {
			t.Errorf("UpdateDomain failed to clean ep.Host! got %q, expected %q", updatedEP.Host, "new-domain.aero-net.com")
		}
		if strings.Contains(updatedEP.SubURL, ":8443") {
			t.Errorf("VIOLATION: UpdateDomain produced SubURL with port: %s", updatedEP.SubURL)
		}
		expectedUpdatedURL := "https://new-domain.aero-net.com/sub/secret_vps_10"
		if updatedEP.SubURL != expectedUpdatedURL {
			t.Errorf("expected SubURL=%s, got=%s", expectedUpdatedURL, updatedEP.SubURL)
		}
		uUpdated, err := url.Parse(updatedEP.SubURL)
		if err != nil || uUpdated.Port() != "" {
			t.Errorf("UpdateDomain SubURL must have empty port, got %s (port: %s)", updatedEP.SubURL, uUpdated.Port())
		}

		vpsSubBuilder := NewSubBuilder(uDB, epStoreTest, nil, sniMgr)
		vpsDoc, _, vpsErr := vpsSubBuilder.BuildSubscriptionDoc(userTom, "", "", false)
		if vpsErr != nil {
			t.Fatalf("BuildSubscriptionDoc after UpdateDomain: %v", vpsErr)
		}
		vpsSubURL, _ := vpsDoc["sub_url"].(string)
		if strings.Contains(vpsSubURL, ":8443") {
			t.Errorf("VIOLATION: BuildSubscriptionDoc after UpdateDomain produced sub_url with port: %s", vpsSubURL)
		}
		vpsServers, ok := vpsDoc["servers"].([]map[string]any)
		if !ok || len(vpsServers) == 0 {
			t.Fatalf("expected servers in vpsDoc")
		}
		if vpsServers[0]["address"] != "new-domain.aero-net.com:8443" {
			t.Errorf("expected address new-domain.aero-net.com:8443, got %v", vpsServers[0]["address"])
		}
	})

	// Subtest E: Empty Endpoints Fallback Zero-Port Mandate (Kills Mutant M6)
	t.Run("EmptyEndpoints_FallbackZeroPortMandate", func(t *testing.T) {
		emptyStore, err := NewEndpointStore(filepath.Join(tempDir, "empty_eps.json"))
		if err != nil {
			t.Fatalf("emptyStore: %v", err)
		}
		emptyBuilder := NewSubBuilder(uDB, emptyStore, nil, sniMgr)
		doc, status, err := emptyBuilder.BuildSubscriptionDoc(userTom, "", "", false)
		if err != nil || status != http.StatusOK {
			t.Fatalf("BuildSubscriptionDoc empty: status=%d err=%v", status, err)
		}
		subUrl, ok := doc["sub_url"].(string)
		if !ok || subUrl == "" {
			t.Fatalf("missing sub_url in empty fallback doc")
		}
		u, err := url.Parse(subUrl)
		if err != nil {
			t.Fatalf("parse fallback sub_url: %v", err)
		}
		if u.Scheme != "https" {
			t.Errorf("expected https, got %s", u.Scheme)
		}
		if u.Port() != "" {
			t.Errorf("VIOLATION: fallback sub_url contains port: %s (port: %s)", subUrl, u.Port())
		}
		if strings.Contains(subUrl, ":8443") || strings.Contains(subUrl, ":443") || strings.Contains(subUrl, ":18080") {
			t.Errorf("VIOLATION: fallback sub_url contains leaked port: %s", subUrl)
		}
		expectedFallbackURL := "https://domain.com/sub/" + userTom.SubSlug
		if subUrl != expectedFallbackURL {
			t.Errorf("expected fallback URL %s, got %s", expectedFallbackURL, subUrl)
		}
	})

	// Subtest F: Abnormal Host (Domain or IP with explicit port) Sanitization
	t.Run("AbnormalHost_PortSanitizationAndIPFiltering", func(t *testing.T) {
		abnormalStore, err := NewEndpointStore(filepath.Join(tempDir, "abnormal_eps.json"))
		if err != nil {
			t.Fatalf("abnormalStore: %v", err)
		}
		// Node with domain having explicit port
		_ = abnormalStore.Upsert(EndpointInfo{
			VPSID:     11,
			Name:      "Node-DirtyDomain",
			Host:      "dirty-domain.aero.com:8443",
			Port:      8443,
			SubSecret: "sec11",
			Installed: true,
		})
		// Node with IP having explicit port
		_ = abnormalStore.Upsert(EndpointInfo{
			VPSID:     12,
			Name:      "Node-DirtyIP",
			Host:      "1.2.3.4:443",
			Port:      443,
			SubSecret: "sec12",
			Installed: true,
		})

		abnormalBuilder := NewSubBuilder(uDB, abnormalStore, nil, sniMgr)
		doc, status, err := abnormalBuilder.BuildSubscriptionDoc(userTom, "", "", false)
		if err != nil || status != http.StatusOK {
			t.Fatalf("BuildSubscriptionDoc abnormal: status=%d err=%v", status, err)
		}
		subUrl := doc["sub_url"].(string)
		u, err := url.Parse(subUrl)
		if err != nil {
			t.Fatalf("parse abnormal sub_url: %v", err)
		}
		if u.Port() != "" {
			t.Errorf("VIOLATION: abnormal sub_url leaked port %s: %s", u.Port(), subUrl)
		}
		if strings.Contains(subUrl, "1.2.3.4") {
			t.Errorf("VIOLATION: IP node with port was not filtered out: %s", subUrl)
		}
		expectedSub := "https://dirty-domain.aero.com/sub/" + userTom.SubSlug
		if subUrl != expectedSub {
			t.Errorf("expected sub_url=%s, got %s", expectedSub, subUrl)
		}

		servers := doc["servers"].([]map[string]any)
		if len(servers) != 1 {
			t.Fatalf("expected 1 server (IP node skipped), got %d", len(servers))
		}
		if servers[0]["address"] != "dirty-domain.aero.com:8443" {
			t.Errorf("expected clean server address dirty-domain.aero.com:8443, got %v", servers[0]["address"])
		}
	})
}
