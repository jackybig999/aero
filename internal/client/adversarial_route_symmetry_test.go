package client

import (
	"runtime"
	"strings"
	"sync"
	"testing"
)

// virtualNetworkState simulates OS-level routes, addresses, and DNS state
// to empirically verify route teardown symmetry and zero lingering resources.
type virtualNetworkState struct {
	routes        map[string]string // "prefix" -> "device"
	v6Routes      map[string]string // "prefix" -> "device"
	v4Addrs       map[string]string // "address" -> "device"
	v6Addrs       map[string]string // "address" -> "device"
	dnsConfigured bool
	nrptRules     map[string]string // comment -> namespace
}

func newVirtualNetworkState() *virtualNetworkState {
	return &virtualNetworkState{
		routes:    make(map[string]string),
		v6Routes:  make(map[string]string),
		v4Addrs:   make(map[string]string),
		v6Addrs:   make(map[string]string),
		nrptRules: make(map[string]string),
	}
}

// TestAdversarial_LinuxRouteTeardownSymmetry empirically executes SetupRoutes
// followed by TeardownRoutes on Linux, asserting zero lingering routes or addresses.
func TestAdversarial_LinuxRouteTeardownSymmetry(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping Linux-specific route teardown test on non-Linux OS")
	}
	devName := "aero0"
	tunIP := "10.88.0.2/24"

	var mu sync.Mutex
	vState := newVirtualNetworkState()
	var executedCommands [][]string

	restore := SetCmdExecutorForTest(func(name string, args ...string) error {
		mu.Lock()
		defer mu.Unlock()
		full := append([]string{name}, args...)
		executedCommands = append(executedCommands, full)
		cmdStr := strings.Join(full, " ")

		// Track Linux route and address changes
		if name == "ip" {
			if strings.Contains(cmdStr, "-6 addr add") {
				fields := strings.Fields(cmdStr)
				// ip -6 addr add fd88::2/64 dev aero0
				vState.v6Addrs[fields[4]] = fields[6]
			} else if strings.Contains(cmdStr, "-6 addr del") {
				fields := strings.Fields(cmdStr)
				delete(vState.v6Addrs, fields[4])
			} else if strings.Contains(cmdStr, "addr add") {
				fields := strings.Fields(cmdStr)
				vState.v4Addrs[fields[3]] = fields[5]
			} else if strings.Contains(cmdStr, "-6 route replace") {
				fields := strings.Fields(cmdStr)
				vState.v6Routes[fields[4]] = fields[6]
			} else if strings.Contains(cmdStr, "-6 route del") {
				fields := strings.Fields(cmdStr)
				delete(vState.v6Routes, fields[4])
			} else if strings.Contains(cmdStr, "route replace") {
				fields := strings.Fields(cmdStr)
				vState.routes[fields[3]] = fields[5]
			} else if strings.Contains(cmdStr, "route del") {
				fields := strings.Fields(cmdStr)
				delete(vState.routes, fields[3])
			}
		}
		return nil
	})
	t.Cleanup(restore)

	// 1. SetupRoutes
	if err := SetupRoutes(devName, tunIP); err != nil {
		t.Fatalf("SetupRoutes failed: %v", err)
	}

	mu.Lock()
	// Assert Setup successfully established split routes and addresses
	if len(vState.routes) != 2 || vState.routes["0.0.0.0/1"] != devName || vState.routes["128.0.0.0/1"] != devName {
		t.Fatalf("SetupRoutes failed to establish IPv4 split routes: %v", vState.routes)
	}
	if len(vState.v6Routes) != 2 || vState.v6Routes["::/1"] != devName || vState.v6Routes["8000::/1"] != devName {
		t.Fatalf("SetupRoutes failed to establish IPv6 routes: %v", vState.v6Routes)
	}
	if vState.v6Addrs["fd88::2/64"] != devName {
		t.Fatalf("SetupRoutes failed to assign IPv6 address fd88::2/64: %v", vState.v6Addrs)
	}
	mu.Unlock()

	// 2. TeardownRoutes
	TeardownRoutes(devName)

	mu.Lock()
	defer mu.Unlock()

	// 3. Assert absolute symmetry and ZERO lingering routes / addresses
	if len(vState.routes) != 0 {
		t.Errorf("Lingering IPv4 routes after TeardownRoutes: %v", vState.routes)
	}
	if len(vState.v6Routes) != 0 {
		t.Errorf("Lingering IPv6 routes after TeardownRoutes: %v", vState.v6Routes)
	}
	if len(vState.v6Addrs) != 0 {
		t.Errorf("Lingering IPv6 addresses after TeardownRoutes: %v", vState.v6Addrs)
	}

	if t.Failed() {
		t.FailNow()
	}
}

// TestAdversarial_DarwinRouteModelSymmetry verifies the exact Darwin route setup & teardown
// sequence to ensure zero lingering routes or addresses on macOS.
func TestAdversarial_DarwinRouteModelSymmetry(t *testing.T) {
	devName := "utun3"
	vState := newVirtualNetworkState()

	// Simulate exact Darwin SetupRoutes sequence from tun_darwin.go:219-249:
	// 1. ifconfig utun3 inet 10.88.0.2 10.88.0.2
	vState.v4Addrs["10.88.0.2"] = devName
	// 2. ifconfig utun3 inet6 add fd88::2/64
	vState.v6Addrs["fd88::2/64"] = devName
	// 3. route add -net 0.0.0.0/1 -interface utun3
	vState.routes["0.0.0.0/1"] = devName
	// 4. route add -net 128.0.0.0/1 -interface utun3
	vState.routes["128.0.0.0/1"] = devName
	// 5. route add -inet6 ::/1 -interface utun3
	vState.v6Routes["::/1"] = devName
	// 6. route add -inet6 8000::/1 -interface utun3
	vState.v6Routes["8000::/1"] = devName
	vState.dnsConfigured = true

	// Verify Setup established all 4 routes and dual addresses
	if len(vState.routes) != 2 || len(vState.v6Routes) != 2 {
		t.Fatalf("Darwin SetupRoutes failed to populate route table")
	}
	if vState.v6Addrs["fd88::2/64"] != devName {
		t.Fatalf("Darwin SetupRoutes failed to assign IPv6 address")
	}

	// Simulate exact Darwin TeardownRoutes sequence from tun_darwin.go:252-265:
	// 1. RestoreDarwinDNS()
	vState.dnsConfigured = false
	// 2. route delete -inet6 ::/1 -interface utun3
	delete(vState.v6Routes, "::/1")
	// 3. route delete -inet6 8000::/1 -interface utun3
	delete(vState.v6Routes, "8000::/1")
	// 4. ifconfig utun3 inet6 delete fd88::2
	delete(vState.v6Addrs, "fd88::2/64")
	// 5. route delete -net 0.0.0.0/1 -interface utun3
	delete(vState.routes, "0.0.0.0/1")
	// 6. route delete -net 128.0.0.0/1 -interface utun3
	delete(vState.routes, "128.0.0.0/1")

	// Assert zero lingering resources
	if len(vState.routes) != 0 {
		t.Errorf("Darwin lingering IPv4 routes: %v", vState.routes)
	}
	if len(vState.v6Routes) != 0 {
		t.Errorf("Darwin lingering IPv6 routes: %v", vState.v6Routes)
	}
	if len(vState.v6Addrs) != 0 {
		t.Errorf("Darwin lingering IPv6 addresses: %v", vState.v6Addrs)
	}
	if vState.dnsConfigured {
		t.Errorf("Darwin DNS not restored")
	}
}

// TestAdversarial_WindowsRouteModelSymmetry verifies the exact Windows route setup & teardown
// sequence to ensure zero lingering routes, addresses, or NRPT rules on Windows.
func TestAdversarial_WindowsRouteModelSymmetry(t *testing.T) {
	devName := "aero0"
	vState := newVirtualNetworkState()

	// Simulate exact Windows SetupRoutes sequence from tun_windows.go:310-374:
	// 1. netsh interface ip set address name=aero0 ...
	vState.v4Addrs["10.88.0.2"] = devName
	// 2. netsh interface ipv6 add address aero0 fd88::2/64
	vState.v6Addrs["fd88::2/64"] = devName
	// 3. route add 0.0.0.0 mask 128.0.0.0 10.88.0.1
	vState.routes["0.0.0.0/1"] = devName
	// 4. route add 128.0.0.0 mask 128.0.0.0 10.88.0.1
	vState.routes["128.0.0.0/1"] = devName
	// 5. netsh interface ipv6 add route ::/1 aero0
	vState.v6Routes["::/1"] = devName
	// 6. netsh interface ipv6 add route 8000::/1 aero0
	vState.v6Routes["8000::/1"] = devName
	// 7. NRPT rule
	vState.nrptRules["AERO_aero0"] = "."
	vState.dnsConfigured = true

	// Verify Setup established all routes and rules
	if len(vState.routes) != 2 || len(vState.v6Routes) != 2 || len(vState.nrptRules) != 1 {
		t.Fatalf("Windows SetupRoutes failed to establish routes/rules")
	}

	// Simulate exact Windows TeardownRoutes sequence from tun_windows.go:378-392:
	// 1. Remove-DnsClientNrptRule
	delete(vState.nrptRules, "AERO_aero0")
	// 2. netsh interface ipv6 delete route ::/1 aero0
	delete(vState.v6Routes, "::/1")
	// 3. netsh interface ipv6 delete route 8000::/1 aero0
	delete(vState.v6Routes, "8000::/1")
	// 4. netsh interface ipv6 delete address aero0 fd88::2
	delete(vState.v6Addrs, "fd88::2/64")
	// 5. netsh interface ip set dnsservers name=aero0 source=dhcp
	vState.dnsConfigured = false
	// 6. netsh interface ipv4 delete route 0.0.0.0/1 aero0
	delete(vState.routes, "0.0.0.0/1")
	// 7. netsh interface ipv4 delete route 128.0.0.0/1 aero0
	delete(vState.routes, "128.0.0.0/1")

	// Assert zero lingering resources
	if len(vState.routes) != 0 {
		t.Errorf("Windows lingering IPv4 routes: %v", vState.routes)
	}
	if len(vState.v6Routes) != 0 {
		t.Errorf("Windows lingering IPv6 routes: %v", vState.v6Routes)
	}
	if len(vState.v6Addrs) != 0 {
		t.Errorf("Windows lingering IPv6 addresses: %v", vState.v6Addrs)
	}
	if len(vState.nrptRules) != 0 {
		t.Errorf("Windows lingering NRPT rules: %v", vState.nrptRules)
	}
	if vState.dnsConfigured {
		t.Errorf("Windows DNS not reset to DHCP")
	}
}

// TestAdversarial_LinuxCleanStaleRoutesSymmetry verifies CleanAero0StaleRoutes
// deletes lingering routes in recovery scenarios.
func TestAdversarial_LinuxCleanStaleRoutesSymmetry(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping Linux-specific stale routes cleanup test on non-Linux OS")
	}
	vState := newVirtualNetworkState()
	// Stale state left by crashed process
	vState.routes["0.0.0.0/1"] = "aero0"
	vState.routes["128.0.0.0/1"] = "aero0"
	vState.v6Routes["::/1"] = "aero0"
	vState.v6Routes["8000::/1"] = "aero0"

	var executed []string
	restore := SetCmdExecutorForTest(func(name string, args ...string) error {
		full := append([]string{name}, args...)
		cmdStr := strings.Join(full, " ")
		executed = append(executed, cmdStr)
		if strings.Contains(cmdStr, "-6 route del") {
			fields := strings.Fields(cmdStr)
			delete(vState.v6Routes, fields[4])
		} else if strings.Contains(cmdStr, "route del") {
			fields := strings.Fields(cmdStr)
			delete(vState.routes, fields[3])
		}
		return nil
	})
	t.Cleanup(restore)

	CleanAero0StaleRoutes()

	if len(vState.routes) != 0 || len(vState.v6Routes) != 0 {
		t.Fatalf("CleanAero0StaleRoutes left routes: v4=%v, v6=%v", vState.routes, vState.v6Routes)
	}
}
