package tun

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// IsTUNName is true for our adapter and other tunnel nics. Shared by Win/mac/Linux.
func IsTUNName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	if strings.Contains(n, "aero") || strings.Contains(n, "wintun") {
		return true
	}
	if strings.HasPrefix(n, "utun") || strings.HasPrefix(n, "tun") {
		return true
	}
	return false
}

// IsTUNIPv4 is the AERO TUN address block (never a physical hop).
func IsTUNIPv4(s string) bool {
	return strings.HasPrefix(s, "10.88.")
}

// WaitStablePhysicalGW waits until PhysicalDefaultGateway stays the same
// across two samples. Used on every OS; each OS implements PhysicalDefaultGateway.
func WaitStablePhysicalGW(timeout time.Duration) (gw, ifIndex string, err error) {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	deadline := time.Now().Add(timeout)
	var prevGW, prevIF string
	for {
		gw, ifIndex, err = PhysicalDefaultGateway()
		if err == nil && gw != "" && ifIndex != "" {
			if gw == prevGW && ifIndex == prevIF {
				return gw, ifIndex, nil
			}
			prevGW, prevIF = gw, ifIndex
		} else {
			prevGW, prevIF = "", ""
		}
		if !time.Now().Before(deadline) {
			if prevGW != "" && prevIF != "" {
				return prevGW, prevIF, nil
			}
			if err == nil {
				err = fmt.Errorf("no stable physical gateway")
			}
			return "", "", err
		}
		time.Sleep(400 * time.Millisecond)
	}
}

func ifaceIndexByName(name string) string {
	if name == "" {
		return ""
	}
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return name
	}
	return strconv.Itoa(ifi.Index)
}

func ifaceIPv4ByName(name string) net.IP {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil
	}
	addrs, _ := ifi.Addrs()
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipn.IP.To4()
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		if IsTUNIPv4(ip.String()) {
			continue
		}
		return ip
	}
	return nil
}

// firstPhysicalIPv4 is the fallback when the OS route table is not readable
// (iOS Network Extension). Change of this IP is still a Wi-Fi switch.
func firstPhysicalIPv4() (ip net.IP, name string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, ""
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if IsTUNName(ifi.Name) {
			continue
		}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			v4 := ipn.IP.To4()
			if v4 == nil || v4.IsLoopback() || v4.IsLinkLocalUnicast() {
				continue
			}
			if IsTUNIPv4(v4.String()) {
				continue
			}
			return v4, ifi.Name
		}
	}
	return nil, ""
}
