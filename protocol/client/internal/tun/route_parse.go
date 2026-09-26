package tun

import (
	"net"
	"strconv"
	"strings"
)

// ParseDarwinNetstatDefaults reads `netstat -rn -f inet` (or `route -n get default`
// fallback lines). First non-TUN default wins.
func ParseDarwinNetstatDefaults(out string) (gw, iface string) {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] != "default" {
			continue
		}
		cand := fields[1]
		if net.ParseIP(cand) == nil || IsTUNIPv4(cand) {
			continue
		}
		name := fields[len(fields)-1]
		if IsTUNName(name) {
			continue
		}
		return cand, name
	}
	return "", ""
}

// ParseDarwinRouteGet reads `route -n get default`.
func ParseDarwinRouteGet(out string) (gw, iface string) {
	for _, line := range strings.Split(out, "\n") {
		s := strings.TrimSpace(line)
		low := strings.ToLower(s)
		if strings.HasPrefix(low, "gateway:") {
			gw = strings.TrimSpace(s[len("gateway:"):])
		}
		if strings.HasPrefix(low, "interface:") {
			iface = strings.TrimSpace(s[len("interface:"):])
		}
	}
	if IsTUNIPv4(gw) || IsTUNName(iface) || net.ParseIP(gw) == nil {
		return "", ""
	}
	return gw, iface
}

// ParseLinuxDefaults reads `ip -4 route show default`. Lowest metric, skip TUN.
func ParseLinuxDefaults(out string) (gw, iface string) {
	best := int(^uint(0) >> 1)
	found := false
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "default" {
			continue
		}
		var via, dev string
		metric := 0
		for i, f := range fields {
			if f == "via" && i+1 < len(fields) {
				via = fields[i+1]
			}
			if f == "dev" && i+1 < len(fields) {
				dev = fields[i+1]
			}
			if f == "metric" && i+1 < len(fields) {
				metric, _ = strconv.Atoi(fields[i+1])
			}
		}
		if via == "" || net.ParseIP(via) == nil || IsTUNIPv4(via) || IsTUNName(dev) {
			continue
		}
		if !found || metric < best {
			found = true
			best = metric
			gw, iface = via, dev
		}
	}
	return gw, iface
}
