package public

import (
	"fmt"
	"net"
	"sync"
	"time"
)

type ProxyTarget struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // "http" or "socks5"
	Name     string `json:"name"`
	Verified bool   `json:"verified"`
}

type SystemProxy struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Server  string `json:"server"`
	Enabled bool   `json:"enabled"`
}

type DetectResponse struct {
	Success     bool          `json:"success"`
	Proxies     []ProxyTarget `json:"proxies"`
	SystemProxy *SystemProxy  `json:"systemProxy"`
	Error       string        `json:"error,omitempty"`
}

var commonPorts = []struct {
	Port     int
	Protocol string
	Name     string
}{
	{55555, "http", "AERO Mixed (55555)"},
	{7890, "http", "Clash / Mihomo (7890)"},
	{7891, "socks5", "Clash SOCKS5 (7891)"},
	{10808, "socks5", "v2rayN SOCKS5 (10808)"},
	{10809, "http", "v2rayN HTTP (10809)"},
	{4780, "http", "Clash Verge (4780)"},
	{1080, "socks5", "SOCKS5 Default (1080)"},
	{20171, "socks5", "v2rayN Alt (20171)"},
	{8080, "http", "HTTP Proxy (8080)"},
	{8888, "http", "Fiddler / Charles (8888)"},
	{9090, "http", "Surge (9090)"},
}

// DetectProxies scans local ports and queries platform for system proxy.
func DetectProxies(p Platform) ([]ProxyTarget, *SystemProxy) {
	var found []ProxyTarget
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, cp := range commonPorts {
		wg.Add(1)
		go func(port int, proto, name string) {
			defer wg.Done()
			addr := fmt.Sprintf("127.0.0.1:%d", port)
			conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				mu.Lock()
				found = append(found, ProxyTarget{
					Host:     "127.0.0.1",
					Port:     port,
					Protocol: proto,
					Name:     name,
					Verified: true,
				})
				mu.Unlock()
			}
		}(cp.Port, cp.Protocol, cp.Name)
	}

	wg.Wait()
	var sp *SystemProxy
	if p != nil {
		sp = p.DetectSystemProxy()
	}
	return found, sp
}
