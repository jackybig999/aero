// aero-guard: detached watchdog for Windows. If aerowin/aero-ech dies (crash, taskkill, cmd closed),
// restore Windows network so proxy or TUN leftovers cannot blackhole the PC.
// Does not touch third-party adapters (sing-box / Clash).
package main

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	modWininet            = syscall.NewLazyDLL("wininet.dll")
	procInternetSetOption = modWininet.NewProc("InternetSetOptionW")
)

func main() {
	pid := 0
	for i, a := range os.Args {
		if a == "-pid" && i+1 < len(os.Args) {
			pid, _ = strconv.Atoi(os.Args[i+1])
		}
	}
	if pid <= 0 {
		os.Exit(2)
	}
	for processAlive(pid) {
		time.Sleep(1500 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	recoverNetwork()
}

func processAlive(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	return code == 259 // STILL_ACTIVE
}

func recoverNetwork() {
	// 1. Direct native registry reset (instant, zero process spawning)
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.SET_VALUE|registry.QUERY_VALUE)
	if err == nil {
		defer k.Close()
		srv, _, _ := k.GetStringValue("ProxyServer")
		pac, _, _ := k.GetStringValue("AutoConfigURL")
		ours := strings.Contains(srv, "55555") || strings.Contains(srv, "19877") ||
			strings.Contains(pac, "19877") || strings.Contains(pac, "aero")
		if ours || srv == "" {
			_ = k.SetDWordValue("ProxyEnable", 0)
			if ours {
				_ = k.DeleteValue("ProxyServer")
			}
			if strings.Contains(pac, "19877") || strings.Contains(pac, "aero") {
				_ = k.DeleteValue("AutoConfigURL")
			}
		}
	}

	// 2. Direct user environment variables cleanup
	if envK, err := registry.OpenKey(registry.CURRENT_USER, `Environment`, registry.SET_VALUE|registry.QUERY_VALUE); err == nil {
		defer envK.Close()
		for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
			if cur, _, _ := envK.GetStringValue(name); strings.Contains(cur, "55555") {
				_ = envK.DeleteValue(name)
			}
		}
	}

	// 3. Reset WinHTTP proxy
	quiet("netsh", "winhttp", "reset", "proxy")

	// 4. Disable AERO TUN adapter if active
	quiet("netsh", "interface", "set", "interface", "name=aero0", "admin=DISABLED")

	// 5. Drop AERO routes
	prt := exec.Command("route", "print", "-4")
	prt.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if out, err := prt.Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			f := strings.Fields(line)
			if len(f) < 3 {
				continue
			}
			if (f[0] == "0.0.0.0" && f[1] == "128.0.0.0" || f[0] == "128.0.0.0" && f[1] == "128.0.0.0") &&
				strings.HasPrefix(f[2], "10.88.") {
				quiet("route", "delete", f[0], "mask", f[1])
			}
		}
	}

	// 6. Delete AERO firewall rules
	for _, n := range []string{"AERO-NoQUIC-all", "AERO-NoQUIC-chrome", "AERO-NoQUIC-edge", "AERO-NoQUIC-msedge", "AERO-NoQUIC-brave", "AERO-NoQUIC-chromium", "AERO-NoIPv6"} {
		quiet("netsh", "advfirewall", "firewall", "delete", "rule", "name="+n)
	}

	// 7. Flush DNS and notify WinINET natively
	quiet("ipconfig", "/flushdns")
	notifyProxy()
}

func quiet(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Run()
}

func notifyProxy() {
	// INTERNET_OPTION_SETTINGS_CHANGED = 39, INTERNET_OPTION_REFRESH = 37
	_, _, _ = procInternetSetOption.Call(0, 39, 0, 0)
	_, _, _ = procInternetSetOption.Call(0, 37, 0, 0)
}
