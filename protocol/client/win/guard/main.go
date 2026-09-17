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
	time.Sleep(400 * time.Millisecond)
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
	ie := `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	srv := regQuery(ie, "ProxyServer")
	pac := regQuery(ie, "AutoConfigURL")
	ours := strings.Contains(srv, "55555") || strings.Contains(srv, "19877") ||
		strings.Contains(pac, "19877") || strings.Contains(pac, "aero")
	if ours || srv == "" {
		quiet("reg", "add", ie, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f")
		if ours {
			quiet("reg", "delete", ie, "/v", "ProxyServer", "/f")
		}
		if strings.Contains(pac, "19877") || strings.Contains(pac, "aero") {
			quiet("reg", "delete", ie, "/v", "AutoConfigURL", "/f")
		}
	}
	quiet("netsh", "winhttp", "reset", "proxy")

	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		cur := userEnv(k)
		if strings.Contains(cur, "55555") {
			quiet("reg", "delete", `HKCU\Environment`, "/v", k, "/f")
		}
	}

	quiet("netsh", "interface", "set", "interface", "name=aero0", "admin=DISABLED")

	// Drop AERO split-default routes only (next hop 10.88.0.2).
	prt := exec.Command("route", "print", "-4")
	prt.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, _ := prt.Output()
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

	for _, n := range []string{"AERO-NoQUIC-all", "AERO-NoQUIC-chrome", "AERO-NoQUIC-edge", "AERO-NoQUIC-msedge", "AERO-NoQUIC-brave", "AERO-NoQUIC-chromium", "AERO-NoIPv6"} {
		quiet("netsh", "advfirewall", "firewall", "delete", "rule", "name="+n)
	}

	// Leftover Fake DNS on physical NIC only.
	ifacesCmd := exec.Command("netsh", "interface", "show", "interface")
	ifacesCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	ifaces, _ := ifacesCmd.Output()
	for _, line := range strings.Split(string(ifaces), "\n") {
		if !strings.Contains(line, "Connected") && !strings.Contains(line, "已连接") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		name := strings.Join(fields[3:], " ")
		low := strings.ToLower(name)
		if strings.Contains(low, "sing") || strings.Contains(low, "loopback") || strings.Contains(low, "meta") || strings.Contains(low, "clash") {
			continue
		}
		dnsCmd := exec.Command("netsh", "interface", "ip", "show", "dns", "name="+name)
		dnsCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		cfg, err := dnsCmd.Output()
		if err != nil || !strings.Contains(string(cfg), "10.88.0.2") {
			continue
		}
		quiet("netsh", "interface", "ip", "set", "dns", "name="+name, "dhcp")
	}
	quiet("ipconfig", "/flushdns")
	notifyProxy()
}

func quiet(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Run()
}

func regQuery(key, val string) string {
	q := exec.Command("reg", "query", key, "/v", val)
	q.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := q.CombinedOutput()
	if err != nil {
		return ""
	}
	return string(out)
}

func userEnv(name string) string {
	return regQuery(`HKCU\Environment`, name)
}

func notifyProxy() {
	ps := `[void][System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer;` +
		`Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class W{` +
		`[DllImport("wininet.dll",SetLastError=true)] public static extern bool InternetSetOption(IntPtr h,int o,IntPtr b,int l);}';` +
		`[void][W]::InternetSetOption([IntPtr]::Zero,39,[IntPtr]::Zero,0);` +
		`[void][W]::InternetSetOption([IntPtr]::Zero,37,[IntPtr]::Zero,0)`
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Run()
}
