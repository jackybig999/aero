//go:build windows

package runtime

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

// LastBrowserLockHint is set by ApplyBrowserLock for the GUI.
var LastBrowserLockHint string

const userEnvKey = `HKCU\Environment`

func userEnvQuery(name string) string {
	out, err := cmdHidden("reg", "query", userEnvKey, "/v", name).CombinedOutput()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, name) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			return fields[len(fields)-1]
		}
	}
	return ""
}

func (w *windowsRuntime) snapshotUserEnvOnce() {
	if w.envSnap {
		return
	}
	w.prevUserHTTP = userEnvQuery("HTTP_PROXY")
	w.prevUserHTTPS = userEnvQuery("HTTPS_PROXY")
	w.prevUserALL = userEnvQuery("ALL_PROXY")
	w.prevUserNO = userEnvQuery("NO_PROXY")
	w.envSnap = true
}

// setUserProxyEnv is sysproxy-only. TUN does not call this.
// Disconnect/exit must clearUserProxyEnv so box/Clash are not left on 55555.
func (w *windowsRuntime) setUserProxyEnv(mixed string) {
	// Zero Environment Tampering: 严禁向 HKCU\Environment 注入任何代理环境变量
	_ = mixed
}

func restoreOneUserEnv(name, prev string) {
	cur := userEnvQuery(name)
	ours := strings.Contains(cur, "55555") || strings.Contains(cur, "127.0.0.1:55556")
	if !ours && cur != "" {
		return
	}
	if prev != "" && !strings.Contains(prev, "55555") {
		quietRun("reg", "add", userEnvKey, "/v", name, "/t", "REG_SZ", "/d", prev, "/f")
		return
	}
	quietRun("reg", "delete", userEnvKey, "/v", name, "/f")
}

func (w *windowsRuntime) clearUserProxyEnv() {
	// Always drop AERO 55555 hijack first. Leaving HTTP_PROXY in HKCU
	// Environment makes grok.exe ignore box/Clash TUN after AERO is "closed".
	for _, n := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy", "NO_PROXY", "no_proxy"} {
		cur := userEnvQuery(n)
		oursNO := (n == "NO_PROXY" || n == "no_proxy") && cur == "localhost,127.0.0.1,::1"
		if cur == "" || oursNO || strings.Contains(cur, "55555") || strings.Contains(cur, "127.0.0.1:55556") {
			quietRun("reg", "delete", userEnvKey, "/v", n, "/f")
		}
	}
	if w.envSnap {
		restoreOneUserEnv("HTTP_PROXY", w.prevUserHTTP)
		restoreOneUserEnv("HTTPS_PROXY", w.prevUserHTTPS)
		restoreOneUserEnv("ALL_PROXY", w.prevUserALL)
		restoreOneUserEnv("NO_PROXY", w.prevUserNO)
		w.envSnap = false
	}
	broadcastEnvChange()
}

var (
	wininet                = syscall.NewLazyDLL("wininet.dll")
	procInternetSetOptionW = wininet.NewProc("InternetSetOptionW")
)

const (
	internetOptionSettingsChanged = 39
	internetOptionRefresh         = 37
)

// notifyWinINet tells WinINET/browsers proxy settings changed.
// Direct DLL call — do not spawn PowerShell (that was 1–3s on disconnect).
func notifyWinINet() {
	_, _, _ = procInternetSetOptionW.Call(0, internetOptionSettingsChanged, 0, 0)
	_, _, _ = procInternetSetOptionW.Call(0, internetOptionRefresh, 0, 0)
}

func broadcastEnvChange() {
	user32 := syscall.NewLazyDLL("user32.dll")
	proc := user32.NewProc("SendMessageTimeoutW")
	var result uintptr
	env, _ := syscall.UTF16PtrFromString("Environment")
	const (
		wmSettingChange = 0x001A
		smtoAbortIfHung = 0x0002
	)
	_, _, _ = proc.Call(
		uintptr(0xffff),
		uintptr(wmSettingChange),
		0,
		uintptr(unsafe.Pointer(env)),
		uintptr(smtoAbortIfHung),
		uintptr(1500),
		uintptr(unsafe.Pointer(&result)),
	)
}

func browserExeCandidates() []string {
	var out []string
	roots := []string{
		os.Getenv("ProgramFiles"),
		os.Getenv("ProgramFiles(x86)"),
		os.Getenv("LocalAppData"),
	}
	rel := []string{
		`Google\Chrome\Application\chrome.exe`,
		`Microsoft\Edge\Application\msedge.exe`,
		`BraveSoftware\Brave-Browser\Application\brave.exe`,
		`Chromium\Application\chrome.exe`,
	}
	seen := map[string]bool{}
	for _, r := range roots {
		if r == "" {
			continue
		}
		for _, p := range rel {
			fp := filepath.Join(r, p)
			if seen[fp] {
				continue
			}
			seen[fp] = true
			if st, err := os.Stat(fp); err == nil && !st.IsDir() {
				out = append(out, fp)
			}
		}
	}
	return out
}

func firewallRuleExists(name string) bool {
	out, err := cmdHidden("netsh", "advfirewall", "firewall", "show", "rule", "name="+name).CombinedOutput()
	if err != nil {
		return false
	}
	s := strings.ToLower(string(out))
	if strings.Contains(s, "no rules") || (strings.Contains(s, "指定") && strings.Contains(s, "没有")) {
		return false
	}
	return strings.Contains(string(out), name)
}

func addFirewallRule(name string, args ...string) bool {
	quietRun("netsh", "advfirewall", "firewall", "delete", "rule", "name="+name)
	cmdArgs := append([]string{"advfirewall", "firewall", "add", "rule", "name=" + name}, args...)
	out, err := cmdHidden("netsh", cmdArgs...).CombinedOutput()
	if err != nil {
		log.Printf("[PROXY] firewall add %s failed (need admin): %v %s", name, err, strings.TrimSpace(string(out)))
		return false
	}
	ok := firewallRuleExists(name)
	if !ok {
		log.Printf("[PROXY] firewall %s not visible after add (need admin)", name)
	}
	return ok
}

func quicRegLocked() bool {
	for _, path := range []string{
		`HKLM\SOFTWARE\Policies\Google\Chrome`,
		`HKCU\Software\Policies\Google\Chrome`,
	} {
		out, err := cmdHidden("reg", "query", path, "/v", "QuicAllowed").CombinedOutput()
		if err == nil && strings.Contains(string(out), "0x0") {
			return true
		}
	}
	return false
}

func deleteQUICFirewallRules() {
	for _, n := range []string{"AERO-NoQUIC-all", "AERO-NoQUIC-chrome", "AERO-NoQUIC-edge", "AERO-NoQUIC-msedge", "AERO-NoQUIC-brave", "AERO-NoQUIC-chromium"} {
		quietRun("netsh", "advfirewall", "firewall", "delete", "rule", "name="+n)
	}
	for _, exe := range browserExeCandidates() {
		base := strings.TrimSuffix(filepath.Base(exe), filepath.Ext(exe))
		quietRun("netsh", "advfirewall", "firewall", "delete", "rule", "name=AERO-NoQUIC-"+base)
	}
}

func addBrowserQUICRules() (ok int, total int) {
	exes := browserExeCandidates()
	total = len(exes)
	for _, exe := range exes {
		base := strings.TrimSuffix(filepath.Base(exe), filepath.Ext(exe))
		name := "AERO-NoQUIC-" + base
		if addFirewallRule(name, "dir=out", "action=block", "protocol=UDP", "remoteport=443", "program="+exe, "enable=yes") {
			ok++
		}
	}
	return ok, total
}

// ApplyBrowserLock stops Chrome/Edge from using Google's Alt-Svc HTTP/3
// (UDP/443) which bypasses WinINET. Games are not blocked (per-browser rules).
// blockUDP443 must be true only in sysproxy. TUN must NOT block UDP/443.
func ApplyBrowserLock(blockUDP443 bool) string {
	return ApplyBrowserLockOn(blockUDP443, "127.0.0.1:55555")
}

func ApplyBrowserLockOn(blockUDP443 bool, mixed string) string {
	_ = blockUDP443
	_ = mixed
	deleteQUICFirewallRules()
	return ""
}

// WipeAEROFirewall drops leftover AERO packet filters so box/Clash are untouched.
func WipeAEROFirewall() {
	deleteQUICFirewallRules()
	quietRun("netsh", "advfirewall", "firewall", "delete", "rule", "name=AERO-NoIPv6")
}

// ApplySocksPrivacy: no WinINET, no UDP/443 block (games). Chrome/Edge ICE
// that would skip 55555 is disabled so fingerprint/WebRTC do not leak home IP.
func ApplySocksPrivacy() {
	setChromiumBrowserPolicies(false, true, "127.0.0.1:55555")
	deleteQUICFirewallRules()
	log.Printf("[PROXY] socks privacy: WebRTC proxy-only, no QUIC firewall")
}

// setBrowserQUICBlock best-effort. Must NOT delete AERO-NoIPv6 (TUN owns that).
func setBrowserQUICBlock(enable bool) {
	deleteQUICFirewallRules()
	if !enable {
		setChromiumBrowserPolicies(false, false, "127.0.0.1:55555")
		return
	}
	_ = ApplyBrowserLock(true)
}
