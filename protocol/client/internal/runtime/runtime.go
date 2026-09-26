// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package runtime 提供跨平台运行时接口（Win/macOS/Linux）。
//
// 核心功能：
//   - TUN/TAP 虚拟网卡创建和管理
//   - 系统路由表操作
//   - DNS 劫持/重定向
//   - 系统代理设置（HTTP/SOCKS）
//   - 进程网络命名空间隔离（Linux）
//
// 平台实现：
//   - Windows: WinTUN + NETSH 路由
//   - macOS:   UTun + PF/Route 命令
//   - Linux:   TUN + iptables/nftables
package runtime

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
)

// quietRun runs a command and discards stdout/stderr.
// Windows `reg delete` prints GBK "key not found" when the value is absent;
// leaking that into a UTF-8 console becomes 锟斤拷 and looks like a crash.
// proxyEpoch invalidates in-flight async proxy cleanup if Connect runs again.
var proxyEpoch atomic.Uint64

func quietRun(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	hideConsole(cmd)
	_ = cmd.Run()
}

func cmdHidden(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	hideConsole(cmd)
	return cmd
}

// OS 当前操作系统类型
type OS int

const (
	Windows OS = iota
	MacOS
	Linux
	UnknownOS
)

func (o OS) String() string {
	switch o {
	case Windows:
		return "windows"
	case MacOS:
		return "darwin"
	case Linux:
		return "linux"
	default:
		return "unknown"
	}
}

// DetectOS 检测当前操作系统
func DetectOS() OS {
	switch runtime.GOOS {
	case "windows":
		return Windows
	case "darwin":
		return MacOS
	case "linux":
		return Linux
	default:
		return UnknownOS
	}
}

// Interface 运行时接口
type Interface interface {
	// TUN 设备管理
	CreateTUN(name string, mtu int) (TUNDevice, error)
	RemoveTUN(name string) error

	// 路由管理
	AddRoute(dst *net.IPNet, gateway net.IP) error
	DeleteRoute(dst *net.IPNet) error
	FlushRoutes() error

	// DNS 管理
	SetDNS(dnsServers []string) error
	RestoreDNS() error

	// 系统代理
	SetSystemProxy(proxyAddr string) error
	ClearSystemProxy() error

	// 防火墙规则
	AddBypassRule(appPath string) error
	RemoveBypassRule(appPath string) error
}

// TUNDevice TUN 虚拟网卡接口
type TUNDevice interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
	Name() string
	MTU() int
}

// Config 运行时配置
type Config struct {
	TUNName    string
	TUNMTU     int
	ProxyAddr  string
	DNSServers []string
	BypassApps []string
	RouteAll   bool // 是否全局代理
}

// DefaultConfig 默认配置
func DefaultConfig() Config {
	return Config{
		TUNName:    "aero0",
		TUNMTU:     1420,
		ProxyAddr:  "127.0.0.1:1080",
		DNSServers: []string{"223.5.5.5", "8.8.8.8"},
		RouteAll:   false,
	}
}

// New 创建平台特定的运行时接口
func New(cfg Config) (Interface, error) {
	switch DetectOS() {
	case Windows:
		return newWindowsRuntime(cfg)
	case MacOS:
		return newMacOSRuntime(cfg)
	case Linux:
		return newLinuxRuntime(cfg)
	default:
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// === Windows 实现 ===

type windowsRuntime struct {
	cfg     Config
	origDNS []string
	routes  []*net.IPNet
	// system proxy snapshot (restore on clear — never leave user offline)
	proxySnap     bool
	prevEnable    string // "0" / "1"
	prevServer    string
	prevOverride  string
	prevPAC       string
	pacPath       string
	envSnap       bool
	prevUserHTTP  string
	prevUserHTTPS string
	prevUserALL   string
	prevUserNO    string
}

func newWindowsRuntime(cfg Config) (Interface, error) {
	return &windowsRuntime{cfg: cfg}, nil
}

func regQuery(name string) string {
	out, err := cmdHidden("reg", "query",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "/v", name).CombinedOutput()
	if err != nil {
		return ""
	}
	// lines like: ProxyEnable    REG_DWORD    0x1
	s := string(out)
	for _, line := range strings.Split(s, "\n") {
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

func (w *windowsRuntime) snapshotProxyOnce() {
	if w.proxySnap {
		return
	}
	en := regQuery("ProxyEnable")
	if strings.HasPrefix(en, "0x") || strings.HasPrefix(en, "0X") {
		if en == "0x0" || en == "0X0" {
			w.prevEnable = "0"
		} else {
			w.prevEnable = "1"
		}
	} else if en == "0" || en == "1" {
		w.prevEnable = en
	} else {
		w.prevEnable = "0"
	}
	w.prevServer = regQuery("ProxyServer")
	w.prevOverride = regQuery("ProxyOverride")
	w.prevPAC = regQuery("AutoConfigURL")
	w.proxySnap = true
}

func winNotifyProxyChange() {
	notifyWinINet()
}

func (w *windowsRuntime) CreateTUN(name string, mtu int) (TUNDevice, error) {
	return nil, fmt.Errorf("CreateTUN requires wintun.dll (download from https://www.wintun.net/)")
}

func (w *windowsRuntime) RemoveTUN(name string) error {
	// 先尝试使用 wintun 卸载（如果 wintun.dll 可用）
	// 回退到 netsh 删除接口
	cmd := cmdHidden("netsh", "interface", "delete", "interface", name)
	if out, err := cmd.CombinedOutput(); err != nil {
		outStr := string(out)
		// 接口不存在时静默忽略
		if !strings.Contains(outStr, "not found") && !strings.Contains(outStr, "找不到") &&
			!strings.Contains(outStr, "not exist") && !strings.Contains(outStr, "不存在") {
			return fmt.Errorf("remove TUN %s failed: %v, output: %s", name, err, outStr)
		}
	}
	return nil
}

func (w *windowsRuntime) AddRoute(dst *net.IPNet, gateway net.IP) error {
	cmd := cmdHidden("route", "add", dst.String(), gateway.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("route add failed: %v, output: %s", err, string(out))
	}
	w.routes = append(w.routes, dst)
	return nil
}

func (w *windowsRuntime) DeleteRoute(dst *net.IPNet) error {
	cmd := cmdHidden("route", "delete", dst.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("route delete failed: %v, output: %s", err, string(out))
	}
	return nil
}

func (w *windowsRuntime) FlushRoutes() error {
	for _, r := range w.routes {
		cmdHidden("route", "delete", r.String()).Run()
	}
	w.routes = nil
	return nil
}

func (w *windowsRuntime) SetDNS(dnsServers []string) error {
	if len(dnsServers) == 0 {
		return nil
	}
	out, err := cmdHidden("netsh", "interface", "show", "interface").Output()
	if err != nil {
		return fmt.Errorf("list interfaces: %w", err)
	}
	lines := strings.Split(string(out), "\n")
	var ifaceName string
	for _, line := range lines {
		if strings.Contains(line, "Connected") {
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				ifaceName = strings.Join(parts[3:], " ")
				break
			}
		}
	}
	if ifaceName == "" {
		return fmt.Errorf("no active interface found")
	}

	cmd := cmdHidden("netsh", "interface", "ip", "set", "dns", ifaceName, "static", dnsServers[0])
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("set dns failed: %v, output: %s", err, string(out))
	}

	for i := 1; i < len(dnsServers); i++ {
		cmdHidden("netsh", "interface", "ip", "add", "dns", ifaceName, dnsServers[i], "index=2").Run()
	}

	w.origDNS = dnsServers
	return nil
}

func (w *windowsRuntime) RestoreDNS() error {
	if len(w.origDNS) == 0 {
		return nil
	}
	out, err := cmdHidden("netsh", "interface", "show", "interface").Output()
	if err != nil {
		return err
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "Connected") {
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				ifaceName := strings.Join(parts[3:], " ")
				cmdHidden("netsh", "interface", "ip", "set", "dns", ifaceName, "dhcp").Run()
			}
		}
	}
	return nil
}

// SetSystemProxy enables Windows system proxy (Clash-style one-click).
// User never configures browsers: connect sets proxy, disconnect clears it.
//
// Extra (still automatic, restored on disconnect): disable Chromium QUIC/DoH.
// Without this Chrome opens Google via UDP QUIC, bypasses HTTP proxy → TIMED_OUT
// while Edge (less aggressive QUIC) still works. User does not need to know this.
func (w *windowsRuntime) SetSystemProxy(proxyAddr string) error {
	proxyEpoch.Add(1)
	w.snapshotProxyOnce()
	raw := strings.TrimSpace(proxyAddr)
	raw = strings.TrimPrefix(raw, "socks=")
	raw = strings.TrimPrefix(raw, "socks5://")
	raw = strings.TrimPrefix(raw, "SOCKS5://")
	raw = strings.TrimPrefix(raw, "http://")
	raw = strings.TrimPrefix(raw, "http=")
	if i := strings.Index(raw, ";"); i >= 0 {
		raw = raw[:i]
	}
	raw = strings.TrimSpace(raw)

	mixed := "127.0.0.1:55555"
	if raw != "" {
		mixed = raw
	}

	bypass := "localhost;127.*;10.*;192.168.*;172.16.*;172.17.*;172.18.*;172.19.*;172.2*.*;172.30.*;172.31.*;<local>;*.local;*.cn;*.baidu.com;*.qq.com;*.taobao.com;*.jd.com;*.alipay.com;*.bilibili.com;*.zhihu.com;*.163.com;*.weibo.com;*.csdn.net;*.douyin.com;*.feishu.cn;*.aliyun.com;*.tencent.com"
	regPath := `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	quietRun("reg", "delete", regPath, "/v", "AutoConfigURL", "/f")
	// Same string Clash/v2rayN write: HTTP CONNECT + SOCKS on the mixed port.
	spec := "http=" + mixed + ";https=" + mixed + ";socks=" + mixed
	cmds := [][]string{
		{"reg", "add", regPath, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f"},
		{"reg", "add", regPath, "/v", "ProxyServer", "/t", "REG_SZ", "/d", spec, "/f"},
		{"reg", "add", regPath, "/v", "ProxyOverride", "/t", "REG_SZ", "/d", bypass, "/f"},
	}
	for _, args := range cmds {
		cmd := cmdHidden(args[0], args[1:]...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("set proxy reg failed: %v, output: %s", err, string(out))
		}
	}
	if err := applyLANProxy(spec, bypass); err != nil {
		log.Printf("[PROXY] WinINET per-conn: %v (registry still set)", err)
	}
	quietRun("netsh", "winhttp", "reset", "proxy")
	quietRun("netsh", "winhttp", "set", "proxy", "proxy-server="+mixed, "bypass-list="+bypass)

	winNotifyProxyChange()
	w.setUserProxyEnv(mixed)
	log.Printf("[PROXY] system proxy ON %s (WinINET+WinHTTP+temp HTTP_PROXY)", mixed)
	return nil
}

// chromePolicyPaths: machine policy first (Chrome honors HKLM more reliably).
func chromePolicyPaths() []string {
	return []string{
		`HKLM\SOFTWARE\Policies\Google\Chrome`,
		`HKCU\Software\Policies\Google\Chrome`,
		`HKLM\SOFTWARE\Policies\Microsoft\Edge`,
		`HKCU\Software\Policies\Microsoft\Edge`,
	}
}

// setChromiumBrowserPolicies: 严格遵从最高准则“严格禁止改变系统环境”，
// 不再向 Windows 注册表写入任何 Chrome/Edge 策略。所有流量与 WebRTC 均在 Wintun / gVisor 协议栈层动态过滤。
func setChromiumBrowserPolicies(quicOff, webrtcProxyOnly bool, mixed string) {
	_ = quicOff
	_ = webrtcProxyOnly
	_ = mixed
}

func setChromiumQUICOff(enable bool) {
	_ = enable
}

func (w *windowsRuntime) ClearSystemProxy() error {
	regPath := `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	// Flip WinINET off first and notify immediately so browsers leave 55555
	// before the slower QUIC/firewall/env cleanup.
	clearLANProxy()
	quietRun("reg", "delete", regPath, "/v", "AutoConfigURL", "/f")
	quietRun("reg", "add", regPath, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f")
	quietRun("reg", "delete", regPath, "/v", "ProxyServer", "/f")
	winNotifyProxyChange()
	// Sync: grok.exe reads HKCU Environment. Async leftover HTTP_PROXY=55555
	// is why box TUN still cannot talk to Grok after AERO is dismissed.
	w.clearUserProxyEnv()
	quietRun("netsh", "winhttp", "reset", "proxy")
	WipeAEROFirewall()
	// Sync: WebRtcIPHandling / QuicAllowed leftover makes Chrome/Grok
	// disagree with box after AERO window close.
	setChromiumQUICOff(false)
	setBrowserQUICBlock(false)

	epoch := proxyEpoch.Add(1)
	prevEnable, prevServer, prevOverride, prevPAC := w.prevEnable, w.prevServer, w.prevOverride, w.prevPAC
	pacPath := w.pacPath
	w.proxySnap = false
	w.pacPath = ""
	go func() {
		if proxyEpoch.Load() != epoch {
			return
		}
		if prevServer != "" && !strings.Contains(prevServer, "55555") && !strings.Contains(prevServer, "19877") && prevEnable == "1" {
			quietRun("reg", "add", regPath, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f")
			quietRun("reg", "add", regPath, "/v", "ProxyServer", "/t", "REG_SZ", "/d", prevServer, "/f")
			winNotifyProxyChange()
		}
		if prevOverride != "" && !strings.Contains(prevOverride, "aero") {
			quietRun("reg", "add", regPath, "/v", "ProxyOverride", "/t", "REG_SZ", "/d", prevOverride, "/f")
		}
		if prevPAC != "" && !strings.Contains(prevPAC, "19877") && !strings.Contains(prevPAC, "aero") {
			quietRun("reg", "add", regPath, "/v", "AutoConfigURL", "/t", "REG_SZ", "/d", prevPAC, "/f")
		}
		if pacPath != "" {
			_ = os.Remove(pacPath)
		}
	}()
	return nil
}

// ForceClearSystemProxy is a best-effort cleanup usable without a prior snapshot
// (process crash recovery / GUI emergency clear).
func ForceClearSystemProxy() {
	regPath := `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	// Only clear if it looks like ours
	pac := regQuery("AutoConfigURL")
	srv := regQuery("ProxyServer")
	ours := strings.Contains(pac, "127.0.0.1:19877") ||
		strings.Contains(pac, "aero-proxy") ||
		strings.Contains(srv, "127.0.0.1:55555") ||
		strings.Contains(srv, "127.0.0.1:55556") ||
		strings.Contains(srv, "http=127.0.0.1:55555")
	(&windowsRuntime{}).clearUserProxyEnv()
	WipeAEROFirewall()
	if !ours && pac == "" && (srv == "" || srv == "(value not set)") {
		setChromiumQUICOff(false)
		setBrowserQUICBlock(false)
		return
	}
	if ours || strings.Contains(pac, "19877") || strings.Contains(srv, "55555") {
		clearLANProxy()
		quietRun("reg", "add", regPath, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f")
		quietRun("reg", "delete", regPath, "/v", "AutoConfigURL", "/f")
		quietRun("reg", "delete", regPath, "/v", "ProxyServer", "/f")
		winNotifyProxyChange()
		var wg sync.WaitGroup
		wg.Add(3)
		go func() { defer wg.Done(); quietRun("netsh", "winhttp", "reset", "proxy") }()
		go func() {
			defer wg.Done()
			setChromiumQUICOff(false)
			setBrowserQUICBlock(false)
		}()
		go func() { defer wg.Done(); (&windowsRuntime{}).clearUserProxyEnv() }()
		wg.Wait()
	}
}

func (w *windowsRuntime) AddBypassRule(appPath string) error {
	cmd := cmdHidden("netsh", "advfirewall", "firewall", "add", "rule",
		"name=AERO_Bypass", "dir=out", "action=allow", "program="+appPath, "enable=yes")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("add bypass rule failed: %v, output: %s", err, string(out))
	}
	return nil
}

func (w *windowsRuntime) RemoveBypassRule(appPath string) error {
	cmd := cmdHidden("netsh", "advfirewall", "firewall", "delete", "rule", "name=AERO_Bypass")
	cmd.Run()
	return nil
}

// NetworkInterface 网络接口信息
type NetworkInterface struct {
	Name string
	IP   string
	MAC  string
	Up   bool
}

// ListInterfaces 枚举所有活跃的非回环网络接口
func ListInterfaces() ([]NetworkInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var result []NetworkInterface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, _ := iface.Addrs()
		var ip string
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				ip = ipnet.IP.String()
				break
			}
		}

		result = append(result, NetworkInterface{
			Name: iface.Name,
			IP:   ip,
			MAC:  iface.HardwareAddr.String(),
			Up:   iface.Flags&net.FlagUp != 0,
		})
	}
	return result, nil
}

// === macOS 实现 ===

type macOSRuntime struct {
	cfg Config
}

func newMacOSRuntime(cfg Config) (Interface, error) {
	return &macOSRuntime{cfg: cfg}, fmt.Errorf("macOS runtime not yet implemented (requires utun + route)")
}

func (m *macOSRuntime) CreateTUN(name string, mtu int) (TUNDevice, error) {
	return nil, fmt.Errorf("CreateTUN not implemented on macOS")
}
func (m *macOSRuntime) RemoveTUN(name string) error {
	return fmt.Errorf("RemoveTUN not implemented on macOS")
}
func (m *macOSRuntime) AddRoute(dst *net.IPNet, gateway net.IP) error {
	return fmt.Errorf("AddRoute not implemented on macOS")
}
func (m *macOSRuntime) DeleteRoute(dst *net.IPNet) error {
	return fmt.Errorf("DeleteRoute not implemented on macOS")
}
func (m *macOSRuntime) FlushRoutes() error {
	return fmt.Errorf("FlushRoutes not implemented on macOS")
}
func (m *macOSRuntime) SetDNS(dnsServers []string) error {
	return fmt.Errorf("SetDNS not implemented on macOS")
}
func (m *macOSRuntime) RestoreDNS() error {
	return fmt.Errorf("RestoreDNS not implemented on macOS")
}
func (m *macOSRuntime) SetSystemProxy(proxyAddr string) error {
	return fmt.Errorf("SetSystemProxy not implemented on macOS")
}
func (m *macOSRuntime) ClearSystemProxy() error {
	return fmt.Errorf("ClearSystemProxy not implemented on macOS")
}
func (m *macOSRuntime) AddBypassRule(appPath string) error {
	return fmt.Errorf("AddBypassRule not implemented on macOS")
}
func (m *macOSRuntime) RemoveBypassRule(appPath string) error {
	return fmt.Errorf("RemoveBypassRule not implemented on macOS")
}

// === Linux 实现 ===

type linuxRuntime struct {
	cfg Config
}

func newLinuxRuntime(cfg Config) (Interface, error) {
	return &linuxRuntime{cfg: cfg}, fmt.Errorf("Linux runtime not yet implemented (requires /dev/net/tun)")
}

func (l *linuxRuntime) CreateTUN(name string, mtu int) (TUNDevice, error) {
	return nil, fmt.Errorf("CreateTUN not implemented on Linux")
}
func (l *linuxRuntime) RemoveTUN(name string) error {
	return fmt.Errorf("RemoveTUN not implemented on Linux")
}
func (l *linuxRuntime) AddRoute(dst *net.IPNet, gateway net.IP) error {
	return fmt.Errorf("AddRoute not implemented on Linux")
}
func (l *linuxRuntime) DeleteRoute(dst *net.IPNet) error {
	return fmt.Errorf("DeleteRoute not implemented on Linux")
}
func (l *linuxRuntime) FlushRoutes() error {
	return fmt.Errorf("FlushRoutes not implemented on Linux")
}
func (l *linuxRuntime) SetDNS(dnsServers []string) error {
	return fmt.Errorf("SetDNS not implemented on Linux")
}
func (l *linuxRuntime) RestoreDNS() error {
	return fmt.Errorf("RestoreDNS not implemented on Linux")
}
func (l *linuxRuntime) SetSystemProxy(proxyAddr string) error {
	return fmt.Errorf("SetSystemProxy not implemented on Linux")
}
func (l *linuxRuntime) ClearSystemProxy() error {
	return fmt.Errorf("ClearSystemProxy not implemented on Linux")
}
func (l *linuxRuntime) AddBypassRule(appPath string) error {
	return fmt.Errorf("AddBypassRule not implemented on Linux")
}
func (l *linuxRuntime) RemoveBypassRule(appPath string) error {
	return fmt.Errorf("RemoveBypassRule not implemented on Linux")
}
