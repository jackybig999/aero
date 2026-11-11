//go:build windows

// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

func ensureWintunDLL() error {
	exe, err := os.Executable()
	if err == nil {
		exeDir := filepath.Dir(exe)
		target := filepath.Join(exeDir, "wintun.dll")
		if _, err := os.Stat(target); err == nil {
			return nil
		}
	}

	sys32 := filepath.Join(os.Getenv("SystemRoot"), "System32", "wintun.dll")
	if _, err := os.Stat(sys32); err == nil {
		return nil
	}

	if _, err := os.Stat("wintun.dll"); err == nil {
		return nil
	}
	return fmt.Errorf("wintun.dll not found in executable directory, System32, or current working directory")
}

const errorNoMoreItems = syscall.Errno(259)

type windowsDevice struct {
	name      string
	adapter   *wintun.Adapter
	session   wintun.Session
	sessionMu sync.RWMutex
	closed    atomic.Bool
	sessionOK atomic.Bool
	readWg    sync.WaitGroup
	writeMu   sync.Mutex
}

var (
	wintunLifecycleMu   sync.Mutex
	lastWintunCloseTime time.Time
)

func (d *windowsDevice) Read(p []byte) (int, error) {
	if d.closed.Load() || !d.sessionOK.Load() {
		return 0, fmt.Errorf("device closed")
	}

	d.readWg.Add(1)
	defer d.readWg.Done()

	d.sessionMu.RLock()
	if !d.sessionOK.Load() {
		d.sessionMu.RUnlock()
		return 0, fmt.Errorf("device closed")
	}
	sess := d.session
	d.sessionMu.RUnlock()

	for {
		if d.closed.Load() || !d.sessionOK.Load() {
			return 0, fmt.Errorf("device closed")
		}
		packet, err := sess.ReceivePacket()
		if err != nil {
			if err == errorNoMoreItems || strings.Contains(err.Error(), "No more data") {
				ev := sess.ReadWaitEvent()
				res, _ := windows.WaitForSingleObject(ev, 1000)
				if d.closed.Load() || !d.sessionOK.Load() {
					return 0, fmt.Errorf("device closed")
				}
				if res == uint32(windows.WAIT_TIMEOUT) {
					continue
				}
				continue
			}
			return 0, err
		}
		n := copy(p, packet)
		sess.ReleaseReceivePacket(packet)
		if n == 0 {
			continue
		}
		return n, nil
	}
}

func (d *windowsDevice) Write(p []byte) (int, error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	if d.closed.Load() || !d.sessionOK.Load() {
		return 0, fmt.Errorf("device closed")
	}
	if len(p) == 0 {
		return 0, nil
	}

	d.sessionMu.RLock()
	if !d.sessionOK.Load() {
		d.sessionMu.RUnlock()
		return 0, fmt.Errorf("device closed")
	}
	sess := d.session
	d.sessionMu.RUnlock()

	buf, err := sess.AllocateSendPacket(len(p))
	if err != nil {
		return 0, err
	}
	copy(buf, p)
	sess.SendPacket(buf)
	return len(p), nil
}

func (d *windowsDevice) Close() error {
	if !d.closed.CompareAndSwap(false, true) {
		return nil
	}
	hadSession := d.sessionOK.CompareAndSwap(true, false)

	// Step 1: 内核级显式唤醒，瞬间击破 WaitForSingleObject 阻塞
	if hadSession {
		d.sessionMu.RLock()
		sess := d.session
		d.sessionMu.RUnlock()
		if ev := sess.ReadWaitEvent(); ev != 0 {
			_ = windows.SetEvent(ev)
		}
	}

	// Step 2: 严格等待正在进行的读循环完全脱离 Wintun 环形缓冲区
	d.readWg.Wait()

	// Step 3: 持锁安全终结 session 并关闭 adapter
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	d.sessionMu.Lock()
	defer d.sessionMu.Unlock()

	wintunLifecycleMu.Lock()
	defer wintunLifecycleMu.Unlock()

	if hadSession {
		d.session.End()
	}
	if d.adapter != nil {
		_ = d.adapter.Close()
		d.adapter = nil
	}
	lastWintunCloseTime = time.Now()

	log.Printf("[TUN] Windows adapter safely closed: %s", d.name)
	return nil
}

func (d *windowsDevice) Name() string { return d.name }

// getWindowsAdaptersSummary 通过原生 IP Helper API 采集完整的网卡描述与 IfType
func getWindowsAdaptersSummary() ([]ifaceSummary, error) {
	var size uint32 = 15000
	for i := 0; i < 3; i++ {
		buf := make([]byte, size)
		p := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		flags := uint32(windows.GAA_FLAG_INCLUDE_ALL_INTERFACES | windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_DNS_SERVER)
		err := windows.GetAdaptersAddresses(windows.AF_INET, flags, 0, p, &size)
		if err == nil {
			var summaries []ifaceSummary
			for curr := p; curr != nil; curr = curr.Next {
				name := windows.UTF16PtrToString(curr.FriendlyName)
				desc := windows.UTF16PtrToString(curr.Description)
				isUp := (curr.OperStatus == windows.IfOperStatusUp)
				isLoopback := (curr.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK)

				var ips []net.IP
				for u := curr.FirstUnicastAddress; u != nil; u = u.Next {
					if ip := u.Address.IP(); ip != nil {
						ips = append(ips, ip)
					}
				}
				summaries = append(summaries, ifaceSummary{
					Name:        name,
					Description: desc,
					IfType:      curr.IfType,
					IsUp:        isUp,
					IsLoopback:  isLoopback,
					IPs:         ips,
				})
			}
			return summaries, nil
		}
		if err != windows.ERROR_BUFFER_OVERFLOW {
			return nil, err
		}
	}
	return nil, fmt.Errorf("GetAdaptersAddresses buffer overflow")
}

// DetectThirdPartyTUN 检测宿主机是否存在其他正在运行 TUN 模式的 VPN
func DetectThirdPartyTUN() (bool, string, error) {
	summaries, err := getWindowsAdaptersSummary()
	if err != nil {
		return false, "", fmt.Errorf("query adapters: %w", err)
	}

	prt := exec.Command("route", "print", "-4")
	prt.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	out, err := prt.CombinedOutput()
	if err != nil {
		return false, "", fmt.Errorf("route print failed: %w", err)
	}

	conflict, name := evaluateThirdPartyTUN(summaries, string(out))
	return conflict, name, nil
}

type cachedGateway struct {
	gw      string
	ifIndex string
	updated time.Time
}

var (
	gwCacheMu sync.RWMutex
	lastGW    cachedGateway
)

func invalidateGatewayCache() {
	gwCacheMu.Lock()
	lastGW = cachedGateway{}
	gwCacheMu.Unlock()
}

// PhysicalDefaultGateway 获取物理默认网关与网卡索引（彻底排除一切虚拟/VPN网卡，严防流量被引向他人隧道）
func PhysicalDefaultGateway() (gw, ifIndex string, err error) {
	gwCacheMu.RLock()
	if lastGW.gw != "" && time.Since(lastGW.updated) < 15*time.Second {
		cachedGW, cachedIdx := lastGW.gw, lastGW.ifIndex
		gwCacheMu.RUnlock()
		return cachedGW, cachedIdx, nil
	}
	gwCacheMu.RUnlock()

	summaries, _ := getWindowsAdaptersSummary()
	prt := exec.Command("route", "print", "-4")
	prt.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	out, e := prt.CombinedOutput()
	if e != nil {
		return "", "", e
	}
	bestGW, bestIdx, err := physicalDefaultGatewayWithInput(summaries, string(out), liveIfIndexForIPv4)
	if err != nil {
		return "", "", err
	}

	gwCacheMu.Lock()
	lastGW = cachedGateway{
		gw:      bestGW,
		ifIndex: bestIdx,
		updated: time.Now(),
	}
	gwCacheMu.Unlock()

	return bestGW, bestIdx, nil
}

func liveIfIndexForIPv4(ip net.IP) string {
	if ip == nil {
		return ""
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if strings.Contains(strings.ToLower(ifi.Name), "aero") {
			continue
		}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil {
				continue
			}
			if ipn.IP.To4().Equal(ip) {
				return strconv.Itoa(ifi.Index)
			}
		}
	}
	return ""
}

// DialPhysicalDirect 绑定物理网卡发包
func DialPhysicalDirect(ctx context.Context, network, addr string) (net.Conn, error) {
	if hook := getPhysicalDialerHook(); hook != nil {
		return hook(ctx, network, addr)
	}
	var dialer net.Dialer
	dialer.Timeout = 8 * time.Second
	if !isLoopbackHost(addr) {
		_, idxStr, err := PhysicalDefaultGateway()
		if err == nil && idxStr != "" {
			if idx, err := strconv.Atoi(idxStr); err == nil && idx > 0 {
				dialer.Control = func(netw, address string, c syscall.RawConn) error {
					var opErr error
					_ = c.Control(func(fd uintptr) {
						var buf [4]byte
						binary.BigEndian.PutUint32(buf[:], uint32(idx))
						opErr = syscall.Setsockopt(syscall.Handle(fd), syscall.IPPROTO_IP, 31, (*byte)(unsafe.Pointer(&buf[0])), 4)
						if opErr == nil {
							_ = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 2*1024*1024)
							_ = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 2*1024*1024)
						}
					})
					return opErr
				}
			}
		}
	}
	return dialer.DialContext(ctx, network, addr)
}

// ListenPhysicalPacket 绑定物理网卡监听
func ListenPhysicalPacket(ctx context.Context, network string) (net.PacketConn, error) {
	_, idxStr, err := PhysicalDefaultGateway()
	if err != nil {
		return nil, fmt.Errorf("physical default gateway: %w", err)
	}
	if idxStr == "" {
		return nil, fmt.Errorf("physical interface index not found")
	}
	idx, err := strconv.Atoi(idxStr)
	if err != nil || idx <= 0 {
		return nil, fmt.Errorf("invalid physical interface index %q", idxStr)
	}
	var lc net.ListenConfig
	lc.Control = func(netw, address string, c syscall.RawConn) error {
		var opErr error
		_ = c.Control(func(fd uintptr) {
			var buf [4]byte
			binary.BigEndian.PutUint32(buf[:], uint32(idx))
			opErr = syscall.Setsockopt(syscall.Handle(fd), syscall.IPPROTO_IP, 31, (*byte)(unsafe.Pointer(&buf[0])), 4)
			if opErr == nil {
				_ = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4*1024*1024)
				_ = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 4*1024*1024)
			}
		})
		return opErr
	}
	return lc.ListenPacket(ctx, network, ":0")
}
