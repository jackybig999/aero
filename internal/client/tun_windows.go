//go:build windows

// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
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

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func ensureWintunDLL() error {
	exe, err := os.Executable()
	if err == nil {
		exeDir := filepath.Dir(exe)
		target := filepath.Join(exeDir, "wintun.dll")
		if _, err := os.Stat(target); err == nil {
			return checkWintunLoadable()
		}
	}

	sys32 := filepath.Join(os.Getenv("SystemRoot"), "System32", "wintun.dll")
	if _, err := os.Stat(sys32); err == nil {
		return checkWintunLoadable()
	}

	// wintun 只从程序所在目录与 System32 加载（LOAD_LIBRARY_SEARCH_APPLICATION_DIR|SYSTEM32），不查工作目录：
	// 此前这里也接受工作目录中的 DLL，检查通过后加载才失败，错误难以理解。
	return fmt.Errorf("wintun.dll not found next to the program or in System32")
}

// checkWintunLoadable 确认 wintun.dll 不只是存在，而且能被加载（位数不符、文件损坏都会失败）。
// wintun 库在 DLL 无法加载时会 panic 而不是返回错误，所以必须在调用它之前检查。
// 搜索范围与 wintun 库一致：程序所在目录与系统目录。
func checkWintunLoadable() error {
	const searchFlags = 0x00000200 | 0x00000800 // LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32
	h, err := windows.LoadLibraryEx("wintun.dll", 0, searchFlags)
	if err != nil {
		return fmt.Errorf("wintun.dll exists but cannot be loaded (wrong architecture or corrupted? use the official amd64 build): %w", err)
	}
	_ = windows.FreeLibrary(h)
	return nil
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
	// dropped 记录因 wintun 环形缓冲区满而丢弃的下行包数。
	dropped atomic.Uint64
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
		// 环形缓冲区满：丢弃该包，与 wireguard-go 的 Windows tun 一致；
		// 若返回错误，数据泵会把它当作写失败而拆掉整条隧道，下行突发即可断线。
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			d.dropped.Add(1)
			return len(p), nil
		}
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
					Index:       curr.IfIndex,
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

// readIPv4Routes 经 IP Helper API 读取 IPv4 活动路由（不解析随系统语言变化的 route print 文本，不启动进程）。
// 有效跃点 = 路由跃点 + 接口跃点（与 Windows 选路一致）。
func readIPv4Routes() ([]ipv4Route, error) {
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return nil, err
	}
	ifMetric := map[uint32]uint32{}
	out := make([]ipv4Route, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		m, ok := ifMetric[r.InterfaceIndex]
		if !ok {
			if row, err := r.InterfaceLUID.IPInterface(windows.AF_INET); err == nil {
				m = row.Metric
			}
			ifMetric[r.InterfaceIndex] = m
		}
		out = append(out, ipv4Route{Dest: r.DestinationPrefix.Prefix(), NextHop: r.NextHop.Addr(), IfIndex: r.InterfaceIndex, Metric: r.Metric + m})
	}
	return out, nil
}

// DetectThirdPartyTUN 检测宿主机是否存在其他正在运行 TUN 模式的 VPN
func DetectThirdPartyTUN() (bool, string, error) {
	summaries, err := getWindowsAdaptersSummary()
	if err != nil {
		return false, "", fmt.Errorf("query adapters: %w", err)
	}

	routes, err := readIPv4Routes()
	if err != nil {
		return false, "", fmt.Errorf("read routes: %w", err)
	}
	conflict, name := evaluateThirdPartyTUN(summaries, routes)
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
	routes, e := readIPv4Routes()
	if e != nil {
		return "", "", e
	}
	bestGW, bestIdx, err := physicalDefaultGateway(summaries, routes)
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

// 套接字选项常量。IPV6_UNICAST_IF 与 IP_UNICAST_IF 数值同为 31（ws2ipdef.h），
// golang.org/x/sys/windows 未导出，这里定义本地常量。
const (
	sockoptIPUnicastIf   = 31 // IP_UNICAST_IF
	sockoptIPv6UnicastIf = 31 // IPV6_UNICAST_IF
)

// unicastIfSockopt 按套接字网络类型（Control 回调收到的 "tcp4"/"udp6" 等）返回绑定出接口的选项参数。
// IPv4 的 IP_UNICAST_IF 要求网络字节序（大端）索引；IPv6 的 IPV6_UNICAST_IF 要求主机字节序索引，
// Windows 只运行在小端架构上，故用小端编码。
func unicastIfSockopt(network string, ifIndex uint32) (level, opt int, val [4]byte) {
	if strings.HasSuffix(network, "6") {
		binary.LittleEndian.PutUint32(val[:], ifIndex)
		return syscall.IPPROTO_IPV6, sockoptIPv6UnicastIf, val
	}
	binary.BigEndian.PutUint32(val[:], ifIndex)
	return syscall.IPPROTO_IP, sockoptIPUnicastIf, val
}

// bindPhysicalControl 返回把套接字绑定到物理网卡并设置收发缓冲区的 Control 回调；
// 拨号与监听共用，仅缓冲区大小不同。
func bindPhysicalControl(ifIndex uint32, bufSize int) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var opErr error
		if err := c.Control(func(fd uintptr) {
			level, opt, val := unicastIfSockopt(network, ifIndex)
			opErr = syscall.Setsockopt(syscall.Handle(fd), int32(level), int32(opt), (*byte)(unsafe.Pointer(&val[0])), 4)
			if opErr == nil {
				_ = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, bufSize)
				_ = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, bufSize)
			}
		}); err != nil {
			return err
		}
		return opErr
	}
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
				dialer.Control = bindPhysicalControl(uint32(idx), 2*1024*1024)
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
	lc.Control = bindPhysicalControl(uint32(idx), 4*1024*1024)
	return lc.ListenPacket(ctx, network, ":0")
}
