//go:build windows

package tun

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

const errorNoMoreItems = syscall.Errno(259)

type windowsDevice struct {
	name      string
	mtu       int
	adapter   *wintun.Adapter
	session   wintun.Session
	sessionOK atomic.Bool
	closed    atomic.Bool
	writeMu   sync.Mutex
}

func NewDevice(name string, mtu int) (Device, error) {
	var adapter *wintun.Adapter
	var session wintun.Session
	var err error

	// 1. 优先尝试 OpenAdapter 复用现有已加载的网卡（免去 Windows PnP 设备增删耗时与重叠冲突）
	adapter, err = wintun.OpenAdapter(name)
	if err == nil {
		session, err = adapter.StartSession(0x800000)
		if err == nil {
			d := &windowsDevice{name: name, mtu: mtu, adapter: adapter, session: session}
			d.sessionOK.Store(true)
			log.Printf("[TUN] Reusing existing Windows adapter: %s (MTU=%d)", name, mtu)
			return d, nil
		}
		// 若旧网卡 session 启动失败，关闭旧句柄并走重建逻辑
		log.Printf("[TUN] StartSession on existing adapter failed: %v, will recreate", err)
		_ = adapter.Close()
		adapter = nil
	}

	// 2. 动态创建全新网卡：传入 nil GUID 让 Windows 动态分配全新唯一标识，杜绝硬编码固定 GUID 导致的 15s PnP 查询超时与 0x1F / 0xC00002F0 错误
	adapter, err = wintun.CreateAdapter(name, "AERO", nil)
	if err != nil {
		log.Printf("[TUN] wintun create adapter failed: %v, attempting single retry after brief pause", err)
		time.Sleep(300 * time.Millisecond)
		adapter, err = wintun.CreateAdapter(name, "AERO", nil)
		if err != nil {
			return nil, fmt.Errorf("wintun create adapter: %w", err)
		}
	}

	session, err = adapter.StartSession(0x800000)
	if err != nil {
		_ = adapter.Close()
		return nil, fmt.Errorf("wintun start session: %w", err)
	}

	d := &windowsDevice{name: name, mtu: mtu, adapter: adapter, session: session}
	d.sessionOK.Store(true)
	log.Printf("[TUN] Windows adapter created: %s (MTU=%d)", name, mtu)
	return d, nil
}

func (d *windowsDevice) Read(p []byte) (int, error) {
	if d.closed.Load() || !d.sessionOK.Load() {
		return 0, fmt.Errorf("device closed")
	}
	for {
		if d.closed.Load() {
			return 0, fmt.Errorf("device closed")
		}
		packet, err := d.session.ReceivePacket()
		if err != nil {
			if err == errorNoMoreItems || strings.Contains(err.Error(), "No more data") {
				ev := d.session.ReadWaitEvent()
				// Block in kernel event wait until driver signals packet arrival or 1s heartbeat
				res, _ := windows.WaitForSingleObject(ev, 1000)
				if res == uint32(windows.WAIT_TIMEOUT) {
					continue
				}
				continue
			}
			return 0, err
		}
		n := copy(p, packet)
		d.session.ReleaseReceivePacket(packet)
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
	// MUST allocate from the wintun send ring. Sending a Go heap slice
	// corrupts the driver ring and exits with 0xC0000374.
	buf, err := d.session.AllocateSendPacket(len(p))
	if err != nil {
		return 0, err
	}
	copy(buf, p)
	d.session.SendPacket(buf)
	return len(p), nil
}

func (d *windowsDevice) Close() error {
	if !d.closed.CompareAndSwap(false, true) {
		return nil
	}
	if d.sessionOK.CompareAndSwap(true, false) {
		d.session.End()
	}
	if d.adapter != nil {
		d.adapter.Close()
		d.adapter = nil
	}
	log.Printf("[TUN] Windows adapter closed: %s", d.name)
	return nil
}

func (d *windowsDevice) Name() string { return d.name }
func (d *windowsDevice) MTU() int     { return d.mtu }
