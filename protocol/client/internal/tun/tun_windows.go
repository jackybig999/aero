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
	for attempt := 0; attempt < 3; attempt++ {
		adapter, err = wintun.OpenAdapter(name)
		if err == nil {
			session, err = adapter.StartSession(0x800000)
			if err == nil {
				d := &windowsDevice{name: name, mtu: mtu, adapter: adapter, session: session}
				d.sessionOK.Store(true)
				log.Printf("[TUN] Reusing existing Windows adapter: %s (MTU=%d)", name, mtu)
				return d, nil
			}
			log.Printf("[TUN] StartSession on existing adapter failed: %v (attempt %d)", err, attempt)
			_ = adapter.Close()
			adapter = nil
			time.Sleep(200 * time.Millisecond)
		}
	}

	// 2. 动态创建全新网卡：传入 nil GUID 让 Windows 动态分配全新唯一标识，杜绝硬编码固定 GUID 导致的 15s PnP 查询超时与 0x1F / 0xC00002F0 错误
	for attempt := 0; attempt < 5; attempt++ {
		adapter, err = wintun.CreateAdapter(name, "AERO", nil)
		if err == nil {
			break
		}
		log.Printf("[TUN] wintun create adapter failed: %v, retrying (%d/5)...", err, attempt+1)
		time.Sleep(500 * time.Millisecond)
		// 检查在重试期间旧网卡是否已注销完成或可直接 Open
		if a, oerr := wintun.OpenAdapter(name); oerr == nil {
			if s, serr := a.StartSession(0x800000); serr == nil {
				d := &windowsDevice{name: name, mtu: mtu, adapter: a, session: s}
				d.sessionOK.Store(true)
				log.Printf("[TUN] Successfully opened adapter during retry: %s", name)
				return d, nil
			}
			_ = a.Close()
		}
	}
	if err != nil {
		return nil, fmt.Errorf("wintun create adapter: %w", err)
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
			// 休眠唤醒 / 驱动重置自愈机制：若 session 异常中断，自动重建 session 保证隧道长效存活
			if !d.closed.Load() && d.adapter != nil {
				log.Printf("[TUN] wintun session interrupted (%v), attempting auto-recovery...", err)
				d.session.End()
				time.Sleep(300 * time.Millisecond)
				if newSess, nerr := d.adapter.StartSession(0x800000); nerr == nil {
					d.session = newSess
					log.Printf("[TUN] wintun session recovered successfully!")
					continue
				}
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
	buf, err := d.session.AllocateSendPacket(len(p))
	if err != nil {
		if !d.closed.Load() && d.adapter != nil {
			d.session.End()
			if newSess, nerr := d.adapter.StartSession(0x800000); nerr == nil {
				d.session = newSess
				buf, err = d.session.AllocateSendPacket(len(p))
			}
		}
		if err != nil {
			return 0, err
		}
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
