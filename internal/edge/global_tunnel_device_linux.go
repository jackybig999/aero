//go:build linux

package edge

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

const edgeTunDevice = "/dev/net/tun"

type linuxGlobalTunnelDevice struct {
	name string
	file *os.File
}

// newEdgeTunIfreq 构造 TUNSETIFF 请求。必须使用 unix.Ifreq：其大小与内核
// struct ifreq（40 字节）一致；内核会按该大小回写，自定义的短结构体会被越界写。
func newEdgeTunIfreq(name string) (*unix.Ifreq, error) {
	if name == "" {
		return nil, errors.New("global TUN device name is empty")
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return nil, fmt.Errorf("global TUN device name %q: %w", name, err)
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	return ifr, nil
}

// openGlobalTunnelDevice 打开共享 TUN。不能用 os.OpenFile：它在 TUNSETIFF 之前就把 fd 注册进
// netpoll（此时设备未绑定，poll 返回错误），随后 file.Fd() 又把 fd 切回阻塞模式，Read 立即返回
// "not pollable"，下行读取协程一启动就退出（v1.3.0 线上故障）。正确顺序：原始 open → TUNSETIFF →
// 非阻塞 → os.NewFile，由 netpoll 管理读写，Close 可唤醒阻塞中的 Read。
func openGlobalTunnelDevice(name string) (GlobalTunnelDevice, error) {
	ifr, err := newEdgeTunIfreq(name)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open(edgeTunDevice, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", edgeTunDevice, err)
	}
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		return nil, errors.Join(fmt.Errorf("TUNSETIFF: %w", err), unix.Close(fd))
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, errors.Join(fmt.Errorf("set %s non-blocking: %w", edgeTunDevice, err), unix.Close(fd))
	}
	return &linuxGlobalTunnelDevice{name: ifr.Name(), file: os.NewFile(uintptr(fd), edgeTunDevice)}, nil
}

func (d *linuxGlobalTunnelDevice) Read(packet []byte) (int, error)  { return d.file.Read(packet) }
func (d *linuxGlobalTunnelDevice) Write(packet []byte) (int, error) { return d.file.Write(packet) }
func (d *linuxGlobalTunnelDevice) Close() error                     { return d.file.Close() }
