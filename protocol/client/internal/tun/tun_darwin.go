//go:build darwin

package tun

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// darwinDevice macOS utun 设备实现
type darwinDevice struct {
	name string
	file *os.File
	mtu  int
}

// NewDevice 创建 macOS utun 设备
//
// macOS 使用 SIOCIFCREATE2 / PF_SYSTEM ioctl 动态创建 utun 接口
func NewDevice(name string, mtu int) (Device, error) {
	// 打开 utun 控制 socket (AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL=2)
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, 2)
	if err != nil {
		return nil, fmt.Errorf("socket: %w", err)
	}

	// 寻找可用的 utun ID（utun0, utun1, ...）
	var devName string
	for id := 0; id < 32; id++ {
		err = unix.Connect(fd, &unix.SockaddrCtl{
			ID:   2,
			Unit: uint32(id + 1),
		})
		if err == nil {
			devName = fmt.Sprintf("utun%d", id)
			break
		}
	}
	if devName == "" {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("no free utun device")
	}

	file := os.NewFile(uintptr(fd), devName)
	return &darwinDevice{name: devName, file: file, mtu: mtu}, nil
}

func (d *darwinDevice) Read(p []byte) (int, error)  { return d.file.Read(p) }
func (d *darwinDevice) Write(p []byte) (int, error) { return d.file.Write(p) }
func (d *darwinDevice) Close() error                { return d.file.Close() }
func (d *darwinDevice) Name() string                { return d.name }
