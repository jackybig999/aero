//go:build linux && !android

package tun

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	tunDevice = "/dev/net/tun"
	iffTun    = 0x0001
	iffNoPi   = 0x1000
	tunSetIff = 0x400454ca
)

// linuxDevice Linux TUN 设备实现
type linuxDevice struct {
	name string
	file *os.File
	mtu  int
}

// NewDevice 创建 Linux TUN 设备
func NewDevice(name string, mtu int) (Device, error) {
	file, err := os.OpenFile(tunDevice, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", tunDevice, err)
	}

	ifr := struct {
		name  [16]byte
		flags uint16
	}{flags: iffTun | iffNoPi}
	copy(ifr.name[:], name)

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		file.Fd(),
		uintptr(tunSetIff),
		uintptr(unsafe.Pointer(&ifr)),
	)
	if errno != 0 {
		file.Close()
		return nil, fmt.Errorf("TUNSETIFF: %v", errno)
	}

	devName := string(ifr.name[:])
	// trim null bytes
	for i, b := range ifr.name {
		if b == 0 {
			devName = string(ifr.name[:i])
			break
		}
	}

	return &linuxDevice{name: devName, file: file, mtu: mtu}, nil
}

func (d *linuxDevice) Read(p []byte) (int, error)  { return d.file.Read(p) }
func (d *linuxDevice) Write(p []byte) (int, error) { return d.file.Write(p) }
func (d *linuxDevice) Close() error                { return d.file.Close() }
func (d *linuxDevice) Name() string                { return d.name }
