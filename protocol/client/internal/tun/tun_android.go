//go:build android

package tun

import (
	"fmt"
	"os"
)

type androidDevice struct {
	file *os.File
	name string
	mtu  int
}

func (d *androidDevice) Read(p []byte) (int, error)  { return d.file.Read(p) }
func (d *androidDevice) Write(p []byte) (int, error) { return d.file.Write(p) }
func (d *androidDevice) Close() error                { return d.file.Close() }
func (d *androidDevice) Name() string                { return d.name }

// NewDeviceFromFD creates a tun.Device from an established VpnService file descriptor.
func NewDeviceFromFD(fd int, mtu int) (Device, error) {
	if fd < 0 {
		return nil, fmt.Errorf("invalid android tun fd: %d", fd)
	}
	f := os.NewFile(uintptr(fd), "tun")
	if f == nil {
		return nil, fmt.Errorf("os.NewFile failed for fd %d", fd)
	}
	return &androidDevice{file: f, name: "vpn0", mtu: mtu}, nil
}

func NewDevice(name string, mtu int) (Device, error) {
	return nil, fmt.Errorf("android TUN fd is VpnService.establish (see protocol/client/android)")
}
