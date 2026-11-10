//go:build linux

package edge

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	edgeTunDevice = "/dev/net/tun"
	edgeIffTun    = 0x0001
	edgeIffNoPi   = 0x1000
	edgeTunSetIff = 0x400454CA
)

type linuxGlobalTunnelDevice struct {
	name string
	file *os.File
}

func openGlobalTunnelDevice(name string) (GlobalTunnelDevice, error) {
	if name == "" {
		return nil, fmt.Errorf("global TUN device name is empty")
	}
	file, err := os.OpenFile(edgeTunDevice, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", edgeTunDevice, err)
	}
	ifr := struct {
		name  [16]byte
		flags uint16
	}{flags: edgeIffTun | edgeIffNoPi}
	copy(ifr.name[:], name)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(edgeTunSetIff), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		if closeErr := file.Close(); closeErr != nil {
			return nil, fmt.Errorf("TUNSETIFF: %v; close device: %w", errno, closeErr)
		}
		return nil, fmt.Errorf("TUNSETIFF: %v", errno)
	}
	devName := string(ifr.name[:])
	for i, value := range ifr.name {
		if value == 0 {
			devName = string(ifr.name[:i])
			break
		}
	}
	return &linuxGlobalTunnelDevice{name: devName, file: file}, nil
}

func (d *linuxGlobalTunnelDevice) Read(packet []byte) (int, error)  { return d.file.Read(packet) }
func (d *linuxGlobalTunnelDevice) Write(packet []byte) (int, error) { return d.file.Write(packet) }
func (d *linuxGlobalTunnelDevice) Close() error                     { return d.file.Close() }
