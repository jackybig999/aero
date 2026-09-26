//go:build !android

package tun

import "fmt"

// NewDeviceFromFD stub for non-Android platforms
func NewDeviceFromFD(fd int, mtu int) (Device, error) {
	return nil, fmt.Errorf("NewDeviceFromFD is only supported on Android")
}
