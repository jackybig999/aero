//go:build !linux

package edge

import "fmt"

func openGlobalTunnelDevice(name string) (GlobalTunnelDevice, error) {
	return nil, fmt.Errorf("shared edge TUN is not supported on this platform")
}
