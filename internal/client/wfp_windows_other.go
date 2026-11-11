//go:build windows && !(amd64 || arm64)

package client

import "errors"

// 32 位 Windows 不在构建目标内；没有 DNS 防泄漏时拒绝启用 TUN（fail-closed）。
type dnsGuard struct{}

func startDNSGuard(uint64) (*dnsGuard, error) {
	return nil, errors.New("DNS leak guard is not supported on this architecture")
}

func (*dnsGuard) Close() error { return nil }
