//go:build windows

package runtime

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Clash/v2rayN sysproxy: INTERNET_OPTION_PER_CONNECTION_OPTION, not env vars.
const (
	internetOptionPerConnectionOption = 75
	internetPerConnFlags              = 1
	internetPerConnProxyServer        = 2
	internetPerConnProxyBypass        = 3
	proxyTypeDirect                   = 1
	proxyTypeProxy                    = 2
)

type internetPerConnOption struct {
	dwOption uint32
	_        uint32
	value    uint64
}

type internetPerConnOptionList struct {
	dwSize        uint32
	_             uint32
	pszConnection uintptr
	dwOptionCount uint32
	dwOptionError uint32
	pOptions      uintptr
}

func applyLANProxy(server, bypass string) error {
	flags := uint32(proxyTypeDirect | proxyTypeProxy)
	srv, err := windows.UTF16PtrFromString(server)
	if err != nil {
		return err
	}
	byp, err := windows.UTF16PtrFromString(bypass)
	if err != nil {
		return err
	}
	opts := [3]internetPerConnOption{
		{dwOption: internetPerConnFlags, value: uint64(flags)},
		{dwOption: internetPerConnProxyServer, value: uint64(uintptr(unsafe.Pointer(srv)))},
		{dwOption: internetPerConnProxyBypass, value: uint64(uintptr(unsafe.Pointer(byp)))},
	}
	return setPerConn(&opts[0], 3)
}

func clearLANProxy() {
	flags := uint32(proxyTypeDirect)
	opts := [1]internetPerConnOption{
		{dwOption: internetPerConnFlags, value: uint64(flags)},
	}
	_ = setPerConn(&opts[0], 1)
}

func setPerConn(opts *internetPerConnOption, n uint32) error {
	list := internetPerConnOptionList{
		dwSize:        uint32(unsafe.Sizeof(internetPerConnOptionList{})),
		dwOptionCount: n,
		pOptions:      uintptr(unsafe.Pointer(opts)),
	}
	r, _, e := procInternetSetOptionW.Call(
		0,
		internetOptionPerConnectionOption,
		uintptr(unsafe.Pointer(&list)),
		uintptr(unsafe.Sizeof(list)),
	)
	notifyWinINet()
	if r == 0 {
		return fmt.Errorf("InternetSetOption PER_CONNECTION: %v", e)
	}
	return nil
}
