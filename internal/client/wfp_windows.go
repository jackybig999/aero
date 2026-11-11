//go:build windows && (amd64 || arm64)

package client

// Windows DNS 防泄漏（ADR-0014）：在 WFP 动态会话（FWPM_SESSION_FLAG_DYNAMIC）中安装过滤规则，
// 会话句柄关闭或进程终止（含崩溃、被强杀）时由内核删除，不写注册表、不留持久规则。
//
// 规则（同一子层，权重高者先匹配）：
//
//	15 放行：本程序 exe（直连 DNS 上游、到 edge 的 QUIC）
//	14 放行：出接口为自有 TUN；放行回环（本机 DNS 代理不受影响）
//	13 屏蔽：远端端口 53 的 UDP/TCP
//
// 结构体布局与常量取自 WireGuard for Windows 的 tunnel/firewall 包（MIT，Copyright WireGuard LLC），
// 只保留用到的部分；布局由下方编译期断言校验（64 位）。

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ---- 类型（fwptypes.h / fwpmtypes.h，64 位布局） ----

type fwpDataType uint32

const (
	fwpUint8        fwpDataType = 1
	fwpUint16       fwpDataType = 2
	fwpUint32       fwpDataType = 3
	fwpUint64       fwpDataType = 4
	fwpByteBlobType fwpDataType = 12
)

type fwpValue0 struct { // FWP_VALUE0 / FWP_CONDITION_VALUE0
	typ   fwpDataType
	value uintptr // 联合体：标量直接存放，其余为指针
}

type fwpByteBlob struct {
	size uint32
	data *uint8
}

type fwpmDisplayData0 struct {
	name        *uint16
	description *uint16
}

type fwpMatchType uint32

const (
	fwpMatchEqual       fwpMatchType = 0
	fwpMatchFlagsAllSet fwpMatchType = 6
)

type fwpmFilterCondition0 struct {
	fieldKey       windows.GUID
	matchType      fwpMatchType
	conditionValue fwpValue0
}

type fwpActionType uint32

const (
	fwpActionBlock  fwpActionType = 0x1 | 0x1000
	fwpActionPermit fwpActionType = 0x2 | 0x1000
)

type fwpmAction0 struct {
	typ        fwpActionType
	filterType windows.GUID
}

type fwpmFilter0 struct {
	filterKey           windows.GUID
	displayData         fwpmDisplayData0
	flags               uint32
	providerKey         *windows.GUID
	providerData        fwpByteBlob
	layerKey            windows.GUID
	subLayerKey         windows.GUID
	weight              fwpValue0
	numFilterConditions uint32
	filterCondition     *fwpmFilterCondition0
	action              fwpmAction0
	_                   [4]byte // C 中其后是 8 字节对齐的联合体
	providerContextKey  windows.GUID
	reserved            *windows.GUID
	filterID            uint64
	effectiveWeight     fwpValue0
}

type fwpmSession0 struct {
	sessionKey           windows.GUID
	displayData          fwpmDisplayData0
	flags                uint32
	txnWaitTimeoutInMSec uint32
	processID            uint32
	sid                  *windows.SID
	username             *uint16
	kernelMode           uint8
}

type fwpmSublayer0 struct {
	subLayerKey  windows.GUID
	displayData  fwpmDisplayData0
	flags        uint32
	providerKey  *windows.GUID
	providerData fwpByteBlob
	weight       uint16
}

// 编译期布局断言（数值来自 WireGuard 的 64 位布局测试）：任一不等即编译失败。
var (
	_ [unsafe.Sizeof(fwpValue0{}) - 16]byte
	_ [16 - unsafe.Sizeof(fwpValue0{})]byte
	_ [unsafe.Sizeof(fwpmFilterCondition0{}) - 40]byte
	_ [40 - unsafe.Sizeof(fwpmFilterCondition0{})]byte
	_ [unsafe.Offsetof(fwpmFilterCondition0{}.conditionValue) - 24]byte
	_ [24 - unsafe.Offsetof(fwpmFilterCondition0{}.conditionValue)]byte
	_ [unsafe.Sizeof(fwpmFilter0{}) - 200]byte
	_ [200 - unsafe.Sizeof(fwpmFilter0{})]byte
	_ [unsafe.Offsetof(fwpmFilter0{}.weight) - 96]byte
	_ [96 - unsafe.Offsetof(fwpmFilter0{}.weight)]byte
	_ [unsafe.Offsetof(fwpmFilter0{}.filterCondition) - 120]byte
	_ [120 - unsafe.Offsetof(fwpmFilter0{}.filterCondition)]byte
	_ [unsafe.Offsetof(fwpmFilter0{}.action) - 128]byte
	_ [128 - unsafe.Offsetof(fwpmFilter0{}.action)]byte
	_ [unsafe.Offsetof(fwpmFilter0{}.providerContextKey) - 152]byte
	_ [152 - unsafe.Offsetof(fwpmFilter0{}.providerContextKey)]byte
	_ [unsafe.Offsetof(fwpmFilter0{}.filterID) - 176]byte
	_ [176 - unsafe.Offsetof(fwpmFilter0{}.filterID)]byte
	_ [unsafe.Sizeof(fwpmSession0{}) - 72]byte
	_ [72 - unsafe.Sizeof(fwpmSession0{})]byte
	_ [unsafe.Offsetof(fwpmSession0{}.kernelMode) - 64]byte
	_ [64 - unsafe.Offsetof(fwpmSession0{}.kernelMode)]byte
	_ [unsafe.Sizeof(fwpmSublayer0{}) - 72]byte
	_ [72 - unsafe.Sizeof(fwpmSublayer0{})]byte
	_ [unsafe.Offsetof(fwpmSublayer0{}.weight) - 64]byte
	_ [64 - unsafe.Offsetof(fwpmSublayer0{}.weight)]byte
)

// ---- GUID（fwpmu.h） ----

var (
	layerALEAuthConnectV4    = windows.GUID{Data1: 0xc38d57d1, Data2: 0x05a7, Data3: 0x4c33, Data4: [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}}
	layerALEAuthRecvAcceptV4 = windows.GUID{Data1: 0xe1cd9fe7, Data2: 0xf4b5, Data3: 0x4273, Data4: [8]byte{0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50}}
	layerALEAuthConnectV6    = windows.GUID{Data1: 0x4a72393b, Data2: 0x319f, Data3: 0x44bc, Data4: [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}}
	layerALEAuthRecvAcceptV6 = windows.GUID{Data1: 0xa3b42c97, Data2: 0x9f04, Data3: 0x4672, Data4: [8]byte{0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f}}

	condIPLocalInterface = windows.GUID{Data1: 0x4cd62a49, Data2: 0x59c3, Data3: 0x4969, Data4: [8]byte{0xb7, 0xf3, 0xbd, 0xa5, 0xd3, 0x28, 0x90, 0xa4}}
	condIPProtocol       = windows.GUID{Data1: 0x3971ef2b, Data2: 0x623e, Data3: 0x4f9a, Data4: [8]byte{0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7}}
	condIPRemotePort     = windows.GUID{Data1: 0xc35a604d, Data2: 0xd22b, Data3: 0x4e1a, Data4: [8]byte{0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b}}
	condALEAppID         = windows.GUID{Data1: 0xd78e1e87, Data2: 0x8644, Data3: 0x4ea5, Data4: [8]byte{0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71}}
	condFlags            = windows.GUID{Data1: 0x632ce23b, Data2: 0x5167, Data3: 0x435c, Data4: [8]byte{0x86, 0xd7, 0xe9, 0x03, 0x68, 0x4a, 0xa8, 0x0c}}

	aleLayers = []*windows.GUID{&layerALEAuthConnectV4, &layerALEAuthRecvAcceptV4, &layerALEAuthConnectV6, &layerALEAuthRecvAcceptV6}
)

const (
	fwpmSessionFlagDynamic   = 0x1
	rpcCAuthnWinNT           = 10
	fwpConditionFlagLoopback = 0x1
	ipProtoTCP               = 6
	ipProtoUDP               = 17
	dnsPort                  = 53
)

// ---- 系统调用（fwpuclnt.dll）；Fwpm* 直接以返回值给出错误码 ----

var (
	modFwpuclnt                   = windows.NewLazySystemDLL("fwpuclnt.dll")
	procFwpmEngineOpen0           = modFwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0          = modFwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmTransactionBegin0     = modFwpuclnt.NewProc("FwpmTransactionBegin0")
	procFwpmTransactionCommit0    = modFwpuclnt.NewProc("FwpmTransactionCommit0")
	procFwpmTransactionAbort0     = modFwpuclnt.NewProc("FwpmTransactionAbort0")
	procFwpmSubLayerAdd0          = modFwpuclnt.NewProc("FwpmSubLayerAdd0")
	procFwpmFilterAdd0            = modFwpuclnt.NewProc("FwpmFilterAdd0")
	procFwpmGetAppIdFromFileName0 = modFwpuclnt.NewProc("FwpmGetAppIdFromFileName0")
	procFwpmFreeMemory0           = modFwpuclnt.NewProc("FwpmFreeMemory0")
)

func fwpmCall(p *windows.LazyProc, args ...uintptr) error {
	if err := p.Find(); err != nil {
		return err
	}
	r, _, _ := syscall.SyscallN(p.Addr(), args...)
	if r != 0 {
		return fmt.Errorf("%s: %w", p.Name, syscall.Errno(r))
	}
	return nil
}

// ---- DNS 防护 ----

type dnsGuard struct {
	engine uintptr
	pins   []any // 被 uintptr 引用的 Go 对象：保持在堆上且存活至规则提交
}

// startDNSGuard 在动态会话中安装 DNS 防泄漏规则。返回的 dnsGuard.Close 删除全部规则；
// 进程意外终止时内核同样会删除。
func startDNSGuard(tunLUID uint64) (*dnsGuard, error) {
	name, err := windows.UTF16PtrFromString("AERO")
	if err != nil {
		return nil, err
	}
	desc, err := windows.UTF16PtrFromString("AERO DNS leak guard (dynamic session)")
	if err != nil {
		return nil, err
	}
	session := fwpmSession0{
		displayData:          fwpmDisplayData0{name: name, description: desc},
		flags:                fwpmSessionFlagDynamic,
		txnWaitTimeoutInMSec: windows.INFINITE,
	}
	g := &dnsGuard{}
	if err := fwpmCall(procFwpmEngineOpen0, 0, rpcCAuthnWinNT, 0,
		uintptr(unsafe.Pointer(&session)), uintptr(unsafe.Pointer(&g.engine))); err != nil {
		return nil, err
	}
	if err := g.install(name, tunLUID); err != nil {
		_ = g.Close()
		return nil, err
	}
	g.pins = nil
	return g, nil
}

func (g *dnsGuard) install(name *uint16, tunLUID uint64) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exePtr, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	var appID *fwpByteBlob // 由 WFP 分配
	if err := fwpmCall(procFwpmGetAppIdFromFileName0, uintptr(unsafe.Pointer(exePtr)), uintptr(unsafe.Pointer(&appID))); err != nil {
		return err
	}
	defer syscall.SyscallN(procFwpmFreeMemory0.Addr(), uintptr(unsafe.Pointer(&appID)))

	if err := fwpmCall(procFwpmTransactionBegin0, g.engine, 0); err != nil {
		return err
	}
	if err := g.addFilters(name, tunLUID, appID); err != nil {
		_ = fwpmCall(procFwpmTransactionAbort0, g.engine)
		return err
	}
	return fwpmCall(procFwpmTransactionCommit0, g.engine)
}

func (g *dnsGuard) addFilters(name *uint16, tunLUID uint64, appID *fwpByteBlob) error {
	subLayerKey, err := windows.GenerateGUID()
	if err != nil {
		return err
	}
	sub := fwpmSublayer0{subLayerKey: subLayerKey, displayData: fwpmDisplayData0{name: name}, weight: 0xffff}
	if err := fwpmCall(procFwpmSubLayerAdd0, g.engine, uintptr(unsafe.Pointer(&sub)), 0); err != nil {
		return err
	}

	luid := new(uint64)
	*luid = tunLUID
	g.pins = append(g.pins, luid)

	rules := []struct {
		weight uint8
		action fwpActionType
		conds  []fwpmFilterCondition0
	}{
		{15, fwpActionPermit, []fwpmFilterCondition0{
			{fieldKey: condALEAppID, matchType: fwpMatchEqual, conditionValue: fwpValue0{fwpByteBlobType, uintptr(unsafe.Pointer(appID))}},
		}},
		{14, fwpActionPermit, []fwpmFilterCondition0{
			{fieldKey: condIPLocalInterface, matchType: fwpMatchEqual, conditionValue: fwpValue0{fwpUint64, uintptr(unsafe.Pointer(luid))}},
		}},
		{14, fwpActionPermit, []fwpmFilterCondition0{
			{fieldKey: condFlags, matchType: fwpMatchFlagsAllSet, conditionValue: fwpValue0{fwpUint32, fwpConditionFlagLoopback}},
		}},
		{13, fwpActionBlock, []fwpmFilterCondition0{ // 不同字段为“与”，同一字段重复为“或”
			{fieldKey: condIPRemotePort, matchType: fwpMatchEqual, conditionValue: fwpValue0{fwpUint16, dnsPort}},
			{fieldKey: condIPProtocol, matchType: fwpMatchEqual, conditionValue: fwpValue0{fwpUint8, ipProtoUDP}},
			{fieldKey: condIPProtocol, matchType: fwpMatchEqual, conditionValue: fwpValue0{fwpUint8, ipProtoTCP}},
		}},
	}
	for _, r := range rules {
		g.pins = append(g.pins, r.conds)
		for _, layer := range aleLayers {
			f := fwpmFilter0{
				displayData:         fwpmDisplayData0{name: name},
				layerKey:            *layer,
				subLayerKey:         subLayerKey,
				weight:              fwpValue0{fwpUint8, uintptr(r.weight)},
				numFilterConditions: uint32(len(r.conds)),
				filterCondition:     &r.conds[0],
				action:              fwpmAction0{typ: r.action},
			}
			var id uint64
			if err := fwpmCall(procFwpmFilterAdd0, g.engine, uintptr(unsafe.Pointer(&f)), 0, uintptr(unsafe.Pointer(&id))); err != nil {
				return err
			}
		}
	}
	return nil
}

// Close 关闭动态会话，内核随即删除本会话的全部规则；幂等。
func (g *dnsGuard) Close() error {
	if g == nil || g.engine == 0 {
		return nil
	}
	err := fwpmCall(procFwpmEngineClose0, g.engine)
	g.engine = 0
	return err
}
