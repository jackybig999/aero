//go:build windows

package main

import (
	"os"
	"syscall"
	"unsafe"

	"github.com/jchv/go-webview2"
)

const (
	NIM_ADD     = 0x00000000
	NIM_MODIFY  = 0x00000001
	NIM_DELETE  = 0x00000002
	NIF_MESSAGE = 0x00000001
	NIF_ICON    = 0x00000002
	NIF_TIP     = 0x00000004

	WM_USER     = 0x0400
	WM_TRAY_MSG = WM_USER + 101

	WM_CLOSE         = 0x0010
	WM_DESTROY       = 0x0002
	WM_LBUTTONUP     = 0x0202
	WM_LBUTTONDBLCLK = 0x0203
	WM_RBUTTONUP     = 0x0205

	SW_HIDE    = 0
	SW_SHOW    = 5
	SW_RESTORE = 9

	MF_STRING       = 0x00000000
	MF_SEPARATOR    = 0x00000800
	TPM_RETURNCMD   = 0x0100
	TPM_NONOTIFY    = 0x0080
	TPM_RIGHTBUTTON = 0x0002

	ID_TRAY_SHOW = 1001
	ID_TRAY_EXIT = 1002
)

var (
	modUser32  = syscall.NewLazyDLL("user32.dll")
	modShell32 = syscall.NewLazyDLL("shell32.dll")

	procShowWindow          = modUser32.NewProc("ShowWindow")
	procSetForegroundWindow = modUser32.NewProc("SetForegroundWindow")
	procSetWindowLongPtrW   = modUser32.NewProc("SetWindowLongPtrW")
	procCallWindowProcW     = modUser32.NewProc("CallWindowProcW")
	procCreatePopupMenu     = modUser32.NewProc("CreatePopupMenu")
	procAppendMenuW         = modUser32.NewProc("AppendMenuW")
	procTrackPopupMenu      = modUser32.NewProc("TrackPopupMenu")
	procDestroyMenu         = modUser32.NewProc("DestroyMenu")
	procGetCursorPos        = modUser32.NewProc("GetCursorPos")
	procLoadIconW           = modUser32.NewProc("LoadIconW")

	procShell_NotifyIconW = modShell32.NewProc("Shell_NotifyIconW")
	procExtractIconW      = modShell32.NewProc("ExtractIconW")
)

type point struct {
	X int32
	Y int32
}

type notifyIconDataW struct {
	CbSize            uint32
	HWnd              uintptr
	UID               uint32
	UFlags            uint32
	UCallbackMessage  uint32
	HIcon             uintptr
	SzTip             [128]uint16
	DwState           uint32
	DwStateMask       uint32
	SzInfo            [256]uint16
	UTimeoutOrVersion uint32
	SzInfoTitle       [64]uint16
	DwInfoFlags       uint32
	GuidItem          [16]byte
	HBalloonIcon      uintptr
}

var (
	origWndProc uintptr
	trayNID     notifyIconDataW
	appHWND     uintptr
	appWV       webview2.WebView
)

func wndProc(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case WM_CLOSE:
		procShowWindow.Call(hwnd, uintptr(SW_HIDE))
		return 0

	case WM_TRAY_MSG:
		if lParam == WM_LBUTTONUP || lParam == WM_LBUTTONDBLCLK {
			procShowWindow.Call(hwnd, uintptr(SW_SHOW))
			procShowWindow.Call(hwnd, uintptr(SW_RESTORE))
			procSetForegroundWindow.Call(hwnd)
			return 0
		} else if lParam == WM_RBUTTONUP {
			hMenu, _, _ := procCreatePopupMenu.Call()
			if hMenu != 0 {
				showStr, _ := syscall.UTF16PtrFromString("显示主界面")
				procAppendMenuW.Call(hMenu, uintptr(MF_STRING), uintptr(ID_TRAY_SHOW), uintptr(unsafe.Pointer(showStr)))
				procAppendMenuW.Call(hMenu, uintptr(MF_SEPARATOR), 0, 0)
				exitStr, _ := syscall.UTF16PtrFromString("退出 AERO OS")
				procAppendMenuW.Call(hMenu, uintptr(MF_STRING), uintptr(ID_TRAY_EXIT), uintptr(unsafe.Pointer(exitStr)))

				var pt point
				procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
				procSetForegroundWindow.Call(hwnd)

				cmd, _, _ := procTrackPopupMenu.Call(hMenu, uintptr(TPM_RETURNCMD|TPM_NONOTIFY|TPM_RIGHTBUTTON), uintptr(pt.X), uintptr(pt.Y), 0, hwnd, 0)
				procDestroyMenu.Call(hMenu)

				if cmd == ID_TRAY_SHOW {
					procShowWindow.Call(hwnd, uintptr(SW_SHOW))
					procShowWindow.Call(hwnd, uintptr(SW_RESTORE))
					procSetForegroundWindow.Call(hwnd)
				} else if cmd == ID_TRAY_EXIT {
					procShell_NotifyIconW.Call(uintptr(NIM_DELETE), uintptr(unsafe.Pointer(&trayNID)))
					if appWV != nil {
						appWV.Terminate()
					}
				}
			}
			return 0
		}

	case WM_DESTROY:
		procShell_NotifyIconW.Call(uintptr(NIM_DELETE), uintptr(unsafe.Pointer(&trayNID)))
	}

	r, _, _ := procCallWindowProcW.Call(origWndProc, hwnd, uintptr(msg), wParam, lParam)
	return r
}

func setupSystemTray(w webview2.WebView) {
	appWV = w
	hwndPtr := w.Window()
	if hwndPtr == nil {
		return
	}
	appHWND = uintptr(hwndPtr)

	// 1. Extract icon
	var hIcon uintptr
	if exePath, err := os.Executable(); err == nil {
		exePathPtr, _ := syscall.UTF16PtrFromString(exePath)
		r, _, _ := procExtractIconW.Call(0, uintptr(unsafe.Pointer(exePathPtr)), 0)
		if r > 1 {
			hIcon = r
		}
	}
	if hIcon == 0 {
		r, _, _ := procLoadIconW.Call(0, uintptr(32512)) // IDI_APPLICATION
		hIcon = r
	}

	// 2. Setup notify icon data
	trayNID.CbSize = uint32(unsafe.Sizeof(trayNID))
	trayNID.HWnd = appHWND
	trayNID.UID = 100
	trayNID.UFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
	trayNID.UCallbackMessage = WM_TRAY_MSG
	trayNID.HIcon = hIcon

	tipText, _ := syscall.UTF16FromString("AERO OS - 生产力工作台")
	copy(trayNID.SzTip[:], tipText)

	procShell_NotifyIconW.Call(uintptr(NIM_ADD), uintptr(unsafe.Pointer(&trayNID)))

	// 3. Subclass window procedure for close interception
	newWndProc := syscall.NewCallback(wndProc)
	const gwlpWndProc = ^uintptr(0) - 3 // GWLP_WNDPROC = -4

	if procSetWindowLongPtrW.Find() == nil {
		r, _, _ := procSetWindowLongPtrW.Call(appHWND, gwlpWndProc, newWndProc)
		origWndProc = r
	} else {
		procSetWindowLongW := modUser32.NewProc("SetWindowLongW")
		r, _, _ := procSetWindowLongW.Call(appHWND, gwlpWndProc, newWndProc)
		origWndProc = r
	}
}
