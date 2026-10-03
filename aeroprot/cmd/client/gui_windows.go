//go:build windows

package main

import (
	"embed"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/jchv/go-webview2"
)

//go:embed assets/icon_blue.ico assets/icon_green.ico assets/icon_yellow.ico
var iconFS embed.FS

const (
	clientMutexName = "Local\\AERO-Client-Single-Instance-Lock"

	NIM_ADD     = 0x00000000
	NIM_MODIFY  = 0x00000001
	NIM_DELETE  = 0x00000002
	NIF_MESSAGE = 0x00000001
	NIF_ICON    = 0x00000002
	NIF_TIP     = 0x00000004

	WM_USER     = 0x0400
	WM_TRAY_MSG = WM_USER + 102

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
	MF_GRAYED       = 0x00000001
	TPM_RETURNCMD   = 0x0100
	TPM_NONOTIFY    = 0x0080
	TPM_RIGHTBUTTON = 0x0002

	ID_TRAY_SHOW = 2001
	ID_TRAY_EXIT = 2002
	ID_MODE_TUN  = 2003
	ID_MODE_SYS  = 2004

	WM_SETICON = 0x0080
	ICON_SMALL = 0
	ICON_BIG   = 1
)

var (
	singleMutex syscall.Handle

	modUser32   = syscall.NewLazyDLL("user32.dll")
	modShell32  = syscall.NewLazyDLL("shell32.dll")
	modKernel32 = syscall.NewLazyDLL("kernel32.dll")

	procSendMessageW             = modUser32.NewProc("SendMessageW")
	procShowWindow               = modUser32.NewProc("ShowWindow")
	procSetForegroundWindow      = modUser32.NewProc("SetForegroundWindow")
	procSetWindowLongPtrW        = modUser32.NewProc("SetWindowLongPtrW")
	procCallWindowProcW          = modUser32.NewProc("CallWindowProcW")
	procCreatePopupMenu          = modUser32.NewProc("CreatePopupMenu")
	procAppendMenuW              = modUser32.NewProc("AppendMenuW")
	procTrackPopupMenu           = modUser32.NewProc("TrackPopupMenu")
	procDestroyMenu              = modUser32.NewProc("DestroyMenu")
	procGetCursorPos             = modUser32.NewProc("GetCursorPos")
	procLoadIconW                = modUser32.NewProc("LoadIconW")
	procLoadImageW               = modUser32.NewProc("LoadImageW")
	procCreateIconFromResourceEx = modUser32.NewProc("CreateIconFromResourceEx")

	procShell_NotifyIconW = modShell32.NewProc("Shell_NotifyIconW")
	procExtractIconW      = modShell32.NewProc("ExtractIconW")

	origWndProc uintptr
	trayNID     notifyIconDataW
	clientHWND  uintptr
	clientWV    webview2.WebView

	hIconBlue   uintptr
	hIconGreen  uintptr
	hIconYellow uintptr
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

var msgAeroRestore uint32

func init() {
	name, _ := syscall.UTF16PtrFromString("AERO_CLIENT_RESTORE_MSG")
	r, _, _ := modUser32.NewProc("RegisterWindowMessageW").Call(uintptr(unsafe.Pointer(name)))
	msgAeroRestore = uint32(r)
}

func ensureSingleInstance() bool {
	name, err := syscall.UTF16PtrFromString(clientMutexName)
	if err != nil {
		return true
	}
	create := modKernel32.NewProc("CreateMutexW")
	h, _, last := create.Call(0, 0, uintptr(unsafe.Pointer(name)))
	singleMutex = syscall.Handle(h)
	if last == syscall.Errno(183) { // ERROR_ALREADY_EXISTS
		restoreExistingWindow()
		return false
	}
	return true
}

func restoreExistingWindow() {
	title, _ := syscall.UTF16PtrFromString("AEROSYS")
	hwnd, _, _ := modUser32.NewProc("FindWindowW").Call(0, uintptr(unsafe.Pointer(title)))
	if hwnd != 0 {
		procShowWindow.Call(hwnd, uintptr(SW_SHOW))
		procShowWindow.Call(hwnd, uintptr(SW_RESTORE))
		procSetForegroundWindow.Call(hwnd)
		return
	}
	if msgAeroRestore != 0 {
		procSendMessageTimeoutW := modUser32.NewProc("SendMessageTimeoutW")
		const hwndBroadcast = 0xffff
		const smtoAbortIfHung = 0x0002
		var result uintptr
		procSendMessageTimeoutW.Call(
			uintptr(hwndBroadcast),
			uintptr(msgAeroRestore),
			0, 0,
			uintptr(smtoAbortIfHung),
			500,
			uintptr(unsafe.Pointer(&result)),
		)
	}
}

func initDPIAwareness() {
	proc := modUser32.NewProc("SetProcessDpiAwarenessContext")
	if proc.Find() == nil {
		// DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = -4
		_, _, _ = proc.Call(^uintptr(3))
	}
}

func hideOwnConsole() {
	hwnd, _, _ := modKernel32.NewProc("GetConsoleWindow").Call()
	if hwnd != 0 {
		modUser32.NewProc("ShowWindow").Call(hwnd, 0)
	}
}

func wndProc(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	if msg == msgAeroRestore && msgAeroRestore != 0 {
		procShowWindow.Call(hwnd, uintptr(SW_SHOW))
		procShowWindow.Call(hwnd, uintptr(SW_RESTORE))
		procSetForegroundWindow.Call(hwnd)
		return 0
	}
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
				statusStr, _ := syscall.UTF16PtrFromString("AEROSYS · 系统托盘")
				procAppendMenuW.Call(hMenu, uintptr(MF_STRING|MF_GRAYED), 0, uintptr(unsafe.Pointer(statusStr)))
				procAppendMenuW.Call(hMenu, uintptr(MF_SEPARATOR), 0, 0)
				showStr, _ := syscall.UTF16PtrFromString("打开主界面")
				procAppendMenuW.Call(hMenu, uintptr(MF_STRING), uintptr(ID_TRAY_SHOW), uintptr(unsafe.Pointer(showStr)))
				procAppendMenuW.Call(hMenu, uintptr(MF_SEPARATOR), 0, 0)
				exitStr, _ := syscall.UTF16PtrFromString("退出客户端")
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
					if clientWV != nil {
						clientWV.Terminate()
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

func loadEmbeddedIconSize(filename string, cx, cy int) uintptr {
	data, err := iconFS.ReadFile(filename)
	if err != nil || len(data) == 0 {
		return 0
	}
	tmpPath := filepath.Join(os.TempDir(), fmt.Sprintf("aero_%dx%d_%s", cx, cy, filepath.Base(filename)))
	if err := os.WriteFile(tmpPath, data, 0644); err == nil {
		pathPtr, _ := syscall.UTF16PtrFromString(tmpPath)
		h, _, _ := procLoadImageW.Call(0, uintptr(unsafe.Pointer(pathPtr)), 1, uintptr(cx), uintptr(cy), 0x0010)
		if h != 0 {
			return h
		}
	}
	r, _, _ := procCreateIconFromResourceEx.Call(
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		1,          // fIcon = TRUE
		0x00030000, // dwVersion
		uintptr(cx), uintptr(cy),
		0,
	)
	return r
}

func loadEmbeddedIcon(filename string) uintptr {
	return loadEmbeddedIconSize(filename, 16, 16)
}

func UpdateTrayIcon(mode string, connected bool) {
	if clientHWND == 0 {
		return
	}
	var targetIcon uintptr
	var tip string

	if !connected {
		targetIcon = hIconBlue
		tip = "AEROSYS · 就绪 (未连接)"
	} else if mode == "tun" {
		targetIcon = hIconGreen
		tip = "AEROSYS · TUN 全局模式 (已连接)"
	} else {
		targetIcon = hIconYellow
		tip = "AEROSYS · 系统代理模式 (已连接)"
	}

	if targetIcon != 0 {
		trayNID.HIcon = targetIcon
		procSendMessageW.Call(clientHWND, uintptr(WM_SETICON), uintptr(ICON_SMALL), targetIcon)
	}
	tipText, _ := syscall.UTF16FromString(tip)
	copy(trayNID.SzTip[:], tipText)

	procShell_NotifyIconW.Call(uintptr(NIM_MODIFY), uintptr(unsafe.Pointer(&trayNID)))
}

func setupSystemTray(w webview2.WebView) {
	clientWV = w
	hwndPtr := w.Window()
	if hwndPtr == nil {
		return
	}
	clientHWND = uintptr(hwndPtr)

	hIconBlue = loadEmbeddedIcon("assets/icon_blue.ico")
	hIconGreen = loadEmbeddedIcon("assets/icon_green.ico")
	hIconYellow = loadEmbeddedIcon("assets/icon_yellow.ico")

	var hIcon uintptr = hIconBlue
	if hIcon == 0 {
		if exePath, err := os.Executable(); err == nil {
			exePathPtr, _ := syscall.UTF16PtrFromString(exePath)
			r, _, _ := procExtractIconW.Call(0, uintptr(unsafe.Pointer(exePathPtr)), 0)
			if r > 1 {
				hIcon = r
			}
		}
	}
	if hIcon == 0 {
		r, _, _ := procLoadIconW.Call(0, uintptr(32512)) // IDI_APPLICATION
		hIcon = r
	}

	// 1. 设置窗口左上角标题栏小图标 (16x16) 与任务栏/Alt+Tab大图标 (32x32)
	if hIconBlue != 0 {
		procSendMessageW.Call(clientHWND, uintptr(WM_SETICON), uintptr(ICON_SMALL), hIconBlue)
		hIconBig := loadEmbeddedIconSize("assets/icon_blue.ico", 32, 32)
		if hIconBig == 0 {
			hIconBig = hIconBlue
		}
		procSendMessageW.Call(clientHWND, uintptr(WM_SETICON), uintptr(ICON_BIG), hIconBig)
	} else if hIcon != 0 {
		procSendMessageW.Call(clientHWND, uintptr(WM_SETICON), uintptr(ICON_SMALL), hIcon)
		procSendMessageW.Call(clientHWND, uintptr(WM_SETICON), uintptr(ICON_BIG), hIcon)
	}

	trayNID.CbSize = uint32(unsafe.Sizeof(trayNID))
	trayNID.HWnd = clientHWND
	trayNID.UID = 101
	trayNID.UFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
	trayNID.UCallbackMessage = WM_TRAY_MSG
	trayNID.HIcon = hIcon

	tipText, _ := syscall.UTF16FromString("AEROSYS · 就绪 (未连接)")
	copy(trayNID.SzTip[:], tipText)

	procShell_NotifyIconW.Call(uintptr(NIM_ADD), uintptr(unsafe.Pointer(&trayNID)))

	newWndProc := syscall.NewCallback(wndProc)
	const gwlpWndProc = ^uintptr(0) - 3 // GWLP_WNDPROC = -4

	if procSetWindowLongPtrW.Find() == nil {
		r, _, _ := procSetWindowLongPtrW.Call(clientHWND, gwlpWndProc, newWndProc)
		origWndProc = r
	} else {
		procSetWindowLongW := modUser32.NewProc("SetWindowLongW")
		r, _, _ := procSetWindowLongW.Call(clientHWND, gwlpWndProc, newWndProc)
		origWndProc = r
	}
}

func runClientWindow(htmlUI string, handler http.Handler, shutdown func()) {
	hideOwnConsole()
	if !ensureSingleInstance() {
		return
	}

	initDPIAwareness()

	wvData := filepath.Join(os.TempDir(), "aero-client-wv-"+strconv.Itoa(os.Getpid()))
	_ = os.MkdirAll(wvData, 0700)
	defer os.RemoveAll(wvData)

	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     false,
		AutoFocus: true,
		DataPath:  wvData,
		WindowOptions: webview2.WindowOptions{
			Title:  "AEROSYS",
			Width:  390,
			Height: 580,
			Center: true,
		},
	})

	if w == nil {
		log.Printf("[UI] WebView2 not available, running headless")
		runHeadless(shutdown)
		return
	}
	defer w.Destroy()

	w.SetSize(390, 580, webview2.HintNone)

	// 绑定内存级原生 IPC 通道，彻底切断对 127.0.0.1 网络端口依赖
	w.Bind("goClientAPI", func(method, path, bodyStr string) (string, error) {
		req := httptest.NewRequest(method, path, strings.NewReader(bodyStr))
		if bodyStr != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Body.String(), nil
	})

	w.SetHtml(htmlUI)

	setupSystemTray(w)

	log.Println("[UI] client window started, entering event loop...")
	w.Run()

	procShell_NotifyIconW.Call(uintptr(NIM_DELETE), uintptr(unsafe.Pointer(&trayNID)))
	shutdown()
}
