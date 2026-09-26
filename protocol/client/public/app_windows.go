//go:build windows

package public

import (
	_ "embed"
	"github.com/getlantern/systray"
	"github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"unsafe"
)

// -----------------------------------------------------------------------------
// Source: aeroapp_tray.go
// -----------------------------------------------------------------------------
func runAppShell(uiURL string) error {
	go func() {
		runtime.LockOSThread()
		if err := runNativeWindow(uiURL); err != nil {
			log.Printf("[UI] window: %v", err)
		}
		exitApp()
	}()
	systray.Run(func() {
		if len(appIcon) > 0 {
			systray.SetIcon(appIcon)
		}
		systray.SetTitle("AERO")
		systray.SetTooltip("AERO")
		mShow := systray.AddMenuItem("打开窗口", "")
		mExit := systray.AddMenuItem("退出", "")
		go func() {
			for {
				select {
				case <-mShow.ClickedCh:
					restoreNativeWindow()
				case <-mExit.ClickedCh:
					exitApp()
					return
				}
			}
		}()
	}, func() {})
	return nil
}

// -----------------------------------------------------------------------------
// Source: aeroapp_tray_click_windows.go
// -----------------------------------------------------------------------------
// Tray left-click is handled by the menu (打开窗口 / 退出).
// Do not subclass HWND — that crashed the client.
func hookTrayLeftClick(func()) {}

// -----------------------------------------------------------------------------
// Source: aeroapp_webview_windows.go
// -----------------------------------------------------------------------------
var (
	uiMu        sync.Mutex
	uiView      webview2.WebView
	uiHwnd      uintptr
	origWndProc uintptr
	closeToTray uintptr

	user32                            = windows.NewLazySystemDLL("user32.dll")
	procSetProcessDpiAwarenessContext = user32.NewProc("SetProcessDpiAwarenessContext")
)

func initDPIAwareness() {
	if procSetProcessDpiAwarenessContext.Find() == nil {
		// DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = -4 (uintptr(^uintptr(3)))
		_, _, _ = procSetProcessDpiAwarenessContext.Call(^uintptr(3))
	}
}

func runNativeWindow(uiURL string) error {
	initDPIAwareness()
	w := newWebView()
	if w == nil {
		return errWebView2Missing()
	}
	uiMu.Lock()
	uiView = w
	uiMu.Unlock()
	defer func() {
		uiMu.Lock()
		uiView = nil
		uiHwnd = 0
		uiMu.Unlock()
		w.Destroy()
	}()
	w.SetSize(390, 560, webview2.HintNone)
	installCloseToTray(uintptr(w.Window()))
	w.Navigate(uiURL)
	w.Run()
	return nil
}

func newWebView() webview2.WebView {
	initDPIAwareness()
	opts := webview2.WebViewOptions{
		Debug:     false,
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title:  "AERO",
			Width:  390,
			Height: 560,
			Center: true,
		},
	}
	// Unique dir so a crashed previous instance cannot lock the profile.
	data := filepath.Join(os.TempDir(), "aeroapp-wv-"+strconv.Itoa(os.Getpid()))
	_ = os.MkdirAll(data, 0o700)
	opts.DataPath = data
	if w := webview2.NewWithOptions(opts); w != nil {
		return w
	}
	opts.DataPath = filepath.Join(os.TempDir(), "aeroapp-wv-fallback")
	_ = os.MkdirAll(opts.DataPath, 0o700)
	return webview2.NewWithOptions(opts)
}

func installCloseToTray(hwnd uintptr) {
	if hwnd == 0 {
		return
	}
	uiMu.Lock()
	uiHwnd = hwnd
	uiMu.Unlock()
	if closeToTray == 0 {
		closeToTray = syscall.NewCallback(closeToTrayProc)
	}
	user32 := syscall.NewLazyDLL("user32.dll")
	set := user32.NewProc("SetWindowLongPtrW")
	const gwlpWndProc = ^uintptr(0) - 3 // GWLP_WNDPROC = -4
	orig, _, _ := set.Call(hwnd, gwlpWndProc, closeToTray)
	if orig != 0 {
		origWndProc = orig
	}
}

func closeToTrayProc(hwnd, msg, wparam, lparam uintptr) uintptr {
	const wmClose = 0x0010
	if msg == wmClose {
		hideNativeWindow()
		log.Printf("[UI] window close -> tray (sysproxy/TUN stay until 退出)")
		return 0
	}
	if origWndProc == 0 {
		return 0
	}
	user32 := syscall.NewLazyDLL("user32.dll")
	r, _, _ := user32.NewProc("CallWindowProcW").Call(origWndProc, hwnd, msg, wparam, lparam)
	return r
}

func hideNativeWindow() {
	uiMu.Lock()
	hwnd := uiHwnd
	uiMu.Unlock()
	if hwnd == 0 {
		return
	}
	syscall.NewLazyDLL("user32.dll").NewProc("ShowWindow").Call(hwnd, 0)
}

func restoreNativeWindow() bool {
	user32 := syscall.NewLazyDLL("user32.dll")
	uiMu.Lock()
	hwnd := uiHwnd
	uiMu.Unlock()
	if hwnd == 0 {
		title, err := syscall.UTF16PtrFromString("AERO")
		if err == nil {
			hwnd, _, _ = user32.NewProc("FindWindowW").Call(0, uintptr(unsafe.Pointer(title)))
		}
	}
	if hwnd == 0 {
		return false
	}
	user32.NewProc("ShowWindow").Call(hwnd, 9) // SW_RESTORE
	user32.NewProc("SetForegroundWindow").Call(hwnd)
	return true
}

func terminateNativeWindow() {
	uiMu.Lock()
	w := uiView
	uiMu.Unlock()
	if w != nil {
		w.Terminate()
	}
}

func errWebView2Missing() error {
	return &simpleError{s: "需要 Microsoft Edge WebView2 Runtime。Windows 10/11 一般已自带。"}
}

type simpleError struct{ s string }

func (e *simpleError) Error() string { return e.s }

func nativeAlert(title, body string) {
	user32 := syscall.NewLazyDLL("user32.dll")
	msgBox := user32.NewProc("MessageBoxW")
	t, _ := syscall.UTF16PtrFromString(title)
	b, _ := syscall.UTF16PtrFromString(body)
	msgBox.Call(0, uintptr(unsafe.Pointer(b)), uintptr(unsafe.Pointer(t)), 0x10)
	log.Printf("[UI] alert: %s", body)
}

// -----------------------------------------------------------------------------
// Source: aeroapp_single_windows.go
// -----------------------------------------------------------------------------
const mutexName = "Local\\AERO-aeroapp-single"

var singleMutex syscall.Handle

// ensureSingleInstance returns false if another aeroapp is already running
// (that instance is brought to the front).
func ensureSingleInstance() bool {
	name, err := syscall.UTF16PtrFromString(mutexName)
	if err != nil {
		return true
	}
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	create := kernel32.NewProc("CreateMutexW")
	h, _, last := create.Call(0, 0, uintptr(unsafe.Pointer(name)))
	singleMutex = syscall.Handle(h)
	if last == syscall.Errno(183) { // ERROR_ALREADY_EXISTS
		log.Printf("[UI] already running, restore window")
		restoreExistingAERO()
		return false
	}
	return true
}

func restoreExistingAERO() {
	user32 := syscall.NewLazyDLL("user32.dll")
	find := user32.NewProc("FindWindowW")
	show := user32.NewProc("ShowWindow")
	fg := user32.NewProc("SetForegroundWindow")
	title, err := syscall.UTF16PtrFromString("AERO")
	if err != nil {
		return
	}
	hwnd, _, _ := find.Call(0, uintptr(unsafe.Pointer(title)))
	if hwnd == 0 {
		nativeAlert("AERO", "AERO 已在运行。请看任务栏托盘，右键「打开窗口」。")
		return
	}
	const swRestore = 9
	show.Call(hwnd, swRestore)
	fg.Call(hwnd)
}

// -----------------------------------------------------------------------------
// Source: aeroapp_wintun_windows.go
// -----------------------------------------------------------------------------
//
//go:embed assets/wintun.dll
var embeddedWintun []byte

func ensureWintun() {
	exe, err := os.Executable()
	if err != nil || len(embeddedWintun) == 0 {
		return
	}
	dst := filepath.Join(filepath.Dir(exe), "wintun.dll")
	if st, err := os.Stat(dst); err == nil && st.Size() > 0 {
		return
	}
	if err := os.WriteFile(dst, embeddedWintun, 0o644); err != nil {
		log.Printf("[TUN] write wintun.dll: %v", err)
		return
	}
	log.Printf("[TUN] wrote wintun.dll next to aeroapp.exe")
}

// -----------------------------------------------------------------------------
// Source: guard_windows.go
// -----------------------------------------------------------------------------
var (
	guardOnce sync.Once
	guardMu   sync.Mutex
	guardPID  int
)

func startCrashGuard() {
	guardOnce.Do(startCrashGuardOnce)
}

func startCrashGuardOnce() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	guard := filepath.Join(filepath.Dir(exe), "aero-guard.exe")
	if _, err := os.Stat(guard); err != nil {
		log.Printf("[GUARD] skip: %s missing", guard)
		return
	}
	cmd := exec.Command(guard, "-pid", strconv.Itoa(os.Getpid()))
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
		CreationFlags: windows.DETACHED_PROCESS |
			windows.CREATE_NEW_PROCESS_GROUP |
			windows.CREATE_NO_WINDOW,
	}
	if err := cmd.Start(); err != nil {
		log.Printf("[GUARD] start: %v", err)
		return
	}
	guardMu.Lock()
	guardPID = cmd.Process.Pid
	guardMu.Unlock()
	log.Printf("[GUARD] aero-guard.exe watching pid=%d (guard pid=%d)", os.Getpid(), cmd.Process.Pid)
	_ = cmd.Process.Release()
}

func stopCrashGuard() {
	guardMu.Lock()
	pid := guardPID
	guardPID = 0
	guardMu.Unlock()
	if pid <= 0 {
		return
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	_ = p.Kill()
	log.Printf("[GUARD] stopped pid=%d", pid)
}

// -----------------------------------------------------------------------------
// Source: hide_windows.go
// -----------------------------------------------------------------------------
func hideConsole(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000,
	}
}

func hideOwnConsole() {
	k := syscall.NewLazyDLL("kernel32.dll")
	u := syscall.NewLazyDLL("user32.dll")
	hwnd, _, _ := k.NewProc("GetConsoleWindow").Call()
	if hwnd != 0 {
		u.NewProc("ShowWindow").Call(hwnd, 0)
	}
	k.NewProc("FreeConsole").Call()
}
