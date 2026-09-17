//go:build !windows && !(darwin && cgo)

package public

import (
	"fmt"
	"os/exec"
	"runtime"
)

// -----------------------------------------------------------------------------
// Source: aeroapp_tray_other.go
// -----------------------------------------------------------------------------
func runAppShell(uiURL string) error {
	return runNativeWindow(uiURL)
}

// -----------------------------------------------------------------------------
// Source: aeroapp_open.go
// -----------------------------------------------------------------------------
func openSystemBrowser(uiURL string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", uiURL)
	default:
		cmd = exec.Command("xdg-open", uiURL)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("open UI: %w", err)
	}
	select {}
}

// -----------------------------------------------------------------------------
// Source: aeroapp_webview_other.go
// -----------------------------------------------------------------------------
func runNativeWindow(uiURL string) error {
	return openSystemBrowser(uiURL)
}

func nativeAlert(title, body string) {}

func restoreNativeWindow() bool { return false }

func terminateNativeWindow() {}

// -----------------------------------------------------------------------------
// Source: aeroapp_single_other.go
// -----------------------------------------------------------------------------
func ensureSingleInstance() bool { return true }

func restoreExistingAERO() {}

// -----------------------------------------------------------------------------
// Source: aeroapp_tray_click_other.go
// -----------------------------------------------------------------------------
func hookTrayLeftClick(func()) {}

// -----------------------------------------------------------------------------
// Source: aeroapp_wintun_stub.go
// -----------------------------------------------------------------------------
func ensureWintun() {}

// -----------------------------------------------------------------------------
// Source: guard_stub.go
// -----------------------------------------------------------------------------
func startCrashGuard() {}

func stopCrashGuard() {}

// -----------------------------------------------------------------------------
// Source: hide_other.go
// -----------------------------------------------------------------------------
func hideConsole(cmd *exec.Cmd) {}

func hideOwnConsole() {}
