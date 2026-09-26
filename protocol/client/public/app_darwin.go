//go:build darwin && cgo

package public

import (
	webview "github.com/webview/webview_go"
	"log"
)

// -----------------------------------------------------------------------------
// Source: aeroapp_webview_darwin.go
// -----------------------------------------------------------------------------
func runNativeWindow(uiURL string) error {
	w := webview.New(false)
	if w == nil {
		return openSystemBrowser(uiURL)
	}
	defer w.Destroy()
	w.SetTitle("AERO")
	w.SetSize(420, 780, webview.HintNone)
	w.Navigate(uiURL)
	w.Run()
	return nil
}

func nativeAlert(title, body string) {
	log.Printf("[UI] %s: %s", title, body)
}

func restoreNativeWindow() bool { return false }

func terminateNativeWindow() {}

func runAppShell(uiURL string) error {
	return runNativeWindow(uiURL)
}

func ensureSingleInstance() bool { return true }
func restoreExistingAERO()       {}
func hookTrayWindowClick()       {}
func ensureWintunDLL() error     { return nil }
func startCrashGuard()           {}
func stopCrashGuard()            {}
func hideOwnConsole()            {}
