//go:build !windows

package runtime

// LastBrowserLockHint is set by ApplyBrowserLock for the GUI.
var LastBrowserLockHint string

func (w *windowsRuntime) snapshotUserEnvOnce()         {}
func (w *windowsRuntime) setUserProxyEnv(mixed string) {}
func (w *windowsRuntime) clearUserProxyEnv()           {}

func notifyWinINet()                  {}
func setBrowserQUICBlock(enable bool) {}

// ApplyBrowserLock stub on non-Windows platforms
func ApplyBrowserLock(blockUDP443 bool) string {
	return ""
}

// ApplyBrowserLockOn stub on non-Windows platforms
func ApplyBrowserLockOn(blockUDP443 bool, mixed string) string {
	return ""
}

// WipeAEROFirewall stub on non-Windows platforms
func WipeAEROFirewall() {}

// ApplySocksPrivacy stub on non-Windows platforms
func ApplySocksPrivacy() {}
