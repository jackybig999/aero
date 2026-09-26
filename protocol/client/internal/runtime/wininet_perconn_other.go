//go:build !windows

package runtime

func applyLANProxy(string, string) error { return nil }
func clearLANProxy()                     {}
