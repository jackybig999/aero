package public

// Platform defines the OS-specific capabilities needed by the core desktop engine.
type Platform interface {
	// DetectSystemProxy returns the system-configured HTTP/SOCKS proxy if enabled.
	DetectSystemProxy() *SystemProxy

	// LaunchCLI launches a CLI tool (e.g., Claude Code, Codex CLI) in a dedicated terminal window.
	LaunchCLI(toolName string, cmd string, args []string, cwd string, env []string) error

	// LaunchBrowser launches a browser with proxy and user-data-dir configured.
	LaunchBrowser(browserName string, cmd string, profileDir string, proxyURL string, cwd string, env []string) error

	// LaunchDesktop launches a desktop application detached.
	LaunchDesktop(cmd string, cwd string, env []string) error

	// ScanBrowsers detects installed browsers (Chrome, Edge, Brave, etc.) on this OS.
	ScanBrowsers() map[string]interface{}

	// FindAeroEngine locates the AERO protocol binary candidate on this OS.
	FindAeroEngine() string

	// ClearProxy clears OS-level proxy settings to prevent network disruption.
	ClearProxy() error

	// KillProcessGroup terminates all tracked external tool processes.
	KillProcessGroup()
}
