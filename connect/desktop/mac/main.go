package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/AIsys/connect/desktop/public"
)

type DarwinPlatform struct {
	mu        sync.Mutex
	processes []*exec.Cmd
}

func (p *DarwinPlatform) DetectSystemProxy() *public.SystemProxy {
	cmd := exec.Command("scutil", "--proxy")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	props := make(map[string]string)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if idx := strings.Index(line, ":"); idx > 0 {
			k := strings.TrimSpace(line[:idx])
			v := strings.TrimSpace(line[idx+1:])
			props[k] = v
		}
	}

	enabled := props["HTTPEnable"] == "1"
	host := props["HTTPProxy"]
	portStr := props["HTTPPort"]

	if !enabled && props["SOCKSEnable"] == "1" {
		enabled = true
		host = props["SOCKSProxy"]
		portStr = props["SOCKSPort"]
	}

	if !enabled || host == "" || portStr == "" {
		return &public.SystemProxy{Enabled: false}
	}

	port, _ := strconv.Atoi(portStr)
	return &public.SystemProxy{
		Host:    host,
		Port:    port,
		Server:  fmt.Sprintf("%s:%d", host, port),
		Enabled: true,
	}
}

func (p *DarwinPlatform) LaunchCLI(toolName, cmdName string, args []string, cwd string, env []string) error {
	title := strings.ToUpper(toolName[:1]) + toolName[1:] + " CLI"

	var proxyExport string
	for _, e := range env {
		if strings.HasPrefix(e, "HTTP_PROXY=") || strings.HasPrefix(e, "HTTPS_PROXY=") || strings.HasPrefix(e, "ALL_PROXY=") {
			proxyExport += "export " + e + "; "
		}
	}

	script := fmt.Sprintf(`tell application "Terminal" to do script "cd '%s' && %s%s"`, cwd, proxyExport, cmdName)
	cmd := exec.Command("osascript", "-e", script)
	if err := cmd.Run(); err != nil {
		// Fallback to direct execution
		dCmd := exec.Command(cmdName, args...)
		dCmd.Dir = cwd
		dCmd.Env = env
		if err := dCmd.Start(); err != nil {
			return err
		}
		p.mu.Lock()
		p.processes = append(p.processes, dCmd)
		p.mu.Unlock()
	}
	_ = title
	return nil
}

func (p *DarwinPlatform) LaunchBrowser(browserName, cmdBin, profileDir, proxyURL, cwd string, env []string) error {
	bApp := "Google Chrome"
	if strings.Contains(strings.ToLower(browserName), "edge") {
		bApp = "Microsoft Edge"
	} else if strings.Contains(strings.ToLower(browserName), "brave") {
		bApp = "Brave Browser"
	}

	args := []string{"-na", bApp, "--args", "--no-first-run", "--no-default-browser-check", fmt.Sprintf("--user-data-dir=%s", profileDir)}
	if proxyURL != "" {
		args = append(args, fmt.Sprintf("--proxy-server=%s", proxyURL))
	}
	args = append(args, "https://www.google.com")

	cmd := exec.Command("open", args...)
	cmd.Dir = cwd
	cmd.Env = env
	return cmd.Start()
}

func (p *DarwinPlatform) LaunchDesktop(cmdPath string, cwd string, env []string) error {
	cmd := exec.Command("open", "-a", cmdPath)
	cmd.Dir = cwd
	cmd.Env = env
	return cmd.Start()
}

func (p *DarwinPlatform) ScanBrowsers() map[string]interface{} {
	results := make(map[string]interface{})
	macBrowsers := map[string]string{
		"chrome": "/Applications/Google Chrome.app",
		"edge":   "/Applications/Microsoft Edge.app",
		"brave":  "/Applications/Brave Browser.app",
	}

	for bName, appPath := range macBrowsers {
		if fi, err := os.Stat(appPath); err == nil && fi.IsDir() {
			results[bName] = map[string]interface{}{
				"name":      strings.ToUpper(bName[:1]) + bName[1:],
				"command":   appPath,
				"installed": true,
			}
		}
	}
	return results
}

func (p *DarwinPlatform) FindAeroEngine() string {
	cwd, _ := os.Getwd()
	candidates := []string{
		filepath.Join(cwd, "..", "..", "protocol", "client", "mac", "aeromac"),
		filepath.Join(cwd, "..", "..", "protocol", "client", "cli", "aerocli"),
		filepath.Join(cwd, "..", "..", "protocol", "client", "dist", "aero-edge-darwin"),
		filepath.Join(cwd, "..", "..", "protocol", "client", "mac", "aero-ech"),
		filepath.Join(cwd, "..", "..", "protocol", "client", "aero-ech", "aero-ech"),
		"/usr/local/bin/aeromac",
		"/usr/local/bin/aerocli",
		"/usr/local/bin/aero-ech",
	}
	for _, pt := range candidates {
		if fi, err := os.Stat(pt); err == nil && !fi.IsDir() {
			return pt
		}
	}
	return candidates[0]
}

func (p *DarwinPlatform) ClearProxy() error {
	_ = exec.Command("networksetup", "-setwebproxystate", "Wi-Fi", "off").Run()
	_ = exec.Command("networksetup", "-setsecurewebproxystate", "Wi-Fi", "off").Run()
	_ = exec.Command("networksetup", "-setsocksfirewallproxystate", "Wi-Fi", "off").Run()
	return nil
}

func (p *DarwinPlatform) KillProcessGroup() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, cmd := range p.processes {
		if cmd != nil && cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}
	p.processes = nil
	_ = exec.Command("pkill", "-f", "claude").Run()
	_ = exec.Command("pkill", "-f", "codex").Run()
}

func main() {
	portFlag := flag.Int("port", 0, "HTTP port (0 for random)")
	serverOnly := flag.Bool("server-only", false, "Run server only without opening browser UI")
	flag.Parse()

	cwd, _ := os.Getwd()
	configDir := filepath.Join(cwd, "..", "config")
	if _, err := os.Stat(configDir); err != nil {
		configDir = "config"
	}

	darwinPlatform := &DarwinPlatform{}
	listener, url, err := public.StartServer(darwinPlatform, configDir, *portFlag)
	if err != nil {
		log.Fatalf("[ARM-DESKTOP-MAC] Failed to start server: %v", err)
	}
	defer listener.Close()

	log.Printf("[ARM-DESKTOP-MAC] Server running at %s", url)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("[ARM-DESKTOP-MAC] Shutting down...")
		darwinPlatform.KillProcessGroup()
		_ = darwinPlatform.ClearProxy()
		os.Exit(0)
	}()

	if !*serverOnly {
		_ = exec.Command("open", url).Start()
	}

	log.Println("[ARM-DESKTOP-MAC] Running. Press Ctrl+C to stop.")
	select {}
}
