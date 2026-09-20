package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/AIsys/connect/desktop/public"
	"github.com/jchv/go-webview2"
)

type WindowsPlatform struct {
	mu        sync.Mutex
	processes []*exec.Cmd
}

func (p *WindowsPlatform) DetectSystemProxy() *public.SystemProxy {
	cmd := exec.Command("reg", "query", `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "/v", "ProxyEnable", "/v", "ProxyServer")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	s := string(out)

	reEnable := regexp.MustCompile(`ProxyEnable\s+REG_DWORD\s+0x([0-9a-fA-F]+)`)
	mEnable := reEnable.FindStringSubmatch(s)
	enabled := false
	if len(mEnable) > 1 {
		val, _ := strconv.ParseInt(mEnable[1], 16, 32)
		enabled = val == 1
	}

	reServer := regexp.MustCompile(`ProxyServer\s+REG_SZ\s+(\S+)`)
	mServer := reServer.FindStringSubmatch(s)
	server := ""
	if len(mServer) > 1 {
		server = mServer[1]
	}

	if !enabled || server == "" {
		return &public.SystemProxy{Enabled: false}
	}

	host := "127.0.0.1"
	port := 0

	if strings.Contains(server, "=") {
		parts := strings.Split(server, ";")
		for _, part := range parts {
			if strings.HasPrefix(strings.ToLower(part), "http=") {
				hp := strings.TrimPrefix(part, "http=")
				if idx := strings.LastIndex(hp, ":"); idx > 0 {
					host = hp[:idx]
					port, _ = strconv.Atoi(hp[idx+1:])
				}
				break
			}
		}
	} else if idx := strings.LastIndex(server, ":"); idx > 0 {
		host = server[:idx]
		port, _ = strconv.Atoi(server[idx+1:])
	}

	if port == 0 {
		return nil
	}

	return &public.SystemProxy{
		Host:    host,
		Port:    port,
		Server:  server,
		Enabled: true,
	}
}

func (p *WindowsPlatform) LaunchCLI(toolName, cmdName string, args []string, cwd string, env []string) error {
	title := strings.ToUpper(toolName[:1]) + toolName[1:] + " CLI"
	cmdArgs := append([]string{"/c", "start", title, "cmd", "/k", "title " + title + " && " + cmdName}, args...)
	cmd := exec.Command("cmd.exe", cmdArgs...)
	cmd.Dir = cwd
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
	if err := cmd.Start(); err != nil {
		return err
	}

	p.mu.Lock()
	p.processes = append(p.processes, cmd)
	p.mu.Unlock()
	return nil
}

func (p *WindowsPlatform) LaunchBrowser(browserName, cmdBin, profileDir, proxyURL, cwd string, env []string) error {
	args := []string{
		"--no-first-run",
		"--no-default-browser-check",
		fmt.Sprintf("--user-data-dir=%s", profileDir),
	}
	if proxyURL != "" {
		args = append(args, fmt.Sprintf("--proxy-server=%s", proxyURL))
	}
	args = append(args, "https://www.google.com")

	cmd := exec.Command(cmdBin, args...)
	cmd.Dir = cwd
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
	if err := cmd.Start(); err != nil {
		return err
	}

	p.mu.Lock()
	p.processes = append(p.processes, cmd)
	p.mu.Unlock()
	return nil
}

func (p *WindowsPlatform) LaunchDesktop(cmdPath string, cwd string, env []string) error {
	cmd := exec.Command(cmdPath)
	cmd.Dir = cwd
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
	if err := cmd.Start(); err != nil {
		return err
	}

	p.mu.Lock()
	p.processes = append(p.processes, cmd)
	p.mu.Unlock()
	return nil
}

func (p *WindowsPlatform) ScanBrowsers() map[string]interface{} {
	results := make(map[string]interface{})
	candidates := map[string][]string{
		"chrome": {
			`C:\Program Files\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
			filepath.Join(os.Getenv("LOCALAPPDATA"), `Google\Chrome\Application\chrome.exe`),
		},
		"edge": {
			`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
			`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
		},
		"brave": {
			`C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe`,
			filepath.Join(os.Getenv("LOCALAPPDATA"), `BraveSoftware\Brave-Browser\Application\brave.exe`),
		},
	}

	for bName, paths := range candidates {
		var foundPath string
		for _, pt := range paths {
			if fi, err := os.Stat(pt); err == nil && !fi.IsDir() {
				foundPath = pt
				break
			}
		}
		if foundPath != "" {
			results[bName] = map[string]interface{}{
				"name":      strings.ToUpper(bName[:1]) + bName[1:],
				"command":   foundPath,
				"installed": true,
			}
		}
	}
	return results
}

func (p *WindowsPlatform) FindAeroEngine() string {
	if envPath := strings.TrimSpace(os.Getenv("AERO_CLIENT_BIN")); envPath != "" {
		if fi, err := os.Stat(envPath); err == nil && !fi.IsDir() {
			return envPath
		}
	}

	var candidates []string
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(exeDir, "aerowin.exe"),
			filepath.Join(exeDir, "..", "..", "protocol", "client", "win", "aerowin.exe"),
			filepath.Join(exeDir, "..", "..", "protocol", "client", "cli", "aerocli.exe"),
			filepath.Join(exeDir, "..", "protocol", "client", "win", "aerowin.exe"),
		)
	}

	cwd, _ := os.Getwd()
	candidates = append(candidates,
		filepath.Join(cwd, "aerowin.exe"),
		filepath.Join(cwd, "..", "..", "protocol", "client", "win", "aerowin.exe"),
		filepath.Join(cwd, "..", "..", "protocol", "client", "cli", "aerocli.exe"),
		filepath.Join(cwd, "protocol", "client", "win", "aerowin.exe"),
		filepath.Join(cwd, "protocol", "client", "cli", "aerocli.exe"),
	)

	for _, pt := range candidates {
		if fi, err := os.Stat(pt); err == nil && !fi.IsDir() {
			return pt
		}
	}
	if len(candidates) > 0 {
		return candidates[0]
	}
	return "aerowin.exe"
}

func (p *WindowsPlatform) ClearProxy() error {
	ie := `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	_ = exec.Command("reg", "add", ie, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f").Run()
	_ = exec.Command("reg", "delete", ie, "/v", "ProxyServer", "/f").Run()
	_ = exec.Command("reg", "delete", ie, "/v", "AutoConfigURL", "/f").Run()
	_ = exec.Command("netsh", "winhttp", "reset", "proxy").Run()
	return nil
}

func (p *WindowsPlatform) KillProcessGroup() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, cmd := range p.processes {
		if cmd != nil && cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}
	p.processes = nil
	_ = exec.Command("taskkill", "/F", "/IM", "claude.exe").Run()
	_ = exec.Command("taskkill", "/F", "/IM", "codex.exe").Run()
}

func main() {
	portFlag := flag.Int("port", 0, "HTTP port (0 for random)")
	serverOnly := flag.Bool("server-only", false, "Run server only without WebView GUI")
	cliMode := flag.Bool("cli", false, "Run in interactive terminal CLI mode")
	flag.Parse()

	if *cliMode {
		public.RunCLIMenu()
		return
	}

	cwd, _ := os.Getwd()
	configDir := filepath.Join(cwd, "..", "config")
	if _, err := os.Stat(configDir); err != nil {
		configDir = "config"
	}

	winPlatform := &WindowsPlatform{}
	listener, url, err := public.StartServer(winPlatform, configDir, *portFlag)
	if err != nil {
		log.Fatalf("[ARM-DESKTOP-WIN] Failed to start server: %v", err)
	}
	defer listener.Close()

	log.Printf("[ARM-DESKTOP-WIN] Server running at %s", url)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("[ARM-DESKTOP-WIN] Shutting down...")
		winPlatform.KillProcessGroup()
		_ = winPlatform.ClearProxy()
		os.Exit(0)
	}()

	if *serverOnly {
		log.Println("[ARM-DESKTOP-WIN] Server-only mode. Press Ctrl+C to exit.")
		select {}
	}

	// Launch WebView2 Window on Windows
	dataDir := filepath.Join(os.TempDir(), "arm-desktop-wv-"+strconv.Itoa(os.Getpid()))
	_ = os.MkdirAll(dataDir, 0o700)
	defer os.RemoveAll(dataDir)

	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     false,
		AutoFocus: true,
		DataPath:  dataDir,
		WindowOptions: webview2.WindowOptions{
			Title:  "AI Runtime Manager",
			Width:  960,
			Height: 720,
			Center: true,
		},
	})
	if w == nil {
		log.Printf("[ARM-DESKTOP-WIN] WebView2 not available, fallback to browser at %s", url)
		_ = exec.Command("cmd.exe", "/c", "start", url).Start()
		select {}
	}
	defer w.Destroy()

	w.SetSize(960, 720, webview2.HintNone)
	w.Navigate(url)
	w.Run()

	winPlatform.KillProcessGroup()
}
