package desk

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

type ToolInfo struct {
	Key        string `json:"key"`
	Name       string `json:"name"`
	Icon       string `json:"icon"`
	Installed  bool   `json:"installed"`
	Path       string `json:"path"`
	Version    string `json:"version,omitempty"`
	CWD        string `json:"cwd"`
	Type       string `json:"type"` // "desktop" | "cli"
	DefaultCmd string `json:"default_cmd"`
}

type ToolStore struct {
	filePath string
	cwds     map[string]string
	mu       sync.RWMutex
}

func NewToolStore(dataDir string) *ToolStore {
	fp := filepath.Join(dataDir, "aitools.json")
	s := &ToolStore{
		filePath: fp,
		cwds:     make(map[string]string),
	}
	s.load()
	return s
}

func (s *ToolStore) SetCWD(key, cwd string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cwds[key] = cwd
	s.save()
}

func (s *ToolStore) GetCWD(key string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if c, ok := s.cwds[key]; ok && c != "" {
		return c
	}
	home, err := os.UserHomeDir()
	if err == nil {
		return home
	}
	cwd, _ := os.Getwd()
	return cwd
}

func (s *ToolStore) load() {
	b, err := os.ReadFile(s.filePath)
	if err == nil {
		_ = json.Unmarshal(b, &s.cwds)
	}
}

func (s *ToolStore) save() {
	b, err := json.MarshalIndent(s.cwds, "", "  ")
	if err == nil {
		_ = os.MkdirAll(filepath.Dir(s.filePath), 0755)
		_ = os.WriteFile(s.filePath, b, 0644)
	}
}

type Executor struct {
	scanner *Scanner
	proxy   string // e.g. "127.0.0.1:55555"
}

func NewExecutor(scanner *Scanner, proxyAddr string) *Executor {
	if proxyAddr == "" {
		proxyAddr = "127.0.0.1:55555"
	}
	return &Executor{
		scanner: scanner,
		proxy:   proxyAddr,
	}
}

func (e *Executor) BuildProxyEnv() []string {
	env := os.Environ()
	filtered := make([]string, 0, len(env)+8)

	for _, kv := range env {
		upper := strings.ToUpper(kv)
		if strings.HasPrefix(upper, "HTTP_PROXY=") ||
			strings.HasPrefix(upper, "HTTPS_PROXY=") ||
			strings.HasPrefix(upper, "ALL_PROXY=") ||
			strings.HasPrefix(upper, "NO_PROXY=") {
			continue
		}
		filtered = append(filtered, kv)
	}

	httpProxy := fmt.Sprintf("http://%s", e.proxy)
	socksProxy := fmt.Sprintf("socks5://%s", e.proxy)

	filtered = append(filtered,
		"HTTP_PROXY="+httpProxy,
		"http_proxy="+httpProxy,
		"HTTPS_PROXY="+httpProxy,
		"https_proxy="+httpProxy,
		"ALL_PROXY="+socksProxy,
		"all_proxy="+socksProxy,
		"NO_PROXY=localhost,127.0.0.1,::1",
		"no_proxy=localhost,127.0.0.1,::1",
	)

	return filtered
}

func (e *Executor) Launch(toolKey, cwdOverride string) (string, error) {
	path, installed := e.scanner.findExecutable(toolKey)
	if !installed || path == "" {
		return "", fmt.Errorf("未检测到 %s 安装路径，请先安装该工具", toolKey)
	}

	cwd := cwdOverride
	if cwd == "" {
		cwd = e.scanner.store.GetCWD(toolKey)
	}
	if fi, err := os.Stat(cwd); err != nil || !fi.IsDir() {
		cwd, _ = os.Getwd()
	}

	env := e.BuildProxyEnv()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		if toolKey == "claude" || toolKey == "terminal" {
			title := strings.ToUpper(toolKey[:1]) + toolKey[1:] + " [AERO OS Proxy: 55555]"
			args := []string{"/c", "start", title, "cmd", "/k", "title " + title}
			if toolKey == "claude" {
				args = append(args, "&&", path)
			}
			cmd = exec.Command("cmd.exe", args...)
			setSysProcAttr(cmd)
		} else {
			cmd = exec.Command(path)
			setSysProcAttr(cmd)
		}
	} else {
		if toolKey == "claude" || toolKey == "terminal" {
			cmd = exec.Command("open", "-a", "Terminal", cwd)
		} else {
			cmd = exec.Command("open", "-a", path)
		}
	}

	cmd.Dir = cwd
	cmd.Env = env

	if err := cmd.Start(); err != nil {
		GlobalLogger.Log("ERROR", "AITOOLS", fmt.Sprintf("启动 %s 失败: %v", toolKey, err))
		return "", fmt.Errorf("启动失败: %w", err)
	}

	msg := fmt.Sprintf("已成功启动 %s (已自动注入高速代理 %s, 工作目录: %s)", toolKey, e.proxy, cwd)
	GlobalLogger.Log("INFO", "AITOOLS", msg)
	return msg, nil
}

type Scanner struct {
	store *ToolStore
}

func NewScanner(store *ToolStore) *Scanner {
	return &Scanner{store: store}
}

// ScanAll returns list of detected tools with active CWD
func (s *Scanner) ScanAll() []ToolInfo {
	tools := []ToolInfo{
		{
			Key:        "claude",
			Name:       "Claude Code",
			Icon:       "🤖",
			Type:       "cli",
			DefaultCmd: "claude",
		},
		{
			Key:        "cursor",
			Name:       "Cursor",
			Icon:       "⚡",
			Type:       "desktop",
			DefaultCmd: "cursor",
		},
		{
			Key:        "windsurf",
			Name:       "Windsurf",
			Icon:       "🏄",
			Type:       "desktop",
			DefaultCmd: "windsurf",
		},
		{
			Key:        "vscode",
			Name:       "VS Code",
			Icon:       "💻",
			Type:       "desktop",
			DefaultCmd: "code",
		},
		{
			Key:        "terminal",
			Name:       "系统终端 (代理已注入)",
			Icon:       "📟",
			Type:       "cli",
			DefaultCmd: "cmd.exe",
		},
	}

	for i := range tools {
		tools[i].CWD = s.store.GetCWD(tools[i].Key)
		path, installed := s.findExecutable(tools[i].Key)
		tools[i].Installed = installed
		tools[i].Path = path
	}

	return tools
}

func (s *Scanner) findExecutable(key string) (string, bool) {
	if runtime.GOOS == "windows" {
		localApp := os.Getenv("LOCALAPPDATA")
		progFiles := os.Getenv("ProgramFiles")
		userProfile := os.Getenv("USERPROFILE")

		candidates := map[string][]string{
			"claude": {
				filepath.Join(os.Getenv("APPDATA"), "npm", "claude.cmd"),
				filepath.Join(userProfile, ".npm-global", "claude.cmd"),
				filepath.Join(userProfile, "AppData", "Roaming", "npm", "claude.cmd"),
			},
			"cursor": {
				filepath.Join(localApp, "Programs", "cursor", "Cursor.exe"),
				filepath.Join(progFiles, "Cursor", "Cursor.exe"),
			},
			"windsurf": {
				filepath.Join(localApp, "Programs", "Windsurf", "Windsurf.exe"),
				filepath.Join(progFiles, "Windsurf", "Windsurf.exe"),
			},
			"vscode": {
				filepath.Join(localApp, "Programs", "Microsoft VS Code", "Code.exe"),
				filepath.Join(progFiles, "Microsoft VS Code", "Code.exe"),
			},
			"terminal": {
				"cmd.exe",
				"powershell.exe",
			},
		}

		for _, p := range candidates[key] {
			if strings.EqualFold(p, "cmd.exe") || strings.EqualFold(p, "powershell.exe") {
				return p, true
			}
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				return p, true
			}
		}

		targetBin := key
		if key == "vscode" {
			targetBin = "code"
		}
		if lp, err := exec.LookPath(targetBin); err == nil {
			return lp, true
		}
	} else {
		macCandidates := map[string][]string{
			"claude": {
				"/usr/local/bin/claude",
				"/opt/homebrew/bin/claude",
			},
			"cursor": {
				"/Applications/Cursor.app/Contents/MacOS/Cursor",
			},
			"windsurf": {
				"/Applications/Windsurf.app/Contents/MacOS/Windsurf",
			},
			"vscode": {
				"/Applications/Visual Studio Code.app/Contents/MacOS/Electron",
			},
			"terminal": {
				"/bin/zsh",
				"/bin/bash",
			},
		}

		for _, p := range macCandidates[key] {
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				return p, true
			}
		}

		targetBin := key
		if key == "vscode" {
			targetBin = "code"
		}
		if lp, err := exec.LookPath(targetBin); err == nil {
			return lp, true
		}
	}

	return "", false
}
