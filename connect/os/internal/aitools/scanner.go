package aitools

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

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

		// Fallback to system PATH lookup
		targetBin := key
		if key == "vscode" {
			targetBin = "code"
		}
		if lp, err := exec.LookPath(targetBin); err == nil {
			return lp, true
		}
	} else {
		// macOS candidates
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
