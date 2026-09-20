package public

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	aeroAPIHost = "127.0.0.1"
	aeroAPIPort = 19877
)

type AeroController struct {
	mu       sync.Mutex
	echProc  *exec.Cmd
	platform Platform
}

var aeroCtrl = &AeroController{}

func SetPlatform(p Platform) {
	aeroCtrl.mu.Lock()
	defer aeroCtrl.mu.Unlock()
	aeroCtrl.platform = p
}

func readLastSub() string {
	cwd, _ := os.Getwd()
	candidates := []string{
		filepath.Join(cwd, "..", "..", "protocol", "client", ".last-sub-url"),
		filepath.Join(cwd, "..", "..", "protocol", "client", "dist", ".last-sub-url"),
		filepath.Join(cwd, "..", "..", "protocol", "client", "win", ".last-sub-url"),
		`D:\jacky\gemini\aisys\protocol\client\.last-sub-url`,
		`D:\jacky\gemini\aisys\protocol\client\win\.last-sub-url`,
	}
	for _, p := range candidates {
		abs, err := filepath.Abs(p)
		if err == nil {
			if data, err := os.ReadFile(abs); err == nil {
				s := strings.TrimSpace(string(data))
				if strings.HasPrefix(strings.ToLower(s), "http") {
					return s
				}
			}
		}
	}
	return ""
}

func readCtrlToken() string {
	home, err := os.UserHomeDir()
	if err == nil {
		if data, err := os.ReadFile(filepath.Join(home, ".aero", "ctrl.token")); err == nil {
			return strings.TrimSpace(string(data))
		}
	}
	if data, err := os.ReadFile("ctrl.token"); err == nil {
		return strings.TrimSpace(string(data))
	}
	return ""
}

func aeroRequest(method, path string, body interface{}) (map[string]interface{}, error) {
	url := fmt.Sprintf("http://%s:%d%s", aeroAPIHost, aeroAPIPort, path)
	var bodyReader io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if tok := readCtrlToken(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var res map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&res)
	return res, err
}

func waitAeroHealth(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := aeroRequest("GET", "/api/v1/health", nil); err == nil {
			return nil
		}
		time.Sleep(350 * time.Millisecond)
	}
	return fmt.Errorf("engine health check timeout")
}

func (c *AeroController) Status() map[string]interface{} {
	c.mu.Lock()
	defer c.mu.Unlock()

	echBin := ""
	if c.platform != nil {
		echBin = c.platform.FindAeroEngine()
	}
	_, statErr := os.Stat(echBin)
	exeExists := statErr == nil

	st, err := aeroRequest("GET", "/api/v1/status", nil)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"running": false,
			"error":   err.Error(),
			"exe":     exeExists,
			"exePath": echBin,
		}
	}
	return map[string]interface{}{
		"success": true,
		"running": true,
		"status":  st,
		"exe":     exeExists,
		"exePath": echBin,
	}
}

func (c *AeroController) Start(subURL string) map[string]interface{} {
	c.mu.Lock()
	defer c.mu.Unlock()

	if subURL == "" {
		subURL = readLastSub()
	}
	if subURL == "" {
		return map[string]interface{}{
			"success": false,
			"error":   "缺少订阅地址，请传入订阅链接或通过客户端连接一次",
		}
	}

	echBin := ""
	if c.platform != nil {
		echBin = c.platform.FindAeroEngine()
	}
	if _, err := os.Stat(echBin); err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   "找不到 aero-ech 引擎: " + echBin,
		}
	}

	if _, err := aeroRequest("GET", "/api/v1/health", nil); err != nil {
		c.stopLocked()

		cmd := exec.Command(echBin, "-sub", subURL, "-listen", "127.0.0.1:55555", "-fingerprint", "std")
		cmd.Dir = filepath.Dir(echBin)
		if err := cmd.Start(); err != nil {
			return map[string]interface{}{
				"success": false,
				"error":   "启动失败: " + err.Error(),
			}
		}
		c.echProc = cmd

		if err := waitAeroHealth(25 * time.Second); err != nil {
			c.stopLocked()
			return map[string]interface{}{
				"success": false,
				"error":   err.Error(),
			}
		}
	}

	if _, err := aeroRequest("POST", "/api/v1/mode", map[string]string{"mode": "tun"}); err != nil {
		_, _ = aeroRequest("POST", "/api/v1/mode", map[string]string{"mode": "sysproxy"})
	}

	res, err := aeroRequest("POST", "/api/v1/connect", nil)
	st, _ := aeroRequest("GET", "/api/v1/status", nil)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		}
	}

	return map[string]interface{}{
		"success": true,
		"result":  res,
		"status":  st,
	}
}

func (c *AeroController) Stop() map[string]interface{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopLocked()
	return map[string]interface{}{"success": true}
}

func (c *AeroController) stopLocked() {
	_, _ = aeroRequest("POST", "/api/v1/disconnect", nil)
	if c.echProc != nil && c.echProc.Process != nil {
		_ = c.echProc.Process.Kill()
		c.echProc = nil
	}
	if c.platform != nil {
		_ = c.platform.ClearProxy()
	}
}
