// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

var (
	ErrInstallInProgress = errors.New("installation already in progress")
)

// WarpLogEntry represents a timestamped log entry from the WARP installation pipeline.
type WarpLogEntry struct {
	Timestamp string `json:"time"`
	Level     string `json:"level"` // "info", "warn", "error", "success"
	Message   string `json:"msg"`
}

// WarpInstallStatus reports the real-time progress and logs of WARP installation.
type WarpInstallStatus struct {
	Status    string         `json:"status"`   // "idle", "running", "success", "failed", "already_active"
	Progress  int            `json:"progress"` // 0 to 100
	Step      string         `json:"step"`     // "detect", "repo", "apt", "config", "ufw", "verify", "complete"
	StepDesc  string         `json:"step_desc"`
	Bypassed  bool           `json:"bypassed"`
	Error     string         `json:"error,omitempty"`
	Logs      []WarpLogEntry `json:"logs"`
	StartTime *time.Time     `json:"start_time,omitempty"`
	EndTime   *time.Time     `json:"end_time,omitempty"`
}

// WarpInstaller coordinates Cloudflare WARP silent installation and bypass protection.
type WarpInstaller struct {
	mu        sync.RWMutex
	status    WarpInstallStatus
	maxLogs   int
	dialGuard *DialGuard

	// Overridable hooks for unit testing
	execCmd         func(ctx context.Context, name string, args ...string) ([]byte, error)
	checkPortActive func(addr string) bool
	checkWarpTrace  func(addr string) bool
	checkWarpCli    func() bool
	checkIsRoot     func() bool
}

// NewWarpInstaller creates a new Cloudflare WARP installer.
func NewWarpInstaller(dialGuard *DialGuard) *WarpInstaller {
	wi := &WarpInstaller{
		maxLogs:   500,
		dialGuard: dialGuard,
		status: WarpInstallStatus{
			Status:   "idle",
			Progress: 0,
			Step:     "idle",
			StepDesc: "就绪",
			Logs:     make([]WarpLogEntry, 0, 64),
		},
	}

	wi.execCmd = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		return cmd.CombinedOutput()
	}

	wi.checkPortActive = func(addr string) bool {
		c, err := net.DialTimeout("tcp", addr, 400*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return true
		}
		return false
	}

	wi.checkWarpTrace = func(addr string) bool {
		transport := &http.Transport{
			DialContext: func(ctx context.Context, network, targetAddr string) (net.Conn, error) {
				return dialViaSOCKS5(addr, targetAddr, 3*time.Second)
			},
			TLSHandshakeTimeout: 3 * time.Second,
		}
		client := &http.Client{
			Transport: transport,
			Timeout:   4 * time.Second,
		}
		req, err := http.NewRequest(http.MethodGet, "https://cloudflare.com/cdn-cgi/trace", nil)
		if err != nil {
			return false
		}
		resp, err := client.Do(req)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
		return bytes.Contains(body, []byte("warp=on")) || bytes.Contains(body, []byte("warp=plus"))
	}

	wi.checkWarpCli = func() bool {
		_, err := exec.LookPath("warp-cli")
		return err == nil
	}

	wi.checkIsRoot = func() bool {
		return os.Geteuid() == 0
	}

	return wi
}

// SetHooks sets mock functions for testing.
func (wi *WarpInstaller) SetHooks(
	execCmd func(ctx context.Context, name string, args ...string) ([]byte, error),
	checkPort func(addr string) bool,
	checkTrace func(addr string) bool,
	checkCli func() bool,
	checkRoot func() bool,
) {
	wi.mu.Lock()
	defer wi.mu.Unlock()
	if execCmd != nil {
		wi.execCmd = execCmd
	}
	if checkPort != nil {
		wi.checkPortActive = checkPort
	}
	if checkTrace != nil {
		wi.checkWarpTrace = checkTrace
	}
	if checkCli != nil {
		wi.checkWarpCli = checkCli
	}
	if checkRoot != nil {
		wi.checkIsRoot = checkRoot
	}
}

// GetStatus returns a snapshot of current installation status.
func (wi *WarpInstaller) GetStatus() WarpInstallStatus {
	wi.mu.RLock()
	defer wi.mu.RUnlock()
	st := wi.status
	logsCopy := make([]WarpLogEntry, len(st.Logs))
	copy(logsCopy, st.Logs)
	st.Logs = logsCopy
	return st
}

// IsInstalled checks if warp-cli is present or warp is bypassed/active
func (wi *WarpInstaller) IsInstalled() bool {
	if wi == nil {
		return false
	}
	wi.mu.RLock()
	checkCli := wi.checkWarpCli
	bypassed := wi.status.Bypassed
	wi.mu.RUnlock()
	if bypassed {
		return true
	}
	if checkCli != nil {
		return checkCli()
	}
	_, err := exec.LookPath("warp-cli")
	return err == nil
}

func (wi *WarpInstaller) appendLogLocked(level, msg string) {
	entry := WarpLogEntry{
		Timestamp: time.Now().UTC().Format("15:04:05"),
		Level:     level,
		Message:   msg,
	}
	wi.status.Logs = append(wi.status.Logs, entry)
	if len(wi.status.Logs) > wi.maxLogs {
		wi.status.Logs = wi.status.Logs[len(wi.status.Logs)-wi.maxLogs:]
	}
}

func (wi *WarpInstaller) appendLog(level, msg string) {
	wi.mu.Lock()
	defer wi.mu.Unlock()
	wi.appendLogLocked(level, msg)
}

// StartInstall initiates the WARP installation or triggers bypass protection.
func (wi *WarpInstaller) StartInstall(ctx context.Context) (status string, bypassed bool, err error) {
	wi.mu.Lock()
	if wi.status.Status == "running" {
		wi.mu.Unlock()
		return "running", false, ErrInstallInProgress
	}

	// 1. Check Bypass Protection: If port 40000 is already active and trace has warp=on
	if wi.checkPortActive("127.0.0.1:40000") && wi.checkWarpTrace("127.0.0.1:40000") {
		now := time.Now()
		wi.status.Status = "already_active"
		wi.status.Progress = 100
		wi.status.Step = "complete"
		wi.status.StepDesc = "旁路保护生效：WARP 已在 127.0.0.1:40000 活跃运行"
		wi.status.Bypassed = true
		wi.status.EndTime = &now
		wi.appendLogLocked("info", "[WARP-BYPASS] 检测到 127.0.0.1:40000 已存在活跃 WARP SOCKS5 代理且 trace 正常，触发旁路保护，跳过安装以保留现有配置。")
		if wi.dialGuard != nil {
			wi.dialGuard.SetWarpProxy("127.0.0.1:40000", false)
		}
		wi.mu.Unlock()
		return "already_active", true, nil
	}

	now := time.Now()
	wi.status = WarpInstallStatus{
		Status:    "running",
		Progress:  5,
		Step:      "detect",
		StepDesc:  "正在检测宿主操作系统环境与权限...",
		Bypassed:  false,
		Logs:      make([]WarpLogEntry, 0, 64),
		StartTime: &now,
	}
	wi.appendLogLocked("info", "启动 Cloudflare 官方 WARP 一键静默安装流水线...")
	wi.mu.Unlock()

	// Launch background installation pipeline
	go wi.runPipeline()

	return "running", false, nil
}

func (wi *WarpInstaller) runPipeline() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	fail := func(step string, err error) {
		wi.mu.Lock()
		defer wi.mu.Unlock()
		now := time.Now()
		wi.status.Status = "failed"
		wi.status.Step = step
		wi.status.Error = err.Error()
		wi.status.EndTime = &now
		wi.appendLogLocked("error", fmt.Sprintf("流水线失败 [%s]: %v", step, err))
	}

	// Step 1: Detect OS & codename
	wi.setStep("detect", "正在检测系统环境...", 15)
	codename, osName, err := detectLinuxCodename()
	if err != nil {
		wi.appendLog("warn", fmt.Sprintf("无法精确识别 Debian/Ubuntu 版本 (%v)，默认使用 jammy", err))
		codename = "jammy"
		osName = "linux"
	}
	wi.appendLog("info", fmt.Sprintf("检测到系统环境: %s (%s)", osName, codename))

	if !wi.checkIsRoot() {
		wi.appendLog("warn", "当前进程非 root 权限，APT 安装可能因权限不足失败")
	}

	// Step 2: Add official Cloudflare APT repository
	wi.setStep("repo", "正在注入 Cloudflare 官方 APT 签名与软件源...", 35)
	if err := wi.injectCloudflareRepo(ctx, codename); err != nil {
		fail("repo", fmt.Errorf("注入 Cloudflare APT 软件源失败: %w", err))
		return
	}
	wi.appendLog("info", "Cloudflare 官方 APT 源注入完成")

	// Step 3: apt-get install cloudflare-warp
	wi.setStep("apt", "正在通过 APT 安装 cloudflare-warp 官方软件包...", 60)
	if err := wi.installPackage(ctx); err != nil {
		fail("apt", fmt.Errorf("安装 cloudflare-warp 软件包失败: %w", err))
		return
	}
	wi.appendLog("info", "cloudflare-warp 软件包安装完成")

	// Step 4: Configure SOCKS5 mode and port 40000
	wi.setStep("config", "正在配置 WARP 代理模式并绑定 127.0.0.1:40000...", 80)
	if err := wi.configureWarpProxy(ctx); err != nil {
		fail("config", fmt.Errorf("配置 WARP SOCKS5 代理模式失败: %w", err))
		return
	}
	wi.appendLog("info", "WARP SOCKS5 模式配置完成 (127.0.0.1:40000)")

	// Step 5: Firewall & Local UFW Rules
	wi.setStep("ufw", "正在配置本地防火墙放行规则...", 90)
	wi.configureFirewall(ctx)

	// Step 6: Verify connection
	wi.setStep("verify", "正在验证 127.0.0.1:40000 SOCKS5 代理可用性...", 95)
	if !wi.checkPortActive("127.0.0.1:40000") {
		// Small grace wait
		time.Sleep(1 * time.Second)
	}
	if !wi.checkPortActive("127.0.0.1:40000") {
		fail("verify", errors.New("WARP 服务启动后 127.0.0.1:40000 端口未处于监听状态"))
		return
	}

	if wi.dialGuard != nil {
		wi.dialGuard.SetWarpProxy("127.0.0.1:40000", false)
	}

	wi.mu.Lock()
	now := time.Now()
	wi.status.Status = "success"
	wi.status.Progress = 100
	wi.status.Step = "complete"
	wi.status.StepDesc = "WARP 安装配置成功，已接管 AI 出口流量！"
	wi.status.EndTime = &now
	wi.appendLogLocked("success", "WARP 官方静默安装与配置全部完成！AI & Google 出口已安全接管。")
	wi.mu.Unlock()
}

func (wi *WarpInstaller) setStep(step, desc string, progress int) {
	wi.mu.Lock()
	defer wi.mu.Unlock()
	wi.status.Step = step
	wi.status.StepDesc = desc
	wi.status.Progress = progress
}

func (wi *WarpInstaller) injectCloudflareRepo(ctx context.Context, codename string) error {
	// 1. mkdir -p /usr/share/keyrings
	_, _ = wi.execCmd(ctx, "mkdir", "-p", "/usr/share/keyrings")

	// 2. Fetch and dearmor pubkey
	curlCmd := "curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg"
	if out, err := wi.execCmd(ctx, "sh", "-c", curlCmd); err != nil {
		return fmt.Errorf("fetch pubkey (%s): %w", string(out), err)
	}

	// 3. Write sources.list.d entry
	repoLine := fmt.Sprintf("deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ %s main\n", codename)
	writeCmd := fmt.Sprintf("echo '%s' > /etc/apt/sources.list.d/cloudflare-client.list", strings.TrimSpace(repoLine))
	if out, err := wi.execCmd(ctx, "sh", "-c", writeCmd); err != nil {
		return fmt.Errorf("write sources list (%s): %w", string(out), err)
	}

	return nil
}

func (wi *WarpInstaller) installPackage(ctx context.Context) error {
	// apt-get update
	out, err := wi.execCmd(ctx, "apt-get", "update", "-y")
	if err != nil {
		return fmt.Errorf("apt-get update (%s): %w", string(out), err)
	}

	// apt-get install cloudflare-warp
	out, err = wi.execCmd(ctx, "apt-get", "install", "-y", "cloudflare-warp")
	if err != nil {
		return fmt.Errorf("apt-get install cloudflare-warp (%s): %w", string(out), err)
	}
	return nil
}

func (wi *WarpInstaller) configureWarpProxy(ctx context.Context) error {
	// Enable and start warp-svc
	_, _ = wi.execCmd(ctx, "systemctl", "enable", "--now", "warp-svc")
	time.Sleep(500 * time.Millisecond)

	// Register / new registration
	regCmd := "warp-cli --accept-tos registration new 2>/dev/null || warp-cli --accept-tos register 2>/dev/null || true"
	_, _ = wi.execCmd(ctx, "sh", "-c", regCmd)

	// Set mode proxy
	modeCmd := "warp-cli --accept-tos mode proxy 2>/dev/null || warp-cli mode proxy 2>/dev/null"
	if out, err := wi.execCmd(ctx, "sh", "-c", modeCmd); err != nil {
		wi.appendLog("warn", fmt.Sprintf("设置 proxy 模式输出: %s", string(out)))
	}

	// Set proxy port 40000
	portCmd := "warp-cli --accept-tos proxy port 40000 2>/dev/null || warp-cli proxy port 40000 2>/dev/null"
	if out, err := wi.execCmd(ctx, "sh", "-c", portCmd); err != nil {
		wi.appendLog("warn", fmt.Sprintf("设置 proxy port 40000 输出: %s", string(out)))
	}

	// Connect
	connCmd := "warp-cli --accept-tos connect 2>/dev/null || warp-cli connect 2>/dev/null"
	if out, err := wi.execCmd(ctx, "sh", "-c", connCmd); err != nil {
		wi.appendLog("warn", fmt.Sprintf("WARP connect 输出: %s", string(out)))
	}

	return nil
}

func (wi *WarpInstaller) configureFirewall(ctx context.Context) {
	// Check if UFW is active
	out, err := wi.execCmd(ctx, "ufw", "status")
	if err == nil && strings.Contains(string(out), "Status: active") {
		// Ensure port 22 is open to prevent accidental lockout
		_, _ = wi.execCmd(ctx, "ufw", "allow", "22/tcp")
		// Allow loopback to port 40000
		_, _ = wi.execCmd(ctx, "ufw", "allow", "in", "on", "lo", "to", "127.0.0.1", "port", "40000", "proto", "tcp")
		_, _ = wi.execCmd(ctx, "ufw", "allow", "40000/tcp")
		wi.appendLog("info", "UFW 增量放行本地环回 40000 端口完成")
	}
}

func detectLinuxCodename() (codename, osName string, err error) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "", "", err
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "VERSION_CODENAME=") {
			codename = strings.Trim(strings.TrimPrefix(line, "VERSION_CODENAME="), `"'`)
		}
		if strings.HasPrefix(line, "ID=") {
			osName = strings.Trim(strings.TrimPrefix(line, "ID="), `"'`)
		}
	}
	if codename == "" {
		codename = "jammy"
	}
	return codename, osName, nil
}
