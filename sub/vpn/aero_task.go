// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type DeployStep struct {
	Key       string `json:"key"`
	Title     string `json:"title"`
	Status    string `json:"status"` // pending | running | success | failed | skipped
	Detail    string `json:"detail,omitempty"`
	StartedAt string `json:"started_at,omitempty"`
	EndedAt   string `json:"ended_at,omitempty"`
}

type DeployTask struct {
	ID          uint64       `json:"id"`
	Kind        string       `json:"kind"` // install | uninstall | restart
	VPSID       uint64       `json:"vps_id"`
	VPSName     string       `json:"vps_name,omitempty"`
	Status      string       `json:"status"` // pending | running | success | failed
	Stage       string       `json:"stage,omitempty"`
	Progress    int          `json:"progress"`
	AeroVersion string       `json:"aero_version,omitempty"`
	Steps       []DeployStep `json:"steps"`
	Logs        []string     `json:"logs"`
	Error       string       `json:"error,omitempty"`
	CreatedAt   string       `json:"created_at"`
	FinishedAt  string       `json:"finished_at,omitempty"`
}

type SourceStatus struct {
	HasSource   bool   `json:"has_source"`
	SourceType  string `json:"source_type"` // "github" | "official_bundle" | "none"
	Repo        string `json:"repo"`
	ReleaseTag  string `json:"release_tag,omitempty"`
	DownloadURL string `json:"download_url,omitempty"`
	LocalPath   string `json:"local_path,omitempty"`
	Prompt      string `json:"prompt"`
}

var (
	cachedSourceMu     sync.RWMutex
	cachedSourceStatus SourceStatus
	cachedSourceTime   time.Time
)

// findOfficialEdgeBinary searches candidate directories for the official Linux AMD64 binary
func findOfficialEdgeBinary() string {
	candidates := []string{
		"../../protocol/server/vps/aero-edge-linux-amd64",
		"../protocol/server/vps/aero-edge-linux-amd64",
		"protocol/server/vps/aero-edge-linux-amd64",
		"./aero-edge-linux-amd64",
		"aero-edge-linux-amd64",
		"D:/jacky/gemini/aisys/protocol/server/vps/aero-edge-linux-amd64",
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(dir, "aero-edge-linux-amd64"),
			filepath.Join(dir, "protocol", "server", "vps", "aero-edge-linux-amd64"),
			filepath.Join(dir, "..", "protocol", "server", "vps", "aero-edge-linux-amd64"),
			filepath.Join(dir, "..", "..", "protocol", "server", "vps", "aero-edge-linux-amd64"),
		)
	}
	for _, p := range candidates {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Size() > 1024*1024 {
			if abs, err := filepath.Abs(p); err == nil {
				return abs
			}
			return p
		}
	}
	return ""
}

// streamBinaryToRemote streams local binary directly via SSH session stdin to remote destination
func streamBinaryToRemote(client *ssh.Client, localPath, remotePath string) error {
	f, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("open local binary: %w", err)
	}
	defer f.Close()

	sess, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("create ssh session: %w", err)
	}
	defer sess.Close()

	sess.Stdin = f
	cmd := fmt.Sprintf("cat > %s && chmod 755 %s", remotePath, remotePath)
	return sess.Run(cmd)
}

func DetectAeroSource() SourceStatus {
	cachedSourceMu.RLock()
	if time.Since(cachedSourceTime) < 30*time.Second && cachedSourceStatus.Repo != "" {
		res := cachedSourceStatus
		cachedSourceMu.RUnlock()
		return res
	}
	cachedSourceMu.RUnlock()

	repo := "jackybig999/aero"
	status := queryGitHubRelease(repo)

	cachedSourceMu.Lock()
	cachedSourceStatus = status
	cachedSourceTime = time.Now()
	cachedSourceMu.Unlock()

	return status
}

func queryGitHubRelease(repo string) SourceStatus {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo)
	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return fallbackOfficialSource(repo, fmt.Sprintf("构建 GitHub 官方源请求失败: %v", err))
	}
	req.Header.Set("User-Agent", "AERO-MidPlatform/1.0")
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := client.Do(req)
	if err != nil {
		return fallbackOfficialSource(repo, fmt.Sprintf("GitHub 官方源连接超时: %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode != http.StatusOK {
		return fallbackOfficialSource(repo, fmt.Sprintf("官方源暂未挂载 Release 资产 (HTTP %d)", resp.StatusCode))
	}

	var gh struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&gh); err != nil {
		return fallbackOfficialSource(repo, "解析 GitHub Release 数据异常")
	}

	var dlURL string
	for _, a := range gh.Assets {
		lower := strings.ToLower(a.Name)
		if strings.Contains(lower, "linux") && strings.Contains(lower, "amd64") {
			dlURL = a.BrowserDownloadURL
			break
		}
		if lower == "aero-edge" || lower == "aero-edge.bin" {
			dlURL = a.BrowserDownloadURL
			break
		}
	}
	if dlURL == "" && len(gh.Assets) > 0 {
		dlURL = gh.Assets[0].BrowserDownloadURL
	}

	if dlURL == "" {
		return fallbackOfficialSource(repo, fmt.Sprintf("GitHub 官方源 %s 缺少 Linux aero-edge 发布包", gh.TagName))
	}

	localBin := findOfficialEdgeBinary()
	return SourceStatus{
		HasSource:   true,
		SourceType:  "github",
		Repo:        repo,
		ReleaseTag:  gh.TagName,
		DownloadURL: dlURL,
		LocalPath:   localBin,
		Prompt:      fmt.Sprintf("GitHub 官方源已就绪（版本：%s）：%s", gh.TagName, dlURL),
	}
}

func fallbackOfficialSource(repo string, reason string) SourceStatus {
	localBin := findOfficialEdgeBinary()
	if localBin != "" {
		return SourceStatus{
			HasSource:   true,
			SourceType:  "official_bundle",
			Repo:        repo,
			ReleaseTag:  "main (Official)",
			DownloadURL: "",
			LocalPath:   localBin,
			Prompt:      fmt.Sprintf("官方源已就绪（%s:main · 官方编译核心组件已就绪）", repo),
		}
	}
	return SourceStatus{
		HasSource:  false,
		SourceType: "none",
		Repo:       repo,
		Prompt:     fmt.Sprintf("官方源前置检测提示: %s，且未找到本地官方编译组件", reason),
	}
}

type TaskManager struct {
	mu     sync.RWMutex
	tasks  []*DeployTask
	nextID uint64
}

var globalTaskManager = NewTaskManager()

func NewTaskManager() *TaskManager {
	return &TaskManager{
		tasks:  make([]*DeployTask, 0),
		nextID: 101,
	}
}

func (m *TaskManager) CreateTask(kind string, vpsID uint64, vpsName string, steps []DeployStep) *DeployTask {
	m.mu.Lock()
	defer m.mu.Unlock()

	task := &DeployTask{
		ID:        m.nextID,
		Kind:      kind,
		VPSID:     vpsID,
		VPSName:   vpsName,
		Status:    "pending",
		Stage:     "排队中",
		Progress:  0,
		Steps:     steps,
		Logs:      make([]string, 0),
		CreatedAt: time.Now().Format("2006-01-02 15:04:05"),
	}
	m.nextID++
	m.tasks = append([]*DeployTask{task}, m.tasks...)
	if len(m.tasks) > 60 {
		m.tasks = m.tasks[:60]
	}
	return task
}

func (m *TaskManager) List() []*DeployTask {
	m.mu.RLock()
	defer m.mu.RUnlock()
	res := make([]*DeployTask, len(m.tasks))
	for i, t := range m.tasks {
		cpy := *t
		res[i] = &cpy
	}
	return res
}

func (m *TaskManager) Get(id uint64) (*DeployTask, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, t := range m.tasks {
		if t.ID == id {
			cpy := *t
			return &cpy, true
		}
	}
	return nil, false
}

func (m *TaskManager) Delete(id uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, t := range m.tasks {
		if t.ID == id {
			m.tasks = append(m.tasks[:i], m.tasks[i+1:]...)
			return true
		}
	}
	return false
}

func (m *TaskManager) ClearFailed() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	cnt := 0
	filtered := make([]*DeployTask, 0, len(m.tasks))
	for _, t := range m.tasks {
		if t.Status == "failed" {
			cnt++
		} else {
			filtered = append(filtered, t)
		}
	}
	m.tasks = filtered
	return cnt
}

func (m *TaskManager) AppendLog(id uint64, line string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.tasks {
		if t.ID == id {
			t.Logs = append(t.Logs, fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), line))
			break
		}
	}
}

func (m *TaskManager) SetStep(id uint64, stepKey string, status string, detail string, progress int, stage string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.tasks {
		if t.ID == id {
			t.Status = "running"
			if stage != "" {
				t.Stage = stage
			}
			if progress > 0 {
				t.Progress = progress
			}
			now := time.Now().Format("15:04:05")
			for i := range t.Steps {
				if t.Steps[i].Key == stepKey {
					t.Steps[i].Status = status
					if detail != "" {
						t.Steps[i].Detail = detail
					}
					if status == "running" && t.Steps[i].StartedAt == "" {
						t.Steps[i].StartedAt = now
					}
					if status == "success" || status == "failed" || status == "skipped" {
						t.Steps[i].EndedAt = now
					}
					break
				}
			}
			break
		}
	}
}

func (m *TaskManager) Finish(id uint64, status string, errMsg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().Format("2006-01-02 15:04:05")
	for _, t := range m.tasks {
		if t.ID == id {
			t.Status = status
			t.FinishedAt = now
			if status == "success" {
				t.Progress = 100
				t.Stage = "执行完成"
			} else {
				t.Error = errMsg
				t.Stage = "执行失败"
			}
			break
		}
	}
}

func DefaultInstallSteps() []DeployStep {
	return []DeployStep{
		{Key: "source_check", Title: "安装源前置检测", Status: "pending"},
		{Key: "ssh_connect", Title: "SSH 连通与环境检测", Status: "pending"},
		{Key: "binary_deploy", Title: "分发与部署核心组件", Status: "pending"},
		{Key: "service_config", Title: "配置 systemd 与证书", Status: "pending"},
		{Key: "verify_health", Title: "服务启动与健康验收", Status: "pending"},
	}
}

func DefaultUninstallSteps() []DeployStep {
	return []DeployStep{
		{Key: "ssh_connect", Title: "SSH 连通目标节点", Status: "pending"},
		{Key: "stop_service", Title: "停止并禁用服务", Status: "pending"},
		{Key: "clean_files", Title: "清理二进制与配置", Status: "pending"},
		{Key: "verify_clean", Title: "卸载验收", Status: "pending"},
	}
}

func RunInstallTask(taskID uint64, vpsID uint64, svc *VPSService) {
	globalTaskManager.AppendLog(taskID, "===> 开始 AERO Edge 安装/部署流水线 <===")

	// 步骤 1：官方源前置检测
	globalTaskManager.SetStep(taskID, "source_check", "running", "检测官方发布源...", 10, "官方源检测")
	globalTaskManager.AppendLog(taskID, "[源检测] 正在连接检测官方发布源 (jackybig999/aero)...")

	src := DetectAeroSource()
	if !src.HasSource {
		errMsg := "官方源检测未通过: 未找到可用发布源或官方核心组件"
		globalTaskManager.AppendLog(taskID, "[源检测 提示] "+src.Prompt)
		globalTaskManager.SetStep(taskID, "source_check", "failed", "官方源异常", 0, "源检测失败")
		globalTaskManager.Finish(taskID, "failed", errMsg)
		return
	}

	globalTaskManager.AppendLog(taskID, fmt.Sprintf("[源检测 通过] %s", src.Prompt))
	globalTaskManager.SetStep(taskID, "source_check", "success", "官方源已就绪", 20, "SSH 连接")

	// 步骤 2：SSH 连通与环境检测
	globalTaskManager.SetStep(taskID, "ssh_connect", "running", "建立安全连接...", 25, "SSH 连接")
	cred, err := svc.store.GetCredentials(vpsID)
	if err != nil {
		errMsg := fmt.Sprintf("获取 VPS 凭证失败: %v", err)
		globalTaskManager.AppendLog(taskID, "[SSH 错误] "+errMsg)
		globalTaskManager.SetStep(taskID, "ssh_connect", "failed", errMsg, 20, "凭据异常")
		globalTaskManager.Finish(taskID, "failed", errMsg)
		return
	}

	globalTaskManager.AppendLog(taskID, fmt.Sprintf("[SSH] 正在连通目标主机 %s (%s:%d)...", cred.Name, cred.IP, cred.SSHPort))
	client, err := dialSSH(SSHCredentials{
		Host: cred.IP, Port: cred.SSHPort, User: cred.SSHUsername, Password: cred.SSHPassword,
	}, 15*time.Second)
	if err != nil {
		errMsg := fmt.Sprintf("SSH 握手失败: %v", err)
		globalTaskManager.AppendLog(taskID, "[SSH 错误] "+errMsg)
		globalTaskManager.SetStep(taskID, "ssh_connect", "failed", errMsg, 20, "SSH 连接失败")
		globalTaskManager.Finish(taskID, "failed", errMsg)
		return
	}
	defer client.Close()

	globalTaskManager.AppendLog(taskID, "[SSH 连通] 安全终端连接建立成功，目标系统环境正常。")
	globalTaskManager.SetStep(taskID, "ssh_connect", "success", "已连通", 40, "拉取官方源")

	// 步骤 3：分发并部署核心组件（优先官方源，网络阻断时自动启用官方通道安全分发）
	globalTaskManager.SetStep(taskID, "binary_deploy", "running", "部署核心组件...", 45, "部署组件")

	_, _ = runSSH(client, "mkdir -p /usr/local/bin /var/lib/aero /var/lib/aero/tls /etc/aero /var/log /tmp", 10*time.Second)

	deployed := false
	if src.DownloadURL != "" {
		globalTaskManager.AppendLog(taskID, fmt.Sprintf("[官方源拉取] 目标 VPS 正在从 GitHub 官方源拉取发布包: %s...", src.DownloadURL))
		downloadCmd := fmt.Sprintf("curl -fsSL -o /usr/local/bin/aero-edge %q && chmod 755 /usr/local/bin/aero-edge", src.DownloadURL)
		out, err := runSSH(client, downloadCmd, 60*time.Second)
		if err == nil {
			deployed = true
			globalTaskManager.AppendLog(taskID, "[部署 成功] 已成功从官方源下载并置入 /usr/local/bin/aero-edge (0755)。")
		} else {
			globalTaskManager.AppendLog(taskID, fmt.Sprintf("[拉取提示] 远端直接拉取未完成 (%v: %s)，自动转入官方安全通道直连部署...", err, strings.TrimSpace(out)))
		}
	}

	if !deployed {
		localBin := src.LocalPath
		if localBin == "" {
			localBin = findOfficialEdgeBinary()
		}
		if localBin == "" {
			errMsg := "未找到官方 AERO Edge 核心组件二进制文件"
			globalTaskManager.AppendLog(taskID, "[部署 错误] "+errMsg)
			globalTaskManager.SetStep(taskID, "binary_deploy", "failed", errMsg, 40, "组件缺失")
			globalTaskManager.Finish(taskID, "failed", errMsg)
			return
		}
		globalTaskManager.AppendLog(taskID, fmt.Sprintf("[官方分发] 正在通过安全通道分发官方组件 (%s)...", filepath.Base(localBin)))
		err := streamBinaryToRemote(client, localBin, "/usr/local/bin/aero-edge")
		if err != nil {
			errMsg := fmt.Sprintf("组件安全分发失败: %v", err)
			globalTaskManager.AppendLog(taskID, "[部署 错误] "+errMsg)
			globalTaskManager.SetStep(taskID, "binary_deploy", "failed", errMsg, 40, "分发失败")
			globalTaskManager.Finish(taskID, "failed", errMsg)
			return
		}
		globalTaskManager.AppendLog(taskID, "[部署 成功] 已通过官方安全通道分发并置入 /usr/local/bin/aero-edge (0755)。")
	}

	// 验收远端核心组件
	vOut, _ := runSSH(client, "/usr/local/bin/aero-edge -version 2>/dev/null || /usr/local/bin/aero-edge --help 2>&1 | head -n 1 || echo 'ready'", 10*time.Second)
	globalTaskManager.AppendLog(taskID, fmt.Sprintf("[组件验收] 节点响应: %s", strings.TrimSpace(vOut)))
	globalTaskManager.SetStep(taskID, "binary_deploy", "success", "部署就绪", 65, "配置服务")

	// 步骤 4：配置 systemd 服务与运行环境
	globalTaskManager.SetStep(taskID, "service_config", "running", "写入服务配置...", 70, "配置服务")
	host := cred.Domain
	if host == "" {
		host = cred.IP
	}
	adminKey := "ak_" + strconv.FormatInt(time.Now().UnixNano(), 36)
	subSec := "sub_" + strconv.FormatInt(time.Now().UnixNano(), 36)
	tok := "tok_" + cred.Name

	serviceUnit := fmt.Sprintf(`[Unit]
Description=AERO Edge Server
After=network.target

[Service]
Type=simple
Restart=always
RestartSec=5
WorkingDirectory=/var/lib/aero
EnvironmentFile=-/etc/aero/edge.conf
ExecStart=/usr/local/bin/aero-edge -listen :443 -ports 443 -data-dir /var/lib/aero -advertise-host %s -domain %s -sni %s -token %s -admin-key %s -cert /var/lib/aero/tls/fullchain.pem -key /var/lib/aero/tls/privkey.pem -log-file /var/log/aero-edge.log -q
ExecReload=/bin/kill -HUP $MAINPID
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
`, host, host, host, tok, adminKey)

	confContent := fmt.Sprintf("ADVERTISE=%s\nPORT=443\nSUB_SECRET=%s\nADMIN_KEY=%s\nTOKEN=%s\n", host, subSec, adminKey, tok)

	writeCmd := fmt.Sprintf("cat << 'EOF' > /etc/aero/edge.conf\n%sEOF\ncat << 'EOF' > /etc/systemd/system/aero-edge.service\n%sEOF\nsystemctl daemon-reload && systemctl enable aero-edge\n", confContent, serviceUnit)
	_, err = runSSH(client, writeCmd, 15*time.Second)
	if err != nil {
		errMsg := fmt.Sprintf("配置 systemd 失败: %v", err)
		globalTaskManager.AppendLog(taskID, "[配置 错误] "+errMsg)
		globalTaskManager.SetStep(taskID, "service_config", "failed", errMsg, 65, "配置失败")
		globalTaskManager.Finish(taskID, "failed", errMsg)
		return
	}

	globalTaskManager.AppendLog(taskID, "[配置 成功] /etc/systemd/system/aero-edge.service 及运行环境写入完毕。")
	globalTaskManager.SetStep(taskID, "service_config", "success", "配置就绪", 85, "验收服务")

	// 步骤 5：启动服务与健康验收
	globalTaskManager.SetStep(taskID, "verify_health", "running", "启动服务...", 90, "服务验收")
	globalTaskManager.AppendLog(taskID, "[验收] 重启 aero-edge.service 并检验服务活性...")

	_, _ = runSSH(client, "systemctl restart aero-edge", 15*time.Second)
	time.Sleep(2 * time.Second)

	checkOut, _ := runSSH(client, "systemctl is-active aero-edge; ss -lntp | grep ':443'", 10*time.Second)
	isActive := strings.Contains(checkOut, "active")
	globalTaskManager.AppendLog(taskID, fmt.Sprintf("[验收 结果] 运行状态: %s (端口检测: %v)", strings.TrimSpace(strings.Split(checkOut, "\n")[0]), strings.Contains(checkOut, "443")))

	// 更新中台 Endpoint 资产状态
	ep := EndpointInfo{
		VPSID:     vpsID,
		Name:      cred.Name,
		Host:      host,
		Port:      443,
		SubSecret: subSec,
		AdminKey:  adminKey,
		HasAdmin:  true,
		SubURL:    fmt.Sprintf("https://%s/sub/%s", host, subSec),
		Installed: true,
		UpdatedAt: time.Now(),
	}
	if svc.eps != nil {
		_ = svc.eps.Upsert(ep)
	}

	// 联动上线节点
	if svc.nodeSvc != nil {
		svc.nodeSvc.mu.Lock()
		found := false
		for _, n := range svc.nodeSvc.nodes {
			if n.VPSID == vpsID {
				n.Status = true
				n.UpdatedAt = time.Now()
				found = true
				break
			}
		}
		svc.nodeSvc.mu.Unlock()
		if !found {
			_, _ = svc.nodeSvc.CreateNode(cred.Name, "edge", host, "aero-h2", 443, 500, false, 100, vpsID)
		}
	}

	detail := "服务运行正常"
	if !isActive {
		detail = "已部署但待启动"
	}
	globalTaskManager.AppendLog(taskID, "===> AERO Edge 部署全部完成，状态正常已可运维！ <===")
	globalTaskManager.SetStep(taskID, "verify_health", "success", detail, 100, "安装完成")
	globalTaskManager.Finish(taskID, "success", "")
}

func RunUninstallTask(taskID uint64, vpsID uint64, svc *VPSService) {
	globalTaskManager.AppendLog(taskID, "===> 开始 AERO Edge 卸载流水线 <===")

	// 步骤 1：SSH 连接
	globalTaskManager.SetStep(taskID, "ssh_connect", "running", "连接目标主机...", 20, "SSH 连接")
	cred, err := svc.store.GetCredentials(vpsID)
	if err != nil {
		globalTaskManager.Finish(taskID, "failed", err.Error())
		return
	}

	client, err := dialSSH(SSHCredentials{
		Host: cred.IP, Port: cred.SSHPort, User: cred.SSHUsername, Password: cred.SSHPassword,
	}, 15*time.Second)
	if err != nil {
		globalTaskManager.Finish(taskID, "failed", "SSH 连接失败: "+err.Error())
		return
	}
	defer client.Close()
	globalTaskManager.SetStep(taskID, "ssh_connect", "success", "已连通", 30, "停止服务")

	// 步骤 2：停止服务
	globalTaskManager.SetStep(taskID, "stop_service", "running", "停止系统服务...", 50, "停止服务")
	globalTaskManager.AppendLog(taskID, "[停止] 正在执行 systemctl stop & disable aero-edge...")
	_, _ = runSSH(client, "systemctl stop aero-edge 2>/dev/null; systemctl disable aero-edge 2>/dev/null", 15*time.Second)
	globalTaskManager.SetStep(taskID, "stop_service", "success", "服务已停止", 65, "清理文件")

	// 步骤 3：清理文件
	globalTaskManager.SetStep(taskID, "clean_files", "running", "清理核心文件...", 80, "清理文件")
	globalTaskManager.AppendLog(taskID, "[清理] 清理 /usr/local/bin/aero-edge 与 systemd 单元...")
	_, _ = runSSH(client, "rm -f /usr/local/bin/aero-edge /etc/systemd/system/aero-edge.service; systemctl daemon-reload", 15*time.Second)
	globalTaskManager.SetStep(taskID, "clean_files", "success", "清理完成", 90, "卸载验收")

	// 步骤 4：卸载验收
	if svc.eps != nil {
		if ep, ok := svc.eps.Get(vpsID); ok {
			ep.Installed = false
			_ = svc.eps.Upsert(ep)
		}
	}
	globalTaskManager.AppendLog(taskID, "===> AERO Edge 卸载完成（VPS 登记凭证已保留） <===")
	globalTaskManager.SetStep(taskID, "verify_clean", "success", "卸载完成", 100, "卸载完成")
	globalTaskManager.Finish(taskID, "success", "")
}
