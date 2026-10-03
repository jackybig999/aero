package desk

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// AppService 核心业务协调总线
type AppService struct {
	DB               *sql.DB
	SysProxyDetector SysProxyDetector
	DataDir          string
	ServerPort       int
	healthTicker     *time.Ticker
	healthStopChan   chan struct{}
	statusCache      sync.Map // profID(int64) -> status(string)
	mu               sync.RWMutex
}

var (
	GlobalService *AppService
	serviceOnce   sync.Once
)

// InitAppService 初始化全局服务
func InitAppService(db *sql.DB, detector SysProxyDetector, dataDir string, port int) *AppService {
	if port <= 0 {
		port = 18888
	}
	serviceOnce.Do(func() {
		GlobalService = &AppService{
			DB:               db,
			SysProxyDetector: detector,
			DataDir:          dataDir,
			ServerPort:       port,
			healthStopChan:   make(chan struct{}),
		}
	})

	if GlobalService != nil {
		GlobalService.mu.Lock()
		if db != nil {
			GlobalService.DB = db
		}
		if detector != nil {
			GlobalService.SysProxyDetector = detector
		}
		if dataDir != "" {
			GlobalService.DataDir = dataDir
		}
		if port > 0 {
			GlobalService.ServerPort = port
		}
		GlobalService.mu.Unlock()
	}
	return GlobalService
}

// SetProfileStatusCache 更新环境运行状态内存快照
func (s *AppService) SetProfileStatusCache(id int64, status string) {
	s.statusCache.Store(id, status)
}

// GetProfileStatusCache 获取环境运行状态内存快照
func (s *AppService) GetProfileStatusCache(id int64) (string, bool) {
	if val, ok := s.statusCache.Load(id); ok {
		if str, ok := val.(string); ok {
			return str, true
		}
	}
	return "", false
}

// StartProfile 启动指定环境的浏览器进程
func (s *AppService) StartProfile(id int64) error {
	var kernelType, kernelVersion, fpJSON, notes string
	var proxyID int64
	var lastLaunchedAt sql.NullTime
	err := s.DB.QueryRow(`SELECT kernel_type, kernel_version, notes, proxy_id, fingerprint_config, last_launched_at FROM profiles WHERE id = ?`, id).Scan(&kernelType, &kernelVersion, &notes, &proxyID, &fpJSON, &lastLaunchedAt)
	if err != nil {
		return fmt.Errorf("未找到环境 %d: %w", id, err)
	}

	var fp FingerprintConfig
	_ = json.Unmarshal([]byte(fpJSON), &fp)

	var proxyCfg *ProxyConfig
	if proxyID > 0 {
		var proto, host, user, pass string
		var port int
		if err := s.DB.QueryRow(`SELECT protocol, host, port, username, password FROM proxies WHERE id = ?`, proxyID).Scan(&proto, &host, &port, &user, &pass); err == nil {
			proxyCfg = &ProxyConfig{
				Enabled:  true,
				Protocol: proto,
				Host:     host,
				Port:     port,
				Username: user,
				Password: pass,
			}
		}
	}

	hasCustomURL := false
	startupURL := ""
	if strings.Contains(notes, "启动: ") {
		idx := strings.Index(notes, "启动: ")
		cand := strings.TrimSpace(notes[idx+len("启动: "):])
		if strings.Contains(cand, " ") {
			cand = strings.Split(cand, " ")[0]
		}
		isLegacyCheck := strings.Contains(cand, "whoer.net") || strings.Contains(cand, "browserleaks.com") || strings.Contains(cand, "ipinfo.io")
		if cand != "" && !isLegacyCheck {
			startupURL = cand
			hasCustomURL = true
		}
	}

	if !hasCustomURL && !lastLaunchedAt.Valid {
		checkLocale := GetHostSystemLocale()
		if len(fp.Languages) > 0 && fp.Languages[0] != "" && !strings.EqualFold(fp.Languages[0], "system") {
			checkLocale = fp.Languages[0]
		}
		startupURL = GetDefaultFingerprintCheckURL(checkLocale)
	}

	var specificPath string
	if kernelVersion != "" {
		targetDir := filepath.Join(s.DataDir, "kernels", fmt.Sprintf("%s_%s", kernelType, kernelVersion))
		loc := LocateDownloadedKernel(targetDir, kernelType)
		if loc != "" {
			specificPath = loc
		}
	}

	var launchErr error
	var cInst *ChromeInstance
	var fInst *FirefoxInstance
	var sInst *SafariInstance
	if kernelType == "firefox" {
		fInst, launchErr = LaunchFirefox(specificPath, s.DataDir, id, proxyCfg, &fp, startupURL)
	} else if kernelType == "safari" {
		sInst, launchErr = LaunchSafari(specificPath, s.DataDir, id, proxyCfg, &fp, startupURL)
	} else {
		cInst, launchErr = LaunchChrome(specificPath, s.DataDir, id, proxyCfg, &fp, startupURL, nil)
	}

	if launchErr != nil {
		s.SetProfileStatusCache(id, "error")
		_, _ = s.DB.Exec(`UPDATE profiles SET status = 'error' WHERE id = ?`, id)
		return launchErr
	}

	s.SetProfileStatusCache(id, "running")
	now := time.Now()
	_, _ = s.DB.Exec(`UPDATE profiles SET status = 'running', last_launched_at = ? WHERE id = ?`, now, id)

	go func(profID int64, c *ChromeInstance, f *FirefoxInstance, sf *SafariInstance) {
		if c != nil {
			<-c.ExitChan
		} else if f != nil {
			<-f.ExitChan
		} else if sf != nil {
			<-sf.ExitChan
		}
		s.SetProfileStatusCache(profID, "stopped")
		_, _ = s.DB.Exec(`UPDATE profiles SET status = 'stopped' WHERE id = ?`, profID)
		log.Printf("[INFO] 环境 #%d 浏览器已关闭，状态已自动变更为 [stopped]\n", profID)
	}(id, cInst, fInst, sInst)

	return nil
}

// StopProfile 停止运行中的环境
func (s *AppService) StopProfile(id int64) error {
	s.SetProfileStatusCache(id, "stopped")
	_ = StopProfileInstance(id)
	_, err := s.DB.Exec(`UPDATE profiles SET status = 'stopped' WHERE id = ?`, id)
	return err
}

// CreateProfileRequest 高级指纹环境创建与编辑参数
type CreateProfileRequest struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	Notes         string `json:"notes"`
	KernelType    string `json:"kernel_type"`
	KernelVersion string `json:"kernel_version"`
	Country       string `json:"country"`
	ProxyMode     string `json:"proxy_mode"` // vpn, sys, custom, direct
	ProxyRaw      string `json:"proxy_raw"`
	Timezone      string `json:"timezone"`
	Languages     string `json:"languages"` // 逗号分隔例如 "en-US,en"
	Platform      string `json:"platform"`  // "Win32", "MacIntel", "Linux x86_64"
	UserAgent     string `json:"user_agent"`
	Resolution    string `json:"resolution"` // "1920x1080"
	CPUCores      int    `json:"cpu_cores"`
	MemoryGB      int    `json:"memory_gb"`
	WebGLVendor   string `json:"webgl_vendor"`
	WebGLRenderer string `json:"webgl_renderer"`
	CanvasNoise   bool   `json:"canvas_noise"`
	AudioNoise    bool   `json:"audio_noise"`
	WebRTCBlock   bool   `json:"webrtc_block"`
	StartupURL    string `json:"startup_url"`
}

// CreateProfile 创建新环境并自动生成指纹
func (s *AppService) CreateProfile(name, kernelType, country, proxyRaw string) (*Profile, error) {
	return s.CreateProfileAdvanced(&CreateProfileRequest{
		Name:       name,
		KernelType: kernelType,
		Country:    country,
		ProxyRaw:   proxyRaw,
	})
}

// CreateProfileAdvanced 创建全维度可配置的指纹环境
func (s *AppService) CreateProfileAdvanced(req *CreateProfileRequest) (*Profile, error) {
	if req.Name == "" {
		return nil, errors.New("环境名称不能为空")
	}
	if req.KernelType == "" {
		req.KernelType = "chrome"
	}
	if req.Country == "" {
		req.Country = "US"
	}

	fp := GenerateFingerprintConfig("", req.Country, req.KernelType, req.KernelVersion)

	if req.Timezone != "" {
		fp.Timezone = req.Timezone
	}
	fp.Languages = ResolveProfileLanguages(req.Languages)
	if req.Platform != "" {
		fp.Platform = req.Platform
	}
	if req.UserAgent != "" {
		fp.UserAgent = req.UserAgent
	}
	if req.Resolution != "" {
		parts := strings.Split(req.Resolution, "x")
		if len(parts) == 2 {
			w, _ := strconv.Atoi(parts[0])
			h, _ := strconv.Atoi(parts[1])
			if w > 0 && h > 0 {
				fp.ScreenWidth = w
				fp.ScreenHeight = h
			}
		}
	}
	if req.CPUCores > 0 {
		fp.HardwareConcurrency = req.CPUCores
	}
	if req.MemoryGB > 0 {
		fp.DeviceMemory = req.MemoryGB
	}
	if req.WebGLVendor != "" {
		fp.WebGLVendor = req.WebGLVendor
	}
	if req.WebGLRenderer != "" {
		fp.WebGLRenderer = req.WebGLRenderer
	}
	if !req.CanvasNoise {
		fp.CanvasNoise = 0
	}
	if !req.AudioNoise {
		fp.AudioNoise = 0
	}

	fpBytes, _ := json.Marshal(fp)

	var proxyID int64 = 0
	if req.ProxyMode == "custom" && req.ProxyRaw != "" {
		proxyCfg, _ := ParseProxyString(req.ProxyRaw)
		if proxyCfg != nil {
			r, err := s.DB.Exec(`INSERT INTO proxies (user_id, raw_input, protocol, host, port, username, password, status) VALUES (1, ?, ?, ?, ?, ?, ?, 'ready')`,
				req.ProxyRaw, proxyCfg.Protocol, proxyCfg.Host, proxyCfg.Port, proxyCfg.Username, proxyCfg.Password,
			)
			if err == nil {
				proxyID, _ = r.LastInsertId()
			}
		}
	}

	notes := req.Notes
	if req.StartupURL != "" {
		if notes != "" {
			notes += " | 启动: " + req.StartupURL
		} else {
			notes = "启动: " + req.StartupURL
		}
	}

	res, err := s.DB.Exec(`INSERT INTO profiles (user_id, name, notes, kernel_type, kernel_version, proxy_id, fingerprint_config, data_dir, status) VALUES (1, ?, ?, ?, ?, ?, ?, ?, 'stopped')`,
		req.Name, notes, req.KernelType, req.KernelVersion, proxyID, string(fpBytes), s.DataDir,
	)
	if err != nil {
		return nil, err
	}

	id, _ := res.LastInsertId()
	return &Profile{
		ID:                id,
		UserID:            1,
		Name:              req.Name,
		Notes:             notes,
		KernelType:        req.KernelType,
		KernelVersion:     req.KernelVersion,
		ProxyID:           proxyID,
		FingerprintConfig: string(fpBytes),
		DataDir:           s.DataDir,
		Status:            "stopped",
		CreatedAt:         time.Now(),
	}, nil
}

// UpdateProfileAdvanced 编辑更新既有指纹环境
func (s *AppService) UpdateProfileAdvanced(req *CreateProfileRequest) (*Profile, error) {
	if req.ID <= 0 {
		return nil, errors.New("无效的环境ID")
	}
	if req.Name == "" {
		return nil, errors.New("环境名称不能为空")
	}

	var oldKernel, oldVer, oldFP, oldNotes string
	var oldProxyID int64
	err := s.DB.QueryRow(`SELECT kernel_type, kernel_version, notes, proxy_id, fingerprint_config FROM profiles WHERE id = ?`, req.ID).Scan(&oldKernel, &oldVer, &oldNotes, &oldProxyID, &oldFP)
	if err != nil {
		return nil, fmt.Errorf("未找到待编辑环境 %d: %w", req.ID, err)
	}

	var fp FingerprintConfig
	if err := json.Unmarshal([]byte(oldFP), &fp); err != nil {
		fp = *GenerateFingerprintConfig("", req.Country, req.KernelType, req.KernelVersion)
	}

	if req.Timezone != "" {
		fp.Timezone = req.Timezone
	}
	if req.Languages != "" {
		fp.Languages = ResolveProfileLanguages(req.Languages)
	}
	if req.Platform != "" {
		fp.Platform = req.Platform
	}
	if req.UserAgent != "" {
		fp.UserAgent = req.UserAgent
	}
	if req.Resolution != "" {
		parts := strings.Split(req.Resolution, "x")
		if len(parts) == 2 {
			w, _ := strconv.Atoi(parts[0])
			h, _ := strconv.Atoi(parts[1])
			if w > 0 && h > 0 {
				fp.ScreenWidth = w
				fp.ScreenHeight = h
			}
		}
	}
	if req.CPUCores > 0 {
		fp.HardwareConcurrency = req.CPUCores
	}
	if req.MemoryGB > 0 {
		fp.DeviceMemory = req.MemoryGB
	}
	if req.WebGLVendor != "" {
		fp.WebGLVendor = req.WebGLVendor
	}
	if req.WebGLRenderer != "" {
		fp.WebGLRenderer = req.WebGLRenderer
	}
	if !req.CanvasNoise {
		fp.CanvasNoise = 0
	} else if fp.CanvasNoise == 0 {
		fp.CanvasNoise = -0.0005
	}
	if !req.AudioNoise {
		fp.AudioNoise = 0
	} else if fp.AudioNoise == 0 {
		fp.AudioNoise = 0.0001
	}

	fpBytes, _ := json.Marshal(fp)

	proxyID := oldProxyID
	if req.ProxyMode == "custom" && req.ProxyRaw != "" {
		proxyCfg, _ := ParseProxyString(req.ProxyRaw)
		if proxyCfg != nil {
			r, err := s.DB.Exec(`INSERT INTO proxies (user_id, raw_input, protocol, host, port, username, password, status) VALUES (1, ?, ?, ?, ?, ?, ?, 'ready')`,
				req.ProxyRaw, proxyCfg.Protocol, proxyCfg.Host, proxyCfg.Port, proxyCfg.Username, proxyCfg.Password,
			)
			if err == nil {
				proxyID, _ = r.LastInsertId()
			}
		}
	} else if req.ProxyMode != "custom" {
		proxyID = 0
	}

	notes := req.Notes
	if req.StartupURL != "" {
		if strings.Contains(notes, "启动: ") {
			idx := strings.Index(notes, "启动: ")
			notes = strings.TrimSpace(notes[:idx])
		}
		if notes != "" {
			notes += " | 启动: " + req.StartupURL
		} else {
			notes = "启动: " + req.StartupURL
		}
	} else if strings.Contains(notes, "启动: ") {
		idx := strings.Index(notes, "启动: ")
		notes = strings.TrimRight(strings.TrimSpace(notes[:idx]), "|")
		notes = strings.TrimSpace(notes)
	}

	_, err = s.DB.Exec(`UPDATE profiles SET name = ?, notes = ?, kernel_type = ?, kernel_version = ?, proxy_id = ?, fingerprint_config = ? WHERE id = ?`,
		req.Name, notes, req.KernelType, req.KernelVersion, proxyID, string(fpBytes), req.ID,
	)
	if err != nil {
		return nil, fmt.Errorf("更新环境失败: %w", err)
	}

	var updated Profile
	_ = s.DB.QueryRow(`SELECT id, user_id, name, notes, icon_color, kernel_type, kernel_version, proxy_id, fingerprint_config, data_dir, status, last_launched_at, created_at FROM profiles WHERE id = ?`, req.ID).Scan(
		&updated.ID, &updated.UserID, &updated.Name, &updated.Notes, &updated.IconColor, &updated.KernelType, &updated.KernelVersion, &updated.ProxyID, &updated.FingerprintConfig, &updated.DataDir, &updated.Status, &updated.LastLaunchedAt, &updated.CreatedAt,
	)
	return &updated, nil
}

// ListProfiles 查询全部环境列表并自愈异常状态
func (s *AppService) ListProfiles() ([]*Profile, error) {
	rows, err := s.DB.Query(`SELECT id, user_id, name, notes, icon_color, kernel_type, kernel_version, proxy_id, fingerprint_config, data_dir, status, last_launched_at, created_at FROM profiles ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	var list []*Profile
	for rows.Next() {
		var p Profile
		err := rows.Scan(&p.ID, &p.UserID, &p.Name, &p.Notes, &p.IconColor, &p.KernelType, &p.KernelVersion, &p.ProxyID, &p.FingerprintConfig, &p.DataDir, &p.Status, &p.LastLaunchedAt, &p.CreatedAt)
		if err != nil {
			continue
		}
		list = append(list, &p)
	}
	_ = rows.Close()

	var desyncIDs []int64
	for _, p := range list {
		if memStatus, ok := s.GetProfileStatusCache(p.ID); ok {
			p.Status = memStatus
			continue
		}
		isRunning := IsProfileRunning(p.ID)
		if isRunning {
			p.Status = "running"
			s.SetProfileStatusCache(p.ID, "running")
		} else {
			if p.Status == "running" {
				p.Status = "stopped"
				desyncIDs = append(desyncIDs, p.ID)
			}
			s.SetProfileStatusCache(p.ID, "stopped")
		}
	}

	if len(desyncIDs) > 0 {
		go func(ids []int64) {
			for _, id := range ids {
				_, _ = s.DB.Exec(`UPDATE profiles SET status = 'stopped' WHERE id = ?`, id)
			}
		}(desyncIDs)
	}

	return list, nil
}

// ResolveProfileLanguages 将语言设置动态解析为与宿主系统完全匹配的语言切片
func ResolveProfileLanguages(lang string) []string {
	lang = strings.TrimSpace(lang)
	if lang == "" || strings.EqualFold(lang, "system") {
		sysLocale := GetHostSystemLocale()
		low := strings.ToLower(sysLocale)
		if strings.HasPrefix(low, "zh") {
			if strings.Contains(low, "tw") {
				return []string{"zh-TW", "zh"}
			}
			if strings.Contains(low, "hk") {
				return []string{"zh-HK", "zh"}
			}
			return []string{"zh-CN", "zh"}
		}
		if strings.HasPrefix(low, "ja") {
			return []string{"ja-JP", "ja"}
		}
		if strings.HasPrefix(low, "de") {
			return []string{"de-DE", "de"}
		}
		if strings.HasPrefix(low, "fr") {
			return []string{"fr-FR", "fr"}
		}
		if strings.HasPrefix(low, "ru") {
			return []string{"ru-RU", "ru"}
		}
		if strings.HasPrefix(low, "es") {
			return []string{"es-ES", "es"}
		}
		if strings.HasPrefix(low, "ko") {
			return []string{"ko-KR", "ko"}
		}
		if strings.HasPrefix(low, "it") {
			return []string{"it-IT", "it"}
		}
		if strings.HasPrefix(low, "en") {
			if strings.Contains(low, "gb") || strings.Contains(low, "uk") {
				return []string{"en-GB", "en"}
			}
			return []string{"en-US", "en"}
		}
		return []string{sysLocale, "en"}
	}

	var langs []string
	for _, l := range strings.Split(lang, ",") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.EqualFold(l, "system") {
			langs = append(langs, l)
		}
	}
	if len(langs) == 0 {
		return ResolveProfileLanguages("system")
	}
	return langs
}

// UpdateProfileLanguage 更新并持久化环境的语言设置
func (s *AppService) UpdateProfileLanguage(id int64, languages string) error {
	langs := ResolveProfileLanguages(languages)
	var fpJSON string
	err := s.DB.QueryRow(`SELECT fingerprint_config FROM profiles WHERE id = ?`, id).Scan(&fpJSON)
	if err != nil {
		return fmt.Errorf("未找到待更新语言的环境 #%d: %w", id, err)
	}

	var fp FingerprintConfig
	_ = json.Unmarshal([]byte(fpJSON), &fp)
	fp.Languages = langs

	newBytes, err := json.Marshal(fp)
	if err != nil {
		return fmt.Errorf("序列化指纹配置失败: %w", err)
	}

	s.mu.Lock()
	_, err = s.DB.Exec(`UPDATE profiles SET fingerprint_config = ? WHERE id = ?`, string(newBytes), id)
	s.mu.Unlock()

	log.Printf("[OK] 环境 #%d 语言配置已持久化更新为: %v\n", id, langs)
	return err
}

// DeleteProfile 停止并删除指定指纹环境及沙箱数据
func (s *AppService) DeleteProfile(id int64) error {
	_ = s.StopProfile(id)
	_, err := s.DB.Exec(`DELETE FROM profiles WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("删除环境数据库记录失败: %w", err)
	}
	profileDir := filepath.Join(s.DataDir, "profiles", strconv.FormatInt(id, 10))
	_ = os.RemoveAll(profileDir)
	return nil
}

// CloneProfile 克隆复制一个既有环境并生成独立微调指纹
func (s *AppService) CloneProfile(id int64) (*Profile, error) {
	var p Profile
	err := s.DB.QueryRow(`SELECT id, user_id, name, notes, icon_color, kernel_type, kernel_version, proxy_id, fingerprint_config, data_dir, status FROM profiles WHERE id = ?`, id).Scan(
		&p.ID, &p.UserID, &p.Name, &p.Notes, &p.IconColor, &p.KernelType, &p.KernelVersion, &p.ProxyID, &p.FingerprintConfig, &p.DataDir, &p.Status,
	)
	if err != nil {
		return nil, fmt.Errorf("未找到要克隆的环境: %w", err)
	}

	var fp FingerprintConfig
	_ = json.Unmarshal([]byte(p.FingerprintConfig), &fp)
	fp.CanvasNoise = -0.0001 - float64(time.Now().UnixNano()%1000)/1000000.0
	fp.AudioNoise = 0.0001 + float64(time.Now().UnixNano()%1000)/1000000.0
	fpBytes, _ := json.Marshal(fp)

	cloneName := p.Name + " (副本)"
	res, err := s.DB.Exec(`INSERT INTO profiles (user_id, name, notes, kernel_type, kernel_version, proxy_id, fingerprint_config, data_dir, status) VALUES (1, ?, ?, ?, ?, ?, ?, ?, 'stopped')`,
		cloneName, p.Notes, p.KernelType, p.KernelVersion, p.ProxyID, string(fpBytes), s.DataDir,
	)
	if err != nil {
		return nil, err
	}
	newID, _ := res.LastInsertId()
	p.ID = newID
	p.Name = cloneName
	p.Status = "stopped"
	p.FingerprintConfig = string(fpBytes)
	p.CreatedAt = time.Now()
	return &p, nil
}

// BatchStartProfiles 批量启动环境
func (s *AppService) BatchStartProfiles(ids []int64) map[string]interface{} {
	success := 0
	failed := 0
	var errs []string
	for _, id := range ids {
		if err := s.StartProfile(id); err != nil {
			failed++
			errs = append(errs, fmt.Sprintf("ID %d: %v", id, err))
		} else {
			success++
		}
	}
	return map[string]interface{}{
		"success_count": success,
		"failed_count":  failed,
		"errors":        errs,
	}
}

// BatchStopProfiles 批量停止环境
func (s *AppService) BatchStopProfiles(ids []int64) map[string]interface{} {
	stopped := 0
	for _, id := range ids {
		_ = s.StopProfile(id)
		stopped++
	}
	return map[string]interface{}{"stopped_count": stopped}
}

// BatchDeleteProfiles 批量删除环境
func (s *AppService) BatchDeleteProfiles(ids []int64) map[string]interface{} {
	deleted := 0
	for _, id := range ids {
		if err := s.DeleteProfile(id); err == nil {
			deleted++
		}
	}
	return map[string]interface{}{"deleted_count": deleted}
}

// StartProxyHealthPoller 启动后台代理健康定期轮询协程
func (s *AppService) StartProxyHealthPoller(interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	s.healthTicker = time.NewTicker(interval)

	go func() {
		for {
			select {
			case <-s.healthTicker.C:
				s.CheckAllProxiesHealth()
			case <-s.healthStopChan:
				return
			}
		}
	}()
}

// CheckAllProxiesHealth 检查所有已保存代理的健康状态
func (s *AppService) CheckAllProxiesHealth() {
	rows, err := s.DB.Query(`SELECT id, raw_input, protocol, host, port, username, password FROM proxies`)
	if err != nil {
		return
	}

	type proxyItem struct {
		id  int64
		cfg *ProxyConfig
	}
	var items []proxyItem

	for rows.Next() {
		var id int64
		var raw, proto, host, user, pass string
		var port int
		if err := rows.Scan(&id, &raw, &proto, &host, &port, &user, &pass); err != nil {
			continue
		}
		items = append(items, proxyItem{
			id: id,
			cfg: &ProxyConfig{
				Enabled:  true,
				Protocol: proto,
				Host:     host,
				Port:     port,
				Username: user,
				Password: pass,
			},
		})
	}
	_ = rows.Close()

	if len(items) == 0 {
		return
	}

	maxWorkers := 8
	if len(items) < maxWorkers {
		maxWorkers = len(items)
	}
	sem := make(chan struct{}, maxWorkers)
	var wg sync.WaitGroup

	for _, it := range items {
		wg.Add(1)
		go func(item proxyItem) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			info, _ := TestOutbound(ctx, item.cfg, 6*time.Second)
			cancel()

			if info != nil {
				s.mu.Lock()
				_, _ = s.DB.Exec(`UPDATE proxies SET outbound_ip = ?, latency_ms = ?, status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
					info.OutboundIP, info.LatencyMs, info.Status, item.id,
				)
				s.mu.Unlock()
			}
		}(it)
	}
	wg.Wait()
}

// StopHealthPoller 停止健康检测定时器
func (s *AppService) StopHealthPoller() {
	if s.healthTicker != nil {
		s.healthTicker.Stop()
	}
	if s.healthStopChan != nil {
		select {
		case s.healthStopChan <- struct{}{}:
		default:
		}
	}
}

// VPNInfo VPN/TUN 状态模型
type VPNInfo struct {
	Detected  bool   `json:"detected"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	IP        string `json:"ip"`
	IsActive  bool   `json:"is_active"`
	CheckedAt string `json:"checked_at"`
}

// UnifiedConfig 跨平台唯一配置文件模型
type UnifiedConfig struct {
	AppVersion  string       `json:"app_version"`
	LastUpdated string       `json:"last_updated"`
	OS          string       `json:"os"`
	VPN         VPNInfo      `json:"vpn"`
	SystemProxy ProxyConfig  `json:"system_proxy"`
	Settings    AppSettings  `json:"settings"`
	Profiles    []*Profile   `json:"profiles"`
	Proxies     []*ProxyItem `json:"proxies"`
}

type AppSettings struct {
	DefaultKernel string `json:"default_kernel"`
	AutoCheckVPN  bool   `json:"auto_check_vpn"`
	WindowWidth   int    `json:"window_width"`
	WindowHeight  int    `json:"window_height"`
}

var (
	globalConfig   *UnifiedConfig
	configMutex    sync.RWMutex
	configFilePath string
)

func DefaultConfigPath() string {
	return "config.json"
}

// LoadOrCreateUnifiedConfig 加载单一全局配置文件
func LoadOrCreateUnifiedConfig(path string) (*UnifiedConfig, error) {
	configMutex.Lock()
	defer configMutex.Unlock()

	if path == "" {
		path = DefaultConfigPath()
	}
	configFilePath = path

	if _, err := os.Stat(path); os.IsNotExist(err) {
		cfg := &UnifiedConfig{
			AppVersion:  "2.0",
			LastUpdated: time.Now().Format(time.RFC3339),
			OS:          runtime.GOOS,
			VPN: VPNInfo{
				Detected: false,
			},
			SystemProxy: ProxyConfig{
				Enabled: false,
			},
			Settings: AppSettings{
				DefaultKernel: "chrome",
				AutoCheckVPN:  true,
				WindowWidth:   1120,
				WindowHeight:  760,
			},
			Profiles: make([]*Profile, 0),
			Proxies:  make([]*ProxyItem, 0),
		}

		data, err := json.MarshalIndent(cfg, "", "  ")
		if err == nil {
			_ = os.WriteFile(path, data, 0644)
		}
		globalConfig = cfg
		return globalConfig, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}

	var cfg UnifiedConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("解析配置文件 JSON 失败: %w", err)
	}

	globalConfig = &cfg
	return globalConfig, nil
}

// GetUnifiedConfig 获取当前全局内存配置
func GetUnifiedConfig() *UnifiedConfig {
	configMutex.RLock()
	defer configMutex.RUnlock()
	return globalConfig
}

// SaveUnifiedConfig 保存全局配置回唯一配置文件
func SaveUnifiedConfig(cfg *UnifiedConfig) error {
	configMutex.Lock()
	defer configMutex.Unlock()

	if cfg == nil {
		cfg = globalConfig
	}
	if cfg == nil {
		return fmt.Errorf("未初始化的配置")
	}

	cfg.LastUpdated = time.Now().Format(time.RFC3339)
	cfg.OS = runtime.GOOS

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置失败: %w", err)
	}

	path := configFilePath
	if path == "" {
		path = DefaultConfigPath()
	}

	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}

	return os.WriteFile(path, data, 0644)
}

// DetectSystemVPN 跨平台智能检测系统是否已开启 VPN / TUN 虚拟网卡
func DetectSystemVPN() (*VPNInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	vpnKeywords := []string{
		"aero0", "wintun",
		"singbox", "sing-tun", "sing_box",
		"tap", "tun",
		"wireguard", "wg",
		"tailscale", "zerotier",
		"clash", "clash_tun",
		"openvpn",
		"utun", "ppp", "ipsec",
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		nameLower := strings.ToLower(iface.Name)
		for _, kw := range vpnKeywords {
			if strings.Contains(nameLower, kw) {
				addrs, _ := iface.Addrs()
				var ipStr string
				for _, a := range addrs {
					if ipNet, ok := a.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
						if ipNet.IP.To4() != nil {
							ipStr = ipNet.IP.String()
							break
						}
					}
				}

				typeName := "TUN/VPN"
				if strings.Contains(nameLower, "aero") {
					typeName = "AERO TUN"
				} else if strings.Contains(nameLower, "wireguard") || strings.Contains(nameLower, "wg") {
					typeName = "WireGuard"
				} else if strings.Contains(nameLower, "tailscale") {
					typeName = "Tailscale"
				} else if strings.Contains(nameLower, "utun") {
					typeName = "macOS utun"
				}

				return &VPNInfo{
					Detected:  true,
					Name:      iface.Name,
					Type:      typeName,
					IP:        ipStr,
					IsActive:  true,
					CheckedAt: time.Now().Format("15:04:05"),
				}, nil
			}
		}
	}

	return &VPNInfo{
		Detected:  false,
		CheckedAt: time.Now().Format("15:04:05"),
	}, nil
}

// BackgroundAsyncVPNCheck 异步后台执行 VPN 探测并自动写入单配置文件
func BackgroundAsyncVPNCheck(onDetected func(info *VPNInfo)) {
	go func() {
		time.Sleep(1 * time.Second)

		vpn, err := DetectSystemVPN()
		if err == nil && vpn.Detected {
			configMutex.Lock()
			if globalConfig != nil {
				globalConfig.VPN = *vpn
			}
			configMutex.Unlock()
			_ = SaveUnifiedConfig(nil)

			if onDetected != nil {
				onDetected(vpn)
			}
		}
	}()
}
