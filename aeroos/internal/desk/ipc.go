package desk

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"
)

// IPCBinder 抽象桌面端 WebView 接口绑定的最小契约
type IPCBinder interface {
	Bind(name string, f interface{}) error
}

// IPCDependencies 桌面端 IPC 依赖注入总表
type IPCDependencies struct {
	AppService   *AppService
	DataDir      string
	AppDB        *sql.DB
	NetBridge    *ClientBridge
	NetDaemon    *ClientDaemon
	AIScanner    *Scanner
	AIExecutor   *Executor
	AIToolStore  *ToolStore
	APIVault     *APIVault
	APITester    *Tester
	HistoryStore *HistoryStore
	Detector     SysProxyDetector
	DirSelector  func() string
}

// RegisterAll binds all domain handlers to the native WebView instance
func RegisterAll(w IPCBinder, deps *IPCDependencies) {
	// 1. Browser & Kernel IPC (Full 100% Fingerprint Suite)
	RegisterFingerprintHandlers(w, deps.AppService, deps.DataDir, deps.AppDB, deps.Detector)

	// 2. Network Center IPC (Client Bridge)
	RegisterNetHandlers(w, deps.NetBridge, deps.NetDaemon)

	// 3. AI Developer Tools IPC
	RegisterAIHandlers(w, deps.AIScanner, deps.AIExecutor, deps.AIToolStore, deps.DirSelector)

	// 4. API Matrix IPC
	RegisterAPIHandlers(w, deps.APIVault, deps.APITester)

	// 5. Audit & Log IPC
	RegisterAuditHandlers(w, deps.HistoryStore)
}

// RegisterFingerprintHandlers registers all fingerprint, browser, and kernel IPC handlers
func RegisterFingerprintHandlers(w IPCBinder, appService *AppService, dataDir string, appDB *sql.DB, detector SysProxyDetector) {
	// 1. Host system information and proxy/VPN detection
	w.Bind("goGetSysInfo", func() map[string]interface{} {
		curCfg := GetUnifiedConfig()
		var sysProxy *ProxyConfig
		if detector != nil {
			sysProxy, _ = detector.Detect()
		}
		vpn, _ := DetectSystemVPN()
		if vpn != nil && vpn.Detected && curCfg != nil {
			curCfg.VPN = *vpn
		}
		sysLocale := GetHostSystemLocale()
		res := map[string]interface{}{
			"os":                  runtime.GOOS,
			"system_locale":       sysLocale,
			"default_startup_url": GetDefaultFingerprintCheckURL(sysLocale),
			"vpn_detected":        false,
		}
		if curCfg != nil && curCfg.VPN.Detected {
			res["vpn_detected"] = true
			res["vpn_name"] = curCfg.VPN.Name
			res["vpn_type"] = curCfg.VPN.Type
			res["vpn_ip"] = curCfg.VPN.IP
		}
		if sysProxy != nil && sysProxy.Enabled {
			res["proxy_enabled"] = true
			res["proxy_host"] = sysProxy.Host
			res["proxy_port"] = sysProxy.Port
			res["proxy_proto"] = sysProxy.Protocol
		}
		return res
	})

	// 2. Register all shared core business IPC methods (24 methods)
	RegisterSharedIPCHandlers(w, appService, dataDir, appDB)
}

// RegisterSharedIPCHandlers 注册跨平台共享的桌面原生 IPC 接口
func RegisterSharedIPCHandlers(w IPCBinder, appService *AppService, dataDir string, appDB *sql.DB) {
	// 1. 环境管理核心接口
	w.Bind("goGetProfiles", func() []*Profile {
		list, _ := appService.ListProfiles()
		return list
	})

	w.Bind("goCreateProfile", func(name, kernelType, country, proxyStr string) *Profile {
		p, err := appService.CreateProfile(name, kernelType, country, proxyStr)
		if err != nil {
			log.Printf("[ERROR] 创建环境失败: %v\n", err)
			return nil
		}
		return p
	})

	w.Bind("goCreateProfileAdvanced", func(reqJSON string) *Profile {
		var req CreateProfileRequest
		if err := json.Unmarshal([]byte(reqJSON), &req); err != nil {
			log.Printf("[ERROR] 解析创建环境参数失败: %v\n", err)
			return nil
		}
		p, err := appService.CreateProfileAdvanced(&req)
		if err != nil {
			log.Printf("[ERROR] 高级创建环境失败: %v\n", err)
			return nil
		}
		log.Printf("[OK] 成功创建指纹环境 [%s] (内核: %s, 时区: %s, 语言: %s)\n", p.Name, p.KernelType, req.Timezone, req.Languages)
		return p
	})

	w.Bind("goStartProfile", func(id int64) map[string]interface{} {
		err := appService.StartProfile(id)
		if err != nil {
			log.Printf("[ERROR] 启动环境 %d 失败: %v\n", id, err)
			return map[string]interface{}{"status": "error", "message": err.Error()}
		}
		log.Printf("[OK] 成功启动环境 %d\n", id)
		return map[string]interface{}{"status": "ok"}
	})

	w.Bind("goStopProfile", func(id int64) map[string]interface{} {
		_ = appService.StopProfile(id)
		log.Printf("[OK] 停止环境 %d\n", id)
		return map[string]interface{}{"status": "ok"}
	})

	w.Bind("goUpdateProfileAdvanced", func(reqJSON string) *Profile {
		var req CreateProfileRequest
		if err := json.Unmarshal([]byte(reqJSON), &req); err != nil {
			log.Printf("[ERROR] 解析更新环境参数失败: %v\n", err)
			return nil
		}
		p, err := appService.UpdateProfileAdvanced(&req)
		if err != nil {
			log.Printf("[ERROR] 更新环境失败: %v\n", err)
			return nil
		}
		log.Printf("[OK] 成功更新指纹环境 #%d [%s]\n", p.ID, p.Name)
		return p
	})

	w.Bind("goUpdateProfileLanguage", func(id int64, languages string) map[string]interface{} {
		err := appService.UpdateProfileLanguage(id, languages)
		if err != nil {
			log.Printf("[ERROR] 更新环境 #%d 语言失败: %v\n", id, err)
			return map[string]interface{}{"status": "error", "message": err.Error()}
		}
		return map[string]interface{}{"status": "ok"}
	})

	w.Bind("goDeleteProfile", func(id int64) map[string]interface{} {
		err := appService.DeleteProfile(id)
		if err != nil {
			log.Printf("[ERROR] 删除环境 #%d 失败: %v\n", id, err)
			return map[string]interface{}{"status": "error", "message": err.Error()}
		}
		log.Printf("[OK] 成功删除指纹环境 #%d\n", id)
		return map[string]interface{}{"status": "ok"}
	})

	w.Bind("goCloneProfile", func(id int64) *Profile {
		p, err := appService.CloneProfile(id)
		if err != nil {
			log.Printf("[ERROR] 克隆环境 #%d 失败: %v\n", id, err)
			return nil
		}
		log.Printf("[OK] 成功克隆指纹环境 #%d -> #%d [%s]\n", id, p.ID, p.Name)
		return p
	})

	w.Bind("goExportProfileConfig", func(id int64, exportPath string) map[string]interface{} {
		err := appService.ExportProfileConfig(id, exportPath)
		if err != nil {
			log.Printf("[ERROR] 导出环境配置失败: %v\n", err)
			return map[string]interface{}{"status": "error", "error": err.Error()}
		}
		log.Printf("[OK] 成功导出环境 #%d 配置至: %s\n", id, exportPath)
		return map[string]interface{}{"status": "ok"}
	})

	w.Bind("ExportProfileConfig", func(id int64, exportPath string) map[string]interface{} {
		err := appService.ExportProfileConfig(id, exportPath)
		if err != nil {
			log.Printf("[ERROR] 导出环境配置失败: %v\n", err)
			return map[string]interface{}{"status": "error", "error": err.Error()}
		}
		log.Printf("[OK] 成功导出环境 #%d 配置至: %s\n", id, exportPath)
		return map[string]interface{}{"status": "ok"}
	})

	w.Bind("goImportProfileConfig", func(importPath string) map[string]interface{} {
		p, err := appService.ImportProfileConfig(importPath)
		if err != nil {
			log.Printf("[ERROR] 导入环境配置失败: %v\n", err)
			return map[string]interface{}{"status": "error", "error": err.Error()}
		}
		log.Printf("[OK] 成功从 %s 导入环境 #%d [%s]\n", importPath, p.ID, p.Name)
		return map[string]interface{}{"status": "ok", "profile": p}
	})

	w.Bind("ImportProfileConfig", func(importPath string) map[string]interface{} {
		p, err := appService.ImportProfileConfig(importPath)
		if err != nil {
			log.Printf("[ERROR] 导入环境配置失败: %v\n", err)
			return map[string]interface{}{"status": "error", "error": err.Error()}
		}
		log.Printf("[OK] 成功从 %s 导入环境 #%d [%s]\n", importPath, p.ID, p.Name)
		return map[string]interface{}{"status": "ok", "profile": p}
	})

	// 2. 批量操作接口
	w.Bind("goBatchStartProfiles", func(idsJSON string) map[string]interface{} {
		var ids []int64
		if err := json.Unmarshal([]byte(idsJSON), &ids); err != nil {
			return map[string]interface{}{"error": "参数解析失败: " + err.Error()}
		}
		return appService.BatchStartProfiles(ids)
	})

	w.Bind("goBatchStopProfiles", func(idsJSON string) map[string]interface{} {
		var ids []int64
		if err := json.Unmarshal([]byte(idsJSON), &ids); err != nil {
			return map[string]interface{}{"error": "参数解析失败: " + err.Error()}
		}
		return appService.BatchStopProfiles(ids)
	})

	w.Bind("goBatchDeleteProfiles", func(idsJSON string) map[string]interface{} {
		var ids []int64
		if err := json.Unmarshal([]byte(idsJSON), &ids); err != nil {
			return map[string]interface{}{"error": "参数解析失败: " + err.Error()}
		}
		return appService.BatchDeleteProfiles(ids)
	})

	// 3. 内核管理接口
	w.Bind("goGetKernels", func() []KernelVersionInfo {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return GetAvailableKernelsWithStatus(ctx, dataDir)
	})

	w.Bind("goRefreshKernels", func() []KernelVersionInfo {
		InvalidateOfficialKernelsCache()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return GetAvailableKernelsWithStatus(ctx, dataDir)
	})

	w.Bind("goDownloadKernel", func(kernelType, milestone, dlURL string) map[string]interface{} {
		log.Printf("[INFO] 用户触发下载内核: %s %s, URL: %s\n", kernelType, milestone, dlURL)
		TriggerKernelDownload(dataDir, kernelType, milestone, dlURL, func(err error) {
			if err != nil {
				log.Printf("[ERROR] 内核下载失败: %v\n", err)
			} else {
				log.Printf("[OK] 内核 %s %s 下载解压成功，已就绪！\n", kernelType, milestone)
			}
		})
		return map[string]interface{}{"status": "started"}
	})

	w.Bind("goGetKernelProgress", func(kernelType, milestone string) int {
		key := fmt.Sprintf("%s_%s", kernelType, milestone)
		return GetKernelProgress(key)
	})

	w.Bind("goDeleteKernel", func(kernelType, milestone string) map[string]interface{} {
		log.Printf("[INFO] 用户触发清理删除内核: %s %s\n", kernelType, milestone)
		err := DeleteKernel(dataDir, kernelType, milestone)
		if err != nil {
			log.Printf("[ERROR] 清理内核失败: %v\n", err)
			return map[string]interface{}{"status": "error", "message": err.Error()}
		}
		log.Printf("[OK] 内核 %s %s 清理成功\n", kernelType, milestone)
		return map[string]interface{}{"status": "ok"}
	})

	// 4. 代理测速与前端日志
	w.Bind("goTestProxy", func(raw string) *OutboundInfo {
		cfg, err := ParseProxyString(raw)
		if err != nil {
			return &OutboundInfo{Status: "failed", ErrorMsg: err.Error()}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		info, _ := TestOutbound(ctx, cfg, 6*time.Second)
		return info
	})

	w.Bind("goCheckSystemNetworkStatus", func() map[string]interface{} {
		vpn, _ := DetectSystemVPN()
		if vpn != nil && (vpn.Detected || vpn.IsActive) {
			return map[string]interface{}{
				"status":  "vpn_ready",
				"message": fmt.Sprintf("已接通 VPN 虚拟网卡 (%s)", vpn.Name),
				"type":    vpn.Type,
			}
		}
		for _, k := range []string{"HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
			if val := os.Getenv(k); val != "" {
				return map[string]interface{}{
					"status":  "proxy_ready",
					"message": fmt.Sprintf("系统代理在线 (%s)", val),
				}
			}
		}
		return map[string]interface{}{
			"status":  "direct",
			"message": "未检测到活跃系统代理或 VPN",
		}
	})

	w.Bind("goCheckAeroProxyStatus", func() map[string]interface{} {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		info, err := TestOutbound(ctx, nil, 3*time.Second)
		if err != nil || info == nil || info.Status != "ok" {
			return map[string]interface{}{
				"status":  "warning",
				"message": "Aero 节点握手准备就绪",
			}
		}
		return map[string]interface{}{
			"status":  "ok",
			"latency": info.LatencyMs,
			"ip":      info.OutboundIP,
			"message": fmt.Sprintf("Aero 专线就绪 (延迟: %dms)", info.LatencyMs),
		}
	})

	w.Bind("goLog", func(msg string) {
		log.Println("[FRONTEND]", msg)
	})

	// 5. 用户认证会话接口
	w.Bind("goRegisterUser", func(username, email, password string) map[string]interface{} {
		u, err := RegisterUserWithEmail(appDB, username, email, password)
		if err != nil {
			return map[string]interface{}{"status": "error", "message": err.Error()}
		}
		_, token, _ := AuthenticateUser(appDB, username, password)
		_ = SaveSessionUser(appDB, u.ID)
		log.Printf("[OK] 用户注册并建立活跃会话: %s (ID: %d)\n", u.Username, u.ID)
		return map[string]interface{}{"status": "ok", "user": u, "token": token}
	})

	w.Bind("goLoginUser", func(usernameOrEmail, password string, remember bool) map[string]interface{} {
		u, token, err := AuthenticateUser(appDB, usernameOrEmail, password)
		if err != nil {
			return map[string]interface{}{"status": "error", "message": err.Error()}
		}
		if remember {
			_ = SaveSessionUser(appDB, u.ID)
		}
		log.Printf("[OK] 用户登录成功: %s (记住会话: %v)\n", u.Username, remember)
		return map[string]interface{}{"status": "ok", "user": u, "token": token}
	})

	w.Bind("goGetCurrentUser", func(token string) map[string]interface{} {
		if token != "" {
			u, err := ValidateToken(token)
			if err == nil && u != nil {
				return map[string]interface{}{"status": "ok", "user": u}
			}
		}
		savedUser, err := GetSavedSessionUser(appDB)
		if err == nil && savedUser != nil {
			log.Printf("[OK] 自动恢复持久化用户登录会话: %s (ID: %d)\n", savedUser.Username, savedUser.ID)
			return map[string]interface{}{"status": "ok", "user": savedUser}
		}
		count, _ := CountUsers(appDB)
		if count == 0 {
			return map[string]interface{}{"status": "need_register"}
		}
		return map[string]interface{}{"status": "need_login"}
	})

	w.Bind("goLogoutUser", func(token string) map[string]interface{} {
		Logout(token)
		_ = ClearSessionUser(appDB)
		log.Println("[OK] 用户已注销退出")
		return map[string]interface{}{"status": "ok"}
	})
}

func RegisterNetHandlers(w IPCBinder, bridge *ClientBridge, daemon *ClientDaemon) {
	w.Bind("goGetNetStatus", func() map[string]interface{} {
		st, err := bridge.GetStatus(true)
		if err != nil {
			return map[string]interface{}{
				"connected": false,
				"error":     err.Error(),
				"listen":    DefaultMixedProxy,
				"ready":     false,
			}
		}
		res := map[string]interface{}{
			"connected":    st.Connected,
			"mode":         st.Mode,
			"listen":       st.Listen,
			"node":         st.Node,
			"rtt_ms":       st.RTTMs,
			"sub_url":      st.SubURL,
			"sub_url_mask": st.SubURLMask,
			"last_error":   st.LastError,
			"protocol":     st.Protocol,
			"isp":          st.ISP,
			"ready":        true,
		}
		if st.ProbeOK != nil {
			res["probe_ok"] = *st.ProbeOK
			res["probe_ms"] = st.ProbeMS
			res["probe_detail"] = st.ProbeDetail
		}
		return res
	})

	w.Bind("goToggleNetPower", func(targetOn bool) map[string]interface{} {
		var err error
		if targetOn {
			if daemon != nil {
				_ = daemon.EnsureRunning()
			}
			err = bridge.Connect()
		} else {
			err = bridge.Disconnect()
		}
		if err != nil {
			log.Printf("[IPC-NET] power toggle error: %v", err)
			return map[string]interface{}{"status": "error", "error": err.Error()}
		}
		return map[string]interface{}{"status": "ok"}
	})

	w.Bind("goSetNetMode", func(mode string) map[string]interface{} {
		if err := bridge.SetMode(mode); err != nil {
			return map[string]interface{}{"status": "error", "error": err.Error()}
		}
		return map[string]interface{}{"status": "ok"}
	})

	w.Bind("goApplyNetSub", func(subURL string) map[string]interface{} {
		if err := bridge.ImportSub(subURL); err != nil {
			return map[string]interface{}{"status": "error", "error": err.Error()}
		}
		return map[string]interface{}{"status": "ok"}
	})

	w.Bind("goProbeNet", func() map[string]interface{} {
		res, err := bridge.Probe()
		if err != nil {
			return map[string]interface{}{"ok": false, "error": err.Error()}
		}
		return res
	})

	w.Bind("goGetNodes", func() []NodeInfo {
		nodes, err := bridge.GetNodes()
		if err != nil {
			log.Printf("[IPC-NET] goGetNodes error: %v", err)
			return []NodeInfo{}
		}
		return nodes
	})

	w.Bind("goProbeAllNodes", func() []NodeInfo {
		nodes, err := bridge.ProbeNodes()
		if err != nil {
			log.Printf("[IPC-NET] goProbeAllNodes error: %v", err)
			return []NodeInfo{}
		}
		return nodes
	})

	w.Bind("goSelectNode", func(address string) map[string]interface{} {
		err := bridge.SelectNode(address)
		if err != nil {
			log.Printf("[IPC-NET] goSelectNode error: %v", err)
			return map[string]interface{}{"status": "error", "error": err.Error()}
		}
		return map[string]interface{}{"status": "ok", "active": address}
	})
}

func RegisterAIHandlers(w IPCBinder, scanner *Scanner, executor *Executor, store *ToolStore, dirSelector func() string) {
	w.Bind("goGetAITools", func() []ToolInfo {
		if scanner == nil {
			return nil
		}
		return scanner.ScanAll()
	})

	w.Bind("goLaunchAITool", func(toolKey, cwd string) map[string]interface{} {
		if executor == nil {
			return map[string]interface{}{"status": "error", "error": "executor not initialized"}
		}
		msg, err := executor.Launch(toolKey, cwd)
		if err != nil {
			return map[string]interface{}{"status": "error", "error": err.Error()}
		}
		return map[string]interface{}{"status": "ok", "message": msg}
	})

	w.Bind("goSetToolCWD", func(toolKey, cwd string) map[string]interface{} {
		if store != nil {
			store.SetCWD(toolKey, cwd)
		}
		return map[string]interface{}{"status": "ok"}
	})

	w.Bind("goSelectDirectory", func() string {
		if dirSelector != nil {
			return dirSelector()
		}
		return ""
	})
}

func RegisterAPIHandlers(w IPCBinder, vault *APIVault, tester *Tester) {
	w.Bind("goGetAPIs", func() []*APIProviderConfig {
		if vault == nil {
			return nil
		}
		return vault.GetAll()
	})

	w.Bind("goSaveAPI", func(id, key, baseURL string) map[string]interface{} {
		if vault != nil {
			vault.SaveKey(id, key, baseURL)
		}
		return map[string]interface{}{"status": "ok"}
	})

	w.Bind("goTestAPI", func(id string) map[string]interface{} {
		if tester == nil {
			return map[string]interface{}{"status": "error", "error": "tester not initialized"}
		}
		status, latency, err := tester.TestProvider(id)
		res := map[string]interface{}{
			"status":     status,
			"latency_ms": latency,
		}
		if err != nil {
			res["error"] = err.Error()
		}
		return res
	})
}

func RegisterAuditHandlers(w IPCBinder, history *HistoryStore) {
	w.Bind("goGetLogs", func() []LogEntry {
		return GlobalLogger.GetLogs()
	})

	w.Bind("goClearLogs", func() map[string]interface{} {
		GlobalLogger.Clear()
		return map[string]interface{}{"status": "ok"}
	})

	w.Bind("goExportLogs", func(customPath string) map[string]interface{} {
		err := GlobalLogger.ExportToFile(customPath)
		if err != nil {
			return map[string]interface{}{"status": "error", "error": err.Error()}
		}
		return map[string]interface{}{"status": "ok"}
	})

	w.Bind("goGetHistory", func() []HistoryItem {
		if history == nil {
			return nil
		}
		return history.GetItems()
	})

	w.Bind("goClearHistory", func() map[string]interface{} {
		if history != nil {
			history.Clear()
		}
		return map[string]interface{}{"status": "ok"}
	})
}
