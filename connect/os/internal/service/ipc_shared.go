package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"aisys/connect/os/internal/domain/proxy"
	"aisys/connect/os/internal/domain/user"
	"aisys/connect/os/internal/infra/config"
	"aisys/connect/os/internal/infra/db"
	"aisys/connect/os/internal/kernel"
)

// IPCBinder 抽象桌面端 WebView 接口绑定的最小契约 (彻底解耦具体 GUI 库，保障纯 Go 跨平台编译)
type IPCBinder interface {
	Bind(name string, f interface{}) error
}

// RegisterSharedIPCHandlers 注册 Win 与 Mac 跨平台完全共享的桌面原生 IPC 接口 (多端统一保证)
func RegisterSharedIPCHandlers(w IPCBinder, appService *AppService, dataDir string, appDB *sql.DB) {
	// 1. 环境管理核心接口
	w.Bind("goGetProfiles", func() []*db.Profile {
		list, _ := appService.ListProfiles()
		return list
	})

	w.Bind("goCreateProfile", func(name, kernelType, country, proxyStr string) *db.Profile {
		p, err := appService.CreateProfile(name, kernelType, country, proxyStr)
		if err != nil {
			log.Printf("[ERROR] 创建环境失败: %v\n", err)
			return nil
		}
		return p
	})

	w.Bind("goCreateProfileAdvanced", func(reqJSON string) *db.Profile {
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

	w.Bind("goUpdateProfileAdvanced", func(reqJSON string) *db.Profile {
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

	w.Bind("goCloneProfile", func(id int64) *db.Profile {
		p, err := appService.CloneProfile(id)
		if err != nil {
			log.Printf("[ERROR] 克隆环境 #%d 失败: %v\n", id, err)
			return nil
		}
		log.Printf("[OK] 成功克隆指纹环境 #%d -> #%d [%s]\n", id, p.ID, p.Name)
		return p
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
	w.Bind("goGetKernels", func() []kernel.KernelVersionInfo {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return kernel.GetAvailableKernelsWithStatus(ctx, dataDir)
	})

	w.Bind("goRefreshKernels", func() []kernel.KernelVersionInfo {
		kernel.InvalidateOfficialKernelsCache()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return kernel.GetAvailableKernelsWithStatus(ctx, dataDir)
	})

	w.Bind("goDownloadKernel", func(kernelType, milestone, dlURL string) map[string]interface{} {
		log.Printf("[INFO] 用户触发下载内核: %s %s, URL: %s\n", kernelType, milestone, dlURL)
		kernel.TriggerKernelDownload(dataDir, kernelType, milestone, dlURL, func(err error) {
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
		return kernel.GetKernelProgress(key)
	})

	w.Bind("goDeleteKernel", func(kernelType, milestone string) map[string]interface{} {
		log.Printf("[INFO] 用户触发清理删除内核: %s %s\n", kernelType, milestone)
		err := kernel.DeleteKernel(dataDir, kernelType, milestone)
		if err != nil {
			log.Printf("[ERROR] 清理内核失败: %v\n", err)
			return map[string]interface{}{"status": "error", "message": err.Error()}
		}
		log.Printf("[OK] 内核 %s %s 清理成功\n", kernelType, milestone)
		return map[string]interface{}{"status": "ok"}
	})

	// 4. 代理测速与前端日志
	w.Bind("goTestProxy", func(raw string) *proxy.OutboundInfo {
		cfg, err := proxy.ParseProxyString(raw)
		if err != nil {
			return &proxy.OutboundInfo{Status: "failed", ErrorMsg: err.Error()}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		info, _ := proxy.TestOutbound(ctx, cfg, 6*time.Second)
		return info
	})

	w.Bind("goCheckSystemNetworkStatus", func() map[string]interface{} {
		vpn, _ := config.DetectSystemVPN()
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
		info, err := proxy.TestOutbound(ctx, nil, 3*time.Second)
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
		u, err := user.RegisterUserWithEmail(appDB, username, email, password)
		if err != nil {
			return map[string]interface{}{"status": "error", "message": err.Error()}
		}
		_, token, _ := user.AuthenticateUser(appDB, username, password)
		_ = user.SaveSessionUser(appDB, u.ID)
		log.Printf("[OK] 用户注册并建立活跃会话: %s (ID: %d)\n", u.Username, u.ID)
		return map[string]interface{}{"status": "ok", "user": u, "token": token}
	})

	w.Bind("goLoginUser", func(usernameOrEmail, password string, remember bool) map[string]interface{} {
		u, token, err := user.AuthenticateUser(appDB, usernameOrEmail, password)
		if err != nil {
			return map[string]interface{}{"status": "error", "message": err.Error()}
		}
		if remember {
			_ = user.SaveSessionUser(appDB, u.ID)
		}
		log.Printf("[OK] 用户登录成功: %s (记住会话: %v)\n", u.Username, remember)
		return map[string]interface{}{"status": "ok", "user": u, "token": token}
	})

	w.Bind("goGetCurrentUser", func(token string) map[string]interface{} {
		if token != "" {
			u, err := user.ValidateToken(token)
			if err == nil && u != nil {
				return map[string]interface{}{"status": "ok", "user": u}
			}
		}
		savedUser, err := user.GetSavedSessionUser(appDB)
		if err == nil && savedUser != nil {
			log.Printf("[OK] 自动恢复持久化用户登录会话: %s (ID: %d)\n", savedUser.Username, savedUser.ID)
			return map[string]interface{}{"status": "ok", "user": savedUser}
		}
		count, _ := user.CountUsers(appDB)
		if count == 0 {
			return map[string]interface{}{"status": "need_register"}
		}
		return map[string]interface{}{"status": "need_login"}
	})

	w.Bind("goLogoutUser", func(token string) map[string]interface{} {
		user.Logout(token)
		_ = user.ClearSessionUser(appDB)
		log.Println("[OK] 用户已注销退出")
		return map[string]interface{}{"status": "ok"}
	})
}
