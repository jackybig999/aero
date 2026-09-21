package ipc

import (
	"database/sql"
	"runtime"

	"aisys/connect/os/internal/domain/proxy"
	"aisys/connect/os/internal/infra/config"
	"aisys/connect/os/internal/service"
)

// RegisterFingerprintHandlers registers all fingerprint, browser, and kernel IPC handlers
func RegisterFingerprintHandlers(w IPCBinder, appService *service.AppService, dataDir string, appDB *sql.DB, detector proxy.SysProxyDetector) {
	// 1. Host system information and proxy/VPN detection
	w.Bind("goGetSysInfo", func() map[string]interface{} {
		curCfg := config.GetUnifiedConfig()
		var sysProxy *proxy.ProxyConfig
		if detector != nil {
			sysProxy, _ = detector.Detect()
		}
		vpn, _ := config.DetectSystemVPN()
		if vpn != nil && vpn.Detected && curCfg != nil {
			curCfg.VPN = *vpn
		}
		sysLocale := config.GetHostSystemLocale()
		res := map[string]interface{}{
			"os":                  runtime.GOOS,
			"system_locale":       sysLocale,
			"default_startup_url": config.GetDefaultFingerprintCheckURL(sysLocale),
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
	service.RegisterSharedIPCHandlers(w, appService, dataDir, appDB)
}
