//go:build windows

package main

import (
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"aisys/connect/os/internal/aitools"
	"aisys/connect/os/internal/apimatrix"
	"aisys/connect/os/internal/audit"
	"aisys/connect/os/internal/infra/config"
	"aisys/connect/os/internal/infra/db"
	"aisys/connect/os/internal/ipc"
	"aisys/connect/os/internal/kernel"
	"aisys/connect/os/internal/netcore"
	"aisys/connect/os/internal/service"
	"aisys/connect/os/internal/ui"
	"github.com/jchv/go-webview2"
)

func main() {
	if !ensureSingleInstance() {
		return
	}

	// 1. Resolve application and data directory
	exe, err := os.Executable()
	baseDir := "."
	if err == nil {
		baseDir = filepath.Dir(exe)
	}
	dataDir := filepath.Join(baseDir, "data")
	_ = os.MkdirAll(dataDir, 0755)

	// 2. Setup persistent file logging
	logFile, err := os.OpenFile(filepath.Join(baseDir, "app.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		defer logFile.Close()
		log.SetOutput(logFile)
	}

	log.Println("=======================================================")
	log.Println("   AERO OS - 跨平台超级桌面工作台启动 (Windows)        ")
	log.Println("=======================================================")

	// 3. Initialize SQLite embedded database
	dbPath := filepath.Join(dataDir, "app.db")
	appDB, err := db.InitDB(dbPath)
	if err != nil {
		log.Fatalf("初始化本地数据库失败: %v", err)
	}
	defer db.CloseDB()

	// Reset stale running profile states
	_, _ = appDB.Exec(`UPDATE profiles SET status = 'stopped' WHERE status = 'running'`)

	// 4. Background sanitize firefox kernels
	go func() {
		if kEntries, err := os.ReadDir(filepath.Join(dataDir, "kernels")); err == nil {
			for _, e := range kEntries {
				if e.IsDir() && strings.HasPrefix(e.Name(), "firefox") {
					kernel.SanitizeFirefoxKernel(filepath.Join(dataDir, "kernels", e.Name()))
				}
			}
		}
	}()

	// 5. Initialize Subsystems
	detector := NewWindowsSysProxyDetector()
	appService := service.InitAppService(appDB, detector, dataDir, 0)

	netBridge := netcore.NewClientBridge(netcore.DefaultAPIEndpoint)
	netDaemon := netcore.NewClientDaemon(netBridge)
	go func() {
		_ = netDaemon.EnsureRunning()
	}()

	aiStore := aitools.NewToolStore(dataDir)
	aiScanner := aitools.NewScanner(aiStore)
	aiExecutor := aitools.NewExecutor(aiScanner, "127.0.0.1:55555")

	apiVault := apimatrix.NewAPIVault(dataDir)
	apiTester := apimatrix.NewTester(apiVault, "127.0.0.1:55555")

	historyStore := audit.NewHistoryStore(dataDir)

	// Async VPN check
	config.BackgroundAsyncVPNCheck(func(vpn *config.VPNInfo) {
		if vpn != nil && vpn.Detected {
			log.Printf("[NET] 检测到系统活动 VPN: %s (%s, IP: %s)", vpn.Name, vpn.Type, vpn.IP)
		}
	})

	// 6. Signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("[SHUTDOWN] 收到终止信号，正在关闭 AERO OS...")
		netDaemon.Stop()
		os.Exit(0)
	}()

	// 7. Create Native WebView2 Desktop Window
	wvData := filepath.Join(os.TempDir(), "aero-os-wv-"+strconv.Itoa(os.Getpid()))
	_ = os.MkdirAll(wvData, 0700)
	defer os.RemoveAll(wvData)

	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     false,
		AutoFocus: true,
		DataPath:  wvData,
		WindowOptions: webview2.WindowOptions{
			Title:  "AERO OS",
			Width:  1200,
			Height: 780,
			Center: true,
		},
	})
	if w == nil {
		nativeAlert("AERO OS 启动失败", "需要 Microsoft Edge WebView2 运行时，请检查系统组件。")
		return
	}
	defer w.Destroy()

	w.SetSize(1200, 780, webview2.HintNone)

	// 8. Register all native IPC functions
	deps := &ipc.IPCDependencies{
		AppService:   appService,
		DataDir:      dataDir,
		AppDB:        appDB,
		NetBridge:    netBridge,
		NetDaemon:    netDaemon,
		AIScanner:    aiScanner,
		AIExecutor:   aiExecutor,
		AIToolStore:  aiStore,
		APIVault:     apiVault,
		APITester:    apiTester,
		HistoryStore: historyStore,
		Detector:     detector,
		DirSelector:  selectDirectoryDialog,
	}
	ipc.RegisterAll(w, deps)

	w.Bind("goMinimizeToTray", func() {
		if appHWND != 0 {
			procShowWindow.Call(appHWND, uintptr(SW_HIDE))
		}
	})

	// 9. Load bundled self-contained HTML
	w.SetHtml(ui.GetHTMLUI())

	// 10. Install tray minimization and menu
	setupSystemTray(w)

	log.Println("[READY] AERO OS 桌面窗口就绪，进入消息循环")
	w.Run()

	netDaemon.Stop()
	log.Println("[EXIT] AERO OS 已正常退出")
}
