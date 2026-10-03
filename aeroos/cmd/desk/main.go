package main

import (
	"embed"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/aero-protocol/aero/aeroos/internal/desk"
)

//go:embed all:ui
var uiFS embed.FS

// getHTMLUI returns the bundled HTML page with inlined CSS and JS for webview
func getHTMLUI() string {
	indexHTML, err := uiFS.ReadFile("ui/index.html")
	if err != nil {
		return "<html><body><h3>Failed to load UI assets</h3></body></html>"
	}
	styleCSS, _ := uiFS.ReadFile("ui/style.css")
	bridgeJS, _ := uiFS.ReadFile("ui/bridge.js")
	appJS, _ := uiFS.ReadFile("ui/app.js")

	html := string(indexHTML)

	cssTag := fmt.Sprintf("<style>\n%s\n</style>", string(styleCSS))
	html = strings.Replace(html, `<link rel="stylesheet" href="style.css" />`, cssTag, 1)

	bridgeTag := fmt.Sprintf("<script>\n%s\n</script>", string(bridgeJS))
	html = strings.Replace(html, `<script src="bridge.js"></script>`, bridgeTag, 1)

	appTag := fmt.Sprintf("<script>\n%s\n</script>", string(appJS))
	html = strings.Replace(html, `<script src="app.js"></script>`, appTag, 1)

	return html
}

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
	log.Println("   AERO OS - 跨平台超级桌面工作台启动                  ")
	log.Println("=======================================================")

	// 3. Initialize SQLite embedded database
	dbPath := filepath.Join(dataDir, "app.db")
	appDB, err := desk.InitDB(dbPath)
	if err != nil {
		log.Fatalf("初始化本地数据库失败: %v", err)
	}
	defer desk.CloseDB()

	// Reset stale running profile states
	_, _ = appDB.Exec(`UPDATE profiles SET status = 'stopped' WHERE status = 'running'`)

	// 4. Background sanitize firefox kernels
	go func() {
		if kEntries, err := os.ReadDir(filepath.Join(dataDir, "kernels")); err == nil {
			for _, e := range kEntries {
				if e.IsDir() && strings.HasPrefix(e.Name(), "firefox") {
					desk.SanitizeFirefoxKernel(filepath.Join(dataDir, "kernels", e.Name()))
				}
			}
		}
	}()

	// 5. Initialize Subsystems (Zero host tampering)
	detector := &desk.NoopSysProxyDetector{}
	appService := desk.InitAppService(appDB, detector, dataDir, 0)

	netBridge := desk.NewClientBridge(desk.DefaultAPIEndpoint)
	netDaemon := desk.NewClientDaemon(netBridge)
	go func() {
		_ = netDaemon.EnsureRunning()
	}()

	aiStore := desk.NewToolStore(dataDir)
	aiScanner := desk.NewScanner(aiStore)
	aiExecutor := desk.NewExecutor(aiScanner, "127.0.0.1:55555")

	apiVault := desk.NewAPIVault(dataDir)
	apiTester := desk.NewTester(apiVault, "127.0.0.1:55555")

	historyStore := desk.NewHistoryStore(dataDir)

	// Async VPN check
	desk.BackgroundAsyncVPNCheck(func(vpn *desk.VPNInfo) {
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

	// 7. Register all native IPC functions and launch window
	deps := &desk.IPCDependencies{
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

	runDesktopWindow(deps, netDaemon)
}
