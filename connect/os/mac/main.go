//go:build darwin

package main

import (
	"log"
	"os"
	"path/filepath"
	"strings"

	"aisys/connect/os/internal/aitools"
	"aisys/connect/os/internal/apimatrix"
	"aisys/connect/os/internal/audit"
	"aisys/connect/os/internal/infra/db"
	"aisys/connect/os/internal/ipc"
	"aisys/connect/os/internal/kernel"
	"aisys/connect/os/internal/netcore"
	"aisys/connect/os/internal/service"
	"aisys/connect/os/internal/ui"
	"github.com/webview/webview_go"
)

func main() {
	exe, err := os.Executable()
	baseDir := "."
	if err == nil {
		baseDir = filepath.Dir(exe)
	}
	dataDir := filepath.Join(baseDir, "data")
	_ = os.MkdirAll(dataDir, 0755)

	logFile, err := os.OpenFile(filepath.Join(baseDir, "app.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		defer logFile.Close()
		log.SetOutput(logFile)
	}

	dbPath := filepath.Join(dataDir, "app.db")
	appDB, err := db.InitDB(dbPath)
	if err != nil {
		log.Fatalf("初始化数据库失败: %v", err)
	}
	defer db.CloseDB()

	_, _ = appDB.Exec(`UPDATE profiles SET status = 'stopped' WHERE status = 'running'`)

	go func() {
		if kEntries, err := os.ReadDir(filepath.Join(dataDir, "kernels")); err == nil {
			for _, e := range kEntries {
				if e.IsDir() && strings.HasPrefix(e.Name(), "firefox") {
					kernel.SanitizeFirefoxKernel(filepath.Join(dataDir, "kernels", e.Name()))
				}
			}
		}
	}()

	detector := NewMacSysProxyDetector()
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

	w := webview.New(false)
	defer w.Destroy()

	w.SetTitle("AERO OS")
	w.SetSize(1200, 780, webview.HintNone)

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
		DirSelector:  func() string { return os.Getenv("HOME") },
	}
	ipc.RegisterAll(w, deps)

	w.SetHtml(ui.GetHTMLUI())
	w.Run()

	netDaemon.Stop()
}
