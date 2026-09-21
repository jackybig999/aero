package ipc

import (
	"database/sql"

	"aisys/connect/os/internal/aitools"
	"aisys/connect/os/internal/apimatrix"
	"aisys/connect/os/internal/audit"
	"aisys/connect/os/internal/domain/proxy"
	"aisys/connect/os/internal/netcore"
	"aisys/connect/os/internal/service"
)

type IPCBinder interface {
	Bind(name string, f interface{}) error
}

type IPCDependencies struct {
	AppService   *service.AppService
	DataDir      string
	AppDB        *sql.DB
	NetBridge    *netcore.ClientBridge
	NetDaemon    *netcore.ClientDaemon
	AIScanner    *aitools.Scanner
	AIExecutor   *aitools.Executor
	AIToolStore  *aitools.ToolStore
	APIVault     *apimatrix.APIVault
	APITester    *apimatrix.Tester
	HistoryStore *audit.HistoryStore
	Detector     proxy.SysProxyDetector
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
