// Copyright 2026 AERO Protocol Contributors
// Plan.md Phase 2: 单端口 18080 纯 Linux VPS 运营中台主入口 (平铺单包架构)
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	portFlag := flag.String("port", "18080", "middle platform listen port")
	dataDirFlag := flag.String("data", "", "data directory path")
	flag.Parse()

	port := *portFlag
	if p := os.Getenv("PORT"); p != "" {
		port = p
	}

	hmacSecret := os.Getenv("HMAC_SECRET")
	if hmacSecret == "" {
		hmacSecret = "dev-secret-change-me"
		log.Printf("[SECURITY NOTICE] Using default HMAC secret. Set HMAC_SECRET in production!")
	}

	dataDir := *dataDirFlag
	if dataDir == "" {
		dataDir = os.Getenv("DATA_DIR")
	}
	if dataDir == "" {
		candidates := []string{"data", "vpn/data", filepath.Join(filepath.Dir(os.Args[0]), "data")}
		for _, c := range candidates {
			if st, err := os.Stat(c); err == nil && st.IsDir() {
				dataDir = c
				break
			}
		}
		if dataDir == "" {
			dataDir = "data"
		}
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		log.Fatalf("failed to init data dir: %v", err)
	}

	// 1. User & Authentication
	userPath := filepath.Join(dataDir, "users.json")
	var userDB UserStore
	if fStore, err := NewFileUserStore(userPath); err == nil {
		userDB = fStore
		log.Printf("[USER] Initialized file store: %s", userPath)
	} else {
		log.Printf("[WARN] user store fallback to memory: %v", err)
		userDB = NewMemoryUserStore()
	}
	userSvc := NewUserService(userDB, hmacSecret)
	seedAdmin(userSvc, userDB)

	// 2. Billing & Node Registry
	billingSvc := NewBillingService()
	nodeSvc := NewNodeService()

	// 3. Double-Entry Financial Ledger
	ledgerPath := filepath.Join(dataDir, "ledger.db")
	ledgerDB, err := NewSQLiteLedgerStore(ledgerPath)
	if err != nil {
		log.Fatalf("failed to open sqlite ledger: %v", err)
	}
	defer ledgerDB.Close()
	ledgerSvc := NewLedgerService(ledgerDB)

	// 4. Payment In & Out
	payInSvc := NewPayInService("", ledgerSvc)
	payInSvc.SetOnOrderSuccess(func(userID uint64, amountCents int64) {
		months := int32(1)
		planName := "月度套餐"
		if amountCents >= 7999 {
			months = 12
			planName = "年度套餐"
		} else if amountCents >= 2499 {
			months = 3
			planName = "季度套餐"
		}
		_, _ = userSvc.RenewUser(userID, planName, months, amountCents)
	})
	payOutSvc := NewPayOutService(ledgerSvc)

	// 5. AERO Endpoints & SNI Matrix & Subscriptions
	epPath := filepath.Join(dataDir, "aero_endpoints.json")
	epStore, err := NewEndpointStore(epPath)
	if err != nil {
		log.Fatalf("endpoint store failed: %v", err)
	}

	// 6. VPS Asset Management & Probe Engine
	box, err := NewSecretBox()
	if err != nil {
		log.Fatalf("secret box init failed: %v", err)
	}
	vpsPath := filepath.Join(dataDir, "vps.json")
	vpsDB, err := NewFileVPSStore(vpsPath, box)
	if err != nil {
		log.Fatalf("vps file store failed: %v", err)
	}
	vpsSvc := NewVPSService(vpsDB, box, epStore)
	vpsSvc.SetNodeService(nodeSvc)
	vpsSvc.StartPurityTicker(context.Background(), 4*time.Hour)

	sniPath := filepath.Join(dataDir, "sni_matrix.json")
	sniMgr := NewSNIMatrixManager(sniPath)
	subBuilder := NewSubBuilder(userDB, epStore, vpsDB, sniMgr)

	// 7. Auto-sync All VPS Assets & AERO Endpoints into Node Registry
	existingHosts, _ := vpsDB.List()
	existingNodes, _ := nodeSvc.ListAll()
	nodeVPSMap := make(map[uint64]bool)
	for _, n := range existingNodes {
		if n.VPSID > 0 {
			nodeVPSMap[n.VPSID] = true
		}
	}
	for _, h := range existingHosts {
		if !nodeVPSMap[h.ID] {
			targetHost := strings.TrimSpace(h.Domain)
			if targetHost == "" {
				targetHost = h.IP
			}
			_, _ = nodeSvc.CreateNode(h.Name, h.Role, targetHost, "aero-h2", 443, 500, false, 100, h.ID)
		}
	}

	for _, ep := range epStore.List() {
		if !ep.Installed {
			continue
		}
		host := strings.TrimSpace(ep.Host)
		if host == "" || net.ParseIP(host) != nil {
			continue
		}
		port := int32(ep.Port)
		if port <= 0 {
			port = 443
		}
		name := ep.Name
		if name == "" {
			name = fmt.Sprintf("VPS-%d", ep.VPSID)
		}
		nodes, _ := nodeSvc.ListAll()
		matched := false
		for _, n := range nodes {
			if n.VPSID == ep.VPSID {
				_ = nodeSvc.Heartbeat(n.ID, ep.Version)
				matched = true
				break
			}
		}
		if !matched {
			_, _ = nodeSvc.CreateNode(name, ep.Region, host, "aero-h2", port, 500, false, 100, ep.VPSID)
		}
	}

	// 8. HTTP Routing Mux Assembly
	api := http.NewServeMux()
	api.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		hosts, _ := vpsDB.List()
		services := []map[string]any{
			{"name": "user-center", "status": "ok"},
			{"name": "billing", "status": "ok"},
			{"name": "vpn-core", "status": "ok"},
			{"name": "node-manager", "status": "ok"},
			{"name": "vps-manager", "status": "ok"},
			{"name": "aero-deploy", "status": "ok"},
			{"name": "payment-ledger", "status": "ok"},
			{"name": "payment-out", "status": "ok"},
			{"name": "scheduler", "status": "ok"},
			{"name": "state-sync-engine", "status": "ok"},
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status":    "ok",
			"mode":      "single-port",
			"port":      port,
			"product":   "vpsserver-aero",
			"data_dir":  dataDir,
			"vps_count": len(hosts),
			"services":  services,
			"timestamp": time.Now().Unix(),
		})
	})

	NewUserHandler(userSvc).RegisterRoutes(api)
	NewBillingHandler(billingSvc).RegisterRoutes(api)
	NewNodeHandler(nodeSvc).RegisterRoutes(api)
	subBuilder.RegisterRoutes(api)
	NewVPSHandler(vpsSvc).RegisterRoutes(api)
	NewAeroHandler(vpsSvc).RegisterRoutes(api)
	NewPayInHandler(payInSvc).RegisterRoutes(api)
	NewPayOutHandler(payOutSvc).RegisterRoutes(api)
	NewLedgerHandler(ledgerDB).RegisterRoutes(api)

	// Static Web SPA Handlers (Admin + User)
	webDist := FindWebDist()
	webHandler := NewWebHandler(webDist, api)

	gate := &Gate{Verify: userSvc.VerifyToken, Next: webHandler}
	chain := CORSPermissive(Recover(gate))

	fmt.Printf("\n=======================================================\n")
	fmt.Printf("  AERO VPS Middle Platform -> http://127.0.0.1:%s\n", port)
	fmt.Printf("  Data directory: %s\n", dataDir)
	fmt.Printf("  Health:         http://127.0.0.1:%s/health\n", port)
	fmt.Printf("  Sub endpoint:   http://127.0.0.1:%s/sub/{slug}\n", port)
	fmt.Printf("=======================================================\n\n")

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      chain,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}
