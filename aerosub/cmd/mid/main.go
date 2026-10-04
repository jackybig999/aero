// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package main provides the single-binary entrypoint for the AERO Midplatform Control Plane.
package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aero-protocol/aero/aerosub/internal/mid"
)

//go:embed all:web
var embeddedWebFS embed.FS

func main() {
	hostFlag := flag.String("host", "0.0.0.0", "middle platform listen host")
	portFlag := flag.String("port", "18080", "middle platform listen port")
	dataDirFlag := flag.String("data", "", "data directory path")
	flag.Parse()

	host := *hostFlag
	if h := os.Getenv("HOST"); h != "" {
		host = h
	}
	port := *portFlag
	if p := os.Getenv("PORT"); p != "" {
		port = p
	}

	dataDir := *dataDirFlag
	if dataDir == "" {
		dataDir = os.Getenv("DATA_DIR")
	}
	if dataDir == "" {
		candidates := []string{"aerosub/data", "data", filepath.Join(filepath.Dir(os.Args[0]), "data")}
		for _, c := range candidates {
			if st, err := os.Stat(c); err == nil && st.IsDir() {
				dataDir = c
				break
			}
		}
		if dataDir == "" {
			dataDir = "aerosub/data"
		}
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		log.Fatalf("failed to init data dir: %v", err)
	}

	hmacSecret := os.Getenv("HMAC_SECRET")
	if hmacSecret == "" {
		keyPath := filepath.Join(dataDir, "hmac.key")
		if b, err := os.ReadFile(keyPath); err == nil && len(strings.TrimSpace(string(b))) >= 32 {
			hmacSecret = strings.TrimSpace(string(b))
			log.Printf("[SECURITY] Loaded persistent HMAC secret from %s", keyPath)
		} else {
			raw := make([]byte, 32)
			if _, err := rand.Read(raw); err != nil {
				log.Fatalf("[FATAL] failed to generate CSPRNG HMAC secret: %v", err)
			}
			hmacSecret = hex.EncodeToString(raw)
			if err := os.WriteFile(keyPath, []byte(hmacSecret), 0o600); err != nil {
				log.Fatalf("[FATAL] failed to persist HMAC secret: %v", err)
			}
			log.Printf("[SECURITY] Generated new 256-bit persistent HMAC secret at %s", keyPath)
		}
	}

	// 1. Double-Entry Financial Ledger & Settlement Database (aeropay.db)
	payDBPath := filepath.Join(dataDir, "aeropay.db")
	payDB, err := mid.NewAeroPayDB(payDBPath)
	if err != nil {
		log.Fatalf("failed to open aeropay db: %v", err)
	}
	defer payDB.Close()
	ledgerSvc := mid.NewLedgerService(payDB)

	// 2. Master Platform Database (aero.db)
	aeroDBPath := filepath.Join(dataDir, "aero.db")
	aeroDB, err := mid.NewAeroDB(aeroDBPath, payDB)
	if err != nil {
		log.Fatalf("failed to open aero db: %v", err)
	}
	defer aeroDB.Close()

	userDB := aeroDB
	userSvc := mid.NewUserService(userDB, hmacSecret)
	mid.SeedAdmin(userSvc, userDB)

	// 3. Billing & Node Registry
	billingSvc := mid.NewBillingService(aeroDB)
	nodeSvc := mid.NewNodeService()

	// 4. Payment In & Out
	payInSvc := mid.NewPayInService("", ledgerSvc)
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
	payOutSvc := mid.NewPayOutService(ledgerSvc)

	// 5. AERO Endpoints & SNI Matrix & Subscriptions
	epPath := filepath.Join(dataDir, "aero_endpoints.json")
	epStore, err := mid.NewEndpointStore(epPath)
	if err != nil {
		log.Fatalf("endpoint store failed: %v", err)
	}

	// 6. VPS Asset Management & Probe Engine
	box, err := mid.NewSecretBox()
	if err != nil {
		log.Fatalf("secret box init failed: %v", err)
	}
	vpsPath := filepath.Join(dataDir, "vps.json")
	vpsDB, err := mid.NewFileVPSStore(vpsPath, box)
	if err != nil {
		log.Fatalf("vps file store failed: %v", err)
	}
	vpsSvc := mid.NewVPSService(vpsDB, box, epStore)
	vpsSvc.SetNodeService(nodeSvc)
	vpsSvc.SetUserStore(userDB)
	vpsSvc.StartPurityTicker(context.Background(), 4*time.Hour)

	sniPath := filepath.Join(dataDir, "sni_matrix.json")
	sniMgr := mid.NewSNIMatrixManager(sniPath)
	subBuilder := mid.NewSubBuilder(userDB, epStore, vpsDB, sniMgr)

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
		ep, ok := epStore.Get(h.ID)
		if !ok || !ep.Installed {
			continue
		}
		if !nodeVPSMap[h.ID] {
			targetHost := strings.TrimSpace(h.Domain)
			if targetHost == "" {
				targetHost = h.IP
			}
			_, _ = nodeSvc.CreateNode(h.Name, h.Role, targetHost, "aero-quic", 443, 500, false, 100, h.ID)
		}
	}

	for _, ep := range epStore.List() {
		var hostFound bool
		for _, h := range existingHosts {
			if h.ID == ep.VPSID {
				hostFound = true
				break
			}
		}
		if !hostFound {
			_ = epStore.Delete(ep.VPSID)
			continue
		}
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
		region := ep.Region
		if region == "" || strings.HasPrefix(region, "VPS") || !strings.Contains(region, "AS") {
			region = mid.ResolveIPRegion(ep.IP)
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
			_, _ = nodeSvc.CreateNode(name, region, host, "aero-quic", port, 500, false, 100, ep.VPSID)
		}
	}

	// 8. HTTP Routing Mux Assembly
	api := http.NewServeMux()
	healthHandler := func(w http.ResponseWriter, r *http.Request) {
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
		mid.WriteJSON(w, http.StatusOK, map[string]any{
			"status":    "ok",
			"mode":      "single-port",
			"port":      port,
			"product":   "vpsserver-aero",
			"data_dir":  dataDir,
			"vps_count": len(hosts),
			"services":  services,
			"timestamp": time.Now().Unix(),
		})
	}
	api.HandleFunc("GET /health", healthHandler)
	api.HandleFunc("GET /healthz", healthHandler)

	api.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		hosts, _ := vpsDB.List()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "# HELP aero_vps_total Total number of managed VPS instances\n")
		fmt.Fprintf(w, "# TYPE aero_vps_total gauge\n")
		fmt.Fprintf(w, "aero_vps_total %d\n", len(hosts))
		fmt.Fprintf(w, "# HELP aero_up Middle platform service up status\n")
		fmt.Fprintf(w, "# TYPE aero_up gauge\n")
		fmt.Fprintf(w, "aero_up 1\n")
	})

	userHandler := mid.NewUserHandler(userSvc)
	userHandler.SetSubBuilder(subBuilder)
	userHandler.RegisterRoutes(api)
	mid.NewBillingHandler(billingSvc).RegisterRoutes(api)
	nodeHandler := mid.NewNodeHandler(nodeSvc, vpsDB)
	nodeHandler.SetVPSService(vpsSvc)
	nodeHandler.SetAeroDB(aeroDB)
	nodeHandler.RegisterRoutes(api)
	subBuilder.RegisterRoutes(api)
	mid.NewVPSHandler(vpsSvc).RegisterRoutes(api)
	mid.NewAeroHandler(vpsSvc).RegisterRoutes(api)
	payInHandler := mid.NewPayInHandler(payInSvc)
	payInHandler.SetDeps(userDB, billingSvc, userSvc, vpsSvc)
	payInHandler.RegisterRoutes(api)
	mid.NewPayOutHandler(payOutSvc).RegisterRoutes(api)
	mid.NewLedgerHandler(payDB).RegisterRoutes(api)

	// Static Web SPA Handlers with Embedded FS & Disk Fallback
	webDist := mid.FindWebDist()
	webHandler := mid.NewFSWebHandler(embeddedWebFS, webDist, api)

	gate := &mid.Gate{Verify: userSvc.VerifyToken, Next: webHandler}
	chain := mid.CORSPermissive(mid.Recover(gate))

	fmt.Printf("\n=======================================================\n")
	fmt.Printf("  AERO VPS Middle Platform -> :%s\n", port)
	fmt.Printf("  Data directory: %s\n", dataDir)
	fmt.Printf("  Health:         /health\n")
	fmt.Printf("  Native Domain Sub:  https://<domain>/sub/superadmin\n")
	fmt.Printf("  User Domain Sub:    https://<domain>/sub/<user_slug>\n")
	fmt.Printf("=======================================================\n\n")

	listenAddr := net.JoinHostPort(host, port)
	server := &http.Server{
		Addr:         listenAddr,
		Handler:      chain,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}
