// VPN 中台主程序 — 单端口
//
//	/login   普通用户订阅
//	/admin/  管理后台
//	/health  健康检查
//	/api/v1/ 业务 API
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/vpn-platform/vpsserver/vpn/internal/middleware"
	"github.com/vpn-platform/vpsserver/vpn/internal/web"

	billingH "github.com/vpn-platform/vpsserver/vpn/internal/modules/billing/handler"
	billingS "github.com/vpn-platform/vpsserver/vpn/internal/modules/billing/service"
	billingStore "github.com/vpn-platform/vpsserver/vpn/internal/modules/billing/store"

	nodeH "github.com/vpn-platform/vpsserver/vpn/internal/modules/node/handler"
	nodeS "github.com/vpn-platform/vpsserver/vpn/internal/modules/node/service"
	nodeStore "github.com/vpn-platform/vpsserver/vpn/internal/modules/node/store"

	payInH "github.com/vpn-platform/vpsserver/vpn/internal/modules/pay/in/handler"
	payInS "github.com/vpn-platform/vpsserver/vpn/internal/modules/pay/in/service"

	ledgerH "github.com/vpn-platform/vpsserver/vpn/internal/modules/pay/ledger/handler"
	ledgerS "github.com/vpn-platform/vpsserver/vpn/internal/modules/pay/ledger/service"
	ledgerStore "github.com/vpn-platform/vpsserver/vpn/internal/modules/pay/ledger/store"

	payOutH "github.com/vpn-platform/vpsserver/vpn/internal/modules/pay/out/handler"
	payOutS "github.com/vpn-platform/vpsserver/vpn/internal/modules/pay/out/service"

	settleH "github.com/vpn-platform/vpsserver/vpn/internal/modules/pay/settlement/handler"
	settleS "github.com/vpn-platform/vpsserver/vpn/internal/modules/pay/settlement/service"

	"github.com/vpn-platform/vpsserver/vpn/internal/modules/user/domain"
	userH "github.com/vpn-platform/vpsserver/vpn/internal/modules/user/handler"
	userS "github.com/vpn-platform/vpsserver/vpn/internal/modules/user/service"
	userStore "github.com/vpn-platform/vpsserver/vpn/internal/modules/user/store"

	subH "github.com/vpn-platform/vpsserver/vpn/internal/modules/subscription/handler"
	subS "github.com/vpn-platform/vpsserver/vpn/internal/modules/subscription/service"
	snimatrix "github.com/vpn-platform/vpsserver/vpn/internal/modules/subscription/snimatrix"
	subStore "github.com/vpn-platform/vpsserver/vpn/internal/modules/subscription/store"

	aeroEndpoint "github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/aero/endpoint"
	aeroH "github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/aero/handler"
	aeroS "github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/aero/service"
	aeroStore "github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/aero/store"
	vpsH "github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/handler"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/secret"
	vpsS "github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/service"
	vpsStore "github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/store"
)

var modules = []string{
	"login", "admin", "billing", "subscriptions", "nodes", "vps", "aero",
	"pay", "ledger", "settlement", "config", "sync",
}

type YamlConfig struct {
	Server struct {
		Port int    `yaml:"port"`
		Host string `yaml:"host"`
	} `yaml:"server"`
	Data struct {
		Dir string `yaml:"dir"`
	} `yaml:"data"`
	Security struct {
		HMACSecret string `yaml:"hmac_secret"`
		SSHCredKey string `yaml:"ssh_cred_key"`
	} `yaml:"security"`
	Aero struct {
		GithubRepo   string `yaml:"github_repo"`
		FollowLatest bool   `yaml:"follow_latest"`
		LocalBin     string `yaml:"local_bin"`
	} `yaml:"aero"`
	Web struct {
		Root string `yaml:"root"`
	} `yaml:"web"`
}

func loadConfigFile() *YamlConfig {
	candidates := []string{
		"config/config.yaml",
		"../config/config.yaml",
		"../../config/config.yaml",
		filepath.Join(filepath.Dir(os.Args[0]), "config", "config.yaml"),
		filepath.Join(filepath.Dir(os.Args[0]), "..", "config", "config.yaml"),
	}
	for _, p := range candidates {
		data, err := os.ReadFile(p)
		if err == nil {
			var cfg YamlConfig
			if err := yaml.Unmarshal(data, &cfg); err == nil {
				log.Printf("[CONFIG] Loaded configuration from %s (port=%d)", p, cfg.Server.Port)
				return &cfg
			}
		}
	}
	return nil
}

func main() {
	cfg := loadConfigFile()

	port := "18080"
	if cfg != nil && cfg.Server.Port > 0 {
		port = strconv.Itoa(cfg.Server.Port)
	}
	if p := os.Getenv("PORT"); p != "" {
		port = p
	}

	hmacSecret := "dev-secret-change-me"
	if cfg != nil && cfg.Security.HMACSecret != "" {
		hmacSecret = cfg.Security.HMACSecret
	}
	if s := os.Getenv("HMAC_SECRET"); s != "" {
		hmacSecret = s
	}
	if hmacSecret == "dev-secret-change-me" {
		log.Printf("[SECURITY NOTICE] Using default HMAC secret. Set HMAC_SECRET in config or env for production!")
	}

	if cfg != nil && cfg.Security.SSHCredKey != "" && os.Getenv("SSH_CRED_KEY") == "" {
		_ = os.Setenv("SSH_CRED_KEY", cfg.Security.SSHCredKey)
	}
	if cfg != nil && cfg.Aero.LocalBin != "" && os.Getenv("AERO_LOCAL_BIN") == "" {
		_ = os.Setenv("AERO_LOCAL_BIN", cfg.Aero.LocalBin)
	}
	if cfg != nil && cfg.Web.Root != "" && os.Getenv("WEB_ROOT") == "" {
		_ = os.Setenv("WEB_ROOT", cfg.Web.Root)
	}

	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" && cfg != nil && cfg.Data.Dir != "" {
		if st, err := os.Stat(cfg.Data.Dir); err == nil && st.IsDir() {
			dataDir = cfg.Data.Dir
		}
	}
	if dataDir == "" {
		candidates := []string{"data", "vpn/data", "../vpn/data", filepath.Join(filepath.Dir(os.Args[0]), "data")}
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
		log.Fatalf("data dir: %v", err)
	}

	userPath := filepath.Join(dataDir, "users.json")
	var userDB userStore.Store
	fStore, err := userStore.NewFileStore(userPath)
	if err != nil {
		log.Printf("[WARN] user file store failed (%v), falling back to memory", err)
		userDB = userStore.NewMemoryStore()
	} else {
		userDB = fStore
		log.Printf("user store: %s", userPath)
	}
	userSvc := userS.New(userDB, hmacSecret)
	seedAdmin(userSvc, userDB)

	billingSvc := billingS.New(billingStore.NewMemoryStore())
	nodeSvc := nodeS.New(nodeStore.NewMemoryStore())
	subSvc := subS.New(subStore.NewMemoryStore())

	ledgerPath := filepath.Join(dataDir, "ledger.db")
	var ledgerDB ledgerStore.Store
	if lStore, err := ledgerStore.NewSQLiteStore(ledgerPath); err == nil {
		ledgerDB = lStore
		log.Printf("ledger store: %s", ledgerPath)
	} else {
		log.Printf("[WARN] ledger sqlite store failed (%v), falling back to memory", err)
		ledgerDB = ledgerStore.NewMemoryStore()
	}
	ledgerSvc := ledgerS.New(ledgerDB)

	ledgerURL := env("LEDGER_URL", "http://127.0.0.1:"+port)
	payInSvc := payInS.New(ledgerURL)
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
	payOutSvc := payOutS.New()
	settleSvc := settleS.New()

	box, err := secret.NewBox()
	if err != nil {
		log.Fatalf("ssh crypto: %v", err)
	}
	vpsPath := filepath.Join(dataDir, "vps.json")
	vpsDB, err := vpsStore.NewFileStore(vpsPath, box)
	if err != nil {
		log.Fatalf("vps store: %v", err)
	}
	if n, _ := vpsDB.List(); len(n) > 0 {
		log.Printf("vps store: loaded %d host(s) from %s", len(n), vpsPath)
	} else {
		log.Printf("vps store: %s (empty)", vpsPath)
	}
	vpsSvc := vpsS.New(vpsDB, box)
	// 启动 VPS 真实出口 IP 纯净度后台例行巡检（每 4 小时）
	vpsSvc.StartPurityTicker(context.Background(), 4*time.Hour)

	epPath := filepath.Join(dataDir, "aero_endpoints.json")
	epStore, err := aeroEndpoint.NewPersist(epPath)
	if err != nil {
		log.Fatalf("aero endpoints: %v", err)
	}
	if n := len(epStore.List()); n > 0 {
		log.Printf("aero endpoints: loaded %d from %s", n, epPath)
	}
	aeroSvc := aeroS.NewWithEndpoints(aeroStore.NewMemoryStore(), vpsS.NewProvider(vpsSvc), epStore)

	// 自动联动：AERO 部署/刷新成功自动推送到节点管理，免手动录入
	syncNode := func(ep aeroEndpoint.Info) {
		if !ep.Installed {
			return
		}
		host := strings.TrimSpace(ep.Host)
		// 铁律：没有有效域名的节点严禁推送到节点管理，杜绝裸 IP 泄露
		if host == "" || net.ParseIP(host) != nil {
			return
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
		for _, n := range nodes {
			if n.VPSID == ep.VPSID {
				_ = nodeSvc.Heartbeat(n.ID, ep.Version)
				return
			}
		}
		_, _ = nodeSvc.CreateNode(name, ep.Region, host, "aero-h2", port, 500, false, 100, ep.VPSID)
	}
	aeroSvc.SetNodeSyncer(syncNode)
	for _, ep := range epStore.List() {
		syncNode(ep)
	}

	api := http.NewServeMux()
	api.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		svcs := make([]map[string]string, 0, len(modules))
		for _, m := range modules {
			svcs = append(svcs, map[string]string{"name": m, "status": "ok"})
		}
		vpsN, _ := vpsDB.List()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "ok", "mode": "single-port", "port": port,
			"product": "vpsserver",
			"data_dir": dataDir,
			"vps_count": len(vpsN),
			"paths": map[string]string{
				"user_login": "/login", "admin": "/admin/", "aero_ui": "/aero-ui/",
				"health": "/health", "api": "/api/v1/",
			},
			"services": svcs,
		})
	})

	userH.New(userSvc).RegisterRoutes(api)
	billingH.New(billingSvc).RegisterRoutes(api)
	nodeH.New(nodeSvc).RegisterRoutes(api)
	sniPath := filepath.Join(dataDir, "sni_matrix.json")
	sniMgr := snimatrix.New(sniPath)
	subHandler := subH.NewWithStores(subSvc, userDB, epStore, sniMgr)
	subHandler.SetVPSStore(vpsDB)
	subHandler.RegisterRoutes(api)
	vpsH.New(vpsSvc).RegisterRoutes(api)
	aeroH.New(aeroSvc).RegisterRoutes(api)
	payInH.New(payInSvc).RegisterRoutes(api)
	payOutH.New(payOutSvc).RegisterRoutes(api)
	ledgerH.New(ledgerSvc).RegisterRoutes(api)
	settleH.New(settleSvc).RegisterRoutes(api)

	dist := web.FindDist()
	pages := web.Handler(dist)
	split := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if p == "/health" || strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/sub/") {
			api.ServeHTTP(w, r)
			return
		}
		pages.ServeHTTP(w, r)
	})

	gate := &middleware.Gate{Verify: userSvc.VerifyToken, Next: split}
	handler := middleware.CORSPermissive(middleware.Recover(gate))

	fmt.Printf("\n  vpsserver → http://127.0.0.1:%s\n", port)
	fmt.Printf("    /login    用户订阅\n")
	fmt.Printf("    /sub/     专属订阅分发 (/sub/{username}{6位随机码})\n")
	fmt.Printf("    /admin/   管理后台\n")
	fmt.Printf("    /aero-ui/ AERO 模块控制台\n")
	fmt.Printf("    /health   健康检查\n")
	fmt.Printf("    data:    %s  (VPS/端点持久化，重启不丢)\n", dataDir)
	fmt.Printf("    user:    %s\n", empty(dist.UserDist, "(missing)"))
	fmt.Printf("    admin:   %s\n", empty(dist.AdminDist, "(missing)"))
	fmt.Printf("    aero-ui: %s\n\n", empty(dist.AeroUIDist, "(missing)"))
	log.Fatal(http.ListenAndServe(":"+port, handler))
}

func empty(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}
func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}
func seedAdmin(svc *userS.Service, db userStore.Store) {
	initPwd := os.Getenv("ADMIN_INIT_PASSWORD")
	if initPwd == "" {
		initPwd = "admin123"
	}
	existing, err := db.GetUserByUsername("admin")
	if err == nil && existing != nil {
		if !existing.IsStaff {
			db.SetStaff(existing.ID, true)
		}
		if existing.PasswordHash == "" {
			db.SetPassword(existing.ID, userS.HashPassword(initPwd))
		}
	} else {
		u, err := svc.Register(domain.CreateUserParams{
			Username: "admin", Password: initPwd, Email: "admin@vpn.local",
		})
		if err == nil && u != nil {
			db.SetStaff(u.ID, true)
		}
	}
}
