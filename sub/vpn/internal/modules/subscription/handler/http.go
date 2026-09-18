package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vpn-platform/vpsserver/vpn/internal/modules/subscription/service"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/subscription/snimatrix"
	userStore "github.com/vpn-platform/vpsserver/vpn/internal/modules/user/store"
	aeroEndpoint "github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/aero/endpoint"
)

type Handler struct {
	svc       *service.Service
	userStore userStore.Store
	epStore   *aeroEndpoint.Persist
	sniMgr    *snimatrix.Manager
}

func New(svc *service.Service) *Handler { return &Handler{svc: svc, sniMgr: snimatrix.New("")} }

func NewWithStores(svc *service.Service, uStore userStore.Store, ep *aeroEndpoint.Persist, mgr ...*snimatrix.Manager) *Handler {
	var m *snimatrix.Manager
	if len(mgr) > 0 && mgr[0] != nil {
		m = mgr[0]
	} else {
		m = snimatrix.New("")
	}
	return &Handler{svc: svc, userStore: uStore, epStore: ep, sniMgr: m}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/subscriptions/", h.Create)
	mux.HandleFunc("GET /api/v1/subscriptions/", h.List)
	mux.HandleFunc("GET /api/v1/subscriptions/config/", h.GetConfig)
	mux.HandleFunc("GET /api/v1/subscriptions/stats/by-node/", h.StatsByNode)
	mux.HandleFunc("POST /api/v1/subscriptions/detach-node/", h.DetachNode)
	mux.HandleFunc("DELETE /api/v1/subscriptions/{id}/", h.Delete)
	// 公开订阅下发路由 (双轨支持: /sub/{username}{6位随机码} 以及 老版 /sub/{secret})
	mux.HandleFunc("GET /sub/{param}", h.ServeSub)
}

func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID     uint64 `json:"user_id"`
		NodeID     uint64 `json:"node_id"`
		UUID       string `json:"uuid"`
		NodeName   string `json:"node_name"`
		NodeIP     string `json:"node_ip"`
		NodePort   int32  `json:"node_port"`
		ExpireDate string `json:"expire_date"`
		Days       int    `json:"days"` // optional convenience: days from now
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 422, errResp(1002, "invalid body"))
		return
	}

	var expire time.Time
	var err error
	if req.ExpireDate != "" {
		expire, err = time.Parse(time.RFC3339, req.ExpireDate)
		if err != nil {
			// try date only
			expire, err = time.Parse("2006-01-02", req.ExpireDate)
			if err != nil {
				writeJSON(w, 422, errResp(1002, "invalid expire_date"))
				return
			}
			expire = expire.Add(23*time.Hour + 59*time.Minute)
		}
	} else if req.Days > 0 {
		expire = time.Now().AddDate(0, 0, req.Days)
	} else {
		expire = time.Now().AddDate(0, 1, 0) // default 1 month
	}

	sub, err := h.svc.CreateSubscription(req.UserID, req.NodeID, req.UUID,
		req.NodeName, req.NodeIP, req.NodePort, expire)
	if err != nil {
		writeJSON(w, 422, errResp(1002, err.Error()))
		return
	}
	writeJSON(w, 201, dataResp(sub))
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	uidStr := r.URL.Query().Get("user_id")
	if uidStr != "" {
		uid, _ := strconv.ParseUint(uidStr, 10, 64)
		subs, _ := h.svc.ListByUser(uid)
		writeJSON(w, 200, map[string]any{"code": 0, "data": map[string]any{"results": subs}})
		return
	}
	subs, _ := h.svc.ListAll()
	writeJSON(w, 200, map[string]any{"code": 0, "data": map[string]any{"results": subs}})
}

// GetConfig is PUBLIC — called by VPN clients, no auth required.
func (h *Handler) GetConfig(w http.ResponseWriter, r *http.Request) {
	uuid := r.URL.Query().Get("uuid")
	if uuid == "" {
		writeJSON(w, 422, errResp(1002, "uuid required"))
		return
	}
	cfg, err := h.svc.GetConfig(uuid)
	if err != nil {
		writeJSON(w, 404, errResp(1001, err.Error()))
		return
	}
	writeJSON(w, 200, dataResp(cfg))
}

func (h *Handler) StatsByNode(w http.ResponseWriter, r *http.Request) {
	m, err := h.svc.NodeSubCounts()
	if err != nil {
		writeJSON(w, 500, errResp(1006, err.Error()))
		return
	}
	// JSON object keys as strings
	out := map[string]int{}
	for k, v := range m {
		out[strconv.FormatUint(k, 10)] = v
	}
	writeJSON(w, 200, dataResp(out))
}

func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	h.svc.DeleteSubscription(id)
	writeJSON(w, 200, okResp())
}

// DetachNode removes all subscriptions bound to a node (called when VPS/node is removed).
func (h *Handler) DetachNode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NodeID uint64 `json:"node_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.NodeID == 0 {
		writeJSON(w, 422, errResp(1002, "node_id required"))
		return
	}
	deact, del, err := h.svc.DetachNode(req.NodeID)
	if err != nil {
		writeJSON(w, 422, errResp(1002, err.Error()))
		return
	}
	writeJSON(w, 200, map[string]any{
		"code": 0,
		"data": map[string]any{"deactivated": deact, "deleted": del, "node_id": req.NodeID},
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func errResp(code int, msg string) map[string]any {
	return map[string]any{"code": code, "message": msg}
}

func dataResp(v any) map[string]any {
	return map[string]any{"code": 0, "data": v}
}

func okResp() map[string]any {
	return map[string]any{"code": 0, "message": "success"}
}

// ServeSub 处理公开订阅获取：优先匹配用户专属 Slug，次优先匹配节点老版 32-hex Secret
func (h *Handler) ServeSub(w http.ResponseWriter, r *http.Request) {
	param := r.PathValue("param")
	if param == "" {
		param = strings.TrimPrefix(r.URL.Path, "/sub/")
		param = strings.Trim(param, "/")
	}
	if param == "" {
		http.NotFound(w, r)
		return
	}

	// 轨道 1: 检查是否匹配用户专属 Slug (格式: {username}{6位随机码})
	if h.userStore != nil {
		if user, err := h.userStore.GetUserBySlug(param); err == nil && user != nil {
			if !user.Status {
				http.Error(w, "User disabled", http.StatusForbidden)
				return
			}
			if !user.ExpireAt.IsZero() && time.Now().After(user.ExpireAt) {
				http.Error(w, "Subscription expired", http.StatusForbidden)
				return
			}

			isp := r.URL.Query().Get("isp")

			// 聚合所有在线 VPS 节点，并根据客户端网络及节点区域计算最优伪装 SNI
			var servers []map[string]any
			if h.epStore != nil {
				for _, ep := range h.epStore.List() {
					host := ep.Host
					if host == "" {
						host = ep.IP
					}
					port := ep.Port
					if port <= 0 {
						port = 443
					}
					name := ep.Name
					if name == "" {
						name = fmt.Sprintf("VPS-%d", ep.VPSID)
					}
					token := user.SubToken
					if token == "" {
						token = "usr_" + user.Username
					}
					sni := host
					if h.sniMgr != nil {
						matched := h.sniMgr.Match(isp, name+" "+host)
						if matched != "" {
							sni = matched
						}
					}
					servers = append(servers, map[string]any{
						"name":     name,
						"address":  fmt.Sprintf("%s:%d", host, port),
						"token":    token,
						"sni":      sni,
						"protocol": "tcp_h2",
					})
				}
			}

			if len(servers) == 0 {
				defaultSNI := "edge.microsoft.com"
				if h.sniMgr != nil {
					defaultSNI = h.sniMgr.Match(isp, "DEFAULT")
				}
				servers = append(servers, map[string]any{
					"name":     "Default-Edge",
					"address":  "127.0.0.1:443",
					"token":    user.SubToken,
					"sni":      defaultSNI,
					"protocol": "tcp_h2",
				})
			}

			expireUnix := int64(0)
			if !user.ExpireAt.IsZero() {
				expireUnix = user.ExpireAt.Unix()
			} else {
				expireUnix = time.Now().AddDate(1, 0, 0).Unix()
			}

			doc := map[string]any{
				"version":   "aero/2.0",
				"userId":    user.Username,
				"slug":      user.SubSlug,
				"expireAt":  expireUnix,
				"createdAt": user.CreatedAt.Unix(),
				"servers":   servers,
				"optimization": map[string]any{
					"defaultQoS": "ultra-low-latency",
					"ispMatched": isp,
				},
			}

			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(doc)
			return
		}
	}

	// 轨道 2: 保持 100% 兼容老单节点密钥
	if h.epStore != nil {
		for _, ep := range h.epStore.List() {
			if ep.SubSecret != "" && ep.SubSecret == param {
				host := ep.Host
				if host == "" {
					host = ep.IP
				}
				port := ep.Port
				if port <= 0 {
					port = 443
				}
				doc := map[string]any{
					"version":   "aero/2.0",
					"createdAt": ep.UpdatedAt.Unix(),
					"servers": []map[string]any{
						{
							"name":     ep.Name,
							"address":  fmt.Sprintf("%s:%d", host, port),
							"token":    ep.SubSecret,
							"sni":      host,
							"protocol": "tcp_h2",
						},
					},
				}
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.Header().Set("Cache-Control", "no-store")
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(doc)
				return
			}
		}
	}

	http.NotFound(w, r)
}

