package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/vpn-platform/vpsserver/vpn/internal/modules/subscription/service"
)

type Handler struct{ svc *service.Service }

func New(svc *service.Service) *Handler { return &Handler{svc: svc} }

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/subscriptions/", h.Create)
	mux.HandleFunc("GET /api/v1/subscriptions/", h.List)
	mux.HandleFunc("GET /api/v1/subscriptions/config/", h.GetConfig)
	mux.HandleFunc("GET /api/v1/subscriptions/stats/by-node/", h.StatsByNode)
	mux.HandleFunc("POST /api/v1/subscriptions/detach-node/", h.DetachNode)
	mux.HandleFunc("DELETE /api/v1/subscriptions/{id}/", h.Delete)
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
