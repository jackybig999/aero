package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/vpn-platform/vpsserver/vpn/internal/modules/node/service"
)

type Handler struct{ svc *service.Service }

func New(svc *service.Service) *Handler { return &Handler{svc: svc} }

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/nodes/", h.Create)
	mux.HandleFunc("GET /api/v1/nodes/", h.List)
	mux.HandleFunc("GET /api/v1/nodes/available/", h.Available)
	// Cascade: DELETE collection with ?vps_id=&ip= (avoids conflict with {id} patterns)
	mux.HandleFunc("DELETE /api/v1/nodes/", h.CascadeDelete)
	mux.HandleFunc("GET /api/v1/nodes/{id}/", h.Get)
	mux.HandleFunc("POST /api/v1/nodes/{id}/heartbeat/", h.Heartbeat)
	mux.HandleFunc("DELETE /api/v1/nodes/{id}/", h.Delete)
}

func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string `json:"name"`
		Region   string `json:"region"`
		IP       string `json:"ip"`
		Protocol string `json:"protocol"`
		Port     int32  `json:"port"`
		MaxUsers int32  `json:"max_users"`
		IsBackup bool   `json:"is_backup"`
		Weight   int32  `json:"weight"`
		VPSID    uint64 `json:"vps_id"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if req.Protocol == "" {
		req.Protocol = "aero"
	}
	if req.Port == 0 { req.Port = 443 }
	if req.MaxUsers == 0 { req.MaxUsers = 100 }
	if req.Weight == 0 { req.Weight = 1 }

	n, err := h.svc.CreateNode(req.Name, req.Region, req.IP, req.Protocol, req.Port, req.MaxUsers, req.IsBackup, req.Weight, req.VPSID)
	if err != nil {
		writeJSON(w, 422, errResp(1002, err.Error()))
		return
	}
	writeJSON(w, 201, dataResp(n))
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	// Admin list: all nodes (online + offline)
	nodes, _ := h.svc.ListAll()
	writeJSON(w, 200, map[string]any{"code": 0, "data": map[string]any{"results": nodes}})
}

func (h *Handler) Available(w http.ResponseWriter, r *http.Request) {
	nodes, _ := h.svc.ListAvailable()
	writeJSON(w, 200, dataResp(nodes))
}

func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	n, err := h.svc.GetNode(id)
	if err != nil {
		writeJSON(w, 404, errResp(1001, "not found"))
		return
	}
	writeJSON(w, 200, dataResp(n))
}

func (h *Handler) Heartbeat(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	var req struct{ AgentVersion string `json:"agent_version"` }
	json.NewDecoder(r.Body).Decode(&req)
	h.svc.Heartbeat(id, req.AgentVersion)
	writeJSON(w, 200, okResp())
}

func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	h.svc.DeleteNode(id)
	writeJSON(w, 200, okResp())
}

// CascadeDelete removes nodes by vps_id and/or ip (VPS lifecycle linkage).
// DELETE /api/v1/nodes/?vps_id=1&ip=1.2.3.4
func (h *Handler) CascadeDelete(w http.ResponseWriter, r *http.Request) {
	vpsID, _ := strconv.ParseUint(r.URL.Query().Get("vps_id"), 10, 64)
	ip := r.URL.Query().Get("ip")
	if vpsID == 0 && ip == "" {
		// optional JSON body
		var req struct {
			VPSID uint64 `json:"vps_id"`
			IP    string `json:"ip"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		vpsID, ip = req.VPSID, req.IP
	}
	if vpsID == 0 && ip == "" {
		writeJSON(w, 422, errResp(1002, "vps_id or ip query required"))
		return
	}
	ids, err := h.svc.DeleteMatching(vpsID, ip)
	if err != nil {
		writeJSON(w, 500, errResp(1006, err.Error()))
		return
	}
	writeJSON(w, 200, map[string]any{"code": 0, "data": map[string]any{"deleted_ids": ids, "count": len(ids)}})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func errResp(code int, msg string) map[string]any { return map[string]any{"code": code, "message": msg} }
func dataResp(v any) map[string]any               { return map[string]any{"code": 0, "data": v} }
func okResp() map[string]any                      { return map[string]any{"code": 0, "message": "success"} }
