package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/aero/service"
)

// Handler exposes AERO package APIs only (no VPS CRUD).
type Handler struct{ svc *service.Service }

func New(svc *service.Service) *Handler { return &Handler{svc: svc} }

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/aero/install/", h.Install)
	mux.HandleFunc("POST /api/v1/aero/uninstall/", h.Uninstall)
	mux.HandleFunc("GET /api/v1/aero/tasks/", h.ListTasks)
	mux.HandleFunc("GET /api/v1/aero/tasks/{id}/", h.GetTask)
	mux.HandleFunc("DELETE /api/v1/aero/tasks/{id}/", h.DeleteTask)
	mux.HandleFunc("POST /api/v1/aero/tasks/clear-failed/", h.ClearFailed)
	mux.HandleFunc("GET /api/v1/aero/vps-options/", h.VPSOptions)
	// endpoint + tokens (for modular aero webui)
	mux.HandleFunc("GET /api/v1/aero/vps/{id}/endpoint/", h.GetEndpoint)
	mux.HandleFunc("POST /api/v1/aero/vps/{id}/endpoint/refresh/", h.RefreshEndpoint)
	mux.HandleFunc("GET /api/v1/aero/vps/{id}/tokens/", h.ListTokens)
	mux.HandleFunc("POST /api/v1/aero/vps/{id}/tokens/", h.AddToken)
	mux.HandleFunc("DELETE /api/v1/aero/vps/{id}/tokens/", h.DelToken)
	mux.HandleFunc("GET /api/v1/aero/vps/{id}/status/", h.EdgeStatus)
	mux.HandleFunc("GET /api/v1/aero/vps/{id}/diagnose/", h.Diagnose)
	mux.HandleFunc("POST /api/v1/aero/vps/{id}/cert/renew/", h.RenewCert)
	mux.HandleFunc("POST /api/v1/aero/vps/{id}/restart/", h.RestartEdge)
	mux.HandleFunc("POST /api/v1/aero/vps/{id}/subs/sync/", h.SyncSubs)
	mux.HandleFunc("POST /api/v1/aero/subs/broadcast/", h.BroadcastSubs)
}

func (h *Handler) Install(w http.ResponseWriter, r *http.Request) {
	var req struct {
		VPSID uint64 `json:"vps_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.VPSID == 0 {
		writeJSON(w, 422, errResp(1002, "vps_id required"))
		return
	}
	t, err := h.svc.StartInstall(req.VPSID)
	if err != nil {
		writeJSON(w, 422, errResp(1002, err.Error()))
		return
	}
	writeJSON(w, 201, dataResp(t))
}

func (h *Handler) Uninstall(w http.ResponseWriter, r *http.Request) {
	var req struct {
		VPSID uint64 `json:"vps_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.VPSID == 0 {
		writeJSON(w, 422, errResp(1002, "vps_id required"))
		return
	}
	t, err := h.svc.StartUninstall(req.VPSID)
	if err != nil {
		writeJSON(w, 422, errResp(1002, err.Error()))
		return
	}
	writeJSON(w, 201, dataResp(t))
}

func (h *Handler) ListTasks(w http.ResponseWriter, r *http.Request) {
	list, _ := h.svc.ListTasks()
	writeJSON(w, 200, map[string]any{"code": 0, "data": map[string]any{"results": list}})
}

func (h *Handler) GetTask(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	t, err := h.svc.GetTask(id)
	if err != nil {
		writeJSON(w, 404, errResp(1001, "not found"))
		return
	}
	writeJSON(w, 200, dataResp(t))
}

func (h *Handler) DeleteTask(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err := h.svc.DeleteTask(id); err != nil {
		writeJSON(w, 422, errResp(1002, err.Error()))
		return
	}
	writeJSON(w, 200, map[string]any{"code": 0, "message": "ok"})
}

func (h *Handler) ClearFailed(w http.ResponseWriter, r *http.Request) {
	n, _ := h.svc.ClearFailed()
	writeJSON(w, 200, map[string]any{"code": 0, "data": map[string]any{"deleted": n}})
}

func (h *Handler) VPSOptions(w http.ResponseWriter, r *http.Request) {
	list, err := h.svc.ListVPSOptions()
	if err != nil {
		writeJSON(w, 502, errResp(1006, "vps provider: "+err.Error()))
		return
	}
	writeJSON(w, 200, map[string]any{"code": 0, "data": map[string]any{"results": list}})
}

func (h *Handler) GetEndpoint(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	ep, err := h.svc.GetEndpoint(id)
	if err != nil {
		writeJSON(w, 404, errResp(1001, err.Error()))
		return
	}
	writeJSON(w, 200, dataResp(ep))
}

func (h *Handler) RefreshEndpoint(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err := h.svc.RefreshEndpoint(id); err != nil {
		writeJSON(w, 422, errResp(1002, err.Error()))
		return
	}
	ep, _ := h.svc.GetEndpoint(id)
	writeJSON(w, 200, dataResp(ep))
}

func (h *Handler) ListTokens(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	list, err := h.svc.ListTokens(id)
	if err != nil {
		writeJSON(w, 502, errResp(1006, err.Error()))
		return
	}
	// mask tokens for UI
	for i := range list {
		if t, ok := list[i]["token"].(string); ok && len(t) > 8 {
			list[i]["token_mask"] = t[:4] + "…" + t[len(t)-4:]
			list[i]["token_full"] = t // admin UI needs full for delete; mid only
		}
	}
	writeJSON(w, 200, map[string]any{"code": 0, "data": map[string]any{"results": list}})
}

func (h *Handler) AddToken(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	var req struct {
		Token    string `json:"token"`
		Label    string `json:"label"`
		TTLHours int    `json:"ttl_hours"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	m, err := h.svc.AddToken(id, req.Token, req.Label, req.TTLHours)
	if err != nil {
		writeJSON(w, 502, errResp(1006, err.Error()))
		return
	}
	writeJSON(w, 201, dataResp(m))
}

func (h *Handler) DelToken(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	tok := r.URL.Query().Get("token")
	if tok == "" {
		writeJSON(w, 422, errResp(1002, "token required"))
		return
	}
	if err := h.svc.DelToken(id, tok); err != nil {
		writeJSON(w, 502, errResp(1006, err.Error()))
		return
	}
	writeJSON(w, 200, map[string]any{"code": 0, "message": "ok"})
}

func (h *Handler) EdgeStatus(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	st, err := h.svc.EdgeStatus(id)
	if err != nil {
		writeJSON(w, 502, errResp(1006, err.Error()))
		return
	}
	writeJSON(w, 200, dataResp(st))
}

func (h *Handler) Diagnose(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	rep, err := h.svc.Diagnose(id)
	if err != nil {
		writeJSON(w, 502, errResp(1006, err.Error()))
		return
	}
	writeJSON(w, 200, dataResp(rep))
}

func (h *Handler) RenewCert(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	var req struct {
		Force bool `json:"force"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	m, err := h.svc.RenewCert(id, req.Force)
	if err != nil {
		writeJSON(w, 502, errResp(1006, err.Error()))
		return
	}
	writeJSON(w, 200, dataResp(m))
}

func (h *Handler) RestartEdge(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	m, err := h.svc.RestartEdge(id)
	if err != nil {
		writeJSON(w, 502, errResp(1006, err.Error()))
		return
	}
	writeJSON(w, 200, dataResp(m))
}

func (h *Handler) SyncSubs(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	var body any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 422, errResp(1002, "invalid json body"))
		return
	}
	m, err := h.svc.SyncSubs(id, body)
	if err != nil {
		writeJSON(w, 502, errResp(1006, err.Error()))
		return
	}
	writeJSON(w, 200, dataResp(m))
}

func (h *Handler) BroadcastSubs(w http.ResponseWriter, r *http.Request) {
	var body any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 422, errResp(1002, "invalid json body"))
		return
	}
	results := h.svc.BroadcastUserSubs(body)
	resMap := make(map[string]any)
	for vpsID, err := range results {
		k := strconv.FormatUint(vpsID, 10)
		if err != nil {
			resMap[k] = map[string]any{"ok": false, "error": err.Error()}
		} else {
			resMap[k] = map[string]any{"ok": true}
		}
	}
	writeJSON(w, 200, dataResp(resMap))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func errResp(code int, msg string) map[string]any {
	return map[string]any{"code": code, "message": msg}
}
func dataResp(v any) map[string]any { return map[string]any{"code": 0, "data": v} }
