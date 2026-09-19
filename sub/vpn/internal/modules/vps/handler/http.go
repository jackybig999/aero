package handler

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/domain"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/service"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/store"
)

// Handler exposes VPS asset APIs only.
type Handler struct {
	svc         *service.Service
	internalKey string
}

func New(svc *service.Service) *Handler {
	key := strings.TrimSpace(os.Getenv("INTERNAL_SERVICE_KEY"))
	if key == "" {
		key = "dev-internal-key-change-me"
	}
	return &Handler{svc: svc, internalKey: key}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/vps/", h.Create)
	mux.HandleFunc("GET /api/v1/vps/", h.List)
	mux.HandleFunc("GET /api/v1/vps/{id}/", h.Get)
	mux.HandleFunc("PATCH /api/v1/vps/{id}/", h.Patch)
	mux.HandleFunc("DELETE /api/v1/vps/{id}/", h.Delete)
	mux.HandleFunc("POST /api/v1/vps/{id}/probe/", h.Probe)
	mux.HandleFunc("POST /api/v1/vps/{id}/verify-domain/", h.VerifyVPSDomain)
	mux.HandleFunc("GET /api/v1/vps/cf-dns/status/", h.CFStatus)
	mux.HandleFunc("POST /api/v1/vps/cf-dns/sync/", h.SyncCFDNS)
	// Optional internal credentials (legacy HTTP); in-process AERO uses iface.VPSProvider
	mux.HandleFunc("GET /api/v1/vps/{id}/credentials/", h.Credentials)
}

func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Role        string `json:"role"`
		IP          string `json:"ip"`
		SSHPort     int    `json:"ssh_port"`
		SSHUsername string `json:"ssh_username"`
		SSHPassword string `json:"ssh_password"`
		Domain      string `json:"domain"`
		Remark      string `json:"remark"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 422, errResp(1002, "invalid body"))
		return
	}
	v, err := h.svc.Create(domain.CreateVPSParams{
		Name: req.Name, Role: req.Role, IP: req.IP, SSHPort: req.SSHPort,
		SSHUsername: req.SSHUsername, SSHPassword: req.SSHPassword,
		Domain: req.Domain, Remark: req.Remark,
	})
	if err != nil {
		writeJSON(w, 422, errResp(1002, err.Error()))
		return
	}
	writeJSON(w, 201, dataResp(v))
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	list, _ := h.svc.List()
	writeJSON(w, 200, map[string]any{"code": 0, "data": map[string]any{"results": list}})
}

func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	v, err := h.svc.Get(id)
	if err != nil {
		writeJSON(w, 404, errResp(1001, "not found"))
		return
	}
	writeJSON(w, 200, dataResp(v))
}

func (h *Handler) Patch(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	var req struct {
		SSHPassword string `json:"ssh_password"`
		IP          string `json:"ip"`
		Domain      string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 422, errResp(1002, "invalid body"))
		return
	}
	if req.IP != "" {
		if err := h.svc.RepairIP(id, req.IP); err != nil {
			writeJSON(w, 422, errResp(1002, err.Error()))
			return
		}
	}
	if req.SSHPassword != "" {
		if err := h.svc.UpdatePassword(id, req.SSHPassword); err != nil {
			writeJSON(w, 422, errResp(1002, err.Error()))
			return
		}
	}
	if req.Domain != "" {
		if err := h.svc.UpdateDomain(r.Context(), id, req.Domain); err != nil {
			writeJSON(w, 422, errResp(1002, err.Error()))
			return
		}
	}
	if req.IP != "" || req.SSHPassword != "" || req.Domain != "" {
		writeJSON(w, 200, map[string]any{"code": 0, "message": "VPS 信息已更新（已加密落盘与复核）"})
		return
	}
	writeJSON(w, 422, errResp(1002, "ssh_password, ip or domain required"))
}

func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	// Registry only — AERO package lifecycle is aero package's job
	if err := h.svc.Delete(id); err != nil {
		writeJSON(w, 404, errResp(1001, err.Error()))
		return
	}
	writeJSON(w, 200, map[string]any{"code": 0, "message": "vps registry deleted (AERO on host unchanged)"})
}

func (h *Handler) Probe(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	m, err := h.svc.Probe(id)
	v, _ := h.svc.Get(id)
	ok := m != nil && m.ProbeOK
	if err != nil && m == nil {
		writeJSON(w, 422, errResp(1002, err.Error()))
		return
	}
	writeJSON(w, 200, map[string]any{"code": 0, "data": map[string]any{"metrics": m, "vps": v, "ok": ok}})
}

func (h *Handler) Credentials(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Internal-Key") != h.internalKey {
		writeJSON(w, 403, errResp(1003, "forbidden: internal key required"))
		return
	}
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	c, err := h.svc.Credentials(id)
	if err != nil {
		if err == store.ErrNotFound {
			writeJSON(w, 404, errResp(1001, "not found"))
			return
		}
		writeJSON(w, 422, errResp(1002, err.Error()))
		return
	}
	writeJSON(w, 200, dataResp(c))
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

func (h *Handler) CFStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"code": 0,
		"data": h.svc.CFStatus(),
	})
}

func (h *Handler) VerifyVPSDomain(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	vps, err := h.svc.Get(id)
	if err != nil {
		writeJSON(w, 404, errResp(1001, "vps not found"))
		return
	}
	res, err := h.svc.VerifyOrSyncDomainDetail(r.Context(), vps.Domain, vps.IP)
	if err != nil {
		writeJSON(w, 422, map[string]any{
			"code":    1002,
			"message": err.Error(),
			"data":    res,
		})
		return
	}
	writeJSON(w, 200, map[string]any{
		"code":    0,
		"message": res.StatusText,
		"data":    res,
	})
}

func (h *Handler) SyncCFDNS(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
		IP     string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 422, errResp(1002, "invalid body"))
		return
	}
	res, err := h.svc.VerifyOrSyncDomainDetail(r.Context(), req.Domain, req.IP)
	if err != nil {
		writeJSON(w, 422, map[string]any{
			"code":    1002,
			"message": err.Error(),
			"data":    res,
		})
		return
	}
	writeJSON(w, 200, map[string]any{
		"code":    0,
		"message": res.StatusText,
		"data":    res,
	})
}

