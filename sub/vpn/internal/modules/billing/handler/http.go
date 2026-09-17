package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/vpn-platform/vpsserver/vpn/internal/modules/billing/service"
)

type Handler struct{ svc *service.Service }

func New(svc *service.Service) *Handler { return &Handler{svc: svc} }

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/plans/", h.List)
	mux.HandleFunc("POST /api/v1/plans/", h.Create)
	mux.HandleFunc("GET /api/v1/plans/{id}/", h.Get)
	mux.HandleFunc("PATCH /api/v1/plans/{id}/", h.Update)
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	plans, _ := h.svc.ListPlans(true)
	writeJSON(w, 200, map[string]any{"code": 0, "data": map[string]any{"results": plans}})
}

func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name       string `json:"name"`
		Months     int32  `json:"duration_months"`
		Traffic    int64  `json:"traffic_bytes"`
		PriceCents int64  `json:"price_cents"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	p, err := h.svc.CreatePlan(req.Name, req.Months, req.Traffic, req.PriceCents)
	if err != nil {
		writeJSON(w, 422, errResp)
		return
	}
	writeJSON(w, 201, map[string]any{"code": 0, "data": p})
}

func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	p, err := h.svc.GetPlan(int32(id))
	if err != nil {
		writeJSON(w, 404, errResp)
		return
	}
	writeJSON(w, 200, map[string]any{"code": 0, "data": p})
}

func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	var req struct {
		Price  *int64 `json:"price_cents"`
		Status *bool  `json:"status"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	h.svc.UpdatePlan(int32(id), req.Price, req.Status)
	writeJSON(w, 200, okResp)
}

var (
	errResp = map[string]any{"code": 1, "message": "error"}
	okResp  = map[string]any{"code": 0, "message": "success"}
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
