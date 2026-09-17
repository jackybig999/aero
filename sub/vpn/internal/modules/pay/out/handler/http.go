package handler

import (
	"encoding/json"
	"net/http"

	"github.com/vpn-platform/vpsserver/vpn/internal/modules/pay/out/service"
)

type Handler struct{ svc *service.Service }

func New(svc *service.Service) *Handler { return &Handler{svc: svc} }

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/payments/out/settle/", h.Settle)
	mux.HandleFunc("GET /api/v1/payments/out/channels/", h.Channels)
}

func (h *Handler) Settle(w http.ResponseWriter, r *http.Request) {
	var req service.SettlementRequest
	json.NewDecoder(r.Body).Decode(&req)
	result := h.svc.Settle(req)
	writeJSON(w, 200, map[string]any{"code": 0, "data": result})
}

func (h *Handler) Channels(w http.ResponseWriter, r *http.Request) {
	channels := h.svc.Channels()
	writeJSON(w, 200, map[string]any{"code": 0, "data": channels})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
