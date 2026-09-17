package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/vpn-platform/vpsserver/vpn/internal/modules/pay/settlement/service"
)

type Handler struct{ svc *service.Service }

func New(svc *service.Service) *Handler { return &Handler{svc: svc} }

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/settlements/run/", h.Run)
}

func (h *Handler) Run(w http.ResponseWriter, r *http.Request) {
	result, err := h.svc.RunDailySettlement(time.Now())
	if err != nil {
		writeJSON(w, 500, map[string]any{"code": 1006, "message": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"code": 0, "data": result})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
