package handler

import (
	"encoding/json"
	"net/http"

	"github.com/vpn-platform/vpsserver/vpn/internal/modules/pay/in/service"
)

type Handler struct{ svc *service.Service }

func New(svc *service.Service) *Handler { return &Handler{svc: svc} }

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/payments/in/orders/", h.CreateOrder)
	mux.HandleFunc("GET /api/v1/payments/in/channels/", h.Channels)
}

func (h *Handler) CreateOrder(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID      uint64 `json:"user_id"`
		Channel     string `json:"channel"`
		AmountCents int64  `json:"amount_cents"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	order, err := h.svc.CreateOrder(req.UserID, req.Channel, req.AmountCents)
	if err != nil {
		writeJSON(w, 422, map[string]any{"code": 1002, "message": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"code": 0, "data": order})
}

// Channels returns Payment IN channels per project.md: wechat/alipay/bankcard
func (h *Handler) Channels(w http.ResponseWriter, r *http.Request) {
	channels := []map[string]any{
		{"channel": "wechat", "name": "微信支付", "icon": "wechat", "enabled": true},
		{"channel": "alipay", "name": "支付宝", "icon": "alipay", "enabled": true},
		{"channel": "bankcard", "name": "银行卡", "icon": "bankcard", "enabled": true},
	}
	writeJSON(w, 200, map[string]any{"code": 0, "data": channels})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
