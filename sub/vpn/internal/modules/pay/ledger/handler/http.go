// Package handler implements HTTP endpoints for payment-ledger.
package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/vpn-platform/vpsserver/vpn/internal/modules/pay/ledger/service"
)

type Handler struct {
	svc *service.Service
}

func New(svc *service.Service) *Handler { return &Handler{svc: svc} }

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/ledger/entries/", h.Record)
	mux.HandleFunc("GET /api/v1/ledger/entries/{ledgerNo}", h.Get)
	mux.HandleFunc("GET /api/v1/ledger/entries/unsettled/", h.ListUnsettled)
	mux.HandleFunc("POST /api/v1/ledger/entries/settle/", h.Settle)
	mux.HandleFunc("GET /api/v1/ledger/summary/", h.Summary)
}

func (h *Handler) Record(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID      uint64 `json:"user_id"`
		AmountCents int64  `json:"amount_cents"`
		Direction   string `json:"direction"`
		Channel     string `json:"channel"`
		ChannelRef  string `json:"channel_ref"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 422, errResp(1002, "invalid body"))
		return
	}
	e, err := h.svc.RecordPayment(req.UserID, req.AmountCents, req.Direction, req.Channel, req.ChannelRef)
	if err != nil {
		writeJSON(w, 422, errResp(1002, err.Error()))
		return
	}
	writeJSON(w, 201, dataResp(e))
}

func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	no := r.PathValue("ledgerNo")
	e, err := h.svc.GetByLedgerNo(no)
	if err != nil {
		writeJSON(w, 404, errResp(1001, "not found"))
		return
	}
	writeJSON(w, 200, dataResp(e))
}

func (h *Handler) ListUnsettled(w http.ResponseWriter, r *http.Request) {
	dir := r.URL.Query().Get("direction")
	if dir == "" {
		dir = "IN"
	}
	entries, err := h.svc.ListUnsettled(dir)
	if err != nil {
		writeJSON(w, 500, errResp(1006, err.Error()))
		return
	}
	writeJSON(w, 200, dataResp(entries))
}

func (h *Handler) Settle(w http.ResponseWriter, r *http.Request) {
	var req struct {
		LedgerNo     string `json:"ledger_no"`
		SettlementNo string `json:"settlement_no"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if err := h.svc.MarkSettled(req.LedgerNo, req.SettlementNo); err != nil {
		writeJSON(w, 422, errResp(1002, err.Error()))
		return
	}
	writeJSON(w, 200, okResp())
}

func (h *Handler) Summary(w http.ResponseWriter, r *http.Request) {
	dateStr := r.URL.Query().Get("date")
	if dateStr == "" {
		dateStr = time.Now().Format("2006-01-02")
	}
	date, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		writeJSON(w, 422, errResp(1002, "invalid date"))
		return
	}
	summary, _ := h.svc.GetDailySummary(date)
	writeJSON(w, 200, dataResp(summary))
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

var _ = strconv.Itoa
