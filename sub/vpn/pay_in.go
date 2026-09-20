// Copyright 2025 AERO Protocol Contributors
// Plan.md Phase 2: 平铺无子包运营中台 — 充值收单与异步回调通道
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// PayInOrder represents a user payment order for subscription recharge.
type PayInOrder struct {
	OrderNo     string `json:"order_no"`
	UserID      uint64 `json:"user_id"`
	Channel     string `json:"channel"`
	AmountCents int64  `json:"amount_cents"`
	LedgerNo    string `json:"ledger_no"`
	Status      string `json:"status"`
}

// PayInService handles payment-in order creation and ledger recording.
type PayInService struct {
	ledgerURL      string
	ledgerSvc      *LedgerService
	onOrderSuccess func(userID uint64, amountCents int64)
}

// NewPayInService creates a PayInService with optional direct ledger service or remote URL fallback.
func NewPayInService(ledgerURL string, ledgerSvc *LedgerService) *PayInService {
	return &PayInService{
		ledgerURL: ledgerURL,
		ledgerSvc: ledgerSvc,
	}
}

// SetOnOrderSuccess registers a hook called when an order succeeds (e.g. to renew user plan).
func (s *PayInService) SetOnOrderSuccess(fn func(userID uint64, amountCents int64)) {
	s.onOrderSuccess = fn
}

// CreateOrder creates a payment order, records it into Ledger, and invokes success callback.
func (s *PayInService) CreateOrder(userID uint64, channel string, amountCents int64) (*PayInOrder, error) {
	if channel == "" {
		channel = "alipay"
	}
	if amountCents <= 0 {
		return nil, fmt.Errorf("invalid amount_cents: %d", amountCents)
	}

	now := time.Now()
	orderNo := fmt.Sprintf("ORD-%s-%d", now.Format("20060102"), now.UnixNano()%1000000)
	ledgerNo := fmt.Sprintf("LED-%s-IN-%s", now.Format("20060102"), orderNo[len(orderNo)-6:])

	// 1. Double-entry ledger recording: Direct local SQLite atomic entry if available
	if s.ledgerSvc != nil {
		_, _ = s.ledgerSvc.RecordEntry(&LedgerEntry{
			LedgerNo:    ledgerNo,
			UserID:      userID,
			Direction:   "IN",
			AmountCents: amountCents,
			Channel:     channel,
			ChannelRef:  orderNo,
			CreatedAt:   now,
		})
	} else if s.ledgerURL != "" {
		// Fallback to HTTP POST if ledger service is decoupled
		body, _ := json.Marshal(map[string]any{
			"user_id":      userID,
			"amount_cents": amountCents,
			"direction":    "IN",
			"channel":      channel,
			"channel_ref":  orderNo,
		})
		go func() {
			resp, err := http.Post(s.ledgerURL+"/api/v1/ledger/entries/", "application/json", bytes.NewReader(body))
			if err == nil && resp != nil {
				_ = resp.Body.Close()
			}
		}()
	}

	// 2. Trigger business fulfillment
	if s.onOrderSuccess != nil && userID > 0 {
		s.onOrderSuccess(userID, amountCents)
	}

	return &PayInOrder{
		OrderNo:     orderNo,
		UserID:      userID,
		Channel:     channel,
		AmountCents: amountCents,
		LedgerNo:    ledgerNo,
		Status:      "completed",
	}, nil
}

// PayInHandler provides HTTP endpoints for payment ingestion.
type PayInHandler struct {
	svc *PayInService
}

func NewPayInHandler(svc *PayInService) *PayInHandler {
	return &PayInHandler{svc: svc}
}

func (h *PayInHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/payments/in/orders/", h.CreateOrder)
	mux.HandleFunc("GET /api/v1/payments/in/channels/", h.Channels)
}

func (h *PayInHandler) CreateOrder(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID      uint64 `json:"user_id"`
		Channel     string `json:"channel"`
		AmountCents int64  `json:"amount_cents"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"code": 1002, "message": "invalid request body"})
		return
	}
	order, err := h.svc.CreateOrder(req.UserID, req.Channel, req.AmountCents)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"code": 1002, "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"code": 0, "data": order})
}

// Channels returns payment IN channels: wechat/alipay/bankcard.
func (h *PayInHandler) Channels(w http.ResponseWriter, r *http.Request) {
	channels := []map[string]any{
		{"channel": "wechat", "name": "微信支付", "icon": "wechat", "enabled": true},
		{"channel": "alipay", "name": "支付宝", "icon": "alipay", "enabled": true},
		{"channel": "bankcard", "name": "银行卡", "icon": "bankcard", "enabled": true},
	}
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "data": channels})
}
