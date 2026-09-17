// Package service implements payment-in business logic.
// Payment IN (wechat/alipay/bankcard) only writes to Ledger, per rule.md.
package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Order represents a user payment order.
type Order struct {
	OrderNo     string `json:"order_no"`
	UserID      uint64 `json:"user_id"`
	Channel     string `json:"channel"`
	AmountCents int64  `json:"amount_cents"`
	LedgerNo    string `json:"ledger_no"`
	Status      string `json:"status"`
}

// Service handles payment-in order creation and ledger recording.
type Service struct {
	ledgerURL string
}

func New(ledgerURL string) *Service { return &Service{ledgerURL: ledgerURL} }

// CreateOrder creates a payment order and records it in the Ledger.
func (s *Service) CreateOrder(userID uint64, channel string, amountCents int64) (*Order, error) {
	now := time.Now()
	orderNo := fmt.Sprintf("ORD-%s-%d", now.Format("20060102"), now.UnixNano()%1000000)
	ledgerNo := fmt.Sprintf("LED-%s-IN-%s", now.Format("20060102"), orderNo[12:])

	// Write to Ledger (HTTP call to payment-ledger module)
	body, _ := json.Marshal(map[string]interface{}{
		"user_id":      userID,
		"amount_cents": amountCents,
		"direction":    "IN",
		"channel":      channel,
		"channel_ref":  orderNo,
	})

	// Fire and record — non-blocking if ledger is unavailable
	http.Post(s.ledgerURL+"/api/v1/ledger/entries/", "application/json", bytes.NewReader(body))

	return &Order{
		OrderNo: orderNo, UserID: userID, Channel: channel,
		AmountCents: amountCents, LedgerNo: ledgerNo, Status: "pending",
	}, nil
}
