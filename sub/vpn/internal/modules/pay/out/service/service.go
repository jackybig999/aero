// Package service implements payment-out settlement dispatch.
// Channel priority per rule.md: PingPong > Airwallex/Stripe > Crypto/PayPal
package service

type SettlementRequest struct {
	SettlementNo string `json:"settlement_no"`
	Channel      string `json:"channel"`
	AmountCents  int64  `json:"amount_cents"`
}

type SettlementResult struct {
	Channel string `json:"channel"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

// Service dispatches settlements to the correct payment channel.
type Service struct{}

func New() *Service { return &Service{} }

// Settle dispatches a settlement to the appropriate channel.
func (s *Service) Settle(req SettlementRequest) SettlementResult {
	return SettlementResult{
		Channel: req.Channel,
		Status:  "pending",
		Message: req.Channel + " payout initiated",
	}
}

// Channels returns available settlement channels with priority.
// Priority is FIXED per rule.md: PingPong(primary), Airwallex/Stripe(hot), Crypto/PayPal(cold)
func (s *Service) Channels() []map[string]interface{} {
	return []map[string]interface{}{
		{"channel": "pingpong", "name": "PingPong", "priority": "primary", "enabled": true},
		{"channel": "airwallex", "name": "Airwallex", "priority": "hot_standby", "enabled": true},
		{"channel": "stripe", "name": "Stripe", "priority": "hot_standby", "enabled": true},
		{"channel": "crypto", "name": "Crypto (USDT)", "priority": "cold_standby", "enabled": true},
		{"channel": "paypal", "name": "PayPal", "priority": "cold_standby", "enabled": false},
	}
}
