// Copyright 2026 AERO Protocol Contributors
// AERO Payment Gateway Domain & Abstraction Layer
package mid

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// CheckoutSessionReq represents an authoritative request to create a payment checkout session.
type CheckoutSessionReq struct {
	OrderNo     string // Authoritative local order number: ORD-20261005-XXXXXX
	PlanID      uint64 // Internal BillingPlan ID
	PlanName    string // Display name of the plan
	AmountCents int64  // Authoritative price in cents (e.g. 999 = $9.99)
	UserID      uint64 // User ID initiating payment
	UserEmail   string // User Email for pre-filling checkout
	SuccessURL  string // HTTPS redirect URL after success
	CancelURL   string // HTTPS redirect URL if cancelled
}

// ValidateAndNormalize validates essential invariants on the checkout session request
// and trims whitespace from string fields.
func (r *CheckoutSessionReq) ValidateAndNormalize() error {
	r.OrderNo = strings.TrimSpace(r.OrderNo)
	r.PlanName = strings.TrimSpace(r.PlanName)
	r.UserEmail = strings.TrimSpace(strings.ToLower(r.UserEmail))
	r.SuccessURL = strings.TrimSpace(r.SuccessURL)
	r.CancelURL = strings.TrimSpace(r.CancelURL)

	if r.OrderNo == "" {
		return errors.New("order_no cannot be empty")
	}
	if r.AmountCents <= 0 {
		return fmt.Errorf("amount_cents must be positive, got %d", r.AmountCents)
	}
	if r.UserID == 0 {
		return errors.New("user_id must be greater than zero")
	}
	return nil
}

// CheckoutSessionResp contains the checkout redirection details from the MoR gateway.
type CheckoutSessionResp struct {
	CheckoutURL string `json:"checkout_url"` // Full checkout URL to redirect the user
	ExternalID  string `json:"external_id"`  // Gateway session/order ID (e.g. ch_xxx)
}

// WebhookEvent represents a normalized, immutable payment or refund event.
type WebhookEvent struct {
	EventID        string // Unique event ID from provider (used for DB idempotency)
	Provider       string // "creem" or "lemonsqueezy"
	EventType      string // "payment.success", "payment.refunded", "dispute.created"
	OrderNo        string // Local order number extracted from metadata/custom_data
	AmountCents    int64  // Amount in integer cents
	Currency       string // USD, EUR, etc.
	ChannelTradeNo string // External trade/transaction number
	RawPayload     string // Raw payload for immutable audit trail
}

// PaymentGateway defines the contract for an authoritative payment provider.
type PaymentGateway interface {
	ProviderName() string
	CreateCheckout(ctx context.Context, req CheckoutSessionReq) (*CheckoutSessionResp, error)
	VerifyAndParseWebhook(r *http.Request) (*WebhookEvent, error)
}

// PayChannelConfig represents a payment account configuration in aeropay.db.
type PayChannelConfig struct {
	ID               int64             `json:"id"`
	Channel          string            `json:"channel"`           // "creem" | "lemonsqueezy"
	DisplayName      string            `json:"display_name"`      // User-facing title
	Icon             string            `json:"icon"`              // "card" | "paypal"
	APIKey           string            `json:"api_key,omitempty"` // Masked when serializing to UI
	WebhookSecret    string            `json:"webhook_secret,omitempty"`
	StoreID          string            `json:"store_id,omitempty"` // For Lemon Squeezy
	PlanMapping      map[uint64]string `json:"plan_mapping"`       // PlanID -> External Product/Variant ID
	IsTest           bool              `json:"is_test"`            // Sandbox/Test mode flag
	Priority         int               `json:"priority"`           // Display order (1 is highest priority)
	Enabled          bool              `json:"enabled"`            // Active status
	UpdatedAt        time.Time         `json:"updated_at"`
}

// Masked returns a safe copy of the config suitable for UI display.
func (c *PayChannelConfig) Masked() PayChannelConfig {
	cp := *c
	if len(cp.APIKey) > 8 {
		cp.APIKey = cp.APIKey[:4] + "****" + cp.APIKey[len(cp.APIKey)-4:]
	} else if cp.APIKey != "" {
		cp.APIKey = "****"
	}
	if len(cp.WebhookSecret) > 8 {
		cp.WebhookSecret = cp.WebhookSecret[:4] + "****" + cp.WebhookSecret[len(cp.WebhookSecret)-4:]
	} else if cp.WebhookSecret != "" {
		cp.WebhookSecret = "****"
	}
	return cp
}

// GetPlanMapping returns the mapped external product/variant ID for an internal plan ID.
func (c *PayChannelConfig) GetPlanMapping(planID uint64) string {
	if c.PlanMapping != nil {
		return c.PlanMapping[planID]
	}
	return ""
}

// ValidateAndNormalize validates channel configuration integrity and normalizes string fields.
func (c *PayChannelConfig) ValidateAndNormalize() error {
	c.Channel = strings.TrimSpace(strings.ToLower(c.Channel))
	c.DisplayName = strings.TrimSpace(c.DisplayName)
	c.Icon = strings.TrimSpace(strings.ToLower(c.Icon))
	c.APIKey = strings.TrimSpace(c.APIKey)
	c.WebhookSecret = strings.TrimSpace(c.WebhookSecret)
	c.StoreID = strings.TrimSpace(c.StoreID)

	if c.Channel == "" {
		return errors.New("channel cannot be empty")
	}
	if c.Channel != "creem" && c.Channel != "lemonsqueezy" {
		return fmt.Errorf("unsupported pay channel: %q (only creem or lemonsqueezy allowed)", c.Channel)
	}
	if c.Priority <= 0 {
		c.Priority = 1
	}
	if c.PlanMapping == nil {
		c.PlanMapping = make(map[uint64]string)
	}
	return nil
}

// GatewayRegistry manages all active PaymentGateway instances in thread-safe memory.
type GatewayRegistry struct {
	mu       sync.RWMutex
	gateways map[string]PaymentGateway
	box      *SecretBox
	payDB    *AeroPayDB
}

// NewGatewayRegistry constructs a new GatewayRegistry.
func NewGatewayRegistry(payDB *AeroPayDB, box *SecretBox) *GatewayRegistry {
	r := &GatewayRegistry{
		gateways: make(map[string]PaymentGateway),
		box:      box,
		payDB:    payDB,
	}
	_ = r.Reload()
	return r
}

// Register registers a gateway under its provider name.
func (r *GatewayRegistry) Register(g PaymentGateway) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gateways[g.ProviderName()] = g
}

// Get returns the gateway by provider name.
func (r *GatewayRegistry) Get(provider string) (PaymentGateway, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	g, ok := r.gateways[provider]
	if !ok {
		return nil, fmt.Errorf("payment provider %q not configured or active", provider)
	}
	return g, nil
}

// ListActiveProviders returns the names of all currently registered and active providers.
func (r *GatewayRegistry) ListActiveProviders() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var list []string
	for name := range r.gateways {
		list = append(list, name)
	}
	return list
}

// Reload queries pay_channel_config from aeropay.db and instantiates Creem and Lemon Squeezy gateways.
func (r *GatewayRegistry) Reload() error {
	if r.payDB == nil {
		return nil
	}
	configs, err := r.payDB.ListPayChannelConfigs()
	if err != nil {
		return fmt.Errorf("list channel configs: %w", err)
	}

	newGateways := make(map[string]PaymentGateway)
	for _, cfg := range configs {
		if !cfg.Enabled {
			continue
		}

		apiKey := cfg.APIKey
		webhookSecret := cfg.WebhookSecret
		if r.box != nil {
			if dec, err := r.box.Decrypt(apiKey); err == nil && dec != "" {
				apiKey = dec
			}
			if dec, err := r.box.Decrypt(webhookSecret); err == nil && dec != "" {
				webhookSecret = dec
			}
		}

		switch cfg.Channel {
		case "creem":
			gw := NewCreemGateway(apiKey, webhookSecret, cfg.IsTest, cfg.PlanMapping)
			newGateways["creem"] = gw
		case "lemonsqueezy":
			gw := NewLemonSqueezyGateway(apiKey, webhookSecret, cfg.StoreID, cfg.IsTest, cfg.PlanMapping)
			newGateways["lemonsqueezy"] = gw
		}
	}

	// If no configs in DB, setup default fallback gateways (in Test Mode)
	if len(newGateways) == 0 {
		defaultPlans := map[uint64]string{
			1: "prod_monthly",
			2: "prod_quarterly",
			3: "prod_annual",
			4: "prod_unlimited",
		}
		newGateways["creem"] = NewCreemGateway("", "", true, defaultPlans)
		newGateways["lemonsqueezy"] = NewLemonSqueezyGateway("", "", "1000", true, defaultPlans)
	}

	r.mu.Lock()
	r.gateways = newGateways
	r.mu.Unlock()
	return nil
}

// MarshalPlanMapping converts a plan mapping map to a JSON string.
func MarshalPlanMapping(m map[uint64]string) string {
	b, err := json.Marshal(m)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// UnmarshalPlanMapping parses a JSON string into a plan mapping map.
func UnmarshalPlanMapping(s string) map[uint64]string {
	out := make(map[uint64]string)
	if s == "" {
		return out
	}
	var raw map[string]string
	if err := json.Unmarshal([]byte(s), &raw); err == nil {
		for k, v := range raw {
			var id uint64
			if n, perr := fmt.Sscanf(k, "%d", &id); perr == nil && n == 1 {
				out[id] = v
			}
		}
	}
	return out
}
