// Copyright 2026 AERO Protocol Contributors
// AERO Pure Go Lemon Squeezy Payment Gateway Driver (Zero External Dependencies)
package mid

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// LemonSqueezyGateway implements PaymentGateway for Lemon Squeezy via pure Go net/http.
type LemonSqueezyGateway struct {
	apiKey        string
	webhookSecret string
	storeID       string
	isTest        bool
	baseURL       string
	httpClient    *http.Client
	planMapping   map[uint64]string // PlanID -> variant_id
}

// NewLemonSqueezyGateway creates a new LemonSqueezyGateway instance.
func NewLemonSqueezyGateway(apiKey, webhookSecret, storeID string, isTest bool, planMapping map[uint64]string) *LemonSqueezyGateway {
	if planMapping == nil {
		planMapping = make(map[uint64]string)
	}
	return &LemonSqueezyGateway{
		apiKey:        apiKey,
		webhookSecret: webhookSecret,
		storeID:       storeID,
		isTest:        isTest,
		baseURL:       "https://api.lemonsqueezy.com/v1",
		httpClient:    &http.Client{Timeout: 15 * time.Second},
		planMapping:   planMapping,
	}
}

func (g *LemonSqueezyGateway) ProviderName() string {
	return "lemonsqueezy"
}

// CreateCheckout creates a checkout session using Lemon Squeezy JSON:API.
func (g *LemonSqueezyGateway) CreateCheckout(ctx context.Context, req CheckoutSessionReq) (*CheckoutSessionResp, error) {
	if err := req.ValidateAndNormalize(); err != nil {
		return nil, fmt.Errorf("lemonsqueezy checkout invalid request: %w", err)
	}
	variantID := g.planMapping[req.PlanID]
	if variantID == "" {
		variantID = fmt.Sprintf("%d", 1000+req.PlanID)
	}

	// If no API key configured yet (e.g. merchant account in application phase), provide sandbox mock checkout
	if g.apiKey == "" {
		mockURL := fmt.Sprintf("/api/v1/payments/mock/checkout?provider=lemonsqueezy&order_no=%s&amount=%d&plan_id=%d",
			req.OrderNo, req.AmountCents, req.PlanID)
		return &CheckoutSessionResp{
			CheckoutURL: mockURL,
			ExternalID:  "ls_sandbox_" + req.OrderNo,
		}, nil
	}

	storeID := g.storeID
	if storeID == "" {
		storeID = "1"
	}

	bodyMap := map[string]any{
		"data": map[string]any{
			"type": "checkouts",
			"attributes": map[string]any{
				"checkout_data": map[string]any{
					"email": req.UserEmail,
					"custom": map[string]any{
						"order_no": req.OrderNo,
						"user_id":  req.UserID,
						"plan_id":  req.PlanID,
					},
				},
				"product_options": map[string]any{
					"redirect_url": req.SuccessURL,
				},
			},
			"relationships": map[string]any{
				"store": map[string]any{
					"data": map[string]any{
						"type": "stores",
						"id":   storeID,
					},
				},
				"variant": map[string]any{
					"data": map[string]any{
						"type": "variants",
						"id":   variantID,
					},
				},
			},
		},
	}

	payload, err := json.Marshal(bodyMap)
	if err != nil {
		return nil, fmt.Errorf("marshal ls checkout request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, g.baseURL+"/checkouts", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create ls http request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+g.apiKey)
	httpReq.Header.Set("Content-Type", "application/vnd.api+json")
	httpReq.Header.Set("Accept", "application/vnd.api+json")

	resp, err := g.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("execute ls checkout request: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read ls checkout response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("ls checkout api returned %d: %s", resp.StatusCode, string(respBytes))
	}

	var result struct {
		Data struct {
			ID         string `json:"id"`
			Attributes struct {
				URL string `json:"url"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBytes, &result); err != nil {
		return nil, fmt.Errorf("unmarshal ls checkout response: %w", err)
	}
	if result.Data.Attributes.URL == "" {
		return nil, fmt.Errorf("ls checkout response missing url")
	}

	return &CheckoutSessionResp{
		CheckoutURL: result.Data.Attributes.URL,
		ExternalID:  result.Data.ID,
	}, nil
}

// VerifyAndParseWebhook verifies the HMAC-SHA256 signature and parses a Lemon Squeezy webhook payload.
func (g *LemonSqueezyGateway) VerifyAndParseWebhook(r *http.Request) (*WebhookEvent, error) {
	sigHeader := r.Header.Get("x-signature")
	if sigHeader == "" {
		sigHeader = r.Header.Get("X-Signature")
	}

	rawBody, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB limit
	if err != nil {
		return nil, fmt.Errorf("read ls webhook body: %w", err)
	}

	// Validate HMAC-SHA256 if webhookSecret is configured
	if g.webhookSecret != "" {
		if sigHeader == "" {
			return nil, fmt.Errorf("missing x-signature header")
		}
		mac := hmac.New(sha256.New, []byte(g.webhookSecret))
		mac.Write(rawBody)
		expectedSig := hex.EncodeToString(mac.Sum(nil))
		if subtle.ConstantTimeCompare([]byte(expectedSig), []byte(sigHeader)) != 1 {
			return nil, fmt.Errorf("invalid ls webhook signature")
		}
	}

	var lsEvent struct {
		Meta struct {
			EventName  string         `json:"event_name"`
			CustomData map[string]any `json:"custom_data"`
		} `json:"meta"`
		Data struct {
			ID         string `json:"id"`
			Type       string `json:"type"`
			Attributes struct {
				Identifier string `json:"identifier"`
				Total      int64  `json:"total"`
				Subtotal   int64  `json:"subtotal"`
				Currency   string `json:"currency"`
				Status     string `json:"status"`
				Refunded   bool   `json:"refunded"`
				RefundedAt string `json:"refunded_at"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if err := json.Unmarshal(rawBody, &lsEvent); err != nil {
		return nil, fmt.Errorf("unmarshal ls event: %w", err)
	}

	var orderNo string
	if lsEvent.Meta.CustomData != nil {
		if ord, ok := lsEvent.Meta.CustomData["order_no"].(string); ok {
			orderNo = ord
		}
	}

	eventID := r.Header.Get("X-Event-Id")
	if eventID == "" {
		eventID = fmt.Sprintf("ls_%s_%s", lsEvent.Meta.EventName, lsEvent.Data.ID)
	}

	// Prefer subtotal to exclude VAT/Sales Tax, fallback to total
	amountCents := lsEvent.Data.Attributes.Subtotal
	if amountCents <= 0 {
		amountCents = lsEvent.Data.Attributes.Total
	}

	tradeNo := lsEvent.Data.Attributes.Identifier
	if tradeNo == "" {
		tradeNo = lsEvent.Data.ID
	}

	normalizedType := "payment.unknown"
	switch lsEvent.Meta.EventName {
	case "order_created", "subscription_created", "subscription_payment_success":
		normalizedType = "payment.success"
	case "order_refunded":
		normalizedType = "payment.refunded"
	case "subscription_cancelled", "subscription_expired":
		normalizedType = "subscription.cancelled"
	}

	return &WebhookEvent{
		EventID:        eventID,
		Provider:       "lemonsqueezy",
		EventType:      normalizedType,
		OrderNo:        orderNo,
		AmountCents:    amountCents,
		Currency:       lsEvent.Data.Attributes.Currency,
		ChannelTradeNo: tradeNo,
		RawPayload:     string(rawBody),
	}, nil
}
