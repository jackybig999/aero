// Copyright 2026 AERO Protocol Contributors
// AERO Pure Go Creem Payment Gateway Driver (Zero External Dependencies)
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
	"strconv"
	"time"
)

// CreemGateway implements PaymentGateway for Creem.io via pure Go net/http.
type CreemGateway struct {
	apiKey        string
	webhookSecret string
	isTest        bool
	baseURL       string
	httpClient    *http.Client
	planMapping   map[uint64]string
}

// NewCreemGateway creates a new CreemGateway instance.
func NewCreemGateway(apiKey, webhookSecret string, isTest bool, planMapping map[uint64]string) *CreemGateway {
	baseURL := "https://api.creem.io/v1"
	if isTest {
		baseURL = "https://test-api.creem.io/v1"
	}
	if planMapping == nil {
		planMapping = make(map[uint64]string)
	}
	return &CreemGateway{
		apiKey:        apiKey,
		webhookSecret: webhookSecret,
		isTest:        isTest,
		baseURL:       baseURL,
		httpClient:    &http.Client{Timeout: 15 * time.Second},
		planMapping:   planMapping,
	}
}

func (g *CreemGateway) ProviderName() string {
	return "creem"
}

// CreateCheckout creates a checkout session using Creem REST API.
func (g *CreemGateway) CreateCheckout(ctx context.Context, req CheckoutSessionReq) (*CheckoutSessionResp, error) {
	if err := req.ValidateAndNormalize(); err != nil {
		return nil, fmt.Errorf("creem checkout invalid request: %w", err)
	}
	productID := g.planMapping[req.PlanID]
	if productID == "" {
		productID = fmt.Sprintf("prod_plan_%d", req.PlanID)
	}

	// If no API key configured yet (e.g. merchant account in application phase), provide sandbox mock checkout
	if g.apiKey == "" {
		mockURL := fmt.Sprintf("/api/v1/payments/mock/checkout?provider=creem&order_no=%s&amount=%d&plan_id=%d",
			req.OrderNo, req.AmountCents, req.PlanID)
		return &CheckoutSessionResp{
			CheckoutURL: mockURL,
			ExternalID:  "ch_sandbox_" + req.OrderNo,
		}, nil
	}

	bodyMap := map[string]any{
		"product_id":  productID,
		"request_id":  req.OrderNo,
		"success_url": req.SuccessURL,
		"metadata": map[string]string{
			"order_no": req.OrderNo,
			"user_id":  strconv.FormatUint(req.UserID, 10),
			"plan_id":  strconv.FormatUint(req.PlanID, 10),
		},
	}
	if req.UserEmail != "" {
		bodyMap["customer"] = map[string]string{
			"email": req.UserEmail,
		}
	}

	payload, err := json.Marshal(bodyMap)
	if err != nil {
		return nil, fmt.Errorf("marshal creem checkout request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, g.baseURL+"/checkouts", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create creem http request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", g.apiKey)

	resp, err := g.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("execute creem checkout request: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read creem checkout response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("creem checkout api returned %d: %s", resp.StatusCode, string(respBytes))
	}

	var result struct {
		ID          string `json:"id"`
		CheckoutURL string `json:"checkout_url"`
		Status      string `json:"status"`
	}
	if err := json.Unmarshal(respBytes, &result); err != nil {
		return nil, fmt.Errorf("unmarshal creem checkout response: %w", err)
	}
	if result.CheckoutURL == "" {
		return nil, fmt.Errorf("creem checkout response missing checkout_url")
	}

	return &CheckoutSessionResp{
		CheckoutURL: result.CheckoutURL,
		ExternalID:  result.ID,
	}, nil
}

// VerifyAndParseWebhook verifies the HMAC-SHA256 signature and parses a Creem webhook payload.
func (g *CreemGateway) VerifyAndParseWebhook(r *http.Request) (*WebhookEvent, error) {
	sigHeader := r.Header.Get("creem-signature")
	if sigHeader == "" {
		sigHeader = r.Header.Get("Creem-Signature")
	}

	rawBody, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB limit
	if err != nil {
		return nil, fmt.Errorf("read creem webhook body: %w", err)
	}

	// Validate HMAC-SHA256 if webhookSecret is configured
	if g.webhookSecret != "" {
		if sigHeader == "" {
			return nil, fmt.Errorf("missing creem-signature header")
		}
		mac := hmac.New(sha256.New, []byte(g.webhookSecret))
		mac.Write(rawBody)
		expectedSig := hex.EncodeToString(mac.Sum(nil))
		if subtle.ConstantTimeCompare([]byte(expectedSig), []byte(sigHeader)) != 1 {
			return nil, fmt.Errorf("invalid creem webhook signature")
		}
	}

	var creemEvent struct {
		ID        string          `json:"id"`
		EventID   string          `json:"event_id"`
		EventType string          `json:"eventType"`
		EventName string          `json:"event_name"`
		Type      string          `json:"type"`
		CreatedAt int64           `json:"created_at"`
		Data      json.RawMessage `json:"data"`
		Object    json.RawMessage `json:"object"`
	}

	if err := json.Unmarshal(rawBody, &creemEvent); err != nil {
		return nil, fmt.Errorf("unmarshal creem event: %w", err)
	}

	eventID := creemEvent.ID
	if eventID == "" {
		eventID = creemEvent.EventID
	}

	eventType := creemEvent.EventType
	if eventType == "" {
		eventType = creemEvent.EventName
	}
	if eventType == "" {
		eventType = creemEvent.Type
	}

	dataRaw := creemEvent.Data
	if len(dataRaw) == 0 {
		dataRaw = creemEvent.Object
	}

	var inner struct {
		ID           string          `json:"id"`
		RequestID    string          `json:"request_id"`
		RequestId    string          `json:"requestId"`
		Status       string          `json:"status"`
		Amount       int64           `json:"amount"`
		Currency     string          `json:"currency"`
		Order        *struct {
			ID       string `json:"id"`
			Amount   int64  `json:"amount"`
			Currency string `json:"currency"`
			Status   string `json:"status"`
		} `json:"order"`
		Refund       *struct {
			ID             string `json:"id"`
			RefundAmount   int64  `json:"refund_amount"`
			Amount         int64  `json:"amount"`
			RefundCurrency string `json:"refund_currency"`
			Currency       string `json:"currency"`
		} `json:"refund"`
		CustomFields map[string]any `json:"customFields"`
		Metadata     map[string]any `json:"metadata"`
		CustomData   map[string]any `json:"custom_data"`
	}

	if len(dataRaw) > 0 {
		_ = json.Unmarshal(dataRaw, &inner)
	}

	orderNo := inner.RequestID
	if orderNo == "" {
		orderNo = inner.RequestId
	}
	if orderNo == "" && inner.CustomFields != nil {
		if ord, ok := inner.CustomFields["order_no"].(string); ok {
			orderNo = ord
		}
	}
	if orderNo == "" && inner.Metadata != nil {
		if ord, ok := inner.Metadata["order_no"].(string); ok {
			orderNo = ord
		}
	}
	if orderNo == "" && inner.CustomData != nil {
		if ord, ok := inner.CustomData["order_no"].(string); ok {
			orderNo = ord
		}
	}

	amountCents := inner.Amount
	currency := inner.Currency
	tradeNo := inner.ID

	if amountCents == 0 && inner.Order != nil {
		amountCents = inner.Order.Amount
	}
	if currency == "" && inner.Order != nil {
		currency = inner.Order.Currency
	}
	if tradeNo == "" && inner.Order != nil {
		tradeNo = inner.Order.ID
	}

	normalizedType := "payment.unknown"
	switch eventType {
	case "checkout.completed", "subscription.paid":
		normalizedType = "payment.success"
	case "refund.created", "dispute.created":
		normalizedType = "payment.refunded"
		if inner.Refund != nil {
			if inner.Refund.RefundAmount > 0 {
				amountCents = inner.Refund.RefundAmount
			} else if inner.Refund.Amount > 0 {
				amountCents = inner.Refund.Amount
			}
			if inner.Refund.RefundCurrency != "" {
				currency = inner.Refund.RefundCurrency
			} else if inner.Refund.Currency != "" {
				currency = inner.Refund.Currency
			}
			if inner.Refund.ID != "" {
				tradeNo = inner.Refund.ID
			}
		}
	case "subscription.canceled", "subscription.expired":
		normalizedType = "subscription.cancelled"
	}

	return &WebhookEvent{
		EventID:        eventID,
		Provider:       "creem",
		EventType:      normalizedType,
		OrderNo:        orderNo,
		AmountCents:    amountCents,
		Currency:       currency,
		ChannelTradeNo: tradeNo,
		RawPayload:     string(rawBody),
	}, nil
}
