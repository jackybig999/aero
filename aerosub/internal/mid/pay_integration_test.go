// Copyright 2026 AERO Protocol Contributors
// AERO Payment Integration & Wire-Contract Concurrency Regression Tests
package mid

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// setupTestPaymentEnv initializes isolated temporary SQLite databases for AeroPayDB and AeroDB.
func setupTestPaymentEnv(t *testing.T) (*AeroPayDB, *AeroDB, *SecretBox, *GatewayRegistry, *PayWebhookHandler, *PayInHandler, *UserService, *BillingService) {
	tempDir, err := os.MkdirTemp("", "aeropay_test_*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tempDir) })

	payDBPath := filepath.Join(tempDir, "aeropay.db")
	payDB, err := NewAeroPayDB(payDBPath)
	if err != nil {
		t.Fatalf("init payDB: %v", err)
	}
	t.Cleanup(func() { _ = payDB.Close() })

	aeroDBPath := filepath.Join(tempDir, "aero.db")
	aeroDB, err := NewAeroDB(aeroDBPath, payDB)
	if err != nil {
		t.Fatalf("init aeroDB: %v", err)
	}
	t.Cleanup(func() { _ = aeroDB.Close() })

	box, err := NewSecretBox()
	if err != nil {
		t.Fatalf("init secret box: %v", err)
	}

	reg := NewGatewayRegistry(payDB, box)
	userSvc := NewUserService(aeroDB, "test-hmac-secret-pay")
	billingSvc := NewBillingService(aeroDB)
	vpsSvc := NewVPSService(nil, box, nil)

	webhookHandler := NewPayWebhookHandler(reg, payDB, aeroDB, billingSvc, userSvc, vpsSvc, box)
	payInSvc := NewPayInService("", NewLedgerService(payDB))
	payInHandler := NewPayInHandler(payInSvc)
	payInHandler.SetDeps(aeroDB, billingSvc, userSvc, vpsSvc)
	payInHandler.SetGateways(reg, payDB)

	return payDB, aeroDB, box, reg, webhookHandler, payInHandler, userSvc, billingSvc
}

// 1. Test Creem Webhook Wire-Contract and HMAC-SHA256 signature verification
func TestCreemWebhook_WireContract_Success(t *testing.T) {
	payDB, aeroDB, box, reg, webhookHandler, _, userSvc, _ := setupTestPaymentEnv(t)

	// Register user
	user, err := userSvc.Register(CreateUserParams{
		Username: "creem_user",
		Password: "Password123#",
		Email:    "creem@aero-net.com",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	// Setup Creem account credentials
	secret := "creem_sec_wh_789xyz"
	secEnc, _ := box.Encrypt(secret)
	err = payDB.SavePayChannelConfig(&PayChannelConfig{
		Channel:       "creem",
		DisplayName:   "Creem Card",
		WebhookSecret: secEnc,
		PlanMapping:   map[uint64]string{1: "prod_creem_month"},
		IsTest:        true,
		Enabled:       true,
	})
	if err != nil {
		t.Fatalf("save pay config: %v", err)
	}
	_ = reg.Reload()

	// Create pending order
	orderNo := "ORD-20261005-CREEM01"
	order := &Order{
		OrderNo:     orderNo,
		UserID:      user.ID,
		PlanID:      1,
		PlanName:    "月度套餐",
		AmountCents: 999,
		PayChannel:  "creem",
		Status:      "pending",
		CreatedAt:   time.Now(),
	}
	if err := aeroDB.CreateOrder(order); err != nil {
		t.Fatalf("create order: %v", err)
	}
	if err := payDB.RecordIncome(order); err != nil {
		t.Fatalf("record income: %v", err)
	}

	// Raw Wire Contract Payload per Creem OpenAPI spec
	payload := fmt.Sprintf(`{
		"id": "evt_creem_wire_101",
		"eventType": "checkout.completed",
		"data": {
			"id": "ch_creem_wire_999",
			"status": "completed",
			"amount": 999,
			"currency": "USD",
			"customFields": {
				"order_no": "%s"
			}
		}
	}`, orderNo)

	// Compute HMAC-SHA256
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/creem", bytes.NewReader([]byte(payload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("creem-signature", sig)

	rec := httptest.NewRecorder()
	webhookHandler.HandleCreemWebhook(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	// Assert Income is completed
	inc, err := payDB.GetIncomeByOrderNo(orderNo)
	if err != nil || inc == nil {
		t.Fatalf("fetch income: %v", err)
	}
	if inc.Status != "completed" {
		t.Fatalf("expected income status completed, got %s", inc.Status)
	}

	// Assert Double-Entry Ledger IN record exists
	entries, _, err := payDB.List(0, 10)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected 1 ledger entry, got %d (err: %v)", len(entries), err)
	}
	if entries[0].Direction != "IN" || entries[0].AmountCents != 999 || entries[0].Channel != "creem" {
		t.Fatalf("unexpected ledger entry: %+v", entries[0])
	}

	// Assert subscription created
	subs, err := aeroDB.ListSubscriptions(user.ID)
	if err != nil || len(subs) != 1 {
		t.Fatalf("expected 1 subscription, got %d", len(subs))
	}
	if !subs[0].Status {
		t.Fatalf("subscription should be active")
	}
}

// 2. Test Lemon Squeezy Webhook Wire-Contract and tax-inclusive handling
func TestLemonSqueezyWebhook_WireContract_Success(t *testing.T) {
	payDB, aeroDB, box, reg, webhookHandler, _, userSvc, _ := setupTestPaymentEnv(t)

	user, err := userSvc.Register(CreateUserParams{
		Username: "ls_user",
		Password: "Password123#",
		Email:    "ls@aero-net.com",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	secret := "ls_wh_sec_456abc"
	secEnc, _ := box.Encrypt(secret)
	err = payDB.SavePayChannelConfig(&PayChannelConfig{
		Channel:       "lemonsqueezy",
		DisplayName:   "Lemon Squeezy",
		WebhookSecret: secEnc,
		StoreID:       "9988",
		PlanMapping:   map[uint64]string{2: "var_ls_quarter"},
		IsTest:        true,
		Enabled:       true,
	})
	if err != nil {
		t.Fatalf("save pay config: %v", err)
	}
	_ = reg.Reload()

	orderNo := "ORD-20261005-LS02"
	order := &Order{
		OrderNo:     orderNo,
		UserID:      user.ID,
		PlanID:      2,
		PlanName:    "季度套餐",
		AmountCents: 2499,
		PayChannel:  "lemonsqueezy",
		Status:      "pending",
		CreatedAt:   time.Now(),
	}
	_ = aeroDB.CreateOrder(order)
	_ = payDB.RecordIncome(order)

	// Raw Wire Contract Payload per Lemon Squeezy JSON:API format (subtotal matches order price, total includes sales tax)
	payload := fmt.Sprintf(`{
		"meta": {
			"event_name": "order_created",
			"custom_data": {
				"order_no": "%s"
			}
		},
		"data": {
			"id": "ls_ord_wire_777",
			"type": "orders",
			"attributes": {
				"subtotal": 2499,
				"total": 2724,
				"tax": 225,
				"currency": "USD",
				"status": "paid"
			}
		}
	}`, orderNo)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/lemonsqueezy", bytes.NewReader([]byte(payload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-signature", sig)

	rec := httptest.NewRecorder()
	webhookHandler.HandleLemonSqueezyWebhook(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	inc, _ := payDB.GetIncomeByOrderNo(orderNo)
	if inc == nil || inc.Status != "completed" {
		t.Fatalf("expected income completed, got: %+v", inc)
	}

	entries, _, _ := payDB.List(0, 10)
	if len(entries) != 1 || entries[0].AmountCents != 2499 {
		t.Fatalf("expected 1 ledger entry of 2499 cents, got %+v", entries)
	}
}

// 3. Test 50 Concurrent Replay Attempts on the Exact Same Webhook Event
func TestWebhook_ConcurrentReplayProtection(t *testing.T) {
	payDB, aeroDB, box, reg, webhookHandler, _, userSvc, _ := setupTestPaymentEnv(t)

	user, _ := userSvc.Register(CreateUserParams{
		Username: "replay_user",
		Password: "Password123#",
		Email:    "replay@aero-net.com",
	})

	secret := "replay_sec_333"
	secEnc, _ := box.Encrypt(secret)
	_ = payDB.SavePayChannelConfig(&PayChannelConfig{
		Channel:       "creem",
		DisplayName:   "Creem",
		WebhookSecret: secEnc,
		Enabled:       true,
	})
	_ = reg.Reload()

	orderNo := "ORD-20261005-REPLAY"
	order := &Order{
		OrderNo:     orderNo,
		UserID:      user.ID,
		PlanID:      1,
		PlanName:    "月度套餐",
		AmountCents: 999,
		PayChannel:  "creem",
		Status:      "pending",
		CreatedAt:   time.Now(),
	}
	_ = aeroDB.CreateOrder(order)
	_ = payDB.RecordIncome(order)

	payload := fmt.Sprintf(`{
		"id": "evt_replay_attack_fixed_id",
		"eventType": "checkout.completed",
		"data": {
			"id": "ch_creem_fixed_123",
			"status": "completed",
			"amount": 999,
			"currency": "USD",
			"customFields": {
				"order_no": "%s"
			}
		}
	}`, orderNo)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))

	concurrency := 50
	var wg sync.WaitGroup
	statusCodeCount := make(map[int]int)
	var mu sync.Mutex

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/creem", bytes.NewReader([]byte(payload)))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("creem-signature", sig)

			rec := httptest.NewRecorder()
			webhookHandler.HandleCreemWebhook(rec, req)

			mu.Lock()
			statusCodeCount[rec.Code]++
			mu.Unlock()
		}()
	}
	wg.Wait()

	// All 50 attempts should safely return 200 OK (the first fulfills, the remaining 49 return 200 idempotent OK)
	if statusCodeCount[http.StatusOK] != concurrency {
		t.Fatalf("expected all %d requests to return 200, got breakdown: %+v", concurrency, statusCodeCount)
	}

	// Assert exactly 1 ledger record in double_entry_ledger
	entries, total, err := payDB.List(0, 100)
	if err != nil || total != 1 || len(entries) != 1 {
		t.Fatalf("CRITICAL IDEMPOTENCY FAILURE: expected exactly 1 ledger entry, got total=%d, len=%d", total, len(entries))
	}
}

// 4. Test Fraud Amount Tampering (1-cent fraud rejection)
func TestWebhook_FraudAmountTampering(t *testing.T) {
	payDB, aeroDB, box, reg, webhookHandler, _, userSvc, _ := setupTestPaymentEnv(t)

	user, _ := userSvc.Register(CreateUserParams{
		Username: "fraud_target",
		Password: "Password123#",
		Email:    "fraud@aero-net.com",
	})

	secret := "fraud_test_sec_777"
	secEnc, _ := box.Encrypt(secret)
	_ = payDB.SavePayChannelConfig(&PayChannelConfig{
		Channel:       "creem",
		DisplayName:   "Creem",
		WebhookSecret: secEnc,
		Enabled:       true,
	})
	_ = reg.Reload()

	orderNo := "ORD-20261005-FRAUD"
	order := &Order{
		OrderNo:     orderNo,
		UserID:      user.ID,
		PlanID:      3,
		PlanName:    "年度套餐",
		AmountCents: 7999, // Expecting $79.99
		PayChannel:  "creem",
		Status:      "pending",
		CreatedAt:   time.Now(),
	}
	_ = aeroDB.CreateOrder(order)
	_ = payDB.RecordIncome(order)

	// Attacker sends 1 cent instead of 7999 cents
	payload := fmt.Sprintf(`{
		"id": "evt_tampered_amount_1cent",
		"eventType": "checkout.completed",
		"data": {
			"id": "ch_tampered_1cent",
			"status": "completed",
			"amount": 1,
			"currency": "USD",
			"customFields": {
				"order_no": "%s"
			}
		}
	}`, orderNo)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/creem", bytes.NewReader([]byte(payload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("creem-signature", sig)

	rec := httptest.NewRecorder()
	webhookHandler.HandleCreemWebhook(rec, req)

	// Must reject with 400 Bad Request
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for 1-cent fraud tampering, got %d", rec.Code)
	}

	// Income record must be flagged as fraud_alert
	inc, _ := payDB.GetIncomeByOrderNo(orderNo)
	if inc == nil || inc.Status != "fraud_alert" {
		t.Fatalf("expected fraud_alert status on income, got: %+v", inc)
	}

	// Zero ledger entries must be recorded
	entries, total, _ := payDB.List(0, 10)
	if total != 0 || len(entries) != 0 {
		t.Fatalf("zero ledger entries expected for fraud, got %d", total)
	}

	// Zero subscriptions created
	subs, _ := aeroDB.ListSubscriptions(user.ID)
	if len(subs) > 0 {
		t.Fatalf("subscription should not be fulfilled on fraud")
	}
}

// 5. Test Refund Reverse Circuit Breaker (Ledger OUT & Subscription Revocation)
func TestWebhook_RefundReverseCircuitBreaker(t *testing.T) {
	payDB, aeroDB, box, reg, webhookHandler, _, userSvc, _ := setupTestPaymentEnv(t)

	user, _ := userSvc.Register(CreateUserParams{
		Username: "refund_user",
		Password: "Password123#",
		Email:    "refund@aero-net.com",
	})

	secret := "refund_sec_888"
	secEnc, _ := box.Encrypt(secret)
	_ = payDB.SavePayChannelConfig(&PayChannelConfig{
		Channel:       "creem",
		DisplayName:   "Creem",
		WebhookSecret: secEnc,
		Enabled:       true,
	})
	_ = reg.Reload()

	orderNo := "ORD-20261005-REFUND"
	order := &Order{
		OrderNo:     orderNo,
		UserID:      user.ID,
		PlanID:      1,
		PlanName:    "月度套餐",
		AmountCents: 999,
		PayChannel:  "creem",
		Status:      "pending",
		CreatedAt:   time.Now(),
	}
	_ = aeroDB.CreateOrder(order)
	_ = payDB.RecordIncome(order)

	// Step 1: Complete payment first
	payPayload := fmt.Sprintf(`{
		"id": "evt_refund_step1_pay",
		"eventType": "checkout.completed",
		"data": {
			"id": "ch_creem_ref_1",
			"status": "completed",
			"amount": 999,
			"currency": "USD",
			"customFields": {"order_no": "%s"}
		}
	}`, orderNo)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payPayload))
	paySig := hex.EncodeToString(mac.Sum(nil))

	reqPay := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/creem", bytes.NewReader([]byte(payPayload)))
	reqPay.Header.Set("Content-Type", "application/json")
	reqPay.Header.Set("creem-signature", paySig)
	recPay := httptest.NewRecorder()
	webhookHandler.HandleCreemWebhook(recPay, reqPay)
	if recPay.Code != http.StatusOK {
		t.Fatalf("pay step failed: %d", recPay.Code)
	}

	// Verify subscription active
	subs, _ := aeroDB.ListSubscriptions(user.ID)
	if len(subs) != 1 || !subs[0].Status {
		t.Fatalf("subscription should be active before refund")
	}

	// Step 2: Trigger refund event
	refundPayload := fmt.Sprintf(`{
		"id": "evt_refund_step2_ref",
		"eventType": "refund.created",
		"data": {
			"id": "rf_creem_ref_2",
			"amount": 999,
			"currency": "USD",
			"customFields": {"order_no": "%s"}
		}
	}`, orderNo)
	macRef := hmac.New(sha256.New, []byte(secret))
	macRef.Write([]byte(refundPayload))
	refSig := hex.EncodeToString(macRef.Sum(nil))

	reqRef := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/creem", bytes.NewReader([]byte(refundPayload)))
	reqRef.Header.Set("Content-Type", "application/json")
	reqRef.Header.Set("creem-signature", refSig)
	recRef := httptest.NewRecorder()
	webhookHandler.HandleCreemWebhook(recRef, reqRef)
	if recRef.Code != http.StatusOK {
		t.Fatalf("refund step failed: %d", recRef.Code)
	}

	// Verify income status is refunded
	inc, _ := payDB.GetIncomeByOrderNo(orderNo)
	if inc == nil || inc.Status != "refunded" {
		t.Fatalf("expected income status refunded, got: %+v", inc)
	}

	// Verify double-entry ledger has both IN and OUT entries
	entries, total, _ := payDB.List(0, 10)
	if total != 2 || len(entries) != 2 {
		t.Fatalf("expected 2 ledger entries (IN + OUT), got %d", total)
	}
	foundIn := false
	foundOut := false
	for _, e := range entries {
		if e.Direction == "IN" && e.AmountCents == 999 {
			foundIn = true
		}
		if e.Direction == "OUT" && e.AmountCents == 999 {
			foundOut = true
		}
	}
	if !foundIn || !foundOut {
		t.Fatalf("ledger must contain balanced IN and OUT entries: %+v", entries)
	}

	// Verify subscription is deactivated
	subsAfter, _ := aeroDB.ListSubscriptions(user.ID)
	for _, s := range subsAfter {
		if s.Status {
			t.Fatalf("subscription must be deactivated on refund")
		}
	}
}

// 6. Test AES-256-GCM Secret Encryption and Masking API
func TestPayChannelConfig_EncryptionAndMasking(t *testing.T) {
	payDB, _, box, _, webhookHandler, _, _, _ := setupTestPaymentEnv(t)

	rawApiKey := "creem_live_sk_893049102830918230918"
	rawSecret := "creem_whsec_129038109283019823019"

	encApiKey, err := box.Encrypt(rawApiKey)
	if err != nil {
		t.Fatalf("encrypt api key: %v", err)
	}
	encSecret, err := box.Encrypt(rawSecret)
	if err != nil {
		t.Fatalf("encrypt secret: %v", err)
	}

	err = payDB.SavePayChannelConfig(&PayChannelConfig{
		Channel:       "creem",
		DisplayName:   "Creem Live",
		APIKey:        encApiKey,
		WebhookSecret: encSecret,
		StoreID:       "str_999",
		PlanMapping:   map[uint64]string{1: "prod_m", 2: "prod_q"},
		Priority:      1,
		Enabled:       true,
	})
	if err != nil {
		t.Fatalf("save config: %v", err)
	}

	// Test GetPayChannelConfig
	cfg, err := payDB.GetPayChannelConfig("creem")
	if err != nil || cfg == nil {
		t.Fatalf("get config: %v", err)
	}
	if cfg.APIKey == rawApiKey || cfg.WebhookSecret == rawSecret {
		t.Fatalf("FATAL: plaintext stored in database!")
	}

	// Verify decryption
	decKey, err := box.Decrypt(cfg.APIKey)
	if err != nil || decKey != rawApiKey {
		t.Fatalf("decrypt api key mismatch: %v (got %s)", err, decKey)
	}
	decSecret, err := box.Decrypt(cfg.WebhookSecret)
	if err != nil || decSecret != rawSecret {
		t.Fatalf("decrypt secret mismatch: %v (got %s)", err, decSecret)
	}

	// Test Masked output via HTTP API
	req := httptest.NewRequest(http.MethodGet, "/api/v1/payment/accounts", nil)
	rec := httptest.NewRecorder()
	webhookHandler.ListAccounts(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("ListAccounts status %d", rec.Code)
	}

	var resp struct {
		Code int `json:"code"`
		Data struct {
			Accounts []PayChannelConfig `json:"accounts"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}

	var foundCreem *PayChannelConfig
	for _, acc := range resp.Data.Accounts {
		if acc.Channel == "creem" {
			foundCreem = &acc
			break
		}
	}
	if foundCreem == nil {
		t.Fatalf("creem account not found in list response")
	}
	if foundCreem.APIKey == rawApiKey || !bytes.Contains([]byte(foundCreem.APIKey), []byte("****")) {
		t.Fatalf("API key must be masked with ****, got: %s", foundCreem.APIKey)
	}
	if foundCreem.WebhookSecret == rawSecret || !bytes.Contains([]byte(foundCreem.WebhookSecret), []byte("****")) {
		t.Fatalf("Webhook secret must be masked with ****, got: %s", foundCreem.WebhookSecret)
	}
}

// 7. Test User Checkout Session Generation and Channels Listing
func TestPayInHandler_ChannelsAndCheckout(t *testing.T) {
	_, aeroDB, _, _, _, payInHandler, userSvc, _ := setupTestPaymentEnv(t)

	user, _ := userSvc.Register(CreateUserParams{
		Username: "checkout_client",
		Password: "Password123#",
		Email:    "client@aero-net.com",
	})
	token := userSvc.GenerateSessionToken(user)

	// 1. Channels listing must return Creem and Lemon Squeezy (zero WeChat/Alipay)
	reqChan := httptest.NewRequest(http.MethodGet, "/api/v1/payments/in/channels/", nil)
	recChan := httptest.NewRecorder()
	payInHandler.Channels(recChan, reqChan)

	if recChan.Code != http.StatusOK {
		t.Fatalf("Channels returned %d", recChan.Code)
	}

	var chanResp struct {
		Code int                      `json:"code"`
		Data []map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(recChan.Body.Bytes(), &chanResp); err != nil {
		t.Fatalf("unmarshal channels: %v", err)
	}

	channelsFound := make(map[string]bool)
	for _, c := range chanResp.Data {
		chName, _ := c["channel"].(string)
		channelsFound[chName] = true
		if chName == "wechat" || chName == "alipay" || chName == "bankcard" {
			t.Fatalf("FATAL: domestic payment channel leaked in production channels: %s", chName)
		}
	}
	if !channelsFound["creem"] || !channelsFound["lemonsqueezy"] {
		t.Fatalf("expected both creem and lemonsqueezy in channels, got: %+v", channelsFound)
	}

	// 2. Checkout creates pending order and returns checkout_url
	bodyJSON := `{"plan_id": 1, "channel": "creem", "assigned_nodes": ["HK-Node-01"]}`
	reqCheckout := httptest.NewRequest(http.MethodPost, "/api/v1/orders/checkout/", bytes.NewReader([]byte(bodyJSON)))
	reqCheckout.Header.Set("Authorization", "Bearer "+token)
	reqCheckout.Header.Set("Content-Type", "application/json")
	recCheckout := httptest.NewRecorder()
	payInHandler.Checkout(recCheckout, reqCheckout)

	if recCheckout.Code != http.StatusOK {
		t.Fatalf("checkout failed: %d - %s", recCheckout.Code, recCheckout.Body.String())
	}

	var checkoutResp struct {
		Code int `json:"code"`
		Data struct {
			OrderNo     string `json:"order_no"`
			CheckoutURL string `json:"checkout_url"`
			Status      string `json:"status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recCheckout.Body.Bytes(), &checkoutResp); err != nil {
		t.Fatalf("parse checkout resp: %v", err)
	}

	if checkoutResp.Data.OrderNo == "" {
		t.Fatalf("expected order_no in checkout response")
	}
	if checkoutResp.Data.Status != "pending" {
		t.Fatalf("expected pending status, got %s", checkoutResp.Data.Status)
	}
	if checkoutResp.Data.CheckoutURL == "" {
		t.Fatalf("expected non-empty checkout_url")
	}

	// Assert order in aeroDB has pending status
	orders, err := aeroDB.ListOrders(user.ID)
	if err != nil || len(orders) != 1 {
		t.Fatalf("expected 1 order in aeroDB, got %d", len(orders))
	}
	if orders[0].Status != "pending" {
		t.Fatalf("expected order status pending, got %s", orders[0].Status)
	}
}

// 8. Test Pay Account Update Mask Retention (P0 Fix Verification)
func TestPayAccount_MaskRetentionOnUpdate(t *testing.T) {
	payDB, _, box, reg, webhookHandler, _, _, _ := setupTestPaymentEnv(t)

	// 1. Initial save of Creem account with real secret
	rawAPIKey := "creem_live_key_998877665544332211"
	rawWebhookSecret := "creem_wh_secret_abcdef123456"

	reqBody1, _ := json.Marshal(map[string]any{
		"channel":        "creem",
		"display_name":   "Creem Official",
		"api_key":        rawAPIKey,
		"webhook_secret": rawWebhookSecret,
		"store_id":       "store_01",
		"priority":       1,
		"is_test":        true,
		"enabled":        true,
	})
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/payment/accounts", bytes.NewReader(reqBody1))
	w1 := httptest.NewRecorder()
	webhookHandler.SaveAccount(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("SaveAccount step 1 failed: %d %s", w1.Code, w1.Body.String())
	}

	// 2. Query masked accounts
	reqGet := httptest.NewRequest(http.MethodGet, "/api/v1/payment/accounts", nil)
	wGet := httptest.NewRecorder()
	webhookHandler.ListAccounts(wGet, reqGet)
	if wGet.Code != http.StatusOK {
		t.Fatalf("ListAccounts failed: %d", wGet.Code)
	}

	var listResp struct {
		Code int `json:"code"`
		Data struct {
			Accounts []PayChannelConfig `json:"accounts"`
		} `json:"data"`
	}
	if err := json.Unmarshal(wGet.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("decode list resp: %v", err)
	}
	if len(listResp.Data.Accounts) == 0 {
		t.Fatalf("expected at least 1 account")
	}

	creemAcc := listResp.Data.Accounts[0]
	if !strings.Contains(creemAcc.APIKey, "****") {
		t.Fatalf("expected masked APIKey, got %s", creemAcc.APIKey)
	}
	if !strings.Contains(creemAcc.WebhookSecret, "****") {
		t.Fatalf("expected masked WebhookSecret, got %s", creemAcc.WebhookSecret)
	}

	// 3. Admin modifies only Priority and StoreID, keeping the masked keys!
	reqBody2, _ := json.Marshal(map[string]any{
		"channel":        "creem",
		"api_key":        creemAcc.APIKey,        // masked
		"webhook_secret": creemAcc.WebhookSecret, // masked
		"store_id":       "store_02_updated",
		"priority":       99,
		"is_test":        true,
		"enabled":        true,
	})
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/payment/accounts", bytes.NewReader(reqBody2))
	w2 := httptest.NewRecorder()
	webhookHandler.SaveAccount(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("SaveAccount step 2 failed: %d %s", w2.Code, w2.Body.String())
	}

	// 4. Verify in DB: real decrypted keys must match original values!
	savedCfg, err := payDB.GetPayChannelConfig("creem")
	if err != nil || savedCfg == nil {
		t.Fatalf("GetPayChannelConfig failed: %v", err)
	}
	if savedCfg.Priority != 99 {
		t.Fatalf("expected priority 99, got %d", savedCfg.Priority)
	}
	if savedCfg.StoreID != "store_02_updated" {
		t.Fatalf("expected store_id updated, got %s", savedCfg.StoreID)
	}

	decAPIKey, err := box.Decrypt(savedCfg.APIKey)
	if err != nil {
		t.Fatalf("failed to decrypt saved API key: %v (saved value was %s)", err, savedCfg.APIKey)
	}
	if decAPIKey != rawAPIKey {
		t.Fatalf("APIKey corrupted! Expected %s, got %s", rawAPIKey, decAPIKey)
	}

	decWHSecret, err := box.Decrypt(savedCfg.WebhookSecret)
	if err != nil {
		t.Fatalf("failed to decrypt saved webhook secret: %v", err)
	}
	if decWHSecret != rawWebhookSecret {
		t.Fatalf("WebhookSecret corrupted! Expected %s, got %s", rawWebhookSecret, decWHSecret)
	}

	// 5. Verify GatewayRegistry reloaded with original keys
	gw, err := reg.Get("creem")
	if err != nil || gw == nil {
		t.Fatalf("reg.Get(creem) failed: %v", err)
	}
	creemGW, ok := gw.(*CreemGateway)
	if !ok {
		t.Fatalf("expected *CreemGateway")
	}
	if creemGW.apiKey != rawAPIKey {
		t.Fatalf("Gateway apiKey corrupted! Expected %s, got %s", rawAPIKey, creemGW.apiKey)
	}
	if creemGW.webhookSecret != rawWebhookSecret {
		t.Fatalf("Gateway webhookSecret corrupted! Expected %s, got %s", rawWebhookSecret, creemGW.webhookSecret)
	}
}

// 9. Test Order Number CSPRNG Collision-Free (P1 Fix Verification)
func TestOrderNo_CSPRNGCollisionFree(t *testing.T) {
	_, _, _, _, _, payInHandler, userSvc, _ := setupTestPaymentEnv(t)

	u, err := userSvc.Register(CreateUserParams{
		Username: "order_col_user",
		Password: "Password123#",
		Email:    "order_col@aero-net.com",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	token := userSvc.GenerateSessionToken(u)

	const concurrency = 200
	var orderMap sync.Map
	var wg sync.WaitGroup
	errCh := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			reqBody := `{"plan_id": 1, "channel": "creem", "assigned_nodes": ["HK-Node-01"]}`
			req := httptest.NewRequest(http.MethodPost, "/api/v1/orders/checkout/", bytes.NewReader([]byte(reqBody)))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			payInHandler.Checkout(w, req)
			if w.Code != http.StatusOK {
				errCh <- fmt.Errorf("worker %d got status %d: %s", workerID, w.Code, w.Body.String())
				return
			}

			var resp struct {
				Code int `json:"code"`
				Data struct {
					OrderNo string `json:"order_no"`
				} `json:"data"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				errCh <- fmt.Errorf("worker %d decode err: %w", workerID, err)
				return
			}

			orderNo := resp.Data.OrderNo
			if orderNo == "" {
				errCh <- fmt.Errorf("worker %d got empty orderNo", workerID)
				return
			}

			if _, loaded := orderMap.LoadOrStore(orderNo, true); loaded {
				errCh <- fmt.Errorf("CRITICAL: duplicate orderNo detected: %s", orderNo)
				return
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatal(err)
	}
}

// 10. Test Strict JSON Decoding Unknown Fields Rejection (P2 Fix Verification)
func TestCheckout_StrictJSONUnknownFields(t *testing.T) {
	_, _, _, _, _, payInHandler, userSvc, _ := setupTestPaymentEnv(t)

	u, err := userSvc.Register(CreateUserParams{
		Username: "strict_json_user",
		Password: "Password123#",
		Email:    "strict@aero-net.com",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	token := userSvc.GenerateSessionToken(u)

	// Send payload with unknown field "unrecognized_attack_vector"
	bodyJSON := `{"plan_id": 1, "channel": "creem", "unrecognized_attack_vector": "payload"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/orders/checkout/", bytes.NewReader([]byte(bodyJSON)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	payInHandler.Checkout(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected HTTP 400 Bad Request on unknown fields, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "strict decode") && !strings.Contains(w.Body.String(), "unknown field") {
		t.Fatalf("expected strict decode error message, got: %s", w.Body.String())
	}
}

// 11. Test Cross-Database Reconciliation Outbox (Issue #9 Verification)
func TestCrossDB_ReconciliationOutbox(t *testing.T) {
	payDB, aeroDB, _, _, webhookHandler, _, userSvc, _ := setupTestPaymentEnv(t)

	user, err := userSvc.Register(CreateUserParams{
		Username: "reconcile_user",
		Password: "Password123#",
		Email:    "reconcile@aero-net.com",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	orderNo := "ORD-20261005-RECONCILE-001"
	order := &Order{
		OrderNo:       orderNo,
		UserID:        user.ID,
		PlanID:        1,
		PlanName:      "月付基础计划",
		AssignedNodes: []string{"HK-Reconcile-01"},
		AmountCents:   999,
		PayChannel:    "creem",
		Status:        "pending", // Unfulfilled state in aero.db
		CreatedAt:     time.Now(),
	}
	if err := aeroDB.CreateOrder(order); err != nil {
		t.Fatalf("create order: %v", err)
	}

	// Verify order is pending in aeroDB
	ordBefore, err := aeroDB.GetOrderByOrderNo(orderNo)
	if err != nil || ordBefore.Status != "pending" {
		t.Fatalf("expected pending order in aeroDB, got: %v, status: %s", err, ordBefore.Status)
	}

	// In aeropay.db, the income record was completed by webhook
	now := time.Now()
	if err := payDB.UpdateIncomeStatus(orderNo, "completed", "TRD-RECON-9999", "ch_ext_reconcile", &now); err != nil {
		t.Fatalf("update income completed: %v", err)
	}

	// Verify no active subscription exists yet
	subsBefore, err := aeroDB.ListSubscriptions(user.ID)
	if err != nil || len(subsBefore) != 0 {
		t.Fatalf("expected 0 subscriptions before reconcile, got %d", len(subsBefore))
	}

	// Execute cross-database reconciliation loop
	reconciled, err := webhookHandler.ReconcileUnfulfilledOrders()
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if reconciled != 1 {
		t.Fatalf("expected 1 reconciled order, got %d", reconciled)
	}

	// Assert order in aeroDB is now healed to "completed"
	ordAfter, err := aeroDB.GetOrderByOrderNo(orderNo)
	if err != nil {
		t.Fatalf("get order after reconcile: %v", err)
	}
	if ordAfter.Status != "completed" {
		t.Fatalf("expected order status completed after reconcile, got: %s", ordAfter.Status)
	}

	// Assert active subscription was fulfilled and created in aero.db
	subsAfter, err := aeroDB.ListSubscriptions(user.ID)
	if err != nil || len(subsAfter) != 1 {
		t.Fatalf("expected 1 subscription after reconcile, got %d", len(subsAfter))
	}
	if !subsAfter[0].Status {
		t.Fatalf("expected active subscription status == true")
	}

	// Run reconciliation a second time: must be idempotent and heal 0 orders
	reconciledSecond, err := webhookHandler.ReconcileUnfulfilledOrders()
	if err != nil {
		t.Fatalf("second reconcile failed: %v", err)
	}
	if reconciledSecond != 0 {
		t.Fatalf("expected 0 reconciled on second pass, got %d", reconciledSecond)
	}
}

// 12. Test ValidateAndNormalize Contract (Issue #10 Verification)
func TestPayment_ValidateAndNormalize(t *testing.T) {
	// 1. CheckoutSessionReq validation
	validReq := CheckoutSessionReq{
		OrderNo:     "  ORD-20261005-001  ",
		PlanID:      1,
		PlanName:    "  Premium  ",
		AmountCents: 1999,
		UserID:      10,
		UserEmail:   " USER@EXAMPLE.COM ",
	}
	if err := validReq.ValidateAndNormalize(); err != nil {
		t.Fatalf("expected validReq to pass normalization: %v", err)
	}
	if validReq.OrderNo != "ORD-20261005-001" || validReq.PlanName != "Premium" || validReq.UserEmail != "user@example.com" {
		t.Fatalf("fields not properly trimmed or normalized: %+v", validReq)
	}

	emptyOrder := CheckoutSessionReq{OrderNo: "   ", AmountCents: 100, UserID: 1}
	if err := emptyOrder.ValidateAndNormalize(); err == nil {
		t.Fatalf("expected error on empty order_no")
	}

	zeroAmount := CheckoutSessionReq{OrderNo: "ORD-001", AmountCents: 0, UserID: 1}
	if err := zeroAmount.ValidateAndNormalize(); err == nil {
		t.Fatalf("expected error on zero amount_cents")
	}

	zeroUser := CheckoutSessionReq{OrderNo: "ORD-001", AmountCents: 100, UserID: 0}
	if err := zeroUser.ValidateAndNormalize(); err == nil {
		t.Fatalf("expected error on zero user_id")
	}

	// 2. PayChannelConfig validation
	validConfig := PayChannelConfig{
		Channel:     " CREEM ",
		DisplayName: "  Creem Payments  ",
		Priority:    0,
	}
	if err := validConfig.ValidateAndNormalize(); err != nil {
		t.Fatalf("expected validConfig to pass: %v", err)
	}
	if validConfig.Channel != "creem" || validConfig.DisplayName != "Creem Payments" || validConfig.Priority != 1 {
		t.Fatalf("config not normalized properly: %+v", validConfig)
	}
	if validConfig.PlanMapping == nil {
		t.Fatalf("expected non-nil PlanMapping after normalization")
	}

	invalidChannel := PayChannelConfig{
		Channel: "alipay",
	}
	if err := invalidChannel.ValidateAndNormalize(); err == nil {
		t.Fatalf("expected error on unsupported channel 'alipay'")
	}

	// 3. SaveAccount endpoint reject invalid channel config
	_, _, _, _, webhookHandler, _, _, _ := setupTestPaymentEnv(t)
	invalidBody := `{"channel": "wechat", "display_name": "WeChat Pay", "priority": 1}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/payment/accounts", bytes.NewReader([]byte(invalidBody)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	webhookHandler.SaveAccount(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request on invalid channel config, got %d: %s", w.Code, w.Body.String())
	}
}



