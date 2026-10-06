// Copyright 2026 AERO Protocol Contributors
// AERO Webhook Processing Engine & Account Management Handler
package mid

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PayWebhookHandler handles incoming webhooks from Creem and Lemon Squeezy and provides Admin account management APIs.
type PayWebhookHandler struct {
	registry    *GatewayRegistry
	payDB       *AeroPayDB
	userStore   UserStore
	billing     *BillingService
	usersSvc    *UserService
	vpsSvc      *VPSService
	box         *SecretBox
	reconcileMu sync.Mutex
}

// NewPayWebhookHandler constructs a new PayWebhookHandler.
func NewPayWebhookHandler(registry *GatewayRegistry, payDB *AeroPayDB, userStore UserStore, billing *BillingService, usersSvc *UserService, vpsSvc *VPSService, box *SecretBox) *PayWebhookHandler {
	return &PayWebhookHandler{
		registry:  registry,
		payDB:     payDB,
		userStore: userStore,
		billing:   billing,
		usersSvc:  usersSvc,
		vpsSvc:    vpsSvc,
		box:       box,
	}
}

// RegisterRoutes registers webhook and payment management endpoints.
func (h *PayWebhookHandler) RegisterRoutes(mux *http.ServeMux) {
	// Webhook ingress endpoints (exempt from auth gate)
	mux.HandleFunc("POST /api/v1/webhooks/creem", h.HandleCreemWebhook)
	mux.HandleFunc("POST /api/v1/webhooks/creem/", h.HandleCreemWebhook)
	mux.HandleFunc("POST /api/v1/webhooks/lemonsqueezy", h.HandleLemonSqueezyWebhook)
	mux.HandleFunc("POST /api/v1/webhooks/lemonsqueezy/", h.HandleLemonSqueezyWebhook)

	// Sandbox / Mock test helpers (for local and transitional verification)
	mux.HandleFunc("GET /api/v1/payments/mock/checkout", h.HandleMockCheckoutPage)
	mux.HandleFunc("POST /api/v1/payments/mock/complete", h.HandleMockComplete)

	// Admin-only Payment Channel Account Maintenance
	mux.HandleFunc("GET /api/v1/payment/accounts", h.ListAccounts)
	mux.HandleFunc("GET /api/v1/payment/accounts/", h.ListAccounts)
	mux.HandleFunc("POST /api/v1/payment/accounts", h.SaveAccount)
	mux.HandleFunc("POST /api/v1/payment/accounts/", h.SaveAccount)
	mux.HandleFunc("PATCH /api/v1/payment/accounts/{channel}", h.UpdateAccount)
	mux.HandleFunc("PATCH /api/v1/payment/accounts/{channel}/", h.UpdateAccount)
}

func (h *PayWebhookHandler) HandleCreemWebhook(w http.ResponseWriter, r *http.Request) {
	h.handleWebhook(w, r, "creem")
}

func (h *PayWebhookHandler) HandleLemonSqueezyWebhook(w http.ResponseWriter, r *http.Request) {
	h.handleWebhook(w, r, "lemonsqueezy")
}

func (h *PayWebhookHandler) handleWebhook(w http.ResponseWriter, r *http.Request, provider string) {
	gw, err := h.registry.Get(provider)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errResp(1002, "unsupported provider: "+err.Error()))
		return
	}

	event, err := gw.VerifyAndParseWebhook(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errResp(1003, "webhook signature verification failed: "+err.Error()))
		return
	}

	if event.EventID == "" {
		writeJSON(w, http.StatusBadRequest, errResp(1002, "missing event id"))
		return
	}

	// 1. Database idempotency check (Anti-Replay)
	isNew, err := h.payDB.RecordPaymentEvent(event)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errResp(1006, "record event failed: "+err.Error()))
		return
	}
	if !isNew {
		// Already processed earlier, return 200 OK immediately
		writeJSON(w, http.StatusOK, map[string]any{"code": 0, "message": "event already processed (idempotent)"})
		return
	}

	if event.OrderNo == "" {
		writeJSON(w, http.StatusOK, map[string]any{"code": 0, "message": "event ignored: no order_no"})
		return
	}

	// 2. Fetch local income record
	income, err := h.payDB.GetIncomeByOrderNo(event.OrderNo)
	if err != nil || income == nil {
		writeJSON(w, http.StatusOK, map[string]any{"code": 0, "message": "order not found locally"})
		return
	}

	now := time.Now()

	// 3. Handle Payment Success
	if event.EventType == "payment.success" {
		if income.Status == "completed" {
			writeJSON(w, http.StatusOK, map[string]any{"code": 0, "message": "order already completed"})
			return
		}

		// Amount verification: prevent 1-cent fraud
		if event.AmountCents < income.AmountCents {
			_ = h.payDB.UpdateIncomeStatus(event.OrderNo, "fraud_alert", event.ChannelTradeNo, "", nil)
			writeJSON(w, http.StatusBadRequest, errResp(1002, fmt.Sprintf("amount mismatch: expected %d, got %d", income.AmountCents, event.AmountCents)))
			return
		}

		// Transition income state to completed
		_ = h.payDB.UpdateIncomeStatus(event.OrderNo, "completed", event.ChannelTradeNo, "", &now)

		// Record in double-entry ledger (direction = IN)
		ledgerNo := fmt.Sprintf("LDG-%s-%04d", now.Format("20060102150405"), now.Nanosecond()%10000)
		_, _ = h.payDB.Append(&LedgerEntry{
			LedgerNo:    ledgerNo,
			UserID:      income.UserID,
			AmountCents: income.AmountCents,
			Direction:   "IN",
			Channel:     income.PayChannel,
			ChannelRef:  income.OrderNo,
			CreatedAt:   now,
		})

		// Fulfill user subscription in aero.db
		h.fulfillSubscription(income)

		writeJSON(w, http.StatusOK, map[string]any{"code": 0, "message": "payment fulfilled successfully"})
		return
	}

	// 4. Handle Refund or Dispute (Reverse Circuit Breaker)
	if event.EventType == "payment.refunded" {
		if income.Status != "refunded" {
			_ = h.payDB.UpdateIncomeStatus(event.OrderNo, "refunded", event.ChannelTradeNo, "", nil)

			// Record OUT entry in double_entry_ledger
			ledgerNo := fmt.Sprintf("LDG-%s-REF-%04d", now.Format("20060102150405"), now.Nanosecond()%10000)
			_, _ = h.payDB.Append(&LedgerEntry{
				LedgerNo:    ledgerNo,
				UserID:      income.UserID,
				AmountCents: income.AmountCents,
				Direction:   "OUT",
				Channel:     income.PayChannel,
				ChannelRef:  "REFUND-" + income.OrderNo,
				CreatedAt:   now,
			})

			// Deactivate subscription
			h.revokeSubscription(income)
		}
		writeJSON(w, http.StatusOK, map[string]any{"code": 0, "message": "refund processed and subscription revoked"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "message": "event acknowledged"})
}

// fulfillSubscription activates or renews the user's subscription and syncs to edge VPS.
func (h *PayWebhookHandler) fulfillSubscription(income *IncomeRecord) {
	if h.userStore == nil {
		return
	}

	plan, _ := h.billing.GetPlan(int32(income.PlanID))
	durationMonths := int32(1)
	planName := income.PlanName
	var trafficBytes int64 = 100 * 1024 * 1024 * 1024
	if plan != nil {
		durationMonths = plan.DurationMonths
		planName = plan.Name
		if plan.TrafficBytes > 0 {
			trafficBytes = plan.TrafficBytes
		}
	}

	u, err := h.userStore.GetUser(income.UserID)
	if err != nil || u == nil {
		return
	}

	now := time.Now()
	var targetSub *Subscription

	// Check if user has an existing subscription to renew
	subs, _ := h.userStore.ListSubscriptions(income.UserID)
	for _, s := range subs {
		if s.Status && s.ExpireAt.After(now) {
			if renewed, err := h.userStore.RenewSubscription(s.SubID, durationMonths, income.AmountCents, planName); err == nil {
				targetSub = renewed
				break
			}
		}
	}

	if targetSub == nil {
		newSlug := GenerateSubscriptionSlug(u.Username)
		seedRaw := make([]byte, 24)
		_, _ = rand.Read(seedRaw)
		tokRaw := make([]byte, 16)
		_, _ = rand.Read(tokRaw)

		baseExp := now.AddDate(0, int(durationMonths), 0)
		newSub := &Subscription{
			SubID:         fmt.Sprintf("sub_%s", newSlug),
			UserID:        u.ID,
			UserUUID:      u.UUID,
			SubSlug:       newSlug,
			SubToken:      hex.EncodeToString(tokRaw),
			SubTicketSeed: "sec_" + hex.EncodeToString(seedRaw),
			PlanName:      planName,
			AssignedNodes: u.AssignedNodes,
			LimitBytes:    trafficBytes,
			UsedBytes:     0,
			ExpireAt:      baseExp,
			Status:        true,
			CreatedAt:     now,
			UpdatedAt:     now,
		}
		_ = h.userStore.CreateSubscription(newSub)
		targetSub = newSub

		_ = h.userStore.UpdateUser(u.ID, UpdateUserParams{
			PlanName:   &planName,
			PlanMonths: &durationMonths,
			PriceCents: &income.AmountCents,
			ExpireAt:   &baseExp,
		})
		_ = h.userStore.UpdateTraffic(u.ID, -1, trafficBytes)
	}

	// Update userStore orders list
	_ = h.userStore.UpdateOrderStatus(income.OrderNo, "completed")

	// Trigger asynchronous edge node sync with safeGo and error logging/retry
	if h.vpsSvc != nil && targetSub != nil {
		safeGo("webhook-vps-sync-fulfill", func() {
			usr, err := h.userStore.GetUser(targetSub.UserID)
			if err != nil || usr == nil {
				log.Printf("[VPS_SYNC_ALERT] cannot load user %d: %v", targetSub.UserID, err)
				return
			}
			if h.vpsSvc.eps == nil {
				return
			}
			for _, ep := range h.vpsSvc.eps.List() {
				if !ep.Installed || ep.Host == "" {
					continue
				}
				matched := len(targetSub.AssignedNodes) == 0
				for _, nodeName := range targetSub.AssignedNodes {
					if ep.Name == nodeName || ep.Host == nodeName {
						matched = true
						break
					}
				}
				if matched {
					var syncErr error
					for attempt := 0; attempt < 3; attempt++ {
						if syncErr = h.vpsSvc.SyncUsersToEdge(ep.VPSID, []*User{usr}); syncErr == nil {
							break
						}
						time.Sleep(time.Duration(1<<attempt) * 200 * time.Millisecond)
					}
					if syncErr != nil {
						log.Printf("[VPS_SYNC_ALERT] Failed to sync active user %s to edge VPS %s (%s) after 3 attempts: %v",
							usr.Username, ep.Name, ep.Host, syncErr)
					}
				}
			}
		})
	}
}

// revokeSubscription deactivates the subscription on refund/chargeback.
func (h *PayWebhookHandler) revokeSubscription(income *IncomeRecord) {
	if h.userStore == nil {
		return
	}
	subs, _ := h.userStore.ListSubscriptions(income.UserID)
	for _, s := range subs {
		s.Status = false
		_ = h.userStore.CreateSubscription(s) // overwrite with status=false
	}
	_ = h.userStore.UpdateOrderStatus(income.OrderNo, "refunded")

	if h.vpsSvc != nil {
		safeGo("webhook-vps-sync-revoke", func() {
			usr, err := h.userStore.GetUser(income.UserID)
			if err != nil || usr == nil {
				return
			}
			if h.vpsSvc.eps == nil {
				return
			}
			for _, ep := range h.vpsSvc.eps.List() {
				if ep.Installed {
					var syncErr error
					for attempt := 0; attempt < 3; attempt++ {
						if syncErr = h.vpsSvc.SyncUsersToEdge(ep.VPSID, []*User{usr}); syncErr == nil {
							break
						}
						time.Sleep(time.Duration(1<<attempt) * 200 * time.Millisecond)
					}
					if syncErr != nil {
						log.Printf("[VPS_REVOKE_ALERT] Failed to sync revoked user %s to edge VPS %s (%s): %v",
							usr.Username, ep.Name, ep.Host, syncErr)
					}
				}
			}
		})
	}
}

// ReconcileUnfulfilledOrders inspects recent completed income in aeropay.db
// against aero.db orders. If an income record is completed in aeropay.db but the
// corresponding order in aero.db is still pending or unfulfilled (e.g. due to crash
// or network timeout during webhook handling), it automatically fulfills the order
// and subscription, healing cross-database state without data loss.
func (h *PayWebhookHandler) ReconcileUnfulfilledOrders() (int, error) {
	if h.payDB == nil || h.userStore == nil {
		return 0, nil
	}

	h.reconcileMu.Lock()
	defer h.reconcileMu.Unlock()

	recent, err := h.payDB.ListRecentCompletedIncome(100)
	if err != nil {
		return 0, fmt.Errorf("list completed income for reconcile: %w", err)
	}

	reconciled := 0
	for _, inc := range recent {
		ord, err := h.userStore.GetOrderByOrderNo(inc.OrderNo)
		if err != nil {
			// Order might not exist or failed to query
			continue
		}
		if ord.Status != "completed" {
			log.Printf("[RECONCILE] Recovering unfulfilled order %s (user %d, plan %d, amount %d cents)",
				inc.OrderNo, inc.UserID, inc.PlanID, inc.AmountCents)
			incomeCopy := inc
			h.fulfillSubscription(&incomeCopy)
			reconciled++
		}
	}
	return reconciled, nil
}

// StartReconciliationLoop begins a background periodic reconciliation routine.
func (h *PayWebhookHandler) StartReconciliationLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	safeGo("pay-reconcile-loop", func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if n, err := h.ReconcileUnfulfilledOrders(); err != nil {
					log.Printf("[RECONCILE_ALERT] periodic reconciliation error: %v", err)
				} else if n > 0 {
					log.Printf("[RECONCILE] periodic loop successfully healed %d orders", n)
				}
			}
		}
	})
}

// ----------------------------------------------------------------------
// Sandbox / Mock Test Simulation Helpers
// ----------------------------------------------------------------------

func (h *PayWebhookHandler) HandleMockCheckoutPage(w http.ResponseWriter, r *http.Request) {
	orderNo := r.URL.Query().Get("order_no")
	amountStr := r.URL.Query().Get("amount")
	provider := r.URL.Query().Get("provider")
	amountCents, _ := strconv.ParseInt(amountStr, 10, 64)

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>AERO 支付沙盒测试收银台</title>
<style>
body { font-family: sans-serif; background: #0b0f19; color: #f1f5f9; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
.card { background: #131b2e; border: 1px solid #1e293b; border-radius: 12px; padding: 32px; max-width: 480px; width: 100%%; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
h2 { margin-top: 0; color: #38bdf8; }
.info { margin: 16px 0; font-size: 14px; line-height: 1.6; }
.btn { display: inline-block; width: 100%%; box-sizing: border-box; padding: 12px; margin-top: 12px; border-radius: 6px; font-weight: bold; cursor: pointer; text-align: center; text-decoration: none; border: none; }
.btn-pay { background: #22c55e; color: #fff; }
.btn-refund { background: #ef4444; color: #fff; }
.btn-back { background: #334155; color: #cbd5e1; }
</style>
</head>
<body>
<div class="card">
  <h2>AERO 托管收银台 (测试沙盒模式)</h2>
  <div class="info">
    <p><b>当前通道:</b> %s (MoR 托管)</p>
    <p><b>测试订单:</b> <code>%s</code></p>
    <p><b>应付金额:</b> $%.2f USD</p>
    <p style="color:#94a3b8;font-size:12px;">注：当前海外对公账户处于办理中，系统启用了合规沙盒模拟链路，可直接点击下方按钮触发全链路回调履约测试。</p>
  </div>
  <button class="btn btn-pay" onclick="simulate('pay')">模拟支付成功 (触发 Webhook)</button>
  <button class="btn btn-refund" onclick="simulate('refund')">模拟退款 (触发熔断测试)</button>
  <a class="btn btn-back" href="/">返回控制台</a>
</div>
<script>
function simulate(action) {
  fetch('/api/v1/payments/mock/complete', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      order_no: '%s',
      provider: '%s',
      amount_cents: %d,
      action: action
    })
  }).then(res => res.json()).then(data => {
    alert(data.message || '操作成功');
    window.location.href = '/';
  }).catch(err => alert('错误: ' + err));
}
</script>
</body>
</html>`, provider, orderNo, float64(amountCents)/100.0, orderNo, provider, amountCents)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(html))
}

func (h *PayWebhookHandler) HandleMockComplete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OrderNo     string `json:"order_no"`
		Provider    string `json:"provider"`
		AmountCents int64  `json:"amount_cents"`
		Action      string `json:"action"` // "pay" or "refund"
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errResp(1002, "invalid json body: "+err.Error()))
		return
	}

	eventType := "payment.success"
	if req.Action == "refund" {
		eventType = "payment.refunded"
	}

	event := &WebhookEvent{
		EventID:        fmt.Sprintf("mock_evt_%d", time.Now().UnixNano()),
		Provider:       req.Provider,
		EventType:      eventType,
		OrderNo:        req.OrderNo,
		AmountCents:    req.AmountCents,
		Currency:       "USD",
		ChannelTradeNo: fmt.Sprintf("MOCK-TRD-%d", time.Now().UnixNano()%1000000),
		RawPayload:     "mock_payload",
	}

	isNew, err := h.payDB.RecordPaymentEvent(event)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errResp(1006, err.Error()))
		return
	}
	if !isNew {
		writeJSON(w, http.StatusOK, map[string]any{"code": 0, "message": "event already processed"})
		return
	}

	income, err := h.payDB.GetIncomeByOrderNo(event.OrderNo)
	if err != nil || income == nil {
		writeJSON(w, http.StatusBadRequest, errResp(1001, "order not found"))
		return
	}

	now := time.Now()
	if req.Action == "pay" {
		_ = h.payDB.UpdateIncomeStatus(event.OrderNo, "completed", event.ChannelTradeNo, "", &now)
		ledgerNo := fmt.Sprintf("LDG-%s-%04d", now.Format("20060102150405"), now.Nanosecond()%10000)
		_, _ = h.payDB.Append(&LedgerEntry{
			LedgerNo:    ledgerNo,
			UserID:      income.UserID,
			AmountCents: income.AmountCents,
			Direction:   "IN",
			Channel:     income.PayChannel,
			ChannelRef:  income.OrderNo,
			CreatedAt:   now,
		})
		h.fulfillSubscription(income)
		writeJSON(w, http.StatusOK, map[string]any{"code": 0, "message": "沙盒支付完成，节点订阅已自动开通！"})
	} else {
		_ = h.payDB.UpdateIncomeStatus(event.OrderNo, "refunded", event.ChannelTradeNo, "", nil)
		ledgerNo := fmt.Sprintf("LDG-%s-REF-%04d", now.Format("20060102150405"), now.Nanosecond()%10000)
		_, _ = h.payDB.Append(&LedgerEntry{
			LedgerNo:    ledgerNo,
			UserID:      income.UserID,
			AmountCents: income.AmountCents,
			Direction:   "OUT",
			Channel:     income.PayChannel,
			ChannelRef:  "REFUND-" + income.OrderNo,
			CreatedAt:   now,
		})
		h.revokeSubscription(income)
		writeJSON(w, http.StatusOK, map[string]any{"code": 0, "message": "沙盒退款完成，节点订阅已即时熔断！"})
	}
}

// ----------------------------------------------------------------------
// Admin Account Management Handlers (Under /api/v1/payment/accounts)
// ----------------------------------------------------------------------

func (h *PayWebhookHandler) ListAccounts(w http.ResponseWriter, r *http.Request) {
	configs, err := h.payDB.ListPayChannelConfigs()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errResp(1006, err.Error()))
		return
	}

	var maskedList []PayChannelConfig
	for _, c := range configs {
		maskedList = append(maskedList, c.Masked())
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"code": 0,
		"data": map[string]any{
			"accounts": maskedList,
			"results":  maskedList,
		},
	})
}

func (h *PayWebhookHandler) SaveAccount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Channel       string            `json:"channel"`
		DisplayName   string            `json:"display_name"`
		Icon          string            `json:"icon"`
		APIKey        string            `json:"api_key"`
		WebhookSecret string            `json:"webhook_secret"`
		StoreID       string            `json:"store_id"`
		PlanMapping   map[uint64]string `json:"plan_mapping"`
		IsTest        bool              `json:"is_test"`
		Priority      int               `json:"priority"`
		Enabled       bool              `json:"enabled"`
	}

	if err := decodeStrictJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errResp(1002, "invalid json body: "+err.Error()))
		return
	}

	req.Channel = strings.ToLower(strings.TrimSpace(req.Channel))
	if req.Channel != "creem" && req.Channel != "lemonsqueezy" {
		writeJSON(w, http.StatusBadRequest, errResp(1002, "unsupported channel: must be creem or lemonsqueezy"))
		return
	}

	existing, _ := h.payDB.GetPayChannelConfig(req.Channel)

	// Encrypt keys before storing in DB (retaining existing encrypted secrets if masked or omitted)
	apiKeyEnc := ""
	if strings.Contains(req.APIKey, "****") || req.APIKey == "" {
		if existing != nil && existing.APIKey != "" {
			apiKeyEnc = existing.APIKey
		}
	} else if h.box != nil && req.APIKey != "" {
		if enc, err := h.box.Encrypt(req.APIKey); err == nil {
			apiKeyEnc = enc
		} else {
			apiKeyEnc = req.APIKey
		}
	} else {
		apiKeyEnc = req.APIKey
	}

	webhookSecretEnc := ""
	if strings.Contains(req.WebhookSecret, "****") || req.WebhookSecret == "" {
		if existing != nil && existing.WebhookSecret != "" {
			webhookSecretEnc = existing.WebhookSecret
		}
	} else if h.box != nil && req.WebhookSecret != "" {
		if enc, err := h.box.Encrypt(req.WebhookSecret); err == nil {
			webhookSecretEnc = enc
		} else {
			webhookSecretEnc = req.WebhookSecret
		}
	} else {
		webhookSecretEnc = req.WebhookSecret
	}

	if req.DisplayName == "" && existing != nil {
		req.DisplayName = existing.DisplayName
	}
	if req.Icon == "" && existing != nil {
		req.Icon = existing.Icon
	}
	if req.StoreID == "" && existing != nil {
		req.StoreID = existing.StoreID
	}

	cfg := &PayChannelConfig{
		Channel:       req.Channel,
		DisplayName:   req.DisplayName,
		Icon:          req.Icon,
		APIKey:        apiKeyEnc,
		WebhookSecret: webhookSecretEnc,
		StoreID:       req.StoreID,
		PlanMapping:   req.PlanMapping,
		IsTest:        req.IsTest,
		Priority:      req.Priority,
		Enabled:       req.Enabled,
		UpdatedAt:     time.Now(),
	}

	if err := cfg.ValidateAndNormalize(); err != nil {
		writeJSON(w, http.StatusBadRequest, errResp(1002, "invalid channel config: "+err.Error()))
		return
	}

	if err := h.payDB.SavePayChannelConfig(cfg); err != nil {
		writeJSON(w, http.StatusInternalServerError, errResp(1006, "save account: "+err.Error()))
		return
	}

	// Reload active gateway memory
	_ = h.registry.Reload()

	writeJSON(w, http.StatusOK, map[string]any{
		"code":    0,
		"message": "支付账户与通道配置保存成功",
		"data":    cfg.Masked(),
	})
}

func (h *PayWebhookHandler) UpdateAccount(w http.ResponseWriter, r *http.Request) {
	h.SaveAccount(w, r)
}
