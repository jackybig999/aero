// Copyright 2026 AERO Protocol Contributors
// AERO Master Dual-Database (aero.db + aeropay.db) Full Lifecycle & Isolation Test
package mid

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDualDatabaseIsolationAndLifecycle(t *testing.T) {
	tempDir := t.TempDir()
	aeroDBPath := filepath.Join(tempDir, "aero.db")
	payDBPath := filepath.Join(tempDir, "aeropay.db")

	// 1. Initialize AeroPayDB
	payDB, err := NewAeroPayDB(payDBPath)
	if err != nil {
		t.Fatalf("NewAeroPayDB failed: %v", err)
	}
	defer payDB.Close()

	// 2. Initialize AeroDB
	aeroDB, err := NewAeroDB(aeroDBPath, payDB)
	if err != nil {
		t.Fatalf("NewAeroDB failed: %v", err)
	}
	defer aeroDB.Close()

	// 3. Verify Plans in aero.db (including Unlimited Traffic -1)
	plans, err := aeroDB.ListPlans()
	if err != nil {
		t.Fatalf("ListPlans failed: %v", err)
	}
	if len(plans) < 4 {
		t.Fatalf("expected at least 4 seeded plans, got %d", len(plans))
	}

	var foundUnlimited bool
	for _, p := range plans {
		if p.TrafficBytes == -1 {
			foundUnlimited = true
			if p.Name != "全年不限流量" {
				t.Errorf("expected plan name '全年不限流量', got '%s'", p.Name)
			}
		}
	}
	if !foundUnlimited {
		t.Fatalf("expected unlimited traffic plan (traffic_bytes == -1) in aero.db")
	}

	// 4. Test Create Custom Plan
	newPlan, err := aeroDB.CreatePlan(&Plan{
		Name:         "极速体验版",
		PeriodType:   "week",
		PeriodValue:  1,
		PriceCents:   499,
		TrafficBytes: 50 * 1024 * 1024 * 1024,
		Status:       true,
	})
	if err != nil {
		t.Fatalf("CreatePlan failed: %v", err)
	}
	if newPlan.ID <= 0 {
		t.Fatalf("expected positive plan ID, got %d", newPlan.ID)
	}

	// 5. Test User & Subscription Creation
	userSvc := NewUserService(aeroDB, "test-hmac-secret-12345")
	u, err := userSvc.Register(CreateUserParams{
		Username:   "testclient99",
		Password:   "securePass123!",
		Email:      "testclient99@aero.test",
		PlanName:   "全年不限流量",
		PlanMonths: 12,
		PriceCents: 12999,
	})
	if err != nil {
		t.Fatalf("Register user failed: %v", err)
	}

	tok, loggedInUser, err := userSvc.Login("testclient99", "securePass123!")
	if err != nil || tok == "" || loggedInUser == nil {
		t.Fatalf("Login testclient99 failed: %v", err)
	}

	subs, err := aeroDB.ListSubscriptions(u.ID)
	if err != nil || len(subs) == 0 {
		t.Fatalf("expected user subscription in aero.db, got err=%v len=%d", err, len(subs))
	}
	sub := subs[0]
	if sub.SwitchStatus != "on" {
		t.Errorf("expected subscription switch_status 'on', got '%s'", sub.SwitchStatus)
	}

	// 6. Test Switch OFF
	if err := aeroDB.UpdateSubscriptionSwitch(sub.SubID, "off"); err != nil {
		t.Fatalf("UpdateSubscriptionSwitch to off failed: %v", err)
	}
	updatedSub, err := aeroDB.GetSubscription(sub.SubID)
	if err != nil || updatedSub.SwitchStatus != "off" {
		t.Fatalf("expected switch_status 'off', got %v (err=%v)", updatedSub, err)
	}

	// 7. Test SubBuilder with Switch OFF -> Expect HTTP 403
	sb := NewSubBuilder(aeroDB, nil, nil, nil)
	req := httptest.NewRequest("GET", "/sub/"+sub.SubSlug, nil)
	rec := httptest.NewRecorder()
	sb.ServeSub(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected HTTP 403 Forbidden when switch is 'off', got %d (body: %s)", rec.Code, rec.Body.String())
	}

	// 8. Test Switch ON -> Expect HTTP 200
	_ = aeroDB.UpdateSubscriptionSwitch(sub.SubID, "on")
	rec2 := httptest.NewRecorder()
	sb.ServeSub(rec2, req)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 OK when switch is 'on', got %d (body: %s)", rec2.Code, rec2.Body.String())
	}

	var subDoc map[string]any
	if err := json.Unmarshal(rec2.Body.Bytes(), &subDoc); err != nil {
		t.Fatalf("unmarshal subDoc failed: %v", err)
	}
	if subDoc["switchStatus"] != "on" {
		t.Errorf("expected doc switchStatus 'on', got %v", subDoc["switchStatus"])
	}

	// 9. Test Subscription Renewal
	renewedSub, err := aeroDB.RenewSubscription(sub.SubID, 12, 12999, "全年不限流量")
	if err != nil {
		t.Fatalf("RenewSubscription failed: %v", err)
	}
	if renewedSub.SwitchStatus != "on" {
		t.Errorf("expected renewed subscription switch_status to be 'on', got %s", renewedSub.SwitchStatus)
	}

	// 10. Test Financial Isolation in aeropay.db
	// Create order to test double-entry ledger & income
	order := &Order{
		OrderNo:     "ORD-TEST-9999",
		UserID:      u.ID,
		PlanID:      uint64(newPlan.ID),
		PlanName:    newPlan.Name,
		AmountCents: 12999,
		PayChannel:  "Stripe",
		Status:      "completed",
		CreatedAt:   time.Now(),
	}
	if err := aeroDB.CreateOrder(order); err != nil {
		t.Fatalf("CreateOrder failed: %v", err)
	}

	// Verify aeropay.db contains income
	incomes, totalInc, err := payDB.ListIncome(0, 10)
	if err != nil || totalInc == 0 {
		t.Fatalf("expected income recorded in aeropay.db, got total=%d err=%v", totalInc, err)
	}
	if incomes[0].UserID != u.ID {
		t.Errorf("expected income user_id %d, got %d", u.ID, incomes[0].UserID)
	}

	// Test Settle Batch in aeropay.db
	outEntry, count, err := payDB.SettleBatch("PingPong", "对公收益归集")
	if err != nil || count == 0 || outEntry == nil {
		t.Fatalf("SettleBatch failed: count=%d err=%v", count, err)
	}
	if outEntry.AmountCents != 12999 {
		t.Errorf("expected settled amount 12999, got %d", outEntry.AmountCents)
	}

	// Verify summary in aeropay.db
	summary, err := payDB.GetDailySummary(time.Now())
	if err != nil {
		t.Fatalf("GetDailySummary failed: %v", err)
	}
	if summary.TotalInCents != 12999 {
		t.Errorf("expected summary TotalInCents 12999, got %d", summary.TotalInCents)
	}
	if summary.TotalOutCents != 12999 {
		t.Errorf("expected summary TotalOutCents 12999, got %d", summary.TotalOutCents)
	}

	// 11. Test Delete Subscription -> Expect HTTP 404
	if err := aeroDB.DeleteSubscription(sub.SubID); err != nil {
		t.Fatalf("DeleteSubscription failed: %v", err)
	}
	rec3 := httptest.NewRecorder()
	sb.ServeSub(rec3, req)
	if rec3.Code != http.StatusNotFound {
		t.Fatalf("expected HTTP 404 NotFound after subscription deletion, got %d", rec3.Code)
	}
}

func TestAutoMigrationFromUsersJSON(t *testing.T) {
	tempDir := t.TempDir()
	jsonPath := filepath.Join(tempDir, "users.json")

	// Create dummy users.json
	dummyJSON := `{
		"users": {
			"1": {
				"id": 1,
				"uuid": "u_admin1",
				"username": "migratedadmin",
				"password_hash": "sha256:1234:5678",
				"email": "admin@aero.test",
				"status": true,
				"is_staff": true,
				"plan_name": "年度套餐",
				"sub_slug": "admin998877",
				"sub_token": "usr_token_xyz",
				"sub_ticket_seed": "sec_seed_123"
			}
		},
		"subscriptions": {
			"sub_admin998877": {
				"sub_id": "sub_admin998877",
				"user_id": 1,
				"user_uuid": "u_admin1",
				"sub_slug": "admin998877",
				"sub_token": "usr_token_xyz",
				"sub_ticket_seed": "sec_seed_123",
				"plan_name": "年度套餐",
				"limit_bytes": 107374182400,
				"used_bytes": 1024,
				"switch_status": "on",
				"status": true
			}
		}
	}`
	if err := os.WriteFile(jsonPath, []byte(dummyJSON), 0o644); err != nil {
		t.Fatalf("write dummy json: %v", err)
	}

	aeroDBPath := filepath.Join(tempDir, "aero.db")
	aeroDB, err := NewAeroDB(aeroDBPath, nil)
	if err != nil {
		t.Fatalf("NewAeroDB: %v", err)
	}
	defer aeroDB.Close()

	u, err := aeroDB.GetUserByUsername("migratedadmin")
	if err != nil || u == nil {
		t.Fatalf("expected migratedadmin in aero.db, got err=%v", err)
	}
	if u.Email != "admin@aero.test" || !u.IsStaff {
		t.Errorf("migrated data mismatch: email=%s staff=%v", u.Email, u.IsStaff)
	}

	sub, err := aeroDB.GetSubscriptionBySlug("admin998877")
	if err != nil || sub == nil {
		t.Fatalf("expected migrated subscription in aero.db, got err=%v", err)
	}
	if sub.SwitchStatus != "on" {
		t.Errorf("expected switch_status 'on', got '%s'", sub.SwitchStatus)
	}
}
