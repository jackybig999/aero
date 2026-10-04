// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package mid

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestPhase8Gate_MidMeteringAndQuotaExhaustion tests middle platform quota accumulation and circuit breaking.
func TestPhase8Gate_MidMeteringAndQuotaExhaustion(t *testing.T) {
	tempDir := t.TempDir()
	aeroDBPath := filepath.Join(tempDir, "aero.db")
	payDBPath := filepath.Join(tempDir, "aeropay.db")

	payDB, err := NewAeroPayDB(payDBPath)
	if err != nil {
		t.Fatalf("NewAeroPayDB failed: %v", err)
	}
	defer payDB.Close()

	aeroDB, err := NewAeroDB(aeroDBPath, payDB)
	if err != nil {
		t.Fatalf("NewAeroDB failed: %v", err)
	}
	defer aeroDB.Close()

	testToken := "tok_phase8_test_token"
	adminKey := "phase8_admin_secret_key"

	// 创建订阅：LimitBytes = 5000, UsedBytes = 0
	sub := &Subscription{
		SubID:         "sub_phase8_test",
		UserID:        1001,
		UserUUID:      "uuid-phase8-1001",
		SubSlug:       "userphase8",
		SubToken:      testToken,
		SubTicketSeed: "seed123",
		PlanName:      "5K测试套餐",
		LimitBytes:    5000,
		UsedBytes:     0,
		ExpireAt:      time.Now().Add(24 * time.Hour),
		SwitchStatus:  "on",
		Status:        true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	if err := aeroDB.CreateSubscription(sub); err != nil {
		t.Fatalf("CreateSubscription failed: %v", err)
	}

	handler := HandleAdminMetering(aeroDB, adminKey)

	// 第一次上报：BytesUp = 2000, BytesDown = 1000 (总计 3000 < 5000)
	req1Body, _ := json.Marshal(MeteringReportRequest{
		NodeID: "node-1",
		Records: []MeteringRecord{
			{
				Token:     testToken,
				BytesUp:   2000,
				BytesDown: 1000,
			},
		},
	})

	req1 := httptest.NewRequest(http.MethodPost, "/admin/metering", bytes.NewReader(req1Body))
	req1.Header.Set("Aero-Admin-Key", adminKey)
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on first report, got %d, body: %s", w1.Code, w1.Body.String())
	}

	var resp1 MeteringReportResponse
	if err := json.Unmarshal(w1.Body.Bytes(), &resp1); err != nil {
		t.Fatalf("unmarshal resp1 failed: %v", err)
	}
	// 断言 revoked_tokens 为空
	if len(resp1.RevokedTokens) != 0 {
		t.Fatalf("expected revoked_tokens to be empty on first report, got: %v", resp1.RevokedTokens)
	}

	// 检查数据库状态：UsedBytes = 3000, SwitchStatus = "on"
	sub1, err := aeroDB.GetSubscriptionByToken(testToken)
	if err != nil {
		t.Fatalf("GetSubscriptionByToken failed: %v", err)
	}
	if sub1.UsedBytes != 3000 {
		t.Fatalf("expected used_bytes = 3000, got %d", sub1.UsedBytes)
	}
	if sub1.SwitchStatus != "on" {
		t.Fatalf("expected switch_status = 'on', got '%s'", sub1.SwitchStatus)
	}

	// 第二次上报：BytesUp = 1500, BytesDown = 1000 (总计 5500 >= 5000)
	req2Body, _ := json.Marshal(MeteringReportRequest{
		NodeID: "node-1",
		Records: []MeteringRecord{
			{
				Token:     testToken,
				BytesUp:   1500,
				BytesDown: 1000,
			},
		},
	})

	req2 := httptest.NewRequest(http.MethodPost, "/admin/metering", bytes.NewReader(req2Body))
	req2.Header.Set("Aero-Admin-Key", adminKey)
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on second report, got %d, body: %s", w2.Code, w2.Body.String())
	}

	var resp2 MeteringReportResponse
	if err := json.Unmarshal(w2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("unmarshal resp2 failed: %v", err)
	}
	// 断言 revoked_tokens 包含该 token
	foundToken := false
	for _, tok := range resp2.RevokedTokens {
		if tok == testToken {
			foundToken = true
			break
		}
	}
	if !foundToken {
		t.Fatalf("expected revoked_tokens to contain %s, got: %v", testToken, resp2.RevokedTokens)
	}

	// 订阅的 switch_status 变为 "off"
	sub2, err := aeroDB.GetSubscriptionByToken(testToken)
	if err != nil {
		t.Fatalf("GetSubscriptionByToken failed: %v", err)
	}
	if sub2.UsedBytes != 5500 {
		t.Fatalf("expected used_bytes = 5500, got %d", sub2.UsedBytes)
	}
	if sub2.SwitchStatus != "off" {
		t.Fatalf("expected switch_status = 'off', got '%s'", sub2.SwitchStatus)
	}

	// 测试未授权访问 (wrong admin key)
	req3 := httptest.NewRequest(http.MethodPost, "/admin/metering", bytes.NewReader(req2Body))
	req3.Header.Set("Aero-Admin-Key", "invalid_key")
	w3 := httptest.NewRecorder()
	handler.ServeHTTP(w3, req3)
	if w3.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for invalid key, got %d", w3.Code)
	}
}

// TestFinalGate_HighConcurrencyBatchMetering verifies high concurrency batch metering reports
// across 20 concurrent goroutines with 0 database locked errors and 100% accurate usage accounting.
func TestFinalGate_HighConcurrencyBatchMetering(t *testing.T) {
	tempDir := t.TempDir()
	aeroDBPath := filepath.Join(tempDir, "aero.db")
	payDBPath := filepath.Join(tempDir, "aeropay.db")

	payDB, err := NewAeroPayDB(payDBPath)
	if err != nil {
		t.Fatalf("NewAeroPayDB failed: %v", err)
	}
	defer payDB.Close()

	aeroDB, err := NewAeroDB(aeroDBPath, payDB)
	if err != nil {
		t.Fatalf("NewAeroDB failed: %v", err)
	}
	defer aeroDB.Close()

	testToken1 := "tok_gate_high_conc_1"
	testToken2 := "tok_gate_high_conc_2"
	adminKey := "gate_admin_key_super_secret"

	// Create 2 test subscriptions with generous limit_bytes
	sub1 := &Subscription{
		SubID:         "sub_gate_1",
		UserID:        2001,
		UserUUID:      "uuid-gate-2001",
		SubSlug:       "usergate1",
		SubToken:      testToken1,
		SubTicketSeed: "seed1",
		PlanName:      "HighConcurrencyPlan1",
		LimitBytes:    10000000,
		UsedBytes:     0,
		ExpireAt:      time.Now().Add(24 * time.Hour),
		SwitchStatus:  "on",
		Status:        true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	if err := aeroDB.CreateSubscription(sub1); err != nil {
		t.Fatalf("CreateSubscription 1 failed: %v", err)
	}

	sub2 := &Subscription{
		SubID:         "sub_gate_2",
		UserID:        2002,
		UserUUID:      "uuid-gate-2002",
		SubSlug:       "usergate2",
		SubToken:      testToken2,
		SubTicketSeed: "seed2",
		PlanName:      "HighConcurrencyPlan2",
		LimitBytes:    10000000,
		UsedBytes:     0,
		ExpireAt:      time.Now().Add(24 * time.Hour),
		SwitchStatus:  "on",
		Status:        true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	if err := aeroDB.CreateSubscription(sub2); err != nil {
		t.Fatalf("CreateSubscription 2 failed: %v", err)
	}

	handler := HandleAdminMetering(aeroDB, adminKey)

	const (
		concurrency     = 20
		roundsPerWorker = 5
		bytesPerReport  = 1024
	)

	var wg sync.WaitGroup
	errCh := make(chan error, concurrency*roundsPerWorker)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for r := 0; r < roundsPerWorker; r++ {
				reqBody, _ := json.Marshal(MeteringReportRequest{
					NodeID: fmt.Sprintf("edge-node-%d", workerID),
					Records: []MeteringRecord{
						{
							Token:     testToken1,
							BytesUp:   bytesPerReport / 2,
							BytesDown: bytesPerReport / 2,
						},
						{
							Token:     testToken2,
							BytesUp:   bytesPerReport,
							BytesDown: bytesPerReport,
						},
					},
				})

				req := httptest.NewRequest(http.MethodPost, "/admin/metering", bytes.NewReader(reqBody))
				req.Header.Set("Aero-Admin-Key", adminKey)
				req.Header.Set("Content-Type", "application/json")
				rec := httptest.NewRecorder()

				handler.ServeHTTP(rec, req)

				if rec.Code != http.StatusOK {
					errCh <- fmt.Errorf("worker %d got status %d: %s", workerID, rec.Code, rec.Body.String())
					return
				}

				var mResp MeteringReportResponse
				if err := json.NewDecoder(rec.Body).Decode(&mResp); err != nil {
					errCh <- fmt.Errorf("worker %d decode response: %w", workerID, err)
					return
				}

				if mResp.Code != 0 {
					errCh <- fmt.Errorf("worker %d returned code %d: %s", workerID, mResp.Code, mResp.Message)
					return
				}
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrency error: %v", err)
	}

	// Verify exact accounting in database ("精准平账")
	expectedBytes1 := int64(concurrency * roundsPerWorker * bytesPerReport)
	expectedBytes2 := int64(concurrency * roundsPerWorker * bytesPerReport * 2)

	res1, err := aeroDB.GetSubscriptionByToken(testToken1)
	if err != nil {
		t.Fatalf("GetSubscriptionByToken 1 failed: %v", err)
	}
	if res1.UsedBytes != expectedBytes1 {
		t.Fatalf("expected token1 usedBytes=%d, got %d", expectedBytes1, res1.UsedBytes)
	}
	if res1.SwitchStatus != "on" {
		t.Fatalf("expected token1 switch_status='on', got '%s'", res1.SwitchStatus)
	}

	res2, err := aeroDB.GetSubscriptionByToken(testToken2)
	if err != nil {
		t.Fatalf("GetSubscriptionByToken 2 failed: %v", err)
	}
	if res2.UsedBytes != expectedBytes2 {
		t.Fatalf("expected token2 usedBytes=%d, got %d", expectedBytes2, res2.UsedBytes)
	}
	if res2.SwitchStatus != "on" {
		t.Fatalf("expected token2 switch_status='on', got '%s'", res2.SwitchStatus)
	}
}
