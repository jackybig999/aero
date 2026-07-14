// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRegistryCounters(t *testing.T) {
	r := NewRegistry()

	r.ConnectionStarted()
	r.ConnectionStarted()
	r.ConnectionEnded()

	snap := r.Snapshot()
	if snap.ActiveConnections != 1 {
		t.Errorf("active connections = %d, want 1", snap.ActiveConnections)
	}
	if snap.TotalConnections != 2 {
		t.Errorf("total connections = %d, want 2", snap.TotalConnections)
	}

	r.AddBytesSent(100)
	r.AddBytesReceived(200)
	snap = r.Snapshot()
	if snap.BytesSent != 100 {
		t.Errorf("bytes sent = %d, want 100", snap.BytesSent)
	}
	if snap.BytesReceived != 200 {
		t.Errorf("bytes received = %d, want 200", snap.BytesReceived)
	}
}

func TestHealthHandler(t *testing.T) {
	r := NewRegistry()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	r.HealthHandler()(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"status":"healthy"`) {
		t.Errorf("body missing healthy status: %s", body)
	}
}

func TestMetricsHandler(t *testing.T) {
	r := NewRegistry()
	r.ConnectionStarted()
	r.AddBytesSent(1024)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()

	r.MetricsHandler()(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "aero_edge_active_connections 1") {
		t.Errorf("body missing active_connections: %s", body)
	}
	if !strings.Contains(body, "aero_edge_bytes_sent_total 1024") {
		t.Errorf("body missing bytes_sent: %s", body)
	}
}

func TestCheckThresholds(t *testing.T) {
	r := NewRegistry()
	for i := 0; i < 15; i++ {
		r.ConnectionStarted()
	}
	r.AuthFailure()
	r.AuthFailure()
	r.AuthFailure()
	r.AuthFailure()

	// total=15, auth failures=4, rate=0.267. threshold 0.25 -> alert
	alerts := r.CheckThresholds(Thresholds{
		MaxActiveConnections: 10,
		MaxAuthFailureRate:   0.25,
	})

	if len(alerts) != 2 {
		t.Fatalf("expected 2 alerts, got %d: %+v", len(alerts), alerts)
	}

	foundConn := false
	foundAuth := false
	for _, a := range alerts {
		if a.Name == "HighActiveConnections" {
			foundConn = true
		}
		if a.Name == "HighAuthFailureRate" {
			foundAuth = true
		}
	}
	if !foundConn {
		t.Error("missing HighActiveConnections alert")
	}
	if !foundAuth {
		t.Error("missing HighAuthFailureRate alert")
	}
}

func TestRecordAlert(t *testing.T) {
	r := NewRegistry()
	r.RecordAlert("warning", "TestAlert", "test message")

	alerts := r.RecentAlerts(10)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Name != "TestAlert" {
		t.Errorf("alert name = %s", alerts[0].Name)
	}
	if alerts[0].Severity != "warning" {
		t.Errorf("alert severity = %s", alerts[0].Severity)
	}
}
