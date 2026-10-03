//go:build windows

// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"errors"
	"reflect"
	"testing"
)

func TestAddHostRoutePPPoEFallback(t *testing.T) {
	origCmd := routeCmd
	t.Cleanup(func() {
		routeCmd = origCmd
	})

	var calls [][]string
	routeCmd = func(name string, args ...string) error {
		calls = append(calls, append([]string{name}, args...))
		if len(calls) == 1 {
			return errors.New("The parameter is incorrect.")
		}
		return nil
	}

	err := addHostRoute("198.51.100.1", "100.65.1.2", "23")
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}

	if len(calls) != 2 {
		t.Fatalf("expected exactly 2 route calls, got %d: %v", len(calls), calls)
	}

	// 第一次调用：网关为 100.65.1.2，带 if 23
	call1 := calls[0]
	expectedCall1 := []string{"route", "add", "198.51.100.1", "mask", "255.255.255.255", "100.65.1.2", "metric", "1", "if", "23"}
	if !reflect.DeepEqual(call1, expectedCall1) {
		t.Fatalf("call 1 mismatch: got %v, want %v", call1, expectedCall1)
	}

	// 第二次调用：网关为 0.0.0.0，metric 1，if 23
	call2 := calls[1]
	expectedCall2 := []string{"route", "add", "198.51.100.1", "mask", "255.255.255.255", "0.0.0.0", "metric", "1", "if", "23"}
	if !reflect.DeepEqual(call2, expectedCall2) {
		t.Fatalf("call 2 mismatch: got %v, want %v", call2, expectedCall2)
	}
}

func TestAddHostRouteOtherErrorIndexFallback(t *testing.T) {
	origCmd := routeCmd
	t.Cleanup(func() {
		routeCmd = origCmd
	})

	var calls [][]string
	routeCmd = func(name string, args ...string) error {
		calls = append(calls, append([]string{name}, args...))
		if len(calls) == 1 {
			return errors.New("Access is denied.")
		}
		return nil
	}

	err := addHostRoute("198.51.100.1", "192.168.1.1", "12")
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}

	if len(calls) != 2 {
		t.Fatalf("expected exactly 2 route calls, got %d: %v", len(calls), calls)
	}

	// 第一次调用：网关 192.168.1.1，带 if 12
	call1 := calls[0]
	expectedCall1 := []string{"route", "add", "198.51.100.1", "mask", "255.255.255.255", "192.168.1.1", "metric", "1", "if", "12"}
	if !reflect.DeepEqual(call1, expectedCall1) {
		t.Fatalf("call 1 mismatch: got %v, want %v", call1, expectedCall1)
	}

	// 第二次调用：网关仍是原网关 192.168.1.1，且不带 if
	call2 := calls[1]
	expectedCall2 := []string{"route", "add", "198.51.100.1", "mask", "255.255.255.255", "192.168.1.1", "metric", "1"}
	if !reflect.DeepEqual(call2, expectedCall2) {
		t.Fatalf("call 2 mismatch: got %v, want %v", call2, expectedCall2)
	}
}

func TestDeleteHostRoutesResidue(t *testing.T) {
	origCmd := routeCmd
	t.Cleanup(func() {
		routeCmd = origCmd
	})

	// 场景 1: 5 次 delete 都成功 -> residue == true
	deleteCount := 0
	routeCmd = func(name string, args ...string) error {
		deleteCount++
		return nil
	}

	residue := deleteHostRoutes("198.51.100.1")
	if !residue {
		t.Errorf("expected residue == true when all 5 deletes succeed")
	}
	if deleteCount != 5 {
		t.Errorf("expected 5 delete calls, got %d", deleteCount)
	}

	// 场景 2: 第 2 次失败 -> residue == false 且停止
	deleteCount = 0
	routeCmd = func(name string, args ...string) error {
		deleteCount++
		if deleteCount == 2 {
			return errors.New("The route specified was not found.")
		}
		return nil
	}

	residue = deleteHostRoutes("198.51.100.1")
	if residue {
		t.Errorf("expected residue == false when 2nd delete fails")
	}
	if deleteCount != 2 {
		t.Errorf("expected 2 delete calls before stop, got %d", deleteCount)
	}
}
