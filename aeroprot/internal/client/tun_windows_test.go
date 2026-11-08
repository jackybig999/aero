//go:build windows

// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"errors"
	"reflect"
	"strings"
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

func TestSetupRoutesDNSGatewayAlignment(t *testing.T) {
	var executedCommands [][]string
	restore := SetCmdExecutorForTest(func(name string, args ...string) error {
		executedCommands = append(executedCommands, append([]string{name}, args...))
		return nil
	})
	t.Cleanup(restore)

	err := SetupRoutes("aero0", "10.88.0.2/24")
	if err != nil {
		t.Fatalf("unexpected error from SetupRoutes: %v", err)
	}

	foundDNSIPv4 := false
	foundDNSIPv6 := false
	foundNRPT := false
	foundMetric := false

	for _, cmd := range executedCommands {
		joined := ""
		for _, arg := range cmd {
			joined += arg + " "
		}
		// 校验 1: DNS 服务器必须指向虚拟网关 10.88.0.1 与 fd88::1，绝不可指向网卡自身 10.88.0.2 / fd88::2
		if len(cmd) >= 6 && cmd[0] == "netsh" && cmd[2] == "ip" && cmd[3] == "set" && cmd[4] == "dnsservers" {
			foundDNSIPv4 = true
			if !reflect.DeepEqual(cmd, []string{"netsh", "interface", "ip", "set", "dnsservers", "name=aero0", "source=static", "address=10.88.0.1", "validate=no"}) {
				t.Errorf("unexpected ipv4 dnsservers command: %v", cmd)
			}
		}
		if len(cmd) >= 6 && cmd[0] == "netsh" && cmd[2] == "ipv6" && cmd[3] == "set" && cmd[4] == "dnsservers" {
			foundDNSIPv6 = true
			if !reflect.DeepEqual(cmd, []string{"netsh", "interface", "ipv6", "set", "dnsservers", "name=aero0", "source=static", "address=fd88::1", "validate=no"}) {
				t.Errorf("unexpected ipv6 dnsservers command: %v", cmd)
			}
		}
		// 校验 2: NRPT 规则必须指向双栈虚拟网关 10.88.0.1 与 fd88::1
		if cmd[0] == "powershell" {
			for _, arg := range cmd {
				if strings.Contains(arg, "Add-DnsClientNrptRule") && strings.Contains(arg, "10.88.0.1") && strings.Contains(arg, "fd88::1") {
					foundNRPT = true
				}
				if strings.Contains(arg, "10.88.0.2") || strings.Contains(arg, "fd88::2") {
					t.Errorf("CRITICAL BUG: NRPT was directed to local adapter IP causing loopback blackhole!")
				}
			}
		}
		// 校验 3: 虚拟网卡优先级置顶 metric=1
		if len(cmd) >= 7 && cmd[0] == "netsh" && cmd[4] == "interface" && cmd[5] == "aero0" && cmd[6] == "metric=1" {
			foundMetric = true
		}
	}

	if !foundDNSIPv4 {
		t.Errorf("expected netsh ipv4 set dnsservers address=10.88.0.1 command not executed")
	}
	if !foundDNSIPv6 {
		t.Errorf("expected netsh ipv6 set dnsservers address=fd88::1 command not executed")
	}
	if !foundNRPT {
		t.Errorf("expected Add-DnsClientNrptRule NameServers 10.88.0.1,fd88::1 command not executed")
	}
	if !foundMetric {
		t.Errorf("expected netsh interface metric=1 command not executed")
	}
}

func TestSetupRoutesSubnetMaskCalculation(t *testing.T) {
	var executedCommands [][]string
	restore := SetCmdExecutorForTest(func(name string, args ...string) error {
		executedCommands = append(executedCommands, append([]string{name}, args...))
		return nil
	})
	t.Cleanup(restore)

	// 当服务端按 RFC 9484 CONNECT-IP 分配 /32 主机前缀时，
	// Windows netsh 要求网关在同一子网内，因此子网掩码必须自动归一化为 255.255.255.0
	err := SetupRoutes("aero0", "10.88.0.2/32")
	if err != nil {
		t.Fatalf("unexpected error from SetupRoutes: %v", err)
	}

	foundSetAddress := false
	for _, cmd := range executedCommands {
		if len(cmd) >= 5 && cmd[0] == "netsh" && cmd[2] == "ip" && cmd[3] == "set" && cmd[4] == "address" {
			foundSetAddress = true
			expected := []string{"netsh", "interface", "ip", "set", "address", "name=aero0", "source=static", "address=10.88.0.2", "mask=255.255.255.0", "gateway=10.88.0.1", "gwmetric=1"}
			if !reflect.DeepEqual(cmd, expected) {
				t.Fatalf("expected command %v, got %v", expected, cmd)
			}
		}
	}
	if !foundSetAddress {
		t.Fatal("expected netsh set address command not executed")
	}
}

func TestRotatePhysicalDNSRoute(t *testing.T) {
	origCmd := routeCmd
	origDNSFn := getPhysicalDNSServersFn
	t.Cleanup(func() {
		routeCmd = origCmd
		getPhysicalDNSServersFn = origDNSFn
		physDNSRoutesMu.Lock()
		physDNSRoutes = nil
		physDNSRoutesMu.Unlock()
	})

	var routeCalls [][]string
	routeCmd = func(name string, args ...string) error {
		routeCalls = append(routeCalls, append([]string{name}, args...))
		return nil
	}

	// 1. First network: physical DNS 192.168.3.1
	getPhysicalDNSServersFn = func() ([]string, error) {
		return []string{"192.168.3.1"}, nil
	}

	if err := RotatePhysicalDNSRoute(); err != nil {
		t.Fatalf("first RotatePhysicalDNSRoute failed: %v", err)
	}

	foundAdd3 := false
	for _, call := range routeCalls {
		if len(call) >= 4 && call[0] == "route" && call[1] == "add" && call[2] == "192.168.3.1" {
			foundAdd3 = true
			break
		}
	}
	if !foundAdd3 {
		t.Fatalf("expected route add 192.168.3.1, calls: %v", routeCalls)
	}

	// 2. Wi-Fi roaming: network changes, physical DNS is now 192.168.1.1
	routeCalls = nil
	getPhysicalDNSServersFn = func() ([]string, error) {
		return []string{"192.168.1.1"}, nil
	}

	if err := RotatePhysicalDNSRoute(); err != nil {
		t.Fatalf("roaming RotatePhysicalDNSRoute failed: %v", err)
	}

	foundDel3 := false
	foundAdd1 := false
	for _, call := range routeCalls {
		if len(call) >= 3 && call[0] == "route" && call[1] == "delete" && call[2] == "192.168.3.1" {
			foundDel3 = true
		}
		if len(call) >= 4 && call[0] == "route" && call[1] == "add" && call[2] == "192.168.1.1" {
			foundAdd1 = true
		}
	}
	if !foundDel3 {
		t.Fatalf("expected old DNS 192.168.3.1 route delete, got calls: %v", routeCalls)
	}
	if !foundAdd1 {
		t.Fatalf("expected new DNS 192.168.1.1 route add, got calls: %v", routeCalls)
	}

	// 3. Teardown / Clean
	routeCalls = nil
	physDNSRoutesMu.Lock()
	cleanPhysicalDNSRoutesLocked()
	physDNSRoutesMu.Unlock()

	foundDel1 := false
	for _, call := range routeCalls {
		if len(call) >= 3 && call[0] == "route" && call[1] == "delete" && call[2] == "192.168.1.1" {
			foundDel1 = true
		}
	}
	if !foundDel1 {
		t.Fatalf("expected route delete 192.168.1.1 on clean, got calls: %v", routeCalls)
	}
}
