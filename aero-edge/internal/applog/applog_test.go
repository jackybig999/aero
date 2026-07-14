// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package applog

import (
	"encoding/json"
	"log"
	"os"
	"strings"
	"testing"
)

func TestInitTextFormat(t *testing.T) {
	defer Close()
	path := t.TempDir() + "/test.log"
	if err := Init(Config{FilePath: path, Format: "text"}); err != nil {
		t.Fatalf("Init text failed: %v", err)
	}

	log.Printf("[TEST] text message")
	Close() // 关闭文件以便 Windows 清理

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if !strings.Contains(string(data), "[TEST] text message") {
		t.Errorf("expected text message, got %q", string(data))
	}
}

func TestInitJSONFormat(t *testing.T) {
	defer Close()
	path := t.TempDir() + "/test.json.log"
	if err := Init(Config{FilePath: path, Format: "json"}); err != nil {
		t.Fatalf("Init json failed: %v", err)
	}

	log.Printf("[TEST] json message")
	Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 {
		t.Fatal("no log output")
	}

	var entry map[string]interface{}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &entry); err != nil {
		t.Fatalf("expected JSON log, got %q: %v", lines[len(lines)-1], err)
	}
	if entry["message"] != "[TEST] json message" {
		t.Errorf("expected message field, got %v", entry["message"])
	}
	if entry["level"] != "info" {
		t.Errorf("expected level=info, got %v", entry["level"])
	}
	if entry["service"] != "aero-edge" {
		t.Errorf("expected service=aero-edge, got %v", entry["service"])
	}
}

func TestExtractLevel(t *testing.T) {
	cases := []struct {
		msg   string
		level string
	}{
		{"[ERROR] something failed", "error"},
		{"[WARN] attention", "warn"},
		{"[DEBUG] details", "debug"},
		{"normal info", "info"},
	}
	for _, c := range cases {
		if got := extractLevel(c.msg); got != c.level {
			t.Errorf("extractLevel(%q) = %q, want %q", c.msg, got, c.level)
		}
	}
}
