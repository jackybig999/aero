package db

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInitDB(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	database, err := InitDB(dbPath)
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	defer CloseDB()

	if database == nil {
		t.Fatal("Expected non-nil db")
	}

	// Verify tables exist
	var tableName string
	err = database.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='profiles'").Scan(&tableName)
	if err != nil || tableName != "profiles" {
		t.Fatalf("profiles table not found: %v", err)
	}
	_ = os.Remove(dbPath)
}
