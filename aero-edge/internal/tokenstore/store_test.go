package tokenstore

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aero-protocol/aero-edge/internal/auth"
)

func TestPersistRoundTrip(t *testing.T) {
	dir := t.TempDir()
	v := auth.NewValidator()
	s, err := Open(dir, v)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := s.AddReturn("tok-a", "alice", time.Hour)
	if err != nil || tok != "tok-a" {
		t.Fatalf("add: %v %s", err, tok)
	}
	if !v.Validate("tok-a") {
		t.Fatal("validate")
	}

	v2 := auth.NewValidator()
	s2, err := Open(dir, v2)
	if err != nil {
		t.Fatal(err)
	}
	if !v2.Validate("tok-a") {
		t.Fatal("reload missing token")
	}
	if err := s2.Remove("tok-a"); err != nil {
		t.Fatal(err)
	}
	v3 := auth.NewValidator()
	_, _ = Open(dir, v3)
	if v3.Validate("tok-a") {
		t.Fatal("removed token still valid")
	}
	if _, err := os.Stat(filepath.Join(dir, "tokens.json")); err != nil {
		t.Fatal(err)
	}
}
