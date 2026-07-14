package subscribe

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureWritesClientSubAndStableSecret(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Ensure(EnsureParams{
		Name: "n1", Address: "1.2.3.4:443", Token: "tok", SNI: "example.com",
		PinSPKI: []string{"pin1"},
	}); err != nil {
		t.Fatal(err)
	}
	sec := st.Secret()
	if sec == "" {
		t.Fatal("empty secret")
	}
	// client-sub.json exists and matches document
	raw, err := os.ReadFile(filepath.Join(dir, "client-sub.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Servers[0].PinSPKI[0] != "pin1" || doc.Servers[0].Token != "tok" {
		t.Fatalf("%+v", doc.Servers[0])
	}
	if doc.Signature == "" || !Verify(doc, []byte("tok")) {
		t.Fatalf("signature missing or invalid: %q", doc.Signature)
	}
	if err := st.Ensure(EnsureParams{
		Name: "n1", Address: "5.6.7.8:443", Token: "tok2", SNI: "example.com", PinSPKI: []string{"pin2"},
	}); err != nil {
		t.Fatal(err)
	}
	if st.Secret() != sec {
		t.Fatal("secret should be stable")
	}
	if st.Document().Servers[0].Address != "5.6.7.8:443" {
		t.Fatal(st.Document().Servers[0].Address)
	}
}
