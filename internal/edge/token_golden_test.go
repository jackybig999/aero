package edge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// C3 跨组件黄金向量（api/testdata/c3-golden.json，由 sub 的编码生成）：edge 必须能验证并得到相同载荷。
func TestC3GoldenVectorVerifies(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "api", "testdata", "c3-golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var g struct {
		Kid       string      `json:"kid"`
		PublicKey string      `json:"public_key"`
		Claims    TokenClaims `json:"claims"`
		Token     string      `json:"token"`
	}
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	keys, err := parseTokenIssuers(map[string]string{g.Kid: g.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	v := NewTokenVerifier(keys)
	v.now = func() time.Time { return time.Unix(g.Claims.Iat+60, 0) }
	got, err := v.Verify(g.Token)
	if err != nil {
		t.Fatalf("golden token rejected: %v", err)
	}
	if !reflect.DeepEqual(*got, g.Claims) {
		t.Fatalf("claims mismatch:\n got  %+v\n want %+v", *got, g.Claims)
	}
}
