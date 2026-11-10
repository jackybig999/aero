package edge

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const subAuthTestToken = "aero_sub_auth_regression_master_token"

func newSubAuthTestHandler(t *testing.T) (*SubHandler, *SubStore) {
	t.Helper()
	store, _, err := BootstrapSubscription(ServerConfig{
		DataDir:                    t.TempDir(),
		Listen:                     ":443",
		Domain:                     "edge.aero.test",
		Token:                      subAuthTestToken,
		AllowSelfSignedCertForTest: true,
	}, nil)
	if err != nil {
		t.Fatalf("BootstrapSubscription: %v", err)
	}
	if store.Secret() == "" {
		t.Fatal("subscription secret must be generated at bootstrap")
	}
	return &SubHandler{Store: store}, store
}

func subAuthGet(t *testing.T, h *SubHandler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://edge.aero.test"+path, nil)
	req.RemoteAddr = "203.0.113.9:40000" // 公网来源
	rec := httptest.NewRecorder()
	if !h.TryServe(rec, req) {
		t.Fatalf("TryServe(%s) did not handle a /sub/ path", path)
	}
	return rec
}

// 回归：匿名请求 /sub/admin 曾返回 200 并带出主 token（2026-11-10 审查 P0-1）。
func TestSubAdminAnonymousRequestIsNotFoundAndLeaksNoToken(t *testing.T) {
	h, _ := newSubAuthTestHandler(t)

	rec := subAuthGet(t, h, "/sub/admin")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /sub/admin status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	if strings.Contains(rec.Body.String(), subAuthTestToken) {
		t.Fatal("GET /sub/admin response leaks the primary token")
	}
}

// 匿名探测 /sub/admin 与任意不存在的路径必须不可区分。
func TestSubAdminAnonymousResponseMatchesUnknownPath(t *testing.T) {
	h, _ := newSubAuthTestHandler(t)

	admin := subAuthGet(t, h, "/sub/admin")
	unknown := subAuthGet(t, h, "/sub/doesnotexist0000")

	if admin.Code != unknown.Code || admin.Body.String() != unknown.Body.String() {
		t.Fatalf("/sub/admin (%d %q) distinguishable from unknown path (%d %q)",
			admin.Code, admin.Body.String(), unknown.Code, unknown.Body.String())
	}
}

// 管理员订阅仍然可用：通过不可猜测的 /sub/{secret} 获取永久、不限量的文档。
func TestSubAdminSecretPathServesUnlimitedAdminDocument(t *testing.T) {
	h, store := newSubAuthTestHandler(t)

	rec := subAuthGet(t, h, "/sub/"+store.Secret())

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /sub/{secret} status = %d, want 200", rec.Code)
	}
	body, err := io.ReadAll(rec.Result().Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var doc SubDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal admin document: %v", err)
	}
	if doc.UserID != "admin" || doc.ExpireAt != 0 || doc.TrafficLimitBytes != 0 {
		t.Fatalf("admin document = userId %q expireAt %d limit %d, want admin/0/0",
			doc.UserID, doc.ExpireAt, doc.TrafficLimitBytes)
	}
	if len(doc.Servers) == 0 || doc.Servers[0].Token != subAuthTestToken {
		t.Fatal("admin document must carry the primary token for the authorized holder")
	}
}

// expectedAdminSubPath 是已鉴权管理接口应返回的管理员订阅路径；secret 未生成时为空。
func expectedAdminSubPath(store *SubStore) string {
	if store == nil || store.Secret() == "" {
		return ""
	}
	return "/sub/" + store.Secret()
}
