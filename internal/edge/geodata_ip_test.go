// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

type geoUpstream struct {
	domains string
	cidrs   string
	failIP  bool
	ipHits  int
}

func (u *geoUpstream) client() *http.Client {
	resp := func(code int, body string) *http.Response {
		return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
	}
	return &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		url := req.URL.String()
		switch {
		case strings.Contains(url, "v2ray-rules-dat"):
			return resp(200, u.domains), nil
		case strings.Contains(url, "Loyalsoldier/geoip"):
			u.ipHits++
			if u.failIP {
				return resp(500, "boom"), nil
			}
			return resp(200, u.cidrs), nil
		}
		return nil, io.ErrUnexpectedEOF
	})}
}

func serveBody(t *testing.T, h *GeoDataHandler) string {
	t.Helper()
	return string(h.Data())
}

// 域名与网段合并成一个下发文件；网段里的非法行被丢弃；条数含网段。
func TestGeoDataMergesIPRanges(t *testing.T) {
	up := &geoUpstream{
		domains: "baidu.com\nfull:a.example.cn\n",
		cidrs:   "1.0.1.0/24\nnot-a-cidr\n240e::/18\n<html>\n",
	}
	h := NewGeoDataHandler(t.TempDir())
	h.httpClient = up.client()
	if err := h.ForceUpdate(context.Background()); err != nil {
		t.Fatal(err)
	}
	body := serveBody(t, h)
	for _, want := range []string{"baidu.com\n", "full:a.example.cn\n", "# --- China IP ranges ---\n", "1.0.1.0/24\n", "240e::/18\n"} {
		if !strings.Contains(body, want) {
			t.Errorf("下发内容缺少 %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "not-a-cidr") || strings.Contains(body, "<html>") {
		t.Errorf("网段里的非法行不应进入下发文件:\n%s", body)
	}
	if n, _, _ := h.GetStatus(); n != 4 { // 2 域名 + 2 网段（注释不计）
		t.Errorf("规则条数 = %d, 期望 4", n)
	}
}

// 网段源全部失败：沿用上一次的网段，域名照常更新。
func TestGeoDataKeepsPreviousIPRangesWhenIPSourceFails(t *testing.T) {
	up := &geoUpstream{domains: "first.example\n", cidrs: "1.0.1.0/24\n"}
	h := NewGeoDataHandler(t.TempDir())
	h.httpClient = up.client()
	if err := h.ForceUpdate(context.Background()); err != nil {
		t.Fatal(err)
	}
	up.domains, up.failIP = "second.example\n", true
	if err := h.ForceUpdate(context.Background()); err != nil {
		t.Fatalf("域名可用时更新不应失败: %v", err)
	}
	body := serveBody(t, h)
	if !strings.Contains(body, "second.example") || strings.Contains(body, "first.example") {
		t.Errorf("域名应更新为第二版:\n%s", body)
	}
	if !strings.Contains(body, "1.0.1.0/24") {
		t.Errorf("网段源失败时应沿用上一次的网段:\n%s", body)
	}
}

// 网段源返回的全是垃圾（没有一行合法 CIDR）：当作失败，同样沿用旧网段。
func TestGeoDataIgnoresGarbageIPSource(t *testing.T) {
	up := &geoUpstream{domains: "a.example\n", cidrs: "1.0.1.0/24\n"}
	h := NewGeoDataHandler(t.TempDir())
	h.httpClient = up.client()
	if err := h.ForceUpdate(context.Background()); err != nil {
		t.Fatal(err)
	}
	up.cidrs = "<html>cover page</html>\n"
	up.domains = "b.example\n"
	if err := h.ForceUpdate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if body := serveBody(t, h); !strings.Contains(body, "1.0.1.0/24") || !strings.Contains(body, "b.example") {
		t.Errorf("应沿用旧网段并更新域名:\n%s", body)
	}
}

// 自定义上游（运维自己指定 fetchURL）时不去拉第三方网段。
func TestGeoDataCustomUpstreamSkipsIPRanges(t *testing.T) {
	up := &geoUpstream{cidrs: "1.0.1.0/24\n"}
	h := NewGeoDataHandler(t.TempDir())
	h.fetchURL = "http://mock.internal/custom-rules.txt"
	h.httpClient = &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.String(), "geoip") {
			up.ipHits++
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("custom.example\n")), Header: make(http.Header)}, nil
	})}
	if err := h.ForceUpdate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if up.ipHits != 0 {
		t.Errorf("自定义上游不应请求网段源，请求了 %d 次", up.ipHits)
	}
	if body := serveBody(t, h); strings.Contains(body, "China IP ranges") {
		t.Errorf("不应含网段:\n%s", body)
	}
}

// 过宽的网段（如 0.0.0.0/0、::/0、/7）一律不下发；正常宽度保留。
func TestGeoDataDropsOverWideRanges(t *testing.T) {
	up := &geoUpstream{
		domains: "baidu.com\n",
		cidrs:   "0.0.0.0/0\n::/0\n1.0.0.0/7\n8000::/15\n10.0.0.0/8\n1.0.1.0/24\n240e::/18\n",
	}
	h := NewGeoDataHandler(t.TempDir())
	h.httpClient = up.client()
	if err := h.ForceUpdate(context.Background()); err != nil {
		t.Fatal(err)
	}
	body := serveBody(t, h)
	for _, bad := range []string{"0.0.0.0/0", "::/0", "1.0.0.0/7", "8000::/15"} {
		if strings.Contains(body, bad+"\n") {
			t.Errorf("过宽网段 %s 不应下发:\n%s", bad, body)
		}
	}
	for _, ok := range []string{"10.0.0.0/8\n", "1.0.1.0/24\n", "240e::/18\n"} {
		if !strings.Contains(body, ok) {
			t.Errorf("正常网段 %q 应保留:\n%s", ok, body)
		}
	}
}

// ---- gzip ----

func geoServe(t *testing.T, h *GeoDataHandler, method string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "/api/v1/geodata/direct", nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	if !h.TryServe(rec, req) {
		t.Fatal("TryServe 应处理该路径")
	}
	return rec
}

func TestGeoDataServesGzipWhenAccepted(t *testing.T) {
	up := &geoUpstream{domains: strings.Repeat("example-domain.cn\n", 3000), cidrs: "1.0.1.0/24\n"}
	h := NewGeoDataHandler(t.TempDir())
	h.httpClient = up.client()
	if err := h.ForceUpdate(context.Background()); err != nil {
		t.Fatal(err)
	}
	plain := h.Data()

	// 接受 gzip：返回压缩内容，解压后与明文一致，且明显更小
	rec := geoServe(t, h, http.MethodGet, map[string]string{"Accept-Encoding": "gzip, deflate"})
	if rec.Code != 200 || rec.Header().Get("Content-Encoding") != "gzip" || rec.Header().Get("Vary") != "Accept-Encoding" {
		t.Fatalf("应返回 gzip: code=%d headers=%v", rec.Code, rec.Header())
	}
	zr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(zr)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("解压后应与明文一致: err=%v len(got)=%d len(plain)=%d", err, len(got), len(plain))
	}
	if cl, _ := strconv.Atoi(rec.Header().Get("Content-Length")); cl <= 0 || cl >= len(plain)/4 {
		t.Errorf("压缩后应明显更小: Content-Length=%d 明文=%d", cl, len(plain))
	}

	// 不接受 gzip（含 q=0、没有该头）：明文
	for _, ae := range []string{"", "identity", "gzip;q=0", "br"} {
		rec := geoServe(t, h, http.MethodGet, map[string]string{"Accept-Encoding": ae})
		if rec.Header().Get("Content-Encoding") != "" || !bytes.Equal(rec.Body.Bytes(), plain) {
			t.Errorf("Accept-Encoding=%q 应返回明文", ae)
		}
	}

	// 条件请求：ETag 命中仍是 304（压缩不改变 ETag 语义）
	etag := h.ETag()
	if rec := geoServe(t, h, http.MethodGet, map[string]string{"Accept-Encoding": "gzip", "If-None-Match": etag}); rec.Code != http.StatusNotModified {
		t.Errorf("ETag 命中应 304，got %d", rec.Code)
	}
	// HEAD：有头无体
	if rec := geoServe(t, h, http.MethodHead, map[string]string{"Accept-Encoding": "gzip"}); rec.Body.Len() != 0 || rec.Header().Get("Content-Encoding") != "gzip" {
		t.Errorf("HEAD 应只有头: body=%d", rec.Body.Len())
	}

	// 数据更新后压缩副本随之更新（按 ETag 缓存，不会返回旧数据）
	up.domains = "brand-new.example\n"
	if err := h.ForceUpdate(context.Background()); err != nil {
		t.Fatal(err)
	}
	rec = geoServe(t, h, http.MethodGet, map[string]string{"Accept-Encoding": "gzip"})
	zr, _ = gzip.NewReader(rec.Body)
	got, _ = io.ReadAll(zr)
	if !strings.Contains(string(got), "brand-new.example") || strings.Contains(string(got), "example-domain.cn") {
		t.Errorf("更新后的压缩内容应是新数据: %q", got[:min(len(got), 80)])
	}
}

// 真实客户端路径：Go 的 http.Client 自动协商 gzip 并解压，调用方拿到的仍是明文。
func TestGeoDataGzipRoundTripWithHTTPClient(t *testing.T) {
	up := &geoUpstream{domains: strings.Repeat("example-domain.cn\n", 2000), cidrs: "1.0.1.0/24\n"}
	h := NewGeoDataHandler(t.TempDir())
	h.httpClient = up.client()
	if err := h.ForceUpdate(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h.TryServe(w, r) {
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/api/v1/geodata/direct")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(body, h.Data()) {
		t.Errorf("客户端拿到的应是解压后的明文，len=%d want=%d", len(body), len(h.Data()))
	}
	if !resp.Uncompressed {
		t.Error("应走了 gzip 协商（Uncompressed=true）")
	}
}
