// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// PurityReport represents the composite IP cleanliness and region unblocking status.
type PurityReport struct {
	Score              int       `json:"score"`
	IPCountry          string    `json:"ip_country"`
	YouTubeLoc         string    `json:"youtube_loc"`
	GoogleClean        bool      `json:"google_clean"`
	GoogleHKRedirect   bool      `json:"google_hk_redirect"`
	CFClean            bool      `json:"cf_clean"`
	NativeGeminiOK     bool      `json:"native_gemini_ok"`
	GeminiCountry      string    `json:"gemini_country"`
	WARPInstalled      bool      `json:"warp_installed"`
	WARPRunning        bool      `json:"warp_running"`
	WARPGeminiOK       bool      `json:"warp_gemini_ok"`
	GeminiOK           bool      `json:"gemini_ok"`
	IsCNMarked         bool      `json:"is_cn_marked"`
	IsRegionMismatched bool      `json:"is_region_mismatched"`
	AIBlocked          bool      `json:"ai_blocked"`
	IsWARPEgress       bool      `json:"is_warp_egress"`
	LastProbeAt        time.Time `json:"last_probe_at"`
	ProbeDurationMs    int64     `json:"probe_duration_ms"`
	ProbeError         string    `json:"probe_error,omitempty"`
}

// UnmarshalJSON supports dual snake_case and camelCase fields for wire compatibility.
func (p *PurityReport) UnmarshalJSON(data []byte) error {
	type Alias PurityReport
	aux := struct {
		*Alias
		CamelScore          int    `json:"purityScore"`
		CamelIPCountry      string `json:"ipCountry"`
		CamelYouTubeLoc     string `json:"youtubeLoc"`
		CamelGoogleClean    bool   `json:"googleClean"`
		CamelGoogleHK       bool   `json:"googleHkRedirect"`
		CamelCFClean        bool   `json:"cfClean"`
		CamelNativeGeminiOK bool   `json:"nativeGeminiOk"`
		CamelGeminiCountry  string `json:"geminiCountry"`
		CamelWARPInstalled  bool   `json:"warpInstalled"`
		CamelWARPRunning    bool   `json:"warpRunning"`
		CamelWARPGeminiOK   bool   `json:"warpGeminiOk"`
		CamelGeminiOK       bool   `json:"geminiOk"`
		CamelIsCNMarked     bool   `json:"isCnMarked"`
		CamelIsRegionMis    bool   `json:"isRegionMismatched"`
		CamelAIBlocked      bool   `json:"aiBlocked"`
		CamelIsWARPEgress   bool   `json:"isWarpEgress"`
	}{
		Alias: (*Alias)(p),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if p.Score == 0 && aux.CamelScore != 0 {
		p.Score = aux.CamelScore
	}
	if p.IPCountry == "" && aux.CamelIPCountry != "" {
		p.IPCountry = aux.CamelIPCountry
	}
	if p.YouTubeLoc == "" && aux.CamelYouTubeLoc != "" {
		p.YouTubeLoc = aux.CamelYouTubeLoc
	}
	if !p.GoogleClean && aux.CamelGoogleClean {
		p.GoogleClean = true
	}
	if !p.GoogleHKRedirect && aux.CamelGoogleHK {
		p.GoogleHKRedirect = true
	}
	if !p.CFClean && aux.CamelCFClean {
		p.CFClean = true
	}
	if !p.NativeGeminiOK && aux.CamelNativeGeminiOK {
		p.NativeGeminiOK = true
	}
	if p.GeminiCountry == "" && aux.CamelGeminiCountry != "" {
		p.GeminiCountry = aux.CamelGeminiCountry
	}
	if !p.WARPInstalled && aux.CamelWARPInstalled {
		p.WARPInstalled = true
	}
	if !p.WARPRunning && aux.CamelWARPRunning {
		p.WARPRunning = true
	}
	if !p.WARPGeminiOK && aux.CamelWARPGeminiOK {
		p.WARPGeminiOK = true
	}
	if !p.GeminiOK && aux.CamelGeminiOK {
		p.GeminiOK = true
	}
	if !p.IsCNMarked && aux.CamelIsCNMarked {
		p.IsCNMarked = true
	}
	if !p.IsRegionMismatched && aux.CamelIsRegionMis {
		p.IsRegionMismatched = true
	}
	if !p.AIBlocked && aux.CamelAIBlocked {
		p.AIBlocked = true
	}
	if !p.IsWARPEgress && aux.CamelIsWARPEgress {
		p.IsWARPEgress = true
	}
	return nil
}

var (
	reYouTubeLoc  = regexp.MustCompile(`(?:"INNERTUBE_CONTEXT_GL"|"countryCode"|"gl")\s*:\s*"([A-Z]{2})"`)
	reGeminiCode  = regexp.MustCompile(`,2,1,200,"([A-Z]{3})"`)
	reCFTraceLoc  = regexp.MustCompile(`(?:^|\n)loc=([A-Z]{2})`)
	reCFTraceWarp = regexp.MustCompile(`(?:^|\n)warp=(on|plus)`)
)

// PurityEngine manages IP cleanliness tests, singleflight execution, and in-memory caching.
type PurityEngine struct {
	mu           sync.RWMutex
	cachedReport *PurityReport
	cachedAt     time.Time
	cacheTTL     time.Duration
	inFlight     chan struct{}

	client     *http.Client
	socksProxy string

	// Configurable endpoints for testing
	youtubeURL string
	googleURL  string
	geminiURL  string
	cfURL      string
}

// NewPurityEngine initializes the purity testing engine.
func NewPurityEngine(socksProxy string) *PurityEngine {
	if socksProxy == "" {
		socksProxy = "127.0.0.1:40000"
	}
	return &PurityEngine{
		cacheTTL:   5 * time.Minute,
		socksProxy: socksProxy,
		youtubeURL: "https://www.youtube.com/premium",
		googleURL:  "https://www.google.com/search?q=aero",
		geminiURL:  "https://gemini.google.com",
		cfURL:      "https://cloudflare.com/cdn-cgi/trace",
		client: &http.Client{
			Timeout: 6 * time.Second,
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout: 3 * time.Second,
				}).DialContext,
				TLSHandshakeTimeout: 3 * time.Second,
			},
		},
	}
}

// SetTestEndpoints allows test suites to redirect probes to mock HTTP servers.
func (e *PurityEngine) SetTestEndpoints(yt, google, gemini, cf string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if yt != "" {
		e.youtubeURL = yt
	}
	if google != "" {
		e.googleURL = google
	}
	if gemini != "" {
		e.geminiURL = gemini
	}
	if cf != "" {
		e.cfURL = cf
	}
}

// SetClient overrides the HTTP client for testing.
func (e *PurityEngine) SetClient(c *http.Client) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.client = c
}

// Probe executes cleanliness checks or returns cached results.
func (e *PurityEngine) Probe(ctx context.Context, force bool) (*PurityReport, error) {
	e.mu.Lock()
	now := time.Now()
	if !force && e.cachedReport != nil && now.Sub(e.cachedAt) < e.cacheTTL {
		report := *e.cachedReport
		e.mu.Unlock()
		return &report, nil
	}

	// Singleflight deduplication
	for e.inFlight != nil {
		waitCh := e.inFlight
		e.mu.Unlock()
		select {
		case <-waitCh:
			e.mu.Lock()
			if e.cachedReport != nil {
				report := *e.cachedReport
				e.mu.Unlock()
				return &report, nil
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	inFlight := make(chan struct{})
	e.inFlight = inFlight
	e.mu.Unlock()

	defer func() {
		e.mu.Lock()
		e.inFlight = nil
		close(inFlight)
		e.mu.Unlock()
	}()

	report := e.executeProbe(ctx)

	e.mu.Lock()
	e.cachedReport = report
	e.cachedAt = time.Now()
	res := *report
	e.mu.Unlock()

	return &res, nil
}

func (e *PurityEngine) executeProbe(ctx context.Context) *PurityReport {
	start := time.Now()
	r := &PurityReport{
		LastProbeAt: start,
	}

	// Check if warp-cli is installed
	if _, err := exec.LookPath("warp-cli"); err == nil {
		r.WARPInstalled = true
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	// 1. YouTube Probe
	wg.Add(1)
	go func() {
		defer wg.Done()
		loc, isCN, err := e.probeYouTube(ctx)
		mu.Lock()
		defer mu.Unlock()
		if err == nil {
			r.YouTubeLoc = loc
			if isCN {
				r.IsCNMarked = true
			}
		}
	}()

	// 2. Google Search Probe
	wg.Add(1)
	go func() {
		defer wg.Done()
		clean, hkRedirect, err := e.probeGoogle(ctx)
		mu.Lock()
		defer mu.Unlock()
		if err == nil {
			r.GoogleClean = clean
			r.GoogleHKRedirect = hkRedirect
		}
	}()

	// 3. Gemini Native Probe
	wg.Add(1)
	go func() {
		defer wg.Done()
		ok, country, err := e.probeGemini(ctx)
		mu.Lock()
		defer mu.Unlock()
		if err == nil {
			r.NativeGeminiOK = ok
			r.GeminiCountry = country
		}
	}()

	// 4. Cloudflare Trace Probe
	wg.Add(1)
	go func() {
		defer wg.Done()
		clean, country, err := e.probeCloudflare(ctx)
		mu.Lock()
		defer mu.Unlock()
		if err == nil {
			r.CFClean = clean
			r.IPCountry = country
		}
	}()

	// 5. WARP 40000 Local Probe
	wg.Add(1)
	go func() {
		defer wg.Done()
		running, geminiOK := e.probeWARPLocal(ctx)
		mu.Lock()
		defer mu.Unlock()
		r.WARPRunning = running
		r.WARPGeminiOK = geminiOK
		if running {
			r.WARPInstalled = true
		}
	}()

	wg.Wait()

	r.ProbeDurationMs = time.Since(start).Milliseconds()
	EvaluatePurityReport(r)
	return r
}

func (e *PurityEngine) probeYouTube(ctx context.Context) (loc string, isCN bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.youtubeURL, nil)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	resp, err := e.client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	bodyStr := string(bodyBytes)

	// Check if redirected to or mentions google.cn
	if resp.Request != nil && resp.Request.URL != nil && strings.Contains(resp.Request.URL.Host, "google.cn") {
		return "CN", true, nil
	}
	if strings.Contains(bodyStr, "www.google.cn") {
		return "CN", true, nil
	}

	if m := reYouTubeLoc.FindStringSubmatch(bodyStr); len(m) >= 2 {
		loc = m[1]
		if loc == "CN" {
			isCN = true
		}
		return loc, isCN, nil
	}

	return "", false, nil
}

func (e *PurityEngine) probeGoogle(ctx context.Context) (clean bool, hkRedirect bool, err error) {
	redirectedToHK := false
	customClient := &http.Client{
		Timeout:   e.client.Timeout,
		Transport: e.client.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if strings.Contains(req.URL.Host, "google.com.hk") {
				redirectedToHK = true
			}
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.googleURL, nil)
	if err != nil {
		return false, false, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	resp, err := customClient.Do(req)
	if err != nil {
		return false, false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusFound {
		clean = true
	}
	if resp.Request != nil && resp.Request.URL != nil && strings.Contains(resp.Request.URL.Host, "google.com.hk") {
		redirectedToHK = true
	}

	return clean, redirectedToHK, nil
}

func (e *PurityEngine) probeGemini(ctx context.Context) (ok bool, country string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.geminiURL, nil)
	if err != nil {
		return false, "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	resp, err := e.client.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return false, "CHN", nil
	}

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	bodyStr := string(bodyBytes)

	if m := reGeminiCode.FindStringSubmatch(bodyStr); len(m) >= 2 {
		country = m[1]
		if country == "CHN" || country == "000" {
			return false, country, nil
		}
		return true, country, nil
	}

	if strings.Contains(bodyStr, "45631641,null,true") {
		return true, "USA", nil
	}

	if resp.StatusCode == http.StatusOK {
		return true, "USA", nil
	}

	return false, "", nil
}

func (e *PurityEngine) probeCloudflare(ctx context.Context) (clean bool, country string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.cfURL, nil)
	if err != nil {
		return false, "", err
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		clean = true
	}
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if m := reCFTraceLoc.FindStringSubmatch(string(bodyBytes)); len(m) >= 2 {
		country = m[1]
	}

	return clean, country, nil
}

func (e *PurityEngine) probeWARPLocal(ctx context.Context) (running bool, geminiOK bool) {
	// 1. Check if SOCKS5 proxy port is active
	conn, err := net.DialTimeout("tcp", e.socksProxy, 300*time.Millisecond)
	if err != nil {
		return false, false
	}
	_ = conn.Close()

	// 2. Query Cloudflare trace via SOCKS5
	socksTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialViaSOCKS5(e.socksProxy, addr, 3*time.Second)
		},
		TLSHandshakeTimeout: 3 * time.Second,
	}
	socksClient := &http.Client{
		Transport: socksTransport,
		Timeout:   4 * time.Second,
	}

	reqCF, err := http.NewRequestWithContext(ctx, http.MethodGet, e.cfURL, nil)
	if err == nil {
		if resp, err := socksClient.Do(reqCF); err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
			_ = resp.Body.Close()
			if reCFTraceWarp.Match(body) || bytes.Contains(body, []byte("warp=on")) {
				running = true
			}
		}
	}

	// 3. Query Gemini via SOCKS5
	reqGem, err := http.NewRequestWithContext(ctx, http.MethodGet, e.geminiURL, nil)
	if err == nil {
		reqGem.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")
		if resp, err := socksClient.Do(reqGem); err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
				if !bytes.Contains(body, []byte(`,2,1,200,"CHN"`)) {
					geminiOK = true
				}
			}
		}
	}

	return running, geminiOK
}

// EvaluatePurityReport calculates the composite score and unblocking status.
func EvaluatePurityReport(r *PurityReport) {
	// 1. Region mismatch check must precede score calculation and be strictly idempotent
	if r.YouTubeLoc != "" && r.IPCountry != "" && r.YouTubeLoc != r.IPCountry {
		r.IsRegionMismatched = true
	} else {
		r.IsRegionMismatched = false
	}

	score := 0
	if r.GoogleClean {
		score += 30
	}
	if r.CFClean {
		score += 20
	}
	if r.NativeGeminiOK {
		score += 30
	}
	if r.YouTubeLoc != "" && r.YouTubeLoc != "CN" && !r.IsRegionMismatched {
		score += 20
	}

	// China flagging
	if r.YouTubeLoc == "CN" || r.GoogleHKRedirect || r.GeminiCountry == "CHN" || !r.NativeGeminiOK {
		r.IsCNMarked = true
		r.AIBlocked = true
	}

	// WARP rescue guarantee
	if r.WARPRunning && r.WARPGeminiOK {
		if score < 90 {
			score = 95
		}
		r.GeminiOK = true
		r.IsWARPEgress = true
	} else {
		r.GeminiOK = r.NativeGeminiOK
		r.IsWARPEgress = false
	}

	if score > 100 {
		score = 100
	}
	r.Score = score
}
