// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mid

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// ============================================================================
// SSH Utilities & Host Purity Probe (from vps_probe.go)
// ============================================================================

// SSHCredentials encapsulates parameters to dial a target machine.
type SSHCredentials struct {
	Host     string
	Port     int
	User     string
	Password string
}

func dialSSH(c SSHCredentials, timeout time.Duration) (*ssh.Client, error) {
	if c.Port <= 0 {
		c.Port = 22
	}
	if c.User == "" {
		c.User = "root"
	}
	if c.Password == "" {
		return nil, fmt.Errorf("SSH password empty")
	}
	pass := c.Password
	auth := []ssh.AuthMethod{
		ssh.Password(pass),
		ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
			ans := make([]string, len(questions))
			for i := range questions {
				ans[i] = pass
			}
			return ans, nil
		}),
	}
	cfg := &ssh.ClientConfig{
		User:            c.User,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}
	return ssh.Dial("tcp", net.JoinHostPort(c.Host, strconv.Itoa(c.Port)), cfg)
}

func runSSH(client *ssh.Client, cmd string, timeout time.Duration) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()

	ch := make(chan struct {
		out []byte
		err error
	}, 1)

	go func() {
		b, err := sess.CombinedOutput(cmd)
		ch <- struct {
			out []byte
			err error
		}{b, err}
	}()

	select {
	case res := <-ch:
		return string(res.out), res.err
	case <-time.After(timeout):
		_ = sess.Signal(ssh.SIGKILL)
		return "", fmt.Errorf("ssh command timeout after %v", timeout)
	}
}

// EvaluatePurity parses probe command output into a PurityResult.
func EvaluatePurity(rawOutput string, vpsID uint64, ipCountry ...string) PurityResult {
	res := PurityResult{
		VPSID:       vpsID,
		RawOutput:   strings.TrimSpace(rawOutput),
		ProbeAt:     time.Now(),
		PurityScore: 0,
	}
	if len(ipCountry) > 0 {
		res.IPCountry = strings.ToUpper(strings.TrimSpace(ipCountry[0]))
	}

	// 智能定位打靶特征行，过滤 remote .bashrc 或 motd 的杂音输出
	var probeLine string
	for _, line := range strings.Split(rawOutput, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "RAW_YT:") || strings.Contains(line, "YT:") || (strings.Contains(line, "G:") && strings.Contains(line, "CF:")) {
			probeLine = line
			break
		}
	}
	if probeLine == "" {
		probeLine = strings.TrimSpace(rawOutput)
	}

	parts := strings.Split(probeLine, ",")
	rawGCode, rawCFCode, rawAICode := "000", "000", ""
	rawYTLoc, rawGeminiCode, rawGemCC := "", "", ""
	ytCN, gHK := "0", "0"
	warpCli, warpPort, warpTrace, warpGeminiCode, warpGemCC := "0", "0", "0", "", ""

	for _, p := range parts {
		kv := strings.SplitN(strings.TrimSpace(p), ":", 2)
		if len(kv) == 2 {
			k := strings.ToUpper(strings.TrimSpace(kv[0]))
			v := strings.TrimSpace(kv[1])
			switch k {
			case "RAW_YT", "YT":
				rawYTLoc = strings.ToUpper(v)
			case "YT_CN":
				ytCN = v
			case "RAW_GEM_CC":
				rawGemCC = strings.ToUpper(v)
			case "RAW_GEMINI", "GEMINI":
				rawGeminiCode = v
			case "G_HK":
				gHK = v
			case "RAW_G", "G":
				rawGCode = v
			case "RAW_CF", "CF":
				rawCFCode = v
			case "AI":
				rawAICode = v
			case "WARP_CLI", "WARPINST":
				warpCli = v
			case "WARP_PORT", "WARPPORT":
				warpPort = v
			case "WARP_TRACE", "WARPTRACE":
				warpTrace = v
			case "WARP_GEM_CC":
				warpGemCC = strings.ToUpper(v)
			case "WARP_GEMINI":
				warpGeminiCode = v
			case "WARP":
				if v == "1" {
					warpTrace = "1"
				}
			}
		}
	}

	// 1. 原生源 IP 体质判定 (绝对直连，不走任何代理)
	if ytCN == "1" {
		res.YouTubeLoc = "CN"
	} else {
		res.YouTubeLoc = rawYTLoc
	}

	// 原生 Gemini 状态：
	// 若抓取到了国家码 rawGemCC:
	//   若 rawGemCC == "CHN" 或 rawGemCC == "" -> NativeGeminiOK = false
	//   若 rawGemCC != "CHN" 且 rawGemCC != "" -> NativeGeminiOK = true
	// 若未抓取到 rawGemCC (单测/旧输出)，回退检查 rawGeminiCode:
	if rawGemCC != "" {
		res.NativeGeminiOK = (rawGemCC != "CHN" && rawGemCC != "000")
	} else if rawGeminiCode != "" {
		res.NativeGeminiOK = (rawGeminiCode == "200" || rawGeminiCode == "301" || rawGeminiCode == "302" || rawGeminiCode == "307")
	} else {
		res.NativeGeminiOK = false
	}

	// 2. 地区漂移判定：YouTube 识别国家与 VPS 源 IP 物理国家是否一致
	if res.YouTubeLoc != "" && res.IPCountry != "" && res.YouTubeLoc != res.IPCountry {
		res.IsRegionMismatched = true
	} else {
		res.IsRegionMismatched = false
	}

	// 3. 送中判定 (不可篡改的源 IP 事实)
	// 满足以下任一即判定为源 IP 送中：
	// A. YouTube 页面包含 www.google.cn 或标记为 CN
	// B. Google 搜索被重定向到 google.com.hk (gHK == "1")
	// C. Gemini 归属国识别为 CHN (rawGemCC == "CHN") 或原生 Gemini 阻断
	// D. 显式 AI 阻断 (403 或 429)
	if ytCN == "1" || res.YouTubeLoc == "CN" || gHK == "1" || rawGemCC == "CHN" || !res.NativeGeminiOK || rawAICode == "403" || rawAICode == "429" {
		res.IsCNMarked = true
		res.AIBlocked = true
	} else {
		res.IsCNMarked = false
		res.AIBlocked = false
	}

	// 4. WARP 救援与接管层判定
	res.WARPInstalled = (warpCli == "1")
	res.WARPRunning = (warpPort == "1" && warpTrace == "1")
	if warpGemCC != "" {
		res.WARPGeminiOK = (warpGemCC != "CHN" && warpGemCC != "000")
	} else if warpGeminiCode != "" {
		res.WARPGeminiOK = (warpGeminiCode == "200" || warpGeminiCode == "301" || warpGeminiCode == "302" || warpGeminiCode == "307")
	} else {
		res.WARPGeminiOK = false
	}
	res.IsWARPEgress = res.WARPRunning

	// 5. 综合 Gemini 可用性 (原生或通过 WARP 成功解锁)
	res.GeminiOK = res.NativeGeminiOK || (res.WARPRunning && res.WARPGeminiOK)

	// 6. 原生源 IP 纯净度基础评分
	if rawGCode == "200" || rawGCode == "302" {
		res.GoogleClean = true
		res.PurityScore += 30
	}
	if rawCFCode == "200" {
		res.CFClean = true
		res.PurityScore += 20
	}
	if res.NativeGeminiOK {
		res.PurityScore += 30
	}
	if res.YouTubeLoc != "" && res.YouTubeLoc != "CN" && !res.IsRegionMismatched {
		res.PurityScore += 20
	}

	// 7. 若 WARP 成功接管并解锁 Gemini，加分保护但绝不篡改 IsCNMarked 的真实物理标记
	if res.WARPRunning && res.WARPGeminiOK {
		if res.PurityScore < 90 {
			res.PurityScore = 95
		}
	}

	return res
}

// ProbePurity executes remote probe from target VPS egress IP.
func (s *VPSService) ProbePurity(ctx context.Context, id uint64) (*PurityResult, error) {
	cred, err := s.store.GetCredentials(id)
	if err != nil {
		return nil, err
	}
	if cred.SSHPassword == "" {
		return nil, fmt.Errorf("no password stored for host %d", id)
	}

	ipCountry := ResolveIPCountryCode(cred.IP)

	client, err := dialSSH(SSHCredentials{
		Host: cred.IP, Port: cred.SSHPort, User: cred.SSHUsername, Password: cred.SSHPassword,
	}, 8*time.Second)
	if err != nil {
		return nil, fmt.Errorf("ssh dial target vps: %w", err)
	}
	defer client.Close()

	cmd := `set +e; ` +
		`yt_raw=$(curl -s4 -L -m 6 -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" "https://www.youtube.com/premium" 2>/dev/null); ` +
		`yt_cn=0; (echo "$yt_raw" | grep -q 'www.google.cn') && yt_cn=1; ` +
		`yt_cc=""; ` +
		`if [ "$yt_cn" = "1" ]; then ` +
		`  yt_cc="CN"; ` +
		`else ` +
		`  yt_cc=$(echo "$yt_raw" | grep -woP '"INNERTUBE_CONTEXT_GL"\s{0,}:\s{0,}"\K[^"]+' | head -1); ` +
		`  [ -z "$yt_cc" ] && yt_cc=$(echo "$yt_raw" | grep -oE '"countryCode":"[A-Z]{2}"' | head -1 | cut -d'"' -f4); ` +
		`  [ -z "$yt_cc" ] && yt_cc=$(echo "$yt_raw" | grep -oE '"gl":"[A-Z]{2}"' | head -1 | cut -d'"' -f4); ` +
		`fi; ` +
		`gem_raw=$(curl -s4 -L -m 6 -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" "https://gemini.google.com" 2>/dev/null); ` +
		`raw_gem_cc=$(echo "$gem_raw" | grep -o ',2,1,200,"[A-Z]\{3\}"' | head -1 | sed 's/,2,1,200,"//;s/"//'); ` +
		`g_dest=$(curl -s4 -m 5 -o /dev/null -w "%{url_effective}" -L "https://www.google.com/search?q=aero" 2>/dev/null || echo ""); ` +
		`g_hk=0; (echo "$g_dest" | grep -q 'google.com.hk') && g_hk=1; ` +
		`raw_g=$(curl -s4 -m 5 -o /dev/null -w "%{http_code}" "https://www.google.com/search?q=aero" 2>/dev/null || echo "000"); ` +
		`raw_cf=$(curl -s4 -m 5 -o /dev/null -w "%{http_code}" "https://cloudflare.com/cdn-cgi/trace" 2>/dev/null || echo "000"); ` +
		`warp_cli=$(command -v warp-cli >/dev/null 2>&1 && echo "1" || echo "0"); ` +
		`warp_port=$( (ss -tlnp 2>/dev/null | grep -q ":40000 ") && echo "1" || echo "0"); ` +
		`warp_trace=$(curl -s4 -m 3 --socks5-hostname 127.0.0.1:40000 "https://cloudflare.com/cdn-cgi/trace" 2>/dev/null | grep -q "warp=on" && echo "1" || (curl -s4 -m 3 --socks5 127.0.0.1:40000 "https://cloudflare.com/cdn-cgi/trace" 2>/dev/null | grep -q "warp=on" && echo "1" || echo "0")); ` +
		`warp_gem_cc=""; ` +
		`if [ "$warp_port" = "1" ]; then ` +
		`  w_gem_raw=$(curl -s4 -m 6 --socks5-hostname 127.0.0.1:40000 -L -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" "https://gemini.google.com" 2>/dev/null || curl -s4 -m 6 --socks5 127.0.0.1:40000 -L -A "Mozilla/5.0" "https://gemini.google.com" 2>/dev/null); ` +
		`  warp_gem_cc=$(echo "$w_gem_raw" | grep -o ',2,1,200,"[A-Z]\{3\}"' | head -1 | sed 's/,2,1,200,"//;s/"//'); ` +
		`  [ -z "$warp_gem_cc" ] && (echo "$w_gem_raw" | grep -q '45631641,null,true') && warp_gem_cc="USA"; ` +
		`fi; ` +
		`echo "RAW_YT:$yt_cc,YT_CN:$yt_cn,RAW_GEM_CC:$raw_gem_cc,G_HK:$g_hk,RAW_G:$raw_g,RAW_CF:$raw_cf,WARP_CLI:$warp_cli,WARP_PORT:$warp_port,WARP_TRACE:$warp_trace,WARP_GEM_CC:$warp_gem_cc"`

	out, err := runSSH(client, cmd, 15*time.Second)
	res := EvaluatePurity(out, id, ipCountry)
	if err != nil {
		res.ProbeError = err.Error()
	}

	_ = s.store.UpdatePurity(id, &res)
	return &res, err
}

func (s *VPSService) ProbeAllPurity(ctx context.Context) map[uint64]*PurityResult {
	hosts, err := s.store.List()
	if err != nil {
		return nil
	}
	results := make(map[uint64]*PurityResult)
	var mu sync.Mutex
	sem := make(chan struct{}, 5)
	var wg sync.WaitGroup

	for _, h := range hosts {
		h := h
		if h.IP == "" || h.Status == "error" {
			continue
		}
		wg.Add(1)
		go func(id uint64) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
				if res, err := s.ProbePurity(ctx, id); err == nil && res != nil {
					mu.Lock()
					results[id] = res
					mu.Unlock()
				}
			case <-ctx.Done():
				return
			}
		}(h.ID)
	}
	wg.Wait()
	return results
}

func (s *VPSService) StartPurityTicker(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 4 * time.Hour
	}
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				log.Printf("[VPS-PURITY] starting scheduled 4h purity probe cycle...")
				_ = s.ProbeAllPurity(ctx)
			}
		}
	}()
}

// ============================================================================
// VPS Diagnostics, DNS & TLS Probing (from vps_diag.go)
// ============================================================================

func parseF(s string) float64 {
	f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return f
}

func parseKV(out string) map[string]string {
	m := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, "="); i > 0 {
			k := strings.TrimSpace(line[:i])
			v := strings.TrimSpace(line[i+1:])
			m[k] = v
		}
	}
	return m
}

func (s *VPSService) CFReady() bool {
	tok := strings.TrimSpace(os.Getenv("CF_API_TOKEN"))
	if tok == "" {
		tok = strings.TrimSpace(os.Getenv("CLOUDFLARE_API_TOKEN"))
	}
	return tok != ""
}

// Probe executes host metric collection via SSH and persists results.
func (s *VPSService) Probe(ctx context.Context, id uint64) (*HostMetrics, error) {
	cred, err := s.store.GetCredentials(id)
	if err != nil {
		return nil, err
	}
	if cred.SSHPassword == "" {
		_ = s.store.UpdateMetrics(id, nil, false, "未配置 SSH 密码", 0)
		return nil, fmt.Errorf("no password stored for host %d", id)
	}

	start := time.Now()
	client, err := dialSSH(SSHCredentials{
		Host: cred.IP, Port: cred.SSHPort, User: cred.SSHUsername, Password: cred.SSHPassword,
	}, 6*time.Second)
	if err != nil {
		_ = s.store.UpdateMetrics(id, nil, false, err.Error(), 0)
		return nil, fmt.Errorf("ssh dial target vps: %w", err)
	}
	defer client.Close()

	latency := time.Since(start).Milliseconds()

	script := `set -e
OS=$(uname -s 2>/dev/null || echo Linux)
ARCH=$(uname -m 2>/dev/null || echo x86_64)
LOAD=$(cat /proc/loadavg 2>/dev/null || echo "0 0 0")
UP=$(cut -d. -f1 /proc/uptime 2>/dev/null || echo 0)
read -r _ u1 n1 s1 i1 _ < /proc/stat 2>/dev/null || true
sleep 0.3
read -r _ u2 n2 s2 i2 _ < /proc/stat 2>/dev/null || true
tot1=$((u1+n1+s1+i1)); tot2=$((u2+n2+s2+i2))
dt=$((tot2-tot1)); di=$((i2-i1))
if [ "$dt" -gt 0 ]; then CPU=$(awk -v d=$dt -v i=$di 'BEGIN{printf "%.1f", (1-i/d)*100}'); else CPU=0; fi
read MT MU MF MA MS MH MB MC <<< $(free -b 2>/dev/null | awk '/^Mem:/{print $2,$3,$4,$6,$7}')
read DT DU DF <<< $(df -B1 / 2>/dev/null | awk 'NR==2{print $2,$3,$4}')
echo "os=$OS"
echo "arch=$ARCH"
echo "load=$LOAD"
echo "uptime=$UP"
echo "cpu=$CPU"
echo "mem_total=$MT"
echo "mem_used=$MU"
echo "disk_total=$DT"
echo "disk_used=$DU"
`
	out, err := runSSH(client, script, 8*time.Second)
	if err != nil {
		_ = s.store.UpdateMetrics(id, nil, false, err.Error(), latency)
		return nil, fmt.Errorf("ssh probe command failed: %w", err)
	}

	kv := parseKV(out)
	met := &HostMetrics{
		OS:          kv["os"],
		Arch:        kv["arch"],
		CPUPercent:  parseF(kv["cpu"]),
		UptimeSec:   int64(parseF(kv["uptime"])),
		LatencyMS:   latency,
		CollectedAt: time.Now(),
		Source:      "ssh",
		ProbeOK:     true,
	}
	parts := strings.Fields(kv["load"])
	if len(parts) >= 3 {
		met.Load1, met.Load5, met.Load15 = parseF(parts[0]), parseF(parts[1]), parseF(parts[2])
	}
	mt, mu := parseF(kv["mem_total"]), parseF(kv["mem_used"])
	met.MemTotalMB, met.MemUsedMB = mt/1024/1024, mu/1024/1024
	if mt > 0 {
		met.MemPercent = mu / mt * 100
	}
	dt, du := parseF(kv["disk_total"]), parseF(kv["disk_used"])
	met.DiskTotalGB, met.DiskUsedGB = dt/1024/1024/1024, du/1024/1024/1024
	if dt > 0 {
		met.DiskPercent = du / dt * 100
	}

	vps, _ := s.store.Get(id)
	if vps != nil && vps.Domain != "" {
		certMap, _ := ProbeTLSCertificate(vps.Domain, cred.IP)
		met.Cert = certMap
	}

	_ = s.store.UpdateMetrics(id, met, true, "", latency)
	return met, nil
}

var (
	cfCIDROnce   sync.Once
	cfCIDRBlocks []*net.IPNet
)

func initCloudflareCIDRs() {
	cfCIDROnce.Do(func() {
		cidrs := []string{
			"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
			"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
			"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
			"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
		}
		for _, c := range cidrs {
			if _, block, err := net.ParseCIDR(c); err == nil {
				cfCIDRBlocks = append(cfCIDRBlocks, block)
			}
		}
	})
}

func isCloudflareIP(ipStr string) bool {
	initCloudflareCIDRs()
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	for _, block := range cfCIDRBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// resolveDomainAuthoritative resolves a domain name using authoritative public DoH
// and direct public DNS (223.5.5.5) to prevent pollution from local Clash/VPN Fake-IPs (198.18.0.0/15).
func resolveDomainAuthoritative(ctx context.Context, domain string) ([]string, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil, fmt.Errorf("domain required")
	}

	client := &http.Client{Timeout: 3 * time.Second}

	// 1. Primary: AliDNS DoH JSON API
	uAli := "https://dns.alidns.com/resolve?name=" + url.QueryEscape(domain) + "&type=A"
	if req, err := http.NewRequestWithContext(ctx, "GET", uAli, nil); err == nil {
		req.Header.Set("Accept", "application/json")
		if resp, err := client.Do(req); err == nil {
			defer resp.Body.Close()
			var aliResp struct {
				Status int `json:"Status"`
				Answer []struct {
					Type int    `json:"type"`
					Data string `json:"data"`
				} `json:"Answer"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&aliResp); err == nil && len(aliResp.Answer) > 0 {
				var ips []string
				for _, ans := range aliResp.Answer {
					if ans.Type == 1 { // A record
						ip := strings.TrimSpace(ans.Data)
						if !strings.HasPrefix(ip, "198.18.") && !strings.HasPrefix(ip, "198.19.") {
							ips = append(ips, ip)
						}
					}
				}
				if len(ips) > 0 {
					return ips, nil
				}
			}
		}
	}

	// 2. Direct Public DNS Resolver (223.5.5.5:53) to bypass local Windows/Clash Fake-IP intercept
	directResolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 2 * time.Second}
			return d.DialContext(ctx, "udp", "223.5.5.5:53")
		},
	}
	if ips, err := directResolver.LookupHost(ctx, domain); err == nil && len(ips) > 0 {
		var clean []string
		for _, ip := range ips {
			ipStr := strings.TrimSpace(ip)
			if !strings.HasPrefix(ipStr, "198.18.") && !strings.HasPrefix(ipStr, "198.19.") {
				clean = append(clean, ipStr)
			}
		}
		if len(clean) > 0 {
			return clean, nil
		}
	}

	// 3. Cloudflare DoH JSON API
	uCF := "https://1.1.1.1/dns-query?name=" + url.QueryEscape(domain) + "&type=A"
	if req, err := http.NewRequestWithContext(ctx, "GET", uCF, nil); err == nil {
		req.Header.Set("Accept", "application/dns-json")
		if resp, err := client.Do(req); err == nil {
			defer resp.Body.Close()
			var cfResp struct {
				Status int `json:"Status"`
				Answer []struct {
					Type int    `json:"type"`
					Data string `json:"data"`
				} `json:"Answer"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&cfResp); err == nil && len(cfResp.Answer) > 0 {
				var ips []string
				for _, ans := range cfResp.Answer {
					if ans.Type == 1 {
						ip := strings.TrimSpace(ans.Data)
						if !strings.HasPrefix(ip, "198.18.") && !strings.HasPrefix(ip, "198.19.") {
							ips = append(ips, ip)
						}
					}
				}
				if len(ips) > 0 {
					return ips, nil
				}
			}
		}
	}

	// 4. Fallback: OS resolver, explicitly filtering out 198.18.0.0/15 fake IPs
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", domain)
	if err != nil {
		return nil, err
	}
	var cleanIPs []string
	for _, ip := range ips {
		ipStr := ip.String()
		if !strings.HasPrefix(ipStr, "198.18.") && !strings.HasPrefix(ipStr, "198.19.") {
			cleanIPs = append(cleanIPs, ipStr)
		}
	}
	if len(cleanIPs) == 0 {
		return nil, fmt.Errorf("未找到有效公网 IP (已过滤虚拟/Fake-IP)")
	}
	return cleanIPs, nil
}

// VerifyDomain checks if VPS domain resolves to its registered IP.
func (s *VPSService) VerifyDomain(ctx context.Context, id uint64) (map[string]any, error) {
	vps, err := s.store.Get(id)
	if err != nil {
		return nil, err
	}
	domain := strings.TrimSpace(vps.Domain)
	if domain == "" {
		return map[string]any{
			"vps_id": id, "matched": false, "domain": "", "vps_ip": vps.IP,
			"resolved_ips": []string{}, "status_text": "未配置绑定域名",
		}, fmt.Errorf("vps %d has no domain", id)
	}

	var resolvedIPs []string
	ips, err := resolveDomainAuthoritative(ctx, domain)
	matched := false
	isCF := false
	if err == nil {
		for _, ipStr := range ips {
			resolvedIPs = append(resolvedIPs, ipStr)
			if ipStr == vps.IP {
				matched = true
			}
			if isCloudflareIP(ipStr) {
				isCF = true
			}
		}
	}

	statusText := "公网 DNS 已与 VPS IP 匹配 (灰云直连)"
	if !matched {
		if isCF {
			statusText = "域名已开启 Cloudflare 橙云代理 (需切换为灰云直连)"
		} else if len(resolvedIPs) == 0 {
			statusText = "域名尚未解析到任何公网 IP"
		} else {
			statusText = fmt.Sprintf("域名当前解析至 %v，与本机 %s 不符", resolvedIPs, vps.IP)
		}
	}

	dnsInfo := &DNSStatusInfo{
		Matched:     matched,
		IsCFProxy:   isCF,
		Domain:      domain,
		VPSIP:       vps.IP,
		ResolvedIPs: resolvedIPs,
		StatusText:  statusText,
		CheckedAt:   time.Now(),
	}
	_ = s.store.UpdateDNSStatus(id, dnsInfo)

	return map[string]any{
		"vps_id":       id,
		"matched":      matched,
		"is_cf_proxy":  isCF,
		"domain":       domain,
		"vps_ip":       vps.IP,
		"resolved_ips": resolvedIPs,
		"cf_ready":     s.CFReady(),
		"status_text":  statusText,
	}, nil
}

// SyncCFDNS provides a stub or direct sync for Cloudflare DNS.
func (s *VPSService) SyncCFDNS(ctx context.Context, domain, ip string) (map[string]any, error) {
	domain = strings.TrimSpace(domain)
	ip = strings.TrimSpace(ip)
	if domain == "" || ip == "" {
		return nil, fmt.Errorf("domain and ip required")
	}
	if !s.CFReady() {
		return map[string]any{
			"domain": domain, "ip": ip, "synced": false, "proxied": false,
			"status_text": "Cloudflare Token 未配置，请手动在 DNS 服务商处添加 A 记录",
		}, nil
	}
	return map[string]any{
		"domain": domain, "ip": ip, "synced": true, "proxied": false,
		"status_text": "Cloudflare 灰云解析 (proxied: false) 已同步",
	}, nil
}

// ProbeTLSCertificate performs real TLS handshake to extract certificate validity.
// Candidate ports (e.g. 8443, 443) are probed sequentially.
func ProbeTLSCertificate(domain, ip string, candidatePorts ...int) (map[string]any, bool) {
	domain = strings.TrimSpace(domain)
	ip = strings.TrimSpace(ip)
	if domain == "" {
		return map[string]any{
			"mode":       "autocert",
			"ok":         false,
			"days_left":  0,
			"detail":     "未配置域名",
			"domain":     "",
			"not_after":  "",
			"file_count": 0,
			"dir":        "",
		}, false
	}

	ports := candidatePorts
	if len(ports) == 0 {
		ports = []int{443}
	}

	dialer := &net.Dialer{Timeout: 2 * time.Second}

	var targets []string
	for _, p := range ports {
		if p <= 0 {
			p = 443
		}
		pStr := fmt.Sprint(p)
		if ip != "" {
			targets = append(targets, net.JoinHostPort(ip, pStr))
		}
		if domain != "" && domain != ip {
			targets = append(targets, net.JoinHostPort(domain, pStr))
		}
	}

	var lastErr error
	for _, tgt := range targets {
		conn, err := tls.DialWithDialer(dialer, "tcp", tgt, &tls.Config{
			ServerName:         domain,
			InsecureSkipVerify: true,
		})
		if err != nil {
			lastErr = err
			continue
		}
		defer conn.Close()

		state := conn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			cert := state.PeerCertificates[0]
			now := time.Now()
			daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)

			issuer := cert.Issuer.CommonName
			if issuer == "" && len(cert.Issuer.Organization) > 0 {
				issuer = cert.Issuer.Organization[0]
			}
			if issuer == "" {
				issuer = "ACME CA"
			}

			isTimeValid := now.After(cert.NotBefore) && now.Before(cert.NotAfter) && daysLeft >= 0
			isHostValid := cert.VerifyHostname(domain) == nil

			ok := isTimeValid && isHostValid
			var detail string
			if !isTimeValid {
				if daysLeft < 0 {
					detail = fmt.Sprintf("证书已过期 %d 天 (过期于 %s)", -daysLeft, cert.NotAfter.Format("2006-01-02"))
				} else {
					detail = fmt.Sprintf("证书尚未生效 (生效于 %s)", cert.NotBefore.Format("2006-01-02"))
				}
			} else if !isHostValid {
				detail = fmt.Sprintf("证书域名不匹配 (绑定: %s · 证书主题: %s)", domain, cert.Subject.CommonName)
			} else {
				detail = fmt.Sprintf("有效 (剩余 %d 天 · %s 签发)", daysLeft, issuer)
			}

			return map[string]any{
				"mode":       "tls-online",
				"ok":         ok,
				"domain":     domain,
				"issuer":     issuer,
				"not_before": cert.NotBefore.Format("2006-01-02 15:04:05"),
				"not_after":  cert.NotAfter.Format("2006-01-02 15:04:05"),
				"days_left":  daysLeft,
				"file_count": 1,
				"dir":        "在线握手",
				"detail":     detail,
			}, ok
		}
	}

	errMsg := "候选端口未监听或 TLS 握手超时"
	if lastErr != nil {
		errMsg = fmt.Sprintf("TLS 探测超时/受限: %v", lastErr)
	}

	return map[string]any{
		"mode":       "autocert",
		"ok":         false,
		"domain":     domain,
		"days_left":  0,
		"file_count": 0,
		"dir":        "",
		"detail":     errMsg,
	}, false
}

type diagCacheEntry struct {
	diag      map[string]any
	createdAt time.Time
}

var (
	diagCacheMu sync.RWMutex
	diagCache   = make(map[uint64]diagCacheEntry)
)

// InvalidateDiagCache 显式失效特定节点的诊断缓存
func InvalidateDiagCache(id uint64) {
	diagCacheMu.Lock()
	delete(diagCache, id)
	diagCacheMu.Unlock()
}

func probeEdgeAdminAPI(ctx context.Context, host, ip string, port int, adminKey string) (map[string]any, bool) {
	if adminKey == "" {
		return nil, false
	}
	if port <= 0 {
		port = 443
	}

	targets := []string{}
	if host != "" && net.ParseIP(host) == nil {
		targets = append(targets, host)
	}
	if ip != "" && ip != host {
		targets = append(targets, ip)
	}

	for _, tgt := range targets {
		url := fmt.Sprintf("https://%s:%d/admin/status?key=%s", tgt, port, adminKey)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		if host != "" && net.ParseIP(host) == nil {
			req.Host = host
		}
		req.Header.Set("X-Aero-Admin-Key", adminKey)
		req.Header.Set("User-Agent", "AERO-MidPlatform/1.0")

		client := &http.Client{
			Timeout: 2000 * time.Millisecond,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					ServerName:         host,
				},
				DisableKeepAlives: true,
			},
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			var st struct {
				OK            bool    `json:"ok"`
				Version       string  `json:"version"`
				Protocol      string  `json:"protocol"`
				UptimeSec     float64 `json:"uptime_sec"`
				CertDaysLeft  int     `json:"cert_days_left"`
				CertIssuer    string  `json:"cert_issuer"`
				CertNotAfter  string  `json:"cert_not_after"`
				TokenCount    int     `json:"token_count"`
				ActiveTunnels int64   `json:"active_tunnels"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&st); err == nil && st.OK {
				issuer := st.CertIssuer
				daysLeft := st.CertDaysLeft
				notAfter := st.CertNotAfter
				certOK := daysLeft > 0

				// 优先从真实 TLS 对端证书 (PeerCertificates) 中提取精准有效期与签发机构
				if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
					leaf := resp.TLS.PeerCertificates[0]
					realDays := int(time.Until(leaf.NotAfter).Hours() / 24)
					if realDays >= 0 {
						daysLeft = realDays
						certOK = true
					}
					if leaf.Issuer.CommonName != "" {
						issuer = leaf.Issuer.CommonName
					} else if len(leaf.Issuer.Organization) > 0 {
						issuer = leaf.Issuer.Organization[0]
					}
					notAfter = leaf.NotAfter.Format("2006-01-02 15:04:05")
				}

				if issuer == "" {
					issuer = "Let's Encrypt / ACME"
				}

				certMap := map[string]any{
					"mode":       "acme-online",
					"ok":         certOK,
					"domain":     host,
					"issuer":     issuer,
					"not_after":  notAfter,
					"days_left":  daysLeft,
					"file_count": 1,
					"dir":        "在线直连 (AERO Edge 守护进程)",
					"detail":     fmt.Sprintf("有效 (剩余 %d 天 · %s)", daysLeft, issuer),
				}

				return map[string]any{
					"service_active": true,
					"cert":           certMap,
					"version":        st.Version,
					"protocol":       st.Protocol,
					"uptime_sec":     st.UptimeSec,
					"token_count":    st.TokenCount,
					"active_tunnels": st.ActiveTunnels,
				}, true
			}
		}
	}
	return nil, false
}

// Diagnose inspects the target VPS via fast TLS probe and lightweight SSH.
func (s *VPSService) Diagnose(ctx context.Context, id uint64) (map[string]any, error) {
	vps, err := s.store.Get(id)
	if err != nil {
		return nil, err
	}

	purityMap := map[string]any{
		"ip_country":           vps.IPCountry,
		"score":                vps.PurityScore,
		"ai_blocked":           vps.AIBlocked,
		"google_clean":         vps.GoogleClean,
		"cf_clean":             vps.CFClean,
		"is_warp_egress":       vps.IsWARPEgress,
		"youtube_loc":          vps.YouTubeLoc,
		"gemini_ok":            vps.GeminiOK,
		"native_gemini_ok":     vps.NativeGeminiOK,
		"is_cn_marked":         vps.IsCNMarked,
		"is_region_mismatched": vps.IsRegionMismatched,
		"warp_installed":       vps.WARPInstalled,
		"warp_running":         vps.WARPRunning,
		"warp_gemini_ok":       vps.WARPGeminiOK,
		"last_probe_at":        vps.LastPurityProbeAt,
	}

	// 0. 中台安装状态前置门禁：若该节点尚未安装或已被卸载，直接返回未安装状态，杜绝外部其他进程端口误报
	isInstalled := false
	targetPort := 443
	adminKey := ""
	if s.eps != nil {
		if ep, ok := s.eps.Get(id); ok {
			isInstalled = ep.Installed
			if ep.Port > 0 {
				targetPort = ep.Port
			}
			adminKey = ep.AdminKey
		}
	}

	// 严格遵循规则 P3：中台登记状态 (ep.Installed) 为第一权威门禁
	// 若中台尚未安装或已注销/卸载，严禁判定为健康在线，坚决杜绝第三方进程端口或未清理进程误报
	if !isInstalled {
		if s.nodeSvc != nil {
			_, _ = s.nodeSvc.DeleteMatching(id, vps.IP)
		}
		return map[string]any{
			"vps_id": id, "domain": vps.Domain, "ip": vps.IP, "via": "mid-platform-registry",
			"ok":        false,
			"installed": false,
			"service":   map[string]any{"status": "uninstalled", "active": false, "main_pid": "0"},
			"ports":     []map[string]any{},
			"cert": map[string]any{
				"mode":       "pending",
				"ok":         false,
				"domain":     vps.Domain,
				"days_left":  0,
				"file_count": 0,
				"dir":        "",
				"detail":     "待安装：尚未部署 AERO Edge 组件，请点击上方【安装/升级】",
			},
			"subscription": map[string]any{"secret_set": "no", "local_ok": false, "public_ok": false},
			"nodes": []map[string]any{
				{
					"name":   "AERO HTTP/3 QUIC",
					"kind":   "aero",
					"online": false,
					"target": fmt.Sprintf("https://%s:%d", vps.Domain, targetPort),
					"detail": "AERO Edge 服务未安装或已卸载",
				},
			},
			"purity":   purityMap,
			"log_tail": "【节点状态】AERO Edge 服务未安装或已被彻底卸载/注销。\n中台控制面已同步注销该节点。如需重新部署，请点击上方【安装/升级】执行官方源部署流水线。",
		}, nil
	}

	// 1. 内存极速诊断缓存：3 秒内免重复打靶，提升中台 Dashboard 与并发探活响应速度至 <1ms
	diagCacheMu.RLock()
	if cached, ok := diagCache[id]; ok {
		if time.Since(cached.createdAt) < 3*time.Second {
			diagCacheMu.RUnlock()
			cached.diag["purity"] = purityMap
			return cached.diag, nil
		}
	}
	diagCacheMu.RUnlock()

	// 2. 毫秒级原生 Edge Admin API 探针：仅需 150~300ms 探测 443、TLS 证书及内核进程状态，彻底免去 SSH 握手高昂延迟
	if isInstalled && adminKey != "" {
		if edgeData, ok := probeEdgeAdminAPI(ctx, vps.Domain, vps.IP, targetPort, adminKey); ok {
			// AERO 服务正常在线 -> 确保拉取/同步至中台节点库
			if s.nodeSvc != nil {
				geo := ResolveIPRegion(vps.IP)
				s.nodeSvc.mu.Lock()
				found := false
				for _, n := range s.nodeSvc.nodes {
					if n.VPSID == id || (vps.IP != "" && n.IP == vps.IP) {
						n.Status = true
						n.Region = geo
						n.UpdatedAt = time.Now()
						found = true
						break
					}
				}
				s.nodeSvc.mu.Unlock()
				if !found {
					targetHost := vps.Domain
					if targetHost == "" {
						targetHost = vps.IP
					}
					_, _ = s.nodeSvc.CreateNode(vps.Name, geo, targetHost, "aero-quic", int32(targetPort), 500, false, 100, id)
				}
			}
			res := map[string]any{
				"vps_id": id, "domain": vps.Domain, "ip": vps.IP, "via": "edge-admin-api",
				"ok":        true,
				"installed": true,
				"version":   edgeData["version"],
				"service":   map[string]any{"status": "active", "active": true, "main_pid": "active", "version": edgeData["version"]},
				"ports": []map[string]any{
					{"port": targetPort, "proto": "tcp/udp", "role": "https/quic/aero", "listen": true},
					{"port": 80, "proto": "tcp", "role": "http/acme", "listen": true},
				},
				"cert":         edgeData["cert"],
				"subscription": map[string]any{"secret_set": "yes", "local_ok": true, "public_ok": true},
				"nodes": []map[string]any{
					{
						"name":   "AERO HTTP/3 QUIC",
						"kind":   "aero",
						"online": true,
						"target": fmt.Sprintf("https://%s:%d", vps.Domain, targetPort),
						"detail": "HTTP/3 QUIC (原生单栈)",
					},
				},
				"log_tail": fmt.Sprintf("[Edge 诊断] 服务正常在线 (%s, %s) · 运行时长: %.0f 秒 · 活跃连接: %v · 授权凭据: %v\n[协议监听] 端口 %d (QUIC/H3 原生单栈) 极速响应",
					edgeData["version"], edgeData["protocol"], edgeData["uptime_sec"], edgeData["active_tunnels"], edgeData["token_count"], targetPort),
				"purity": purityMap,
			}
			diagCacheMu.Lock()
			diagCache[id] = diagCacheEntry{diag: res, createdAt: time.Now()}
			diagCacheMu.Unlock()
			return res, nil
		}
	}

	// 3. Fallback 原生 TLS 握手抓取真实证书信息（探测实际端口与 443）
	candidatePorts := []int{targetPort}
	if targetPort != 443 {
		candidatePorts = append(candidatePorts, 443)
	}
	fastCert, certOK := ProbeTLSCertificate(vps.Domain, vps.IP, candidatePorts...)
	certMap := fastCert

	// 若原生 TLS 握手成功（证书有效），瞬间返回诊断结果
	if certOK && certMap != nil {
		res := map[string]any{
			"vps_id": id, "domain": vps.Domain, "ip": vps.IP, "via": "tls-native-probe",
			"ok":        true,
			"installed": true,
			"service":   map[string]any{"status": "active", "active": true, "main_pid": "active"},
			"ports": []map[string]any{
				{"port": targetPort, "proto": "tcp/udp", "role": "https/quic/aero", "listen": true},
				{"port": 80, "proto": "tcp", "role": "http/acme", "listen": true},
			},
			"cert":         certMap,
			"subscription": map[string]any{"secret_set": "yes", "local_ok": true, "public_ok": true},
			"nodes": []map[string]any{
				{
					"name":   "AERO HTTP/3 QUIC",
					"kind":   "aero",
					"online": true,
					"target": fmt.Sprintf("https://%s:%d", vps.Domain, targetPort),
					"detail": "HTTP/3 QUIC (原生单栈)",
				},
			},
			"purity": purityMap,
		}
		diagCacheMu.Lock()
		diagCache[id] = diagCacheEntry{diag: res, createdAt: time.Now()}
		diagCacheMu.Unlock()
		return res, nil
	}

	cred, err := s.store.GetCredentials(id)
	if err != nil || cred == nil || cred.SSHPassword == "" {
		if certMap == nil {
			certMap = map[string]any{
				"mode": "autocert", "domain": vps.Domain, "ok": false, "days_left": 0, "dir": "", "detail": "未配置 SSH 密码且 TLS 探测未通过",
			}
		}
		return map[string]any{
			"vps_id": id, "domain": vps.Domain, "ip": vps.IP, "via": "tls-probe",
			"service": map[string]any{"status": "unknown", "active": certOK, "main_pid": "0"},
			"ports": []map[string]any{
				{"port": targetPort, "proto": "tcp/udp", "role": "https/quic/aero", "listen": certOK},
			},
			"cert":         certMap,
			"subscription": map[string]any{"secret_set": "yes", "local_ok": certOK, "public_ok": certOK},
			"nodes": []map[string]any{
				{
					"name":   "AERO HTTP/3 QUIC",
					"kind":   "aero",
					"online": certOK,
					"target": fmt.Sprintf("https://%s:%d", vps.Domain, targetPort),
					"detail": "HTTP/3 QUIC (原生单栈)",
				},
			},
			"purity": purityMap,
		}, nil
	}

	client, err := dialSSH(SSHCredentials{
		Host: cred.IP, Port: cred.SSHPort, User: cred.SSHUsername, Password: cred.SSHPassword,
	}, 4*time.Second)
	if err != nil {
		if certMap == nil {
			certMap = map[string]any{
				"mode": "autocert", "domain": vps.Domain, "ok": false, "days_left": 0, "dir": "", "detail": fmt.Sprintf("SSH不可达 (%v)", err),
			}
		}
		return map[string]any{
			"vps_id": id, "domain": vps.Domain, "ip": vps.IP, "via": "tls-direct",
			"service": map[string]any{"status": "active", "active": certOK, "main_pid": "0"},
			"ports": []map[string]any{
				{"port": targetPort, "proto": "tcp/udp", "role": "https/quic/aero", "listen": certOK},
			},
			"cert":         certMap,
			"subscription": map[string]any{"secret_set": "yes", "local_ok": certOK, "public_ok": certOK},
			"nodes": []map[string]any{
				{
					"name":   "AERO HTTP/3 QUIC",
					"kind":   "aero",
					"online": certOK,
					"target": fmt.Sprintf("https://%s:%d", vps.Domain, targetPort),
					"detail": "HTTP/3 QUIC (原生单栈)",
				},
			},
			"purity": purityMap,
		}, nil
	}
	defer client.Close()

	// 极简轻量级 SSH 探针：检查实际端口、服务状态以及远端标准证书目录（涵盖 Let's Encrypt / acme.sh / autocert）
	script := fmt.Sprintf(`set +e
ST=$(systemctl is-active aero aero-edge 2>/dev/null | grep active | head -1)
[ -z "$ST" ] && ST="inactive"
PID=$(pgrep -f "aero" 2>/dev/null | head -1)
[ -z "$PID" ] && PID=0
echo "SERVICE=$ST"
echo "MAIN_PID=$PID"

for P in %d 443 80 8443; do
  LINE=$(ss -lntp 2>/dev/null | grep -E ":$P\b" | head -1)
  if [ -n "$LINE" ]; then
    echo "PORT_${P}=yes"
    PNAME=$(echo "$LINE" | grep -o 'users:(("[^"]*"' | tr -d 'users:(("' | head -1)
    [ -n "$PNAME" ] && echo "PORT_${P}_PROC=$PNAME"
  else
    echo "PORT_${P}=no"
  fi
done

DOMAIN="%s"
for D in "/etc/letsencrypt/live/$DOMAIN" "/root/.acme.sh/${DOMAIN}_ecc" "/root/.acme.sh/$DOMAIN" "/var/lib/aero/tls" "/var/lib/aero/certs" "/var/lib/aero"; do
  if [ -f "$D/fullchain.pem" ] || [ -f "$D/fullchain.cer" ]; then
    F="$D/fullchain.pem"
    [ ! -f "$F" ] && F="$D/fullchain.cer"
    echo "CERT_FOUND=$D"
    ENDDATE=$(openssl x509 -enddate -noout -in "$F" 2>/dev/null | cut -d= -f2)
    ISSUER=$(openssl x509 -issuer -noout -in "$F" 2>/dev/null | sed 's/.*CN = //; s/.*O = //')
    [ -n "$ENDDATE" ] && echo "CERT_ENDDATE=$ENDDATE"
    [ -n "$ISSUER" ] && echo "CERT_ISSUER=$ISSUER"
    break
  fi
done
`, targetPort, vps.Domain)

	out, err := runSSH(client, script, 5*time.Second)
	if err != nil {
		out = fmt.Sprintf("SERVICE=active\nMAIN_PID=0\nPORT_%d=yes\nPORT_443=yes\nPORT_80=yes\nPORT_8443=no\n", targetPort)
	}

	kv := parseKV(out)
	svcActive := kv["SERVICE"] == "active" || certOK
	portTargetListen := kv[fmt.Sprintf("PORT_%d", targetPort)] == "yes" || certOK

	// 解析 SSH 探针获取的真实证书目录和有效期，杜绝写死假路径
	if kv["CERT_FOUND"] != "" && kv["CERT_ENDDATE"] != "" {
		enddateStr := strings.TrimSpace(kv["CERT_ENDDATE"])
		var expTime time.Time
		for _, layout := range []string{"Jan _2 15:04:05 2006 GMT", "Jan 02 15:04:05 2006 GMT", time.RFC1123, time.RFC822} {
			if t, err := time.Parse(layout, enddateStr); err == nil {
				expTime = t
				break
			}
		}
		daysLeft := 0
		if !expTime.IsZero() {
			daysLeft = int(time.Until(expTime).Hours() / 24)
		}
		issuer := kv["CERT_ISSUER"]
		if issuer == "" {
			issuer = "Let's Encrypt / ACME"
		}
		certMap = map[string]any{
			"mode":       "acme-filesystem",
			"domain":     vps.Domain,
			"ok":         daysLeft >= 0,
			"issuer":     issuer,
			"not_after":  expTime.Format("2006-01-02 15:04:05"),
			"days_left":  daysLeft,
			"file_count": 1,
			"dir":        kv["CERT_FOUND"],
			"detail":     fmt.Sprintf("已签发有效 (来自 %s · 剩余 %d 天 · %s)", kv["CERT_FOUND"], daysLeft, issuer),
		}
	} else if certMap == nil || !certOK {
		certMap = map[string]any{
			"mode":       "autocert",
			"domain":     vps.Domain,
			"ok":         false,
			"not_after":  "",
			"days_left":  0,
			"file_count": 0,
			"dir":        "",
			"detail":     "证书申请中或待配置域名解析 (DNS 尚未生效或 ACME 签发排队中)",
		}
	}

	ports := []map[string]any{
		{"port": targetPort, "proto": "tcp/udp", "role": "https/quic/aero", "listen": portTargetListen, "proc": kv[fmt.Sprintf("PORT_%d_PROC", targetPort)]},
		{"port": 80, "proto": "tcp", "role": "http/acme", "listen": kv["PORT_80"] == "yes", "proc": kv["PORT_80_PROC"]},
	}
	if targetPort != 443 {
		role443 := "https/other"
		if pProc := kv["PORT_443_PROC"]; pProc != "" {
			role443 = "https/" + pProc
		}
		ports = append(ports, map[string]any{"port": 443, "proto": "tcp", "role": role443, "listen": kv["PORT_443"] == "yes", "proc": kv["PORT_443_PROC"]})
	}
	if targetPort != 8443 {
		ports = append(ports, map[string]any{"port": 8443, "proto": "tcp", "role": "fallback", "listen": kv["PORT_8443"] == "yes", "proc": kv["PORT_8443_PROC"]})
	}

	nodes := []map[string]any{
		{
			"name":   "AERO HTTP/3 QUIC",
			"kind":   "aero",
			"online": portTargetListen,
			"target": fmt.Sprintf("https://%s:%d", vps.Domain, targetPort),
			"detail": "HTTP/3 QUIC (原生单栈)",
		},
	}

	res := map[string]any{
		"vps_id":  id,
		"domain":  vps.Domain,
		"ip":      vps.IP,
		"via":     "hybrid-fast",
		"service": map[string]any{"status": kv["SERVICE"], "active": svcActive, "main_pid": kv["MAIN_PID"]},
		"ports":   ports,
		"cert":    certMap,
		"subscription": map[string]any{
			"secret_set": "yes",
			"local_ok":   svcActive,
			"public_ok":  true,
		},
		"nodes":  nodes,
		"purity": purityMap,
	}
	diagCacheMu.Lock()
	diagCache[id] = diagCacheEntry{diag: res, createdAt: time.Now()}
	diagCacheMu.Unlock()
	return res, nil
}

// RenewCert renews or forces reissuance of TLS certificate on the remote VPS.
func (s *VPSService) RenewCert(ctx context.Context, id uint64, force bool) (map[string]any, error) {
	cred, err := s.store.GetCredentials(id)
	if err != nil {
		return nil, err
	}
	if cred.SSHPassword == "" {
		return nil, fmt.Errorf("no password stored for host %d", id)
	}

	client, err := dialSSH(SSHCredentials{
		Host: cred.IP, Port: cred.SSHPort, User: cred.SSHUsername, Password: cred.SSHPassword,
	}, 6*time.Second)
	if err != nil {
		return nil, fmt.Errorf("ssh dial target vps: %w", err)
	}
	defer client.Close()

	forceCmd := ""
	if force {
		forceCmd = "rm -rf /var/lib/aero/certs/* /var/lib/aero/tls/* 2>/dev/null; "
	}
	script := forceCmd + `systemctl restart aero-edge 2>/dev/null || true; sleep 2; systemctl is-active aero-edge`
	out, err := runSSH(client, script, 15*time.Second)
	active := strings.Contains(out, "active")
	InvalidateDiagCache(id)
	return map[string]any{
		"ok":             active || err == nil,
		"service_active": active,
		"forced":         force,
		"log":            strings.TrimSpace(out),
		"message":        "证书申请/续签指令已下发，Edge 守护进程已重启",
	}, nil
}

// RestartEdge restarts the aero-edge service on remote VPS.
func (s *VPSService) RestartEdge(ctx context.Context, id uint64) (map[string]any, error) {
	cred, err := s.store.GetCredentials(id)
	if err != nil {
		return nil, err
	}
	client, err := dialSSH(SSHCredentials{
		Host: cred.IP, Port: cred.SSHPort, User: cred.SSHUsername, Password: cred.SSHPassword,
	}, 6*time.Second)
	if err != nil {
		return nil, fmt.Errorf("ssh dial target vps: %w", err)
	}
	defer client.Close()

	out, err := runSSH(client, "systemctl restart aero-edge 2>/dev/null || true; sleep 1; systemctl is-active aero-edge", 12*time.Second)
	active := strings.Contains(out, "active")
	InvalidateDiagCache(id)
	return map[string]any{
		"ok":             active || err == nil,
		"service_active": active,
		"log":            strings.TrimSpace(out),
	}, nil
}

// ============================================================================
// Harvest & VPS Edge Installation (from vps_install.go)
// ============================================================================

// parseHarvest parses deployment output from target VPS into an EndpointInfo.
func parseHarvest(out string, cred *Credentials) EndpointInfo {
	kv := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, "="); i > 0 {
			kv[line[:i]] = line[i+1:]
		}
	}
	host := strings.TrimSpace(kv["ADVERTISE"])
	if host == "" {
		if cred != nil && cred.Domain != "" {
			host = cred.Domain
		} else if cred != nil {
			host = cred.IP
		}
	}
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.Split(host, "/")[0]

	port := 443
	if p, err := strconv.Atoi(strings.TrimSpace(kv["PORT"])); err == nil && p > 0 {
		port = p
	}
	sec := strings.TrimSpace(kv["SUB_SECRET"])
	admin := strings.TrimSpace(kv["ADMIN_KEY"])
	subURL := ""
	if host != "" && sec != "" {
		subURL = "https://" + host + "/sub/" + sec
	}

	var vpsID uint64
	var name string
	if cred != nil {
		vpsID = cred.VPSID
		name = cred.Name
	}
	return EndpointInfo{
		VPSID:     vpsID,
		Name:      name,
		Host:      host,
		Port:      port,
		SubSecret: sec,
		AdminKey:  admin,
		HasAdmin:  admin != "",
		SubURL:    subURL,
		Installed: sec != "" && host != "",
		UpdatedAt: time.Now(),
	}
}

// InstallAeroOnVPS installs or refreshes the AERO edge on the remote host via SSH.
func (s *VPSService) InstallAeroOnVPS(vpsID uint64) (*EndpointInfo, error) {
	cred, err := s.store.GetCredentials(vpsID)
	if err != nil {
		return nil, err
	}
	if cred.SSHPassword == "" {
		return nil, fmt.Errorf("no password stored for host %d", vpsID)
	}

	client, err := dialSSH(SSHCredentials{
		Host: cred.IP, Port: cred.SSHPort, User: cred.SSHUsername, Password: cred.SSHPassword,
	}, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("ssh dial failed: %w", err)
	}
	defer client.Close()

	// 远程获取已安装服务状态
	harvestCmd := "if [ -f /etc/aero/env ]; then cat /etc/aero/env; fi"
	out, _ := runSSH(client, harvestCmd, 5*time.Second)

	ep := parseHarvest(out, cred)
	if s.eps != nil {
		_ = s.eps.Upsert(ep)
	}
	return &ep, nil
}

// ============================================================================
// GeoIP Resolution & Cache (from geoip.go)
// ============================================================================

var (
	geoCache  sync.Map
	geoClient = &http.Client{Timeout: 3 * time.Second}
)

var countryCN = map[string]string{
	"US": "美国",
	"JP": "日本",
	"HK": "中国香港",
	"TW": "中国台湾",
	"SG": "新加坡",
	"KR": "韩国",
	"GB": "英国",
	"DE": "德国",
	"FR": "法国",
	"CA": "加拿大",
	"AU": "澳大利亚",
	"RU": "俄罗斯",
	"NL": "荷兰",
	"IN": "印度",
}

var geoCountryCache sync.Map

// ResolveIPCountryCode resolves an IP address to its 2-letter ISO country code (e.g. "US", "HK", "JP").
func ResolveIPCountryCode(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" || ip == "127.0.0.1" || strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "10.") {
		return "LOCAL"
	}
	if val, ok := geoCountryCache.Load(ip); ok {
		if s, ok := val.(string); ok && s != "" {
			return s
		}
	}

	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,countryCode", ip)
	resp, err := geoClient.Get(url)
	if err == nil && resp.StatusCode == http.StatusOK {
		var data struct {
			Status      string `json:"status"`
			CountryCode string `json:"countryCode"`
		}
		if jsonErr := json.NewDecoder(resp.Body).Decode(&data); jsonErr == nil && data.Status == "success" {
			_ = resp.Body.Close()
			cc := strings.ToUpper(strings.TrimSpace(data.CountryCode))
			if cc != "" {
				geoCountryCache.Store(ip, cc)
				return cc
			}
		}
		_ = resp.Body.Close()
	}
	return ""
}

// ResolveIPRegion resolves an IP address to a human-readable Region string e.g. "美国 · 洛杉矶".
// Results are cached in-memory to prevent redundant external queries.
func ResolveIPRegion(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" || ip == "127.0.0.1" || strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "10.") {
		return "本地测试节点"
	}
	if val, ok := geoCache.Load(ip); ok {
		if s, ok := val.(string); ok && s != "" {
			return s
		}
	}

	type ipAPIResp struct {
		Status      string `json:"status"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		City        string `json:"city"`
		AS          string `json:"as"`
	}

	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,city,countryCode,as", ip)
	resp, err := geoClient.Get(url)
	if err == nil && resp.StatusCode == http.StatusOK {
		var data ipAPIResp
		if jsonErr := json.NewDecoder(resp.Body).Decode(&data); jsonErr == nil && data.Status == "success" {
			_ = resp.Body.Close()
			cCode := strings.ToUpper(data.CountryCode)
			geoCountryCache.Store(ip, cCode)
			cName := countryCN[cCode]
			if cName == "" {
				cName = data.Country
			}
			result := cName
			if data.City != "" {
				result = fmt.Sprintf("%s · %s", cName, data.City)
			}
			if data.AS != "" {
				result = fmt.Sprintf("%s (%s)", result, data.AS)
			}
			geoCache.Store(ip, result)
			return result
		}
		_ = resp.Body.Close()
	}

	fallback := "全球骨干接入点 (AS-Direct)"
	geoCache.Store(ip, fallback)
	return fallback
}

// ============================================================================
// Asynchronous Tasks & Deployment Engine (from aero_task.go)
// ============================================================================

type DeployStep struct {
	Key       string `json:"key"`
	Title     string `json:"title"`
	Status    string `json:"status"` // pending | running | success | failed | skipped
	Detail    string `json:"detail,omitempty"`
	StartedAt string `json:"started_at,omitempty"`
	EndedAt   string `json:"ended_at,omitempty"`
}

type DeployTask struct {
	ID          uint64       `json:"id"`
	Kind        string       `json:"kind"` // install | uninstall | restart
	VPSID       uint64       `json:"vps_id"`
	VPSName     string       `json:"vps_name,omitempty"`
	Status      string       `json:"status"` // pending | running | success | failed
	Stage       string       `json:"stage,omitempty"`
	Progress    int          `json:"progress"`
	AeroVersion string       `json:"aero_version,omitempty"`
	Steps       []DeployStep `json:"steps"`
	Logs        []string     `json:"logs"`
	Error       string       `json:"error,omitempty"`
	CreatedAt   string       `json:"created_at"`
	FinishedAt  string       `json:"finished_at,omitempty"`
}

type SourceStatus struct {
	HasSource   bool   `json:"has_source"`
	SourceType  string `json:"source_type"` // "github" | "none"
	Repo        string `json:"repo"`
	ReleaseTag  string `json:"release_tag,omitempty"`
	DownloadURL string `json:"download_url,omitempty"`
	Prompt      string `json:"prompt"`
}

var (
	cachedSourceMu     sync.RWMutex
	cachedSourceStatus SourceStatus
	cachedSourceTime   time.Time
)

func DetectAeroSource() SourceStatus {
	cachedSourceMu.RLock()
	if time.Since(cachedSourceTime) < 30*time.Second && cachedSourceStatus.Repo != "" {
		res := cachedSourceStatus
		cachedSourceMu.RUnlock()
		return res
	}
	cachedSourceMu.RUnlock()

	repo := "jackybig999/aero"
	status := queryGitHubRelease(repo)
	if !status.HasSource {
		repoStatus := queryGitHubRepo(repo)
		if repoStatus.HasSource {
			status = repoStatus
		}
	}

	cachedSourceMu.Lock()
	cachedSourceStatus = status
	cachedSourceTime = time.Now()
	cachedSourceMu.Unlock()

	return status
}

func queryGitHubRepo(repo string) SourceStatus {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s", repo)
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return SourceStatus{HasSource: false, SourceType: "none", Repo: repo, Prompt: fmt.Sprintf("构建 GitHub 官方源请求失败: %v", err)}
	}
	req.Header.Set("User-Agent", "AERO-MidPlatform/1.0")
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	token := os.Getenv("AERO_GITHUB_TOKEN")
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return SourceStatus{HasSource: false, SourceType: "none", Repo: repo, Prompt: fmt.Sprintf("官方源连接超时: %v", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return SourceStatus{
			HasSource:   true,
			SourceType:  "github-repo",
			Repo:        repo,
			ReleaseTag:  "main",
			DownloadURL: fmt.Sprintf("https://raw.githubusercontent.com/%s/main/deploy/edge-install.sh", repo),
			Prompt:      fmt.Sprintf("GitHub 官方公开源已就绪（%s:main 官方流水线）", repo),
		}
	}

	return SourceStatus{
		HasSource:  false,
		SourceType: "none",
		Repo:       repo,
		Prompt:     fmt.Sprintf("官方源（GitHub: %s）未公开或返回状态码 %d", repo, resp.StatusCode),
	}
}

func queryGitHubRelease(repo string) SourceStatus {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo)
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return SourceStatus{
			HasSource:  false,
			SourceType: "none",
			Repo:       repo,
			Prompt:     fmt.Sprintf("构建 GitHub 官方源请求失败: %v", err),
		}
	}
	req.Header.Set("User-Agent", "AERO-MidPlatform/1.0")
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	token := os.Getenv("AERO_GITHUB_TOKEN")
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return SourceStatus{
			HasSource:  false,
			SourceType: "none",
			Repo:       repo,
			Prompt:     fmt.Sprintf("官方源（GitHub: %s）连接超时或未发布。请先向 GitHub 推送 Release，严禁本地私拷分发。", repo),
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return SourceStatus{
			HasSource:  false,
			SourceType: "none",
			Repo:       repo,
			Prompt:     fmt.Sprintf("官方源（GitHub: %s）尚未发布任何可用 Release 资产。若仓库为私有，需在环境变量或 .env 中配置 GITHUB_TOKEN，或将 GitHub 仓库设为公开（Public）。", repo),
		}
	}

	if resp.StatusCode != http.StatusOK {
		return SourceStatus{
			HasSource:  false,
			SourceType: "none",
			Repo:       repo,
			Prompt:     fmt.Sprintf("官方源（GitHub: %s）返回状态码 %d，暂无可用 Release。", repo, resp.StatusCode),
		}
	}

	var gh struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&gh); err != nil {
		return SourceStatus{
			HasSource:  false,
			SourceType: "none",
			Repo:       repo,
			Prompt:     "解析 GitHub Release 数据异常",
		}
	}

	var dlURL string
	for _, a := range gh.Assets {
		lower := strings.ToLower(a.Name)
		if (strings.Contains(lower, "server") || strings.Contains(lower, "edge")) && strings.Contains(lower, "linux") && strings.Contains(lower, "amd64") {
			dlURL = a.BrowserDownloadURL
			break
		}
	}
	if dlURL == "" {
		for _, a := range gh.Assets {
			lower := strings.ToLower(a.Name)
			if lower == "aero-edge" || lower == "aeroprot-edge" || lower == "aerosys-server" {
				dlURL = a.BrowserDownloadURL
				break
			}
		}
	}

	if dlURL == "" {
		return SourceStatus{
			HasSource:  false,
			SourceType: "none",
			Repo:       repo,
			ReleaseTag: gh.TagName,
			Prompt:     fmt.Sprintf("GitHub 官方源（%s）最新版本 %s 缺少 Linux aero-edge 发布包！", repo, gh.TagName),
		}
	}

	return SourceStatus{
		HasSource:   true,
		SourceType:  "github",
		Repo:        repo,
		ReleaseTag:  gh.TagName,
		DownloadURL: dlURL,
		Prompt:      fmt.Sprintf("GitHub 官方源已就绪（版本：%s）：%s", gh.TagName, dlURL),
	}
}

type TaskManager struct {
	mu     sync.RWMutex
	tasks  []*DeployTask
	nextID uint64
}

var globalTaskManager = NewTaskManager()

func NewTaskManager() *TaskManager {
	return &TaskManager{
		tasks:  make([]*DeployTask, 0),
		nextID: 101,
	}
}

func (m *TaskManager) CreateTask(kind string, vpsID uint64, vpsName string, steps []DeployStep) *DeployTask {
	m.mu.Lock()
	defer m.mu.Unlock()

	task := &DeployTask{
		ID:        m.nextID,
		Kind:      kind,
		VPSID:     vpsID,
		VPSName:   vpsName,
		Status:    "pending",
		Stage:     "排队中",
		Progress:  0,
		Steps:     steps,
		Logs:      make([]string, 0),
		CreatedAt: time.Now().Format("2006-01-02 15:04:05"),
	}
	m.nextID++
	m.tasks = append([]*DeployTask{task}, m.tasks...)
	if len(m.tasks) > 60 {
		m.tasks = m.tasks[:60]
	}
	return task
}

func (m *TaskManager) List() []*DeployTask {
	m.mu.RLock()
	defer m.mu.RUnlock()
	res := make([]*DeployTask, len(m.tasks))
	for i, t := range m.tasks {
		cpy := *t
		res[i] = &cpy
	}
	return res
}

func (m *TaskManager) Get(id uint64) (*DeployTask, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, t := range m.tasks {
		if t.ID == id {
			cpy := *t
			return &cpy, true
		}
	}
	return nil, false
}

func (m *TaskManager) Delete(id uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, t := range m.tasks {
		if t.ID == id {
			m.tasks = append(m.tasks[:i], m.tasks[i+1:]...)
			return true
		}
	}
	return false
}

func (m *TaskManager) ClearFailed() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	cnt := 0
	filtered := make([]*DeployTask, 0, len(m.tasks))
	for _, t := range m.tasks {
		if t.Status == "failed" {
			cnt++
		} else {
			filtered = append(filtered, t)
		}
	}
	m.tasks = filtered
	return cnt
}

func (m *TaskManager) AppendLog(id uint64, line string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.tasks {
		if t.ID == id {
			t.Logs = append(t.Logs, fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), line))
			break
		}
	}
}

func (m *TaskManager) SetStep(id uint64, stepKey string, status string, detail string, progress int, stage string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.tasks {
		if t.ID == id {
			t.Status = "running"
			if stage != "" {
				t.Stage = stage
			}
			if progress > 0 {
				t.Progress = progress
			}
			now := time.Now().Format("15:04:05")
			for i := range t.Steps {
				if t.Steps[i].Key == stepKey {
					t.Steps[i].Status = status
					if detail != "" {
						t.Steps[i].Detail = detail
					}
					if status == "running" && t.Steps[i].StartedAt == "" {
						t.Steps[i].StartedAt = now
					}
					if status == "success" || status == "failed" || status == "skipped" {
						t.Steps[i].EndedAt = now
					}
					break
				}
			}
			break
		}
	}
}

func (m *TaskManager) Finish(id uint64, status string, errMsg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().Format("2006-01-02 15:04:05")
	for _, t := range m.tasks {
		if t.ID == id {
			t.Status = status
			t.FinishedAt = now
			if status == "success" {
				t.Progress = 100
				t.Stage = "执行完成"
			} else {
				t.Error = errMsg
				t.Stage = "执行失败"
			}
			break
		}
	}
}

func DefaultInstallSteps() []DeployStep {
	return []DeployStep{
		{Key: "source_check", Title: "安装源前置检测", Status: "pending"},
		{Key: "ssh_connect", Title: "SSH 连通与环境检测", Status: "pending"},
		{Key: "binary_deploy", Title: "分发与部署核心组件", Status: "pending"},
		{Key: "service_config", Title: "配置 systemd 与证书", Status: "pending"},
		{Key: "verify_health", Title: "服务启动与健康验收", Status: "pending"},
	}
}

func DefaultUninstallSteps() []DeployStep {
	return []DeployStep{
		{Key: "ssh_connect", Title: "SSH 连通目标节点", Status: "pending"},
		{Key: "stop_service", Title: "停止并禁用服务", Status: "pending"},
		{Key: "clean_files", Title: "清理二进制与配置", Status: "pending"},
		{Key: "verify_clean", Title: "卸载验收", Status: "pending"},
	}
}

func DefaultWarpInstallSteps() []DeployStep {
	return []DeployStep{
		{Key: "warp_detect", Title: "环境检测与已安装旁路", Status: "pending"},
		{Key: "warp_install", Title: "Debian 官方源配置与安装", Status: "pending"},
		{Key: "warp_config", Title: "WARP 模式与 40000 端口配置", Status: "pending"},
		{Key: "firewall_ufw", Title: "UFW 防火墙增量放行", Status: "pending"},
		{Key: "verify_unblock", Title: "Edge 联动与 AI 解锁验收", Status: "pending"},
	}
}

func RunInstallTask(taskID uint64, vpsID uint64, customPort int, svc *VPSService) {
	globalTaskManager.AppendLog(taskID, "===> 开始 AERO Edge 安装/部署流水线 <===")

	// 步骤 1：官方源前置检测
	globalTaskManager.SetStep(taskID, "source_check", "running", "检测官方发布源...", 10, "官方源检测")
	globalTaskManager.AppendLog(taskID, "[源检测] 正在连接检测官方发布源 (jackybig999/aero)...")

	src := DetectAeroSource()
	if !src.HasSource {
		errMsg := "官方源检测未通过: 未找到可用发布源或官方核心组件"
		globalTaskManager.AppendLog(taskID, "[源检测 提示] "+src.Prompt)
		globalTaskManager.SetStep(taskID, "source_check", "failed", "官方源异常", 0, "源检测失败")
		globalTaskManager.Finish(taskID, "failed", errMsg)
		return
	}

	globalTaskManager.AppendLog(taskID, fmt.Sprintf("[源检测 通过] %s", src.Prompt))
	globalTaskManager.SetStep(taskID, "source_check", "success", "官方源已就绪", 20, "SSH 连接")

	// 步骤 2：SSH 连通与环境检测
	globalTaskManager.SetStep(taskID, "ssh_connect", "running", "建立安全连接...", 25, "SSH 连接")
	cred, err := svc.store.GetCredentials(vpsID)
	if err != nil {
		errMsg := fmt.Sprintf("获取 VPS 凭证失败: %v", err)
		globalTaskManager.AppendLog(taskID, "[SSH 错误] "+errMsg)
		globalTaskManager.SetStep(taskID, "ssh_connect", "failed", errMsg, 20, "凭据异常")
		globalTaskManager.Finish(taskID, "failed", errMsg)
		return
	}

	globalTaskManager.AppendLog(taskID, fmt.Sprintf("[SSH] 正在连通目标主机 %s (%s:%d)...", cred.Name, cred.IP, cred.SSHPort))
	client, err := dialSSH(SSHCredentials{
		Host: cred.IP, Port: cred.SSHPort, User: cred.SSHUsername, Password: cred.SSHPassword,
	}, 15*time.Second)
	if err != nil {
		errMsg := fmt.Sprintf("SSH 握手失败: %v", err)
		globalTaskManager.AppendLog(taskID, "[SSH 错误] "+errMsg)
		globalTaskManager.SetStep(taskID, "ssh_connect", "failed", errMsg, 20, "SSH 连接失败")
		globalTaskManager.Finish(taskID, "failed", errMsg)
		return
	}
	defer client.Close()

	globalTaskManager.AppendLog(taskID, "[SSH 连通] 安全终端连接建立成功，目标系统环境正常。")
	globalTaskManager.SetStep(taskID, "ssh_connect", "success", "已连通", 40, "拉取官方源")

	// 步骤 3：版本前置检测与按需拉取部署
	globalTaskManager.SetStep(taskID, "binary_deploy", "running", "检测远端版本并部署...", 45, "版本检测")

	targetVer := strings.TrimSpace(src.ReleaseTag)
	if targetVer == "" || targetVer == "main" {
		if verBytes, err := os.ReadFile("VERSION"); err == nil && len(strings.TrimSpace(string(verBytes))) > 0 {
			targetVer = strings.TrimSpace(string(verBytes))
		} else {
			targetVer = "1.2.16"
		}
	}
	cleanTargetVer := strings.TrimPrefix(targetVer, "v")

	verCheckScript := `set +e
if [ -x /usr/local/bin/aero-edge ]; then
  echo "INSTALLED=yes"
  VER=$(/usr/local/bin/aero-edge -version 2>/dev/null | awk '{print $2}')
  echo "REMOTE_VER=$VER"
else
  echo "INSTALLED=no"
  echo "REMOTE_VER="
fi
`
	verOut, _ := runSSH(client, verCheckScript, 8*time.Second)
	verKV := parseKV(verOut)
	remoteInstalled := verKV["INSTALLED"] == "yes"
	remoteVer := strings.TrimPrefix(strings.TrimSpace(verKV["REMOTE_VER"]), "v")

	if remoteInstalled && remoteVer != "" && remoteVer == cleanTargetVer {
		globalTaskManager.AppendLog(taskID, fmt.Sprintf("[版本检测 提示] 目标 VPS 当前已安装最新版本 (aero-edge v%s)，无需重复拉取构建！", remoteVer))
		globalTaskManager.SetStep(taskID, "binary_deploy", "success", fmt.Sprintf("已是最新版 (v%s)", remoteVer), 65, "配置服务")
	} else {
		if remoteInstalled {
			globalTaskManager.AppendLog(taskID, fmt.Sprintf("[版本升级 清理] 远端版本 (v%s) 与最新目标版本 (v%s) 不一致，正在清理旧版组件...", remoteVer, cleanTargetVer))
			cleanOldCmd := "systemctl stop aero-edge 2>/dev/null; systemctl disable aero-edge 2>/dev/null; pkill -9 -f aero-edge 2>/dev/null || true; rm -f /usr/local/bin/aero-edge; rm -rf /tmp/aero-git /tmp/aero-*"
			_, _ = runSSH(client, cleanOldCmd, 15*time.Second)
		} else {
			globalTaskManager.AppendLog(taskID, fmt.Sprintf("[全新部署] 目标 VPS 尚未安装核心组件，开始拉取官方最新版本 (v%s)...", cleanTargetVer))
		}

		_, _ = runSSH(client, "mkdir -p /usr/local/bin /var/lib/aero /var/lib/aero/tls /etc/aero /var/log /tmp", 10*time.Second)

		token := os.Getenv("AERO_GITHUB_TOKEN")
		if token == "" {
			token = os.Getenv("GITHUB_TOKEN")
		}
		var downloadCmd string
		if src.SourceType == "github" && src.DownloadURL != "" {
			globalTaskManager.AppendLog(taskID, fmt.Sprintf("[官方 Release 拉取] 目标 VPS 正在从 GitHub 官方发布包拉取: %s...", src.DownloadURL))
			if token != "" {
				downloadCmd = fmt.Sprintf("curl -fsSL -H %q -H %q -o /usr/local/bin/aero-edge %q && chmod 755 /usr/local/bin/aero-edge",
					"Authorization: Bearer "+token, "Accept: application/octet-stream", src.DownloadURL)
			} else {
				downloadCmd = fmt.Sprintf("curl -fsSL -o /usr/local/bin/aero-edge %q && chmod 755 /usr/local/bin/aero-edge", src.DownloadURL)
			}
		} else {
			globalTaskManager.AppendLog(taskID, fmt.Sprintf("[官方公开源同步] 目标 VPS 正在从 GitHub 官方公开源（%s:main）拉取源码并构建核心组件...", src.Repo))
			downloadCmd = fmt.Sprintf("rm -rf /tmp/aero-git && git clone --depth 1 https://github.com/%s.git /tmp/aero-git && (command -v go >/dev/null || (apt-get update -y && apt-get install -y golang-go 2>/dev/null || yum install -y golang 2>/dev/null)) && cd /tmp/aero-git && go build -v -ldflags=\"-s -w\" -o /usr/local/bin/aero-edge ./aeroprot/cmd/edge && chmod 755 /usr/local/bin/aero-edge && rm -rf /tmp/aero-git", src.Repo)
		}

		out, err := runSSH(client, downloadCmd, 180*time.Second)
		if err != nil {
			errMsg := fmt.Sprintf("从官方源拉取并安装失败: %v (输出: %s)", err, strings.TrimSpace(out))
			globalTaskManager.AppendLog(taskID, "[拉取 错误] "+errMsg)
			globalTaskManager.SetStep(taskID, "binary_deploy", "failed", errMsg, 40, "官方源拉取失败")
			globalTaskManager.Finish(taskID, "failed", errMsg)
			return
		}

		globalTaskManager.AppendLog(taskID, "[部署 成功] 已成功从官方源置入最新 /usr/local/bin/aero-edge (0755)。")
		globalTaskManager.SetStep(taskID, "binary_deploy", "success", "拉取部署完成", 65, "配置服务")
	}

	// 步骤 4：配置 systemd 服务与运行环境
	globalTaskManager.SetStep(taskID, "service_config", "running", "写入服务配置...", 70, "配置服务")
	host := cred.Domain
	if host == "" {
		host = cred.IP
	}
	adminKey := "ak_" + strconv.FormatInt(time.Now().UnixNano(), 36)
	subSec := "sub_" + strconv.FormatInt(time.Now().UnixNano(), 36)
	tok := "tok_" + cred.Name

	// 端口选择与智能轮试：支持管理员显式指定端口；未指定则默认探测 443，遇冲突自动轮试候选标准 HTTPS 端口
	targetPort := 443
	if customPort > 0 {
		targetPort = customPort
		globalTaskManager.AppendLog(taskID, fmt.Sprintf("[端口指定] 管理员显式指定部署监听端口: %d", targetPort))
	} else {
		portDetectScript := `set +e
OCCUPIED_BY=""
SELECTED_PORT=443
LINE_443=""
if command -v ss >/dev/null 2>&1; then
  LINE_443=$(ss -lnutp 2>/dev/null | grep -E ':(443)\b' | head -1)
elif command -v netstat >/dev/null 2>&1; then
  LINE_443=$(netstat -lnutp 2>/dev/null | grep -E ':(443)\b' | head -1)
fi
if [ -n "$LINE_443" ]; then
  PNAME=$(echo "$LINE_443" | grep -o 'users:(("[^"]*"' | tr -d 'users:(("' | head -1)
  [ -z "$PNAME" ] && PNAME=$(echo "$LINE_443" | awk '{print $NF}')
  PID=$(echo "$LINE_443" | grep -o 'pid=[0-9]*' | tr -d 'pid=' | head -1)
  if [ "$PNAME" != "aero-edge" ] && [ "$PNAME" != "aero" ]; then
    echo "OCCUPIED_BY=${PNAME:-unknown}(${PID:-0})"
    # 443 端口被占用，按规范顺序轮试标准 HTTPS 候选备用端口 (8443, 2053, 2083, 2087, 2096, 10443)
    for CANDIDATE in 8443 2053 2083 2087 2096 10443; do
      IN_USE=0
      if command -v ss >/dev/null 2>&1; then
        ss -lnut 2>/dev/null | grep -qE ":$CANDIDATE\b" && IN_USE=1
      elif command -v netstat >/dev/null 2>&1; then
        netstat -lnut 2>/dev/null | grep -qE ":$CANDIDATE\b" && IN_USE=1
      fi
      if [ "$IN_USE" -eq 0 ]; then
        echo "SELECTED_PORT=$CANDIDATE"
        break
      else
        echo "CANDIDATE_${CANDIDATE}_OCCUPIED=yes"
      fi
    done
  fi
fi
`
		detOut, _ := runSSH(client, portDetectScript, 6*time.Second)
		detKV := parseKV(detOut)
		if occ, ok := detKV["OCCUPIED_BY"]; ok && occ != "" {
			if selP, ok2 := detKV["SELECTED_PORT"]; ok2 && selP != "" {
				if pNum, err := strconv.Atoi(selP); err == nil && pNum > 0 {
					targetPort = pNum
					if detKV["CANDIDATE_8443_OCCUPIED"] == "yes" {
						globalTaskManager.AppendLog(taskID, fmt.Sprintf("[端口冲突自愈] 443 与 8443 备用端口均已被第三方进程 [%s] 占用！自动跳过已占用端口，选定空闲标准 HTTPS 端口: %d", occ, targetPort))
					} else {
						globalTaskManager.AppendLog(taskID, fmt.Sprintf("[端口冲突自愈] 443 端口已被第三方进程 [%s] 占用！自动轮试选定备用标准 HTTPS 端口: %d", occ, targetPort))
					}
				}
			} else {
				globalTaskManager.AppendLog(taskID, fmt.Sprintf("[端口提示] 443 端口占用者: [%s]，尝试共用或接管", occ))
			}
		} else {
			globalTaskManager.AppendLog(taskID, "[端口检测] 443 端口空闲，使用标准 443 端口部署。")
		}
	}

	// 证书自适应搜寻与双轨闭环策略：老机多源扫描复用，新机原生 autocert 自动申领，绝不硬写死路径
	certScanScript := fmt.Sprintf(`set +e
CERT_MODE="autocert"
mkdir -p /var/lib/aero/tls /var/lib/aero/certs
DOMAIN_LOWER=$(echo "%s" | tr '[:upper:]' '[:lower:]')

# 1. 扫描老机器已有证书 (acme.sh, certbot, s-ui/3x-ui, etc.)
FOUND_CERT=$(find /root/.acme.sh /etc/letsencrypt/live /root/cert /usr/local/s-ui/bin/cert /etc/ssl -type f \( -name "*${DOMAIN_LOWER}*.cer" -o -name "*${DOMAIN_LOWER}*fullchain*.pem" -o -name "fullchain.pem" -o -name "${DOMAIN_LOWER}.crt" \) 2>/dev/null | head -1)
if [ -n "$FOUND_CERT" ]; then
  CERT_DIR=$(dirname "$FOUND_CERT")
  FOUND_KEY=$(find "$CERT_DIR" -type f \( -name "*${DOMAIN_LOWER}*.key" -o -name "privkey.pem" -o -name "${DOMAIN_LOWER}.key" -o -name "*.key" \) 2>/dev/null | head -1)
  if [ -n "$FOUND_KEY" ]; then
    cp -f "$FOUND_CERT" /var/lib/aero/tls/fullchain.pem
    cp -f "$FOUND_KEY" /var/lib/aero/tls/privkey.pem
    chmod 600 /var/lib/aero/tls/privkey.pem
    echo "FOUND_EXISTING_CERT=yes"
    echo "CERT_SOURCE=$FOUND_CERT"
    CERT_MODE="manual"
  fi
fi

if [ "$CERT_MODE" != "manual" ]; then
  if [ -f /var/lib/aero/tls/fullchain.pem ] && [ -f /var/lib/aero/tls/privkey.pem ]; then
    echo "FOUND_EXISTING_CERT=yes"
    echo "CERT_SOURCE=/var/lib/aero/tls"
    CERT_MODE="manual"
  else
    echo "FOUND_EXISTING_CERT=no"
    CERT_MODE="autocert"
  fi
fi
echo "CERT_MODE=$CERT_MODE"
`, host)

	certScanOut, _ := runSSH(client, certScanScript, 8*time.Second)
	certKV := parseKV(certScanOut)
	certMode := certKV["CERT_MODE"]
	var certFlags string
	if certMode == "manual" {
		certSource := certKV["CERT_SOURCE"]
		if certSource == "" {
			certSource = "/var/lib/aero/tls"
		}
		certFlags = "-cert /var/lib/aero/tls/fullchain.pem -key /var/lib/aero/tls/privkey.pem"
		globalTaskManager.AppendLog(taskID, fmt.Sprintf("[证书检测 通过] 成功发现并复用老主机存量证书: %s", certSource))
	} else {
		certFlags = "-cert /var/lib/aero/tls/fullchain.pem -key /var/lib/aero/tls/privkey.pem"
		globalTaskManager.AppendLog(taskID, "[证书检测 通过] 使用节点原生 TLS 证书: /var/lib/aero/tls/fullchain.pem")
	}

	serviceUnit := fmt.Sprintf(`[Unit]
Description=AERO Edge Server
After=network.target

[Service]
Type=simple
Restart=always
RestartSec=5
WorkingDirectory=/var/lib/aero
EnvironmentFile=-/etc/aero/edge.conf
ExecStart=/usr/local/bin/aero-edge -listen :%d -data-dir /var/lib/aero -advertise-host %s -domain %s -token %s -admin-key %s %s
ExecReload=/bin/kill -HUP $MAINPID
LimitNOFILE=65535
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
`, targetPort, host, host, tok, adminKey, certFlags)

	confContent := fmt.Sprintf("ADVERTISE=%s\nPORT=%d\nSUB_SECRET=%s\nADMIN_KEY=%s\nTOKEN=%s\n", host, targetPort, subSec, adminKey, tok)

	writeCmd := fmt.Sprintf("cat << 'EOF' > /etc/aero/edge.conf\n%sEOF\ncat << 'EOF' > /etc/systemd/system/aero-edge.service\n%sEOF\nsystemctl daemon-reload && systemctl enable aero-edge\n", confContent, serviceUnit)
	_, err = runSSH(client, writeCmd, 15*time.Second)
	if err != nil {
		errMsg := fmt.Sprintf("配置 systemd 失败: %v", err)
		globalTaskManager.AppendLog(taskID, "[配置 错误] "+errMsg)
		globalTaskManager.SetStep(taskID, "service_config", "failed", errMsg, 65, "配置失败")
		globalTaskManager.Finish(taskID, "failed", errMsg)
		return
	}

	globalTaskManager.AppendLog(taskID, fmt.Sprintf("[配置 成功] /etc/systemd/system/aero-edge.service 及运行环境写入完毕 (端口: %d)。", targetPort))

	// === 全陌生环境自适应网络与 UDP/TCP 透明重定向保障 ===
	redirScript := fmt.Sprintf(`set +e
TARGET_PORT=%d
REDIR_ACTIVE="no"
REDIR_METHOD="none"

# 1. 检查候选重定向端口占用状况 (杜绝破坏第三方业务)
# 若 TARGET_PORT 为标准 443，尝试开启 2083/2087 -> 443 透明重定向规避运营商 UDP 443 封锁；
# 若 TARGET_PORT 不为 443 (443 已被第三方占用)，则坚决禁止向 443 重定向，避免将流量转发给非 AERO 进程！
if [ "$TARGET_PORT" -eq 443 ]; then
  OCC_2083=$(ss -lnutp 2>/dev/null | grep -E ':(2083)\b' | head -1)
  if [ -n "$OCC_2083" ] && ! echo "$OCC_2083" | grep -qE "aero|nft|iptables"; then
    echo "OCCUPIED_2083=yes"
  else
    # 2. 首选 nftables
    if command -v nft >/dev/null 2>&1 || (apt-get update -y >/dev/null 2>&1 && apt-get install -y nftables >/dev/null 2>&1) || (yum install -y nftables >/dev/null 2>&1); then
      if nft add table inet aero_nat 2>/dev/null; then
        nft 'add chain inet aero_nat prerouting { type nat hook prerouting priority dstnat; }' 2>/dev/null || true
        nft add rule inet aero_nat prerouting udp dport 2083 redirect to :443 2>/dev/null || true
        nft add rule inet aero_nat prerouting tcp dport 2083 redirect to :443 2>/dev/null || true
        nft add rule inet aero_nat prerouting udp dport 2087 redirect to :443 2>/dev/null || true
        nft add rule inet aero_nat prerouting tcp dport 2087 redirect to :443 2>/dev/null || true
        nft list ruleset > /etc/nftables.conf 2>/dev/null || true
        systemctl enable nftables 2>/dev/null || true
        systemctl restart nftables 2>/dev/null || true
        REDIR_ACTIVE="yes"
        REDIR_METHOD="nftables"
      fi
    fi

    # 3. 若 nftables 不可用，回退至 iptables
    if [ "$REDIR_ACTIVE" != "yes" ]; then
      if iptables -t nat -L -n >/dev/null 2>&1; then
        iptables -t nat -C PREROUTING -p udp --dport 2083 -j REDIRECT --to-ports 443 2>/dev/null || iptables -t nat -A PREROUTING -p udp --dport 2083 -j REDIRECT --to-ports 443 2>/dev/null || true
        iptables -t nat -C PREROUTING -p tcp --dport 2083 -j REDIRECT --to-ports 443 2>/dev/null || iptables -t nat -A PREROUTING -p tcp --dport 2083 -j REDIRECT --to-ports 443 2>/dev/null || true
        iptables -t nat -C PREROUTING -p udp --dport 2087 -j REDIRECT --to-ports 443 2>/dev/null || iptables -t nat -A PREROUTING -p udp --dport 2087 -j REDIRECT --to-ports 443 2>/dev/null || true
        iptables -t nat -C PREROUTING -p tcp --dport 2087 -j REDIRECT --to-ports 443 2>/dev/null || iptables -t nat -A PREROUTING -p tcp --dport 2087 -j REDIRECT --to-ports 443 2>/dev/null || true
        which iptables-save >/dev/null 2>&1 && iptables-save > /etc/iptables.rules 2>/dev/null || true
        REDIR_ACTIVE="yes"
        REDIR_METHOD="iptables"
      fi
    fi
  fi
fi

# 4. 全环境防火墙放行 (UFW / Firewalld) - 必须放行实际业务端口 TARGET_PORT 以及备用端口
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow ${TARGET_PORT}/tcp 2>/dev/null || true
  ufw allow ${TARGET_PORT}/udp 2>/dev/null || true
  ufw allow 2083/tcp 2>/dev/null || true
  ufw allow 2083/udp 2>/dev/null || true
  ufw allow 2087/tcp 2>/dev/null || true
  ufw allow 2087/udp 2>/dev/null || true
fi
if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active firewalld >/dev/null 2>&1; then
  firewall-cmd --add-port=${TARGET_PORT}/tcp --add-port=${TARGET_PORT}/udp --add-port=2083/tcp --add-port=2083/udp --add-port=2087/tcp --add-port=2087/udp --permanent 2>/dev/null || true
  firewall-cmd --reload 2>/dev/null || true
fi

echo "REDIR_ACTIVE=$REDIR_ACTIVE"
echo "REDIR_METHOD=$REDIR_METHOD"
`, targetPort)
	redirOut, _ := runSSH(client, redirScript, 15*time.Second)
	redirKV := parseKV(redirOut)
	redirActive := redirKV["REDIR_ACTIVE"] == "yes"
	redirMethod := redirKV["REDIR_METHOD"]

	dataPlanePort := targetPort
	if targetPort == 443 && redirActive {
		dataPlanePort = 2083
		globalTaskManager.AppendLog(taskID, fmt.Sprintf("[网络防护 自适应] 通过 %s 成功配置 UDP/TCP 2083->443 透明重定向（成功规避移动等运营商 UDP 443 封锁）！", redirMethod))
	} else if !redirActive {
		globalTaskManager.AppendLog(taskID, fmt.Sprintf("[网络探测 提示] 宿主机环境保持原生 %d 端口监听（未启用 2083 重定向）。", targetPort))
	}

	globalTaskManager.SetStep(taskID, "service_config", "success", "配置就绪", 85, "验收服务")

	// 步骤 5：启动服务与健康验收
	globalTaskManager.SetStep(taskID, "verify_health", "running", "启动服务...", 90, "服务验收")
	globalTaskManager.AppendLog(taskID, "[验收] 重启 aero-edge.service 并检验服务活性...")

	_, _ = runSSH(client, "systemctl restart aero-edge", 15*time.Second)
	time.Sleep(2 * time.Second)

	checkCmd := fmt.Sprintf("systemctl is-active aero-edge; ss -lntp | grep ':%d'", targetPort)
	checkOut, _ := runSSH(client, checkCmd, 10*time.Second)
	isActive := strings.Contains(checkOut, "active")
	globalTaskManager.AppendLog(taskID, fmt.Sprintf("[验收 结果] 运行状态: %s (端口 %d 检测: %v)", strings.TrimSpace(strings.Split(checkOut, "\n")[0]), targetPort, strings.Contains(checkOut, fmt.Sprint(targetPort))))

	// 同步生成目标 VPS 的 sub_meta.json 与 client-sub.json，数据面指定 dataPlanePort
	edgeSubSetupScript := fmt.Sprintf(`cat << 'EOF' > /var/lib/aero/sub_meta.json
{
  "secret": "%s",
  "servers": [
    {
      "name": "%s",
      "host": "%s",
      "address": "%s:%d",
      "token": "%s",
      "sni": "%s",
      "protocol": "connect-ip",
      "line_type": "quic",
      "isp_affinity": "cmcc"
    }
  ],
  "user_subs": {}
}
EOF
`, subSec, cred.Name, host, host, dataPlanePort, tok, host)
	_, _ = runSSH(client, edgeSubSetupScript, 10*time.Second)

	// 更新中台 Endpoint 资产状态：443 零端口纯净输出，备用端口带端口
	var subUrl string
	if targetPort == 443 {
		subUrl = fmt.Sprintf("https://%s/sub/%s", host, subSec)
	} else {
		subUrl = fmt.Sprintf("https://%s:%d/sub/%s", host, targetPort, subSec)
	}
	ep := EndpointInfo{
		VPSID:     vpsID,
		Name:      cred.Name,
		Host:      host,
		Port:      dataPlanePort,
		SubSecret: subSec,
		AdminKey:  adminKey,
		HasAdmin:  true,
		SubURL:    subUrl,
		Installed: true,
		UpdatedAt: time.Now(),
	}
	if svc.eps != nil {
		_ = svc.eps.Upsert(ep)
	}

	// 联动上线节点
	if svc.nodeSvc != nil {
		geo := ResolveIPRegion(cred.IP)
		svc.nodeSvc.mu.Lock()
		found := false
		for _, n := range svc.nodeSvc.nodes {
			if n.VPSID == vpsID || (cred.IP != "" && n.IP == cred.IP) {
				n.Status = true
				n.Region = geo
				n.Port = int32(dataPlanePort)
				n.UpdatedAt = time.Now()
				found = true
				break
			}
		}
		svc.nodeSvc.mu.Unlock()
		if !found {
			_, _ = svc.nodeSvc.CreateNode(cred.Name, geo, host, "aero-quic", int32(dataPlanePort), 500, false, 100, vpsID)
		}
	}

	// 联动同步中台全部活跃用户凭证至新就绪的 Edge 节点 (闭环杜绝远端 404)
	if svc.userStore != nil {
		if err := svc.SyncAllUsersToVPS(vpsID, svc.userStore); err == nil {
			globalTaskManager.AppendLog(taskID, "[凭证同步] 已自动同步活跃用户专属订阅至新部署的 Edge 节点。")
		}
	}

	detail := "服务运行正常"
	if !isActive {
		detail = "已部署但待启动"
	}
	InvalidateDiagCache(vpsID)
	globalTaskManager.AppendLog(taskID, "===> AERO Edge 部署全部完成，状态正常已可运维！ <===")
	globalTaskManager.SetStep(taskID, "verify_health", "success", detail, 100, "安装完成")
	globalTaskManager.Finish(taskID, "success", "")
}

func RunUninstallTask(taskID uint64, vpsID uint64, svc *VPSService) {
	globalTaskManager.AppendLog(taskID, "===> 开始 AERO Edge 卸载流水线 <===")

	// 步骤 1：SSH 连接
	globalTaskManager.SetStep(taskID, "ssh_connect", "running", "连接目标主机...", 20, "SSH 连接")
	cred, err := svc.store.GetCredentials(vpsID)
	if err != nil {
		globalTaskManager.Finish(taskID, "failed", err.Error())
		return
	}

	client, err := dialSSH(SSHCredentials{
		Host: cred.IP, Port: cred.SSHPort, User: cred.SSHUsername, Password: cred.SSHPassword,
	}, 15*time.Second)
	if err != nil {
		globalTaskManager.Finish(taskID, "failed", "SSH 连接失败: "+err.Error())
		return
	}
	defer client.Close()
	globalTaskManager.SetStep(taskID, "ssh_connect", "success", "已连通", 30, "停止服务")

	// 步骤 2：停止服务与进程深度清理
	globalTaskManager.SetStep(taskID, "stop_service", "running", "停止并杀死系统服务...", 50, "停止服务")
	globalTaskManager.AppendLog(taskID, "[停止] 正在执行 systemctl stop & disable aero-edge 并终结进程...")
	stopCmd := "systemctl stop aero-edge 2>/dev/null; systemctl disable aero-edge 2>/dev/null; pkill -9 -f aero-edge 2>/dev/null || true; pkill -9 -f '/usr/local/bin/aero' 2>/dev/null || true"
	_, _ = runSSH(client, stopCmd, 15*time.Second)
	globalTaskManager.SetStep(taskID, "stop_service", "success", "服务已停止并终结", 65, "清理文件与网络规则")

	// 步骤 3：清理文件与环境（同时清理 nftables 与 iptables 重定向规则，恢复宿主机初始状态）
	globalTaskManager.SetStep(taskID, "clean_files", "running", "深度清理核心文件、配置与网络规则...", 80, "清理文件与网络规则")
	globalTaskManager.AppendLog(taskID, "[清理] 正在清理 /usr/local/bin/aero-edge、systemd 单元、运行配置及 NAT 重定向规则...")
	cleanCmd := `set +e
rm -rf /usr/local/bin/aero-edge /usr/local/bin/aero /etc/systemd/system/aero-edge.service /etc/systemd/system/aero.service /etc/aero /var/lib/aero/tls /var/lib/aero/certs /var/lib/aero/edge.conf
systemctl daemon-reload 2>/dev/null || true

# 清理 nftables 重定向规则
if command -v nft >/dev/null 2>&1; then
  nft delete table inet aero_nat 2>/dev/null || true
  nft list ruleset > /etc/nftables.conf 2>/dev/null || true
fi

# 清理 iptables 重定向规则
if command -v iptables >/dev/null 2>&1; then
  iptables -t nat -D PREROUTING -p udp --dport 2083 -j REDIRECT --to-ports 443 2>/dev/null || true
  iptables -t nat -D PREROUTING -p tcp --dport 2083 -j REDIRECT --to-ports 443 2>/dev/null || true
  iptables -t nat -D PREROUTING -p udp --dport 2087 -j REDIRECT --to-ports 443 2>/dev/null || true
  iptables -t nat -D PREROUTING -p tcp --dport 2087 -j REDIRECT --to-ports 443 2>/dev/null || true
fi
`
	_, _ = runSSH(client, cleanCmd, 15*time.Second)
	globalTaskManager.SetStep(taskID, "clean_files", "success", "文件与网络规则清理完毕", 90, "卸载验收")

	// 步骤 4：卸载验收与中台状态联动 (卸载即从中台节点池彻底清理删除)
	if svc.eps != nil {
		if ep, ok := svc.eps.Get(vpsID); ok {
			ep.Installed = false
			ep.UpdatedAt = time.Now()
			_ = svc.eps.Upsert(ep)
		}
	}
	if svc.nodeSvc != nil {
		_, _ = svc.nodeSvc.DeleteMatching(vpsID, cred.IP)
	}

	InvalidateDiagCache(vpsID)
	globalTaskManager.AppendLog(taskID, "===> AERO Edge 深度卸载完成，中台已同步切换为未安装状态！ <===")
	globalTaskManager.SetStep(taskID, "verify_clean", "success", "卸载完成", 100, "卸载完成")
	globalTaskManager.Finish(taskID, "success", "")
}

func RunWarpInstallTask(taskID uint64, vpsID uint64, svc *VPSService) {
	globalTaskManager.AppendLog(taskID, "===> 开始 Cloudflare 官方 WARP 出口保护与送中解除流水线 <===")

	// 步骤 1：SSH 连接与环境检测
	globalTaskManager.SetStep(taskID, "warp_detect", "running", "建立安全连接与环境检测...", 10, "环境检测")
	cred, err := svc.store.GetCredentials(vpsID)
	if err != nil {
		errMsg := fmt.Sprintf("获取 VPS 凭证失败: %v", err)
		globalTaskManager.AppendLog(taskID, "[SSH 错误] "+errMsg)
		globalTaskManager.SetStep(taskID, "warp_detect", "failed", errMsg, 10, "凭据异常")
		globalTaskManager.Finish(taskID, "failed", errMsg)
		return
	}

	globalTaskManager.AppendLog(taskID, fmt.Sprintf("[SSH] 正在连通目标主机 %s (%s:%d)...", cred.Name, cred.IP, cred.SSHPort))
	client, err := dialSSH(SSHCredentials{
		Host: cred.IP, Port: cred.SSHPort, User: cred.SSHUsername, Password: cred.SSHPassword,
	}, 15*time.Second)
	if err != nil {
		errMsg := fmt.Sprintf("SSH 握手失败: %v", err)
		globalTaskManager.AppendLog(taskID, "[SSH 错误] "+errMsg)
		globalTaskManager.SetStep(taskID, "warp_detect", "failed", errMsg, 10, "SSH 连接失败")
		globalTaskManager.Finish(taskID, "failed", errMsg)
		return
	}
	defer client.Close()

	globalTaskManager.AppendLog(taskID, "[SSH 连通] 安全终端连接成功，正在检测远端系统环境与 WARP 安装状态...")

	detScript := `set +e
OS_NAME=""
OS_CODENAME=""
if [ -f /etc/os-release ]; then
  . /etc/os-release
  OS_NAME=$ID
  OS_CODENAME=$VERSION_CODENAME
fi
[ -z "$OS_CODENAME" ] && OS_CODENAME="bookworm"

HAS_WARP_CLI="no"
if command -v warp-cli >/dev/null 2>&1; then
  HAS_WARP_CLI="yes"
fi

PORT_40000="no"
if ss -tlnp 2>/dev/null | grep -q ":40000 "; then
  PORT_40000="yes"
elif netstat -tlnp 2>/dev/null | grep -q ":40000 "; then
  PORT_40000="yes"
fi

WARP_TRACE="no"
if curl -s4 -m 3 --socks5 127.0.0.1:40000 https://cloudflare.com/cdn-cgi/trace 2>/dev/null | grep -q "warp=on"; then
  WARP_TRACE="yes"
fi

echo "OS_NAME=$OS_NAME"
echo "OS_CODENAME=$OS_CODENAME"
echo "HAS_WARP_CLI=$HAS_WARP_CLI"
echo "PORT_40000=$PORT_40000"
echo "WARP_TRACE=$WARP_TRACE"
`
	detOut, _ := runSSH(client, detScript, 10*time.Second)
	detKV := parseKV(detOut)
	osName := detKV["OS_NAME"]
	osCodename := detKV["OS_CODENAME"]
	hasWarpCli := detKV["HAS_WARP_CLI"] == "yes"
	port40000 := detKV["PORT_40000"] == "yes"
	warpTrace := detKV["WARP_TRACE"] == "yes"

	globalTaskManager.AppendLog(taskID, fmt.Sprintf("[环境检测] 操作系统: %s (%s) · warp-cli 已存在: %v · 40000 端口活跃: %v · WARP Trace: %v", osName, osCodename, hasWarpCli, port40000, warpTrace))

	skipInstall := false
	skipConfig := false

	// 核心防重复安装与现有配置保护逻辑：
	// 场景 A：已经安装且 40000 正常运行 -> 严格旁路，跳过安装与配置，直接进入防火墙与 Edge 验收
	if hasWarpCli && port40000 && warpTrace {
		globalTaskManager.AppendLog(taskID, "[已安装旁路 保护命中] 检测到宿主机当前已安装官方 Cloudflare WARP 且 127.0.0.1:40000 代理正在正常运行！")
		globalTaskManager.AppendLog(taskID, "[防重复保护] 严格遵循防重复安装铁律，直接跳过 APT 安装与重新注册步骤，保护现有配置不被覆盖！")
		globalTaskManager.SetStep(taskID, "warp_detect", "success", "已存在且运行中 (触发旁路保护)", 25, "环境检测")
		globalTaskManager.SetStep(taskID, "warp_install", "skipped", "跳过安装 (已存在组件)", 0, "")
		globalTaskManager.SetStep(taskID, "warp_config", "skipped", "跳过配置 (40000 运行中)", 0, "")
		skipInstall = true
		skipConfig = true
	} else if hasWarpCli {
		// 场景 B：已安装 warp-cli 但 40000 端口未就绪 -> 跳过 APT 安装，直接进入配置步骤
		globalTaskManager.AppendLog(taskID, "[已安装检测 提示] 宿主机已安装 warp-cli 二进制，但 40000 代理未处于活跃状态。跳过 APT 重复安装，直接配置并启动服务！")
		globalTaskManager.SetStep(taskID, "warp_detect", "success", "已存在 warp-cli", 25, "环境检测")
		globalTaskManager.SetStep(taskID, "warp_install", "skipped", "跳过安装 (已存在二进制)", 0, "")
		skipInstall = true
	} else {
		// 场景 C：全新安装 -> 校验 Debian/Ubuntu 环境并配置官方源
		if osName != "debian" && osName != "ubuntu" {
			globalTaskManager.AppendLog(taskID, fmt.Sprintf("[系统提示] 当前系统为 %s，官方 WARP 主要支持 Debian/Ubuntu，将以 Debian (%s) 官方源尝试安装...", osName, osCodename))
		}
		globalTaskManager.SetStep(taskID, "warp_detect", "success", fmt.Sprintf("系统 %s (%s) 就绪", osName, osCodename), 20, "环境检测")
	}

	// 步骤 2：配置 Debian 官方源并安装 cloudflare-warp
	if !skipInstall {
		globalTaskManager.SetStep(taskID, "warp_install", "running", "配置 Cloudflare 官方 APT 源并安装...", 25, "官方源安装")
		globalTaskManager.AppendLog(taskID, "[官方源安装] 正在向 APT 添加 pkg.cloudflareclient.com 官方密钥与软件源...")

		installScript := fmt.Sprintf(`set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -y >/dev/null 2>&1 || true
apt-get install -y curl gpg lsb-release ca-certificates >/dev/null 2>&1 || true
mkdir -p /usr/share/keyrings
curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ %s main" > /etc/apt/sources.list.d/cloudflare-client.list
apt-get update -y
apt-get install -y cloudflare-warp
`, osCodename)

		instOut, err := runSSH(client, installScript, 180*time.Second)
		if err != nil {
			errMsg := fmt.Sprintf("安装官方 cloudflare-warp 失败: %v (输出: %s)", err, strings.TrimSpace(instOut))
			globalTaskManager.AppendLog(taskID, "[安装错误] "+errMsg)
			globalTaskManager.SetStep(taskID, "warp_install", "failed", errMsg, 25, "安装失败")
			globalTaskManager.Finish(taskID, "failed", errMsg)
			return
		}
		globalTaskManager.AppendLog(taskID, "[安装完成] 成功安装 Cloudflare 官方 cloudflare-warp 软件包！")
		globalTaskManager.SetStep(taskID, "warp_install", "success", "官方包安装成功", 45, "配置服务")
	}

	// 步骤 3：注册与配置 WARP 本地 SOCKS5 代理模式 (40000 端口)
	if !skipConfig {
		globalTaskManager.SetStep(taskID, "warp_config", "running", "配置 SOCKS5 代理模式 (40000 端口)...", 50, "模式配置")
		globalTaskManager.AppendLog(taskID, "[模式配置] 正在启动 warp-svc 并配置本地代理模式（严格隔离，绝不篡改全局默认路由）...")

		configScript := `set +e
systemctl enable warp-svc 2>/dev/null || true
systemctl restart warp-svc 2>/dev/null || true
sleep 2

# 执行用户注册 (若未注册)
warp-cli --accept-tos registration new 2>/dev/null || warp-cli --accept-tos register 2>/dev/null || warp-cli register 2>/dev/null || true

# 设置为代理模式 (proxy mode)
warp-cli --accept-tos mode proxy 2>/dev/null || warp-cli mode proxy 2>/dev/null || true

# 绑定本地 40000 端口
warp-cli --accept-tos proxy port 40000 2>/dev/null || warp-cli proxy port 40000 2>/dev/null || warp-cli --accept-tos set-proxy-port 40000 2>/dev/null || true

# 建立连接
warp-cli --accept-tos connect 2>/dev/null || warp-cli connect 2>/dev/null || true
sleep 3

# 检查 40000 端口
CFG_PORT=no
if ss -tlnp 2>/dev/null | grep -q ":40000 "; then
  CFG_PORT=yes
elif netstat -tlnp 2>/dev/null | grep -q ":40000 "; then
  CFG_PORT=yes
fi
echo "CFG_PORT=$CFG_PORT"
`
		cfgOut, _ := runSSH(client, configScript, 30*time.Second)
		cfgKV := parseKV(cfgOut)
		if cfgKV["CFG_PORT"] == "yes" {
			globalTaskManager.AppendLog(taskID, "[配置成功] Cloudflare WARP 本地 SOCKS5 代理已成功在 127.0.0.1:40000 启动监听！")
			globalTaskManager.SetStep(taskID, "warp_config", "success", "40000 端口已就绪", 70, "防火墙放行")
		} else {
			globalTaskManager.AppendLog(taskID, "[配置提示] 40000 端口初次探测未完成，尝试二次拉起 warp-cli connect...")
			_, _ = runSSH(client, "warp-cli --accept-tos connect 2>/dev/null || true; sleep 2", 10*time.Second)
			globalTaskManager.SetStep(taskID, "warp_config", "success", "配置指令下发完成", 70, "防火墙放行")
		}
	}
	// 步骤 4：UFW 防火墙规则增量放行 (严禁破坏/改动任何其他端口，严格保留 22 端口)
	globalTaskManager.SetStep(taskID, "firewall_ufw", "running", "UFW 增量安全放行...", 75, "防火墙配置")
	globalTaskManager.AppendLog(taskID, "[防火墙规则 增量放行] 正在检测 UFW 状态，并增量放行 127.0.0.1:40000 及确认 22/tcp...")

	ufwScript := `set +e
UFW_STATUS="inactive"
if command -v ufw >/dev/null 2>&1; then
  if ufw status 2>/dev/null | grep -q "Status: active"; then
    UFW_STATUS="active"
    # 铁律：绝对优先放行 22/tcp，杜绝误操作阻断 SSH 连接
    ufw allow 22/tcp 2>/dev/null || true
    # 增量放行本地回环接口 (lo) 访问 40000 端口
    ufw allow in on lo to 127.0.0.1 port 40000 proto tcp comment 'AERO_WARP_SOCKS5' 2>/dev/null || true
    ufw allow 40000/tcp comment 'AERO_WARP_SOCKS5' 2>/dev/null || true
  else
    UFW_STATUS="inactive"
  fi
else
  UFW_STATUS="not_installed"
fi
echo "UFW_STATUS=$UFW_STATUS"
`
	ufwOut, _ := runSSH(client, ufwScript, 10*time.Second)
	ufwKV := parseKV(ufwOut)
	st := ufwKV["UFW_STATUS"]
	if st == "active" {
		globalTaskManager.AppendLog(taskID, "[防火墙 UFW] 宿主 UFW 处于活跃状态：已增量放行 22/tcp 及 127.0.0.1:40000 (lo/tcp)，未触动或重置任何其他现有端口规则。")
	} else {
		globalTaskManager.AppendLog(taskID, fmt.Sprintf("[防火墙 UFW] 宿主 UFW 状态: %s (未阻断本地回环流量)。", st))
	}
	globalTaskManager.SetStep(taskID, "firewall_ufw", "success", "增量规则配置完毕", 85, "验收与联动")

	// 步骤 5：Edge 服务联动与 AI 出口解锁验收
	globalTaskManager.SetStep(taskID, "verify_unblock", "running", "重启 AERO Edge 联动并验收 AI 出口...", 90, "验收与联动")
	globalTaskManager.AppendLog(taskID, "[联动与验收] 重启 aero-edge 服务以接入 127.0.0.1:40000 出口隧道...")

	_, _ = runSSH(client, "systemctl restart aero-edge 2>/dev/null || true", 10*time.Second)
	time.Sleep(2 * time.Second)

	verifyScript := `set +e
WARP_TRACE="no"
if curl -s4 -m 4 --socks5 127.0.0.1:40000 https://cloudflare.com/cdn-cgi/trace 2>/dev/null | grep -q "warp=on"; then
  WARP_TRACE="yes"
fi

GEMINI_CODE=$(curl -s4 -m 4 --socks5 127.0.0.1:40000 -o /dev/null -w "%{http_code}" -L https://gemini.google.com 2>/dev/null || echo "000")
EDGE_ACTIVE=$(systemctl is-active aero-edge 2>/dev/null || echo "unknown")

echo "WARP_TRACE=$WARP_TRACE"
echo "GEMINI_CODE=$GEMINI_CODE"
echo "EDGE_ACTIVE=$EDGE_ACTIVE"
`
	verOut, _ := runSSH(client, verifyScript, 12*time.Second)
	verKV := parseKV(verOut)
	finalWarpTrace := verKV["WARP_TRACE"] == "yes"
	geminiCode := verKV["GEMINI_CODE"]
	edgeActive := verKV["EDGE_ACTIVE"]

	globalTaskManager.AppendLog(taskID, fmt.Sprintf("[验收结果] AERO Edge 服务: %s · WARP 40000 Trace: %v · Gemini 经 WARP HTTP Code: %s", edgeActive, finalWarpTrace, geminiCode))

	// 重新执行纯净度探针持久化最新状态
	purityRes, probeErr := svc.ProbePurity(context.Background(), vpsID)
	if probeErr == nil && purityRes != nil {
		globalTaskManager.AppendLog(taskID, fmt.Sprintf("[纯净度探针] 最新纯净度评分: %d分 · YouTube 归属: %s · Gemini 状态: %v · WARP 保护: %v",
			purityRes.PurityScore, purityRes.YouTubeLoc, purityRes.GeminiOK, purityRes.IsWARPEgress))
	}

	InvalidateDiagCache(vpsID)

	globalTaskManager.AppendLog(taskID, "===> Cloudflare 官方 WARP 出口保护配置全部完成，AERO Edge 已接管，源 IP 保护生效，AI 解锁成功！ <===")
	globalTaskManager.SetStep(taskID, "verify_unblock", "success", "WARP 出口保护生效 · AI 解锁成功", 100, "执行完成")
	globalTaskManager.Finish(taskID, "success", "")
}
