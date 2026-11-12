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

package sub

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
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
		targetPort := 443
		if s.eps != nil {
			if ep, ok := s.eps.Get(id); ok && ep.Port > 0 {
				targetPort = ep.Port
			}
		}
		candidatePorts := []int{targetPort}
		for _, cp := range []int{443, 2083, 2087, 8443, 2053, 2096, 10443, 24443, 34443, 44443} {
			if cp != targetPort {
				candidatePorts = append(candidatePorts, cp)
			}
		}
		certMap, _ := ProbeTLSCertificate(vps.Domain, cred.IP, candidatePorts...)
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
	var bestMismatch map[string]any
	for _, tgt := range targets {
		conn, err := tls.DialWithDialer(dialer, "tcp", tgt, &tls.Config{
			ServerName:         domain,
			InsecureSkipVerify: true,
		})
		if err != nil {
			lastErr = err
			continue
		}

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

			res := map[string]any{
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
			}
			_ = conn.Close()

			if ok {
				return res, true
			}
			if bestMismatch == nil {
				bestMismatch = res
			}
		} else {
			_ = conn.Close()
		}
	}

	if bestMismatch != nil {
		return bestMismatch, false
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

func cloneDiagMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	c := make(map[string]any, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
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

// probeEdgeAdminAPI 经 edge 管理接口读取状态（edgeDo：严格 TLS，密钥只在请求头）。
func probeEdgeAdminAPI(ctx context.Context, host, ip string, port int, adminKey string) (map[string]any, bool) {
	if adminKey == "" {
		return nil, false
	}
	resp, err := edgeDo(ctx, host, ip, port, http.MethodGet, "/admin/status", adminKey, nil, 1200*time.Millisecond)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	var st struct {
		OK            bool    `json:"ok"`
		Version       string  `json:"version"`
		Protocol      string  `json:"protocol"`
		UptimeSec     float64 `json:"uptime_sec"`
		TokenCount    int     `json:"token_count"`
		ActiveTunnels int64   `json:"active_tunnels"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&st); err != nil || !st.OK {
		return nil, false
	}
	// 证书信息取自已校验通过的对端证书
	certMap := map[string]any{"mode": "acme-online", "ok": false, "domain": host, "file_count": 1, "dir": "在线直连 (AERO Edge 守护进程)"}
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		leaf := resp.TLS.PeerCertificates[0]
		daysLeft := int(time.Until(leaf.NotAfter).Hours() / 24)
		issuer := leaf.Issuer.CommonName
		if issuer == "" && len(leaf.Issuer.Organization) > 0 {
			issuer = leaf.Issuer.Organization[0]
		}
		certMap["ok"] = daysLeft >= 0
		certMap["issuer"] = issuer
		certMap["not_after"] = leaf.NotAfter.Format("2006-01-02 15:04:05")
		certMap["days_left"] = daysLeft
		certMap["detail"] = fmt.Sprintf("有效 (剩余 %d 天 · %s)", daysLeft, issuer)
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

	// 1. 内存极速诊断缓存：15 秒内免重复打靶，提升中台 Dashboard 与并发探活响应速度至 <1ms
	diagCacheMu.RLock()
	if cached, ok := diagCache[id]; ok {
		if time.Since(cached.createdAt) < 15*time.Second {
			res := cloneDiagMap(cached.diag)
			diagCacheMu.RUnlock()
			res["purity"] = purityMap
			return res, nil
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
			diagCache[id] = diagCacheEntry{diag: cloneDiagMap(res), createdAt: time.Now()}
			diagCacheMu.Unlock()
			return res, nil
		}
	}

	// 3. Fallback 原生 TLS 握手抓取真实证书信息（顺位探测候选端口池）
	candidatePorts := []int{targetPort}
	for _, cp := range []int{443, 2083, 2087, 8443, 2053, 2096, 10443, 24443, 34443, 44443} {
		if cp != targetPort {
			candidatePorts = append(candidatePorts, cp)
		}
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
		diagCache[id] = diagCacheEntry{diag: cloneDiagMap(res), createdAt: time.Now()}
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
			"ok":        certOK,
			"installed": isInstalled,
			"service":   map[string]any{"status": "unknown", "active": certOK, "main_pid": "0"},
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
			"ok":        certOK,
			"installed": isInstalled,
			"service":   map[string]any{"status": "active", "active": certOK, "main_pid": "0"},
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

	// 只读 SSH 探针：服务状态、端口监听与证书有效期（edge 状态只经管理接口读取，不在节点上带密钥调用）
	script := fmt.Sprintf(`set +e
ST=$(systemctl is-active aero-edge aero 2>/dev/null | grep -E '^(active|activating)$' | head -1)
[ -z "$ST" ] && ST="inactive"
PID=$(pgrep -f "aero-edge" 2>/dev/null | head -1)
[ -z "$PID" ] && PID=$(pgrep -f "aero" 2>/dev/null | head -1)
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
		out = "" // 探测失败如实报告未知，不伪造“运行中”
	}

	kv := parseKV(out)
	svcActive := kv["SERVICE"] == "active" || certOK
	if !svcActive && kv["MAIN_PID"] != "0" && kv["MAIN_PID"] != "" {
		for _, p := range []int{targetPort, 443, 8443} {
			proc := kv[fmt.Sprintf("PORT_%d_PROC", p)]
			if strings.Contains(proc, "aero") || strings.Contains(proc, "ao-dg") {
				svcActive = true
				break
			}
		}
	}

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
		"vps_id":    id,
		"domain":    vps.Domain,
		"ip":        vps.IP,
		"via":       "hybrid-fast",
		"ok":        isInstalled && (svcActive || portTargetListen),
		"installed": isInstalled,
		"service": map[string]any{
			"status":   kv["SERVICE"],
			"active":   svcActive,
			"main_pid": kv["MAIN_PID"],
		},
		"ports": ports,
		"cert":  certMap,
		"subscription": map[string]any{
			"secret_set": "yes",
			"local_ok":   svcActive,
			"public_ok":  true,
		},
		"nodes":  nodes,
		"purity": purityMap,
	}
	diagCacheMu.Lock()
	diagCache[id] = diagCacheEntry{diag: cloneDiagMap(res), createdAt: time.Now()}
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

// InstallAeroOnVPS 刷新节点信息：只读读取已安装 edge 的端口与管理密钥（不安装、不修改节点）。
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

	// 只读回读 edge 持久化的端口与管理密钥（与安装流程相同来源 /etc/aero/edge.json）
	st, err := readEdgeServiceState(client)
	if err != nil {
		return nil, err
	}
	host := cred.Domain
	if host == "" {
		host = cred.IP
	}
	ep := EndpointInfo{
		VPSID:       vpsID,
		Name:        cred.Name,
		Host:        host,
		IP:          cred.IP,
		Port:        st.Port,
		AdminKey:    st.AdminKey,
		HasAdmin:    st.AdminKey != "",
		MeteringKey: st.MeteringKey,
		Installed:   true,
		UpdatedAt:   time.Now(),
	}
	if s.eps != nil {
		if err := s.eps.Upsert(ep); err != nil {
			return nil, err
		}
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

	// 步骤 3 起（ADR-0011 运维面、ADR-0012 宿主状态）：安装只做三件事——放置经校验的二进制、
	// 全新安装时写入最小配置、注册服务单元。不安装系统软件，不改防火墙、sysctl、nftables/iptables
	// 持久配置，不写 edge 的业务数据（sub_meta.json 等），密钥不出现在命令行。端口轮试、令牌、证书
	// 发现均由 edge 自己完成并持久化到 /etc/aero/edge.json。
	globalTaskManager.SetStep(taskID, "binary_deploy", "running", "检测远端版本并部署...", 45, "版本检测")
	if src.SourceType != "github" || strings.TrimSpace(src.ReleaseTag) == "" || src.ReleaseTag == "main" {
		errMsg := "未找到可用的 GitHub Release（安装只使用经校验的发布产物，不在节点上编译源码）"
		globalTaskManager.SetStep(taskID, "binary_deploy", "failed", errMsg, 40, "官方源不可用")
		globalTaskManager.Finish(taskID, "failed", errMsg)
		return
	}
	tag := strings.TrimSpace(src.ReleaseTag)
	domain := strings.TrimSpace(cred.Domain)
	if !nodeDomainPattern.MatchString(domain) {
		errMsg := "节点未配置域名：证书与中台管理都按域名进行（只有 IP 的节点无法校验身份）。请先为该 VPS 填写域名并解析到节点（Cloudflare 灰云）。"
		globalTaskManager.SetStep(taskID, "binary_deploy", "failed", errMsg, 40, "缺少域名")
		globalTaskManager.Finish(taskID, "failed", errMsg)
		return
	}
	if err := deployEdgeBinary(client, taskID, src.Repo, tag, domain); err != nil {
		globalTaskManager.AppendLog(taskID, "[部署 错误] "+err.Error())
		globalTaskManager.SetStep(taskID, "binary_deploy", "failed", err.Error(), 40, "部署失败")
		globalTaskManager.Finish(taskID, "failed", err.Error())
		return
	}
	globalTaskManager.SetStep(taskID, "binary_deploy", "success", "已部署 "+tag, 65, "配置服务")

	// 步骤 4：配置与服务单元
	globalTaskManager.SetStep(taskID, "service_config", "running", "写入服务配置...", 70, "配置服务")
	host := cred.Domain
	if host == "" {
		host = cred.IP
	}
	adminKey, err := randomHex(32)
	if err != nil {
		globalTaskManager.Finish(taskID, "failed", err.Error())
		return
	}
	created, err := configureEdgeService(client, host, adminKey, customPort, svc.issuer)
	if err != nil {
		errMsg := fmt.Sprintf("配置服务失败: %v", err)
		globalTaskManager.AppendLog(taskID, "[配置 错误] "+errMsg)
		globalTaskManager.SetStep(taskID, "service_config", "failed", errMsg, 65, "配置失败")
		globalTaskManager.Finish(taskID, "failed", errMsg)
		return
	}
	if created {
		globalTaskManager.AppendLog(taskID, "[配置] 已写入最小配置 /etc/aero/edge.json（0600）；端口、令牌、证书由 edge 自行选择并持久化。")
	} else {
		globalTaskManager.AppendLog(taskID, "[配置] 保留节点现有 /etc/aero/edge.json（配置归 edge 管理，不覆盖）。")
	}
	globalTaskManager.SetStep(taskID, "service_config", "success", "配置就绪", 85, "验收服务")

	// 步骤 5：启动与验收（只读回读 edge 选定的端口与管理密钥）
	globalTaskManager.SetStep(taskID, "verify_health", "running", "启动服务...", 90, "服务验收")
	st, err := readEdgeServiceState(client)
	if err != nil {
		errMsg := fmt.Sprintf("服务未就绪: %v", err)
		globalTaskManager.AppendLog(taskID, "[验收 错误] "+errMsg)
		globalTaskManager.SetStep(taskID, "verify_health", "failed", errMsg, 90, "服务未就绪")
		globalTaskManager.Finish(taskID, "failed", errMsg)
		return
	}
	globalTaskManager.AppendLog(taskID, fmt.Sprintf("[验收] aero-edge 运行中，监听端口 %d。", st.Port))
	if len(st.Firewalls) > 0 {
		globalTaskManager.AppendLog(taskID, fmt.Sprintf("[防火墙 提示] 检测到 %s 处于启用状态。安装程序不修改宿主防火墙，请运维放行 UDP/TCP %d 及备用端口 2083 2087 8443 2053 2096 10443 24443 34443 44443。",
			strings.Join(st.Firewalls, "、"), st.Port))
	}

	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	ep := EndpointInfo{
		VPSID:       vpsID,
		Name:        cred.Name,
		Host:        host,
		IP:          cred.IP,
		Port:        st.Port,
		AdminKey:    st.AdminKey,
		HasAdmin:    st.AdminKey != "",
		MeteringKey: st.MeteringKey,
		Installed:   true,
		Version:     strings.TrimPrefix(tag, "v"),
		UpdatedAt:   time.Now(),
	}
	if svc.eps != nil {
		if err := svc.eps.Upsert(ep); err != nil {
			globalTaskManager.AppendLog(taskID, "[资产 警告] 记录节点信息失败: "+err.Error())
		}
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
				n.Port = int32(st.Port)
				n.UpdatedAt = time.Now()
				found = true
				break
			}
		}
		svc.nodeSvc.mu.Unlock()
		if !found {
			_, _ = svc.nodeSvc.CreateNode(cred.Name, geo, host, "aero-quic", int32(st.Port), 500, false, 100, vpsID)
		}
	}

	// 过渡期：用户凭证仍经 /admin/subs 同步；C3 签名 token 上线后删除（ADR-0010/0011）。
	if svc.userStore != nil {
		if err := svc.SyncAllUsersToVPS(vpsID, svc.userStore); err == nil {
			globalTaskManager.AppendLog(taskID, "[凭证同步] 已同步活跃用户凭证至节点。")
		} else {
			globalTaskManager.AppendLog(taskID, "[凭证同步 警告] "+err.Error())
		}
	}

	InvalidateDiagCache(vpsID)
	globalTaskManager.AppendLog(taskID, "===> AERO Edge 部署完成 <===")
	globalTaskManager.SetStep(taskID, "verify_health", "success", "服务运行正常", 100, "安装完成")
	globalTaskManager.Finish(taskID, "success", "")
}

// deployEdgeBinary 在节点上按架构下载 Release 产物，对照同一 Release 的 SHA256SUMS 校验后原子替换。
// 旧 Release 没有 SHA256SUMS 时记录“未校验”并继续；有 SHA256SUMS 但缺条目或不匹配时拒绝安装。
// deployEdgeBinary 下载并校验发布物，先用新二进制执行只读证书预检（check-cert，与 edge 启动规则相同），
// 通过后才替换 /usr/local/bin/aero-edge；预检不通过时节点保持原样。
func deployEdgeBinary(client *ssh.Client, taskID uint64, repo, tag, domain string) error {
	if !nodeDomainPattern.MatchString(domain) {
		return fmt.Errorf("节点域名无效: %q", domain)
	}
	base := fmt.Sprintf("https://github.com/%s/releases/download/%s", repo, tag)
	script := fmt.Sprintf(`set -e
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "RESULT=unsupported-arch-$(uname -m)"; exit 0 ;;
esac
ASSET="edge_linux_$ARCH"
TMP="/usr/local/bin/.aero-edge.new.$$"
SUMS="/tmp/.aero-edge-sums.$$"
trap 'rm -f "$TMP" "$SUMS"' EXIT
mkdir -p /usr/local/bin
curl -fsSL --retry 3 -o "$TMP" "%s/$ASSET" || { echo "RESULT=download-failed"; exit 0; }
if curl -fsSL --retry 2 -o "$SUMS" "%s/SHA256SUMS"; then
  EXP=$(awk -v n="$ASSET" '$2==n || $2=="*"n {print $1}' "$SUMS")
  [ -n "$EXP" ] || { echo "RESULT=checksum-entry-missing"; exit 0; }
  echo "$EXP  $TMP" | sha256sum -c - >/dev/null 2>&1 || { echo "RESULT=checksum-mismatch"; exit 0; }
  echo "CHECKSUM=verified"
else
  echo "CHECKSUM=unavailable"
fi
chmod 0755 "$TMP"
VER=$("$TMP" -version 2>/dev/null | awk '{print $2}')
[ -n "$VER" ] || { echo "RESULT=binary-not-runnable"; exit 0; }
echo "VERSION=$VER"
CHECK=$("$TMP" check-cert -domain '%s' 2>/dev/null || true)
echo "$CHECK"
echo "$CHECK" | grep -qx 'CERT_FOUND=yes' || { echo "RESULT=cert-missing"; exit 0; }
mv -f "$TMP" /usr/local/bin/aero-edge
echo "RESULT=ok"
`, base, base, domain)
	out, err := runSSH(client, script, 180*time.Second)
	kv := parseKV(out)
	if err == nil && kv["RESULT"] == "cert-missing" {
		return certMissingError(domain, kv)
	}
	if err != nil || kv["RESULT"] != "ok" {
		return fmt.Errorf("部署 aero-edge %s 失败: result=%q err=%v", tag, kv["RESULT"], err)
	}
	globalTaskManager.AppendLog(taskID, fmt.Sprintf("[证书] 已有覆盖 %s 的有效证书 %s（到期 %s），跳过证书步骤。", domain, kv["CERT_FILE"], kv["CERT_NOT_AFTER"]))
	if kv["CHECKSUM"] == "verified" {
		globalTaskManager.AppendLog(taskID, fmt.Sprintf("[部署] aero-edge %s 已安装，SHA256 校验通过。", kv["VERSION"]))
	} else {
		globalTaskManager.AppendLog(taskID, fmt.Sprintf("[部署 警告] aero-edge %s 已安装，但该 Release 无 SHA256SUMS，未做哈希校验。", kv["VERSION"]))
	}
	return nil
}

// nodeDomainPattern 限定节点域名（证书与中台管理都按域名；也用于安全地拼入远程命令）。
var nodeDomainPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62}\.)+[A-Za-z]{2,63}$`)

// certMissingError 生成证书预检失败的提示：中台不在节点上安装或签发任何东西，由运维用系统 ACME 客户端完成。
func certMissingError(domain string, kv map[string]string) error {
	where := strings.ReplaceAll(kv["CERT_SEARCHED"], ",", "、")
	if kv["ACME_SH"] != "yes" && kv["CERTBOT"] != "yes" {
		return fmt.Errorf("证书预检未通过：节点上未检测到 acme.sh 或 certbot。请先安装其一，并为 %s 签发证书（使用默认位置），"+
			"完成后重新执行安装。节点未做任何改动。查找位置：%s", domain, where)
	}
	client := "acme.sh"
	if kv["ACME_SH"] != "yes" {
		client = "certbot"
	}
	return fmt.Errorf("证书预检未通过：已检测到 %s，但没有覆盖 %s 的有效证书。请先用 %s 签发（默认位置），完成后重新执行安装。"+
		"节点未做任何改动。查找位置：%s", client, domain, client, where)
}

// edgeServiceUnit 是 aero-edge 的 systemd 单元：命令行不含任何密钥（配置在 0600 的 /etc/aero/edge.json），
// 退出（含崩溃）后由 ExecStopPost 还原宿主状态（ADR-0012）。
const edgeServiceUnit = `[Unit]
Description=AERO Edge Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/aero-edge -config /etc/aero/edge.json
ExecStopPost=/usr/local/bin/aero-edge cleanup-host -config /etc/aero/edge.json
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
`

// configureEdgeService 全新安装时写入最小配置（已有配置不覆盖，返回 created=false），写入服务单元并重启服务。
func configureEdgeService(client *ssh.Client, host, adminKey string, customPort int, issuer *TokenIssuer) (created bool, err error) {
	cfg := map[string]any{"domain": host, "data_dir": "/var/lib/aero", "admin_key": adminKey}
	if customPort > 0 {
		cfg["listen"] = fmt.Sprintf(":%d", customPort)
	}
	if issuer != nil {
		// 只写公钥（运维面配置）；auth_signed_token 默认关闭，由运维确认后开启（C3）
		cfg["token_issuers"] = map[string]string{issuer.Kid(): issuer.PublicKeyBase64()}
	}
	cfgJSON, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return false, err
	}
	script := fmt.Sprintf(`set -e
mkdir -p /etc/aero /var/lib/aero
chmod 700 /etc/aero
if [ -f /etc/aero/edge.json ]; then
  echo "CONFIG=existing"
else
  ( umask 077; cat > /etc/aero/edge.json.new <<'AERO_CFG_EOF'
%s
AERO_CFG_EOF
  )
  mv -f /etc/aero/edge.json.new /etc/aero/edge.json
  echo "CONFIG=created"
fi
cat > /etc/systemd/system/aero-edge.service <<'AERO_UNIT_EOF'
%sAERO_UNIT_EOF
systemctl daemon-reload
systemctl enable aero-edge >/dev/null 2>&1
systemctl restart aero-edge
echo "RESULT=ok"
`, cfgJSON, edgeServiceUnit)
	out, err := runSSH(client, script, 30*time.Second)
	kv := parseKV(out)
	if err != nil || kv["RESULT"] != "ok" {
		return false, fmt.Errorf("result=%q err=%v", kv["RESULT"], err)
	}
	return kv["CONFIG"] == "created", nil
}

type edgeServiceState struct {
	Port        int
	AdminKey    string
	MeteringKey string   // usage_api 开启后才有（C6）
	Firewalls   []string // 处于启用状态的宿主防火墙（只检测，不修改）
}

// readEdgeServiceState 等待服务就绪后只读回读 edge 持久化的监听端口与管理密钥，并检测宿主防火墙。
func readEdgeServiceState(client *ssh.Client) (edgeServiceState, error) {
	script := `set +e
for i in $(seq 1 30); do
  if systemctl is-active --quiet aero-edge && grep -q '"listen"' /etc/aero/edge.json 2>/dev/null; then break; fi
  sleep 0.5
done
echo "ACTIVE=$(systemctl is-active aero-edge)"
echo "LISTEN=$(grep -o '"listen"[[:space:]]*:[[:space:]]*"[^"]*"' /etc/aero/edge.json | sed 's/.*"\([^"]*\)"$/\1/')"
echo "ADMIN_KEY=$(grep -o '"admin_key"[[:space:]]*:[[:space:]]*"[^"]*"' /etc/aero/edge.json | sed 's/.*"\([^"]*\)"$/\1/')"
echo "METERING_KEY=$(grep -o '"metering_key"[[:space:]]*:[[:space:]]*"[^"]*"' /etc/aero/edge.json | sed 's/.*"\([^"]*\)"$/\1/')"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then echo "FW_UFW=yes"; fi
if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then echo "FW_FIREWALLD=yes"; fi
`
	out, err := runSSH(client, script, 30*time.Second)
	if err != nil {
		return edgeServiceState{}, err
	}
	kv := parseKV(out)
	if kv["ACTIVE"] != "active" {
		return edgeServiceState{}, fmt.Errorf("aero-edge 状态为 %q（请查看 journalctl -u aero-edge）", kv["ACTIVE"])
	}
	_, portStr, err := net.SplitHostPort(kv["LISTEN"])
	if err != nil {
		return edgeServiceState{}, fmt.Errorf("无法从 edge.json 读取监听地址 %q: %w", kv["LISTEN"], err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 {
		return edgeServiceState{}, fmt.Errorf("监听端口无效 %q", portStr)
	}
	st := edgeServiceState{Port: port, AdminKey: kv["ADMIN_KEY"], MeteringKey: kv["METERING_KEY"]}
	if kv["FW_UFW"] == "yes" {
		st.Firewalls = append(st.Firewalls, "UFW")
	}
	if kv["FW_FIREWALLD"] == "yes" {
		st.Firewalls = append(st.Firewalls, "firewalld")
	}
	return st, nil
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
	// 正常停止，让 ExecStopPost（cleanup-host）还原宿主状态；不强杀，不按路径前缀误杀其他进程。
	stopCmd := "systemctl stop aero-edge 2>/dev/null; systemctl disable aero-edge 2>/dev/null; true"
	_, _ = runSSH(client, stopCmd, 15*time.Second)
	globalTaskManager.SetStep(taskID, "stop_service", "success", "服务已停止并终结", 65, "清理文件与网络规则")

	// 步骤 3：清理文件与环境（同时清理 nftables 与 iptables 重定向规则，恢复宿主机初始状态）
	globalTaskManager.SetStep(taskID, "clean_files", "running", "深度清理核心文件、配置与网络规则...", 80, "清理文件与网络规则")
	globalTaskManager.AppendLog(taskID, "[清理] 正在清理 /usr/local/bin/aero-edge、systemd 单元、运行配置及 NAT 重定向规则...")
	cleanCmd := `set +e
# 先还原宿主（转发规则、ip_forward），再删除程序（ADR-0012）
[ -x /usr/local/bin/aero-edge ] && /usr/local/bin/aero-edge cleanup-host
rm -rf /usr/local/bin/aero-edge /usr/local/bin/aero /etc/systemd/system/aero-edge.service /etc/systemd/system/aero.service /etc/aero /var/lib/aero/tls /var/lib/aero/certs /var/lib/aero/edge.conf
systemctl daemon-reload 2>/dev/null || true

# 清理旧版本（≤1.2.x）安装流程添加的重定向规则（本程序的残留）；不改写系统防火墙持久配置文件
if command -v nft >/dev/null 2>&1; then
  nft delete table inet aero_nat 2>/dev/null || true
fi

# 同上：旧版本 iptables 重定向规则
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
