package service

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/aero/artifact"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/aero/domain"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/aero/edgeclient"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/aero/endpoint"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/aero/iface"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/aero/store"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/sshprobe"
)

// Service deploys AERO only. VPS data comes via iface.VPSProvider (in-process).
type Service struct {
	store    store.Store
	vps      iface.VPSProvider
	endpoint endpoint.Backend
}

func New(st store.Store, vps iface.VPSProvider) *Service {
	return &Service{store: st, vps: vps, endpoint: endpoint.NewStore()}
}

// NewWithEndpoints allows a durable endpoint store (file-backed).
func NewWithEndpoints(st store.Store, vps iface.VPSProvider, ep endpoint.Backend) *Service {
	if ep == nil {
		ep = endpoint.NewStore()
	}
	return &Service{store: st, vps: vps, endpoint: ep}
}

func (s *Service) Endpoints() endpoint.Backend { return s.endpoint }

func (s *Service) ListTasks() ([]domain.DeployTask, error) { return s.store.ListTasks() }
func (s *Service) GetTask(id uint64) (*domain.DeployTask, error) {
	return s.store.GetTask(id)
}

func (s *Service) DeleteTask(id uint64) error { return s.store.DeleteTask(id) }
func (s *Service) ClearFailed() (int, error)  { return s.store.DeleteByStatus("failed") }

// ListVPSOptions returns VPS picker rows via interface (no HTTP).
func (s *Service) ListVPSOptions() ([]iface.Option, error) {
	return s.vps.ListOptions()
}

func (s *Service) StartInstall(vpsID uint64) (*domain.DeployTask, error) {
	cred, err := s.vps.Credentials(vpsID)
	if err != nil {
		return nil, fmt.Errorf("fetch VPS credentials: %w", err)
	}
	spec, _ := artifact.ResolveDesired()
	ver := "…"
	if spec.Tag != "" {
		ver = spec.Tag
	}
	t := &domain.DeployTask{
		Kind: "install", VPSID: vpsID, VPSName: cred.Name,
		Status: "pending", Stage: "排队", Progress: 0, AeroVersion: ver,
		Steps: installSteps(), Logs: []string{},
	}
	if _, err := s.store.CreateTask(t); err != nil {
		return nil, err
	}
	go s.runInstall(t.ID, cred)
	return t, nil
}

func (s *Service) StartUninstall(vpsID uint64) (*domain.DeployTask, error) {
	cred, err := s.vps.Credentials(vpsID)
	if err != nil {
		return nil, fmt.Errorf("fetch VPS credentials: %w", err)
	}
	t := &domain.DeployTask{
		Kind: "uninstall", VPSID: vpsID, VPSName: cred.Name,
		Status: "pending", Stage: "排队", Progress: 0,
		Steps: uninstallSteps(), Logs: []string{},
	}
	if _, err := s.store.CreateTask(t); err != nil {
		return nil, err
	}
	go s.runUninstall(t.ID, cred)
	return t, nil
}

func installSteps() []domain.DeployStep {
	return []domain.DeployStep{
		{Key: "resolve", Title: "解析最新制品", Status: "pending"},
		{Key: "ssh", Title: "SSH 连通", Status: "pending"},
		{Key: "detect", Title: "检测已有版本", Status: "pending"},
		{Key: "binary", Title: "安装/升级二进制", Status: "pending"},
		{Key: "systemd", Title: "配置 systemd", Status: "pending"},
		{Key: "finish", Title: "验收", Status: "pending"},
	}
}

func uninstallSteps() []domain.DeployStep {
	return []domain.DeployStep{
		{Key: "ssh", Title: "SSH 连通", Status: "pending"},
		{Key: "stop", Title: "停止服务", Status: "pending"},
		{Key: "purge", Title: "清除文件", Status: "pending"},
		{Key: "finish", Title: "验收", Status: "pending"},
	}
}

func (s *Service) runInstall(taskID uint64, cred *iface.Cred) {
	steps := installSteps()
	log := func(line string) { _ = s.store.AppendLog(taskID, line) }
	setStep := func(i int, st, detail string) {
		now := time.Now()
		if st == "running" {
			steps[i].Started = &now
		}
		if st == "success" || st == "failed" || st == "skipped" {
			steps[i].Ended = &now
		}
		steps[i].Status = st
		steps[i].Detail = detail
		prog := ((i + 1) * 100) / len(steps)
		if st == "running" {
			prog = (i * 100) / len(steps)
		}
		_ = s.store.UpdateProgress(taskID, steps[i].Title, prog, steps)
	}
	fail := func(i int, msg string) {
		setStep(i, "failed", msg)
		log("ERROR  " + msg)
		_ = s.store.Finish(taskID, "failed", msg)
	}

	setStep(0, "running", "GitHub latest")
	log(fmt.Sprintf("AERO 安装任务 #%d → VPS %s (%s)", taskID, cred.Name, cred.IP))
	log("模块边界: 凭据经 VPSProvider 接口，本包只负责 Edge 包")
	spec, err := artifact.ResolveDesired()
	if err != nil {
		fail(0, "解析制品失败: "+err.Error())
		return
	}
	log(fmt.Sprintf("期望 %s source=%s url=%s", spec.Tag, spec.Source, spec.URL))
	setStep(0, "success", spec.Tag)

	setStep(1, "running", "SSH")
	clientSSH, err := sshprobe.Dial(sshprobe.Credentials{
		Host: cred.IP, Port: cred.SSHPort, User: cred.SSHUsername, Password: cred.SSHPassword,
	}, 15*time.Second)
	if err != nil {
		fail(1, err.Error())
		return
	}
	defer clientSSH.Close()
	setStep(1, "success", "已连接")
	log("SSH 成功")

	setStep(2, "running", "VERSION 对比")
	detOut, _ := sshprobe.Run(clientSSH, detectScript, 20*time.Second)
	for _, line := range strings.Split(strings.TrimSpace(detOut), "\n") {
		if strings.TrimSpace(line) != "" {
			log("检测  " + strings.TrimSpace(line))
		}
	}
	det := parseDetect(detOut)
	skipBin := det.ok && (artifact.EqualVersion(det.version, spec.Version) ||
		(spec.SHA256 != "" && det.sha != "" && strings.EqualFold(det.sha, spec.SHA256)))
	// Prefer local fix binary (TLS SNI/autocert bugfix) when present, even if version tag matches.
	localBin := resolveLocalEdgeBin()
	forceLocal := localBin != ""

	if skipBin && !forceLocal {
		log("已是最新 " + spec.Tag + "，跳过下载")
		setStep(2, "success", "已最新")
		setStep(3, "skipped", "跳过二进制")
	} else {
		if forceLocal {
			log("使用本地制品覆盖安装: " + localBin)
		} else if det.ok {
			log(fmt.Sprintf("需升级 actual=%s desired=%s", empty(det.version, "?"), spec.Tag))
		} else {
			log("未安装或损坏，安装最新 " + spec.Tag)
		}
		setStep(2, "success", "需要安装/升级")
		setStep(3, "running", "上传/下载二进制")
		var out string
		var err error
		if forceLocal {
			// SCP local binary then install
			_, _ = sshprobe.Run(clientSSH, "mkdir -p /opt/aero /usr/local/bin /tmp", 10*time.Second)
			if err = sshprobe.SCPPut(clientSSH, localBin, "/tmp/aero-edge.tmp", 180*time.Second); err != nil {
				fail(3, "SCP 上传失败: "+err.Error())
				return
			}
			out, err = sshprobe.Run(clientSSH, `set -e
[ -s /tmp/aero-edge.tmp ] || { echo "ERROR: uploaded binary is empty"; exit 1; }
chmod +x /tmp/aero-edge.tmp
systemctl stop aero-edge 2>/dev/null || true
mv -f /tmp/aero-edge.tmp /opt/aero/aero-edge
chmod +x /opt/aero/aero-edge
cp -f /opt/aero/aero-edge /usr/local/bin/aero-edge
printf '%s\n' 'v1.0.1-tlsfix' > /opt/aero/VERSION
ls -lh /opt/aero/aero-edge
`, 30*time.Second)
		} else {
			dl := fmt.Sprintf(`set -e
mkdir -p /opt/aero /usr/local/bin
cd /tmp
curl -fsSL --connect-timeout 20 --max-time 180 -o aero-edge.tmp %q
[ -s aero-edge.tmp ] || { echo "ERROR: downloaded binary is empty"; exit 1; }
chmod +x aero-edge.tmp
systemctl stop aero-edge 2>/dev/null || true
mv -f aero-edge.tmp /opt/aero/aero-edge
chmod +x /opt/aero/aero-edge
cp -f /opt/aero/aero-edge /usr/local/bin/aero-edge
printf '%%s\n' %q > /opt/aero/VERSION
ls -lh /opt/aero/aero-edge
`, spec.URL, spec.Tag)
			out, err = sshprobe.Run(clientSSH, dl, 200*time.Second)
		}
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			if strings.TrimSpace(line) != "" {
				log("制品  " + strings.TrimSpace(line))
			}
		}
		if err != nil {
			fail(3, "安装二进制失败: "+err.Error())
			return
		}
		if forceLocal {
			setStep(3, "success", "local-tlsfix")
		} else {
			setStep(3, "success", spec.Tag)
		}
	}

	setStep(4, "running", "systemd")
	out, err := sshprobe.Run(clientSSH, ensureSystemd(cred), 45*time.Second)
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.TrimSpace(line) != "" {
			log("服务  " + strings.TrimSpace(line))
		}
	}
	if err != nil || !strings.Contains(out, "SERVICE_ACTIVE=yes") {
		log("WARN  服务可能未 active，检查 journalctl -u aero-edge")
		if err != nil {
			fail(4, "systemd 失败: "+err.Error())
			return
		}
		setStep(4, "skipped", "未 active")
	} else {
		setStep(4, "success", "active")
		log("aero-edge.service active")
	}

	setStep(5, "running", "采集订阅元数据")
	metaOut, _ := sshprobe.Run(clientSSH, harvestMetaScript, 15*time.Second)
	for _, line := range strings.Split(strings.TrimSpace(metaOut), "\n") {
		if strings.TrimSpace(line) != "" {
			log("元数据  " + strings.TrimSpace(line))
		}
	}
	ep := parseHarvest(metaOut, cred)
	if ep.SubSecret != "" || ep.AdminKey != "" {
		s.endpoint.Upsert(ep)
		log("SUB_URL=" + ep.SubURL)
	} else {
		log("WARN  未能解析 sub_secret，可稍后点「刷新端点」")
	}
	log(fmt.Sprintf("客户端: connect.ps1 -Sub %s", empty(ep.SubURL, "(pending)")))
	setStep(5, "success", "完成")
	_ = s.store.Finish(taskID, "success", "")
}

func (s *Service) runUninstall(taskID uint64, cred *iface.Cred) {
	steps := uninstallSteps()
	log := func(line string) { _ = s.store.AppendLog(taskID, line) }
	setStep := func(i int, st, detail string) {
		now := time.Now()
		if st == "running" {
			steps[i].Started = &now
		}
		if st == "success" || st == "failed" || st == "skipped" {
			steps[i].Ended = &now
		}
		steps[i].Status = st
		steps[i].Detail = detail
		_ = s.store.UpdateProgress(taskID, steps[i].Title, ((i+1)*100)/len(steps), steps)
	}
	fail := func(i int, msg string) {
		setStep(i, "failed", msg)
		log("ERROR  " + msg)
		_ = s.store.Finish(taskID, "failed", msg)
	}

	log(fmt.Sprintf("AERO 卸载 #%d → %s %s（不删除 VPS 登记）", taskID, cred.Name, cred.IP))
	setStep(0, "running", "SSH")
	c, err := sshprobe.Dial(sshprobe.Credentials{
		Host: cred.IP, Port: cred.SSHPort, User: cred.SSHUsername, Password: cred.SSHPassword,
	}, 15*time.Second)
	if err != nil {
		fail(0, err.Error())
		return
	}
	defer c.Close()
	setStep(0, "success", "ok")

	setStep(1, "running", "stop")
	out, _ := sshprobe.Run(c, `set +e
systemctl stop aero-edge 2>&1; systemctl disable aero-edge 2>&1
pkill -x aero-edge 2>/dev/null; echo stop_done
`, 30*time.Second)
	log(trim(out, 400))
	setStep(1, "success", "stopped")

	setStep(2, "running", "purge")
	out, _ = sshprobe.Run(c, `set +e
rm -f /etc/systemd/system/aero-edge.service
systemctl daemon-reload
rm -rf /opt/aero /var/lib/aero /etc/aero
rm -f /usr/local/bin/aero-edge
echo purge_done
`, 30*time.Second)
	log(trim(out, 400))
	setStep(2, "success", "purged")

	setStep(3, "running", "verify")
	out, _ = sshprobe.Run(c, `set +e
systemctl is-active aero-edge 2>&1 || echo unit_gone
test ! -e /opt/aero && echo opt_gone
`, 10*time.Second)
	log(trim(out, 300))
	setStep(3, "success", "done")
	s.endpoint.Delete(cred.VPSID)
	log("卸载完成。VPS 资产仍在登记表，可再次安装 AERO。")
	_ = s.store.Finish(taskID, "success", "")
}

// GetEndpoint returns stored edge endpoint for UI.
func (s *Service) GetEndpoint(vpsID uint64) (map[string]any, error) {
	if ep, ok := s.endpoint.Get(vpsID); ok {
		return ep.Public(), nil
	}
	// try live harvest if credentials available
	if err := s.RefreshEndpoint(vpsID); err != nil {
		return nil, fmt.Errorf("not installed or unreachable: %w", err)
	}
	ep, ok := s.endpoint.Get(vpsID)
	if !ok {
		return nil, fmt.Errorf("endpoint not found")
	}
	return ep.Public(), nil
}

// RefreshEndpoint SSH-harvests sub secret + admin key from VPS.
func (s *Service) RefreshEndpoint(vpsID uint64) error {
	cred, err := s.vps.Credentials(vpsID)
	if err != nil {
		return err
	}
	c, err := sshprobe.Dial(sshprobe.Credentials{
		Host: cred.IP, Port: cred.SSHPort, User: cred.SSHUsername, Password: cred.SSHPassword,
	}, 12*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	out, err := sshprobe.Run(c, harvestMetaScript, 15*time.Second)
	if err != nil {
		return err
	}
	ep := parseHarvest(out, cred)
	if ep.SubSecret == "" && ep.AdminKey == "" {
		return fmt.Errorf("no edge metadata on host")
	}
	ep.Installed = true
	s.endpoint.Upsert(ep)
	return nil
}

func (s *Service) endpointReady(vpsID uint64) (*endpoint.Info, error) {
	ep, ok := s.endpoint.Get(vpsID)
	if !ok || ep.AdminKey == "" {
		_ = s.RefreshEndpoint(vpsID)
		ep, ok = s.endpoint.Get(vpsID)
	}
	if !ok {
		return nil, fmt.Errorf("endpoint not found — install or refresh first")
	}
	if ep.AdminKey == "" {
		return nil, fmt.Errorf("admin key unknown — install or refresh endpoint first")
	}
	return ep, nil
}

// edgeFor builds a public HTTPS client (may fail if edge TLS/network blocked from mid).
func (s *Service) edgeFor(vpsID uint64) (*edgeclient.Client, error) {
	ep, err := s.endpointReady(vpsID)
	if err != nil {
		return nil, err
	}
	// Prefer IP: domain CDN/WAF often drops Admin; IP + skip-verify is direct.
	host := ep.IP
	if host == "" {
		host = ep.Host
	}
	if ep.Port > 0 && ep.Port != 443 && !strings.Contains(host, ":") {
		host = fmt.Sprintf("%s:%d", host, ep.Port)
	}
	return edgeclient.New(host, ep.AdminKey), nil
}

func (s *Service) ListTokens(vpsID uint64) ([]map[string]any, error) {
	if cli, err := s.edgeFor(vpsID); err == nil {
		if list, err2 := cli.ListTokens(); err2 == nil {
			return list, nil
		}
	}
	raw, err := s.adminViaSSH(vpsID, "GET", "/admin/tokens", "")
	if err != nil {
		return nil, fmt.Errorf("public Admin unreachable; SSH fallback failed: %w", err)
	}
	var wrap struct {
		Tokens []map[string]any `json:"tokens"`
	}
	if err := json.Unmarshal(raw, &wrap); err != nil {
		return nil, fmt.Errorf("ssh admin parse: %w", err)
	}
	return wrap.Tokens, nil
}

func (s *Service) AddToken(vpsID uint64, token, label string, ttlHours int) (map[string]any, error) {
	if cli, err := s.edgeFor(vpsID); err == nil {
		if m, err2 := cli.AddToken(token, label, ttlHours); err2 == nil {
			return m, nil
		}
	}
	body, _ := json.Marshal(map[string]any{"token": token, "label": label, "ttl_hours": ttlHours})
	raw, err := s.adminViaSSH(vpsID, "POST", "/admin/tokens", string(body))
	if err != nil {
		return nil, err
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return m, nil
}

func (s *Service) DelToken(vpsID uint64, token string) error {
	if cli, err := s.edgeFor(vpsID); err == nil {
		if err2 := cli.DelToken(token); err2 == nil {
			return nil
		}
	}
	path := "/admin/tokens?token=" + url.QueryEscape(token)
	_, err := s.adminViaSSH(vpsID, "DELETE", path, "")
	return err
}

func (s *Service) EdgeStatus(vpsID uint64) (map[string]any, error) {
	// Full SSH diagnose is source of truth (public HTTPS Admin often broken from mid).
	rep, err := s.Diagnose(vpsID)
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(rep)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m, nil
}

// adminViaSSH talks to edge Admin on 127.0.0.1 via python3 over SSH.
func (s *Service) adminViaSSH(vpsID uint64, method, path, jsonBody string) ([]byte, error) {
	ep, err := s.endpointReady(vpsID)
	if err != nil {
		return nil, err
	}
	cred, err := s.vps.Credentials(vpsID)
	if err != nil {
		return nil, err
	}
	c, err := sshprobe.Dial(sshprobe.Credentials{
		Host: cred.IP, Port: cred.SSHPort, User: cred.SSHUsername, Password: cred.SSHPassword,
	}, 12*time.Second)
	if err != nil {
		return nil, fmt.Errorf("ssh dial: %w", err)
	}
	defer c.Close()

	// Loopback Admin must send SNI=domain — pure autocert rejects empty SNI.
	sni := ep.Host
	if sni == "" {
		sni = ep.IP
	}
	sni = strings.TrimPrefix(strings.TrimPrefix(sni, "https://"), "http://")
	sni = strings.Split(sni, "/")[0]
	sni = strings.Split(sni, ":")[0]
	if sni == "" {
		sni = "localhost"
	}
	port := ep.Port
	if port <= 0 {
		port = 443
	}
	cmd := "export AERO_ADMIN_KEY_ENV=" + shellQuote(ep.AdminKey) +
		"; export AERO_ADM_METHOD=" + shellQuote(method) +
		"; export AERO_ADM_PATH=" + shellQuote(path) +
		"; export AERO_ADM_BODY=" + shellQuote(jsonBody) +
		"; export AERO_SNI_ENV=" + shellQuote(sni) +
		"; export AERO_ADM_PORT=" + strconv.Itoa(port) +
		`; python3 - <<'PY'
import os, ssl, json, sys, socket, http.client
method = os.environ.get("AERO_ADM_METHOD","GET")
path = os.environ.get("AERO_ADM_PATH","/admin/status")
body = os.environ.get("AERO_ADM_BODY","")
key = os.environ.get("AERO_ADMIN_KEY_ENV","")
sni = (os.environ.get("AERO_SNI_ENV") or "localhost").strip() or "localhost"
port = int(os.environ.get("AERO_ADM_PORT", "443"))
try:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection(("127.0.0.1", port), timeout=12)
    ssock = ctx.wrap_socket(raw, server_hostname=sni)
    conn = http.client.HTTPSConnection("127.0.0.1", port, timeout=12, context=ctx)
    conn.sock = ssock
    headers = {"X-Aero-Admin-Key": key, "Host": sni}
    data = body.encode() if body else None
    if body:
        headers["Content-Type"] = "application/json"
    conn.request(method, path, body=data, headers=headers)
    resp = conn.getresponse()
    out = resp.read().decode("utf-8","replace")
    if resp.status >= 300:
        sys.stderr.write(out or ("http %d" % resp.status))
        sys.exit(1)
    sys.stdout.write(out)
    conn.close()
except Exception as e:
    sys.stderr.write(str(e))
    sys.exit(1)
PY`
	out, err := sshprobe.Run(c, cmd, 25*time.Second)
	out = strings.TrimSpace(out)
	if err != nil {
		if out != "" {
			return nil, fmt.Errorf("edge admin: %s", trim(out, 200))
		}
		return nil, fmt.Errorf("ssh admin: %w", err)
	}
	if out == "" {
		return nil, fmt.Errorf("empty response from edge Admin via SSH (is aero-edge active? python3?)")
	}
	if strings.HasPrefix(out, "forbidden") {
		return nil, fmt.Errorf("edge admin: %s", trim(out, 160))
	}
	return []byte(out), nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

const harvestMetaScript = `set +e
[ -f /etc/aero/edge.conf ] && . /etc/aero/edge.conf 2>/dev/null
echo "ADMIN_KEY=${AERO_ADMIN_KEY:-$ADMIN_KEY}"
echo "AERO_TOKEN=${AERO_TOKEN:-$TOKEN}"
echo "ADVERTISE=${AERO_ADVERTISE:-${AERO_DOMAIN:-}}"
PORT="${AERO_PORTS:-}"
if [ -z "$PORT" ] && [ -f /var/lib/aero/sub_meta.json ]; then
  PORT=$(python3 -c "import json;addr=json.load(open('/var/lib/aero/sub_meta.json'))['document']['servers'][0]['address'];print(addr.split(':')[-1])" 2>/dev/null)
fi
[ -z "$PORT" ] && PORT="443"
echo "PORT=$PORT"
if [ -f /var/lib/aero/sub_meta.json ]; then
  SEC=$(python3 -c "import json;print(json.load(open('/var/lib/aero/sub_meta.json')).get('secret',''))" 2>/dev/null)
  [ -z "$SEC" ] && SEC=$(grep -o '"secret"[[:space:]]*:[[:space:]]*"[^"]*"' /var/lib/aero/sub_meta.json | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
  echo "SUB_SECRET=$SEC"
else
  echo "SUB_SECRET="
fi
systemctl is-active aero-edge 2>/dev/null | sed 's/^/SERVICE=/'
`

func parseHarvest(out string, cred *iface.Cred) endpoint.Info {
	kv := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, "="); i > 0 {
			kv[line[:i]] = line[i+1:]
		}
	}
	host := strings.TrimSpace(kv["ADVERTISE"])
	if host == "" {
		host = empty(cred.Domain, cred.IP)
	}
	// strip scheme if any
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
		if port == 443 {
			subURL = "https://" + host + "/sub/" + sec
		} else {
			subURL = fmt.Sprintf("https://%s:%d/sub/%s", host, port, sec)
		}
	}
	return endpoint.Info{
		VPSID:     cred.VPSID,
		Name:      cred.Name,
		Host:      host,
		IP:        cred.IP,
		Port:      port,
		SubSecret: sec,
		AdminKey:  admin,
		HasAdmin:  admin != "",
		SubURL:    subURL,
		Installed: kv["SERVICE"] == "active" || sec != "" || admin != "",
	}
}

type detectInfo struct {
	ok      bool
	version string
	sha     string
}

func parseDetect(out string) detectInfo {
	kv := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, "="); i > 0 {
			kv[line[:i]] = line[i+1:]
		}
	}
	return detectInfo{
		ok:      kv["INSTALLED"] == "yes" && kv["BINARY_OK"] == "yes",
		version: kv["VERSION"],
		sha:     strings.ToLower(kv["SHA256"]),
	}
}

const detectScript = `set +e
BIN=""
for p in /opt/aero/aero-edge /usr/local/bin/aero-edge; do
  [ -f "$p" ] && BIN="$p" && break
done
if [ -n "$BIN" ]; then echo "INSTALLED=yes"; echo "BINARY_PATH=$BIN"; else echo "INSTALLED=no"; fi
if [ -n "$BIN" ] && [ -f "$BIN" ]; then echo "BINARY_OK=yes"; else echo "BINARY_OK=no"; fi
[ -f /opt/aero/VERSION ] && echo "VERSION=$(cat /opt/aero/VERSION | tr -d '\r\n')" || echo "VERSION="
if [ -n "$BIN" ] && command -v sha256sum >/dev/null; then echo "SHA256=$(sha256sum "$BIN" | awk '{print $1}')"; else echo "SHA256="; fi
systemctl is-active aero-edge 2>/dev/null | sed 's/^/SERVICE=/' || true
`

func ensureSystemd(cred *iface.Cred) string {
	domain := strings.TrimSpace(cred.Domain)
	ip := cred.IP
	// Cert policy (user requirement):
	// 1) If /var/lib/aero/tls/{fullchain,privkey}.pem exist → use them (static LE/ZeroSSL)
	// 2) Else try copy from acme.sh / certbot
	// 3) Else issue via acme.sh: Let's Encrypt first, ZeroSSL fallback — NEVER self-signed
	// 4) Install renew cron
	return fmt.Sprintf(`set +e
BIN=/usr/local/bin/aero-edge
[ -x /opt/aero/aero-edge ] && cp -f /opt/aero/aero-edge "$BIN" && chmod +x "$BIN"
if [ ! -x "$BIN" ]; then echo "ERROR no binary"; exit 1; fi
mkdir -p /etc/aero /var/lib/aero/certs /var/lib/aero/tls /var/log
DOMAIN=%q
IP=%q
TOKEN=""; ADMIN_KEY=""
[ -f /etc/aero/edge.conf ] && . /etc/aero/edge.conf 2>/dev/null
[ -z "$TOKEN" ] && [ -n "$AERO_TOKEN" ] && TOKEN="$AERO_TOKEN"
[ -z "$ADMIN_KEY" ] && [ -n "$AERO_ADMIN_KEY" ] && ADMIN_KEY="$AERO_ADMIN_KEY"
if [ -z "$TOKEN" ] && [ -f /etc/systemd/system/aero-edge.service ]; then
  TOKEN=$(grep -oE '\-token [^ ]+' /etc/systemd/system/aero-edge.service 2>/dev/null | awk '{print $2}')
fi
if [ -z "$ADMIN_KEY" ] && [ -f /etc/systemd/system/aero-edge.service ]; then
  ADMIN_KEY=$(grep -oE '\-admin-key [^ ]+' /etc/systemd/system/aero-edge.service 2>/dev/null | awk '{print $2}')
fi
[ -z "$TOKEN" ] && TOKEN="aero_$(openssl rand -hex 16 2>/dev/null || echo fallbacktoken)"
[ -z "$ADMIN_KEY" ] && ADMIN_KEY="$(openssl rand -hex 16 2>/dev/null || echo adminkey)"
# --- Auto-detect Best HTTPS Port (Preferred 443, fallback standard CF/IANA ports) ---
systemctl stop aero-edge 2>/dev/null || true
CANDIDATE_PORTS=(443 8443 2053 2083 2087 2096)
CHOSEN_PORT=""
for p in "${CANDIDATE_PORTS[@]}"; do
  in_use=0
  if command -v python3 >/dev/null 2>&1; then
    python3 -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.bind(('0.0.0.0', $p)); s.close()" 2>/dev/null || in_use=1
  elif command -v ss >/dev/null 2>&1; then
    ss -tlpn 2>/dev/null | grep -qE ":$p\b" && in_use=1
  elif command -v fuser >/dev/null 2>&1; then
    fuser "$p/tcp" >/dev/null 2>&1 && in_use=1
  fi
  if [ "$in_use" -eq 0 ]; then
    CHOSEN_PORT="$p"
    break
  fi
done
[ -z "$CHOSEN_PORT" ] && CHOSEN_PORT=443
echo "CHOSEN_PORT=$CHOSEN_PORT"

# Open firewall for CHOSEN_PORT & 80
command -v ufw >/dev/null 2>&1 && ufw allow ${CHOSEN_PORT}/tcp 2>/dev/null || true
command -v ufw >/dev/null 2>&1 && ufw allow 80/tcp 2>/dev/null || true
command -v iptables >/dev/null 2>&1 && iptables -I INPUT -p tcp --dport ${CHOSEN_PORT} -j ACCEPT 2>/dev/null || true
command -v iptables >/dev/null 2>&1 && iptables -I INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || true

cat > /etc/aero/edge.conf << EOF
AERO_TOKEN=$TOKEN
AERO_ADMIN_KEY=$ADMIN_KEY
AERO_DOMAIN=$DOMAIN
AERO_PORTS=$CHOSEN_PORT
AERO_ADVERTISE=${DOMAIN:-$IP}
EOF
chmod 600 /etc/aero/edge.conf

# --- TLS cert: detect → issue → never self-signed ---
CERT=/var/lib/aero/tls/fullchain.pem
KEY=/var/lib/aero/tls/privkey.pem
[ -f "$CERT" ] && cp -f "$CERT" "$CERT.bak" 2>/dev/null || true
[ -f "$KEY" ] && cp -f "$KEY" "$KEY.bak" 2>/dev/null || true
need_issue=1
if [ -f "$CERT" ] && [ -f "$KEY" ]; then
  if openssl x509 -in "$CERT" -noout -checkend 86400 >/dev/null 2>&1; then
    echo "CERT_STATUS=existing_ok"
    need_issue=0
  else
    echo "CERT_STATUS=existing_expiring"
  fi
fi
# copy from acme.sh / certbot if present
if [ "$need_issue" = "1" ]; then
  if [ -n "$DOMAIN" ]; then
    for d in "/root/.acme.sh/${DOMAIN}_ecc" "/root/.acme.sh/${DOMAIN}" "/etc/letsencrypt/live/${DOMAIN}"; do
      if [ -f "$d/fullchain.cer" ] || [ -f "$d/fullchain.pem" ]; then
        FC="$d/fullchain.cer"; [ -f "$d/fullchain.pem" ] && FC="$d/fullchain.pem"
        KY=$(ls "$d"/*.key 2>/dev/null | head -1)
        [ -f "$d/privkey.pem" ] && KY="$d/privkey.pem"
        if [ -f "$FC" ] && [ -n "$KY" ] && [ -f "$KY" ]; then
          cp -f "$FC" "$CERT"; cp -f "$KY" "$KEY"
          chmod 644 "$CERT"; chmod 600 "$KEY"
          echo "CERT_STATUS=copied_from $d"
          need_issue=0
          break
        fi
      fi
    done
  fi
  if [ "$need_issue" = "1" ]; then
    for d in /root/.acme.sh/*_ecc /root/.acme.sh/* /etc/letsencrypt/live/*; do
      if [ -d "$d" ] && ([ -f "$d/fullchain.cer" ] || [ -f "$d/fullchain.pem" ]); then
        FC="$d/fullchain.cer"; [ -f "$d/fullchain.pem" ] && FC="$d/fullchain.pem"
        KY=$(ls "$d"/*.key 2>/dev/null | head -1)
        [ -f "$d/privkey.pem" ] && KY="$d/privkey.pem"
        if [ -f "$FC" ] && [ -n "$KY" ] && [ -f "$KY" ]; then
          cp -f "$FC" "$CERT"; cp -f "$KY" "$KEY"
          chmod 644 "$CERT"; chmod 600 "$KEY"
          echo "CERT_STATUS=auto_copied_existing $d"
          need_issue=0
          break
        fi
      fi
    done
  fi
fi
if [ "$need_issue" = "1" ] && [ -n "$DOMAIN" ]; then
  echo "CERT_STATUS=issuing"
  # free :80 for HTTP-01 if aero-edge holds it
  systemctl stop aero-edge 2>/dev/null
  if [ ! -f /root/.acme.sh/acme.sh ]; then
    curl -fsSL https://get.acme.sh | sh -s email="$EMAIL" 2>/dev/null || true
  fi
  export HOME=/root
  ACME=/root/.acme.sh/acme.sh
  if [ -x "$ACME" ]; then
    # Primary: Let's Encrypt
    $ACME --set-default-ca --server letsencrypt >/dev/null 2>&1
    $ACME --issue -d "$DOMAIN" --standalone --keylength ec-256 --force 2>&1 | tail -20
    if [ ! -f "/root/.acme.sh/${DOMAIN}_ecc/fullchain.cer" ] && [ ! -f "/root/.acme.sh/${DOMAIN}/fullchain.cer" ]; then
      echo "CERT_STATUS=le_failed_try_zerossl"
      # Backup CA: ZeroSSL (acme.sh built-in)
      $ACME --set-default-ca --server zerossl >/dev/null 2>&1
      $ACME --register-account -m "$EMAIL" >/dev/null 2>&1
      $ACME --issue -d "$DOMAIN" --standalone --keylength ec-256 --force 2>&1 | tail -20
    fi
    for d in "/root/.acme.sh/${DOMAIN}_ecc" "/root/.acme.sh/${DOMAIN}"; do
      if [ -f "$d/fullchain.cer" ]; then
        cp -f "$d/fullchain.cer" "$CERT"
        cp -f "$(ls "$d"/*.key | head -1)" "$KEY"
        chmod 644 "$CERT"; chmod 600 "$KEY"
        echo "CERT_STATUS=issued_ok from $d"
        # renew install hook → keep /var/lib/aero/tls updated
        $ACME --install-cert -d "$DOMAIN" --ecc \
          --fullchain-file "$CERT" --key-file "$KEY" \
          --reloadcmd "systemctl reload aero-edge 2>/dev/null || systemctl restart aero-edge" 2>/dev/null \
          || $ACME --install-cert -d "$DOMAIN" \
          --fullchain-file "$CERT" --key-file "$KEY" \
          --reloadcmd "systemctl restart aero-edge" 2>/dev/null || true
        need_issue=0
        break
      fi
    done
  else
    echo "CERT_STATUS=acme_sh_missing"
  fi
fi
if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
  if [ -f "$CERT.bak" ] && [ -f "$KEY.bak" ]; then
    echo "WARN: new cert failed, restoring existing cert from backup"
    cp -f "$CERT.bak" "$CERT" 2>/dev/null || true
    cp -f "$KEY.bak" "$KEY" 2>/dev/null || true
  else
    echo "CERT_STATUS=FAILED_no_public_cert"
    echo "ERROR: refuse self-signed; fix domain:80 ACME or place PEMs in /var/lib/aero/tls/"
  fi
fi
if [ -f "$CERT" ]; then
  openssl x509 -in "$CERT" -noout -issuer -subject -dates 2>/dev/null | sed 's/^/CERT_INFO /'
fi
# cron renew (acme.sh installs its own cron; ensure exists)
crontab -l 2>/dev/null | grep -q acme.sh || (crontab -l 2>/dev/null; echo "0 3 * * * /root/.acme.sh/acme.sh --cron --home /root/.acme.sh > /dev/null") | crontab - 2>/dev/null || true

# systemd: ONLY static cert when present — never -autocert (avoids Go self-signed fallback)
if [ -n "$DOMAIN" ] && [ -f "$CERT" ] && [ -f "$KEY" ]; then
cat > /etc/systemd/system/aero-edge.service << EOF
[Unit]
Description=AERO Edge Server
After=network.target
[Service]
Type=simple
Restart=always
RestartSec=5
WorkingDirectory=/var/lib/aero
EnvironmentFile=-/etc/aero/edge.conf
ExecStart=/usr/local/bin/aero-edge -token ${TOKEN} -listen :${CHOSEN_PORT} -ports ${CHOSEN_PORT} -profile small -data-dir /var/lib/aero -admin-key ${ADMIN_KEY} -domain ${DOMAIN} -sni ${DOMAIN} -advertise-host ${DOMAIN} -cert /var/lib/aero/tls/fullchain.pem -key /var/lib/aero/tls/privkey.pem -log-file /var/log/aero-edge.log -q
ExecReload=/bin/kill -HUP \$MAINPID
LimitNOFILE=65535
[Install]
WantedBy=multi-user.target
EOF
elif [ -n "$DOMAIN" ]; then
  echo "WARN unit written without cert files — service may fail until PEMs exist"
cat > /etc/systemd/system/aero-edge.service << EOF
[Unit]
Description=AERO Edge Server
After=network.target
[Service]
Type=simple
Restart=always
RestartSec=5
WorkingDirectory=/var/lib/aero
EnvironmentFile=-/etc/aero/edge.conf
ExecStart=/usr/local/bin/aero-edge -token ${TOKEN} -listen :${CHOSEN_PORT} -ports ${CHOSEN_PORT} -profile small -data-dir /var/lib/aero -admin-key ${ADMIN_KEY} -domain ${DOMAIN} -sni ${DOMAIN} -advertise-host ${DOMAIN} -cert /var/lib/aero/tls/fullchain.pem -key /var/lib/aero/tls/privkey.pem -log-file /var/log/aero-edge.log -q
ExecReload=/bin/kill -HUP \$MAINPID
LimitNOFILE=65535
[Install]
WantedBy=multi-user.target
EOF
else
CERT_ARGS=""
if [ -f "$CERT" ] && [ -f "$KEY" ]; then
  CERT_ARGS="-cert /var/lib/aero/tls/fullchain.pem -key /var/lib/aero/tls/privkey.pem"
fi
cat > /etc/systemd/system/aero-edge.service << EOF
[Unit]
Description=AERO Edge Server
After=network.target
[Service]
Type=simple
Restart=always
RestartSec=5
WorkingDirectory=/var/lib/aero
EnvironmentFile=-/etc/aero/edge.conf
ExecStart=/usr/local/bin/aero-edge -token ${TOKEN} -listen :${CHOSEN_PORT} -ports ${CHOSEN_PORT} -profile small -data-dir /var/lib/aero -admin-key ${ADMIN_KEY} -advertise-host ${IP} ${CERT_ARGS} -log-file /var/log/aero-edge.log -q
ExecReload=/bin/kill -HUP \$MAINPID
LimitNOFILE=65535
[Install]
WantedBy=multi-user.target
EOF
fi
systemctl daemon-reload
systemctl enable aero-edge
systemctl restart aero-edge
for i in 1 2 3 4 5 6 7 8 9 10; do
  sleep 1
  ST=$(systemctl is-active aero-edge 2>/dev/null || echo failed)
  [ "$ST" = "active" ] && break
done
echo "SERVICE_STATUS=$ST"
[ "$ST" = "active" ] && echo "SERVICE_ACTIVE=yes" || echo "SERVICE_ACTIVE=no"
systemctl status aero-edge --no-pager 2>/dev/null | head -15
ss -lntp 2>/dev/null | grep -E ":${CHOSEN_PORT}\\b" || echo "WARN ${CHOSEN_PORT}"
echo | timeout 4 openssl s_client -connect 127.0.0.1:${CHOSEN_PORT} -servername "${DOMAIN:-localhost}" 2>/dev/null | openssl x509 -noout -issuer -subject 2>/dev/null | sed 's/^/TLS /'
`, domain, ip)
}

func empty(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}
func trim(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// resolveLocalEdgeBin finds a locally built edge binary for SCP install
// (fixes TLS/autocert without waiting for GitHub release).
func resolveLocalEdgeBin() string {
	if p := strings.TrimSpace(os.Getenv("AERO_LOCAL_BIN")); p != "" {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			abs, _ := filepath.Abs(p)
			return abs
		}
	}
	var roots []string
	if wd, err := os.Getwd(); err == nil {
		roots = append(roots, wd, filepath.Join(wd, ".."), filepath.Join(wd, "..", ".."))
	}
	cands := []string{
		// AIsys layout: protocol/server/vps · protocol/dist · protocol/server/dist
		filepath.Join("protocol", "server", "vps", "aero-edge-linux-amd64"),
		filepath.Join("..", "protocol", "server", "vps", "aero-edge-linux-amd64"),
		filepath.Join("..", "..", "protocol", "server", "vps", "aero-edge-linux-amd64"),
		filepath.Join("protocol", "dist", "aero-edge-linux-amd64-fix"),
		filepath.Join("protocol", "dist", "aero-edge-linux-amd64"),
		filepath.Join("protocol", "server", "dist", "aero-edge-linux-amd64"),
		filepath.Join("..", "protocol", "dist", "aero-edge-linux-amd64-fix"),
		filepath.Join("..", "protocol", "dist", "aero-edge-linux-amd64"),
		filepath.Join("..", "protocol", "server", "dist", "aero-edge-linux-amd64"),
		// legacy monorepo
		filepath.Join("aero", "dist", "aero-edge-linux-amd64-fix"),
		filepath.Join("aero", "dist", "aero-edge-linux-amd64"),
		filepath.Join("aero", "server", "dist", "aero-edge-linux-amd64"),
		filepath.Join("dist", "aero-edge-linux-amd64-fix"),
	}
	for _, root := range roots {
		for _, rel := range cands {
			fp := filepath.Join(root, rel)
			if st, err := os.Stat(fp); err == nil && !st.IsDir() && st.Size() > 1_000_000 {
				abs, _ := filepath.Abs(fp)
				return abs
			}
		}
	}
	return ""
}
