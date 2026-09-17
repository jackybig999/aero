package service

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/aero/iface"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/sshprobe"
)

// DiagnoseReport is an Xray-style ops snapshot for one edge VPS (all via SSH).
type DiagnoseReport struct {
	OK        bool           `json:"ok"`
	Via       string         `json:"via"` // ssh
	CheckedAt time.Time      `json:"checked_at"`
	VPSID     uint64         `json:"vps_id"`
	Name      string         `json:"name,omitempty"`
	IP        string         `json:"ip,omitempty"`
	Domain    string         `json:"domain,omitempty"`
	Service   ServiceCheck   `json:"service"`
	Binary    BinaryCheck    `json:"binary"`
	Ports     []PortCheck    `json:"ports"`
	Cert      CertCheck      `json:"cert"`
	Admin     AdminCheck     `json:"admin"`
	Sub       SubCheck       `json:"subscription"`
	Nodes     []NodeKind     `json:"nodes"` // protocol endpoints / roles
	Metrics   map[string]any `json:"metrics,omitempty"`
	LogTail   string         `json:"log_tail,omitempty"`
	Hints     []string       `json:"hints,omitempty"`
	RawKV     map[string]string `json:"-"`
}

type ServiceCheck struct {
	Unit     string `json:"unit"`
	Active   bool   `json:"active"`
	Status   string `json:"status"`
	Enabled  bool   `json:"enabled"`
	MainPID  string `json:"main_pid,omitempty"`
	Restarts string `json:"restarts,omitempty"`
}

type BinaryCheck struct {
	Installed bool   `json:"installed"`
	Path      string `json:"path,omitempty"`
	Version   string `json:"version,omitempty"`
}

type PortCheck struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"` // tcp
	Listen  bool   `json:"listen"`
	Process string `json:"process,omitempty"`
	Role    string `json:"role"` // edge-tls | unknown
}

type CertCheck struct {
	Mode       string `json:"mode"` // autocert | static | self-signed | none | unknown
	Domain     string `json:"domain,omitempty"`
	HasFiles   bool   `json:"has_files"`
	Dir        string `json:"dir,omitempty"`
	FileCount  int    `json:"file_count"`
	NotAfter   string `json:"not_after,omitempty"`
	DaysLeft   int    `json:"days_left,omitempty"`
	OK         bool   `json:"ok"`
	Detail     string `json:"detail,omitempty"`
	CanRenew   bool   `json:"can_renew"`
}

type AdminCheck struct {
	Reachable bool           `json:"reachable"`
	Via       string         `json:"via,omitempty"` // loopback-python | loopback-curl | https-public
	Error     string         `json:"error,omitempty"`
	Status    map[string]any `json:"status,omitempty"`
}

type SubCheck struct {
	Secret      string `json:"secret_set"` // yes/no (never full secret in detail if long - we mask)
	URL         string `json:"url,omitempty"`
	LocalOK     bool   `json:"local_ok"`     // fetch from VPS loopback
	LocalHTTP   int    `json:"local_http,omitempty"`
	LocalBytes  int    `json:"local_bytes,omitempty"`
	LocalError  string `json:"local_error,omitempty"`
	PublicOK    bool   `json:"public_ok"` // fetch from mid host
	PublicHTTP  int    `json:"public_http,omitempty"`
	PublicError string `json:"public_error,omitempty"`
	Preview     string `json:"preview,omitempty"` // first 120 chars of body
}

type NodeKind struct {
	Kind    string `json:"kind"`    // aero-h2 | subscription | admin | ssh-mgmt
	Name    string `json:"name"`
	Target  string `json:"target"`
	Online  bool   `json:"online"`
	Latency int64  `json:"latency_ms,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// Diagnose runs a full SSH ops probe (does not depend on public HTTPS Admin).
func (s *Service) Diagnose(vpsID uint64) (*DiagnoseReport, error) {
	cred, err := s.vps.Credentials(vpsID)
	if err != nil {
		return nil, err
	}
	c, err := sshprobe.Dial(sshprobe.Credentials{
		Host: cred.IP, Port: cred.SSHPort, User: cred.SSHUsername, Password: cred.SSHPassword,
	}, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("ssh: %w", err)
	}
	defer c.Close()

	out, err := sshprobe.Run(c, diagnoseScript, 35*time.Second)
	if err != nil && strings.TrimSpace(out) == "" {
		return nil, fmt.Errorf("diagnose ssh: %w", err)
	}
	kv := parseKV(out)
	// refresh endpoint store from harvest fields
	if kv["SUB_SECRET"] != "" || kv["ADMIN_KEY"] != "" {
		ep := parseHarvest(out, cred)
		ep.Installed = kv["SERVICE_ACTIVE"] == "yes" || ep.SubSecret != ""
		s.endpoint.Upsert(ep)
	}

	rep := buildReport(cred, kv, out)
	// optional public sub probe from mid (best-effort, short timeout)
	if rep.Sub.URL != "" {
		ok, code, perr, n := probeHTTP(rep.Sub.URL, 6*time.Second)
		rep.Sub.PublicOK = ok
		rep.Sub.PublicHTTP = code
		rep.Sub.PublicError = perr
		if n > 0 && rep.Sub.LocalBytes == 0 {
			rep.Sub.LocalBytes = n
		}
	}
	// try merge admin metrics if loopback admin worked
	if rep.Admin.Reachable && rep.Admin.Status != nil {
		rep.Metrics = rep.Admin.Status
		if v, ok := rep.Admin.Status["version"].(string); ok && rep.Binary.Version == "" {
			rep.Binary.Version = v
		}
	}
	rep.Hints = buildHints(rep)
	return rep, nil
}

// RenewCert clears ACME cache (optional) and restarts edge so autocert re-issues.
func (s *Service) RenewCert(vpsID uint64, forceClear bool) (map[string]any, error) {
	cred, err := s.vps.Credentials(vpsID)
	if err != nil {
		return nil, err
	}
	c, err := sshprobe.Dial(sshprobe.Credentials{
		Host: cred.IP, Port: cred.SSHPort, User: cred.SSHUsername, Password: cred.SSHPassword,
	}, 12*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	script := `set +e
systemctl is-active aero-edge
`
	if forceClear {
		script += `rm -rf /var/lib/aero/certs/* /var/lib/aero/tls/* 2>/dev/null; echo "CLEARED=yes"
`
	} else {
		script += `echo "CLEARED=no"
`
	}
	script += `systemctl restart aero-edge
sleep 3
systemctl is-active aero-edge | sed 's/^/SERVICE=/'
ls -la /var/lib/aero/tls /var/lib/aero/certs 2>/dev/null | head -20
journalctl -u aero-edge -n 25 --no-pager 2>/dev/null | tail -20
`
	out, err := sshprobe.Run(c, script, 40*time.Second)
	if err != nil {
		return map[string]any{"ok": false, "log": out, "error": err.Error()}, err
	}
	// re-diagnose cert
	rep, _ := s.Diagnose(vpsID)
	return map[string]any{
		"ok":      strings.Contains(out, "SERVICE=active"),
		"log":     trim(out, 2500),
		"cert":    rep.Cert,
		"service": rep.Service,
	}, nil
}

// RestartEdge restarts aero-edge.service via SSH.
func (s *Service) RestartEdge(vpsID uint64) (map[string]any, error) {
	cred, err := s.vps.Credentials(vpsID)
	if err != nil {
		return nil, err
	}
	c, err := sshprobe.Dial(sshprobe.Credentials{
		Host: cred.IP, Port: cred.SSHPort, User: cred.SSHUsername, Password: cred.SSHPassword,
	}, 12*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	out, err := sshprobe.Run(c, `systemctl restart aero-edge; sleep 2; systemctl is-active aero-edge; journalctl -u aero-edge -n 15 --no-pager`, 30*time.Second)
	ok := strings.Contains(out, "active") && !strings.Contains(out, "inactive")
	return map[string]any{"ok": ok || err == nil, "log": trim(out, 2000)}, err
}

func buildReport(cred *iface.Cred, kv map[string]string, raw string) *DiagnoseReport {
	rep := &DiagnoseReport{
		Via:       "ssh",
		CheckedAt: time.Now(),
		VPSID:     cred.VPSID,
		Name:      cred.Name,
		IP:        cred.IP,
		Domain:    empty(kv["DOMAIN"], cred.Domain),
		RawKV:     kv,
	}
	rep.Service = ServiceCheck{
		Unit:     "aero-edge",
		Active:   kv["SERVICE_ACTIVE"] == "yes" || kv["SERVICE"] == "active",
		Status:   empty(kv["SERVICE"], kv["SERVICE_ACTIVE"]),
		Enabled:  kv["SERVICE_ENABLED"] == "enabled" || kv["SERVICE_ENABLED"] == "yes",
		MainPID:  kv["MAIN_PID"],
		Restarts: kv["N_RESTARTS"],
	}
	rep.Binary = BinaryCheck{
		Installed: kv["INSTALLED"] == "yes",
		Path:      kv["BINARY_PATH"],
		Version:   kv["VERSION"],
	}
	// ports
	for _, p := range []int{443, 80, 8443, 2053, 2083, 2087, 2096} {
		key := fmt.Sprintf("PORT_%d", p)
		listen := kv[key] == "yes"
		role := "unknown"
		if p == 443 || p == 8443 || p == 2053 || p == 2083 || p == 2087 || p == 2096 {
			role = "edge-tls"
		}
		if p == 80 {
			role = "http-acme"
		}
		rep.Ports = append(rep.Ports, PortCheck{
			Port: p, Proto: "tcp", Listen: listen, Process: kv[key+"_PROC"], Role: role,
		})
	}
	// cert
	days, _ := strconv.Atoi(kv["CERT_DAYS"])
	fc, _ := strconv.Atoi(kv["CERT_FILES"])
	certOK := kv["CERT_OK"] == "yes"
	certDetail := kv["CERT_DETAIL"]
	notAfter := kv["CERT_NOT_AFTER"]

	// Fallback to Edge runtime metrics if available
	if !certOK && rep.Metrics != nil {
		if d, ok := rep.Metrics["cert_days_left"].(float64); ok && d > 0 {
			days = int(d)
			certOK = true
			if na, ok := rep.Metrics["cert_not_after"].(string); ok && na != "" {
				notAfter = na
			}
			certDetail = fmt.Sprintf("valid %dd (Let's Encrypt / public)", days)
			if fc == 0 {
				fc = 2
			}
		}
	}

	rep.Cert = CertCheck{
		Mode:      empty(kv["CERT_MODE"], "static"),
		Domain:    empty(kv["CERT_DOMAIN"], rep.Domain),
		HasFiles:  certOK || kv["CERT_HAS"] == "yes" || fc > 0,
		Dir:       empty(kv["CERT_DIR"], "/var/lib/aero/tls"),
		FileCount: fc,
		NotAfter:  notAfter,
		DaysLeft:  days,
		OK:        certOK,
		Detail:    certDetail,
		CanRenew:  rep.Domain != "" || kv["CERT_MODE"] == "autocert",
	}
	// admin
	rep.Admin = AdminCheck{
		Reachable: kv["ADMIN_OK"] == "yes",
		Via:       kv["ADMIN_VIA"],
		Error:     kv["ADMIN_ERR"],
	}
	if body := kv["ADMIN_JSON"]; body != "" {
		var m map[string]any
		if json.Unmarshal([]byte(body), &m) == nil {
			rep.Admin.Status = m
		}
	}
	// sub
	secSet := "no"
	if kv["SUB_SECRET"] != "" {
		secSet = "yes"
	}
	subURL := kv["SUB_URL"]
	if subURL == "" && kv["SUB_SECRET"] != "" {
		host := empty(kv["ADVERTISE"], empty(rep.Domain, cred.IP))
		host = strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
		host = strings.Split(host, "/")[0]
		subURL = "https://" + host + "/sub/" + kv["SUB_SECRET"]
	}
	lb, _ := strconv.Atoi(kv["SUB_LOCAL_BYTES"])
	lh, _ := strconv.Atoi(kv["SUB_LOCAL_HTTP"])
	rep.Sub = SubCheck{
		Secret:     secSet,
		URL:        subURL,
		LocalOK:    kv["SUB_LOCAL_OK"] == "yes",
		LocalHTTP:  lh,
		LocalBytes: lb,
		LocalError: kv["SUB_LOCAL_ERR"],
		Preview:    trim(kv["SUB_PREVIEW"], 160),
	}
	port := 443
	if p, err := strconv.Atoi(kv["PORT"]); err == nil && p > 0 {
		port = p
	}
	// nodes (kinds)
	edgeOnline := rep.Service.Active && portListen(rep.Ports, port)
	rep.Nodes = []NodeKind{
		{
			Kind: "aero-h2", Name: "AERO H2 CONNECT",
			Target: fmt.Sprintf("https://%s:%d", empty(rep.Domain, cred.IP), port),
			Online: edgeOnline,
			Detail: serviceDetail(rep),
		},
		{
			Kind: "subscription", Name: "订阅 /sub",
			Target: rep.Sub.URL,
			Online: rep.Sub.LocalOK || rep.Sub.PublicOK,
			Detail: subDetail(rep.Sub),
		},
		{
			Kind: "admin", Name: "Admin API",
			Target: "loopback /admin/*",
			Online: rep.Admin.Reachable,
			Detail: empty(rep.Admin.Error, rep.Admin.Via),
		},
		{
			Kind: "ssh-mgmt", Name: "中台 SSH 运维通道",
			Target: cred.IP + ":22",
			Online: true, // we got here
			Detail: "probe ok",
		},
	}
	// overall ok
	rep.OK = rep.Service.Active && edgeOnline && (rep.Sub.LocalOK || rep.Sub.Secret == "yes")
	rep.LogTail = trim(kv["LOG_TAIL"], 2000)
	rep.Hints = buildHints(rep)
	return rep
}

func serviceDetail(r *DiagnoseReport) string {
	if r.Service.Active {
		return "systemd active · " + r.Binary.Version
	}
	return "service " + empty(r.Service.Status, "down")
}

func subDetail(s SubCheck) string {
	parts := []string{}
	if s.Secret == "yes" {
		parts = append(parts, "secret ok")
	} else {
		parts = append(parts, "no secret")
	}
	if s.LocalOK {
		parts = append(parts, fmt.Sprintf("local HTTP %d %dB", s.LocalHTTP, s.LocalBytes))
	} else if s.LocalError != "" {
		parts = append(parts, "local: "+s.LocalError)
	}
	if s.PublicOK {
		parts = append(parts, "public ok")
	} else if s.PublicError != "" {
		parts = append(parts, "public: "+trim(s.PublicError, 80))
	}
	return strings.Join(parts, " · ")
}

func portListen(ports []PortCheck, p int) bool {
	for _, x := range ports {
		if x.Port == p && x.Listen {
			return true
		}
	}
	return false
}

func buildHints(r *DiagnoseReport) []string {
	var h []string
	if !r.Service.Active {
		h = append(h, "aero-edge 未 active：点「重启 Edge」或重新安装")
	}
	edgePortListening := false
	for _, p := range r.Ports {
		if p.Role == "edge-tls" && p.Listen {
			edgePortListening = true
			break
		}
	}
	if !edgePortListening {
		h = append(h, "Edge 业务端口未监听：检查防火墙 / 进程是否崩溃（看日志）")
	}
	if !r.Cert.OK && r.Domain != "" {
		h = append(h, "证书异常或未签发：确认域名 A 记录指向本机 IP 后点「安装/续签证书」")
	}
	if r.Domain == "" {
		h = append(h, "未配置域名：当前为 IP/自签模式，客户端需允许不安全证书或补域名")
	}
	if r.Sub.Secret != "yes" {
		h = append(h, "无订阅 secret：重新安装或检查 /var/lib/aero/sub_meta.json")
	} else if !r.Sub.LocalOK {
		h = append(h, "本机拉订阅失败：Edge 可能未就绪或证书导致 TLS 握手失败")
	}
	if r.Sub.LocalOK && !r.Sub.PublicOK {
		h = append(h, "VPS 本机订阅 OK，但中台公网拉订阅失败：DNS/防火墙/TLS 问题；客户端在可达网络仍可能可用")
	}
	if !r.Admin.Reachable {
		h = append(h, "Admin loopback 不可达：Token 在线管理受限，但不影响已有 token 客户端隧道")
	}
	if len(h) == 0 {
		h = append(h, "核心路径正常：可把订阅 URL 给客户端测试连接")
	}
	return h
}

func parseKV(out string) map[string]string {
	kv := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		i := strings.Index(line, "=")
		if i <= 0 {
			continue
		}
		k, v := line[:i], line[i+1:]
		// multi-line values: last wins for simple keys; LOG_TAIL accumulates
		if k == "LOG_TAIL" || k == "ADMIN_JSON" || k == "SUB_PREVIEW" {
			if prev, ok := kv[k]; ok && prev != "" {
				kv[k] = prev + "\n" + v
			} else {
				kv[k] = v
			}
		} else {
			kv[k] = v
		}
	}
	return kv
}

// diagnoseScript emits KEY=value lines; self-contained, prefers python3 for HTTPS loopback.
const diagnoseScript = `set +e
echo "DOMAIN="; [ -f /etc/aero/edge.conf ] && . /etc/aero/edge.conf 2>/dev/null
echo "DOMAIN=${AERO_DOMAIN:-}"
echo "ADVERTISE=${AERO_ADVERTISE:-${AERO_DOMAIN:-}}"
echo "ADMIN_KEY=${AERO_ADMIN_KEY:-$ADMIN_KEY}"
echo "AERO_TOKEN=${AERO_TOKEN:-$TOKEN}"

# service
ST=$(systemctl is-active aero-edge 2>/dev/null || echo inactive)
echo "SERVICE=$ST"
[ "$ST" = "active" ] && echo "SERVICE_ACTIVE=yes" || echo "SERVICE_ACTIVE=no"
EN=$(systemctl is-enabled aero-edge 2>/dev/null || echo no)
echo "SERVICE_ENABLED=$EN"
echo "MAIN_PID=$(systemctl show -p MainPID --value aero-edge 2>/dev/null)"
echo "N_RESTARTS=$(systemctl show -p NRestarts --value aero-edge 2>/dev/null)"

# binary
BIN=""
for p in /opt/aero/aero-edge /usr/local/bin/aero-edge; do [ -x "$p" ] && BIN="$p" && break; done
if [ -n "$BIN" ]; then echo "INSTALLED=yes"; echo "BINARY_PATH=$BIN"; else echo "INSTALLED=no"; echo "BINARY_PATH="; fi
[ -f /opt/aero/VERSION ] && echo "VERSION=$(tr -d '\r\n' </opt/aero/VERSION)" || echo "VERSION="

# ports
for P in 443 80 8443 2053 2083 2087 2096; do
  if ss -lntp 2>/dev/null | grep -qE ":$P\\b"; then
    echo "PORT_${P}=yes"
    PROC=$(ss -lntp 2>/dev/null | grep -E ":$P\\b" | head -1 | sed 's/.*users:((//' | cut -c1-80)
    echo "PORT_${P}_PROC=$PROC"
  else
    echo "PORT_${P}=no"
    echo "PORT_${P}_PROC="
  fi
done

# certs
CERT_DIR=/var/lib/aero/tls
if [ ! -d "$CERT_DIR" ] || [ $(ls -A "$CERT_DIR" 2>/dev/null | wc -l) -eq 0 ]; then
  [ -d /var/lib/aero/certs ] && CERT_DIR=/var/lib/aero/certs
fi
echo "CERT_DIR=$CERT_DIR"
if [ -d "$CERT_DIR" ]; then
  FC=$(find "$CERT_DIR" -type f 2>/dev/null | wc -l | tr -d ' ')
  echo "CERT_FILES=$FC"
  [ "$FC" -gt 0 ] && echo "CERT_HAS=yes" || echo "CERT_HAS=no"
else
  echo "CERT_FILES=0"; echo "CERT_HAS=no"
fi
if grep -q autocert /etc/systemd/system/aero-edge.service 2>/dev/null; then
  echo "CERT_MODE=autocert"
else
  echo "CERT_MODE=static"
fi
echo "CERT_DOMAIN=${AERO_DOMAIN:-}"
# try read leaf cert notAfter
CERT_PEM=$(find "$CERT_DIR" /var/lib/aero/tls -name 'fullchain.pem' -o -name '*.crt' -o -name 'certificate' -o -name '*leaf*' 2>/dev/null | head -1)
if [ -z "$CERT_PEM" ]; then CERT_PEM=$(find "$CERT_DIR" -type f 2>/dev/null | head -1); fi
if [ -n "$CERT_PEM" ] && command -v openssl >/dev/null; then
  NA=$(openssl x509 -in "$CERT_PEM" -noout -enddate 2>/dev/null | cut -d= -f2)
  echo "CERT_NOT_AFTER=$NA"
  if [ -n "$NA" ]; then
    # days left approx
    END=$(date -d "$NA" +%s 2>/dev/null || echo 0)
    NOW=$(date +%s)
    if [ "$END" -gt 0 ]; then
      DAYS=$(( (END - NOW) / 86400 ))
      echo "CERT_DAYS=$DAYS"
      if [ "$DAYS" -gt 7 ]; then echo "CERT_OK=yes"; echo "CERT_DETAIL=valid ${DAYS}d"; else echo "CERT_OK=no"; echo "CERT_DETAIL=expiring/expired ${DAYS}d"; fi
    else
      echo "CERT_DAYS="; echo "CERT_OK=yes"; echo "CERT_DETAIL=has cert files"
    fi
  else
    # autocert may store binary cache not PEM
    [ "${FC:-0}" -gt 0 ] && echo "CERT_OK=yes" && echo "CERT_DETAIL=acme cache present" || { echo "CERT_OK=no"; echo "CERT_DETAIL=no readable cert"; }
  fi
else
  if [ "${FC:-0}" -gt 0 ]; then echo "CERT_OK=yes"; echo "CERT_DETAIL=cache files exist"; else echo "CERT_OK=no"; echo "CERT_DETAIL=no cert files yet"; fi
fi

# sub secret & port
PORT="${AERO_PORTS:-}"
if [ -z "$PORT" ] && [ -f /var/lib/aero/sub_meta.json ]; then
  PORT=$(python3 -c "import json;addr=json.load(open('/var/lib/aero/sub_meta.json'))['document']['servers'][0]['address'];print(addr.split(':')[-1])" 2>/dev/null)
fi
[ -z "$PORT" ] && PORT="443"
echo "PORT=$PORT"

if [ -f /var/lib/aero/sub_meta.json ]; then
  SEC=$(python3 -c "import json;print(json.load(open('/var/lib/aero/sub_meta.json')).get('secret',''))" 2>/dev/null)
  [ -z "$SEC" ] && SEC=$(grep -oE '"secret"[[:space:]]*:[[:space:]]*"[^"]+"' /var/lib/aero/sub_meta.json | head -1 | sed 's/.*"\([^"]*\)"/\1/')
  echo "SUB_SECRET=$SEC"
else
  echo "SUB_SECRET="
  SEC=""
fi
HOST=${AERO_ADVERTISE:-${AERO_DOMAIN:-}}
[ -z "$HOST" ] && HOST=$(hostname -I 2>/dev/null | awk '{print $1}')
if [ -n "$SEC" ] && [ -n "$HOST" ]; then
  if [ "$PORT" = "443" ]; then
    echo "SUB_URL=https://${HOST}/sub/${SEC}"
  else
    echo "SUB_URL=https://${HOST}:${PORT}/sub/${SEC}"
  fi
fi

# local admin + sub via python3 with correct SNI & port
export AERO_ADMIN_KEY_ENV="${AERO_ADMIN_KEY:-$ADMIN_KEY}"
export AERO_SUB_SEC_ENV="$SEC"
export AERO_SNI_ENV="${AERO_DOMAIN:-${AERO_ADVERTISE:-localhost}}"
export AERO_PORT_ENV="$PORT"
# strip scheme/path if any
export AERO_SNI_ENV=$(echo "$AERO_SNI_ENV" | sed -e 's#https\?://##' -e 's#/.*##' -e 's/:.*//')
python3 - <<'PY' 2>/tmp/aero_diag_py.err
import os, ssl, json, sys, socket, http.client

key = os.environ.get("AERO_ADMIN_KEY_ENV","")
sec = os.environ.get("AERO_SUB_SEC_ENV","")
sni = (os.environ.get("AERO_SNI_ENV") or "localhost").strip() or "localhost"
port = int(os.environ.get("AERO_PORT_ENV", "443"))

def fetch(path, headers=None, timeout=10):
    """TLS to 127.0.0.1:port with SNI=domain."""
    headers = headers or {}
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # prefer TLS1.2+; edge may be TLS1.3-only which is fine
        raw = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        ssock = ctx.wrap_socket(raw, server_hostname=sni)
        conn = http.client.HTTPSConnection("127.0.0.1", port, timeout=timeout, context=ctx)
        conn.sock = ssock
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        body = resp.read()
        code = resp.status
        conn.close()
        return code, body, ""
    except Exception as e:
        return 0, b"", str(e)

# admin
st, body, err = fetch("/admin/status", {"X-Aero-Admin-Key": key, "Host": sni})
if st and 200 <= st < 300 and body:
    print("ADMIN_OK=yes")
    print("ADMIN_VIA=loopback-sni-"+sni)
    try:
        j = json.loads(body.decode("utf-8","replace"))
        print("ADMIN_JSON=" + json.dumps(j, ensure_ascii=False, separators=(",",":")))
    except Exception:
        print("ADMIN_JSON=")
else:
    print("ADMIN_OK=no")
    print("ADMIN_VIA=")
    print("ADMIN_ERR=" + (err or ("http "+str(st)))[:200])
    print("ADMIN_JSON=")

# sub local
if sec:
    st2, body2, err2 = fetch("/sub/"+sec, {"Host": sni})
    if st2 and 200 <= st2 < 300 and body2:
        print("SUB_LOCAL_OK=yes")
        print("SUB_LOCAL_HTTP="+str(st2))
        print("SUB_LOCAL_BYTES="+str(len(body2)))
        prev = body2[:120].decode("utf-8","replace").replace("\n"," ")
        print("SUB_PREVIEW="+prev)
        print("SUB_LOCAL_ERR=")
    else:
        print("SUB_LOCAL_OK=no")
        print("SUB_LOCAL_HTTP="+str(st2 or 0))
        print("SUB_LOCAL_BYTES=0")
        print("SUB_LOCAL_ERR="+(err2 or ("http "+str(st2)))[:200])
        print("SUB_PREVIEW=")
else:
    print("SUB_LOCAL_OK=no")
    print("SUB_LOCAL_HTTP=0")
    print("SUB_LOCAL_BYTES=0")
    print("SUB_LOCAL_ERR=no secret")
    print("SUB_PREVIEW=")
PY
if [ -s /tmp/aero_diag_py.err ]; then echo "PY_ERR=$(head -c 200 /tmp/aero_diag_py.err | tr '\n' ' ')"; fi

# log tail single-line escaped
if [ -f /var/log/aero-edge.log ]; then
  echo "LOG_TAIL=$(tail -n 30 /var/log/aero-edge.log 2>/dev/null | tr '\n' '|' | cut -c1-1800)"
else
  echo "LOG_TAIL=$(journalctl -u aero-edge -n 20 --no-pager 2>/dev/null | tr '\n' '|' | cut -c1-1800)"
fi
`

// probeHTTP is mid-side best-effort GET (TLS skip verify).
func probeHTTP(rawURL string, timeout time.Duration) (ok bool, code int, errMsg string, n int) {
	// implemented in probe_http.go to keep imports clean — inline here via edgeclient style
	return probeHTTPImpl(rawURL, timeout)
}
