// Package sshprobe collects host metrics over SSH.
package sshprobe

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/domain"
)

type Credentials struct {
	Host     string
	Port     int
	User     string
	Password string
}

func Dial(c Credentials, timeout time.Duration) (*ssh.Client, error) {
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
	client, err := ssh.Dial("tcp", net.JoinHostPort(c.Host, strconv.Itoa(c.Port)), cfg)
	if err != nil {
		return nil, classifySSHErr(err)
	}
	return client, nil
}

func classifySSHErr(err error) error {
	s := err.Error()
	switch {
	case strings.Contains(s, "unable to authenticate"),
		strings.Contains(s, "no supported methods remain"),
		strings.Contains(s, "permission denied"):
		return fmt.Errorf("SSH 认证失败：密码错误，或服务器禁用了 PasswordAuthentication / 仅允许密钥登录")
	case strings.Contains(s, "handshake failed"),
		strings.Contains(s, "EOF"),
		strings.Contains(s, "connection reset"):
		// common when wrong password causes server to drop, or MaxAuthTries / fail2ban
		return fmt.Errorf("SSH 握手中断(%s)。常见原因：①密码不对 ②被 fail2ban/临时封禁 ③仅允许密钥登录。请点「改密码」填入正确 root 密码后重试", shortErr(s))
	case strings.Contains(s, "connection refused"):
		return fmt.Errorf("SSH 连接被拒绝：检查端口/sshd 是否监听")
	case strings.Contains(s, "i/o timeout"), strings.Contains(s, "timed out"):
		return fmt.Errorf("SSH 超时：网络不通或防火墙未放行 22")
	default:
		return fmt.Errorf("SSH: %v", err)
	}
}

func shortErr(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 80 {
		return s[:80] + "…"
	}
	return s
}

func Run(client *ssh.Client, cmd string, timeout time.Duration) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	type result struct {
		out []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		out, err := sess.CombinedOutput(cmd)
		ch <- result{out, err}
	}()
	select {
	case r := <-ch:
		return string(r.out), r.err
	case <-time.After(timeout):
		return "", fmt.Errorf("command timeout after %s", timeout)
	}
}

// SCPPut uploads a local file to remote path using the scp protocol over SSH.
func SCPPut(client *ssh.Client, localPath, remotePath string, timeout time.Duration) error {
	f, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	w, err := sess.StdinPipe()
	if err != nil {
		return err
	}
	type result struct{ err error }
	ch := make(chan result, 1)
	go func() {
		// remote dir must exist; scp -t writes the file at remotePath
		ch <- result{sess.Run("scp -t " + remotePath)}
	}()
	// scp single-file header
	base := remotePath
	if i := strings.LastIndex(remotePath, "/"); i >= 0 {
		base = remotePath[i+1:]
	}
	if _, err := fmt.Fprintf(w, "C0755 %d %s\n", st.Size(), base); err != nil {
		_ = w.Close()
		return err
	}
	if _, err := io.Copy(w, f); err != nil {
		_ = w.Close()
		return err
	}
	if _, err := fmt.Fprint(w, "\x00"); err != nil {
		_ = w.Close()
		return err
	}
	_ = w.Close()
	select {
	case r := <-ch:
		return r.err
	case <-time.After(timeout):
		return fmt.Errorf("scp timeout after %s", timeout)
	}
}

func CollectMetrics(client *ssh.Client) (*domain.HostMetrics, error) {
	script := `set -e
OS=$(uname -s 2>/dev/null || echo unknown)
ARCH=$(uname -m 2>/dev/null || echo unknown)
LOAD=$(cat /proc/loadavg 2>/dev/null || echo "0 0 0")
UP=$(cut -d. -f1 /proc/uptime 2>/dev/null || echo 0)
read -r _ u1 n1 s1 i1 _ < /proc/stat
sleep 0.4
read -r _ u2 n2 s2 i2 _ < /proc/stat
tot1=$((u1+n1+s1+i1)); tot2=$((u2+n2+s2+i2))
dt=$((tot2-tot1)); di=$((i2-i1))
if [ "$dt" -gt 0 ]; then CPU=$(awk -v d=$dt -v i=$di 'BEGIN{printf "%.1f", (1-i/d)*100}'); else CPU=0; fi
read MT MU MF MA MS MH MB MC <<< $(free -b | awk '/^Mem:/{print $2,$3,$4,$6,$7}')
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
	out, err := Run(client, script, 12*time.Second)
	if err != nil {
		return nil, fmt.Errorf("metrics: %w (%s)", err, trim(out, 200))
	}
	m := parseKV(out)
	metrics := &domain.HostMetrics{
		OS: m["os"], Arch: m["arch"], CPUPercent: parseF(m["cpu"]),
		UptimeSec: int64(parseF(m["uptime"])), CollectedAt: time.Now(), Source: "ssh", ProbeOK: true,
	}
	parts := strings.Fields(m["load"])
	if len(parts) >= 3 {
		metrics.Load1, metrics.Load5, metrics.Load15 = parseF(parts[0]), parseF(parts[1]), parseF(parts[2])
	}
	mt, mu := parseF(m["mem_total"]), parseF(m["mem_used"])
	metrics.MemTotalMB, metrics.MemUsedMB = mt/1024/1024, mu/1024/1024
	if mt > 0 {
		metrics.MemPercent = mu / mt * 100
	}
	dt, du := parseF(m["disk_total"]), parseF(m["disk_used"])
	metrics.DiskTotalGB, metrics.DiskUsedGB = dt/1024/1024/1024, du/1024/1024/1024
	if dt > 0 {
		metrics.DiskPercent = du / dt * 100
	}
	return metrics, nil
}

func CollectNetDelta(client *ssh.Client) (rxMbps, txMbps float64, err error) {
	cmd := `awk -F'[: ]+' 'NR>2 && $1!="lo"{rx+=$3;tx+=$11} END{print rx+0,tx+0}' /proc/net/dev`
	a, err := Run(client, cmd, 5*time.Second)
	if err != nil {
		return 0, 0, err
	}
	time.Sleep(500 * time.Millisecond)
	b, err := Run(client, cmd, 5*time.Second)
	if err != nil {
		return 0, 0, err
	}
	r1, t1 := parsePair(a)
	r2, t2 := parsePair(b)
	rxMbps = (r2 - r1) * 8 / 0.5 / 1e6
	txMbps = (t2 - t1) * 8 / 0.5 / 1e6
	if rxMbps < 0 {
		rxMbps = 0
	}
	if txMbps < 0 {
		txMbps = 0
	}
	return rxMbps, txMbps, nil
}

func parsePair(s string) (float64, float64) {
	f := strings.Fields(strings.TrimSpace(s))
	if len(f) < 2 {
		return 0, 0
	}
	return parseF(f[0]), parseF(f[1])
}
func parseKV(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, "="); i > 0 {
			m[line[:i]] = line[i+1:]
		}
	}
	return m
}
func parseF(s string) float64 {
	f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return f
}
func trim(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
