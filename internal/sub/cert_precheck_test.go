package sub

import (
	"strings"
	"testing"
)

func TestNodeDomainPattern(t *testing.T) {
	for d, want := range map[string]bool{
		"node.example.com": true, "x7k2.edge.example.org": true,
		"": false, "203.0.113.5": false, "localhost": false, "a.b'; rm -rf /;'.com": false, "exa mple.com": false,
	} {
		if got := nodeDomainPattern.MatchString(d); got != want {
			t.Errorf("%q: %v", d, got)
		}
	}
}

// 预检失败的提示：区分“未安装 ACME 客户端”与“已安装但没有证书”，并明确节点未被改动。
func TestCertMissingError(t *testing.T) {
	none := certMissingError("n.example.com", map[string]string{"ACME_SH": "no", "CERTBOT": "no", "CERT_SEARCHED": "/root/.acme.sh,/etc/letsencrypt/live"}).Error()
	if !strings.Contains(none, "未检测到 acme.sh 或 certbot") || !strings.Contains(none, "/root/.acme.sh、/etc/letsencrypt/live") || !strings.Contains(none, "未做任何改动") {
		t.Fatal(none)
	}
	cb := certMissingError("n.example.com", map[string]string{"ACME_SH": "no", "CERTBOT": "yes"}).Error()
	if !strings.Contains(cb, "已检测到 certbot") || !strings.Contains(cb, "n.example.com") {
		t.Fatal(cb)
	}
}
