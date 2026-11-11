package client

import (
	"net/netip"
)

// tunPool 是 edge 为 CONNECT-IP 会话分配地址的池（edge 侧 NewIPPool 默认值），网关为 .1。
// edge 按 token 哈希在整个池内分配 /32，客户端不得假设固定地址或 /24。
var tunPool = netip.MustParsePrefix("10.88.0.0/16")

// isAeroTunAddr 判断 ip 是否属于隧道地址池（用于识别本程序自己的虚拟网卡）。
func isAeroTunAddr(ip string) bool {
	a, err := netip.ParseAddr(ip)
	return err == nil && tunPool.Contains(a)
}
