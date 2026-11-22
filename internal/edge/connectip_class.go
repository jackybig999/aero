// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package edge

import (
	"net/http"
	"slices"
	"strings"

	connectip "github.com/quic-go/connect-ip-go"
)

// CONNECT-IP 场景会话（ADR-0017、api/dataplane.md §4.1）：同一条 QUIC 连接上，每个类别最多一条会话，
// 类别决定地址子网与 IP 包的承载方式。

const (
	classDefault = "default"
	classAI      = "ai"

	headerClass     = "Aero-Class"
	headerTransport = "Aero-Transport"

	// 两个子网都切自 10.88.0.0/16：NAT、TUN 地址与宿主还原逻辑（nat_linux.go）不需要改动（ADR-0012）。
	edgeDefaultPoolCIDR = "10.88.0.0/17"
	edgeAIPoolCIDR      = "10.88.128.0/17"

	transportDatagram = "datagram"
	transportCapsule  = "capsule"
)

// connectIPClass 描述一个已实现的类别。
type connectIPClass struct {
	name      string
	mode      connectip.DataMode
	transport string // 写入响应头 Aero-Transport
}

var connectIPClasses = map[string]connectIPClass{
	classDefault: {classDefault, connectip.DataModeDatagram, transportDatagram},
	classAI:      {classAI, connectip.DataModeCapsule, transportCapsule},
}

// supportedTransports 是本节点支持的传输方式，写入订阅的 transports 字段（C5）。
func supportedTransports() []string { return []string{transportDatagram, transportCapsule} }

// parseConnectIPClass 读取请求头 Aero-Class。缺省为 default（旧客户端不发该头）；
// 出现多个值、空值、未实现的类别（含保留值 browser、game）一律返回 400 并写好响应。
func parseConnectIPClass(w http.ResponseWriter, r *http.Request) (connectIPClass, bool) {
	vals := r.Header.Values(headerClass)
	if len(vals) == 0 {
		return connectIPClasses[classDefault], true
	}
	if len(vals) > 1 || strings.TrimSpace(vals[0]) != vals[0] {
		rejectUnsupportedClass(w)
		return connectIPClass{}, false
	}
	c, ok := connectIPClasses[vals[0]]
	if !ok {
		rejectUnsupportedClass(w)
		return connectIPClass{}, false
	}
	return c, true
}

// classAllowedByClaims 判定本次请求的 token 是否授权 class。claims 为 nil 表示不透明 token
// （过渡期，没有 classes 声明）或出口跳间凭证，授权全部已实现类别；签名 token 必须在 classes 里列出该类别
// （classes 为空的签名 token 在验签阶段已被拒绝，token.go claimsWellFormed）。
func classAllowedByClaims(claims *TokenClaims, class string) bool {
	if claims == nil {
		return true
	}
	return slices.Contains(claims.Classes, class)
}

// rejectUnsupportedClass 返回 400：Aero-Class 取值无效或为保留值。
func rejectUnsupportedClass(w http.ResponseWriter) {
	w.Header().Set("Proxy-Status", `aero; error=unsupported_class; details="EDGE_UNSUPPORTED_CLASS"`)
	w.WriteHeader(http.StatusBadRequest)
}

// rejectClassNotAllowed 返回 403：token 未授权该类别。
func rejectClassNotAllowed(w http.ResponseWriter) {
	w.Header().Set("Proxy-Status", `aero; error=class_not_allowed; details="EDGE_CLASS_NOT_ALLOWED"`)
	w.WriteHeader(http.StatusForbidden)
}

// poolForClass 返回类别对应的地址池；未配置时返回 nil。
func (s *QUICServer) poolForClass(class string) *IPPool {
	switch class {
	case classDefault:
		return s.ipPool
	case classAI:
		return s.aiPool
	}
	return nil
}
