// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode"
)

// 订阅地址保存在数据目录里，启动时读回，使用者不必每次输入。
// 不能靠界面的 localStorage：Windows 的 WebView2 数据目录是 %TEMP%\aero-client-wv-<PID>，进程退出时整个删除。
// 订阅地址的路径里含订阅标识（相当于凭据），所以文件 0600、原子替换，且任何日志都不写地址本身。

const (
	savedSubFileName = "subscription.json"
	maxSavedSubLen   = 4096
)

var savedSubMu sync.Mutex

type savedSubFile struct {
	URL string `json:"url"`
}

func savedSubPath() string { return filepath.Join(GetDataDir(), savedSubFileName) }

// validSavedSubURL 只接受带主机名的 https 地址（与 FetchSubscription 的要求一致，C5 §1），不含空白与控制字符。
func validSavedSubURL(raw string) bool {
	if raw == "" || len(raw) > maxSavedSubLen || strings.TrimSpace(raw) != raw {
		return false
	}
	for _, r := range raw {
		// 拒绝 ASCII 控制与空白，以及 Unicode 的控制（U+0085）、空白（U+2028 等）、格式字符（U+202E 双向覆盖符、零宽字符）：
		// 地址会填回输入框，这些字符可用来伪装显示的内容。
		if r <= ' ' || r == 0x7f || unicode.IsControl(r) || unicode.IsSpace(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	u, err := url.Parse(raw)
	// 带 user:pass@ 的地址不接受：订阅标识在路径里，不需要 userinfo，保存它只会多存一份凭据
	return err == nil && strings.EqualFold(u.Scheme, "https") && u.Hostname() != "" && u.User == nil
}

// LoadSavedSubscription 读取保存的订阅地址；没有、损坏或不合法时返回空串。
func LoadSavedSubscription() string {
	savedSubMu.Lock()
	defer savedSubMu.Unlock()
	return loadSavedSubLocked()
}

func loadSavedSubLocked() string {
	b, err := os.ReadFile(savedSubPath())
	if err != nil {
		return ""
	}
	var f savedSubFile
	if json.Unmarshal(b, &f) != nil || !validSavedSubURL(f.URL) {
		return ""
	}
	return f.URL
}

// SaveSubscriptionURL 保存订阅地址：与已保存的相同则不写盘（changed=false），不同则覆盖。
// 地址不合法时返回错误且不改动已保存的内容。
func SaveSubscriptionURL(raw string) (changed bool, err error) {
	raw = strings.TrimSpace(raw)
	if !validSavedSubURL(raw) {
		return false, errors.New("subscription URL must be an https:// URL with a host")
	}
	savedSubMu.Lock()
	defer savedSubMu.Unlock()
	if loadSavedSubLocked() == raw {
		return false, nil
	}
	data, err := json.Marshal(savedSubFile{URL: raw})
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(savedSubPath()), 0o700); err != nil {
		return false, err
	}
	if err := writeFileAtomic(savedSubPath(), data); err != nil {
		return false, err
	}
	return true, nil
}
