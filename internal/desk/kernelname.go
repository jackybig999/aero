// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package desk

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

// 内核目录名由前端传来的 kernelType、milestone 拼成（L0 §7.3、§11.6：信任边界上一次校验）。
// 不校验时 milestone="/../.." 会让 RemoveAll 越出 dataDir/kernels。

var kernelNamePart = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// 可由本程序下载与删除的内核类型。
var kernelTypes = map[string]bool{"chrome": true, "firefox": true}

// kernelDownloadHosts 是内核包允许的下载主机（与 fetch.go 里内核目录使用的官方来源一致）。
var kernelDownloadHosts = map[string]bool{
	"storage.googleapis.com":   true, // Chrome for Testing
	"playwright.azureedge.net": true, // Firefox
}

// kernelDirFor 校验内核类型与里程碑，返回目录键与目录，并确认目录位于 dataDir/kernels 之内。
func kernelDirFor(dataDir, kernelType, milestone string) (key, dir string, err error) {
	if !kernelTypes[kernelType] {
		return "", "", fmt.Errorf("不支持的内核类型 %q", kernelType)
	}
	if !kernelNamePart.MatchString(milestone) || strings.Contains(milestone, "..") {
		return "", "", fmt.Errorf("无效的内核版本 %q", milestone)
	}
	key = kernelType + "_" + milestone
	root := filepath.Join(dataDir, "kernels")
	dir = filepath.Join(root, key)
	if dir == root || !pathWithin(root, dir) {
		return "", "", errors.New("内核目录越界")
	}
	return key, dir, nil
}

// validateKernelURL 只接受 https 与官方下载主机，不接受带用户信息的地址。
func validateKernelURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("下载链接无效: %w", err)
	}
	if u.Scheme != "https" || u.User != nil || !kernelDownloadHosts[strings.ToLower(u.Hostname())] {
		return fmt.Errorf("下载链接不在允许的官方来源内: %s", u.Hostname())
	}
	return nil
}
