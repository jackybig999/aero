// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package desk

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// 内核目录名由前端传来的 kernelType、milestone 拼成（L0 §7.3、§11.6：信任边界上一次校验）。
// 不校验时 milestone="/../.." 会让 RemoveAll 越出 dataDir/kernels。

var kernelNamePart = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// 可由本程序下载与删除的内核类型。
var kernelTypes = map[string]bool{"chrome": true, "firefox": true}

// kernelDownloadSources 是内核包允许的下载来源：主机 → 路径前缀（与 fetch.go 里内核目录使用的官方来源一致）。
// 只限主机不够：storage.googleapis.com 是公共存储主机，任何人的 bucket 都在它下面。
var kernelDownloadSources = map[string][]string{
	"storage.googleapis.com":   {"/chrome-for-testing-public/"}, // Chrome for Testing
	"playwright.azureedge.net": {"/builds/firefox/"},            // Firefox（旧地址，现在会 307 到下面的微软官方主机）
	// Firefox：azureedge 的重定向目标（2026-11-24 实测 307 → 此主机，200 返回 zip）。
	"playwright.download.prss.microsoft.com": {"/dbazure/download/playwright/builds/firefox/"},
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

// validateKernelURL 只接受 https、官方下载主机与该主机下的官方路径前缀；不接受带用户信息、非 443 端口或含 .. 的地址。
func validateKernelURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("下载链接无效: %w", err)
	}
	if err := validateKernelHost(u); err != nil {
		return err
	}
	// 官方地址不含百分号编码与反斜杠；编码（%2f、%2e%2e）或反斜杠可能被中间的 CDN 规范化成别的路径。
	if u.RawPath != "" || strings.ContainsRune(u.Path, '\\') || path.Clean(u.Path) != u.Path { // 含 ..、//、. 等不规范写法
		return fmt.Errorf("下载链接路径不规范: %s", u.EscapedPath())
	}
	for _, prefix := range kernelDownloadSources[strings.ToLower(u.Hostname())] {
		if strings.HasPrefix(u.Path, prefix) {
			return nil
		}
	}
	return fmt.Errorf("下载链接不在官方路径内: %s%s", u.Hostname(), u.Path)
}

// validateKernelHost 检查 https、官方主机、无用户信息、默认端口。
func validateKernelHost(u *url.URL) error {
	if u.Scheme != "https" || u.User != nil {
		return fmt.Errorf("下载链接必须是不带用户信息的 https 地址")
	}
	host := u.Hostname()
	// 主机名必须是纯 ASCII：strings.ToLower 会把 U+0130 'İ' 之类转成 ASCII 字母，同形主机名因此能通过名单，
	// 而 Go 实际拨的是它的 punycode（storage.googleapİs.com → storage.xn--googleapis-v2f.com，任何人都能注册）。
	for i := 0; i < len(host); i++ {
		if host[i] >= 0x80 {
			return errors.New("下载链接主机名含非 ASCII 字符")
		}
	}
	if _, ok := kernelDownloadSources[strings.ToLower(host)]; !ok {
		return fmt.Errorf("下载链接不在允许的官方来源内: %s", host)
	}
	if port := u.Port(); port != "" && port != "443" {
		return fmt.Errorf("下载链接端口不允许: %s", port)
	}
	return nil
}

// checkKernelRedirect 用作下载客户端的 CheckRedirect：官方源即使 30x，每一跳也要通过与初始地址相同的完整校验
// （https、官方主机、官方路径前缀），否则白名单形同虚设（Go 默认最多跟随 10 次，目标可以是任意主机，也可以是 http）。
func checkKernelRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("重定向次数过多")
	}
	return validateKernelURL(req.URL.String())
}
