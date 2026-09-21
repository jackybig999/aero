package kernel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// DownloadAndExtractKernel 下载并解压内核至目标目录
func DownloadAndExtractKernel(ctx context.Context, dlURL, targetDir string, progressFn func(percent int)) error {
	if dlURL == "" {
		return errors.New("下载链接为空")
	}

	kernelType := "chrome"
	if strings.Contains(strings.ToLower(targetDir), "firefox") || strings.Contains(strings.ToLower(dlURL), "firefox") {
		kernelType = "firefox"
	}

	parentDir := filepath.Dir(targetDir)
	if err := os.MkdirAll(parentDir, 0755); err != nil {
		return fmt.Errorf("创建内核存储根目录失败: %w", err)
	}

	// 1. 创建隔离的 staging 临时工作区
	stagingDir, err := os.MkdirTemp(parentDir, ".staging_*")
	if err != nil {
		return fmt.Errorf("创建临时解压工作区失败: %w", err)
	}
	defer os.RemoveAll(stagingDir)

	finalURLPath := strings.ToLower(dlURL)
	isExe := strings.HasSuffix(finalURLPath, ".exe") || strings.Contains(finalURLPath, ".exe")
	isDmg := strings.HasSuffix(finalURLPath, ".dmg") || strings.Contains(finalURLPath, ".dmg")

	tmpPackage := filepath.Join(stagingDir, "package.tmp")
	if isExe {
		tmpPackage = filepath.Join(stagingDir, "setup.exe")
	} else if isDmg {
		tmpPackage = filepath.Join(stagingDir, "package.dmg")
	} else {
		tmpPackage = filepath.Join(stagingDir, "package.zip")
	}

	var downloaded int64
	var total int64
	maxRetries := 5
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		req, err := http.NewRequestWithContext(ctx, "GET", dlURL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		if downloaded > 0 {
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-", downloaded))
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("网络连接官方源失败: %w", err)
			time.Sleep(1 * time.Second)
			continue
		}

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
			resp.Body.Close()
			if resp.StatusCode == http.StatusRequestedRangeNotSatisfiable && total > 0 && downloaded >= total {
				break
			}
			return fmt.Errorf("下载官方内核返回异常状态码: %d", resp.StatusCode)
		}

		if resp.StatusCode == http.StatusOK {
			downloaded = 0
			total = resp.ContentLength
			_ = os.Remove(tmpPackage)
		} else if resp.StatusCode == http.StatusPartialContent {
			if total == 0 && resp.ContentLength > 0 {
				total = downloaded + resp.ContentLength
			}
		}

		openFlag := os.O_CREATE | os.O_WRONLY
		if downloaded > 0 {
			openFlag |= os.O_APPEND
		}
		out, err := os.OpenFile(tmpPackage, openFlag, 0644)
		if err != nil {
			resp.Body.Close()
			return fmt.Errorf("打开临时安装包失败: %w", err)
		}

		buf := make([]byte, 64*1024)
		var readErr error
		for {
			select {
			case <-ctx.Done():
				out.Close()
				resp.Body.Close()
				return ctx.Err()
			default:
			}

			n, rErr := resp.Body.Read(buf)
			if n > 0 {
				if _, wErr := out.Write(buf[:n]); wErr != nil {
					out.Close()
					resp.Body.Close()
					return fmt.Errorf("写入临时安装包失败 (可能磁盘空间不足): %w", wErr)
				}
				downloaded += int64(n)
				if total > 0 && progressFn != nil {
					pct := int(float64(downloaded) / float64(total) * 70)
					if pct < 1 {
						pct = 1
					}
					if pct > 70 {
						pct = 70
					}
					progressFn(pct)
				}
			}
			if rErr != nil {
				readErr = rErr
				break
			}
		}
		out.Close()
		resp.Body.Close()

		if readErr == io.EOF {
			lastErr = nil
			break
		}
		lastErr = fmt.Errorf("网络流中断: %w (已自动保持断点，准备重试)", readErr)
		time.Sleep(1 * time.Second)
	}

	if lastErr != nil {
		return lastErr
	}

	if progressFn != nil {
		progressFn(75)
	}

	// 2. 解压到 staging 内部的 extracted 目录
	extractedDir := filepath.Join(stagingDir, "extracted")
	if err := os.MkdirAll(extractedDir, 0755); err != nil {
		return fmt.Errorf("创建临时解压目标目录失败: %w", err)
	}

	if isExe {
		// .exe 格式仅用于 Chrome 等（Firefox 现在用 zip，不会走这里）
		// 用 tar 提取 NSIS/7z 封装的 exe，严禁直接运行安装程序
		if runtime.GOOS == "windows" {
			tarCmd := exec.Command("tar.exe", "-xf", tmpPackage, "-C", extractedDir)
			if err := tarCmd.Run(); err != nil {
				return fmt.Errorf("解压安装包失败（不支持直接运行安装程序以防止系统污染）: %w", err)
			}
			coreDir := filepath.Join(extractedDir, "core")
			if fi, err := os.Stat(coreDir); err == nil && fi.IsDir() {
				entries, _ := os.ReadDir(coreDir)
				for _, entry := range entries {
					oldP := filepath.Join(coreDir, entry.Name())
					newP := filepath.Join(extractedDir, entry.Name())
					_ = os.Rename(oldP, newP)
				}
				_ = os.RemoveAll(coreDir)
			}
			_ = os.Remove(filepath.Join(extractedDir, "setup.exe"))
		} else {
			return fmt.Errorf("当前平台不支持 .exe 格式内核包，请使用 zip/dmg 格式")
		}
		CleanInstallerArtifacts(extractedDir)

	} else if isDmg {
		if runtime.GOOS == "darwin" {
			mountDir := filepath.Join(stagingDir, "dmg_mount")
			_ = os.MkdirAll(mountDir, 0755)
			cmd := exec.Command("hdiutil", "attach", tmpPackage, "-mountpoint", mountDir, "-nobrowse", "-quiet")
			if err := cmd.Run(); err == nil {
				entries, _ := os.ReadDir(mountDir)
				for _, entry := range entries {
					if strings.HasSuffix(entry.Name(), ".app") {
						srcApp := filepath.Join(mountDir, entry.Name())
						dstApp := filepath.Join(extractedDir, entry.Name())
						_ = exec.Command("cp", "-R", srcApp, dstApp).Run()
						break
					}
				}
				_ = exec.Command("hdiutil", "detach", mountDir, "-quiet").Run()
			}
		}
	} else {
		if err := unzipArchive(tmpPackage, extractedDir); err != nil {
			return fmt.Errorf("解压 zip 压缩包失败: %w", err)
		}
	}

	if progressFn != nil {
		progressFn(90)
	}

	// 3. 严格完整性自检
	validPath := LocateDownloadedKernel(extractedDir, kernelType)
	if validPath == "" || !isKernelExecutableValid(validPath, kernelType) {
		return fmt.Errorf("内核完整性校验未通过: 缺失核心组件或文件损坏")
	}

	if progressFn != nil {
		progressFn(95)
	}

	// 4. 清理旧目录并原子替换
	_ = CleanKernelDir(targetDir)

	if err := os.Rename(extractedDir, targetDir); err != nil {
		if cErr := copyDir(extractedDir, targetDir); cErr != nil {
			return fmt.Errorf("部署内核至目标目录失败: %w", cErr)
		}
	}

	// 5. 目标目录最终验收
	finalPath := LocateDownloadedKernel(targetDir, kernelType)
	if finalPath == "" || !isKernelExecutableValid(finalPath, kernelType) {
		_ = CleanKernelDir(targetDir)
		return fmt.Errorf("内核部署验证失败，已自动回滚清理")
	}

	if runtime.GOOS == "darwin" {
		_ = os.Chmod(finalPath, 0755)
		_ = exec.Command("xattr", "-dr", "com.apple.quarantine", targetDir).Run()
	}

	CleanInstallerArtifacts(targetDir)
	if kernelType == "firefox" {
		SanitizeFirefoxKernel(targetDir)
	}

	if progressFn != nil {
		progressFn(100)
	}
	return nil
}
