package storage

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// BackupUserData 将指定 profile 的 UserData 打包为 zip 备份
func BackupUserData(userDataDir, destBackupZip string) error {
	if _, err := os.Stat(userDataDir); os.IsNotExist(err) {
		return fmt.Errorf("UserData 目录不存在: %s", userDataDir)
	}

	if destBackupZip == "" {
		timestamp := time.Now().Format("20060102_150405")
		destBackupZip = filepath.Join(filepath.Dir(userDataDir), fmt.Sprintf("backup_%s.zip", timestamp))
	}

	dir := filepath.Dir(destBackupZip)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}

	out, err := os.Create(destBackupZip)
	if err != nil {
		return fmt.Errorf("创建备份文件失败: %w", err)
	}
	defer out.Close()

	w := zip.NewWriter(out)
	defer w.Close()

	walker := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		name := info.Name()
		if name == "SingletonLock" || name == "SingletonSocket" || name == "parent.lock" || strings.HasSuffix(name, ".lock") {
			return nil
		}

		relPath, err := filepath.Rel(userDataDir, path)
		if err != nil {
			return err
		}
		if relPath == "." {
			return nil
		}

		zipEntryPath := filepath.ToSlash(relPath)
		if info.IsDir() {
			zipEntryPath += "/"
			_, err := w.Create(zipEntryPath)
			return err
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = zipEntryPath
		header.Method = zip.Deflate

		writer, err := w.CreateHeader(header)
		if err != nil {
			return err
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		_, err = io.Copy(writer, file)
		return err
	}

	return filepath.Walk(userDataDir, walker)
}

// RestoreUserData 从备份 zip 还原到指定的 profile 目录
func RestoreUserData(backupZip, destUserDataDir string) error {
	r, err := zip.OpenReader(backupZip)
	if err != nil {
		return fmt.Errorf("打开备份文件失败: %w", err)
	}
	defer r.Close()

	if err := os.MkdirAll(destUserDataDir, 0755); err != nil {
		return fmt.Errorf("创建目标目录失败: %w", err)
	}

	for _, f := range r.File {
		fpath := filepath.Join(destUserDataDir, filepath.FromSlash(f.Name))
		if !strings.HasPrefix(fpath, filepath.Clean(destUserDataDir)+string(os.PathSeparator)) {
			return fmt.Errorf("非法路径穿越: %s", fpath)
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(fpath, os.ModePerm); err != nil {
				return fmt.Errorf("创建子目录失败: %w", err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return err
		}

		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
		if err != nil {
			return err
		}
	}

	return nil
}
