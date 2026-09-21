package service

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"aisys/connect/os/internal/domain/fingerprint"
	"aisys/connect/os/internal/infra/config"
	"aisys/connect/os/internal/infra/db"
	"aisys/connect/os/internal/kernel"
)

// ListProfiles 查询全部环境列表并自愈异常状态 (纯只读极速响应，零锁争用)
func (s *AppService) ListProfiles() ([]*db.Profile, error) {
	rows, err := s.DB.Query(`SELECT id, user_id, name, notes, icon_color, kernel_type, kernel_version, proxy_id, fingerprint_config, data_dir, status, last_launched_at, created_at FROM profiles ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	var list []*db.Profile
	for rows.Next() {
		var p db.Profile
		err := rows.Scan(&p.ID, &p.UserID, &p.Name, &p.Notes, &p.IconColor, &p.KernelType, &p.KernelVersion, &p.ProxyID, &p.FingerprintConfig, &p.DataDir, &p.Status, &p.LastLaunchedAt, &p.CreatedAt)
		if err != nil {
			continue
		}
		list = append(list, &p)
	}
	_ = rows.Close()

	var desyncIDs []int64
	for _, p := range list {
		if memStatus, ok := s.GetProfileStatusCache(p.ID); ok {
			p.Status = memStatus
			continue
		}
		isRunning := kernel.IsProfileRunning(p.ID)
		if isRunning {
			p.Status = "running"
			s.SetProfileStatusCache(p.ID, "running")
		} else {
			if p.Status == "running" {
				p.Status = "stopped"
				desyncIDs = append(desyncIDs, p.ID)
			}
			s.SetProfileStatusCache(p.ID, "stopped")
		}
	}

	// 异步单次批量纠正 DB，绝不阻塞当前 IPC 查询
	if len(desyncIDs) > 0 {
		go func(ids []int64) {
			for _, id := range ids {
				_, _ = s.DB.Exec(`UPDATE profiles SET status = 'stopped' WHERE id = ?`, id)
			}
		}(desyncIDs)
	}

	return list, nil
}

// ResolveProfileLanguages 将语言设置 (含 "system") 动态解析为与宿主系统完全匹配的语言切片 (绝无硬编码固定中文)
func ResolveProfileLanguages(lang string) []string {
	lang = strings.TrimSpace(lang)
	if lang == "" || strings.EqualFold(lang, "system") {
		sysLocale := config.GetHostSystemLocale()
		low := strings.ToLower(sysLocale)
		if strings.HasPrefix(low, "zh") {
			if strings.Contains(low, "tw") {
				return []string{"zh-TW", "zh"}
			}
			if strings.Contains(low, "hk") {
				return []string{"zh-HK", "zh"}
			}
			return []string{"zh-CN", "zh"}
		}
		if strings.HasPrefix(low, "ja") {
			return []string{"ja-JP", "ja"}
		}
		if strings.HasPrefix(low, "de") {
			return []string{"de-DE", "de"}
		}
		if strings.HasPrefix(low, "fr") {
			return []string{"fr-FR", "fr"}
		}
		if strings.HasPrefix(low, "ru") {
			return []string{"ru-RU", "ru"}
		}
		if strings.HasPrefix(low, "es") {
			return []string{"es-ES", "es"}
		}
		if strings.HasPrefix(low, "ko") {
			return []string{"ko-KR", "ko"}
		}
		if strings.HasPrefix(low, "it") {
			return []string{"it-IT", "it"}
		}
		if strings.HasPrefix(low, "en") {
			if strings.Contains(low, "gb") || strings.Contains(low, "uk") {
				return []string{"en-GB", "en"}
			}
			return []string{"en-US", "en"}
		}
		return []string{sysLocale, "en"}
	}

	var langs []string
	for _, l := range strings.Split(lang, ",") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.EqualFold(l, "system") {
			langs = append(langs, l)
		}
	}
	if len(langs) == 0 {
		return ResolveProfileLanguages("system")
	}
	return langs
}

// UpdateProfileLanguage 更新并持久化环境的语言设置 (固定写入数据库)
func (s *AppService) UpdateProfileLanguage(id int64, languages string) error {
	langs := ResolveProfileLanguages(languages)
	var fpJSON string
	err := s.DB.QueryRow(`SELECT fingerprint_config FROM profiles WHERE id = ?`, id).Scan(&fpJSON)
	if err != nil {
		return fmt.Errorf("未找到待更新语言的环境 #%d: %w", id, err)
	}

	var fp fingerprint.FingerprintConfig
	_ = json.Unmarshal([]byte(fpJSON), &fp)
	fp.Languages = langs

	newBytes, err := json.Marshal(fp)
	if err != nil {
		return fmt.Errorf("序列化指纹配置失败: %w", err)
	}

	s.mu.Lock()
	_, err = s.DB.Exec(`UPDATE profiles SET fingerprint_config = ? WHERE id = ?`, string(newBytes), id)
	s.mu.Unlock()

	log.Printf("[OK] 环境 #%d 语言配置已持久化更新为: %v\n", id, langs)
	return err
}

// DeleteProfile 停止并删除指定指纹环境及沙箱数据
func (s *AppService) DeleteProfile(id int64) error {
	_ = s.StopProfile(id)
	_, err := s.DB.Exec(`DELETE FROM profiles WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("删除环境数据库记录失败: %w", err)
	}
	profileDir := filepath.Join(s.DataDir, "profiles", strconv.FormatInt(id, 10))
	_ = os.RemoveAll(profileDir)
	return nil
}

// CloneProfile 克隆复制一个既有环境并生成独立微调指纹
func (s *AppService) CloneProfile(id int64) (*db.Profile, error) {
	var p db.Profile
	err := s.DB.QueryRow(`SELECT id, user_id, name, notes, icon_color, kernel_type, kernel_version, proxy_id, fingerprint_config, data_dir, status FROM profiles WHERE id = ?`, id).Scan(
		&p.ID, &p.UserID, &p.Name, &p.Notes, &p.IconColor, &p.KernelType, &p.KernelVersion, &p.ProxyID, &p.FingerprintConfig, &p.DataDir, &p.Status,
	)
	if err != nil {
		return nil, fmt.Errorf("未找到要克隆的环境: %w", err)
	}

	var fp fingerprint.FingerprintConfig
	_ = json.Unmarshal([]byte(p.FingerprintConfig), &fp)
	fp.CanvasNoise = -0.0001 - float64(time.Now().UnixNano()%1000)/1000000.0
	fp.AudioNoise = 0.0001 + float64(time.Now().UnixNano()%1000)/1000000.0
	fpBytes, _ := json.Marshal(fp)

	cloneName := p.Name + " (副本)"
	res, err := s.DB.Exec(`INSERT INTO profiles (user_id, name, notes, kernel_type, kernel_version, proxy_id, fingerprint_config, data_dir, status) VALUES (1, ?, ?, ?, ?, ?, ?, ?, 'stopped')`,
		cloneName, p.Notes, p.KernelType, p.KernelVersion, p.ProxyID, string(fpBytes), s.DataDir,
	)
	if err != nil {
		return nil, err
	}
	newID, _ := res.LastInsertId()
	p.ID = newID
	p.Name = cloneName
	p.Status = "stopped"
	p.FingerprintConfig = string(fpBytes)
	p.CreatedAt = time.Now()
	return &p, nil
}
