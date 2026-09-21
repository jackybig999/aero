package kernel

import (
	"archive/zip"
	"os"
	"path/filepath"
)

// BuildFirefoxFingerprintExtension 动态生成 Firefox 注入扩展 (.xpi)
func BuildFirefoxFingerprintExtension(targetDir string, jsCode string) (string, error) {
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return "", err
	}
	xpiPath := filepath.Join(targetDir, "fingerprint_hook.xpi")

	out, err := os.Create(xpiPath)
	if err != nil {
		return "", err
	}
	defer out.Close()

	w := zip.NewWriter(out)
	defer w.Close()

	manifest := `{
  "manifest_version": 2,
  "name": "Fingerprint Defense",
  "version": "1.0",
  "content_scripts": [
    {
      "matches": ["<all_urls>"],
      "js": ["content.js"],
      "run_at": "document_start",
      "all_frames": true
    }
  ]
}`
	f, err := w.Create("manifest.json")
	if err != nil {
		return "", err
	}
	_, _ = f.Write([]byte(manifest))

	f2, err := w.Create("content.js")
	if err != nil {
		return "", err
	}
	_, _ = f2.Write([]byte(jsCode))

	return xpiPath, nil
}
