// Package artifact resolves the AERO binary to install (prefer GitHub latest).
package artifact

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Spec is the desired AERO install target.
type Spec struct {
	Version string // e.g. 1.0.0 or v1.0.0 (normalized without leading v for compare)
	Tag     string // original tag e.g. v1.0.0
	URL     string
	SHA256  string // optional; empty if unknown
	Source  string // github-latest | env-pin
}

// ResolveDesired returns the artifact that deploy should install.
// AERO_FOLLOW_LATEST=1 (default) → GitHub latest release.
// AERO_FOLLOW_LATEST=0 → pin AERO_RELEASE_URL / AERO_VERSION / AERO_SHA256.
func ResolveDesired() (Spec, error) {
	follow := strings.ToLower(strings.TrimSpace(os.Getenv("AERO_FOLLOW_LATEST")))
	if follow == "0" || follow == "false" || follow == "no" {
		return pinFromEnv(), nil
	}
	repo := strings.TrimSpace(os.Getenv("AERO_GITHUB_REPO"))
	if repo == "" {
		repo = "jackybig999/aero"
	}
	spec, err := fetchGitHubLatest(repo)
	if err != nil {
		// fallback to pin so deploy can still work offline
		pin := pinFromEnv()
		pin.Source = "env-pin-fallback"
		if pin.URL == "" {
			return Spec{}, fmt.Errorf("resolve latest from %s: %w; and no AERO_RELEASE_URL fallback", repo, err)
		}
		return pin, nil
	}
	// optional: override SHA from env if matches same version
	envSHA := strings.TrimSpace(os.Getenv("AERO_SHA256"))
	envVer := normalizeVer(os.Getenv("AERO_VERSION"))
	if envSHA != "" && envVer != "" && envVer == normalizeVer(spec.Version) {
		spec.SHA256 = envSHA
	}
	return spec, nil
}

func pinFromEnv() Spec {
	ver := strings.TrimSpace(os.Getenv("AERO_VERSION"))
	if ver == "" {
		ver = "0.0.0"
	}
	return Spec{
		Version: normalizeVer(ver),
		Tag:     ensureV(ver),
		URL:     strings.TrimSpace(os.Getenv("AERO_RELEASE_URL")),
		SHA256:  strings.TrimSpace(os.Getenv("AERO_SHA256")),
		Source:  "env-pin",
	}
}

func fetchGitHubLatest(repo string) (Spec, error) {
	api := "https://api.github.com/repos/" + repo + "/releases/latest"
	client := &http.Client{Timeout: 20 * time.Second}
	req, err := http.NewRequest(http.MethodGet, api, nil)
	if err != nil {
		return Spec{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "vpn-deploy-engine")
	if tok := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := client.Do(req)
	if err != nil {
		return Spec{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return Spec{}, fmt.Errorf("GitHub API HTTP %d: %s", resp.StatusCode, trim(string(body), 200))
	}
	var rel struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
			Digest             string `json:"digest"` // sha256:hex (newer API)
		} `json:"assets"`
	}
	if err := json.Unmarshal(body, &rel); err != nil {
		return Spec{}, err
	}
	if rel.TagName == "" {
		return Spec{}, fmt.Errorf("empty tag_name")
	}
	// prefer linux-amd64 edge binary
	var url, sha string
	for _, a := range rel.Assets {
		name := strings.ToLower(a.Name)
		if strings.Contains(name, "linux") && (strings.Contains(name, "amd64") || strings.Contains(name, "x86_64")) {
			if strings.Contains(name, "edge") || strings.Contains(name, "aero") || !strings.Contains(name, "sha") {
				url = a.BrowserDownloadURL
				if strings.HasPrefix(a.Digest, "sha256:") {
					sha = strings.TrimPrefix(a.Digest, "sha256:")
				}
				// prefer name containing edge
				if strings.Contains(name, "edge") {
					break
				}
			}
		}
	}
	if url == "" {
		// any asset
		for _, a := range rel.Assets {
			if a.BrowserDownloadURL != "" && !strings.HasSuffix(strings.ToLower(a.Name), ".sha256") {
				url = a.BrowserDownloadURL
				if strings.HasPrefix(a.Digest, "sha256:") {
					sha = strings.TrimPrefix(a.Digest, "sha256:")
				}
				break
			}
		}
	}
	if url == "" {
		// conventional path if no assets listed
		url = fmt.Sprintf("https://github.com/%s/releases/download/%s/aero-edge-linux-amd64", repo, rel.TagName)
	}
	return Spec{
		Version: normalizeVer(rel.TagName),
		Tag:     ensureV(rel.TagName),
		URL:     url,
		SHA256:  sha,
		Source:  "github-latest",
	}, nil
}

func normalizeVer(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	return v
}

func ensureV(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if strings.HasPrefix(v, "v") || strings.HasPrefix(v, "V") {
		return "v" + normalizeVer(v)
	}
	return "v" + v
}

// EqualVersion compares two version strings ignoring leading v.
func EqualVersion(a, b string) bool {
	return normalizeVer(a) != "" && normalizeVer(a) == normalizeVer(b)
}

func trim(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
