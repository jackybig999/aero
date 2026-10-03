package desk

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
)

// FingerprintConfig 完整指纹参数模型
type FingerprintConfig struct {
	Seed                string   `json:"seed"`
	UserAgent           string   `json:"user_agent"`
	Platform            string   `json:"platform"`  // "Win32", "MacIntel"
	Languages           []string `json:"languages"` // ["en-US", "en"], ["ja-JP", "ja"]
	Timezone            string   `json:"timezone"`  // "America/New_York", "Asia/Tokyo"
	ScreenWidth         int      `json:"screen_width"`
	ScreenHeight        int      `json:"screen_height"`
	ColorDepth          int      `json:"color_depth"`
	DevicePixelRatio    float64  `json:"device_pixel_ratio"`
	HardwareConcurrency int      `json:"hardware_concurrency"` // CPU 核心数
	DeviceMemory        int      `json:"device_memory"`        // 内存大小 (GB)
	WebGLVendor         string   `json:"webgl_vendor"`         // "Google Inc. (Apple)", "Intel Inc."
	WebGLRenderer       string   `json:"webgl_renderer"`       // "ANGLE (Apple, Apple M2 Pro, OpenGL 4.1)"
	CanvasNoise         float64  `json:"canvas_noise"`
	AudioNoise          float64  `json:"audio_noise"`
}

// CountryConfigMapping 国家代码对应推荐时区与语言
var CountryConfigMapping = map[string]struct {
	Timezone  string
	Languages []string
}{
	"US": {Timezone: "America/New_York", Languages: []string{"en-US", "en"}},
	"JP": {Timezone: "Asia/Tokyo", Languages: []string{"ja-JP", "ja"}},
	"GB": {Timezone: "Europe/London", Languages: []string{"en-GB", "en"}},
	"DE": {Timezone: "Europe/Berlin", Languages: []string{"de-DE", "de"}},
	"FR": {Timezone: "Europe/Paris", Languages: []string{"fr-FR", "fr"}},
	"SG": {Timezone: "Asia/Singapore", Languages: []string{"en-SG", "en", "zh-CN"}},
	"HK": {Timezone: "Asia/Hong_Kong", Languages: []string{"zh-HK", "zh", "en"}},
	"TW": {Timezone: "Asia/Taipei", Languages: []string{"zh-TW", "zh", "en"}},
	"CN": {Timezone: "Asia/Shanghai", Languages: []string{"zh-CN", "zh"}},
}

// GenerateFingerprintConfig 根据 Seed 和出站国家/内核版本生成确定性指纹参数
func GenerateFingerprintConfig(seed string, countryCode string, kernelType, kernelVersion string) *FingerprintConfig {
	if seed == "" {
		hash := md5.Sum([]byte(fmt.Sprintf("%d", rand.Int63())))
		seed = hex.EncodeToString(hash[:])[:8]
	}

	h := md5.Sum([]byte(seed))
	intSeed := int64(h[0]) | int64(h[1])<<8 | int64(h[2])<<16 | int64(h[3])<<24
	r := rand.New(rand.NewSource(intSeed))

	cfg := &FingerprintConfig{
		Seed: seed,
	}

	countryCode = strings.ToUpper(strings.TrimSpace(countryCode))
	if mapping, ok := CountryConfigMapping[countryCode]; ok {
		cfg.Timezone = mapping.Timezone
		cfg.Languages = mapping.Languages
	} else {
		cfg.Timezone = "America/New_York"
		cfg.Languages = []string{"en-US", "en"}
	}

	screenProfiles := [][]int{
		{1920, 1080},
		{1440, 900},
		{2560, 1440},
		{1680, 1050},
		{1536, 864},
	}
	sp := screenProfiles[r.Intn(len(screenProfiles))]
	cfg.ScreenWidth = sp[0]
	cfg.ScreenHeight = sp[1]
	cfg.ColorDepth = 24
	cfg.DevicePixelRatio = 1.0
	if r.Float64() > 0.6 {
		cfg.DevicePixelRatio = 2.0
	}

	cpus := []int{4, 8, 12, 16}
	cfg.HardwareConcurrency = cpus[r.Intn(len(cpus))]
	mems := []int{4, 8, 16}
	cfg.DeviceMemory = mems[r.Intn(len(mems))]

	gpus := []struct {
		Vendor   string
		Renderer string
		Platform string
	}{
		{
			Vendor:   "Google Inc. (Apple)",
			Renderer: "ANGLE (Apple, Apple M2, OpenGL 4.1)",
			Platform: "MacIntel",
		},
		{
			Vendor:   "Google Inc. (NVIDIA)",
			Renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)",
			Platform: "Win32",
		},
		{
			Vendor:   "Google Inc. (Intel)",
			Renderer: "ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)",
			Platform: "Win32",
		},
	}
	gpu := gpus[r.Intn(len(gpus))]
	cfg.WebGLVendor = gpu.Vendor
	cfg.WebGLRenderer = gpu.Renderer
	cfg.Platform = gpu.Platform

	if kernelType == "safari" {
		cfg.Platform = "MacIntel"
		cfg.WebGLVendor = "Google Inc. (Apple)"
		cfg.WebGLRenderer = "ANGLE (Apple, Apple M2, OpenGL 4.1)"
		cfg.UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15"
	} else if kernelType == "firefox" {
		v := kernelVersion
		if v == "" {
			v = "134.0"
		}
		cfg.UserAgent = fmt.Sprintf("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:%s) Gecko/20100101 Firefox/%s", v, v)
	} else {
		v := kernelVersion
		if v == "" {
			v = "133.0.6943.98"
		}
		major := strings.Split(v, ".")[0]
		cfg.UserAgent = fmt.Sprintf("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s.0.0.0 Safari/537.36", major)
	}

	cfg.CanvasNoise = (r.Float64() - 0.5) * 0.002
	cfg.AudioNoise = (r.Float64() - 0.5) * 0.0002

	return cfg
}

// BuildFingerprintScript 生成在页面最早时机注入的 JavaScript 防御代码
func BuildFingerprintScript(cfg *FingerprintConfig) string {
	langJSON, _ := json.Marshal(cfg.Languages)
	platformJSON, _ := json.Marshal(cfg.Platform)
	vendorJSON, _ := json.Marshal(cfg.WebGLVendor)
	rendererJSON, _ := json.Marshal(cfg.WebGLRenderer)

	return fmt.Sprintf(`(function() {
    'use strict';

    try {
        Object.defineProperty(navigator, 'webdriver', {
            get: () => undefined,
            configurable: true
        });
        delete Object.getPrototypeOf(navigator).webdriver;
    } catch (e) {}

    try {
        Object.defineProperty(navigator, 'platform', { get: () => %s });
        Object.defineProperty(navigator, 'languages', { get: () => %s });
        Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => %d });
        Object.defineProperty(navigator, 'deviceMemory', { get: () => %d });
        if (navigator.platform === 'MacIntel' && typeof window !== 'undefined') {
            delete window.chrome;
        }
    } catch (e) {}

    try {
        Object.defineProperty(screen, 'width', { get: () => %d });
        Object.defineProperty(screen, 'height', { get: () => %d });
        Object.defineProperty(screen, 'availWidth', { get: () => %d });
        Object.defineProperty(screen, 'availHeight', { get: () => %d - 40 });
        Object.defineProperty(screen, 'colorDepth', { get: () => %d });
        Object.defineProperty(screen, 'pixelDepth', { get: () => %d });
        Object.defineProperty(window, 'devicePixelRatio', { get: () => %f });
    } catch (e) {}

    try {
        const getParameterOrig = WebGLRenderingContext.prototype.getParameter;
        WebGLRenderingContext.prototype.getParameter = function(param) {
            if (param === 37445) { // UNMASKED_VENDOR_WEBGL
                return %s;
            }
            if (param === 37446) { // UNMASKED_RENDERER_WEBGL
                return %s;
            }
            return getParameterOrig.apply(this, arguments);
        };
        if (typeof WebGL2RenderingContext !== 'undefined') {
            const getParameter2 = WebGL2RenderingContext.prototype.getParameter;
            WebGL2RenderingContext.prototype.getParameter = function(param) {
                if (param === 37445) return %s;
                if (param === 37446) return %s;
                return getParameter2.apply(this, arguments);
            };
        }
    } catch (e) {}

    try {
        const toDataURLOrig = HTMLCanvasElement.prototype.toDataURL;
        HTMLCanvasElement.prototype.toDataURL = function(type) {
            const ctx = this.getContext('2d');
            if (ctx && this.width > 0 && this.height > 0) {
                try {
                    const imgData = ctx.getImageData(0, 0, Math.min(this.width, 16), Math.min(this.height, 16));
                    for (let i = 0; i < imgData.data.length; i += 8) {
                        imgData.data[i] = (imgData.data[i] + Math.round(%f * 1000)) %% 256;
                    }
                    ctx.putImageData(imgData, 0, 0);
                } catch (err) {}
            }
            return toDataURLOrig.apply(this, arguments);
        };
    } catch (e) {}

    try {
        const origGetChannelData = AudioBuffer.prototype.getChannelData;
        AudioBuffer.prototype.getChannelData = function() {
            const data = origGetChannelData.apply(this, arguments);
            for (let i = 0; i < data.length; i += 100) {
                data[i] += %f;
            }
            return data;
        };
    } catch (e) {}

})();`,
		string(platformJSON),
		string(langJSON),
		cfg.HardwareConcurrency,
		cfg.DeviceMemory,
		cfg.ScreenWidth,
		cfg.ScreenHeight,
		cfg.ScreenWidth,
		cfg.ScreenHeight,
		cfg.ColorDepth,
		cfg.ColorDepth,
		cfg.DevicePixelRatio,
		string(vendorJSON),
		string(rendererJSON),
		string(vendorJSON),
		string(rendererJSON),
		cfg.CanvasNoise,
		cfg.AudioNoise,
	)
}
