package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ANSI color codes for rich terminal display without third-party dependencies.
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
	colorBold   = "\033[1m"
)

type ProxyInfo struct {
	Host     string
	Port     int
	Protocol string // "http" or "socks5"
	Name     string
}

func (p *ProxyInfo) URL() string {
	if p == nil || p.Port == 0 {
		return ""
	}
	proto := p.Protocol
	if proto == "" {
		proto = "http"
	}
	return fmt.Sprintf("%s://%s:%d", proto, p.Host, p.Port)
}

func (p *ProxyInfo) String() string {
	if p == nil || p.Port == 0 {
		return "直连 (无代理)"
	}
	return fmt.Sprintf("%s (%s://%s:%d)", p.Name, p.Protocol, p.Host, p.Port)
}

// Known ports prioritized for local proxies.
var knownProxyTargets = []struct {
	Port     int
	Protocol string
	Name     string
}{
	{55555, "http", "AERO Mixed (HTTP CONNECT)"},
	{7890, "http", "Clash / Mihomo Mixed"},
	{10808, "socks5", "v2rayN SOCKS5"},
	{10809, "http", "v2rayN HTTP"},
	{4780, "http", "Clash Verge"},
	{1080, "socks5", "SOCKS5 Default"},
	{7891, "socks5", "Clash SOCKS5"},
	{20171, "socks5", "v2rayN Alt"},
	{8080, "http", "HTTP Proxy"},
	{9090, "http", "Surge"},
}

// detectLocalProxy scans local loopback ports concurrently and returns the first reachable proxy.
func detectLocalProxy() *ProxyInfo {
	type result struct {
		info *ProxyInfo
		prio int
	}

	resCh := make(chan result, len(knownProxyTargets))
	var wg sync.WaitGroup

	for i, target := range knownProxyTargets {
		wg.Add(1)
		go func(idx int, port int, proto, name string) {
			defer wg.Done()
			addr := fmt.Sprintf("127.0.0.1:%d", port)
			conn, err := net.DialTimeout("tcp", addr, 250*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				resCh <- result{
					info: &ProxyInfo{
						Host:     "127.0.0.1",
						Port:     port,
						Protocol: proto,
						Name:     name,
					},
					prio: idx,
				}
			}
		}(i, target.Port, target.Protocol, target.Name)
	}

	wg.Wait()
	close(resCh)

	var best *result
	for r := range resCh {
		if best == nil || r.prio < best.prio {
			temp := r
			best = &temp
		}
	}

	if best != nil {
		return best.info
	}
	return nil
}

// ToolConfig stores launch information for an AI CLI tool.
type ToolConfig struct {
	Name        string
	Display     string
	Command     string
	Args        []string
	DefaultCwd  string
	EnvVars     []string
}

func getTools() map[string]*ToolConfig {
	userHome, _ := os.UserHomeDir()
	claudeCwd := filepath.Join(userHome, "claude")
	if _, err := os.Stat(claudeCwd); err != nil {
		claudeCwd = ""
	}

	return map[string]*ToolConfig{
		"claude": {
			Name:       "claude",
			Display:    "Claude Code",
			Command:    "claude",
			Args:       []string{},
			DefaultCwd: claudeCwd,
			EnvVars:    []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"},
		},
		"codex": {
			Name:       "codex",
			Display:    "Codex CLI",
			Command:    "codex",
			Args:       []string{},
			DefaultCwd: "",
			EnvVars:    []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"},
		},
	}
}

// buildProxyEnv builds the environment list with proxy variables set.
func buildProxyEnv(proxy *ProxyInfo) []string {
	env := os.Environ()
	if proxy == nil || proxy.Port == 0 {
		return env
	}

	filtered := make([]string, 0, len(env)+10)
	for _, e := range env {
		upper := strings.ToUpper(e)
		if strings.HasPrefix(upper, "HTTP_PROXY=") ||
			strings.HasPrefix(upper, "HTTPS_PROXY=") ||
			strings.HasPrefix(upper, "ALL_PROXY=") ||
			strings.HasPrefix(upper, "FTP_PROXY=") ||
			strings.HasPrefix(upper, "NO_PROXY=") {
			continue
		}
		filtered = append(filtered, e)
	}

	httpUrl := fmt.Sprintf("http://%s:%d", proxy.Host, proxy.Port)
	socksUrl := fmt.Sprintf("socks5://%s:%d", proxy.Host, proxy.Port)

	filtered = append(filtered,
		"HTTP_PROXY="+httpUrl,
		"http_proxy="+httpUrl,
		"HTTPS_PROXY="+httpUrl,
		"https_proxy="+httpUrl,
	)

	if proxy.Protocol == "socks5" {
		filtered = append(filtered,
			"ALL_PROXY="+socksUrl,
			"all_proxy="+socksUrl,
		)
	} else {
		filtered = append(filtered,
			"ALL_PROXY="+httpUrl,
			"all_proxy="+httpUrl,
		)
	}

	filtered = append(filtered,
		"NO_PROXY=localhost,127.0.0.1,::1",
		"no_proxy=localhost,127.0.0.1,::1",
	)

	return filtered
}

// launchTool opens a new console window to run the selected tool.
func launchTool(tool *ToolConfig, proxy *ProxyInfo, cwd string) error {
	if cwd == "" {
		cwd, _ = os.Getwd()
	}

	env := buildProxyEnv(proxy)

	if runtime.GOOS == "windows" {
		// Launch in a new dedicated CMD window via cmd.exe start
		title := tool.Display
		args := append([]string{"/c", "start", title, "cmd", "/k", "title " + title + " && " + tool.Command}, tool.Args...)
		cmd := exec.Command("cmd.exe", args...)
		cmd.Dir = cwd
		cmd.Env = env
		return cmd.Start()
	}

	// Linux / macOS fallback
	cmd := exec.Command(tool.Command, tool.Args...)
	cmd.Dir = cwd
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Start()
}

func printBanner(proxy *ProxyInfo) {
	fmt.Print("\033[H\033[2J") // Clear screen
	fmt.Println(colorCyan + colorBold + "========================================================" + colorReset)
	fmt.Println(colorCyan + colorBold + "             AI Runtime Manager (ARM) - CLI            " + colorReset)
	fmt.Println(colorCyan + colorBold + "========================================================" + colorReset)
	if proxy != nil && proxy.Port > 0 {
		fmt.Printf("  "+colorGreen+"● 当前代理:"+colorReset+" %s%s%s\n", colorBold, proxy.String(), colorReset)
	} else {
		fmt.Printf("  " + colorYellow + "○ 当前代理: 直连模式 (无本地代理)" + colorReset + "\n")
	}
	fmt.Println(colorGray + "--------------------------------------------------------" + colorReset)
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	proxy := detectLocalProxy()
	tools := getTools()

	for {
		printBanner(proxy)

		fmt.Println("  " + colorBold + "[1]" + colorReset + " 启动 Claude Code (" + colorCyan + "claude" + colorReset + ")")
		fmt.Println("  " + colorBold + "[2]" + colorReset + " 启动 Codex CLI   (" + colorCyan + "codex" + colorReset + ")")
		fmt.Println("  " + colorBold + "[3]" + colorReset + " 重新检测本地代理端口")
		fmt.Println("  " + colorBold + "[4]" + colorReset + " 手动设置代理地址/端口")
		fmt.Println("  " + colorBold + "[5]" + colorReset + " 切换为直连 (不使用代理)")
		fmt.Println("  " + colorBold + "[0]" + colorReset + " 退出")
		fmt.Println(colorGray + "--------------------------------------------------------" + colorReset)
		fmt.Print(colorYellow + "  > 请输入选项 [0-5]: " + colorReset)

		input, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		input = strings.TrimSpace(input)

		switch input {
		case "1":
			runToolFlow(reader, tools["claude"], proxy)
		case "2":
			runToolFlow(reader, tools["codex"], proxy)
		case "3":
			fmt.Println(colorCyan + "\n  正在扫描本地常用代理端口..." + colorReset)
			proxy = detectLocalProxy()
			if proxy != nil {
				fmt.Printf(colorGreen+"  [✓] 发现并应用代理: %s\n"+colorReset, proxy.String())
			} else {
				fmt.Println(colorYellow + "  [!] 未检测到运行中的代理，已切为直连模式" + colorReset)
			}
			time.Sleep(1 * time.Second)
		case "4":
			fmt.Print("\n  请输入代理端口 (如 55555 或 7890): ")
			portStr, _ := reader.ReadString('\n')
			portStr = strings.TrimSpace(portStr)
			if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p < 65536 {
				proxy = &ProxyInfo{
					Host:     "127.0.0.1",
					Port:     p,
					Protocol: "http",
					Name:     fmt.Sprintf("Custom Proxy :%d", p),
				}
				fmt.Printf(colorGreen+"  [✓] 已设置为: %s\n"+colorReset, proxy.String())
			} else {
				fmt.Println(colorRed + "  [x] 端口格式无效" + colorReset)
			}
			time.Sleep(1 * time.Second)
		case "5":
			proxy = nil
			fmt.Println(colorGreen + "  [✓] 已切换为直连模式" + colorReset)
			time.Sleep(800 * time.Millisecond)
		case "0", "q", "exit":
			fmt.Println("\n  再见！")
			return
		default:
			fmt.Println(colorRed + "  [!] 无效输入，请按回车重试..." + colorReset)
			time.Sleep(800 * time.Millisecond)
		}
	}
}

func runToolFlow(reader *bufio.Reader, tool *ToolConfig, proxy *ProxyInfo) {
	if tool == nil {
		return
	}

	currDir, _ := os.Getwd()
	defaultDir := tool.DefaultCwd
	if defaultDir == "" {
		defaultDir = currDir
	}

	fmt.Printf("\n  准备启动: %s%s%s\n", colorBold, tool.Display, colorReset)
	fmt.Printf("  默认工作目录: %s%s%s\n", colorCyan, defaultDir, colorReset)
	fmt.Print("  按 [Enter] 使用默认目录，或输入新路径: ")

	customDir, _ := reader.ReadString('\n')
	customDir = strings.TrimSpace(customDir)
	targetDir := defaultDir
	if customDir != "" {
		if fi, err := os.Stat(customDir); err == nil && fi.IsDir() {
			targetDir = customDir
		} else {
			fmt.Println(colorYellow + "  [!] 输入路径不存在，将回退使用默认路径" + colorReset)
		}
	}

	fmt.Printf(colorGreen+"  --> 正在新窗口拉起 %s ...\n"+colorReset, tool.Display)
	if err := launchTool(tool, proxy, targetDir); err != nil {
		fmt.Printf(colorRed+"  [x] 启动失败: %v\n"+colorReset, err)
	} else {
		fmt.Printf(colorGreen+"  [✓] %s 已成功启动并在独立窗口运行！\n"+colorReset, tool.Display)
	}

	fmt.Print(colorGray + "\n  按 [Enter] 返回主菜单..." + colorReset)
	_, _ = reader.ReadString('\n')
}
