package main

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
)

// 客户端在 Windows 上是窗口程序（-H windowsgui），没有控制台，日志默认无处可去。
// 这里把日志同时写入数据目录下的 client.log，供排查“已连接但网络不通”之类的问题。
//
// 日志里可能出现订阅链接（路径含令牌）或带完整 URL 的网络错误，所以写入前一律脱敏：
// URL 只保留 scheme 与主机，路径、查询串全部打码。

const (
	logFileName    = "client.log"
	logRotateBytes = 1 << 20 // 超过 1 MiB 则轮转，只保留一份旧日志
)

// urlPathRe 匹配 http(s)://主机[:端口] 之后的路径与查询串。
var urlPathRe = regexp.MustCompile(`(https?://[^/\s"'<>)]+)/[^\s"'<>)]*`)

// redactLogLine 把日志中的 URL 路径/查询串替换为 /…，保留 scheme 与主机便于定位。
func redactLogLine(p []byte) []byte {
	return urlPathRe.ReplaceAll(p, []byte("$1/…"))
}

// redactingWriter 在写入前脱敏。返回的 n 恒为原始长度，避免 log 包把脱敏造成的长度变化当作短写。
type redactingWriter struct{ w io.Writer }

func (r redactingWriter) Write(p []byte) (int, error) {
	if _, err := r.w.Write(redactLogLine(p)); err != nil {
		return 0, err
	}
	return len(p), nil
}

// tolerantWriter 忽略底层写入错误：窗口程序的 stderr 无效，不能因此让日志整体失败。
type tolerantWriter struct{ w io.Writer }

func (t tolerantWriter) Write(p []byte) (int, error) {
	_, _ = t.w.Write(p)
	return len(p), nil
}

// setupLogFile 打开 dir/client.log（0600，必要时轮转）并把标准日志输出指向它（headless 时同时写 stderr）。
// 失败时保持原有输出并返回错误，不影响客户端运行。
func setupLogFile(dir string, alsoStderr bool) (func(), error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return func() {}, err
	}
	path := filepath.Join(dir, logFileName)
	if fi, err := os.Stat(path); err == nil && fi.Size() > logRotateBytes {
		_ = os.Remove(path + ".1")
		_ = os.Rename(path, path+".1")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return func() {}, err
	}
	var out io.Writer = f
	if alsoStderr {
		out = io.MultiWriter(f, tolerantWriter{os.Stderr})
	}
	log.SetOutput(redactingWriter{out})
	return func() { _ = f.Close() }, nil
}
