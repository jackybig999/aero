package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Channel   string `json:"channel"`
	Message   string `json:"message"`
}

type RingLogger struct {
	mu      sync.RWMutex
	entries []LogEntry
	maxSize int
}

var (
	GlobalLogger = NewRingLogger(500)
)

func NewRingLogger(maxSize int) *RingLogger {
	if maxSize <= 0 {
		maxSize = 500
	}
	return &RingLogger{
		entries: make([]LogEntry, 0, maxSize),
		maxSize: maxSize,
	}
}

func (l *RingLogger) Log(level, channel, msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry := LogEntry{
		Timestamp: time.Now().Format("15:04:05.000"),
		Level:     level,
		Channel:   channel,
		Message:   msg,
	}

	if len(l.entries) >= l.maxSize {
		l.entries = append(l.entries[1:], entry)
	} else {
		l.entries = append(l.entries, entry)
	}
}

func (l *RingLogger) GetLogs() []LogEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	res := make([]LogEntry, len(l.entries))
	copy(res, l.entries)
	return res
}

func (l *RingLogger) Clear() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = l.entries[:0]
}

func (l *RingLogger) ExportToFile(filePath string) error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if filePath == "" {
		exe, _ := os.Executable()
		filePath = filepath.Join(filepath.Dir(exe), fmt.Sprintf("aero-os-%s.log", time.Now().Format("20060102-150405")))
	}

	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, e := range l.entries {
		line := fmt.Sprintf("[%s] [%s] [%s] %s\n", e.Timestamp, e.Level, e.Channel, e.Message)
		if _, err := f.WriteString(line); err != nil {
			return err
		}
	}
	return nil
}
