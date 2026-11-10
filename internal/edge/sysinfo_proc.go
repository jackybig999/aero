// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"bufio"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// CollectSysInfoFrom allows unit tests to sample metrics from a custom mock proc and root directory
func CollectSysInfoFrom(procDir, rootDir string) (*SystemMetrics, error) {
	metrics, _ := collectLinuxMetricsFrom(procDir, rootDir, nil)
	return metrics, nil
}

func collectLinuxMetricsFrom(procDir, rootDir string, prev *rawMetricsSample) (*SystemMetrics, *rawMetricsSample) {
	now := time.Now()
	m := &SystemMetrics{
		Platform:  "linux",
		SampledAt: now,
	}
	nextRaw := &rawMetricsSample{
		sampleAt: now,
	}

	// 1. CPU Usage from /proc/stat
	statPath := filepath.Join(procDir, "stat")
	if f, err := os.Open(statPath); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "cpu ") {
				fields := strings.Fields(line)
				if len(fields) >= 5 {
					var total, idle uint64
					for i := 1; i < len(fields); i++ {
						val, _ := strconv.ParseUint(fields[i], 10, 64)
						total += val
						if i == 4 { // idle
							idle += val
						} else if i == 5 { // iowait
							idle += val
						}
					}
					nextRaw.cpuTotal = total
					nextRaw.cpuIdle = idle

					if prev != nil && prev.cpuTotal > 0 && total >= prev.cpuTotal {
						deltaTotal := total - prev.cpuTotal
						deltaIdle := uint64(0)
						if idle >= prev.cpuIdle {
							deltaIdle = idle - prev.cpuIdle
						}
						if deltaTotal > 0 {
							deltaActive := deltaTotal
							if deltaIdle <= deltaTotal {
								deltaActive = deltaTotal - deltaIdle
							}
							m.CPUUsagePct = round2((float64(deltaActive) / float64(deltaTotal)) * 100.0)
						}
					} else if total > 0 {
						active := total
						if idle <= total {
							active = total - idle
						}
						m.CPUUsagePct = round2((float64(active) / float64(total)) * 100.0)
					}
					m.CPUUsagePercent = m.CPUUsagePct
				}
				break
			}
		}
		_ = f.Close()
	}

	// 2. Memory Usage from /proc/meminfo
	memPath := filepath.Join(procDir, "meminfo")
	if f, err := os.Open(memPath); err == nil {
		scanner := bufio.NewScanner(f)
		var memTotalKB, memFreeKB, memAvailKB, buffersKB, cachedKB uint64
		for scanner.Scan() {
			line := scanner.Text()
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			valStr := strings.TrimSpace(parts[1])
			valFields := strings.Fields(valStr)
			if len(valFields) == 0 {
				continue
			}
			valKB, _ := strconv.ParseUint(valFields[0], 10, 64)

			switch key {
			case "MemTotal":
				memTotalKB = valKB
			case "MemFree":
				memFreeKB = valKB
			case "MemAvailable":
				memAvailKB = valKB
			case "Buffers":
				buffersKB = valKB
			case "Cached":
				cachedKB = valKB
			}
		}
		_ = f.Close()

		if memTotalKB > 0 {
			var memUsedKB uint64
			if memAvailKB > 0 && memAvailKB <= memTotalKB {
				memUsedKB = memTotalKB - memAvailKB
			} else {
				nonUsed := memFreeKB + buffersKB + cachedKB
				if nonUsed <= memTotalKB {
					memUsedKB = memTotalKB - nonUsed
				}
			}
			m.MemoryTotalMB = memTotalKB / 1024
			m.MemTotalMB = m.MemoryTotalMB
			m.MemoryUsedMB = memUsedKB / 1024
			m.MemUsedMB = m.MemoryUsedMB
			if m.MemoryTotalMB >= m.MemoryUsedMB {
				m.MemoryFreeMB = m.MemoryTotalMB - m.MemoryUsedMB
			}
			m.MemFreeMB = m.MemoryFreeMB
			m.MemoryUsagePct = round2((float64(memUsedKB) / float64(memTotalKB)) * 100.0)
			m.MemUsagePercent = m.MemoryUsagePct
		}
	}

	// 3. Network Throughput from /proc/net/dev
	netPath := filepath.Join(procDir, "net", "dev")
	if f, err := os.Open(netPath); err == nil {
		scanner := bufio.NewScanner(f)
		var totalRx, totalTx uint64
		for scanner.Scan() {
			line := scanner.Text()
			colonIdx := strings.Index(line, ":")
			if colonIdx == -1 {
				continue
			}
			iface := strings.TrimSpace(line[:colonIdx])
			if iface == "lo" {
				continue
			}
			fields := strings.Fields(line[colonIdx+1:])
			if len(fields) >= 9 {
				rx, _ := strconv.ParseUint(fields[0], 10, 64)
				tx, _ := strconv.ParseUint(fields[8], 10, 64)
				totalRx += rx
				totalTx += tx
			}
		}
		_ = f.Close()

		m.NetRxBytes = totalRx
		m.NetTxBytes = totalTx
		m.NetTotalRxMB = round2(float64(totalRx) / (1024.0 * 1024.0))
		m.NetTotalTxMB = round2(float64(totalTx) / (1024.0 * 1024.0))
		nextRaw.rxBytes = totalRx
		nextRaw.txBytes = totalTx

		if prev != nil && prev.rxBytes > 0 && totalRx >= prev.rxBytes && prev.sampleAt.Before(now) {
			elapsed := now.Sub(prev.sampleAt).Seconds()
			if elapsed > 0 {
				m.NetRxRateKBps = round2(float64(totalRx-prev.rxBytes) / (1024.0 * elapsed))
				m.NetTxRateKBps = round2(float64(totalTx-prev.txBytes) / (1024.0 * elapsed))
			}
		}
	}

	// 4. Uptime from /proc/uptime
	uptimePath := filepath.Join(procDir, "uptime")
	if data, err := os.ReadFile(uptimePath); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			if upFloat, err := strconv.ParseFloat(fields[0], 64); err == nil && upFloat >= 0 {
				m.UptimeSeconds = uint64(upFloat)
				m.UptimeFormatted = FormatUptime(m.UptimeSeconds)
			}
		}
	}

	// 5. Load Average from /proc/loadavg
	loadPath := filepath.Join(procDir, "loadavg")
	if data, err := os.ReadFile(loadPath); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 3 {
			for i := 0; i < 3; i++ {
				if l, err := strconv.ParseFloat(fields[i], 64); err == nil {
					m.LoadAverage[i] = round2(l)
				}
			}
		}
	}

	// 6. Disk Usage
	statfsDiskUsage(rootDir, m)

	return m, nextRaw
}

func round2(val float64) float64 {
	if math.IsNaN(val) || math.IsInf(val, 0) {
		return 0.0
	}
	return math.Round(val*100) / 100
}
