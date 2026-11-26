// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sort"
	"time"
)

// 客户端自身资源的只读监控（诊断“风扇狂转”类问题）：
//   - 每 selfInterval 记一行 [SELF]：本进程 CPU（核数，含内核态）、其中 Go 垃圾回收占多少、协程数、堆大小。
//     CPU 低于 selfLogMinCPU 核时不记，避免空闲时刷屏；
//   - 本进程 CPU 连续两个周期不低于 selfProfileCPU 核时，自动抓一份 selfProfileFor 秒的 CPU 剖析与协程快照，
//     写到数据目录（cpu-时间.pprof、goroutines-时间.txt，0600），最多保留 selfKeepFiles 份、每 selfProfileGap 最多抓一次；
//     把这两个文件交给开发者，可以直接看到是哪段代码在耗 CPU。
//
// AERO_SELFMON=0 关闭。如果 [SELF] 显示本进程并不高，而风扇仍在转，说明耗 CPU 的是别的进程（任务管理器里看）。
const (
	selfInterval   = 10 * time.Second
	selfLogMinCPU  = 0.10
	selfProfileCPU = 0.50
	selfProfileGap = 10 * time.Minute
	selfKeepFiles  = 6
)

// selfProfileFor 是一次 CPU 剖析的时长（测试中会缩短）。
var selfProfileFor = 10 * time.Second

// StartSelfMonitor 启动自监控协程，ctx 取消时退出。dir 是数据目录（剖析文件写在这里）。
func StartSelfMonitor(ctx context.Context, dir string) {
	if os.Getenv("AERO_SELFMON") == "0" {
		return
	}
	go selfMonitor(ctx, dir)
}

func selfMonitor(ctx context.Context, dir string) {
	t := time.NewTicker(selfInterval)
	defer t.Stop()
	prevCPU, ok := processCPUSeconds()
	prevGC := goGCSeconds()
	prevAt := time.Now()
	hot := 0
	var lastProfile time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now := time.Now()
		cpu, okNow := processCPUSeconds()
		gc := goGCSeconds()
		wall := now.Sub(prevAt).Seconds()
		if !ok || !okNow || wall <= 0 {
			prevCPU, ok, prevGC, prevAt = cpu, okNow, gc, now
			continue
		}
		cores, gcCores := (cpu-prevCPU)/wall, (gc-prevGC)/wall
		prevCPU, prevGC, prevAt = cpu, gc, now
		if cores >= selfLogMinCPU {
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			log.Printf("[SELF] cpu=%.2f核 其中Go垃圾回收=%.2f核 协程=%d 堆=%dMB 系统内存=%dMB",
				cores, gcCores, runtime.NumGoroutine(), ms.HeapAlloc>>20, ms.Sys>>20)
		}
		if cores < selfProfileCPU {
			hot = 0
			continue
		}
		if hot++; hot < 2 || now.Sub(lastProfile) < selfProfileGap {
			continue
		}
		lastProfile = now
		captureProfile(ctx, dir)
		prevCPU, _ = processCPUSeconds() // 抓取期间的 CPU 不计入下一个周期
		prevGC, prevAt = goGCSeconds(), time.Now()
	}
}

// captureProfile 抓 selfProfileFor 的 CPU 剖析与协程快照；失败只记日志。
func captureProfile(ctx context.Context, dir string) {
	stamp := time.Now().Format("20060102-150405")
	cpuPath := filepath.Join(dir, "cpu-"+stamp+".pprof")
	f, err := os.OpenFile(cpuPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		log.Printf("[SELF] 无法写剖析文件: %v", err)
		return
	}
	if err := pprof.StartCPUProfile(f); err != nil {
		_ = f.Close()
		_ = os.Remove(cpuPath)
		log.Printf("[SELF] CPU 剖析启动失败: %v", err)
		return
	}
	log.Printf("[SELF] 本进程 CPU 持续偏高，开始抓取 %v 的 CPU 剖析: %s", selfProfileFor, cpuPath)
	select {
	case <-ctx.Done():
	case <-time.After(selfProfileFor):
	}
	pprof.StopCPUProfile()
	_ = f.Close()
	gPath := filepath.Join(dir, "goroutines-"+stamp+".txt")
	if g, err := os.OpenFile(gPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600); err == nil {
		_ = pprof.Lookup("goroutine").WriteTo(g, 1)
		_ = g.Close()
	}
	log.Printf("[SELF] 剖析完成: %s 与 %s（请一并交给开发者）", cpuPath, gPath)
	pruneProfiles(dir)
}

// pruneProfiles 只保留最新的 selfKeepFiles 份（cpu-*.pprof 与 goroutines-*.txt 各自计数）。
func pruneProfiles(dir string) {
	for _, pat := range []string{"cpu-*.pprof", "goroutines-*.txt"} {
		files, _ := filepath.Glob(filepath.Join(dir, pat))
		sort.Strings(files) // 文件名带时间戳，字典序即时间序
		for len(files) > selfKeepFiles {
			_ = os.Remove(files[0])
			files = files[1:]
		}
	}
}

// goGCSeconds 返回 Go 运行时累计花在垃圾回收上的 CPU 秒数；取不到返回 0。
func goGCSeconds() float64 {
	return readRuntimeMetric("/cpu/classes/gc/total:cpu-seconds")
}
