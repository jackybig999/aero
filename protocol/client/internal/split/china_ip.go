// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package split

import (
	_ "embed"
	"encoding/binary"
	"net"
	"sort"
	"strings"
)

//go:embed china_ip.txt
var chinaIPData string

// ipRange 表示一个连续的 IPv4 地址闭区间 [start, end]
type ipRange struct {
	start uint32
	end   uint32
}

// ChinaIPMatcher 基于 APNIC 权威统计的高性能中国大陆 IPv4 判定器。
// 底层使用紧凑的闭区间数组与 O(log N) 二分查找，单次判定仅需 ~10ns，零内存分配。
type ChinaIPMatcher struct {
	ranges []ipRange
}

// NewChinaIPMatcher 创建并初始化中国大陆 IP 匹配器
func NewChinaIPMatcher() *ChinaIPMatcher {
	m := &ChinaIPMatcher{}
	m.init(chinaIPData)
	return m
}

func (m *ChinaIPMatcher) init(data string) {
	lines := strings.Split(data, "\n")
	ranges := make([]ipRange, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, ipNet, err := net.ParseCIDR(line)
		if err != nil || ipNet.IP.To4() == nil {
			continue
		}
		ip4 := ipNet.IP.To4()
		mask := ipNet.Mask
		start := binary.BigEndian.Uint32(ip4)
		maskVal := binary.BigEndian.Uint32(mask)
		end := start | (^maskVal)
		ranges = append(ranges, ipRange{start: start, end: end})
	}

	// 按起始地址升序排列
	sort.Slice(ranges, func(i, j int) bool {
		return ranges[i].start < ranges[j].start
	})

	// 合并重叠或相邻的网段
	if len(ranges) > 0 {
		merged := make([]ipRange, 0, len(ranges))
		curr := ranges[0]
		for i := 1; i < len(ranges); i++ {
			if ranges[i].start <= curr.end+1 {
				if ranges[i].end > curr.end {
					curr.end = ranges[i].end
				}
			} else {
				merged = append(merged, curr)
				curr = ranges[i]
			}
		}
		merged = append(merged, curr)
		ranges = merged
	}
	m.ranges = ranges
}

// TotalRanges 返回合并后的有效网段数量
func (m *ChinaIPMatcher) TotalRanges() int {
	return len(m.ranges)
}

// Contains 检查给定 IP 是否属于中国大陆 IP 网段。
// 仅支持 IPv4；IPv6 或 nil 返回 false。
// 时间复杂度：O(log N)，内存分配：0 B/op。
func (m *ChinaIPMatcher) Contains(ip net.IP) bool {
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	v := binary.BigEndian.Uint32(ip4)
	idx := sort.Search(len(m.ranges), func(i int) bool {
		return m.ranges[i].end >= v
	})
	return idx < len(m.ranges) && m.ranges[idx].start <= v
}
