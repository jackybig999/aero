// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package sub

// SnapshotKey 用于热更比对：地址列表 + 主 token + 主 SNI
func (a *Applied) SnapshotKey() string {
	if a == nil {
		return ""
	}
	return a.EdgeAddresses + "|" + a.PrimaryToken + "|" + a.PrimarySNI
}

// SameRouting 路由相关字段是否与另一份相同（忽略 Opt 等）
func (a *Applied) SameRouting(other *Applied) bool {
	if a == nil || other == nil {
		return a == other
	}
	return a.SnapshotKey() == other.SnapshotKey()
}
