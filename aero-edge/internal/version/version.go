// Package version Edge 服务端语义化版本（冻结契约随大版本变更）。
package version

// Version 当前发布版本。小改小升，破坏性变更升 major。
const Version = "1.0.0"

// Protocol 主路径协议标识。
const Protocol = "aero/2.0"

// APILevel Admin/订阅/限制 运维契约级别；只增字段则升次版本。
const APILevel = 1
