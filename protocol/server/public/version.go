// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package public Edge 服务端语义化版本（冻结契约随大版本变更）。
package public

// Version 当前发布版本。小改小升，破坏性变更升 major。
const Version = "1.1.0"

// Protocol 主路径协议标识。
const Protocol = "aero/2.0"

// APILevel Admin/订阅/限制 运维契约级别；只增字段则升次版本。
const APILevel = 1
