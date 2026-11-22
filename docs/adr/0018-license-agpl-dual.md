# ADR-0018 许可证：AGPL-3.0-or-later，另发商业授权

状态：accepted（2026-11-22，用户决定：开源、个人免费、商业授权；选 AGPL-3.0）

## 背景
此前 93 个 Go 文件头写 Apache-2.0，仓库根目录无 LICENSE。Apache-2.0 允许任何人（含大企业）闭源商用与修改，与“个人免费、商业收费、防止被直接搬走”的目标冲突。另有 152 个 Go 文件没有许可证声明（18 个只有版权行、134 个无头）。

## 备选
1. 保持 Apache-2.0：不限制商用，排除。
2. AGPL-3.0-or-later 加商业授权（双许可）。
3. PolyForm Noncommercial：明确禁止商用，但不属于 OSI 意义的开源，社区与依赖兼容性较弱。
4. BUSL 等延迟开源许可：条款复杂，且到期后转为宽松许可，排除。

## 决定
选 2。
- 版权主体：**Aero AI System**；商业授权签约人：jacky；咨询邮箱写在 `LICENSING.md`（用户 2026-11-22 指定填写）。
- 全部 245 个 Go 文件头统一为两行：`// SPDX-License-Identifier: AGPL-3.0-or-later` 与 `// Copyright YYYY Aero AI System`（已有头的文件保留原年份，新补头的用 2026）。`//go:build` 行保持在最前。
- 根目录 `LICENSE` 放 GNU 官方 AGPL-3.0 全文；`LICENSING.md` 说明免费与需商业授权的情形；`CONTRIBUTING.md` 规定 CLA 建立前不接收外部代码。
- 商业授权由项目所有者另签；AGPL 第 13 条（网络交互须提供源码）覆盖自建节点和中台的 SaaS 化。
- 依赖许可证由 CI 检查：`tools/check-licenses.sh` 按 linux、windows、darwin 三个平台列出实际编入（含测试）的第三方模块，读其 LICENSE 文本判定，白名单在 `tools/licenses-allowed.txt`（MIT、Apache-2.0、BSD-2-Clause、BSD-3-Clause、ISC）。不使用 go-licenses：2026-11-22 试跑在 Go 1.27 上超时。

## 理由
AGPL 是真正的开源许可，个人自用与学习免费；大企业通常回避 AGPL，要闭源使用就需要购买商业授权。服务端与中台的网络使用条款能约束“改了不公开”的托管服务。

## 后果
- L0 §7.6 对 GPL/AGPL 的限制针对“进入闭源产物的依赖”；本项目自身是 AGPL，直接与传递依赖共 26 个模块（2026-11-22 脚本实测）全部为 MIT、BSD、ISC 宽松许可，可并入 AGPL 作品。
- 新增依赖的许可证必须在白名单内；GPL-2.0-only 与 AGPL-3.0 不兼容，弱 copyleft 逐个评审并写 ADR。
- 界面伪装站页脚与中台前端脚本里的旧主体名一并改为 Aero AI System。
- 历史版本：GitHub 上已有的版本均为测试版本，用户决定按现在的修改执行（2026-11-22）；已按 Apache-2.0 发布的旧版本，其授权不可追溯撤回，这一点不变。
- 本 ADR 不构成法律意见；正式的商业授权合同建议由律师审阅。

## 待办
- 接收外部贡献前建立 CLA（`CONTRIBUTING.md`）。
- `tmp/gate.sh` 未包含 `tools/check-licenses.sh`（`tmp/` 不入库）；本地需要时手动运行，CI 已包含。
- 商业授权合同模板、隐私声明（ADR-0017 质量回传）由所有者准备。
