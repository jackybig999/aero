# 贡献说明

本项目按 AGPL-3.0-or-later 授权，同时由项目所有者（Aero AI System）另发商业授权（见 `LICENSING.md`、ADR-0018）。

## 现在能做什么
- **提交 Issue**：报告缺陷、提出建议，欢迎。
- **讨论方案与文档勘误**：欢迎，以 Issue 形式提出。

## 暂不接收外部代码
在贡献者许可协议（CLA）建立之前，**不合并任何外部代码**（Pull Request 会被关闭并说明原因）。原因：商业授权要求所有者对被授权代码拥有再授权权利，没有 CLA 就无法保证。

CLA 建立后，本文件会补充签署方式与流程。

## 提交前自检（项目成员）
`bash tmp/gate.sh` 必须输出 `GATE PASS`。新增依赖须写明理由，且许可证在 `tools/licenses-allowed.txt` 白名单内（ADR-0018）。
