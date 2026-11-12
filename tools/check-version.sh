#!/usr/bin/env bash
# 版本统一门禁：所有组件（edge、中台、客户端、desk）与界面显示的版本必须等于仓库根目录 VERSION。
# 发版只改 VERSION 时，本检查列出所有需要同步的位置。
set -euo pipefail
cd "$(dirname "$0")/.."
v=$(tr -d ' \r\n' < VERSION)
[[ $v =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "VERSION 格式无效: $v"; exit 1; }

# 文件|grep -E 提取版本的模式（版本号位于唯一的捕获位置）
checks=(
  'internal/edge/admin.go|Version  = "[0-9.]+"'
  'cmd/sub/main.go|const Version = "[0-9.]+"'
  'internal/client/engine.go|ClientVersion = "[0-9.]+"'
  'deploy/edge-install.sh|^VERSION="[0-9.]+"'
  'deploy/aero|v[0-9]+\.[0-9]+\.[0-9]+'
  'cmd/sub/web/admin/dist/index.html|官方管控中台 v[0-9.]+'
  'cmd/sub/web/admin/dist/admin.js|release_tag\) \|\| .v[0-9.]+'
  'cmd/client/ui/index.html|>v[0-9.]+</span>'
  'cmd/desk/ui/index.html|v[0-9.]+ Workspace'
  'internal/edge/web/console.html|id="appVersion">v[0-9.]+'
)
fail=0
for c in "${checks[@]}"; do
  file=${c%%|*} pat=${c#*|}
  found=$(grep -oE "$pat" "$file" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | sort -u || true)
  if [ -z "$found" ]; then
    echo "未找到版本: $file（模式 $pat）"; fail=1
  elif [ "$found" != "$v" ]; then
    echo "版本不一致: $file 为 $(echo "$found" | tr '\n' ' ')，应为 $v"; fail=1
  fi
done
[ $fail -eq 0 ] && echo "版本统一检查通过（$v）"
exit $fail
