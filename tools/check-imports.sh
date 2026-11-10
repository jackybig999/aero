#!/usr/bin/env bash
# 组件隔离门禁（PROJECT_RULES“目录布局”，ADR-0009）：
#   internal/<A> 不得 import internal/<B>；
#   cmd/<X> 只能 import 所属组件的 internal 包；
#   tests/ 不得 import 任何 internal 包（黑盒测试）。
# 对 linux、windows、darwin 三个 GOOS 分别检查，覆盖带构建标签的文件。
# 额外参数原样传给 go list（例如 -overlay）。
set -euo pipefail
cd "$(dirname "$0")/.."
mod=$(go list -m)

# cmd 名 -> 允许 import 的组件
component_of_cmd() {
  case "$1" in
    guard) echo client ;;
    *) echo "$1" ;;
  esac
}

fail=0
for goos in linux windows darwin; do
  while read -r pkg imports; do
    rel=${pkg#"$mod"/}
    case "$rel" in
      internal/*) own=${rel#internal/}; own=${own%%/*} ;;
      cmd/*) own=${rel#cmd/}; own=$(component_of_cmd "${own%%/*}") ;;
      tests/*) own="" ;;
      *) continue ;;
    esac
    for imp in $imports; do
      case "$imp" in
        "$mod"/internal/*) ;;
        *) continue ;;
      esac
      target=${imp#"$mod"/internal/}; target=${target%%/*}
      if [[ -z "$own" || "$target" != "$own" ]]; then
        echo "IMPORT_VIOLATION GOOS=$goos: $rel -> internal/$target"
        fail=1
      fi
    done
  done < <(GOOS=$goos go list "$@" -e -f '{{.ImportPath}} {{join .Imports " "}} {{join .TestImports " "}} {{join .XTestImports " "}}' ./...)
done

if [[ $fail -ne 0 ]]; then
  echo "组件隔离检查失败：组件之间只能通过 api/ 契约通信。" >&2
  exit 1
fi
echo "组件隔离检查通过（linux/windows/darwin）。"
