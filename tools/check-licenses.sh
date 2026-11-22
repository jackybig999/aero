#!/usr/bin/env bash
# 第三方依赖许可证检查（L0 §7.6、ADR-0018）。
# 对 linux、windows、darwin 三个平台，列出实际编入的第三方模块，读取其 LICENSE 文本判定许可证，
# 不在 tools/licenses-allowed.txt 白名单内（或无法判定且没有人工登记）则失败。
# 只用 go list 与模块自带的许可证文件，不依赖网络与第三方工具。
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
allowed_file="tools/licenses-allowed.txt"

declare -A allow override
while read -r kind a b _; do
  case "$kind" in
    allow) allow["$a"]=1 ;;
    override) override["$a"]="$b" ;;
  esac
done < <(grep -Ev '^\s*(#|$)' "$allowed_file")

# classify 读取许可证文件，输出 SPDX 标识；无法判定输出 UNKNOWN。
classify() {
  local f="$1"
  if grep -qiE 'GNU (AFFERO )?(LESSER )?GENERAL PUBLIC LICENSE' "$f"; then echo "GPL-family"
  elif grep -qi 'Mozilla Public License' "$f"; then echo "MPL-2.0"
  elif grep -qi 'Apache License' "$f" && grep -qi 'Version 2.0' "$f"; then echo "Apache-2.0"
  elif grep -qi 'Permission is hereby granted, free of charge' "$f"; then echo "MIT"
  elif grep -qi 'Permission to use, copy, modify, and/or distribute' "$f"; then echo "ISC"
  elif grep -qi 'Redistribution and use in source and binary forms' "$f"; then
    if grep -qiE 'Neither the name|endorse or promote' "$f"; then echo "BSD-3-Clause"; else echo "BSD-2-Clause"; fi
  else echo "UNKNOWN"
  fi
}

pkgs=(./cmd/... ./internal/...)
[[ -d tests ]] && pkgs+=(./tests/...)

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
for goos in linux windows darwin; do
  # -test 把测试代码的依赖也算进来
  GOOS="$goos" go list -deps -test -f '{{if .Module}}{{if not .Module.Main}}{{.Module.Path}} {{.Module.Version}} {{.Module.Dir}}{{end}}{{end}}' \
    "${pkgs[@]}" >>"$tmp"
done
sort -u "$tmp" -o "$tmp"

fail=0
count=0
while read -r mod ver dir; do
  count=$((count + 1))
  lic=""
  if [[ -n "${override[$mod]:-}" ]]; then
    lic="${override[$mod]}"
  else
    file=""
    for n in LICENSE LICENSE.md LICENSE.txt LICENCE COPYING COPYING.md; do
      [[ -f "$dir/$n" ]] && { file="$dir/$n"; break; }
    done
    if [[ -z "$file" ]]; then lic="NO-LICENSE-FILE"; else lic="$(classify "$file")"; fi
  fi
  if [[ -n "${allow[$lic]:-}" ]]; then
    printf 'ok    %-45s %-14s %s\n' "$mod" "$ver" "$lic"
  else
    printf 'FAIL  %-45s %-14s %s\n' "$mod" "$ver" "$lic"
    fail=1
  fi
done <"$tmp"

echo "checked $count third-party modules (linux, windows, darwin)"
if [[ "$fail" -ne 0 ]]; then
  echo "license check FAILED: 见上面 FAIL 行；核对后在 $allowed_file 登记 override，或移除该依赖" >&2
  exit 1
fi
echo "license check PASS"
