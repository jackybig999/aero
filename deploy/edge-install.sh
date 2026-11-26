#!/usr/bin/env bash
# AERO Edge 安装/升级（只安装服务端本身，ADR-0016）
#
# 只做三件事：下载同一版本的发布物并按 SHA256SUMS 校验；安装 aero-edge、运维命令 aero 与卸载脚本；
# 写入 systemd 服务单元。不写 edge 配置、不安装其他软件、不改防火墙与内核参数、不生成或打印密钥。
# 证书、WARP、端口、管理密钥等在安装后由 `aero setup` 在本机完成，检查通过后再启动服务。
#
# 用法：bash edge-install.sh            # 安装本脚本对应版本
#       AERO_VERSION=1.4.1 bash edge-install.sh
set -euo pipefail

REPO="jackybig999/aero"
VERSION="1.8.2"
VERSION="${AERO_VERSION:-$VERSION}"
BIN=/usr/local/bin/aero-edge
CLI=/usr/local/bin/aero
LIBDIR=/usr/local/lib/aero
UNIT=/etc/systemd/system/aero-edge.service
CONFIG=/etc/aero/edge.json

die() { echo "错误: $*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die "需要 root 权限"
command -v systemctl >/dev/null || die "需要 systemd"
command -v curl >/dev/null || die "需要 curl"
command -v sha256sum >/dev/null || die "需要 sha256sum"
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "不支持的架构 $(uname -m)" ;;
esac

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
BASE="https://github.com/${REPO}/releases/download/v${VERSION}"
echo "[1/3] 下载 AERO Edge v${VERSION}（${ARCH}）并校验..."
for f in "edge_linux_${ARCH}" aero edge-uninstall.sh SHA256SUMS; do
  curl -fsSL --retry 3 -o "$TMP/$f" "$BASE/$f" || die "下载 $f 失败"
done
( cd "$TMP"
  for f in "edge_linux_${ARCH}" aero edge-uninstall.sh; do
    line=$(awk -v n="$f" '$2==n || $2=="*"n' SHA256SUMS)
    [[ -n "$line" ]] || die "SHA256SUMS 中没有 $f"
    echo "$line" | sha256sum -c --quiet - || die "$f 校验失败"
  done )
chmod 0755 "$TMP/edge_linux_${ARCH}"
GOT=$("$TMP/edge_linux_${ARCH}" -version | awk '{print $2}')
[[ "$GOT" == "$VERSION" ]] || die "程序版本 $GOT 与 $VERSION 不一致"

echo "[2/3] 安装程序..."
UPGRADE=0
systemctl is-active --quiet aero-edge 2>/dev/null && UPGRADE=1
install -d -m 0755 "$LIBDIR"
install -m 0755 "$TMP/edge_linux_${ARCH}" "$BIN.new" && mv -f "$BIN.new" "$BIN"
install -m 0755 "$TMP/aero" "$CLI"
install -m 0755 "$TMP/edge-uninstall.sh" "$LIBDIR/edge-uninstall.sh"
install -d -m 0700 /etc/aero

echo "[3/3] 写入 systemd 服务单元..."
cat > "$UNIT" <<'UNIT'
[Unit]
Description=AERO Edge Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/aero-edge -config /etc/aero/edge.json
# 退出（含崩溃）后还原宿主：删除 edge 自己的转发规则、还原 ip_forward（ADR-0012）
ExecStopPost=/usr/local/bin/aero-edge cleanup-host -config /etc/aero/edge.json
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload

if [[ $UPGRADE -eq 1 ]]; then
  if "$BIN" check -config "$CONFIG"; then
    systemctl restart aero-edge
    echo "已升级到 v${VERSION} 并重启服务。"
    echo "提示：往返长、有随机丢包的链路上网页/下载/AI 很慢时，执行 aero cc lossy 开启对随机丢包不敏感的拥塞控制；aero cc cubic 回退。"
  else
    echo "已升级到 v${VERSION}，但检查未通过，服务保持运行旧进程；修复后执行: aero restart"
  fi
else
  echo "已安装 AERO Edge v${VERSION}。服务尚未启动。"
  echo "下一步：输入 aero 打开功能菜单，选 1「配置向导」（域名、证书、可选 WARP、端口、管理密钥），检查通过后自动启动服务。"
  echo "也可直接运行 aero setup；aero help 查看全部命令。"
fi
