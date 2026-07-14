# AERO Edge 发布与安装（阶段 A）

## 构建

```bash
cd aero-protocol
go build -o aero-edge ./aero-edge/cmd/aero-edge
go build -o aero-ech ./aero-ech/cmd/aero-ech
```

## 发布命名（install 下载约定）

```
aero-edge-linux-amd64
aero-edge-linux-arm64
```

上传到 GitHub Release `v2.0.0`（或修改 `install.sh` 中 `VERSION`/`REPO`）。

## 安装

```bash
# 有域名（Let's Encrypt）
sudo bash deploy/install.sh -d edge.example.com -b ./aero-edge

# 仅 IP（自签 + pin 写入 client-sub.json）
sudo bash deploy/install.sh -i 203.0.113.10 -p 443 -b ./aero-edge
```

数据目录固定：`/var/lib/aero`（`AERO_DATA_DIR`）

| 文件 | 说明 |
|------|------|
| `sub_meta.json` | secret + 完整 meta |
| `client-sub.json` | 客户端直接 `-sub` 导入 |

## 客户端

```bash
# 推荐：文件导入（含 pin_spki，自签可校验）
aero-ech -sub /var/lib/aero/client-sub.json

# 或 HTTPS 拉订阅（自签需 -insecure 除非只用 pin）
aero-ech -sub https://edge.example.com/sub/<secret>
```

有 `pin_spki` 时客户端自动钉扎，无需 `-insecure`。

## 注意

- **不监听 QUIC**（数据面未完成）
- 订阅 URL 与 `client-sub.json` **同源**（同一 data-dir）
