## AERO 1.5.0

### 服务端
- **DoH 重写为原样转发**：此前只解析 A 记录且只返回一个地址，MX、TXT、SRV、HTTPS 等类型和上游故障一律返回“无记录”，也不返回 NXDOMAIN。现在把查询原样转发给宿主 `/etc/resolv.conf` 的上游（截断时改用 TCP），所有记录类型与应答码保持不变；上游全部失败时返回 SERVFAIL。节点没有公网 IPv6 出口时 AAAA 返回空应答。
- **新增 `connect_ip` 开关**（`aero tunnel on|off`，默认开启）：关闭后不建 TUN、完全不修改宿主，只提供 TCP/UDP 代理与 DoH，适用于没有 TUN 的 VPS（此前这类机器无法启动）。
- **宿主转发准备失败时拒绝启动**：此前只记日志，隧道照常接受连接但出口不通。
- **订阅不再携带 token-HMAC 签名**（C5）：该签名不防伪，且字段不一致时会让客户端拒绝订阅。完整性由 HTTPS 严格证书校验保证。不再输出 `ech_config`（只输出 `ech`）。

### 客户端
- **按服务端的拒绝原因处理重连**：token 失效时立即重新拉取订阅换 token，并在本地停止向服务端发送注定失败的请求；认证失败的重试间隔至少 15 秒（此前快速重试会触发服务端 15 分钟的 IP 封禁）；被限流时按 `Retry-After` 等待；节点不可用时放慢重试。界面显示具体错误码。
- **休眠唤醒后及时刷新 token**：此前计时器在休眠期间不走，醒来后可能长时间使用已过期的 token。
- **Linux 客户端数据目录改为 `/var/lib/aero-client`**：此前与服务端共用 `/var/lib/aero`，同机运行时会覆盖服务端的规则库文件。

### 契约与测试
- 新增数据面契约 `api/dataplane.md`（C1/C2）与订阅契约 `api/subscription.md`（C5）。
- 新增黑盒端到端测试：真实服务端与客户端在隔离网络中验证 TCP、UDP、CONNECT-IP 全局隧道、服务端重启后重连、退出无残留；CI 必跑，不再静默跳过。

### 升级提示
- 节点上执行 `aero update`。客户端需同步升级以获得新的重连行为；旧客户端可继续使用（订阅仍接受旧字段）。

## AERO 1.4.4（上一版本）

- 修复 1.4.3 未生效的迁移（实机升级验证发现）：配置中由旧版本写入、位于 acme.sh/certbot 默认目录的证书路径，启动时按自动发现处理并从配置中清除；默认目录里按域名找不到时沿用配置的路径。
- `aero update` 执行安装脚本前，先按同一版本的 `SHA256SUMS` 校验安装脚本本身（此前只校验安装脚本下载的文件）。

## AERO 1.4.3（上一版本）

- edge 不再把自动发现的证书路径（acme.sh/certbot 默认目录）写入 `edge.json`，每次启动重新查找；升级后自动清除旧版本写入的路径。此前用 `aero domain` 换域名后，配置仍指向旧域名的证书，检查失败。显式配置的证书路径保持不变。
- `aero restart` 只认本次重启之后的启动日志，不再可能把 30 秒内上一次的启动误判为成功。

## AERO 1.4.2（上一版本）

### 卸载彻底还原（实机验证：卸载后与装机前快照一致）
- `aero warp install` 记录 WARP 依赖包新建的系统用户与组；`aero warp uninstall` 先停止 warp-svc，删除残留的 WARP 策略路由（fwmark 0x100cf），并删除这些用户与组（Debian 卸载软件包不删用户）。
- `aero cert` 安装 acme.sh 前备份 `.bashrc` 并记录 crontab 状态；`aero uninstall` 卸载 acme.sh 后只在与安装前精确对应时还原（删除 acme.sh 留下的空 crontab 与 `.bashrc` 末尾空行）。
- edge 还原宿主的日志分别说明 iptables 规则与 nft 表的删除情况。

### 已知
- Cloudflare 官方 `cloudflare-warp` 在 Debian 上硬依赖图形库，安装 WARP 会新增约 200 个软件包（约 760 MiB）；卸载时全部移除。

## AERO 1.4.1（上一版本）

### 安装只安装服务端，其余在服务器上用 aero 完成（ADR-0016 修订）
- `edge-install.sh` 重写：按版本下载并对照 `SHA256SUMS` 校验 aero-edge、运维命令 `aero` 与卸载脚本，写入服务单元；不写配置、不生成或打印密钥、不安装其他软件、不改系统。此前的脚本下载 `latest` 不校验、用 sed 改配置、允许并打印弱密钥。
- 新的 `aero` 命令：`aero setup` 依次完成域名、证书、可选 WARP、端口（默认 443，被占用自动轮试）、管理密钥，`aero-edge check` 全部通过后才启动服务；另有 `aero cert|warp|port|key|check|status|update|uninstall`。
- 可选安装项需要用户确认，只用官方来源：acme.sh（证书在默认目录）、Cloudflare WARP（proxy 模式，不改系统路由）。卸载时逐项询问，只移除 aero 安装的内容。
- edge 新增 `aero-edge config get|set` 与 `aero-edge check`；edge 的配置只由 edge 写入。
- 没有证书时 edge 不再崩溃重启，也不对外监听，等待 `aero setup`。
- 中台安装任务改为运行同一个 `edge-install.sh`，经 `aero-edge config` 写入域名与管理密钥（经标准输入，不出现在命令行），检查通过才启动；证书未就绪时提示在节点上执行 `aero setup`。卸载调用节点自带的卸载脚本。

### WARP 规则流量接管开关
- edge 控制台与中台只提供开关：关闭 / 仅 AI 场景 / 全部流量（中台经 C13）。删除中台“一键安装 WARP”。

### 其他
- 宿主没有 iptables（Debian 13 默认）时使用 edge 自有的 nft 表 `inet aero_edge`，停止时整表删除；此前这类宿主隧道出口不通，且还原会报错。
- 管理密钥短于 32 位时不启用远程管理接口（`aero key` 生成新密钥）。
- Release 附带 `aero`、`edge-install.sh`、`edge-uninstall.sh`，均列入 `SHA256SUMS`。
- 新增版本统一门禁：所有组件与界面版本必须等于 `VERSION`。

### 升级提示
- 1.4.0 节点升级：`curl -fsSLO https://github.com/jackybig999/aero/releases/download/v1.4.1/edge-install.sh` 并核对 `SHA256SUMS` 后执行；检查通过会自动重启。

## AERO 1.4.0（上一版本）

### 服务端与中台彻底解耦（ADR-0016）
- edge 与客户端独立部署、独立运行；没有中台也能完整工作。中台只经 GitHub Release 与 edge 接口管理节点，SSH 只用于安装、升级、卸载 edge 程序本身。
- 新增 edge 远程管理接口 C13（`/admin/v1/*`）：状态（含主机负载、证书、监听端口）、出口纯净度、计量开关、WARP 开关、重新加载证书、优雅重启。只认管理密钥（Authorization 头），未鉴权一律返回伪装站。默认开启，配置 `"remote_admin_v1": false` 可关闭。
- 中台的状态、诊断、主机指标、纯净度、证书、重启、刷新节点全部改为调用 C13，不再登录节点读取文件或执行命令。
- 删除 edge 旧管理接口 `/admin/status|version|reload|tokens|ech`；`/admin/subs` 暂时保留。旧 `/admin/*` 未鉴权时也返回伪装站（此前 403 暴露接口存在）。

### 安全修复（中台）
- 在中台删除节点或 VPS 记录不再 SSH 卸载节点上的 edge（此前还会 `pkill -9 -f aero` 与 `fuser -k 443/tcp`，可能误杀宿主上的 xray 等服务）。卸载必须走显式的卸载任务。
- 修复节点 IP 为空时删除一个节点会删除全部节点记录。
- 中台调用 edge 严格校验证书，密钥只放请求头（此前跳过校验，并把管理密钥放在 URL 与节点上的命令行里）。
- 删除伪造的节点 Token 接口与界面（列表是编造的，“新增/删除”从未作用于节点）。
- SSH 探测失败时不再伪造“运行中”。

### 证书：使用系统 acme.sh / certbot
- edge 在 acme.sh 与 certbot 的默认位置只读查找证书：支持通配符证书；只采用有效期内且私钥匹配的证书，多张时取最晚到期者；续期后自动热加载。
- 新增 `aero-edge check-cert -domain <域名>`。中台安装前用新版本做只读预检：证书已存在则跳过证书步骤；未安装 acme.sh/certbot 或没有证书时提示运维处理后重试，节点保持不变。
- 安装要求节点配置域名。

### 计量（C6）
- edge 按用户、按小时计量（`usage_api`，默认关闭），只读接口 `/v1/usage`、`/v1/status` 使用独立的计量只读密钥。
- 中台每 60 秒拉取，按自然月（UTC，每月 1 日清零）汇总到用户已用流量。
- 删除从未启用的 edge→中台推送计量代码。

### 签名 token（C3，默认关闭）
- edge 支持 Ed25519 签名 token（`auth_signed_token`）；设备数达上限时保留最新连接、断开最早的连接；地址租约按用户保持，token 轮换不断隧道。
- 中台可签发签名 token（`-signed-tokens`，默认关闭）；客户端在有效期剩余 25% 时刷新。
- 中台密码改为 argon2id，登录时自动迁移旧哈希。

### 升级提示
- edge 现在只接受有效期内的证书；若节点上只有已过期的证书，edge 将拒绝启动，请先用 acme.sh/certbot 续期。
- 升级后 C13 默认开启，中台即可管理已有节点（需要中台登记的管理密钥）。
- 只有 IP、没有域名的节点无法由中台安全管理（不会向无法校验身份的对端发送密钥）。

## AERO 1.3.2（上一版本）

### 服务端：退出、崩溃、重启都还原宿主（ADR-0012）
- edge 修改 `net.ipv4.ip_forward` 前把原值记入数据目录 `host-state.json`，退出时还原（此前只开不还）。
- 转发规则按标记 `aero_edge_default` 扫描删除，覆盖崩溃残留、出口网卡变化与旧版遗留的全局 MSS 规则。
- 新增 `aero-edge cleanup-host`：服务单元以 `ExecStopPost` 调用，进程崩溃后同样还原；edge 运行中拒绝执行。
- 宿主原本未开启转发时，追加只放行 aero 网卡的隔离规则，保持宿主原有语义。
- 只有 TUN 就绪后才修改宿主。

### 中台安装流程不再修改节点系统（安全修复）
- 修复：节点令牌曾为 `tok_<VPS 名称>`、管理密钥与订阅 secret 由时间戳生成，可被猜出。现为 128 位随机密钥，且不再出现在启动命令行。
- 删除：覆盖 `/etc/nftables.conf`、`iptables-save` 持久化、apt 安装软件、永久开放 UFW/firewalld、2083→443 重定向、覆盖 edge 的 `sub_meta.json`。
- 二进制按节点架构下载，并对照 Release 的 `SHA256SUMS` 校验；全新安装只写最小配置，已有配置不覆盖。防火墙仅检测并提示运维。
- 停用中台的 WARP 安装任务（曾以 `ufw allow 40000/tcp` 把 SOCKS5 代理对公网开放）。

### WARP 改为插件
- edge 删除 WARP 安装器，只读取本机官方客户端代理（127.0.0.1:40000）的状态；控制台开关持久化到配置文件，重启后保持。

### 其他
- Release 不再被重复构建覆盖，并附带 `SHA256SUMS`。

### 升级提示
- 服务单元需加入 `ExecStopPost=/usr/local/bin/aero-edge cleanup-host`（新安装自动包含）。
