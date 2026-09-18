# AERO 系统全面代码审查报告

> **审查时间**：2026-09-18  
> **覆盖范围**：`protocol/client`、`protocol/server`、`sub/vpn`、`connect` 全部核心模块  
> **审查方式**：直接读代码（不看文档），从设计、架构、代码质量、模块化、系统衔接等维度展开  
> **原则**：纯分析，不动任何文件

---

## 一、架构与设计层面

### ✅ 优点：三树解耦执行到位

三大子树（`protocol`、`sub`、`connect`）的物理隔离做到了：独立 `go.mod`、零跨树 import、只通过 HTTP/JSON 交互。这是最重要的架构纪律，执行良好。

### ✅ 优点：瘦客户端架构落地正确

客户端的角色分工是清晰的：

- 客户端 `split/isp.go` 做 DNS RTT 测速识别运营商 → 携带 `?isp=` 上报；
- 服务端 `snimatrix/matrix.go` 完成计算下发 SNI；
- 客户端直接使用下发结果拨号，零本地规则包。**设计正确。**

### ⚠️ 问题：`public` 包是一个臃肿的 "God Package"

[`protocol/client/public/`](file:///D:/jacky/gemini/aisys/protocol/client/public/) 目录下有 **22 个 Go 文件**，合计约 **120KB**：

| 文件 | 行数 |
|---|---|
| `engine.go` | 716 |
| `tunnel.go` | 660 |
| `tun.go` | 648 |
| `engine_dialer.go` | 607 |
| `engine_api.go` | 447 |
| `proxy_socks5.go` | ~500 |
| `proxy_http.go` | ~450 |
| `tunnel_relay.go` | ~350 |
| ... | ... |

**核心问题**：`engine.go` 里把 CLI flags（全局 `var`）、配置加载、订阅拉取、日志初始化、ISP 检测调度、TUN 刷新调度、进程代理环境清理全部揉在一起。这个包承担了「代理服务」、「TUN驱动」、「订阅管理」、「API层」、「连接探测」五个完全不同的职责，**已触发 God Package 红线（通常单包 >10 个文件、>3000 行是强烈信号）**。

### ⚠️ 问题：`engine.go` 里的全局变量是隐式状态机

`engine.go` 第 34-50 行有大量 package-level 全局 flag 指针（`listenAddr`、`edgeAddr`、`token`、`publicName` 等），并分散在多个文件中被直接读写：

```go
var (
    listenAddr  = flag.String(...)
    edgeAddr    = flag.String(...)
    token       = flag.String(...)
    publicName  = flag.String(...)
    ...
)
```

`engine_dialer.go`、`tunnel.go`、`tun.go` 中都直接操作这些全局指针，形成**隐式共享状态机**。并发读写依赖 `edgeAddrMu` 这个锁，但多处直接无锁访问（如 `dialEdgeTCP` 第 170 行 `addr := *edgeAddr`），存在**数据竞争风险**。

### ⚠️ 问题：订阅 `signature` 逻辑存在安全弱点

`engine.go` 第 556-560 行：

```go
if doc.Signature == "" {
    return nil, fmt.Errorf("subscription missing signature")
}
if !sub.Verify(doc, []byte(doc.Servers[0].Token)) {
    return nil, fmt.Errorf("subscription signature invalid")
}
```

**问题**：验签所用的密钥来自于订阅文档本身（`doc.Servers[0].Token`），而非预置在客户端的独立密钥。这意味着攻击者只要伪造一份 `{token: "foo", signature: HMAC("foo")}` 的订阅，就可以通过验证——**验签本身形同虚设，无法防止中间人替换节点**。真正的订阅签名应该用预置在客户端的固定密钥来验证，而不是用订阅内容自带的密钥。

---

## 二、代码质量层面

### ⚠️ `public` 包文件是多源合并产物，注释痕迹明显

`tunnel.go`、`engine_dialer.go` 内有大量 `// Source: xxx.go` 注释块，说明这些文件是从多个原始文件手工合并来的，**不是原生设计**，后期维护时极容易出现修改一处遗漏另一处的问题：

```
// Source: aero_stream.go
// Source: h2tunnel.go
// Source: tunnel_handshake.go
// Source: tunnel_heartbeat.go
// Source: tunnel_loop.go
```

应当恢复为各自独立文件，不要合并。

### ⚠️ `isAITraffic` 是硬编码字符串列表，维护繁重

`engine.go` 第 667-686 行：

```go
func isAITraffic(host string) bool {
    aiDomains := []string{
        "openai.com", "api.openai.com", "chatgpt.com", ...
        // 30+ 条硬编码
    }
```

- 这个列表**每次调用都重新创建**，每次 CONNECT 请求都分配一个新 slice，性能差；
- 注释说"权威来源：data/ai_services.json"，但实际上并未从 JSON 加载，**注释与实现矛盾**；
- 应改为启动时加载并编译为 `map` 或 `trie`。

### ⚠️ `sub/vpn/main.go` 包含大量与主程序不相关的直接路由注册

`main.go`（401 行）在主函数中直接注册了 `registerConfig`、`registerSync`、`registerSecurity`、`registerTestPay`、`registerStubs` 等函数，且这些函数的内部逻辑和状态也在 `main.go` 中定义（如 `configStore`、`agentState`）。

这是**职责边界被侵蚀**的典型：`main.go` 应该只负责装配（DI Container），业务逻辑应移入各自的 module。`configStore`、`agentState` 至少应移到对应的 internal 模块。

### 🔴 `sub/vpn/main.go` 中存在明文默认密码问题

```go
// main.go 第 126 行
hmacSecret := "dev-secret-change-me"

// main.go 第 300 行（seedAdmin 函数）
svc.Register(domain.CreateUserParams{
    Username: "admin", Password: "admin123", ...
})
```

**两个安全红线**：

1. HMAC 密钥有硬编码默认值，生产如果没配置 `HMAC_SECRET` 环境变量就会用弱密钥；
2. `seedAdmin` 每次启动都检查是否有 `admin` 用户，有则跳过——但没有任何机制强制首次启动时修改密码，`admin123` 可能永远不被改。

**建议**：应在首次启动时生成随机密码或强制要求环境变量传入初始密码，没有时直接 `log.Fatal`。

### ✅ 优点：VPS SSH 密码静态加密设计正确

`vps/service/service.go` 第 45-60 行：  
SSH 密码通过 `secret.Box`（AES-GCM）加密后再持久化，服务启动时要求 `SSH_CRED_KEY` 环境变量。**设计正确，落库无明文。**

### ⚠️ `snimatrix.Match` 的 region 解析太粗糙

`snimatrix/matrix.go` 第 149-164 行：

```go
func normalizeRegion(raw string) string {
    s := strings.ToUpper(strings.TrimSpace(raw))
    switch {
    case strings.Contains(s, "JP") || ...
```

`ServeSub` 调用时传入的是 `name + " " + host`（如 `"VPS-1 myconsun.de5.net"`），`normalizeRegion` 并不能从域名 `de5.net` 解析出区域（德国），而是依赖 node 的 Name 字段中包含 `DE` 关键字。

**这套 region 识别依赖命名约定，极不稳定**——操作员随便命名就可能导致 SNI 匹配落到 DEFAULT，完全无法感知。应在 `aero_endpoints.json` 的数据模型中增加显式的 `region` 字段（如 `"region": "DE"`）。

---

## 三、模块化与单向依赖原则

### ⚠️ `subscription/handler/http.go` 违反分层原则

`subscription/handler/http.go` 直接引入了：

- `userStore`（另一个模块的 Store 层）
- `aeroEndpoint`（vps 模块的 endpoint 层）
- `snimatrix`

**问题**：Handler 层按理只应依赖本模块的 Service 层，现在 handler 直接操作跨模块 Store，跳过了 Service 抽象，这破坏了分层纪律：

```go
type Handler struct {
    svc       *service.Service
    userStore userStore.Store       // 跨模块 Store 层
    epStore   *aeroEndpoint.Persist // 跨模块 Store 层
    sniMgr    *snimatrix.Manager
}
```

**正确做法**：应在 `subscription/service` 层封装 endpoint 的查询，并通过接口注入，handler 只依赖 `service.Service`。

### ⚠️ `middleware/gate.go` 中 ACL 白名单是硬编码

`gate.go` 第 68-119 行：认证白名单（哪些路由是公开的）完全写死为字符串比较，每次加新路由就得修改这个文件。**应使用路由中间件注解或注册模式**，否则随着路由增多极易出现遗漏。

### ✅ 优点：`edgepool.go` 并发控制设计良好

`edgepool.go`：`Pool` 的所有操作都通过 `sync.RWMutex` 保护，`ProbeAll` 并发探测但只写各节点独立字段，`FindServer` 返回值副本不持有锁，**无死锁风险，并发安全。**

---

## 四、系统衔接层面

### ⚠️ 客户端订阅格式 vs 中台下发格式存在 Schema 漂移风险

客户端解析订阅（`sub/sub.go`）的 `Subscription.Servers` 结构，与中台 `ServeSub` 下发的 JSON 字段（如 `servers[].address`、`servers[].token`、`servers[].sni`）。虽然目前字段一致，但两侧没有共享的 Schema 定义（因为跨树解耦不能共享结构体），完全依赖"字段名约定"。

**建议**：在独立文档中明确定义订阅 JSON Schema，双侧都参照文档，否则后续修改极易悄然破坏兼容性。

### 🔴 中台的 `billing`、`node`、`pay`、`ledger`、`settlement` 全部用内存 Store

```go
// main.go 第 177-185 行
billingSvc := billingS.New(billingStore.NewMemoryStore())
nodeSvc    := nodeS.New(nodeStore.NewMemoryStore())
subSvc     := subS.New(subStore.NewMemoryStore())
ledgerSvc  := ledgerS.New(ledgerStore.NewMemoryStore())
```

**重启即丢数据**。目前只有 `user`、`vps`、`aeroEndpoints` 有文件持久化。订阅数据、账单数据、节点状态在服务重启后会全部丢失，对于生产系统这是严重的数据持久化缺口。

### ✅ 优点：订阅拉取的多级 Failover 链设计完整

`sub/fetch.go` 的三级容灾链：

```
主URL → 缓存服务器列表备用URL → 本地最后一次成功订阅 → 报错
```

逻辑完整，且每次成功拉取都会更新 host IP 缓存（`dialWithHostCache`），即使 DNS 挂掉也能基于缓存 IP 直连。**这是工程亮点。**

### ⚠️ `h2Tunnel` 的 `closed` 字段非原子操作（数据竞争）

`tunnel.go` 第 200-288 行：

```go
type h2Tunnel struct {
    ...
    closed    bool    // ← 普通 bool，非原子
}

func (t *h2Tunnel) Read(...) {
    // 读 closed 无锁！
    if t.closed { return 0, ... }
```

`Read` 方法检查 `t.closed` 时没有持锁（而 `Write` 用了 `writeMu`），`Close` 方法持 `writeMu` 写 `t.closed`。当 `Read` 和 `Close` 并发执行时，存在 **data race**（Read 无锁读，Close 有锁写）。应改为 `atomic.Bool`（与 `aeroStreamConn` 保持一致）。

---

## 五、优先级问题汇总

| # | 严重程度 | 位置 | 问题描述 |
|---|---|---|---|
| 1 | 🔴 安全 | `engine.go:559` | 订阅验签用订阅自带 token，等于无效签名，无法防中间人攻击 |
| 2 | 🔴 安全 | `main.go:126,300` | `dev-secret-change-me` 弱 HMAC 密钥 + `admin123` 默认密码未强制更改 |
| 3 | 🔴 数据丢失 | `main.go:177-185` | billing/node/sub/ledger 全内存无持久化，重启清零 |
| 4 | 🟡 并发 BUG | `tunnel.go:205,216` | `h2Tunnel.closed` 非原子，Read/Close 存在数据竞争 |
| 5 | 🟡 安全性 | `gate.go:68-119` | ACL 白名单硬编码，扩展性差且易遗漏新路由 |
| 6 | 🟡 架构 | `subscription/handler/http.go` | Handler 跨模块直接依赖 Store，违反分层原则 |
| 7 | 🟡 性能 | `engine.go:667` | `isAITraffic` 每次 CONNECT 请求创建临时 slice，热路径低效 |
| 8 | 🟡 可维护 | `tunnel.go` / `engine_dialer.go` | 多源合并为单大文件，Source 注释掩盖结构混乱 |
| 9 | 🟡 可维护 | `snimatrix` | region 从节点 name 字符串推断，操作员命名不规范即失效 |
| 10 | 🔵 工程规范 | 两侧 | 订阅 JSON Schema 无文档，跨树兼容完全依赖"字段名约定" |

---

## 六、最优先要做的 3 件事

> 若后续要修改，按此顺序。

### 第一优先：安全红线修复（🔴）

1. **订阅验签**：引入预置 SPKI Pin 或服务端公钥对订阅文档签名，客户端用固定公钥验证，而非用订阅内 token 自验；
2. **禁止弱密钥启动**：`HMAC_SECRET` 未配置时直接 `log.Fatal`，不使用默认值；
3. **admin 初始密码**：首次启动随机生成并打印，或强制从环境变量注入，禁止 `admin123`。

### 第二优先：持久化补全（🔴）

- 为 `subscription`（用户专属订阅记录）增加文件持久化（参照 `user` 的 `FileStore` 实现），重启不丢用户订阅状态；
- `billing`、`ledger` 后续按业务需要逐步跟进。

### 第三优先：`public` 包拆分（🟡）

- 将 `tunnel.go`（`aeroStreamConn`、`h2Tunnel`、`aeroHandshake`、`heartbeat`、`serveTarget`）按职责分拆回独立文件；
- 将 `engine.go` 中的订阅相关逻辑提取为独立的 `subscription_manager.go`；
- `tun.go` 中的 sim 函数（`runDataPlaneSim`、`simHTTPS204` 等）移入测试或独立 `sim` 包；
- 消除或规范化隐式全局变量，考虑封装为 `EngineState` 结构体。

---

## 七、整体评分

| 维度 | 评分 | 说明 |
|---|---|---|
| 架构解耦 | ⭐⭐⭐⭐½ | 三树解耦、瘦客户端执行到位，`public` 包内聚差 |
| 安全性 | ⭐⭐⭐ | VPS 密码加密好，但签名逻辑和默认密码是安全漏洞 |
| 并发正确性 | ⭐⭐⭐⭐ | `edgepool` 优秀，`h2Tunnel` 有 data race |
| 代码可维护性 | ⭐⭐⭐ | 合并大文件、God Package、硬编码列表拉低评分 |
| 系统韧性 | ⭐⭐⭐⭐½ | Failover 链、EdgePool、心跳重试设计均属上乘 |
| 持久化完整性 | ⭐⭐½ | 核心业务数据（订阅/计费）无持久化是生产大隐患 |

**综合**：系统协议层设计扎实，工程实践上还差「最后一公里」——主要是安全配置硬编码和持久化缺口这两个必须在生产前修复的问题。
