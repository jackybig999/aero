# ADR-0010 edge 本地用户库：与中台字段对齐，互不依赖

状态：accepted（2026-11-10，用户决定）

## 背景
用户要求服务端具备基本的用户操作，数据模型与中台对齐，但服务端的订阅不能依赖中台，否则中台故障时节点无法发放订阅，形成死结。同时 ADR-0001 规定 sub 不写 edge、edge 不调用 sub。现状：edge 用户分散在 sub_meta.json（UserSubs）与 tokens.json；中台 user 与 subscription 表重复保存 slug/token，traffic 表与 subscription.used_bytes 重复。

## 备选
1. edge 镜像中台全部用户（需要中台推送或 edge 拉取用户表）：运行时耦合，违反 ADR-0001，中台故障影响节点。
2. edge 不保存用户，订阅全部由中台提供：中台故障即无法订阅，正是要避免的死结。
3. edge 只保存本地用户（iss=edge），本地签发 token、本地提供订阅；中台用户由中台签名 token（C3），edge 离线验签，不留副本。两边字段语义一致。

## 理由
选 3。两条签发路径互不依赖：中台故障时，本地用户不受影响，中台签发的 token 在有效期内继续可用。字段语义一致，中台日后可原样导入或展示节点本地用户。

## 后果
- edge 本地用户存于 SQLite（ADR-0008），表字段：uid、username、slug、tier、classes、max_devices、quota_bytes、used_bytes、bw_bps、expire_at、status、created_at、updated_at。不存邮箱、手机等个人信息（§6.11 最小化）。
- 与中台 subscription 的映射：uid↔user_uuid，slug↔sub_slug，tier↔plan_name，quota_bytes↔limit_bytes，used_bytes↔used_bytes，expire_at、status 同名；classes、max_devices、bw_bps 由中台定义档位时补齐。
- 计量（C6）对两类用户一视同仁，按 uid 与 iss 区分。
- 迁移：首次启动时把 sub_meta.json 的 UserSubs 与 tokens.json 导入 SQLite，原文件归档（PROJECT_RULES：破坏性变更先归档）。
- 管理员订阅改为一个本地 admin 用户（tier=admin，不限量），取代 /sub/{secret} 过渡方案。
