<template>
  <div class="layout" :class="{ collapsed }">
    <!-- 左侧导航（可折叠） -->
    <aside class="sidebar">
      <div class="brand">
        <div class="brand-mark">A</div>
        <div class="brand-text">
          <div class="brand-title">VPN 中台</div>
          <div class="brand-sub">管理后台</div>
        </div>
      </div>
      <nav class="menu">
        <button
          v-for="t in tabs"
          :key="t.id"
          type="button"
          class="menu-item"
          :class="{ active: tab === t.id }"
          :title="t.label"
          @click="switchTab(t)"
        >
          <el-icon class="mi"><component :is="t.icon" /></el-icon>
          <span class="menu-label">{{ t.label }}</span>
        </button>
      </nav>
      <div class="sidebar-foot">
        <button type="button" class="collapse-btn" :title="collapsed ? '展开菜单' : '收起菜单'" @click="toggleSidebar">
          <el-icon><Fold v-if="!collapsed" /><Expand v-else /></el-icon>
          <span class="menu-label">{{ collapsed ? '展开' : '收起' }}</span>
        </button>
        <div class="foot-note muted">v1 · 半成品演示</div>
      </div>
    </aside>

    <!-- 右侧 -->
    <div class="main-wrap">
      <header class="topbar">
        <div class="top-left">
          <el-button class="fold-btn" text @click="toggleSidebar" :title="collapsed ? '展开菜单' : '收起菜单'">
            <el-icon :size="18"><Fold v-if="!collapsed" /><Expand v-else /></el-icon>
          </el-button>
          <div class="page-title">{{ currentTitle }}</div>
        </div>
        <div class="top-actions">
          <el-segmented v-model="themeMode" :options="themeOptions" size="small" @change="onThemeChange" />
          <span class="user-chip">{{ user?.username || 'admin' }}</span>
          <el-button size="small" @click="load">刷新</el-button>
          <el-button size="small" type="danger" plain @click="logout">退出</el-button>
        </div>
      </header>

      <main class="content">
        <!-- 总览 -->
        <div v-show="tab === 'dash'">
          <el-row :gutter="12">
            <el-col :span="6" v-for="s in stats" :key="s.l">
              <div class="stat-card">
                <div class="sl">{{ s.l }}</div>
                <div class="sv">{{ s.v }}</div>
              </div>
            </el-col>
          </el-row>
          <el-row :gutter="12" style="margin-top: 16px">
            <el-col :span="12">
              <el-card shadow="never" class="panel-card">
                <template #header>
                  <div class="card-hd">
                    <span>系统运行状态</span>
                    <div class="card-hd-right">
                      <span class="muted">点击分组展开</span>
                      <el-tag size="small" :type="coreDown ? 'danger' : 'success'">
                        {{ coreDown ? '部分异常' : '运行正常' }}
                      </el-tag>
                    </div>
                  </div>
                </template>
                <div v-if="!svcGroups.length" class="muted">暂无数据（请确认 platform 单端口已启动）</div>
                <el-collapse v-else v-model="svcOpen" class="svc-collapse">
                  <el-collapse-item v-for="g in svcGroups" :key="g.title" :name="g.title">
                    <template #title>
                      <div class="collapse-title">
                        <span>{{ g.title }}</span>
                        <el-tag size="small" :type="g.down ? 'danger' : 'success'" effect="plain">
                          {{ g.ok }}/{{ g.total }}
                        </el-tag>
                      </div>
                    </template>
                    <div v-for="sv in g.items" :key="sv.name" class="row">
                      <span>{{ sv.label }}</span>
                      <el-tag :type="sv.status === 'ok' ? 'success' : 'danger'" size="small">
                        {{ sv.status === 'ok' ? '正常' : '异常' }}
                      </el-tag>
                    </div>
                  </el-collapse-item>
                </el-collapse>
              </el-card>
            </el-col>
            <el-col :span="12">
              <el-card shadow="never" class="panel-card" header="今日账本">
                <div class="row"><span>入账</span><b>${{ (Number(ledger.total_in_cents || 0) / 100).toFixed(2) }}</b></div>
                <div class="row"><span>出账</span><b>${{ (Number(ledger.total_out_cents || 0) / 100).toFixed(2) }}</b></div>
                <div class="row"><span>笔数</span><b>{{ ledger.entry_count || 0 }}</b></div>
              </el-card>
            </el-col>
          </el-row>
        </div>

        <!-- 用户：管理员 / 订阅用户 分开 -->
        <div v-show="tab === 'users'">
          <div class="toolbar">
            <el-radio-group v-model="userKind" size="default">
              <el-radio-button value="staff">管理员 ({{ staffUsers.length }})</el-radio-button>
              <el-radio-button value="sub">订阅用户 ({{ subUsers.length }})</el-radio-button>
            </el-radio-group>
            <el-button type="primary" @click="openUserDlg()">
              {{ userKind === 'staff' ? '新增管理员' : '新增订阅用户' }}
            </el-button>
            <el-button v-if="userKind === 'sub'" :loading="syncingSubs" @click="broadcastAllSubs">
              一键同步用户凭证至所有 Edge VPS
            </el-button>
          </div>
          <el-card shadow="never" class="panel-card">
            <el-table :data="filteredUsers" stripe :empty-text="userKind === 'staff' ? '暂无管理员' : '暂无订阅用户'">
              <el-table-column prop="id" label="ID" width="70" />
              <el-table-column prop="username" label="用户名" width="120" />
              <el-table-column v-if="userKind === 'sub'" label="专属 Slug" min-width="160">
                <template #default="{ row }">
                  <el-tag size="small" type="success">{{ row.sub_slug || '未生成' }}</el-tag>
                </template>
              </el-table-column>
              <el-table-column v-if="userKind === 'sub'" label="到期时间" min-width="160">
                <template #default="{ row }">
                  {{ row.expire_at ? fmt(row.expire_at) : '长期有效' }}
                </template>
              </el-table-column>
              <el-table-column prop="email" label="邮箱" min-width="140" />
              <el-table-column label="类型" width="100">
                <template #default="{ row }">
                  <el-tag :type="row.is_staff ? 'warning' : 'primary'" size="small">
                    {{ row.is_staff ? '管理员' : '订阅用户' }}
                  </el-tag>
                </template>
              </el-table-column>
              <el-table-column label="状态" width="80">
                <template #default="{ row }">
                  <el-tag :type="row.status ? 'success' : 'danger'" size="small">{{ row.status ? '正常' : '停用' }}</el-tag>
                </template>
              </el-table-column>
              <el-table-column label="操作" :width="userKind === 'sub' ? 260 : 180" fixed="right">
                <template #default="{ row }">
                  <el-button v-if="!row.is_staff && row.sub_slug" size="small" type="primary" plain @click="copySubLink(row)">
                    复制订阅
                  </el-button>
                  <el-button size="small" @click="editUser(row)">编辑</el-button>
                  <el-button size="small" type="danger" @click="delUser(row.id)">删除</el-button>
                </template>
              </el-table-column>
            </el-table>
          </el-card>
        </div>

        <!-- VPS 主机与部署 -->
        <!-- VPS 模块：仅资产/集群，不装 AERO -->
        <div v-show="tab === 'vps'">
          <el-alert
            type="info"
            :closable="false"
            show-icon
            style="margin-bottom: 12px"
            title="本页只管理 VPS 机器（登记/探测/密码）。安装 AERO 请到左侧「AERO」模块，两模块通过 HTTP 接口协作。"
          />
          <div class="toolbar">
            <el-button type="primary" @click="openVpsDlg">添加 VPS</el-button>
            <el-button @click="refreshVpsAll" :loading="vpsRefreshing">刷新探测</el-button>
            <el-switch v-model="vpsAutoProbe" active-text="自动探测" inactive-text="" style="margin-left: 8px" />
            <span class="muted">仅 CPU/内存等 · 删除只去掉中台登记，不卸 Edge</span>
          </div>

          <el-empty v-if="!vpsList.length" description="尚未登记 VPS" />

          <div v-for="v in vpsList" :key="v.id" class="vps-card">
            <div class="vps-card-hd">
              <div class="vps-id">
                <el-tag size="small" effect="dark" type="info">{{ v.role || 'node' }}</el-tag>
                <span class="vps-name">{{ v.name }}</span>
                <el-tag size="small" :type="vpsStatusType(v.status)">{{ vpsStatusLabel(v.status) }}</el-tag>
              </div>
              <div class="vps-actions">
                <el-button size="small" :loading="probingId === v.id" @click="probeVps(v)">探测状态</el-button>
                <el-button size="small" @click="updateVpsPassword(v)">改密码</el-button>
                <el-button size="small" type="danger" plain @click="delVps(v.id)">删除登记</el-button>
              </div>
            </div>
            <div class="vps-meta">
              <span>{{ v.ssh_username }}@{{ v.ip }}:{{ v.ssh_port }}</span>
              <span v-if="v.domain">· {{ v.domain }}</span>
              <span v-if="v.metrics?.latency_ms != null">· 延迟 {{ v.metrics.latency_ms }}ms</span>
              <span v-if="v.metrics?.os">· {{ v.metrics.os }}/{{ v.metrics.arch }}</span>
              <span v-if="v.last_probe_at" class="muted">· 探测 {{ fmt(v.last_probe_at) }}</span>
            </div>

            <div v-if="v.metrics && v.metrics.probe_ok" class="metric-grid">
              <div class="metric-item" :class="metricLevel(v.metrics.cpu_percent)">
                <div class="metric-label">CPU</div>
                <div class="metric-value">{{ fmtNum(v.metrics.cpu_percent) }}%</div>
                <el-progress :percentage="clampPct(v.metrics.cpu_percent)" :show-text="false" :stroke-width="6" :status="progStatus(v.metrics.cpu_percent)" />
              </div>
              <div class="metric-item" :class="metricLevel(v.metrics.mem_percent)">
                <div class="metric-label">内存</div>
                <div class="metric-value">{{ fmtNum(v.metrics.mem_percent) }}%</div>
                <div class="metric-sub">{{ fmtNum(v.metrics.mem_used_mb) }} / {{ fmtNum(v.metrics.mem_total_mb) }} MB</div>
                <el-progress :percentage="clampPct(v.metrics.mem_percent)" :show-text="false" :stroke-width="6" :status="progStatus(v.metrics.mem_percent)" />
              </div>
              <div class="metric-item" :class="metricLevel(v.metrics.disk_percent)">
                <div class="metric-label">磁盘</div>
                <div class="metric-value">{{ fmtNum(v.metrics.disk_percent) }}%</div>
                <div class="metric-sub">{{ fmtNum(v.metrics.disk_used_gb) }} / {{ fmtNum(v.metrics.disk_total_gb) }} GB</div>
                <el-progress :percentage="clampPct(v.metrics.disk_percent)" :show-text="false" :stroke-width="6" :status="progStatus(v.metrics.disk_percent)" />
              </div>
              <div class="metric-item">
                <div class="metric-label">负载 Load</div>
                <div class="metric-value sm">{{ fmtNum(v.metrics.load_1, 2) }}</div>
                <div class="metric-sub">5m {{ fmtNum(v.metrics.load_5, 2) }} · 15m {{ fmtNum(v.metrics.load_15, 2) }}</div>
              </div>
              <div class="metric-item">
                <div class="metric-label">网络</div>
                <div class="metric-value sm">↓{{ fmtNum(v.metrics.net_rx_mbps, 2) }}</div>
                <div class="metric-sub">↑ {{ fmtNum(v.metrics.net_tx_mbps, 2) }} Mbps</div>
              </div>
              <div class="metric-item">
                <div class="metric-label">运行时间</div>
                <div class="metric-value sm">{{ fmtUptime(v.metrics.uptime_sec) }}</div>
                <div class="metric-sub">来源 {{ v.metrics.source || 'ssh' }}</div>
              </div>
            </div>
            <div v-else class="metric-empty">
              <span class="muted">
                {{ v.metrics?.probe_error ? ('探测失败：' + v.metrics.probe_error) : '尚未采集运行状态，点击「探测状态」或开启自动探测' }}
              </span>
            </div>

          </div>
        </div>

        <!-- AERO：嵌入模块化 webui（同源 /aero-ui，源码在 aero/webui，可独立部署到 VPS） -->
        <div v-show="tab === 'aero'" class="aero-embed-wrap">
          <el-alert
            type="info"
            :closable="false"
            show-icon
            style="margin-bottom: 8px"
            title="模块化 AERO Console（aero/webui）。中台多 VPS 部署 + 订阅/Token；同一套 UI 也可在独立 VPS 用 aero-panel 运行。"
          />
          <iframe
            class="aero-embed"
            src="/aero-ui/?mode=mid&embed=1"
            title="AERO Console"
          />
        </div>

        <!-- 节点 -->
        <div v-show="tab === 'nodes'">
          <div class="toolbar">
            <el-button type="primary" @click="openNodeDlg">手动登记节点</el-button>
            <el-button @click="syncNodesWithVps" :loading="nodeSyncing">刷新并校验联动</el-button>
            <el-button v-if="orphanNodes.length" type="warning" @click="cleanOrphanNodes">
              清理失联节点 ({{ orphanNodes.length }})
            </el-button>
            <span class="muted">删除 VPS 会自动删关联节点并清理订阅；失联节点可一键清理</span>
          </div>
          <el-alert
            v-if="orphanNodes.length"
            type="warning"
            :closable="false"
            show-icon
            style="margin-bottom: 12px"
            :title="`有 ${orphanNodes.length} 个节点找不到对应 VPS（可能删 VPS 时未联动），请点「清理失联节点」`"
          />
          <el-empty v-if="!nlist.length" description="暂无节点 — 请到 VPS 页部署" />
          <el-card v-else shadow="never" class="panel-card">
            <el-table :data="nlist" stripe size="small">
              <el-table-column prop="id" label="ID" width="60" />
              <el-table-column prop="name" label="名称" />
              <el-table-column label="地址" min-width="140">
                <template #default="{ row }">{{ row.ip }}:{{ row.port }}</template>
              </el-table-column>
              <el-table-column prop="protocol" label="协议" width="80" />
              <el-table-column label="VPS" width="100">
                <template #default="{ row }">
                  <el-tag v-if="isOrphanNode(row)" size="small" type="danger">失联</el-tag>
                  <span v-else>#{{ row.vps_id || '—' }}</span>
                </template>
              </el-table-column>
              <el-table-column label="状态" width="90">
                <template #default="{ row }">
                  <el-tag :type="nodeDisplayOnline(row) ? 'success' : 'info'" size="small">
                    {{ nodeDisplayOnline(row) ? '在线' : (isOrphanNode(row) ? '失联' : '离线') }}
                  </el-tag>
                </template>
              </el-table-column>
              <el-table-column label="订阅/容量" width="110">
                <template #default="{ row }">
                  <span :class="{ 'cap-warn': subCount(row.id) >= (row.max_users || 100) * 0.9 }">
                    {{ subCount(row.id) }}/{{ row.max_users || 100 }}
                  </span>
                </template>
              </el-table-column>
              <el-table-column label="操作" width="160">
                <template #default="{ row }">
                  <el-button size="small" :disabled="isOrphanNode(row)" @click="hb(row.id)">心跳</el-button>
                  <el-button size="small" type="danger" @click="delNode(row.id)">删除</el-button>
                </template>
              </el-table-column>
            </el-table>
          </el-card>
        </div>

        <!-- 订阅：给「订阅用户」开节点访问（一用户可多条，一节点可多人） -->
        <div v-show="tab === 'subs'">
          <el-alert
            type="info"
            :closable="false"
            show-icon
            style="margin-bottom: 12px"
            title="订阅 = 用户专属凭据，绑定某个节点。同一节点可挂很多用户。"
          />
          <div class="toolbar">
            <el-button type="primary" @click="openSubDlg">开通订阅</el-button>
            <span class="muted">订阅用户 {{ subUsers.length }} 人 · 在线节点 {{ onlineNodes.length }} 个</span>
          </div>
          <el-card shadow="never" class="panel-card">
            <el-table :data="slist" stripe empty-text="暂无订阅，请先为订阅用户开通">
              <el-table-column prop="id" label="ID" width="60" />
              <el-table-column label="用户" width="120">
                <template #default="{ row }">{{ userName(row.user_id) }}</template>
              </el-table-column>
              <el-table-column label="节点" min-width="140">
                <template #default="{ row }">
                  {{ row.node_name || nodeName(row.node_id) }}
                  <span class="muted"> #{{ row.node_id }}</span>
                </template>
              </el-table-column>
              <el-table-column prop="client_uuid" label="客户端 UUID" min-width="200" show-overflow-tooltip />
              <el-table-column label="到期" width="160">
                <template #default="{ row }">{{ fmt(row.expire_date) }}</template>
              </el-table-column>
              <el-table-column label="状态" width="80">
                <template #default="{ row }">
                  <el-tag size="small" :type="subActive(row) ? 'success' : 'info'">{{ subActive(row) ? '有效' : '过期' }}</el-tag>
                </template>
              </el-table-column>
              <el-table-column label="操作" width="180" fixed="right">
                <template #default="{ row }">
                  <el-button size="small" @click="copySubCfg(row)">复制配置</el-button>
                  <el-button size="small" type="danger" @click="delSub(row.id)">删除</el-button>
                </template>
              </el-table-column>
            </el-table>
          </el-card>
        </div>

        <!-- 账本 -->
        <div v-show="tab === 'ledger'">
          <el-card shadow="never" class="panel-card">
            <el-table :data="llist" stripe empty-text="暂无账本记录">
              <el-table-column prop="ledger_no" label="账本号" min-width="180" />
              <el-table-column label="方向" width="80">
                <template #default="{ row }">
                  <el-tag :type="row.direction === 'IN' ? 'success' : 'warning'" size="small">{{ row.direction }}</el-tag>
                </template>
              </el-table-column>
              <el-table-column label="金额" width="100">
                <template #default="{ row }">${{ (Number(row.amount_cents || 0) / 100).toFixed(2) }}</template>
              </el-table-column>
              <el-table-column prop="channel" label="渠道" width="90" />
              <el-table-column label="结算" width="70">
                <template #default="{ row }">{{ row.settled ? '是' : '否' }}</template>
              </el-table-column>
              <el-table-column label="时间" width="170">
                <template #default="{ row }">{{ fmt(row.created_at) }}</template>
              </el-table-column>
            </el-table>
          </el-card>
        </div>
      </main>
    </div>

    <!-- dialogs -->
    <el-dialog v-model="userDlg" :title="userEdit ? '编辑用户' : (uf.is_staff ? '新增管理员' : '新增订阅用户')" width="420px" destroy-on-close>
      <el-form label-width="80px">
        <el-form-item label="用户名"><el-input v-model="uf.username" :disabled="userEdit" /></el-form-item>
        <el-form-item v-if="!userEdit" label="密码"><el-input v-model="uf.password" type="password" show-password /></el-form-item>
        <el-form-item label="邮箱"><el-input v-model="uf.email" /></el-form-item>
        <el-form-item label="类型">
          <el-radio-group v-model="uf.is_staff" :disabled="userEdit && uf.username === 'admin'">
            <el-radio :value="true">管理员</el-radio>
            <el-radio :value="false">订阅用户</el-radio>
          </el-radio-group>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="userDlg = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="saveUser">确定</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="vpsDlg" title="添加 VPS（测试机）" width="460px" destroy-on-close>
      <el-form label-width="90px">
        <el-form-item label="名称"><el-input v-model="vf.name" placeholder="vps-a" /></el-form-item>
        <el-form-item label="角色">
          <el-select v-model="vf.role" style="width: 100%">
            <el-option label="VPS-A（首节点）" value="VPS-A" />
            <el-option label="VPS-B（第二节点）" value="VPS-B" />
            <el-option label="其他" value="node" />
          </el-select>
        </el-form-item>
        <el-form-item label="公网 IP"><el-input v-model="vf.ip" placeholder="x.x.x.x" /></el-form-item>
        <el-form-item label="SSH 端口"><el-input-number v-model="vf.ssh_port" :min="1" :max="65535" /></el-form-item>
        <el-form-item label="SSH 用户"><el-input v-model="vf.ssh_username" placeholder="root" /></el-form-item>
        <el-form-item label="SSH 密码" required>
          <el-input v-model="vf.ssh_password" type="password" show-password placeholder="root 密码 · 服务端 AES 加密存储 · 永不回显" />
        </el-form-item>
        <el-form-item label="域名"><el-input v-model="vf.domain" placeholder="可选 a.example.com" /></el-form-item>
        <el-form-item label="备注"><el-input v-model="vf.remark" placeholder="可选" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="vpsDlg = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="saveVps">登记</el-button>
      </template>
    </el-dialog>

    <!-- 部署 / 卸载详情抽屉 -->
    <el-drawer v-model="deployDrawer" size="520px" :title="deployDrawerTitle" destroy-on-close>
      <div v-if="activeTask" class="deploy-detail">
        <div class="dd-row">
          <el-tag size="small" :type="kindTag(activeTask.kind)">{{ kindLabel(activeTask.kind) }}</el-tag>
          <el-tag :type="taskStatusType(activeTask.status)">{{ activeTask.status }}</el-tag>
          <span class="muted">进度 {{ activeTask.progress || 0 }}%</span>
          <span v-if="activeTask.node_id" class="muted">节点 #{{ activeTask.node_id }}</span>
        </div>
        <el-progress
          :percentage="activeTask.progress || 0"
          :status="activeTask.status === 'failed' ? 'exception' : (activeTask.status === 'success' ? 'success' : undefined)"
          style="margin: 12px 0 16px"
        />
        <div class="dd-stage muted">当前阶段：{{ activeTask.stage || '—' }}</div>

        <div class="dd-section-title">流水线步骤</div>
        <el-steps direction="vertical" :active="stepActive(activeTask)" finish-status="success" process-status="process">
          <el-step
            v-for="st in (activeTask.steps || [])"
            :key="st.key"
            :title="st.title"
            :description="st.detail || stepStatusText(st.status)"
            :status="stepElStatus(st.status)"
          />
        </el-steps>

        <div class="dd-section-title" style="margin-top: 16px">完整日志</div>
        <pre ref="logBox" class="task-log live">{{ (activeTask.logs || []).join('\n') || '（等待日志…）' }}</pre>
        <div v-if="activeTask.error" class="dd-err">{{ activeTask.error }}</div>
      </div>
      <el-empty v-else description="暂无任务" />
    </el-drawer>

    <el-dialog v-model="nodeDlg" title="新增节点" width="420px" destroy-on-close>
      <el-form label-width="80px">
        <el-form-item label="名称"><el-input v-model="nf.name" placeholder="sg-1" /></el-form-item>
        <el-form-item label="IP"><el-input v-model="nf.ip" placeholder="1.2.3.4" /></el-form-item>
        <el-form-item label="端口"><el-input-number v-model="nf.port" :min="1" :max="65535" /></el-form-item>
        <el-form-item label="协议">
          <el-select v-model="nf.protocol" style="width: 100%">
            <el-option label="aero（推荐）" value="aero" />
            <el-option label="vmess（旧）" value="vmess" />
            <el-option label="vless（旧）" value="vless" />
          </el-select>
        </el-form-item>
        <el-form-item label="最大用户"><el-input-number v-model="nf.max_users" :min="1" /></el-form-item>
        <el-form-item label="地区"><el-input v-model="nf.region" placeholder="sg" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="nodeDlg = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="saveNode">确定</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="subDlg" title="开通订阅（绑定用户 ↔ 节点）" width="460px" destroy-on-close>
      <el-form label-width="88px">
        <el-form-item label="订阅用户" required>
          <el-select v-model="sf.user_id" filterable placeholder="仅订阅用户" style="width: 100%">
            <el-option
              v-for="u in subUsers"
              :key="u.id"
              :label="`${u.username} (#${u.id})`"
              :value="u.id"
            />
          </el-select>
        </el-form-item>
        <el-form-item label="节点" required>
          <el-select v-model="sf.node_id" filterable placeholder="选择节点" style="width: 100%">
            <el-option
              v-for="n in nlist"
              :key="n.id"
              :label="`${n.name} · ${n.ip}:${n.port} · 已挂 ${subCount(n.id)}/${n.max_users || 100}`"
              :value="n.id"
            />
          </el-select>
        </el-form-item>
        <el-form-item label="时长">
          <el-radio-group v-model="sf.days">
            <el-radio-button :value="30">30天</el-radio-button>
            <el-radio-button :value="90">90天</el-radio-button>
            <el-radio-button :value="365">1年</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="到期">
          <el-date-picker v-model="sf.expire_date" type="datetime" style="width: 100%" />
        </el-form-item>
      </el-form>
      <p class="muted" style="margin: 0 0 0 88px">UUID 自动生成；同一用户可多次开通不同节点。</p>
      <template #footer>
        <el-button @click="subDlg = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="saveSub">开通</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted, onUnmounted, nextTick, watch } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  Odometer, User, Monitor, Ticket, Wallet, Fold, Expand, Cloudy, Box,
} from '@element-plus/icons-vue'
import { userApi, nodeApi, subApi, ledgerApi, healthApi, vpsApi, aeroApi } from '../api'
import { getStoredMode, applyTheme, watchSystemTheme } from '../theme'

const router = useRouter()
const user = JSON.parse(localStorage.getItem('vpn_admin_user') || '{}')
if (!user.is_staff) router.replace('/login')

const SIDEBAR_KEY = 'vpn_admin_sidebar_collapsed'
const collapsed = ref(localStorage.getItem(SIDEBAR_KEY) === '1')
function toggleSidebar() {
  collapsed.value = !collapsed.value
  localStorage.setItem(SIDEBAR_KEY, collapsed.value ? '1' : '0')
}

const tab = ref('dash')
const tabs = [
  { id: 'dash', label: '总览', icon: Odometer },
  { id: 'users', label: '用户', icon: User },
  { id: 'vps', label: 'VPS', icon: Cloudy },
  { id: 'aero', label: 'AERO', icon: Box },
  { id: 'nodes', label: '节点', icon: Monitor },
  { id: 'subs', label: '订阅', icon: Ticket },
  { id: 'ledger', label: '账本', icon: Wallet },
]
const currentTitle = computed(() => tabs.find((t) => t.id === tab.value)?.label || '')

const themeMode = ref(getStoredMode())
const themeOptions = [
  { label: '浅色', value: 'light' },
  { label: '深色', value: 'dark' },
  { label: '系统', value: 'system' },
]
function onThemeChange(v) {
  applyTheme(v)
}

const stats = ref([
  { l: '在线服务', v: '…' },
  { l: '今日入账', v: '…' },
  { l: '活跃节点', v: '…' },
  { l: '注册用户', v: '…' },
])
const svcs = ref([])
const svcGroups = ref([])
const svcOpen = ref([]) // 默认全折叠，点击展开
const coreDown = ref(false)
const ledger = ref({ total_in_cents: 0, total_out_cents: 0, entry_count: 0 })
const users = ref([])
const userKind = ref('sub') // staff | sub
const staffUsers = computed(() => users.value.filter((u) => u.is_staff))
const subUsers = computed(() => users.value.filter((u) => !u.is_staff))
const filteredUsers = computed(() => (userKind.value === 'staff' ? staffUsers.value : subUsers.value))
const nlist = ref([])
const nodeSyncing = ref(false)
const vpsList = ref([])
/** 节点找不到对应 VPS 登记 → 失联 */
const orphanNodes = computed(() => {
  const vpsIds = new Set(vpsList.value.map((v) => v.id))
  const vpsIPs = new Set(vpsList.value.map((v) => v.ip))
  return nlist.value.filter((n) => {
    if (n.vps_id && vpsIds.has(n.vps_id)) return false
    if (n.ip && vpsIPs.has(n.ip)) return false
    // no vps at all → all nodes with vps_id are orphan; nodes without vps_id still orphan if no IP match
    return true
  })
})
function isOrphanNode(row) {
  return orphanNodes.value.some((n) => n.id === row.id)
}
function nodeDisplayOnline(row) {
  if (isOrphanNode(row)) return false
  return !!row.status
}
const taskList = ref([])
const taskFilter = ref('all') // all | success | failed
const taskListSorted = computed(() =>
  [...taskList.value].sort((a, b) => new Date(b.created_at) - new Date(a.created_at)),
)
const taskListFiltered = computed(() => {
  if (taskFilter.value === 'all') return taskListSorted.value
  return taskListSorted.value.filter((t) => t.status === taskFilter.value)
})
const failedTaskCount = computed(() => taskList.value.filter((t) => t.status === 'failed').length)
const nodeSubMap = ref({}) // node_id -> active sub count
const onlineNodes = computed(() => nlist.value.filter((n) => n.status))
const slist = ref([])
const llist = ref([])
const saving = ref(false)
const deployingId = ref(0)
const aeroVpsId = ref(null)
const probingId = ref(0)
const vpsRefreshing = ref(false)
const vpsAutoProbe = ref(false)
const deployDrawer = ref(false)
const activeTask = ref(null)
const logBox = ref(null)
const deployDrawerTitle = computed(() => {
  if (!activeTask.value) return '任务详情'
  const k = kindLabel(activeTask.value.kind)
  return `${k} #${activeTask.value.id} · ${activeTask.value.vps_name || ''}`
})
let vpsPollTimer = null
let taskPollTimer = null

const SVC_META = {
  'user-center': { label: '用户中心', group: '用户与订阅' },
  billing: { label: '套餐计费', group: '用户与订阅' },
  'vpn-core': { label: '订阅服务', group: '用户与订阅' },
  'node-manager': { label: '节点管理', group: 'VPS 与节点' },
  'vps-manager': { label: 'VPS 资产', group: 'VPS 与节点' },
  'aero-deploy': { label: 'AERO 部署', group: 'VPS 与节点' },
  scheduler: { label: '负载调度', group: 'VPS 与节点' },
  'failover-engine': { label: '故障切换', group: 'VPS 与节点' },
  'state-sync-engine': { label: '节点同步', group: 'VPS 与节点' },
  'payment-in': { label: '用户收款', group: '资金' },
  'payment-ledger': { label: '资金账本', group: '资金' },
  'settlement-engine': { label: '日清算', group: '资金' },
  'payment-out': { label: '企业归集', group: '资金' },
  'payment-test-module': { label: '模拟支付（测试）', group: '资金' },
  'config-center': { label: '系统配置', group: '系统' },
  'security-layer': { label: '安全防护', group: '系统' },
  'audit-log': { label: '操作审计', group: '系统' },
}

function buildSvcGroups(list) {
  const order = ['用户与订阅', 'VPS 与节点', '资金', '系统']
  const map = {}
  for (const g of order) map[g] = []
  for (const s of list || []) {
    const meta = SVC_META[s.name] || { label: s.name, group: '系统' }
    map[meta.group].push({ name: s.name, label: meta.label, status: s.status })
  }
  return order
    .filter((t) => map[t]?.length)
    .map((t) => {
      const items = map[t]
      const ok = items.filter((x) => x.status === 'ok').length
      return { title: t, items, ok, total: items.length, down: ok < items.length }
    })
}

const userDlg = ref(false)
const userEdit = ref(false)
const uf = reactive({ id: null, username: '', password: '', email: '', is_staff: false })
const vpsDlg = ref(false)
const vf = reactive({
  name: '', role: 'VPS-A', ip: '', ssh_port: 22, ssh_username: 'root',
  ssh_password: '', domain: '', remark: '',
})
const nodeDlg = ref(false)
const nf = reactive({ name: '', ip: '', port: 443, protocol: 'aero', max_users: 100, region: '' })
const subDlg = ref(false)
const sf = reactive({ user_id: null, node_id: null, days: 30, expire_date: null })

function switchTab(t) {
  tab.value = t.id
  load()
}

function vpsStatusType(s) {
  if (s === 'online') return 'success'
  if (s === 'deploying' || s === 'connecting') return 'warning'
  if (s === 'error' || s === 'offline') return 'danger'
  return 'info'
}
function vpsStatusLabel(s) {
  const map = {
    registered: '已登记', online: '在线', offline: '离线',
    deploying: '部署中', connecting: '连接中', error: '异常',
  }
  return map[s] || s || '—'
}
function taskStatusType(s) {
  if (s === 'success') return 'success'
  if (s === 'failed') return 'danger'
  if (s === 'running') return 'warning'
  return 'info'
}
function kindLabel(k) {
  return ({ install: '安装', deploy: '安装', uninstall: '卸载' })[k] || k || '任务'
}
function kindTag(k) {
  if (k === 'uninstall') return 'danger'
  return 'primary'
}
function clampPct(n) {
  const x = Number(n) || 0
  return Math.max(0, Math.min(100, Math.round(x)))
}
function fmtNum(n, d = 1) {
  const x = Number(n)
  if (Number.isNaN(x)) return '—'
  return x.toFixed(d)
}
function progStatus(p) {
  if (p >= 90) return 'exception'
  if (p >= 75) return 'warning'
  return undefined
}
function metricLevel(p) {
  if (p >= 90) return 'hot'
  if (p >= 75) return 'warm'
  return ''
}
function fmtUptime(sec) {
  const s = Number(sec) || 0
  if (s < 60) return s + 's'
  if (s < 3600) return Math.floor(s / 60) + 'm'
  if (s < 86400) return Math.floor(s / 3600) + 'h'
  return Math.floor(s / 86400) + 'd ' + Math.floor((s % 86400) / 3600) + 'h'
}
function latestTask(vpsId) {
  return taskListSorted.value.find((t) => t.vps_id === vpsId) || null
}
function subCount(nodeId) {
  return nodeSubMap.value[String(nodeId)] || nodeSubMap.value[nodeId] || 0
}
function userName(uid) {
  const u = users.value.find((x) => x.id === uid)
  return u ? u.username : `#${uid}`
}
function nodeName(nid) {
  const n = nlist.value.find((x) => x.id === nid)
  return n ? n.name : `节点${nid}`
}
function subActive(row) {
  if (!row?.status) return false
  if (!row.expire_date) return true
  return new Date(row.expire_date) > new Date()
}
function stepActive(task) {
  const steps = task?.steps || []
  let i = 0
  for (; i < steps.length; i++) {
    if (steps[i].status === 'running') return i
    if (steps[i].status === 'pending') return Math.max(0, i)
  }
  return steps.length
}
function stepElStatus(st) {
  if (st === 'success') return 'success'
  if (st === 'failed') return 'error'
  if (st === 'running') return 'process'
  if (st === 'skipped') return 'wait'
  return 'wait'
}
function stepStatusText(st) {
  return ({ pending: '等待', running: '进行中', success: '完成', failed: '失败', skipped: '跳过' })[st] || st
}

function stopVpsPoll() {
  if (vpsPollTimer) { clearInterval(vpsPollTimer); vpsPollTimer = null }
}
function stopTaskPoll() {
  if (taskPollTimer) { clearInterval(taskPollTimer); taskPollTimer = null }
}

watch(vpsAutoProbe, (on) => {
  stopVpsPoll()
  if (on && tab.value === 'vps') {
    refreshVpsAll()
    vpsPollTimer = setInterval(() => refreshVpsAll(true), 15000)
  }
})
watch(tab, (t) => {
  if (t === 'vps' && vpsAutoProbe.value) {
    stopVpsPoll()
    vpsPollTimer = setInterval(() => refreshVpsAll(true), 15000)
  } else {
    stopVpsPoll()
  }
})

onMounted(() => {
  applyTheme(themeMode.value)
  watchSystemTheme(() => {
    if (themeMode.value === 'system') applyTheme('system')
  })
  load()
})
onUnmounted(() => {
  stopVpsPoll()
  stopTaskPoll()
})

async function load() {
  try {
    const h = await healthApi.check()
    svcs.value = h.data?.services || []
    svcGroups.value = buildSvcGroups(svcs.value)
    const ok = svcs.value.filter((x) => x.status === 'ok').length
    const total = svcs.value.length || 0
    stats.value[0].v = total ? `${ok}/${total}` : '0'
    coreDown.value = total > 0 && ok < total
  } catch {
    svcs.value = []
    svcGroups.value = []
    coreDown.value = true
    stats.value[0].v = '网关未连接'
  }
  try {
    const s = await ledgerApi.summary(new Date().toISOString().slice(0, 10))
    const d = s.data?.data || {}
    ledger.value = d
    stats.value[1].v = `$${(Number(d.total_in_cents || 0) / 100).toFixed(2)}`
  } catch {
    stats.value[1].v = '$0.00'
  }
  try {
    const l = await ledgerApi.list()
    llist.value = Array.isArray(l.data?.data) ? l.data.data : l.data?.data?.results || []
  } catch {
    llist.value = []
  }
  try {
    const u = await userApi.list({ page: 1, page_size: 100 })
    users.value = u.data?.data?.results || []
    stats.value[3].v = `${users.value.length}人`
  } catch {
    users.value = []
    stats.value[3].v = '0人'
  }
  try {
    const n = await nodeApi.list()
    nlist.value = n.data?.data?.results || []
    stats.value[2].v = `${nlist.value.filter((x) => x.status).length}/${nlist.value.length}`
  } catch {
    nlist.value = []
    stats.value[2].v = '0/0'
  }
  try {
    const s = await subApi.list()
    slist.value = s.data?.data?.results || []
  } catch {
    slist.value = []
  }
  try {
    const st = await subApi.nodeStats()
    nodeSubMap.value = st.data?.data || {}
  } catch {
    nodeSubMap.value = {}
  }
  await loadVps()
}

async function loadVps() {
  try {
    const r = await vpsApi.list()
    vpsList.value = r.data?.data?.results || []
    if (!aeroVpsId.value && vpsList.value[0]) aeroVpsId.value = vpsList.value[0].id
  } catch {
    vpsList.value = []
  }
  await loadAeroTasks()
}

async function loadAeroTasks() {
  try {
    const r = await aeroApi.listTasks()
    taskList.value = r.data?.data?.results || []
  } catch {
    taskList.value = []
  }
  if (activeTask.value?.id) {
    const t = taskList.value.find((x) => x.id === activeTask.value.id)
    if (t) {
      activeTask.value = t
      await nextTick()
      if (logBox.value) logBox.value.scrollTop = logBox.value.scrollHeight
    }
  }
}

async function loadNodesOnly() {
  try {
    const n = await nodeApi.list()
    nlist.value = n.data?.data?.results || []
    const online = nlist.value.filter((x) => x.status && !isOrphanNode(x)).length
    stats.value[2].v = `${online}/${nlist.value.length}`
  } catch {
    nlist.value = []
  }
}

/** 拉 VPS + 节点 + 订阅，校验失联 */
async function syncNodesWithVps() {
  nodeSyncing.value = true
  try {
    await loadVps()
    await loadNodesOnly()
    try {
      const s = await subApi.list({ page_size: 200 })
      slist.value = s.data?.data?.results || []
      const st = await subApi.nodeStats()
      nodeSubMap.value = st.data?.data || {}
    } catch { /* ignore */ }
    if (orphanNodes.value.length) {
      ElMessage.warning(`发现 ${orphanNodes.value.length} 个失联节点（VPS 已删）`)
    } else {
      ElMessage.success('节点与 VPS 联动正常')
    }
  } finally {
    nodeSyncing.value = false
  }
}

async function cleanOrphanNodes() {
  const list = [...orphanNodes.value]
  if (!list.length) return
  try {
    await ElMessageBox.confirm(
      `将删除 ${list.length} 个失联节点，并清理其订阅。确认？`,
      '清理失联节点',
      { type: 'warning' },
    )
  } catch {
    return
  }
  for (const n of list) {
    try {
      await subApi.detachNode(n.id)
    } catch { /* continue */ }
    try {
      await nodeApi.remove(n.id)
    } catch { /* continue */ }
  }
  ElMessage.success('失联节点已清理')
  await syncNodesWithVps()
}

async function probeVps(v) {
  probingId.value = v.id
  try {
    const r = await vpsApi.probe(v.id)
    const updated = r.data?.data?.vps
    if (updated) {
      const i = vpsList.value.findIndex((x) => x.id === v.id)
      if (i >= 0) vpsList.value[i] = updated
      else await loadVps()
    } else {
      await loadVps()
    }
    if (r.data?.data?.ok) ElMessage.success('探测成功')
    else ElMessage.warning(r.data?.data?.metrics?.probe_error || '探测未完全成功')
  } catch (e) {
    ElMessage.error(e.response?.data?.message || '探测失败')
    await loadVps()
  } finally {
    probingId.value = 0
  }
}

async function refreshVpsAll(silent = false) {
  if (!silent) vpsRefreshing.value = true
  try {
    await loadVps()
    // sequential probe to avoid overload
    for (const v of vpsList.value) {
      if (!v.has_password) continue
      try {
        const r = await vpsApi.probe(v.id)
        const updated = r.data?.data?.vps
        if (updated) {
          const i = vpsList.value.findIndex((x) => x.id === v.id)
          if (i >= 0) vpsList.value[i] = { ...vpsList.value[i], ...updated }
        }
      } catch { /* keep going */ }
    }
  } finally {
    vpsRefreshing.value = false
  }
}

function openDeployDetail(v) {
  const t = latestTask(v.id)
  if (t) openTaskDetail(t)
  else ElMessage.info('该 VPS 尚无部署任务')
}

function openTaskDetail(row) {
  if (!row) return
  activeTask.value = row
  deployDrawer.value = true
  stopTaskPoll()
  // poll while open and running
  taskPollTimer = setInterval(async () => {
    if (!deployDrawer.value || !activeTask.value) {
      stopTaskPoll()
      return
    }
    try {
      const r = await aeroApi.getTask(activeTask.value.id)
      activeTask.value = r.data?.data || activeTask.value
      await loadVps()
      await loadNodesOnly()
      await nextTick()
      if (logBox.value) logBox.value.scrollTop = logBox.value.scrollHeight
      if (activeTask.value.status === 'success' || activeTask.value.status === 'failed') {
        stopTaskPoll()
      }
    } catch { /* ignore */ }
  }, 1200)
}

watch(deployDrawer, (open) => {
  if (!open) stopTaskPoll()
})

const syncingSubs = ref(false)

function copySubLink(row) {
  if (!row.sub_slug) {
    return ElMessage.warning('该用户暂无专属 Slug')
  }
  const url = `${location.origin}/sub/${row.sub_slug}`
  navigator.clipboard.writeText(url).then(() => {
    ElMessage.success(`用户 ${row.username} 专属订阅链接已复制！`)
  }).catch(() => {
    ElMessage.info(url)
  })
}

async function broadcastAllSubs() {
  syncingSubs.value = true
  try {
    const list = subUsers.value.map((u) => ({
      username: u.username,
      slug: u.sub_slug,
      token: u.sub_token,
      expire_at: u.expire_at ? Math.floor(new Date(u.expire_at).getTime() / 1000) : 0,
    })).filter((x) => x.slug)

    if (!list.length) {
      ElMessage.warning('暂无具备专属 Slug 的订阅用户')
      return
    }

    await aeroApi.broadcastSubs({ subs: list })
    ElMessage.success('已广播同步用户凭证至所有在线 Edge VPS！')
  } catch (err) {
    ElMessage.error('同步失败: ' + (err.response?.data?.message || err.message || '网络错误'))
  } finally {
    syncingSubs.value = false
  }
}

function openUserDlg() {
  userEdit.value = false
  Object.assign(uf, {
    id: null, username: '', password: '', email: '',
    is_staff: userKind.value === 'staff',
  })
  userDlg.value = true
}
function editUser(row) {
  userEdit.value = true
  Object.assign(uf, {
    id: row.id, username: row.username, email: row.email || '', password: '',
    is_staff: !!row.is_staff,
  })
  userDlg.value = true
}
async function saveUser() {
  if (!userEdit.value && (!uf.username || !uf.password)) return ElMessage.warning('用户名和密码必填')
  saving.value = true
  try {
    if (userEdit.value) {
      await userApi.update(uf.id, { email: uf.email, is_staff: uf.is_staff })
    } else {
      await userApi.create({
        username: uf.username, password: uf.password, email: uf.email, is_staff: uf.is_staff,
      })
    }
    ElMessage.success('成功')
    userDlg.value = false
    userKind.value = uf.is_staff ? 'staff' : 'sub'
    await load()
  } catch (e) {
    ElMessage.error(e.response?.data?.message || '失败')
  } finally {
    saving.value = false
  }
}

function openVpsDlg() {
  const n = vpsList.value.length
  Object.assign(vf, {
    name: n === 0 ? 'vps-a' : n === 1 ? 'vps-b' : `vps-${n + 1}`,
    role: n === 0 ? 'VPS-A' : n === 1 ? 'VPS-B' : 'node',
    ip: '', ssh_port: 22, ssh_username: 'root', ssh_password: '', domain: '', remark: '',
  })
  vpsDlg.value = true
}
async function saveVps() {
  if (!vf.name || !vf.ip) return ElMessage.warning('名称和 IP 必填')
  if (!vf.ssh_password) return ElMessage.warning('请填写 SSH 密码（服务端 AES 加密存储，不会回显）')
  saving.value = true
  try {
    await vpsApi.create({ ...vf })
    ElMessage.success('VPS 已登记（密码加密 · 模块 vps-manager）')
    vpsDlg.value = false
    vf.ssh_password = ''
    await loadVps()
  } catch (e) {
    const st = e.response?.status
    const msg = e.response?.data?.message
    if (st === 502 || st === 503 || !e.response) {
      ElMessage.error('登记失败：vps-manager(:8085) 未运行')
    } else {
      ElMessage.error(msg || `登记失败 (${st || '网络错误'})`)
    }
  } finally {
    saving.value = false
  }
}

async function updateVpsPassword(v) {
  try {
    const { value } = await ElMessageBox.prompt(
      `更新 ${v.name}（${v.ip}）SSH 密码。AES 加密存储，不回显。`,
      '更新 SSH 密码',
      {
        inputType: 'password',
        confirmButtonText: '保存',
        cancelButtonText: '取消',
        inputValidator: (val) => (!!val && val.length > 0) || '密码不能为空',
      },
    )
    await vpsApi.updatePassword(v.id, value)
    ElMessage.success('密码已更新')
    await probeVps(v)
  } catch (e) {
    if (e === 'cancel' || e === 'close') return
    ElMessage.error(e?.response?.data?.message || '更新失败')
  }
}

/** VPS 模块：只删登记，不碰 AERO 包 */
async function delVps(id) {
  const v = vpsList.value.find((x) => x.id === id)
  try {
    await ElMessageBox.confirm(
      `删除 VPS「${v?.name || id}」的中台登记？\n不会卸载远端 AERO（请到「AERO」模块卸载）。`,
      '删除 VPS 登记',
      { type: 'warning', confirmButtonText: '仅删登记' },
    )
    await vpsApi.remove(id)
    ElMessage.success('已删除登记')
    await loadVps()
  } catch (e) {
    if (e === 'cancel' || e === 'close') return
    ElMessage.error(e?.response?.data?.message || '删除失败')
  }
}

async function doAeroInstall() {
  if (!aeroVpsId.value) return
  deployingId.value = aeroVpsId.value
  try {
    const r = await aeroApi.install(aeroVpsId.value)
    const task = r.data?.data
    ElMessage.success('AERO 安装任务已创建')
    if (task) openTaskDetail(task)
    for (let i = 0; i < 60; i++) {
      await new Promise((x) => setTimeout(x, 800))
      await loadAeroTasks()
      const t = taskList.value.find((x) => x.id === task?.id)
      if (t && (t.status === 'success' || t.status === 'failed')) {
        ElMessage[t.status === 'success' ? 'success' : 'error'](
          t.status === 'success' ? 'AERO 安装/升级完成' : (t.error || '安装失败'),
        )
        break
      }
    }
  } catch (e) {
    ElMessage.error(e.response?.data?.message || '创建任务失败（检查 aero-deploy:8070）')
  } finally {
    deployingId.value = 0
  }
}

async function doAeroUninstall() {
  if (!aeroVpsId.value) return
  try {
    await ElMessageBox.confirm(
      '将在 VPS 上停止并清除 AERO（systemd/文件）。不删除 VPS 登记。',
      '卸载 AERO',
      { type: 'warning' },
    )
  } catch {
    return
  }
  deployingId.value = aeroVpsId.value
  try {
    const r = await aeroApi.uninstall(aeroVpsId.value)
    const task = r.data?.data
    ElMessage.success('卸载任务已创建')
    if (task) openTaskDetail(task)
    for (let i = 0; i < 40; i++) {
      await new Promise((x) => setTimeout(x, 600))
      await loadAeroTasks()
      const t = taskList.value.find((x) => x.id === task?.id)
      if (t && (t.status === 'success' || t.status === 'failed')) break
    }
  } catch (e) {
    ElMessage.error(e.response?.data?.message || '卸载失败')
  } finally {
    deployingId.value = 0
  }
}
async function delUser(id) {
  try {
    await ElMessageBox.confirm('确认删除该用户？', '警告', { type: 'warning' })
    await userApi.remove(id)
    ElMessage.success('已删除')
    await load()
  } catch {}
}
function openNodeDlg() {
  Object.assign(nf, { name: '', ip: '', port: 443, protocol: 'aero', max_users: 100, region: '' })
  nodeDlg.value = true
}
async function saveNode() {
  if (!nf.name || !nf.ip) return ElMessage.warning('名称和 IP 必填')
  saving.value = true
  try {
    await nodeApi.create({ ...nf })
    ElMessage.success('节点已创建')
    nodeDlg.value = false
    await load()
  } catch (e) {
    ElMessage.error(e.response?.data?.message || '创建失败')
  } finally {
    saving.value = false
  }
}
async function hb(id) {
  try {
    await nodeApi.heartbeat(id, '1.0.0')
    ElMessage.success('心跳已发送')
    await load()
  } catch {
    ElMessage.error('心跳失败')
  }
}
async function delNode(id) {
  try {
    await ElMessageBox.confirm('确认删除节点？将同时清理该节点下的订阅。', '警告', { type: 'warning' })
    try {
      await subApi.detachNode(id)
    } catch { /* best effort */ }
    await nodeApi.remove(id)
    ElMessage.success('节点及关联订阅已删除')
    await load()
  } catch {}
}
function openSubDlg() {
  const su = subUsers.value
  if (!su.length) {
    ElMessage.warning('请先在「用户」页创建订阅用户（非管理员）')
    return
  }
  if (!nlist.value.length) {
    ElMessage.warning('请先部署/登记节点')
    return
  }
  sf.user_id = su[0].id
  // pick node with most free capacity
  const sorted = [...nlist.value].sort(
    (a, b) => subCount(a.id) / (a.max_users || 100) - subCount(b.id) / (b.max_users || 100),
  )
  sf.node_id = sorted[0]?.id || nlist.value[0].id
  sf.days = 30
  sf.expire_date = new Date(Date.now() + 30 * 864e5)
  subDlg.value = true
}
watch(
  () => sf.days,
  (d) => {
    if (d) sf.expire_date = new Date(Date.now() + d * 864e5)
  },
)
async function saveSub() {
  if (!sf.user_id || !sf.node_id) return ElMessage.warning('请选择用户和节点')
  saving.value = true
  try {
    const e = sf.expire_date || new Date(Date.now() + (sf.days || 30) * 864e5)
    const node = nlist.value.find((n) => n.id === sf.node_id)
    const r = await subApi.create({
      user_id: sf.user_id,
      node_id: sf.node_id,
      node_name: node?.name || '',
      node_ip: node?.ip || '',
      node_port: node?.port || 443,
      expire_date: new Date(e).toISOString(),
    })
    ElMessage.success(`订阅已开通 UUID=${r.data?.data?.client_uuid || ''}`)
    subDlg.value = false
    await load()
  } catch (e) {
    ElMessage.error(e.response?.data?.message || '开通失败')
  } finally {
    saving.value = false
  }
}
async function delSub(id) {
  try {
    await ElMessageBox.confirm('确认删除该用户订阅？凭据将失效。', '警告', { type: 'warning' })
    await subApi.remove(id)
    ElMessage.success('已删除')
    await load()
  } catch {}
}
async function copySubCfg(row) {
  try {
    const r = await subApi.config(row.client_uuid)
    const text = JSON.stringify(r.data?.data || r.data, null, 2)
    await navigator.clipboard.writeText(text)
    ElMessage.success('配置已复制到剪贴板')
  } catch {
    ElMessage.error('获取配置失败')
  }
}
async function delTask(row) {
  try {
    await ElMessageBox.confirm(`删除失败任务 #${row.id} 及其日志？`, '清理', { type: 'warning' })
    await aeroApi.deleteTask(row.id)
    ElMessage.success('已删除')
    if (activeTask.value?.id === row.id) {
      deployDrawer.value = false
      activeTask.value = null
    }
    await loadVps()
  } catch (e) {
    if (e !== 'cancel' && e?.toString?.() !== 'cancel') {
      ElMessage.error(e.response?.data?.message || '删除失败')
    }
  }
}
async function clearFailedTasks() {
  try {
    await ElMessageBox.confirm(`清理全部 ${failedTaskCount.value} 条失败任务及日志？`, '批量清理', { type: 'warning' })
    const r = await aeroApi.clearFailed()
    ElMessage.success(`已清理 ${r.data?.data?.deleted || 0} 条`)
    await loadVps()
  } catch (e) {
    if (e !== 'cancel' && e?.toString?.() !== 'cancel') {
      ElMessage.error(e.response?.data?.message || '清理失败')
    }
  }
}
function logout() {
  localStorage.removeItem('vpn_admin_token')
  localStorage.removeItem('vpn_admin_user')
  router.push('/login')
}
function fmt(t) {
  return t ? new Date(t).toLocaleString('zh-CN') : '-'
}
</script>

<style scoped>
.layout {
  display: flex;
  min-height: 100vh;
  background: var(--app-bg);
  color: var(--app-text);
}
.sidebar {
  width: 220px;
  flex-shrink: 0;
  background: var(--app-sidebar);
  color: var(--app-sidebar-text);
  display: flex;
  flex-direction: column;
  position: sticky;
  top: 0;
  height: 100vh;
  transition: width 0.2s ease;
  overflow: hidden;
}
.layout.collapsed .sidebar { width: 72px }
.brand {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 20px 16px 16px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.08);
  min-height: 72px;
}
.brand-mark {
  width: 36px;
  height: 36px;
  flex-shrink: 0;
  border-radius: 10px;
  background: linear-gradient(135deg, #409eff, #67c23a);
  color: #fff;
  font-weight: 800;
  display: flex;
  align-items: center;
  justify-content: center;
}
.brand-title { color: #fff; font-weight: 700; font-size: 15px; line-height: 1.2; white-space: nowrap }
.brand-sub { font-size: 12px; opacity: 0.65; margin-top: 2px; white-space: nowrap }
.menu { padding: 12px 10px; flex: 1; overflow: auto }
.menu-item {
  width: 100%;
  display: flex;
  align-items: center;
  gap: 10px;
  border: 0;
  background: transparent;
  color: var(--app-sidebar-text);
  padding: 11px 12px;
  border-radius: 10px;
  cursor: pointer;
  font-size: 14px;
  margin-bottom: 4px;
  text-align: left;
  white-space: nowrap;
}
.layout.collapsed .menu-item { justify-content: center; padding: 11px 0 }
.menu-item:hover { background: rgba(255, 255, 255, 0.06); color: #fff }
.menu-item.active {
  background: var(--app-sidebar-active-bg);
  color: var(--app-sidebar-active);
  font-weight: 600;
}
.mi { font-size: 18px; flex-shrink: 0 }
.sidebar-foot {
  padding: 10px;
  border-top: 1px solid rgba(255, 255, 255, 0.08);
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.collapse-btn {
  width: 100%;
  display: flex;
  align-items: center;
  gap: 10px;
  border: 0;
  background: rgba(255, 255, 255, 0.06);
  color: var(--app-sidebar-text);
  padding: 10px 12px;
  border-radius: 10px;
  cursor: pointer;
  font-size: 13px;
  white-space: nowrap;
}
.layout.collapsed .collapse-btn { justify-content: center; padding: 10px 0 }
.collapse-btn:hover { background: rgba(255, 255, 255, 0.12); color: #fff }
.foot-note { padding: 0 6px }
.layout.collapsed .brand-text,
.layout.collapsed .menu-label,
.layout.collapsed .foot-note { display: none }
.main-wrap { flex: 1; min-width: 0; display: flex; flex-direction: column }
.topbar {
  height: 56px;
  background: var(--app-header);
  border-bottom: 1px solid var(--app-border);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 16px 0 8px;
  position: sticky;
  top: 0;
  z-index: 10;
}
.top-left { display: flex; align-items: center; gap: 4px }
.fold-btn { padding: 8px !important }
.page-title { font-size: 16px; font-weight: 700 }
.top-actions { display: flex; align-items: center; gap: 10px; flex-wrap: wrap }
.user-chip {
  font-size: 13px;
  color: var(--app-muted);
  padding: 4px 10px;
  border-radius: 999px;
  background: var(--app-bg);
}
.content { padding: 16px 20px 28px; flex: 1 }
.aero-embed-wrap {
  display: flex;
  flex-direction: column;
  min-height: calc(100vh - 120px);
}
.aero-embed {
  flex: 1;
  width: 100%;
  min-height: calc(100vh - 180px);
  border: 1px solid var(--app-border);
  border-radius: 12px;
  background: #0b1220;
}
.stat-card, .panel-card, .nrow {
  background: var(--app-card);
  border: 1px solid var(--app-border);
  border-radius: 12px;
}
.stat-card { padding: 16px 18px }
.sl { color: var(--app-muted); font-size: 13px }
.sv { font-size: 22px; font-weight: 700; margin-top: 6px }
.row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 0;
  border-bottom: 1px solid var(--app-border);
}
.row:last-child { border-bottom: 0 }
.card-hd { display: flex; align-items: center; justify-content: space-between; gap: 8px }
.card-hd-right { display: flex; align-items: center; gap: 8px }
.svc-collapse { border: 0 }
.svc-collapse :deep(.el-collapse-item__header) {
  background: transparent; border-bottom-color: var(--app-border); height: 44px; line-height: 44px;
}
.svc-collapse :deep(.el-collapse-item__wrap) { background: transparent; border-bottom-color: var(--app-border) }
.svc-collapse :deep(.el-collapse-item__content) { padding-bottom: 8px }
.collapse-title {
  display: flex; align-items: center; justify-content: space-between; width: 100%;
  padding-right: 12px; font-weight: 600; font-size: 13px;
}
.toolbar { margin-bottom: 12px; display: flex; align-items: center; gap: 12px; flex-wrap: wrap }
.vps-card {
  background: var(--app-card); border: 1px solid var(--app-border); border-radius: 14px;
  padding: 16px 18px; margin-bottom: 14px;
}
.vps-card-hd { display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap }
.vps-id { display: flex; align-items: center; gap: 8px; flex-wrap: wrap }
.vps-name { font-weight: 700; font-size: 16px }
.vps-actions { display: flex; gap: 8px; flex-wrap: wrap }
.vps-meta { margin-top: 8px; font-size: 13px; color: var(--app-muted) }
.metric-grid {
  display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 10px; margin-top: 14px;
}
@media (max-width: 1200px) {
  .metric-grid { grid-template-columns: repeat(3, minmax(0, 1fr)); }
}
@media (max-width: 700px) {
  .metric-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
.metric-item {
  background: var(--app-bg); border-radius: 12px; padding: 12px 12px 10px; border: 1px solid transparent;
}
.metric-item.warm { border-color: rgba(230, 162, 60, 0.45) }
.metric-item.hot { border-color: rgba(245, 108, 108, 0.5) }
.metric-label { font-size: 12px; color: var(--app-muted); margin-bottom: 4px }
.metric-value { font-size: 22px; font-weight: 700; line-height: 1.2 }
.metric-value.sm { font-size: 18px }
.metric-sub { font-size: 11px; color: var(--app-muted); margin: 4px 0 6px }
.metric-empty {
  margin-top: 12px; padding: 14px; border-radius: 10px; background: var(--app-bg); font-size: 13px;
}
.vps-task-strip {
  margin-top: 12px; padding: 10px 12px; border-radius: 10px; background: var(--app-bg);
  display: flex; align-items: center; gap: 10px; flex-wrap: wrap; cursor: pointer; font-size: 13px;
}
.vps-task-strip:hover { outline: 1px solid var(--app-border) }
.vps-task-strip .link { margin-left: auto; color: #409eff; font-size: 12px }
.task-log {
  margin: 0; max-height: 360px; overflow: auto; font-size: 12px; line-height: 1.55;
  background: var(--app-bg); padding: 12px; border-radius: 8px; white-space: pre-wrap;
  color: var(--app-text); font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
.task-log.live { max-height: 280px; border: 1px solid var(--app-border) }
.deploy-detail { padding: 0 4px 20px }
.dd-row { display: flex; align-items: center; gap: 10px }
.dd-stage { font-size: 13px; margin-bottom: 8px }
.dd-section-title { font-weight: 700; font-size: 13px; margin: 8px 0 10px }
.dd-err {
  margin-top: 10px; color: #f56c6c; font-size: 13px; padding: 8px 10px;
  background: rgba(245, 108, 108, 0.08); border-radius: 8px;
}
.cap-warn { color: #e6a23c; font-weight: 600 }
.nrow {
  padding: 12px 16px;
  margin-bottom: 8px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  font-size: 13px;
}
.muted { color: var(--app-muted); font-size: 12px }
</style>
