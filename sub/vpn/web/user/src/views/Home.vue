<template>
  <div class="layout" :class="{ collapsed }">
    <aside class="sidebar">
      <div class="brand">
        <div class="brand-mark">V</div>
        <div class="brand-text">
          <div class="brand-title">VPN 用户中心</div>
          <div class="brand-sub">{{ user?.username || '用户' }}</div>
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
        <div class="foot-note muted">我的空间</div>
      </div>
    </aside>

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
          <el-button size="small" type="danger" plain @click="logout">退出</el-button>
        </div>
      </header>

      <main class="content">
        <div v-show="tab === 'subs'">
          <el-alert
            v-if="!subs.length"
            type="info"
            :closable="false"
            show-icon
            title="暂无订阅。可购买套餐，或联系管理员为您开通节点访问。"
            style="margin-bottom: 12px"
          />
          <el-card shadow="never" class="panel">
            <el-table :data="subs" stripe empty-text="暂无订阅">
              <el-table-column prop="node_name" label="节点" min-width="100" />
              <el-table-column label="地址" min-width="140">
                <template #default="{ row }">{{ row.node_ip }}:{{ row.node_port || 443 }}</template>
              </el-table-column>
              <el-table-column label="UUID" min-width="180" show-overflow-tooltip>
                <template #default="{ row }">{{ row.client_uuid }}</template>
              </el-table-column>
              <el-table-column label="到期" width="160">
                <template #default="{ row }">{{ fmt(row.expire_date) }}</template>
              </el-table-column>
              <el-table-column label="状态" width="80">
                <template #default="{ row }">
                  <el-tag :type="isActive(row) ? 'success' : 'info'" size="small">{{ isActive(row) ? '有效' : '过期' }}</el-tag>
                </template>
              </el-table-column>
              <el-table-column label="操作" width="180" fixed="right">
                <template #default="{ row }">
                  <el-button size="small" type="primary" @click="showCfg(row.client_uuid)">查看配置</el-button>
                  <el-button size="small" @click="quickCopy(row.client_uuid)">复制</el-button>
                </template>
              </el-table-column>
            </el-table>
          </el-card>
        </div>

        <div v-show="tab === 'plans'">
          <el-row :gutter="12">
            <el-col :span="8" v-for="p in plans" :key="p.id">
              <div class="plan" :class="{ sel: selPlan === p.id }" @click="selPlan = p.id">
                <h3>{{ p.name }}</h3>
                <div class="price">${{ (Number(p.price_cents || 0) / 100).toFixed(2) }}</div>
                <div class="muted">{{ p.duration_months }}个月 · {{ fmtBytes(p.traffic_bytes) }}</div>
              </div>
            </el-col>
          </el-row>
          <div class="buy-bar">
            <el-select v-model="selChannel" placeholder="支付方式" style="width: 160px; margin-right: 12px">
              <el-option v-for="c in channels" :key="c.channel" :label="c.name" :value="c.channel" />
            </el-select>
            <el-button type="primary" :loading="buying" :disabled="!selPlan || !selChannel" @click="buy">
              立即支付
            </el-button>
          </div>
        </div>

        <div v-show="tab === 'nodes'">
          <el-empty v-if="!nodes.length" description="暂无在线节点" />
          <el-row :gutter="12">
            <el-col :span="8" v-for="n in nodes" :key="n.id">
              <div class="node-card" :class="{ off: !n.status }">
                <b>{{ n.name }}</b>
                <el-tag :type="n.status ? 'success' : 'danger'" size="small" style="margin-left: 6px">
                  {{ n.status ? '在线' : '离线' }}
                </el-tag>
                <p class="muted">{{ n.ip }}:{{ n.port }} · {{ n.protocol || 'aero' }}</p>
              </div>
            </el-col>
          </el-row>
        </div>

        <div v-show="tab === 'orders'">
          <el-card shadow="never" class="panel">
            <el-table :data="orders" stripe empty-text="暂无订单">
              <el-table-column prop="ledger_no" label="账本号" min-width="180" />
              <el-table-column label="金额" width="100">
                <template #default="{ row }">${{ (Number(row.amount_cents || 0) / 100).toFixed(2) }}</template>
              </el-table-column>
              <el-table-column prop="channel" label="渠道" width="90" />
              <el-table-column label="时间" width="170">
                <template #default="{ row }">{{ fmt(row.created_at) }}</template>
              </el-table-column>
            </el-table>
          </el-card>
        </div>
      </main>
    </div>

    <el-dialog v-model="cfgShow" title="节点配置" width="520px">
      <el-input v-model="cfgStr" type="textarea" :rows="12" readonly />
      <template #footer>
        <el-button type="primary" @click="copy">复制</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { Ticket, Goods, Monitor, Document, Fold, Expand } from '@element-plus/icons-vue'
import { subApi, planApi, nodeApi, payInApi, ledgerApi } from '../api'
import { getStoredMode, applyTheme, watchSystemTheme } from '../theme'

const router = useRouter()
const user = JSON.parse(localStorage.getItem('vpn_user_user') || '{}')
if (!user.username) router.replace('/login')

const SIDEBAR_KEY = 'vpn_user_sidebar_collapsed'
const collapsed = ref(localStorage.getItem(SIDEBAR_KEY) === '1')
function toggleSidebar() {
  collapsed.value = !collapsed.value
  localStorage.setItem(SIDEBAR_KEY, collapsed.value ? '1' : '0')
}

const tab = ref('subs')
const tabs = [
  { id: 'subs', label: '我的订阅', icon: Ticket },
  { id: 'plans', label: '购买套餐', icon: Goods },
  { id: 'nodes', label: '可用节点', icon: Monitor },
  { id: 'orders', label: '我的订单', icon: Document },
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

const subs = ref([])
const plans = ref([])
const nodes = ref([])
const orders = ref([])
const channels = ref([])
const selPlan = ref(0)
const selChannel = ref('')
const buying = ref(false)
const cfgShow = ref(false)
const cfgStr = ref('')

function switchTab(t) {
  tab.value = t.id
  loadTab()
}

async function loadTab() {
  if (tab.value === 'subs') {
    try {
      const uid = user.user_id
      const r = await subApi.list(uid ? { user_id: uid } : {})
      subs.value = r.data?.data?.results || []
    } catch {
      subs.value = []
    }
  }
  if (tab.value === 'plans') {
    try {
      const r = await planApi.list()
      plans.value = r.data?.data?.results || []
      if (!selPlan.value && plans.value[0]) selPlan.value = plans.value[0].id
    } catch {
      plans.value = []
    }
    try {
      const r = await payInApi.channels()
      channels.value = r.data?.data || []
      const e = channels.value.find((c) => c.enabled)
      if (e) selChannel.value = e.channel
    } catch {
      channels.value = []
    }
  }
  if (tab.value === 'nodes') {
    try {
      const r = await nodeApi.available()
      const d = r.data?.data
      nodes.value = Array.isArray(d) ? d : d?.results || []
    } catch {
      nodes.value = []
    }
  }
  if (tab.value === 'orders') {
    try {
      const r = await ledgerApi.list()
      const list = Array.isArray(r.data?.data) ? r.data.data : []
      const uid = user.user_id
      orders.value = uid ? list.filter((x) => x.user_id === uid) : list
    } catch {
      orders.value = []
    }
  }
}

onMounted(() => {
  applyTheme(themeMode.value)
  watchSystemTheme()
  loadTab()
})

async function buy() {
  const p = plans.value.find((x) => x.id === selPlan.value)
  if (!p) return ElMessage.warning('请选择套餐')
  if (!selChannel.value) return ElMessage.warning('请选择支付方式')
  buying.value = true
  try {
    await payInApi.order({
      user_id: user.user_id,
      channel: selChannel.value,
      amount_cents: p.price_cents,
    })
    ElMessage.success('下单成功（演示）')
    tab.value = 'orders'
    await loadTab()
  } catch (e) {
    ElMessage.error(e.response?.data?.message || '下单失败')
  } finally {
    buying.value = false
  }
}

async function showCfg(uuid) {
  try {
    const r = await subApi.config(uuid)
    cfgStr.value = JSON.stringify(r.data?.data || r.data, null, 2)
    cfgShow.value = true
  } catch {
    ElMessage.error('获取配置失败')
  }
}

async function quickCopy(uuid) {
  try {
    const r = await subApi.config(uuid)
    const text = JSON.stringify(r.data?.data || r.data, null, 2)
    await navigator.clipboard.writeText(text)
    ElMessage.success('配置已复制')
  } catch {
    ElMessage.error('复制失败')
  }
}

async function copy() {
  try {
    await navigator.clipboard.writeText(cfgStr.value)
    ElMessage.success('已复制')
  } catch {
    ElMessage.warning('请手动复制')
  }
}

function isActive(row) {
  if (!row?.status) return false
  if (!row.expire_date) return true
  return new Date(row.expire_date) > new Date()
}

function logout() {
  localStorage.removeItem('vpn_user_token')
  localStorage.removeItem('vpn_user_user')
  router.push('/login')
}
function fmt(t) {
  return t ? new Date(t).toLocaleString('zh-CN') : '-'
}
function fmtBytes(b) {
  if (!b) return '-'
  return b > 1e9 ? (b / 1e9).toFixed(0) + 'GB' : (b / 1e6).toFixed(0) + 'MB'
}
</script>

<style scoped>
.layout { display: flex; min-height: 100vh; background: var(--app-bg); color: var(--app-text) }
.sidebar {
  width: 220px; flex-shrink: 0; background: var(--app-sidebar); color: var(--app-sidebar-text);
  display: flex; flex-direction: column; position: sticky; top: 0; height: 100vh;
  transition: width 0.2s ease; overflow: hidden;
}
.layout.collapsed .sidebar { width: 72px }
.brand {
  display: flex; gap: 10px; align-items: center; padding: 20px 16px 16px; min-height: 72px;
  border-bottom: 1px solid rgba(255,255,255,.08);
}
.brand-mark {
  width: 36px; height: 36px; flex-shrink: 0; border-radius: 10px;
  background: linear-gradient(135deg,#667eea,#764ba2);
  color: #fff; font-weight: 800; display: flex; align-items: center; justify-content: center;
}
.brand-title { color: #fff; font-weight: 700; font-size: 14px; line-height: 1.2; white-space: nowrap }
.brand-sub { font-size: 12px; opacity: .65; margin-top: 2px; white-space: nowrap }
.menu { padding: 12px 10px; flex: 1; overflow: auto }
.menu-item {
  width: 100%; display: flex; align-items: center; gap: 10px; border: 0; background: transparent;
  color: var(--app-sidebar-text); text-align: left; padding: 11px 12px; border-radius: 10px;
  cursor: pointer; margin-bottom: 4px; font-size: 14px; white-space: nowrap;
}
.layout.collapsed .menu-item { justify-content: center; padding: 11px 0 }
.menu-item:hover { background: rgba(255,255,255,.06); color: #fff }
.menu-item.active { background: var(--app-sidebar-active-bg); color: var(--app-sidebar-active); font-weight: 600 }
.mi { font-size: 18px; flex-shrink: 0 }
.sidebar-foot {
  padding: 10px; border-top: 1px solid rgba(255,255,255,.08);
  display: flex; flex-direction: column; gap: 8px;
}
.collapse-btn {
  width: 100%; display: flex; align-items: center; gap: 10px; border: 0;
  background: rgba(255,255,255,.06); color: var(--app-sidebar-text);
  padding: 10px 12px; border-radius: 10px; cursor: pointer; font-size: 13px; white-space: nowrap;
}
.layout.collapsed .collapse-btn { justify-content: center; padding: 10px 0 }
.collapse-btn:hover { background: rgba(255,255,255,.12); color: #fff }
.foot-note { padding: 0 6px }
.layout.collapsed .brand-text,
.layout.collapsed .menu-label,
.layout.collapsed .foot-note { display: none }
.main-wrap { flex: 1; min-width: 0; display: flex; flex-direction: column }
.topbar {
  height: 56px; background: var(--app-header); border-bottom: 1px solid var(--app-border);
  display: flex; align-items: center; justify-content: space-between; padding: 0 16px 0 8px;
  position: sticky; top: 0; z-index: 5;
}
.top-left { display: flex; align-items: center; gap: 4px }
.fold-btn { padding: 8px !important }
.page-title { font-size: 16px; font-weight: 700 }
.top-actions { display: flex; align-items: center; gap: 10px; flex-wrap: wrap }
.content { padding: 16px 20px 28px; flex: 1 }
.panel, .plan, .node-card {
  background: var(--app-card); border: 1px solid var(--app-border); border-radius: 12px;
}
.plan { padding: 18px; text-align: center; cursor: pointer; margin-bottom: 12px }
.plan.sel, .plan:hover { border-color: #409eff; background: rgba(64,158,255,.08) }
.price { font-size: 26px; font-weight: 700; color: #f56c6c; margin: 8px 0 }
.node-card { padding: 14px 16px; margin-bottom: 12px }
.node-card.off { opacity: .55 }
.buy-bar { margin-top: 12px }
.muted { color: var(--app-muted); font-size: 12px }
</style>
