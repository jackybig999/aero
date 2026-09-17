<template>
  <div class="aero-root" :class="{ embedded }">
    <header class="aero-header">
      <div class="aero-brand">
        <el-icon :size="22" color="#3b82f6"><Box /></el-icon>
        <div>
          <h1>AERO 运维台</h1>
          <div class="sub">
            证书 · 节点 · 订阅 · Token（参考 Xray 面板）·
            <el-tag size="small" :type="api.mode === 'mid' ? 'primary' : 'success'" effect="dark">
              {{ api.mode === 'mid' ? 'mid-platform' : 'standalone' }}
            </el-tag>
          </div>
        </div>
      </div>
      <div class="toolbar" style="margin: 0">
        <el-button size="small" type="primary" :loading="refreshing" @click="fullRefresh">
          <el-icon><Refresh /></el-icon> 全面诊断
        </el-button>
      </div>
    </header>

    <!-- Standalone config -->
    <el-card v-if="api.mode === 'standalone'" shadow="never" class="panel-card" style="margin-bottom: 12px">
      <template #header>
        <div class="card-hd">
          <span>连接 Edge</span>
          <el-button size="small" type="primary" :loading="savingCfg" @click="saveConfig">保存</el-button>
        </div>
      </template>
      <div class="toolbar">
        <el-input v-model="cfg.edge_url" placeholder="https://127.0.0.1:443" style="width: 280px" clearable />
        <el-input v-model="cfg.admin_key" placeholder="Admin Key" style="width: 220px" show-password clearable />
        <el-input v-model="cfg.sub_url" placeholder="订阅 URL" style="width: 320px" clearable />
      </div>
    </el-card>

    <!-- Deploy -->
    <el-card v-if="api.features.deploy" shadow="never" class="panel-card" style="margin-bottom: 12px">
      <template #header>
        <div class="card-hd">
          <span>部署 / 节点选择</span>
          <div>
            <el-button size="small" :disabled="!vpsId" :loading="acting" @click="doRestart">重启 Edge</el-button>
            <el-button size="small" type="primary" :disabled="!vpsId" :loading="deploying" @click="doInstall">安装/升级</el-button>
            <el-button size="small" type="danger" plain :disabled="!vpsId" :loading="deploying" @click="doUninstall">卸载</el-button>
          </div>
        </div>
      </template>
      <div class="toolbar">
        <el-select v-model="vpsId" placeholder="选择 VPS" style="width: 300px" filterable @change="onVpsChange">
          <el-option v-for="v in vpsList" :key="v.id" :label="`${v.name || v.id} · ${v.ip || ''}`" :value="v.id" />
        </el-select>
        <span class="muted">中台经 SSH 运维；状态不依赖公网 Admin</span>
      </div>
      <el-table v-if="tasksFiltered.length" :data="tasksFiltered" stripe size="small" max-height="180" @row-click="openTask">
        <el-table-column prop="id" label="ID" width="56" />
        <el-table-column prop="kind" label="类型" width="80" />
        <el-table-column prop="vps_name" label="VPS" width="100" />
        <el-table-column label="进度" width="130">
          <template #default="{ row }">
            <el-progress
              :percentage="row.progress || 0"
              :status="row.status === 'failed' ? 'exception' : row.status === 'success' ? 'success' : undefined"
              :stroke-width="10"
            />
          </template>
        </el-table-column>
        <el-table-column prop="stage" label="阶段" min-width="90" show-overflow-tooltip />
        <el-table-column prop="status" label="状态" width="90" />
      </el-table>
    </el-card>

    <!-- Overview strip -->
    <div class="ov-strip" v-if="diag || statusErr">
      <div class="ov-item">
        <div class="ov-k">总览</div>
        <el-tag :type="overallOnline ? 'success' : 'danger'" effect="dark" size="small">
          {{ overallOnline ? '可运维' : '异常' }}
        </el-tag>
        <span class="muted" style="margin-left: 8px">via {{ diag?.via || '—' }}</span>
      </div>
      <div class="ov-item">
        <div class="ov-k">服务</div>
        <el-tag :type="diag?.service?.active ? 'success' : 'danger'" size="small">
          {{ diag?.service?.status || 'unknown' }}
        </el-tag>
      </div>
      <div class="ov-item">
        <div class="ov-k">443</div>
        <el-tag :type="port443 ? 'success' : 'warning'" size="small">{{ port443 ? 'LISTEN' : 'DOWN' }}</el-tag>
      </div>
      <div class="ov-item">
        <div class="ov-k">证书</div>
        <el-tag :type="diag?.cert?.ok ? 'success' : 'warning'" size="small">
          {{ diag?.cert?.mode || '—' }} {{ diag?.cert?.ok ? 'OK' : '异常' }}
        </el-tag>
      </div>
      <div class="ov-item">
        <div class="ov-k">订阅本机</div>
        <el-tag :type="diag?.subscription?.local_ok ? 'success' : 'danger'" size="small">
          {{ diag?.subscription?.local_ok ? '可达' : '失败' }}
        </el-tag>
      </div>
      <div class="ov-item">
        <div class="ov-k">订阅公网</div>
        <el-tag :type="diag?.subscription?.public_ok ? 'success' : 'info'" size="small">
          {{ diag?.subscription?.public_ok ? '可达' : '中台侧不可达' }}
        </el-tag>
      </div>
    </div>

    <div class="aero-grid two" style="margin-top: 12px">
      <!-- Nodes -->
      <el-card shadow="never" class="panel-card">
        <template #header>
          <div class="card-hd">
            <span>节点种类 / 连通</span>
            <el-button size="small" :loading="refreshing" @click="loadDiag">重测</el-button>
          </div>
        </template>
        <el-table :data="diag?.nodes || []" size="small" stripe empty-text="请选 VPS 并诊断">
          <el-table-column label="状态" width="72">
            <template #default="{ row }">
              <el-tag :type="row.online ? 'success' : 'danger'" size="small" effect="dark">
                {{ row.online ? '通' : '断' }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="name" label="类型" min-width="120" />
          <el-table-column prop="kind" label="Kind" width="110" />
          <el-table-column prop="target" label="目标" min-width="140" show-overflow-tooltip />
          <el-table-column prop="detail" label="详情" min-width="140" show-overflow-tooltip />
        </el-table>
        <div v-if="diag?.ports?.length" style="margin-top: 12px">
          <div class="muted" style="margin-bottom: 6px">监听端口</div>
          <div class="chip-row">
            <el-tag
              v-for="p in diag.ports"
              :key="p.port"
              :type="p.listen ? 'success' : 'info'"
              size="small"
              style="margin: 0 6px 6px 0"
            >
              {{ p.port }}/{{ p.proto }} · {{ p.role }} · {{ p.listen ? 'listen' : 'closed' }}
            </el-tag>
          </div>
        </div>
      </el-card>

      <!-- Cert -->
      <el-card shadow="never" class="panel-card">
        <template #header>
          <div class="card-hd">
            <span>证书状态</span>
            <div>
              <el-button
                size="small"
                type="primary"
                :disabled="!vpsId || !api.features.cert"
                :loading="certing"
                @click="doRenewCert(false)"
              >
                安装/续签
              </el-button>
              <el-button size="small" :disabled="!vpsId || !api.features.cert" :loading="certing" @click="doRenewCert(true)">
                清空重签
              </el-button>
            </div>
          </div>
        </template>
        <div v-if="diag?.cert" class="kv-grid">
          <div class="kv"><span class="k">模式</span><span class="v">{{ diag.cert.mode || '—' }}</span></div>
          <div class="kv"><span class="k">域名</span><span class="v">{{ diag.cert.domain || diag.domain || '—' }}</span></div>
          <div class="kv">
            <span class="k">状态</span>
            <span class="v">
              <el-tag :type="diag.cert.ok ? 'success' : 'danger'" size="small">{{ diag.cert.ok ? 'OK' : '异常' }}</el-tag>
              {{ diag.cert.detail || '' }}
            </span>
          </div>
          <div class="kv"><span class="k">文件</span><span class="v">{{ diag.cert.file_count ?? 0 }} · {{ diag.cert.dir || '' }}</span></div>
          <div class="kv"><span class="k">到期</span><span class="v">{{ diag.cert.not_after || '—' }}</span></div>
          <div class="kv"><span class="k">剩余天</span><span class="v">{{ diag.cert.days_left != null && diag.cert.days_left !== 0 ? diag.cert.days_left : '—' }}</span></div>
        </div>
        <div v-else class="empty-hint">未诊断</div>
        <el-alert
          v-if="diag && !diag.cert?.ok"
          type="warning"
          :closable="false"
          show-icon
          style="margin-top: 10px"
          title="证书异常时客户端 TLS 会失败。确认域名 A 记录指向 VPS IP 后点「安装/续签」。"
        />
      </el-card>
    </div>

    <div class="aero-grid two" style="margin-top: 12px">
      <!-- Subscription detail -->
      <el-card shadow="never" class="panel-card">
        <template #header>
          <div class="card-hd">
            <span>订阅详细信息</span>
            <div>
              <el-button size="small" :disabled="!subURL" @click="copy(subURL)">复制 URL</el-button>
            </div>
          </div>
        </template>
        <div class="sub-box">
          <div class="mono">{{ subURL || '（无）' }}</div>
          <div class="sub-row" style="margin-top: 10px">
            <div class="qr-wrap" v-if="qrDataUrl">
              <img :src="qrDataUrl" alt="QR" />
            </div>
            <div class="kv-grid" style="flex: 1">
              <div class="kv">
                <span class="k">Secret</span>
                <span class="v">{{ diag?.subscription?.secret_set === 'yes' ? '已配置' : '缺失' }}</span>
              </div>
              <div class="kv">
                <span class="k">VPS 本机拉取</span>
                <span class="v">
                  <el-tag :type="diag?.subscription?.local_ok ? 'success' : 'danger'" size="small">
                    {{ diag?.subscription?.local_ok ? 'OK' : 'FAIL' }}
                  </el-tag>
                  <span class="muted" v-if="diag?.subscription?.local_http">
                    HTTP {{ diag.subscription.local_http }} · {{ diag.subscription.local_bytes || 0 }} B
                  </span>
                </span>
              </div>
              <div class="kv">
                <span class="k">中台公网拉取</span>
                <span class="v">
                  <el-tag :type="diag?.subscription?.public_ok ? 'success' : 'info'" size="small">
                    {{ diag?.subscription?.public_ok ? 'OK' : '不可达/超时' }}
                  </el-tag>
                </span>
              </div>
              <div class="kv" v-if="diag?.subscription?.local_error">
                <span class="k">本机错误</span>
                <span class="v mono">{{ diag.subscription.local_error }}</span>
              </div>
              <div class="kv" v-if="diag?.subscription?.public_error">
                <span class="k">公网错误</span>
                <span class="v mono">{{ diag.subscription.public_error }}</span>
              </div>
              <div class="kv" v-if="diag?.subscription?.preview">
                <span class="k">内容预览</span>
                <span class="v mono">{{ diag.subscription.preview }}</span>
              </div>
            </div>
          </div>
          <el-alert
            type="info"
            :closable="false"
            show-icon
            style="margin-top: 10px"
            title="本机可达即可给客户端用；中台公网失败多半是 DNS/TLS/防火墙，不代表 Edge 没装好。"
          />
        </div>
      </el-card>

      <!-- Tokens + service metrics -->
      <div style="display: flex; flex-direction: column; gap: 12px">
        <el-card shadow="never" class="panel-card">
          <template #header>
            <div class="card-hd">
              <span>Token</span>
              <el-button size="small" type="primary" :disabled="!canTokens" @click="showAdd = true">新增</el-button>
            </div>
          </template>
          <el-table :data="tokens" stripe size="small" empty-text="无 token 或 Admin 不可达">
            <el-table-column label="Token" min-width="140">
              <template #default="{ row }">
                <span class="mono">{{ row.token_mask || mask(row.token) || row.token }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="label" label="标签" width="90" show-overflow-tooltip />
            <el-table-column label="操作" width="120" fixed="right">
              <template #default="{ row }">
                <el-button size="small" link type="primary" @click="copy(tokenValue(row))">复制</el-button>
                <el-button size="small" link type="danger" @click="removeToken(row)">删</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-card>

        <el-card shadow="never" class="panel-card">
          <template #header>
            <div class="card-hd"><span>运行指标 / 提示</span></div>
          </template>
          <div class="status-grid" v-if="metricCards.length">
            <div class="status-item" v-for="(it, i) in metricCards" :key="i">
              <div class="k">{{ it.k }}</div>
              <div class="v">{{ it.v }}</div>
            </div>
          </div>
          <ul v-if="diag?.hints?.length" class="hint-list">
            <li v-for="(h, i) in diag.hints" :key="i">{{ h }}</li>
          </ul>
          <div v-if="diag?.log_tail" class="log-box" style="margin-top: 8px">{{ prettyLog(diag.log_tail) }}</div>
          <div v-if="statusErr && !diag" class="empty-hint">{{ statusErr }}</div>
        </el-card>
      </div>
    </div>

    <el-drawer v-model="taskOpen" title="任务详情" size="420px">
      <template v-if="activeTask">
        <p><b>#{{ activeTask.id }}</b> · {{ activeTask.kind }} · {{ activeTask.status }}</p>
        <div class="log-box">{{ activeTask.log || activeTask.error || '(no log)' }}</div>
      </template>
    </el-drawer>

    <el-dialog v-model="showAdd" title="新增 Token" width="420px" destroy-on-close>
      <el-form label-width="90px">
        <el-form-item label="标签"><el-input v-model="newTok.label" /></el-form-item>
        <el-form-item label="自定义"><el-input v-model="newTok.token" placeholder="空则自动生成" /></el-form-item>
        <el-form-item label="TTL 小时"><el-input-number v-model="newTok.ttl_hours" :min="0" :max="87600" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showAdd = false">取消</el-button>
        <el-button type="primary" :loading="adding" @click="addToken">创建</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import QRCode from 'qrcode'
import { createAeroClient, PANEL_KEY } from '../api/client'

const props = defineProps({
  mode: { type: String, default: '' },
  embedded: { type: Boolean, default: false },
})

const api = createAeroClient(props.mode || undefined)

const vpsId = ref(null)
const vpsList = ref([])
const tasks = ref([])
const endpoint = ref(null)
const tokens = ref([])
const diag = ref(null)
const statusErr = ref('')
const qrDataUrl = ref('')
const deploying = ref(false)
const refreshing = ref(false)
const acting = ref(false)
const certing = ref(false)
const showAdd = ref(false)
const adding = ref(false)
const newTok = reactive({ label: '', token: '', ttl_hours: 0 })
const taskOpen = ref(false)
const activeTask = ref(null)
const cfg = reactive({ edge_url: '', admin_key: '', sub_url: '' })
const savingCfg = ref(false)
let pollTimer = null

const canTokens = computed(() => (api.mode === 'standalone' ? true : !!vpsId.value))
const tasksFiltered = computed(() => tasks.value || [])
const subURL = computed(() => diag.value?.subscription?.url || endpoint.value?.sub_url || cfg.sub_url || '')
const overallOnline = computed(() => !!(diag.value?.ok || diag.value?.service?.active))
const port443 = computed(() => (diag.value?.ports || []).some((p) => p.port === 443 && p.listen))

const metricCards = computed(() => {
  const m = diag.value?.metrics || diag.value?.admin?.status || {}
  const cards = []
  const pick = (k, label) => {
    if (m[k] != null) cards.push({ k: label || k, v: typeof m[k] === 'number' ? Math.round(m[k] * 100) / 100 : m[k] })
  }
  pick('version', 'version')
  pick('protocol', 'protocol')
  pick('active_tunnels', 'tunnels')
  pick('token_count', 'tokens')
  pick('uptime_sec', 'uptime_s')
  pick('max_conn', 'max_conn')
  if (diag.value?.binary?.version) cards.unshift({ k: 'binary', v: diag.value.binary.version })
  if (diag.value?.service?.main_pid) cards.push({ k: 'pid', v: diag.value.service.main_pid })
  return cards
})

function mask(t) {
  if (!t || t.length < 8) return t
  return t.slice(0, 4) + '…' + t.slice(-4)
}
function tokenValue(row) {
  return row.token_full || row.token || ''
}
function prettyLog(s) {
  return String(s || '').replace(/\|/g, '\n')
}

async function copy(text) {
  if (!text) return
  try {
    await navigator.clipboard.writeText(text)
    ElMessage.success('已复制')
  } catch {
    ElMessage.warning('复制失败')
  }
}

async function renderQR(url) {
  if (!url) {
    qrDataUrl.value = ''
    return
  }
  try {
    qrDataUrl.value = await QRCode.toDataURL(url, { width: 168, margin: 1 })
  } catch {
    qrDataUrl.value = ''
  }
}
watch(subURL, (u) => renderQR(u), { immediate: true })

async function loadVPS() {
  if (!api.features.multiVps) return
  try {
    vpsList.value = await api.listVPS()
    if (!vpsId.value && vpsList.value[0]) vpsId.value = vpsList.value[0].id
  } catch (e) {
    ElMessage.error(e.message || '加载 VPS 失败')
  }
}
async function loadTasks() {
  if (!api.features.tasks) return
  try {
    tasks.value = await api.listTasks()
  } catch {
    /* ignore */
  }
}
async function loadEndpoint() {
  try {
    if (api.mode === 'mid') {
      if (!vpsId.value) {
        endpoint.value = null
        return
      }
      endpoint.value = await api.getEndpoint(vpsId.value)
    } else {
      endpoint.value = await api.getEndpoint()
    }
  } catch {
    endpoint.value = null
  }
}
async function loadTokens() {
  try {
    if (api.mode === 'mid') {
      if (!vpsId.value) {
        tokens.value = []
        return
      }
      tokens.value = await api.listTokens(vpsId.value)
    } else {
      tokens.value = await api.listTokens()
    }
  } catch {
    tokens.value = []
  }
}
async function loadDiag() {
  statusErr.value = ''
  try {
    if (api.mode === 'mid') {
      if (!vpsId.value) {
        diag.value = null
        return
      }
      diag.value = await api.diagnose(vpsId.value)
    } else {
      diag.value = await api.status()
    }
    if (diag.value?.subscription?.url) {
      endpoint.value = {
        ...(endpoint.value || {}),
        sub_url: diag.value.subscription.url,
        host: diag.value.domain,
        ip: diag.value.ip,
        installed: diag.value.service?.active,
        has_admin: diag.value.admin?.reachable,
      }
    }
  } catch (e) {
    diag.value = null
    statusErr.value = e.message || '诊断失败'
  }
}

async function fullRefresh() {
  refreshing.value = true
  try {
    await loadVPS()
    await loadTasks()
    await loadEndpoint()
    await loadDiag()
    await loadTokens()
  } finally {
    refreshing.value = false
  }
}

async function onVpsChange() {
  await loadEndpoint()
  await loadDiag()
  await loadTokens()
}

async function doInstall() {
  if (!vpsId.value) return
  deploying.value = true
  try {
    const task = await api.install(vpsId.value)
    ElMessage.success('安装任务已创建')
    if (task) openTask(task)
    for (let i = 0; i < 80; i++) {
      await sleep(800)
      await loadTasks()
      const t = tasks.value.find((x) => x.id === task?.id)
      if (t && (t.status === 'success' || t.status === 'failed')) {
        ElMessage[t.status === 'success' ? 'success' : 'error'](t.status === 'success' ? '完成' : t.error || '失败')
        if (t.status === 'success') await fullRefresh()
        break
      }
    }
  } catch (e) {
    ElMessage.error(e.message || '失败')
  } finally {
    deploying.value = false
  }
}

async function doUninstall() {
  if (!vpsId.value) return
  try {
    await ElMessageBox.confirm('卸载 AERO（保留 VPS 登记）？', '卸载', { type: 'warning' })
  } catch {
    return
  }
  deploying.value = true
  try {
    const task = await api.uninstall(vpsId.value)
    if (task) openTask(task)
    for (let i = 0; i < 50; i++) {
      await sleep(600)
      await loadTasks()
      const t = tasks.value.find((x) => x.id === task?.id)
      if (t && (t.status === 'success' || t.status === 'failed')) break
    }
    diag.value = null
    tokens.value = []
  } catch (e) {
    ElMessage.error(e.message || '卸载失败')
  } finally {
    deploying.value = false
  }
}

async function doRestart() {
  if (!vpsId.value) return
  acting.value = true
  try {
    const r = await api.restartEdge(vpsId.value)
    ElMessage[r?.ok ? 'success' : 'warning'](r?.ok ? '已重启' : '重启完成但状态存疑')
    await loadDiag()
  } catch (e) {
    ElMessage.error(e.message || '重启失败')
  } finally {
    acting.value = false
  }
}

async function doRenewCert(force) {
  if (!vpsId.value) return
  if (force) {
    try {
      await ElMessageBox.confirm('将清空 ACME 缓存并重启 Edge 重新申请证书。域名 A 记录必须指向本机。', '清空重签', {
        type: 'warning',
      })
    } catch {
      return
    }
  }
  certing.value = true
  try {
    const r = await api.renewCert(vpsId.value, force)
    ElMessage[r?.ok ? 'success' : 'warning'](r?.ok ? '证书流程已执行' : '已执行，请看证书状态')
    await loadDiag()
  } catch (e) {
    ElMessage.error(e.message || '证书操作失败')
  } finally {
    certing.value = false
  }
}

function openTask(row) {
  activeTask.value = row
  taskOpen.value = true
  if (row?.id && api.features.tasks) {
    api.getTask(row.id).then((t) => {
      if (t) activeTask.value = t
    }).catch(() => {})
  }
}

async function addToken() {
  adding.value = true
  try {
    const r = await api.addToken(vpsId.value, {
      token: newTok.token,
      label: newTok.label,
      ttl_hours: newTok.ttl_hours || 0,
    })
    ElMessage.success('已创建')
    if (r?.token) await copy(r.token)
    showAdd.value = false
    newTok.label = ''
    newTok.token = ''
    newTok.ttl_hours = 0
    await loadTokens()
    await loadDiag()
  } catch (e) {
    ElMessage.error(e.message || '新增失败')
  } finally {
    adding.value = false
  }
}

async function removeToken(row) {
  const tok = tokenValue(row)
  if (!tok) return ElMessage.warning('无完整 token')
  try {
    await ElMessageBox.confirm('删除该 token？', '删除', { type: 'warning' })
    await api.delToken(vpsId.value, tok)
    ElMessage.success('已删除')
    await loadTokens()
  } catch (e) {
    if (e === 'cancel' || e === 'close') return
    ElMessage.error(e.message || '删除失败')
  }
}

async function loadConfig() {
  if (api.mode !== 'standalone') return
  try {
    const c = await api.getPanelConfig()
    if (c?.edge_url) cfg.edge_url = c.edge_url
    if (c?.sub_url) cfg.sub_url = c.sub_url
    const local = localStorage.getItem(PANEL_KEY)
    if (local) cfg.admin_key = local
  } catch {
    /* ignore */
  }
}

async function saveConfig() {
  savingCfg.value = true
  try {
    if (cfg.admin_key) localStorage.setItem(PANEL_KEY, cfg.admin_key)
    else localStorage.removeItem(PANEL_KEY)
    await api.savePanelConfig({ edge_url: cfg.edge_url, admin_key: cfg.admin_key, sub_url: cfg.sub_url })
    ElMessage.success('已保存')
    await fullRefresh()
  } catch (e) {
    ElMessage.error(e.message || '保存失败')
  } finally {
    savingCfg.value = false
  }
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms))
}

onMounted(async () => {
  await loadConfig()
  await fullRefresh()
  pollTimer = setInterval(() => {
    if (api.features.tasks) loadTasks()
    if (vpsId.value || api.mode === 'standalone') loadDiag()
  }, 20000)
})
onUnmounted(() => {
  if (pollTimer) clearInterval(pollTimer)
})
</script>

<style scoped>
.ov-strip {
  display: flex;
  flex-wrap: wrap;
  gap: 10px 16px;
  padding: 12px 14px;
  background: var(--aero-card);
  border: 1px solid var(--aero-border);
  border-radius: 10px;
  align-items: center;
}
.ov-item {
  display: flex;
  align-items: center;
  gap: 6px;
}
.ov-k {
  color: var(--aero-muted);
  font-size: 12px;
}
.kv-grid {
  display: grid;
  gap: 8px;
}
.kv {
  display: grid;
  grid-template-columns: 100px 1fr;
  gap: 8px;
  font-size: 13px;
  align-items: start;
}
.kv .k {
  color: var(--aero-muted);
}
.kv .v {
  word-break: break-all;
}
.chip-row {
  display: flex;
  flex-wrap: wrap;
}
.hint-list {
  margin: 8px 0 0;
  padding-left: 18px;
  color: #c9d4e8;
  font-size: 12px;
  line-height: 1.55;
}
</style>
