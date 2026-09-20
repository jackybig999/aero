let _reg = null
let _sessions = []
let _selected = null
let _search = ''
let _category = 'all'

const CATEGORIES = [
  { key: 'all',    i18nKey: 'allSessions' },
  { key: 'claude', i18nKey: 'claudeCode' },
  { key: 'codex',  i18nKey: 'codexCLI' },
]

function filterSessions() {
  let list = _sessions
  if (_category !== 'all') {
    list = list.filter(s => s.id.startsWith(_category + ':'))
  }
  if (_search) {
    const q = _search.toLowerCase()
    list = list.filter(s => s.title.toLowerCase().includes(q) || s.id.toLowerCase().includes(q))
  }
  return list
}

// ─── Overlay DOM ─────────────────────────────────────────────────────────────

function buildOverlay() {
  const t = _reg.i18n.t

  const mask = document.createElement('div')
  mask.id = 'history-mask'
  mask.className = 'history-mask'

  const panel = document.createElement('div')
  panel.className = 'history-panel'

  // Header
  const hdr = document.createElement('div')
  hdr.className = 'history-header'
  const title = document.createElement('h3')
  title.textContent = t('historyTitle') || '历史对话'
  const closeBtn = document.createElement('button')
  closeBtn.className = 'btn-icon'
  closeBtn.textContent = '✕'
  closeBtn.onclick = closeOverlay
  hdr.appendChild(title)
  hdr.appendChild(closeBtn)
  panel.appendChild(hdr)

  // Body
  const body = document.createElement('div')
  body.className = 'history-body'

  // Left panel
  const left = document.createElement('div')
  left.className = 'history-left'

  // Category tabs
  const tabs = document.createElement('div')
  tabs.className = 'history-tabs'
  for (const cat of CATEGORIES) {
    const tab = document.createElement('button')
    tab.className = 'history-tab' + (_category === cat.key ? ' active' : '')
    tab.textContent = t(cat.i18nKey)
    tab.dataset.cat = cat.key
    tab.onclick = () => { _category = cat.key; refreshOverlay(left) }
    tabs.appendChild(tab)
  }
  left.appendChild(tabs)

  // Search
  const search = document.createElement('input')
  search.className = 'history-search'
  search.placeholder = t('searchPlaceholder') || '搜索对话...'
  search.oninput = (e) => { _search = e.target.value.toLowerCase(); renderList(left) }
  left.appendChild(search)

  // Count
  const count = document.createElement('div')
  count.className = 'history-count'
  count.textContent = `${t('totalSessions') || '共'} ${_sessions.length} ${t('sessionsUnit') || '条'}`
  left.appendChild(count)

  // List
  const listEl = document.createElement('div')
  listEl.className = 'history-list'
  left.appendChild(listEl)

  // Actions
  const actions = document.createElement('div')
  actions.className = 'history-actions'

  const exportBtn = document.createElement('button')
  exportBtn.className = 'btn-text'
  exportBtn.textContent = t('exportMd') || '导出 MD'
  exportBtn.onclick = doExport

  const delBtn = document.createElement('button')
  delBtn.className = 'btn-text'
  delBtn.style.color = 'var(--error)'
  delBtn.textContent = t('deleteSelected') || '删除'
  delBtn.onclick = doDelete

  actions.appendChild(exportBtn)
  actions.appendChild(delBtn)
  left.appendChild(actions)
  body.appendChild(left)

  // Right: preview
  const right = document.createElement('div')
  right.id = 'history-preview'
  right.className = 'history-preview'
  const placeholder = document.createElement('div')
  placeholder.className = 'history-placeholder'
  placeholder.textContent = t('selectSessionHint') || '← 选择一个会话查看对话内容'
  right.appendChild(placeholder)
  body.appendChild(right)

  panel.appendChild(body)
  mask.appendChild(panel)
  return mask
}

function refreshOverlay(left) {
  // Update active tab
  left.querySelectorAll('.history-tab').forEach(t => {
    t.classList.toggle('active', t.dataset.cat === _category)
  })
  // Update count
  const count = left.querySelector('.history-count')
  const filtered = filterSessions()
  if (count) count.textContent = `${_reg.i18n.t('totalSessions') || '共'} ${filtered.length} ${_reg.i18n.t('sessionsUnit') || '条'}`
  renderList(left)
}

function renderList(left) {
  const listEl = left.querySelector('.history-list')
  listEl.textContent = ''

  const filtered = filterSessions()

  if (filtered.length === 0) {
    const empty = document.createElement('div')
    empty.className = 'history-empty'
    empty.textContent = _search
      ? ((_reg.i18n.t('noSearchResults')) || '无匹配结果')
      : ((_reg.i18n.t('noHistory')) || '暂无对话记录')
    listEl.appendChild(empty)
    return
  }

  const now = Date.now()
  for (const s of filtered) {
    const item = document.createElement('div')
    item.className = 'history-item' + (_selected && _selected.id === s.id ? ' selected' : '')

    const icon = document.createElement('span')
    icon.className = 'history-item-icon'
    icon.textContent = s.icon

    const info = document.createElement('div')
    info.className = 'history-item-info'

    const titleLine = document.createElement('div')
    titleLine.className = 'history-item-title'
    titleLine.textContent = s.title || '(无标题)'

    const metaLine = document.createElement('div')
    metaLine.className = 'history-item-meta'
    const age = Math.round((now - s.time) / 3600000)
    const ageStr = age < 1 ? '刚刚' : age < 24 ? `${age}h前` : `${Math.round(age/24)}d前`
    metaLine.textContent = `${s.tool} · ${s.lines}行 · ${ageStr}`
    if (s.project) metaLine.textContent += ` · ${s.project}`

    info.appendChild(titleLine)
    info.appendChild(metaLine)
    item.appendChild(icon)
    item.appendChild(info)

    item.onclick = () => selectSession(s, item)
    listEl.appendChild(item)
  }
}

async function selectSession(session, el) {
  _selected = session

  const listEl = document.querySelector('.history-list')
  if (listEl) {
    listEl.querySelectorAll('.history-item').forEach(i => i.classList.remove('selected'))
    if (el) el.classList.add('selected')
  }

  const right = document.getElementById('history-preview')
  if (!right) return
  right.textContent = ''

  const loading = document.createElement('div')
  loading.className = 'history-placeholder'
  loading.textContent = '加载中...'
  right.appendChild(loading)

  const res = await window.armAPI.history.view(session.id)
  if (!res.success || !res.content) {
    loading.textContent = '无法加载对话内容'
    return
  }

  right.textContent = ''
  const wrap = document.createElement('div')
  wrap.className = 'history-messages'

  const lines = res.content.split('\n').filter(l => l.trim())
  for (const line of lines) {
    try {
      const obj = JSON.parse(line)
      if (obj.type === 'user') {
        const text = obj.message?.content || ''
        if (text) {
          const msg = document.createElement('div')
          msg.className = 'history-msg history-msg-user'
          msg.textContent = text
          wrap.appendChild(msg)
        }
      } else if (obj.type === 'assistant') {
        const blocks = obj.message?.content || []
        for (const block of blocks) {
          if (block.type === 'text' && block.text) {
            const msg = document.createElement('div')
            msg.className = 'history-msg history-msg-assistant'
            msg.textContent = block.text.slice(0, 500)
            wrap.appendChild(msg)
          }
        }
      }
    } catch {}
  }

  right.appendChild(wrap)
  right.scrollTop = 0
}

function closeOverlay() {
  const mask = document.getElementById('history-mask')
  if (mask) mask.remove()
  _selected = null
}

async function doExport() {
  if (!_selected) return
  const t = _reg.i18n.t
  const res = await window.armAPI.history.export(_selected.id)
  if (res.success) {
    _reg.bus.emit('log:append', `[${new Date().toLocaleTimeString()}] ${t('exportedTo') || '已导出到'}: ${res.path}`)
  } else if (res.error !== 'cancelled') {
    _reg.bus.emit('log:append', `[${new Date().toLocaleTimeString()}] ${t('exportFailed') || '导出失败'}: ${res.error}`)
  }
}

async function doDelete() {
  if (!_selected) return
  if (!confirm((_reg.i18n.t('confirmDeleteSession') || '确认删除此对话记录？'))) return

  const res = await window.armAPI.history.delete(_selected.id)
  if (res.success) {
    _reg.bus.emit('log:append', `[${new Date().toLocaleTimeString()}] ${_reg.i18n.t('sessionDeleted') || '已删除对话'}`)
    _sessions = _sessions.filter(s => s.id !== _selected.id)
    _selected = null
    const left = document.querySelector('.history-left')
    if (left) refreshOverlay(left)
  }
}

async function showOverlay() {
  const old = document.getElementById('history-mask')
  if (old) old.remove()

  _selected = null
  _category = 'all'
  _search = ''
  const res = await window.armAPI.history.list()
  if (res.success) _sessions = res.sessions

  const overlay = buildOverlay()
  document.body.appendChild(overlay)

  renderList(overlay.querySelector('.history-left'))
  overlay.onclick = (e) => { if (e.target === overlay) closeOverlay() }
  document.addEventListener('keydown', onKeyDown)
}

function onKeyDown(e) {
  if (e.key === 'Escape') {
    closeOverlay()
    document.removeEventListener('keydown', onKeyDown)
  }
}

// ─── Module descriptor ───────────────────────────────────────────────────────

function updateBtnText() {
  const btn = document.getElementById('btn-history')
  if (btn) btn.textContent = _reg.i18n.t('historyTitle') || '对话历史'
}

export const historyModule = {
  name: 'history',

  init(reg) {
    _reg = reg
    updateBtnText()
    const btn = document.getElementById('btn-history')
    if (btn) btn.onclick = () => showOverlay()
  },

  async refresh() {
    updateBtnText()
  },

  destroy() {
    document.removeEventListener('keydown', onKeyDown)
    const mask = document.getElementById('history-mask')
    if (mask) mask.remove()
  }
}
