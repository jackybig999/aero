import { proxyApi, aeroApi } from '../../api/bridge.js'

let _reg = null
let _pollingTimer = null
let _firstPoll = true

const POLL_INTERVAL = 3000

// ─── Internal state ────────────────────────────────────────────────────────────
const _state = {
  proxies: [],
  selected: null,
  systemProxy: null,
}

function _key(p) { return `${p.host}:${p.port}` }

function _sameList(a, b) {
  if (a.length !== b.length) return false
  const setA = new Set(a.map(p => _key(p)))
  return b.every(p => setA.has(_key(p)))
}

// ─── Render ────────────────────────────────────────────────────────────────────

function updateAeroBar(proxies) {
  const el = document.getElementById('aero-status')
  if (!el) return
  const hit = (proxies || []).find(p =>
    Number(p.port) === 55555 ||
    Number(p.port) === 1080 ||
    String(p.name || '').toLowerCase().includes('aero')
  )
  if (hit) {
    el.className = 'aero-status ok'
    el.textContent = `已连接 ${hit.host}:${hit.port} · 启动 AI 工具走 AERO`
  } else {
    el.className = 'aero-status miss'
    el.textContent = '未连接 — 点「连接 AERO」一键接管，替代其它 VPN'
  }
}

function renderSystemProxy() {
  const list = document.getElementById('proxy-list')
  if (!list) return

  const existing = list.querySelector('.system-proxy-bar')
  if (existing) existing.remove()

  const sp = _state.systemProxy
  if (!sp || !sp.enabled) return

  const bar = document.createElement('div')
  bar.className = 'system-proxy-bar'

  const dot = document.createElement('span')
  dot.className = 'system-proxy-dot'

  const text = document.createElement('span')
  text.textContent = `系统代理: ${sp.host}:${sp.port}`

  bar.appendChild(dot)
  bar.appendChild(text)
  list.insertBefore(bar, list.firstChild)
}

function renderEmpty() {
  const list = document.getElementById('proxy-list')
  if (!list) return
  list.textContent = ''
  renderSystemProxy()
  const empty = document.createElement('div')
  empty.className = 'proxy-empty'
  const t = _reg.i18n.t
  const line1 = document.createElement('div')
  line1.textContent = t('noProxy')
  const line2 = document.createElement('span')
  line2.className = 'proxy-hint'
  line2.textContent = t('proxyHint')
  empty.appendChild(line1)
  empty.appendChild(document.createElement('br'))
  empty.appendChild(line2)
  list.appendChild(empty)
}

function renderList(proxies) {
  const list = document.getElementById('proxy-list')
  if (!list) return
  list.textContent = ''
  renderSystemProxy()
  const t = _reg.i18n.t

  proxies.forEach((p) => {
    const isSelected = _state.selected && _key(_state.selected) === _key(p)
    const item = document.createElement('div')
    item.className = 'proxy-item' + (isSelected ? ' selected' : '')

    const icon = document.createElement('div')
    icon.className = 'proxy-icon'
    icon.textContent = p.protocol === 'socks5' ? 'S5' : 'H'

    const info = document.createElement('div')
    info.className = 'proxy-info'
    const addr = document.createElement('div')
    addr.className = 'proxy-addr'
    addr.textContent = `${p.host}:${p.port}`
    const meta = document.createElement('div')
    meta.className = 'proxy-meta'
    meta.textContent = `${p.protocol.toUpperCase()} · ${p.latency}ms`
    info.appendChild(addr)
    info.appendChild(meta)

    const badge = document.createElement('div')
    badge.className = 'proxy-badge ' + (p.verified ? 'verified' : 'unverified')
    badge.textContent = p.verified ? t('verified') : t('unverified')

    item.appendChild(icon)
    item.appendChild(info)
    item.appendChild(badge)

    item.onclick = () => {
      document.querySelectorAll('.proxy-item').forEach(el => el.classList.remove('selected'))
      item.classList.add('selected')
      _state.selected = p
      _reg.bus.emit('proxy:changed', { proxies, selected: p })
      _reg.bus.emit('launch:update')
    }

    list.appendChild(item)
  })
}

// ─── Polling ───────────────────────────────────────────────────────────────────

async function poll() {
  try {
    const res = await proxyApi.detect()
    if (!res.success) return

    _state.systemProxy = res.systemProxy || null

    const oldList = _state.proxies || []
    const newList = res.proxies || []

    const listChanged = !_sameList(oldList, newList)
    if (!_firstPoll && !listChanged) {
      renderSystemProxy()
      return
    }
    _firstPoll = false

    const oldKey = _state.selected ? _key(_state.selected) : null

    _state.proxies = newList

    if (newList.length === 0) {
      _state.selected = null
      renderEmpty()
      _reg.bus.emit('status:set', { type: 'error', text: _reg.i18n.t('noProxyShort') })
    } else {
      const stillExists = oldKey && newList.some(p => _key(p) === oldKey)
      if (!stillExists) _state.selected = newList[0]
      renderList(newList)
      _reg.bus.emit('status:set', { type: 'ready', text: `${newList.length} ${_reg.i18n.t('proxiesAvailable')}` })
    }

    _reg.bus.emit('proxy:changed', { proxies: newList, selected: _state.selected })
    _reg.bus.emit('launch:update')
    // Proxy found — stop polling to save CPU
    if (_state.selected) this._maybeStopPolling()
  } catch {
    // ignore polling errors
  }
}

// ─── Module descriptor ─────────────────────────────────────────────────────────

export const proxyModule = {
  name: 'proxy',

  init(reg) {
    _reg = reg
    _firstPoll = true
    this._userRequested = false

    // Bind DOM — detect only when user clicks refresh (P1: fast cold start)
    const refreshBtn = document.getElementById('btn-refresh')
    if (refreshBtn) {
      refreshBtn.onclick = () => {
        this._userRequested = true
        this.refresh()
      }
    }
    const btnOn = document.getElementById('btn-aero-connect')
    const btnOff = document.getElementById('btn-aero-disconnect')
    const st = document.getElementById('aero-status')
    if (btnOn) {
      btnOn.onclick = async () => {
        btnOn.disabled = true
        if (st) {
          st.className = 'aero-status'
          st.textContent = '正在连接 AERO…'
        }
        try {
          const r = await aeroApi.start()
          if (!r || !r.success) throw new Error((r && r.error) || '连接失败')
          if (st) {
            st.className = 'aero-status ok'
            st.textContent = 'AERO 已连接 · 再启动 AI 工具'
          }
          this._userRequested = true
          await this.refresh()
        } catch (e) {
          if (st) {
            st.className = 'aero-status miss'
            st.textContent = e.message || String(e)
          }
        } finally {
          btnOn.disabled = false
        }
      }
    }
    if (btnOff) {
      btnOff.onclick = async () => {
        btnOff.disabled = true
        try {
          await aeroApi.stop()
          if (st) {
            st.className = 'aero-status miss'
            st.textContent = '已断开 AERO'
          }
        } catch (e) {
          if (st) st.textContent = e.message || String(e)
        } finally {
          btnOff.disabled = false
        }
      }
    }

    const list = document.getElementById('proxy-list')
    if (list) {
      list.textContent = ''
      const empty = document.createElement('div')
      empty.className = 'proxy-empty'
      empty.textContent = _reg.i18n.t('clickRefreshProxy') || '点击右上角刷新检测本地代理（含 AERO 55555）'
      list.appendChild(empty)
    }
  },

  _maybeStopPolling() {
    if (_state.selected && _state.proxies.length > 0) {
      clearInterval(_pollingTimer)
      _pollingTimer = null
    }
  },

  _resumePolling() {
    if (!_pollingTimer) {
      _pollingTimer = setInterval(() => poll(), POLL_INTERVAL)
    }
  },

  async refresh() {
    // registry.refreshAll() on boot must not block UI with full port scan
    if (!this._userRequested) return

    _firstPoll = false
    if (_pollingTimer) {
      clearInterval(_pollingTimer)
      _pollingTimer = null
    }
    _reg.bus.emit('status:set', { type: 'busy', text: _reg.i18n.t('busy') })
    const refreshBtn = document.getElementById('btn-refresh')
    if (refreshBtn) refreshBtn.disabled = true

    const t0 = performance.now()
    const res = await proxyApi.detect()
    const ms = Math.round(performance.now() - t0)
    _reg.bus.emit('log:append', `[proxy] detect ${ms}ms · ${(res.proxies || []).length} found`)

    const list = document.getElementById('proxy-list')
    if (list) list.textContent = ''
    _state.systemProxy = res.systemProxy || null

    if (!res.success || !res.proxies || res.proxies.length === 0) {
      _state.proxies = []
      _state.selected = null
      renderEmpty()
      updateAeroBar([])
      _reg.bus.emit('status:set', { type: 'error', text: _reg.i18n.t('noProxyShort') })
      _reg.bus.emit('launch:update')
      _reg.bus.emit('proxy:changed', { proxies: [], selected: null })
      if (refreshBtn) refreshBtn.disabled = false
      return
    }

    // Prefer AERO mixed 55555 (or legacy 1080)
    const aero = res.proxies.find(p =>
      Number(p.port) === 55555 ||
      Number(p.port) === 1080 ||
      String(p.name || '').toLowerCase().includes('aero') ||
      (String(p.host) === '127.0.0.1' && (Number(p.port) === 55555 || Number(p.port) === 1080))
    )
    _state.proxies = res.proxies
    _state.selected = aero || res.proxies[0]
    renderList(res.proxies)
    updateAeroBar(res.proxies)

    _reg.bus.emit('status:set', { type: 'ready', text: `${res.proxies.length} ${_reg.i18n.t('proxiesAvailable')}` })
    if (refreshBtn) refreshBtn.disabled = false
    _reg.bus.emit('launch:update')
    _reg.bus.emit('proxy:changed', { proxies: res.proxies, selected: _state.selected })
  },

  destroy() {
    if (_pollingTimer) {
      clearInterval(_pollingTimer)
      _pollingTimer = null
    }
  },

  // Exposed for framework launch orchestration (not for other modules)
  getState() { return _state }
}
