import { systemApi, globalApi } from '../../api/bridge.js'

let _reg = null

// ─── Internal state ────────────────────────────────────────────────────────────
const _state = {
  browsers: {},
  customBrowser: null,

  getBrowser(key) { return key === 'custom' ? this.customBrowser : this.browsers[key] },

  getAll() {
    const list = Object.values(this.browsers)
    if (this.customBrowser) list.push(this.customBrowser)
    return list
  }
}

// ─── Render ────────────────────────────────────────────────────────────────────

function renderCard(browser, grid) {
  const t = _reg.i18n.t
  const icons = { chrome: '🌐', edge: '🔷', firefox: '🦊', brave: '🦁', opera: '🔴' }
  const isCustom = browser.key === 'custom'

  const card = document.createElement('div')
  card.className = 'browser-card'
  card.dataset.key = browser.key
  card.dataset.command = browser.command

  if (isCustom) {
    const clearBtn = document.createElement('button')
    clearBtn.className = 'btn-clear-browser'
    clearBtn.style.cssText = 'position:absolute;top:2px;right:4px;font-size:9px;color:var(--error);background:transparent;border:none;cursor:pointer;padding:1px 3px;border-radius:3px;z-index:2;'
    clearBtn.textContent = t('clear')
    clearBtn.onclick = (e) => { e.stopPropagation(); clearCustom() }
    card.appendChild(clearBtn)
  }

  const iconEl = document.createElement('div')
  iconEl.className = 'browser-icon'
  iconEl.textContent = isCustom ? '🌐' : (icons[browser.key] || '🌐')

  const nameEl = document.createElement('div')
  nameEl.className = 'browser-name'
  nameEl.textContent = browser.name

  card.appendChild(iconEl)
  card.appendChild(nameEl)

  card.onclick = (e) => {
    if (e.target.closest('.btn-clear-browser')) return
    document.querySelectorAll('.app-card, .browser-card').forEach(el => el.classList.remove('selected'))
    card.classList.add('selected')
    _reg.bus.emit('app:select', { key: browser.key, type: 'browser', command: browser.command })
  }

  grid.appendChild(card)
}

function renderAddCard(grid) {
  const t = _reg.i18n.t
  const card = document.createElement('div')
  card.className = 'browser-card'
  const icon = document.createElement('div')
  icon.className = 'browser-icon'
  icon.textContent = '➕'
  const name = document.createElement('div')
  name.className = 'browser-name'
  name.textContent = t('custom')
  card.appendChild(icon)
  card.appendChild(name)
  card.onclick = () => addCustom()
  grid.appendChild(card)
}

// ─── Custom browser actions ────────────────────────────────────────────────────

async function addCustom() {
  const t = _reg.i18n.t
  const res = await globalApi.selectBrowser(t('selectBrowserExe'))
  if (res.success && res.path) {
    const name = res.path.split(/[\\/]/).pop().replace(/\.exe$/i, '')
    _state.customBrowser = { key: 'custom', name, command: res.path }
    _reg.storage.set('custom_browser', { path: res.path })
    await refresh()
    _reg.bus.emit('log:append', `[${new Date().toLocaleTimeString()}] ${t('addCustomBrowser')}: ${res.path}`)
  }
}

function clearCustom() {
  _state.customBrowser = null
  _reg.storage.remove('custom_browser')
  _reg.bus.emit('app:deselect', { key: 'custom' })
  refresh()
}

// ─── Refresh ───────────────────────────────────────────────────────────────────

async function refresh() {
  const grid = document.getElementById('browser-grid')
  if (!grid) return

  _state.browsers = {}
  const res = await systemApi.scanBrowsers()
  if (res.success) {
    for (const b of res.browsers) _state.browsers[b.key] = b
  }

  // Restore custom browser from storage
  const saved = _reg.storage.get('custom_browser', null)
  if (saved && saved.path) {
    const name = saved.path.split(/[\\/]/).pop().replace(/\.exe$/i, '')
    _state.customBrowser = { key: 'custom', name, command: saved.path }
  }

  grid.textContent = ''
  _state.getAll().forEach(b => renderCard(b, grid))
  renderAddCard(grid)

  _reg.bus.emit('launch:update')
}

// ─── Module descriptor ─────────────────────────────────────────────────────────

export const browserModule = {
  name: 'browser',

  init(reg) {
    _reg = reg
  },

  refresh,
  destroy() {},

  getState() { return _state }
}
