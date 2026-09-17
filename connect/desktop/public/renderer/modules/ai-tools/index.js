import { configApi, systemApi, globalApi } from '../../api/bridge.js'

let _reg = null

// ─── Internal state ────────────────────────────────────────────────────────────
const _state = {
  appsConfig: {},
  desktopApps: {},
  customTool: null,
  versions: {},

  getApp(key) { return this.appsConfig[key] },
  getDesktopApp(key) { return this.desktopApps[key] }
}

// ─── Render ────────────────────────────────────────────────────────────────────

function renderCliCard(key, displayName, config, grid) {
  const t = _reg.i18n.t
  const cwdStore = _reg.get('cwd')
  const cwdText = cwdStore.get(key) || config.cwd || t('selectCwd')
  const icons = { claude: '🤖', codex: '⚡' }

  const card = document.createElement('div')
  card.className = 'app-card'
  card.dataset.key = key

  const icon = document.createElement('div')
  icon.className = 'app-icon'
  icon.textContent = icons[key] || '▶'

  const name = document.createElement('div')
  name.className = 'app-name'
  name.textContent = displayName

  // Version text (async: may update later)
  const ver = _state.versions[key]
  const verEl = document.createElement('div')
  verEl.className = 'app-version'
  verEl.dataset.appKey = key
  // .app-version styles already in style.css
  verEl.textContent = ver ? `${_reg.i18n.t('versionLabel')}：${ver}` : ''

  const cwdRow = document.createElement('div')
  cwdRow.className = 'app-cwd'
  // styles moved to .app-cwd in style.css
  cwdRow.title = cwdText

  const cwdSpan = document.createElement('span')
  cwdSpan.className = 'cwd-text'
  cwdSpan.textContent = `${t('setCwd')}：${cwdText}`

  const editSpan = document.createElement('span')
  editSpan.className = 'cwd-edit'
  // styles moved to .cwd-edit in style.css
  editSpan.title = t('setCwdTitle')
  editSpan.textContent = '✎'
  editSpan.onclick = async (e) => {
    e.stopPropagation()
    const res = await globalApi.selectDirectory()
    if (res.success && res.path) {
      cwdStore.set(key, res.path)
      cwdSpan.textContent = `${t('setCwd')}：${res.path}`
      cwdRow.title = res.path
    }
  }

  cwdRow.appendChild(cwdSpan)
  cwdRow.appendChild(editSpan)
  card.appendChild(icon)
  card.appendChild(name)
  card.appendChild(verEl)
  card.appendChild(cwdRow)

  card.onclick = () => {
    document.querySelectorAll('.app-card, .browser-card').forEach(el => el.classList.remove('selected'))
    card.classList.add('selected')
    _reg.bus.emit('app:select', { key, type: 'cli', cwd: cwdStore.get(key) || config.cwd })
  }

  grid.appendChild(card)
}

function renderDesktopCard(key, displayName, iconText, grid) {
  const t = _reg.i18n.t
  const installed = !!_state.getDesktopApp(key)
  const command = _state.getDesktopApp(key)

  const card = document.createElement('div')
  card.className = 'app-card' + (installed ? '' : ' disabled')
  card.dataset.key = key
  if (command) card.dataset.command = command

  const icon = document.createElement('div')
  icon.className = 'app-icon'
  icon.textContent = iconText

  const name = document.createElement('div')
  name.className = 'app-name'
  name.textContent = displayName

  card.appendChild(icon)
  card.appendChild(name)

  // Desktop app version (async: may update later)
  const dver = _state.versions[key]
  const dverEl = document.createElement('div')
  dverEl.className = 'app-version'
  dverEl.dataset.appKey = key
  // .app-version styles already in style.css
  dverEl.textContent = dver ? `${t('versionLabel')}：${dver}` : ''

  card.appendChild(dverEl)

  if (!installed) {
    const status = document.createElement('div')
    status.className = 'app-status'
    status.textContent = t('notInstalled')
    card.appendChild(status)
  }

  card.onclick = () => {
    if (!installed) return
    document.querySelectorAll('.app-card, .browser-card').forEach(el => el.classList.remove('selected'))
    card.classList.add('selected')
    _reg.bus.emit('app:select', { key, type: 'desktop', command })
  }

  grid.appendChild(card)
}

function renderCustomToolCard(grid) {
  const t = _reg.i18n.t
  const tool = _state.customTool
  const card = document.createElement('div')
  card.className = 'app-card'
  card.dataset.key = 'custom-tool'

  if (tool) {
    const header = document.createElement('div')
    header.className = 'custom-tool-header'

    const icon = document.createElement('div')
    icon.className = 'app-icon'
    icon.textContent = '🛠'

    const clearBtn = document.createElement('button')
    clearBtn.className = 'btn-clear-tool'
    clearBtn.title = t('clear')
    // styles moved to .btn-clear-tool in style.css
    clearBtn.textContent = t('clear')
    clearBtn.onclick = (e) => { e.stopPropagation(); clearCustomTool() }

    header.appendChild(icon)
    header.appendChild(clearBtn)

    const name = document.createElement('div')
    name.className = 'app-name'
    name.textContent = tool.name

    const meta = document.createElement('div')
    meta.className = 'app-meta custom-tool-meta'
    meta.title = t('setCwdTitle')

    const cwdSpan = document.createElement('span')
    cwdSpan.className = 'cwd-text'
    cwdSpan.textContent = `${t('setCwd')}：${tool.cwd || t('selectCwd')}`

    const editSpan = document.createElement('span')
    editSpan.className = 'cwd-edit'
    editSpan.title = t('setCwdTitle')
    editSpan.textContent = '✎'
    editSpan.onclick = (e) => { e.stopPropagation(); selectCustomToolCwd() }

    meta.appendChild(cwdSpan)
    meta.appendChild(editSpan)
    card.appendChild(header)
    card.appendChild(name)
    card.appendChild(meta)
  } else {
    const icon = document.createElement('div')
    icon.className = 'app-icon'
    icon.textContent = '➕'

    const name = document.createElement('div')
    name.className = 'app-name'
    name.textContent = t('custom')

    const meta = document.createElement('div')
    meta.className = 'app-meta custom-tool-meta'

    const cwdSpan = document.createElement('span')
    cwdSpan.className = 'cwd-text'
    cwdSpan.textContent = `${t('setCwd')}：${t('selectCwd')}`

    const editSpan = document.createElement('span')
    editSpan.className = 'cwd-edit'
    editSpan.title = t('setCwdTitle')
    editSpan.textContent = '✎'
    editSpan.onclick = (e) => { e.stopPropagation(); selectCustomToolCwd() }

    meta.appendChild(cwdSpan)
    meta.appendChild(editSpan)
    card.appendChild(icon)
    card.appendChild(name)
    card.appendChild(meta)
  }

  card.addEventListener('click', (e) => {
    if (e.target.closest('.btn-clear-tool') || e.target.closest('.cwd-edit')) return
    if (!_state.customTool) {
      _reg.bus.emit('log:append', `[${new Date().toLocaleTimeString()}] ${t('mustSelectProgram')}`)
      selectCustomToolExe()
      return
    }
    document.querySelectorAll('.app-card, .browser-card').forEach(el => el.classList.remove('selected'))
    card.classList.add('selected')
    _reg.bus.emit('app:select', { key: 'custom-tool', type: 'custom', command: _state.customTool.command, cwd: _state.customTool.cwd })
  })

  grid.appendChild(card)
}

// ─── Custom tool actions ───────────────────────────────────────────────────────

async function selectCustomToolExe() {
  const t = _reg.i18n.t
  const res = await globalApi.selectBrowser(t('selectToolExe'))
  if (!res.success || !res.path) return
  const name = res.path.split(/[\\/]/).pop().replace(/\.exe$/i, '')
  _state.customTool = { command: res.path, name, cwd: _state.customTool?.cwd || '' }
  _reg.storage.set('custom_tool', _state.customTool)
  await refresh()
  _reg.bus.emit('log:append', `[${new Date().toLocaleTimeString()}] ${t('customToolAdded')}: ${name}`)
}

async function selectCustomToolCwd() {
  const t = _reg.i18n.t
  if (!_state.customTool) {
    _reg.bus.emit('log:append', `[${new Date().toLocaleTimeString()}] ${t('mustSelectProgram')}`)
    return
  }
  const res = await globalApi.selectDirectory('')
  if (res.success && res.path) {
    _state.customTool.cwd = res.path
    _reg.storage.set('custom_tool', _state.customTool)
    await refresh()
  }
}

function clearCustomTool() {
  _state.customTool = null
  _reg.storage.remove('custom_tool')
  _reg.bus.emit('app:deselect', { key: 'custom-tool' })
  refresh()
}

// ─── Async helpers ─────────────────────────────────────────────────────────────

function updateVersionTexts() {
  document.querySelectorAll('.app-version').forEach(el => {
    const key = el.dataset.appKey
    if (key && _state.versions[key]) {
      el.textContent = `${_reg.i18n.t('versionLabel')}：${_state.versions[key]}`
    }
  })
}

function refreshDesktopCards() {
  const grid = document.getElementById('cli-grid')
  if (!grid) return
  const cards = grid.querySelectorAll('.app-card')
  cards.forEach(card => {
    const key = card.dataset.key
    if (!key || !key.endsWith('-app')) return
    const command = _state.getDesktopApp(key)
    if (command) {
      card.classList.remove('disabled')
      card.dataset.command = command
      // Update status text
      const status = card.querySelector('.app-status')
      if (status) status.remove()
    }
  })
}

// ─── Refresh ───────────────────────────────────────────────────────────────────

async function refresh() {
  const grid = document.getElementById('cli-grid')
  if (!grid) return

  const t = _reg.i18n.t
  const res = await configApi.loadApps()
  if (!res.success) {
    _reg.bus.emit('log:append', t('launchFailed') + ': ' + res.error)
    return
  }
  _state.appsConfig = res.config

  // Kick off slow fetches in parallel, don't block render
  const scanPromise = systemApi.scanDesktop().then(r => {
    if (r.success) _state.desktopApps = r.apps
  }).catch(() => {})

  const verPromise = (!_state._versionsLoaded)
    ? systemApi.getVersions().then(r => {
        if (r.success) { _state.versions = r.versions; _state._versionsLoaded = true }
        updateVersionTexts()
      }).catch(() => {})
    : Promise.resolve()

  // Render UI immediately
  grid.textContent = ''

  const aiTools = [
    { key: 'claude', name: 'Claude CLI', icon: '🤖' },
    { key: 'codex', name: 'CodeX CLI', icon: '⚡' },
    { key: 'claude-app', name: 'Claude App', icon: '🤖' },
    { key: 'codex-app', name: 'CodeX App', icon: '⚡' }
  ]

  for (const tool of aiTools) {
    if (tool.key.endsWith('-app')) {
      renderDesktopCard(tool.key, tool.name, tool.icon, grid)
    } else {
      const config = _state.getApp(tool.key)
      if (config && config.type !== 'browser') {
        renderCliCard(tool.key, tool.name, config, grid)
      }
    }
  }

  renderCustomToolCard(grid)
  _reg.bus.emit('launch:update')

  // Wait for slow fetches, then update desktop cards if needed
  await Promise.all([scanPromise, verPromise])
  if (Object.keys(_state.desktopApps).length > 0) {
    // Re-render desktop cards now that we know what's installed
    refreshDesktopCards()
  }
}

// ─── Module descriptor ─────────────────────────────────────────────────────────

export const aiToolsModule = {
  name: 'ai-tools',

  init(reg) {
    _reg = reg
    _state.customTool = reg.storage.get('custom_tool', null)
  },

  refresh,
  destroy() {},

  // Framework-accessible state
  getState() { return _state }
}
