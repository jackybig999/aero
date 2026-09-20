import { registry } from './core/registry.js'
import { storage } from './core/storage.js'
import { bus } from './api/event-bus.js'
import * as i18n from './modules/i18n/index.js'
import { cwdService } from './services/cwd.js'
import { proxyModule } from './modules/proxy/index.js'
import { aiToolsModule } from './modules/ai-tools/index.js'
import { browserModule } from './modules/browser/index.js'
import { logModule } from './modules/log/index.js'
import { historyModule } from './modules/history/index.js'
import { thirdPartyApiModule } from './modules/third-party-api/index.js'
import { appApi, globalApi } from './api/bridge.js'

const $ = (sel) => document.querySelector(sel)

// ─── Shared services ───────────────────────────────────────────────────────────
registry.provide('i18n', i18n)
registry.provide('storage', storage)
registry.provide('cwd', cwdService)

// ─── Module registration ──────────────────────────────────────────────────────
// To add a new module: create modules/xxx/index.js, then add one line here.
registry.register(proxyModule)
registry.register(aiToolsModule)
registry.register(browserModule)
registry.register(logModule)
registry.register(historyModule)
registry.register(thirdPartyApiModule)

// ─── App selection (framework-owned — fed by module events) ────────────────────
let selectedApp = null
let selectedType = null
let selectedCommand = null
let selectedCwd = null

bus.on('app:select', ({ key, type: appType, command, cwd }) => {
  selectedApp = key
  selectedType = appType
  selectedCommand = command || null
  selectedCwd = cwd || null
  updateLaunchBtn()
})

bus.on('app:deselect', ({ key }) => {
  if (selectedApp === key) { selectedApp = null; selectedType = null; selectedCommand = null; selectedCwd = null }
  updateLaunchBtn()
})

// ─── Status bar ────────────────────────────────────────────────────────────────
bus.on('status:set', ({ type, text }) => {
  const dot = $('#status-dot')
  const label = $('#status-text')
  if (dot) dot.className = 'status-dot ' + type
  if (label) label.textContent = text
})

// ─── Launch control ────────────────────────────────────────────────────────────
function updateLaunchBtn() {
  const btn = $('#btn-launch')
  if (!btn) return

  const toolsState = aiToolsModule.getState()
  const browserState = browserModule.getState()
  const proxyState = proxyModule.getState()

  const app = toolsState.getApp(selectedApp)
  const browser = browserState.getBrowser(selectedApp)
  const desktopPath = toolsState.getDesktopApp(selectedApp)
  const customReady = selectedApp === 'custom-tool' && toolsState.customTool

  if (!app && !browser && !desktopPath && !customReady) {
    btn.disabled = true
    btn.textContent = i18n.t('launch')
    return
  }

  btn.disabled = false
  btn.textContent = `${i18n.t('launchApp')} ${selectedApp}`
}

bus.on('launch:update', updateLaunchBtn)

async function launchSelected() {
  if (!selectedApp) return

  const t = i18n.t
  const toolsState = aiToolsModule.getState()
  const browserState = browserModule.getState()
  const proxyState = proxyModule.getState()

  const app = toolsState.getApp(selectedApp)
  const browser = browserState.getBrowser(selectedApp)
  const desktopPath = toolsState.getDesktopApp(selectedApp)
  let cwd = cwdService.get(selectedApp) || (app && app.cwd)

  if (app && app.type === 'cli' && !cwd) {
    try { cwd = globalApi.getCwd() } catch { cwd = './' }
    cwdService.set(selectedApp, cwd)
    bus.emit('log:append', `[${new Date().toLocaleTimeString()}] ${t('noCwd')}，使用默认目录: ${cwd}`)
    const cwdEl = document.querySelector(`.app-card[data-key="${selectedApp}"] .app-cwd`)
    if (cwdEl) cwdEl.textContent = t('setCwd') + '：' + cwd
  }

  const btn = $('#btn-launch')
  btn.disabled = true
  btn.textContent = t('launching')
  bus.emit('status:set', { type: 'busy', text: t('busy') })
  bus.emit('log:append', `[${new Date().toLocaleTimeString()}] ${t('launchApp')} ${selectedApp}...`)

  const payload = {
    appKey: selectedApp,
    proxy: proxyState.selected || null,
    profileName: `${selectedApp}-gui`,
    cwd
  }

  if (browser) payload.command = browser.command
  if (desktopPath) { payload.command = desktopPath; payload.type = 'desktop' }
  if (selectedApp === 'custom-tool' && toolsState.customTool) {
    payload.command = toolsState.customTool.command
    payload.cwd = toolsState.customTool.cwd
    payload.type = 'desktop'
  }

  const res = await appApi.launch(payload)

  if (res.success) {
    bus.emit('log:append', `[${new Date().toLocaleTimeString()}] ✓ ${selectedApp} ${t('launched')}`)
    bus.emit('status:set', { type: 'ready', text: `${selectedApp} ${t('proxyRunning')}` })
    globalApi.showTray(i18n.t('trayNotifyTitle'), i18n.t('trayNotifyBody'))
  } else if (res.error && res.error.includes('already running')) {
    bus.emit('log:append', `[${new Date().toLocaleTimeString()}] ⚠ ${selectedApp} ${t('alreadyRunning')}`)
    bus.emit('status:set', { type: 'error', text: `${selectedApp} ${t('alreadyRunning')}` })
  } else {
    bus.emit('log:append', `[${new Date().toLocaleTimeString()}] ✗ ${t('launchFailed')}: ${res.error}`)
    bus.emit('status:set', { type: 'error', text: t('launchError') })
  }

  btn.disabled = false
  updateLaunchBtn()
}

async function killAll() {
  const t = i18n.t
  bus.emit('status:set', { type: 'busy', text: t('busy') })
  await appApi.killAll()
  bus.emit('log:append', `[${new Date().toLocaleTimeString()}] ${t('allKilled')}`)
  bus.emit('status:set', { type: 'ready', text: t('ready') })
}

// ─── Language ──────────────────────────────────────────────────────────────────
function initLangSwitcher() {
  const dropdown = $('#lang-dropdown')
  const current = $('#lang-current')
  const options = $('#lang-options')
  if (!current) return

  current.textContent = i18n.t('langLabel')

  current.onclick = (e) => {
    e.stopPropagation()
    options.classList.toggle('show')
  }

  document.addEventListener('click', () => options.classList.remove('show'))

  options.querySelectorAll('.lang-option').forEach(opt => {
    opt.onclick = () => {
      const lang = opt.dataset.lang
      if (lang === i18n.getLang()) return
      options.classList.remove('show')
      globalApi.setMenuLang(lang)
    }
  })
}

async function onLanguageChanged(lang) {
  if (lang === i18n.getLang() && Object.keys(i18n.getDict()).length) return
  i18n.setLang(lang)
  await i18n.load(lang)
  applyStaticI18n()
  await updateTrialBadge()
  await registry.refreshAll()
  if (selectedApp) {
    const card = document.querySelector(`.app-card[data-key="${selectedApp}"], .browser-card[data-key="${selectedApp}"]`)
    if (card) card.classList.add('selected')
  }
}

// ─── Static labels from i18n ───────────────────────────────────────────────────
function applyStaticI18n() {
  const map = {
    'panel-proxy': 'proxyStatus',
    'panel-ai': 'aiTools',
    'panel-browser': 'browser',
    'panel-logs': 'logs',
    'btn-copy-log': 'copy',
    'btn-clear': 'clear',
    'btn-kill': 'killAll',
    'warn-text': 'warnProxy',
    'btn-launch': 'launch'
  }
  for (const [id, key] of Object.entries(map)) {
    const el = document.getElementById(id)
    if (el) el.textContent = i18n.t(key)
  }
  const tp = document.getElementById('btn-third-party')
  if (tp) tp.textContent = i18n.t('thirdPartyApi') || '第三方API'
  const hi = document.getElementById('btn-history')
  if (hi) hi.textContent = i18n.t('chatHistory') || i18n.t('history') || '对话历史'
  const langCurrent = $('#lang-current')
  if (langCurrent) langCurrent.textContent = i18n.t('langLabel')
  const refreshBtn = $('#btn-refresh')
  if (refreshBtn) refreshBtn.title = i18n.t('refresh')
}

// ─── Trial badge ──────────────────────────────────────────────────────────────
async function updateTrialBadge() {
  const badge = document.getElementById('trial-badge')
  if (!badge) return
  try {
    const info = await globalApi.getTrialInfo()
    if (!info) {
      badge.style.display = 'none'
      return
    }
    // licensed
    if (info.licensed) {
      badge.style.display = ''
      badge.className = 'trial-badge licensed'
      badge.textContent = i18n.t('licensed') || '已授权'
      return
    }
    // trial object { daysLeft } or nested
    const days =
      (info.trial && typeof info.trial === 'object' && info.trial.daysLeft != null)
        ? info.trial.daysLeft
        : (info.daysLeft != null ? info.daysLeft : null)
    if (days != null && days > 0) {
      badge.style.display = ''
      badge.className = 'trial-badge'
      badge.textContent = (i18n.t('trialDaysLeft') || '试用剩余 {d} 天').replace('{d}', String(days))
      return
    }
    badge.style.display = ''
    badge.className = 'trial-badge expired'
    badge.textContent = i18n.t('licenseRequired') || '需注册'
  } catch (e) {
    console.error('[trial-badge]', e)
    badge.style.display = ''
    badge.className = 'trial-badge'
    badge.textContent = 'Trial'
  }
}

// ─── Init ──────────────────────────────────────────────────────────────────────
async function init() {
  const t0 = performance.now()
  await i18n.load(i18n.getLang())
  applyStaticI18n()
  bus.emit('log:append', `[boot] i18n ${Math.round(performance.now() - t0)}ms lang=${i18n.getLang()}`)

  bus.emit('log:append', '[' + new Date().toLocaleTimeString() + '] AI Runtime Manager ' + i18n.t('launched'))
  bus.emit('log:append', i18n.t('clickRefreshProxy') || '请点击刷新检测本地代理（含 AERO 55555）')

  initLangSwitcher()
  globalApi.setMenuLang(i18n.getLang())
  globalApi.onChangeLang((lang) => onLanguageChanged(lang))

  await cwdService.load()
  await registry.initAll()
  await registry.refreshAll()
  bus.emit('log:append', `[boot] ui ready ${Math.round(performance.now() - t0)}ms`)

  await updateTrialBadge()
  $('#btn-launch').onclick = launchSelected
  $('#btn-kill').onclick = killAll

  if (selectedApp) {
    const card = document.querySelector(`.app-card[data-key="${selectedApp}"], .browser-card[data-key="${selectedApp}"]`)
    if (card) card.classList.add('selected')
  }
}

init().catch(err => {
  bus.emit('log:append', i18n.t('initError') + ': ' + err.message)
})
