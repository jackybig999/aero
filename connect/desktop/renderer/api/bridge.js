// API Bridge — wraps HTTP fetch calls to Go backend API server.
// All renderer modules import from here instead of accessing armAPI directly.
// This replaces the Electron IPC bridge with standard HTTP fetch.

const API_BASE = window.__ARM_API_BASE || ''

async function rpc(method, path, body) {
  const opts = { method, headers: {} }
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json'
    opts.body = JSON.stringify(body)
  }
  const res = await fetch(API_BASE + path, opts)
  return res.json()
}

export const proxyApi = {
  detect: () => rpc('GET', '/api/proxy/detect')
}

export const aeroApi = {
  status: () => rpc('GET', '/api/aero/status'),
  start: (opts) => rpc('POST', '/api/aero/start', opts),
  stop: () => rpc('POST', '/api/aero/stop')
}

export const configApi = {
  loadApps: () => rpc('GET', '/api/config/apps'),
  getCwd: () => rpc('GET', '/api/config/cwd'),
  saveCwd: (data) => rpc('POST', '/api/config/cwd', data)
}

export const systemApi = {
  scanBrowsers: () => rpc('GET', '/api/system/browsers'),
  scanDesktop: () => rpc('GET', '/api/system/desktop'),
  getVersions: () => rpc('GET', '/api/system/versions')
}

export const appApi = {
  launch: (params) => rpc('POST', '/api/app/launch', params),
  killAll: () => rpc('POST', '/api/app/kill-all')
}

export const logApi = {
  get: () => rpc('GET', '/api/log'),
  clear: () => rpc('POST', '/api/log/clear')
}

export const thirdPartyApi = {
  list: () => rpc('GET', '/api/provider/list'),
  save: (data) => rpc('POST', '/api/provider/save', data),
  del: (data) => rpc('POST', '/api/provider/delete', data),
  test: (data) => rpc('POST', '/api/provider/test', data),
  apply: (data) => rpc('POST', '/api/provider/apply', data),
  restore: (data) => rpc('POST', '/api/provider/restore', data),
  models: (data) => rpc('POST', '/api/provider/models', data)
}

// Global APIs that don't fit a single module
const _langCallbacks = []
export const globalApi = {
  selectDirectory: (defaultPath) => rpc('POST', '/api/system/select-directory', { defaultPath }),
  selectBrowser: (title) => rpc('POST', '/api/system/select-browser', { title }),
  setMenuLang: (lang) => rpc('POST', '/api/config/lang', { lang }),
  getI18n: (lang) => rpc('GET', '/api/config/i18n?lang=' + encodeURIComponent(lang || '')),
  getCwd: () => {
    // Return user home directory synchronously (no Electron needed)
    try { return localStorage.getItem('arm_home') || '' } catch { return '' }
  },
  onChangeLang: (cb) => _langCallbacks.push(cb),
  showTray: (title, body) => rpc('POST', '/api/system/tray-notify', { title, body }),
  getTrialInfo: () => rpc('GET', '/api/config/trial')
}

// Poll for language changes (replaces Electron IPC push)
setInterval(async () => {
  try {
    const r = await rpc('GET', '/api/config/lang')
    if (r && r.lang && window.__lastLang !== r.lang) {
      window.__lastLang = r.lang
      _langCallbacks.forEach(cb => { try { cb(r.lang) } catch {} })
    }
  } catch {}
}, 2000)
