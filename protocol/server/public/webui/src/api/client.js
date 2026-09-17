/**
 * Dual-mode AERO WebUI API client.
 * mid: vpsserver /api/v1/aero/*
 * standalone: aero-panel /api/v1/aero/*
 */
import axios from 'axios'

const TOKEN_KEY = 'vpn_admin_token'
const PANEL_KEY = 'aero_panel_admin_key'

function detectMode() {
  const q = new URLSearchParams(location.search)
  if (q.get('mode') === 'mid' || q.get('mode') === 'standalone') return q.get('mode')
  if (window.__AERO_WEBUI__?.mode) return window.__AERO_WEBUI__.mode
  if (location.pathname.startsWith('/aero-ui') && localStorage.getItem(TOKEN_KEY)) return 'mid'
  return 'standalone'
}

function createHttp(mode) {
  const http = axios.create({ baseURL: '/api/v1', timeout: 45000 })
  http.interceptors.request.use((cfg) => {
    if (mode === 'mid') {
      const t = localStorage.getItem(TOKEN_KEY)
      if (t) cfg.headers.Authorization = `Bearer ${t}`
    } else {
      const key = window.__AERO_WEBUI__?.adminKey || localStorage.getItem(PANEL_KEY) || ''
      if (key) cfg.headers['X-Aero-Admin-Key'] = key
    }
    return cfg
  })
  return http
}

function unwrap(res) {
  const body = res?.data
  if (body && typeof body === 'object' && 'code' in body) {
    if (body.code !== 0 && body.code !== undefined) {
      const err = new Error(body.message || `code ${body.code}`)
      err.response = res
      throw err
    }
    return body.data
  }
  return body
}

function createMidClient(http) {
  return {
    mode: 'mid',
    features: {
      multiVps: true,
      deploy: true,
      tasks: true,
      tokens: true,
      status: true,
      sub: true,
      diagnose: true,
      cert: true,
    },

    async listVPS() {
      const d = unwrap(await http.get('/aero/vps-options/'))
      return d?.results || []
    },
    async install(vpsId) {
      return unwrap(await http.post('/aero/install/', { vps_id: vpsId }, { timeout: 20000 }))
    },
    async uninstall(vpsId) {
      return unwrap(await http.post('/aero/uninstall/', { vps_id: vpsId }, { timeout: 20000 }))
    },
    async listTasks() {
      const d = unwrap(await http.get('/aero/tasks/'))
      return d?.results || []
    },
    async getTask(id) {
      return unwrap(await http.get(`/aero/tasks/${id}/`))
    },
    async deleteTask(id) {
      unwrap(await http.delete(`/aero/tasks/${id}/`))
    },
    async clearFailed() {
      return unwrap(await http.post('/aero/tasks/clear-failed/'))
    },
    async getEndpoint(vpsId) {
      return unwrap(await http.get(`/aero/vps/${vpsId}/endpoint/`))
    },
    async refreshEndpoint(vpsId) {
      return unwrap(await http.post(`/aero/vps/${vpsId}/endpoint/refresh/`))
    },
    async listTokens(vpsId) {
      const d = unwrap(await http.get(`/aero/vps/${vpsId}/tokens/`))
      return d?.results || []
    },
    async addToken(vpsId, { token = '', label = '', ttl_hours = 0 } = {}) {
      return unwrap(await http.post(`/aero/vps/${vpsId}/tokens/`, { token, label, ttl_hours }))
    },
    async delToken(vpsId, token) {
      unwrap(await http.delete(`/aero/vps/${vpsId}/tokens/`, { params: { token } }))
    },
    async status(vpsId) {
      return unwrap(await http.get(`/aero/vps/${vpsId}/status/`, { timeout: 50000 }))
    },
    async diagnose(vpsId) {
      return unwrap(await http.get(`/aero/vps/${vpsId}/diagnose/`, { timeout: 50000 }))
    },
    async renewCert(vpsId, force = false) {
      return unwrap(await http.post(`/aero/vps/${vpsId}/cert/renew/`, { force }, { timeout: 60000 }))
    },
    async restartEdge(vpsId) {
      return unwrap(await http.post(`/aero/vps/${vpsId}/restart/`, {}, { timeout: 45000 }))
    },
    async getPanelConfig() {
      return { mode: 'mid', connected: true }
    },
    async savePanelConfig() {
      throw new Error('mid mode: use VPS + install')
    },
  }
}

function createStandaloneClient(http) {
  return {
    mode: 'standalone',
    features: {
      multiVps: false,
      deploy: false,
      tasks: false,
      tokens: true,
      status: true,
      sub: true,
      diagnose: false,
      cert: false,
    },
    async listVPS() {
      return []
    },
    async install() {
      throw new Error('standalone: use mid or install.sh')
    },
    async uninstall() {
      throw new Error('standalone: use systemctl')
    },
    async listTasks() {
      return []
    },
    async getTask() {
      return null
    },
    async deleteTask() {},
    async clearFailed() {
      return { deleted: 0 }
    },
    async getEndpoint() {
      return unwrap(await http.get('/aero/endpoint/'))
    },
    async refreshEndpoint() {
      return unwrap(await http.post('/aero/endpoint/refresh/'))
    },
    async listTokens() {
      const d = unwrap(await http.get('/aero/tokens/'))
      return d?.results || d?.tokens || []
    },
    async addToken(_id, { token = '', label = '', ttl_hours = 0 } = {}) {
      return unwrap(await http.post('/aero/tokens/', { token, label, ttl_hours }))
    },
    async delToken(_id, token) {
      unwrap(await http.delete('/aero/tokens/', { params: { token } }))
    },
    async status() {
      return unwrap(await http.get('/aero/status/'))
    },
    async diagnose() {
      return unwrap(await http.get('/aero/status/'))
    },
    async renewCert() {
      throw new Error('standalone: renew cert on host (restart edge / LE)')
    },
    async restartEdge() {
      throw new Error('standalone: systemctl restart aero-edge')
    },
    async getPanelConfig() {
      try {
        return unwrap(await http.get('/aero/panel/config/'))
      } catch {
        return { mode: 'standalone' }
      }
    },
    async savePanelConfig(cfg) {
      return unwrap(await http.post('/aero/panel/config/', cfg))
    },
  }
}

export function createAeroClient(forcedMode) {
  const mode = forcedMode || detectMode()
  const http = createHttp(mode)
  if (mode === 'mid') return createMidClient(http)
  return createStandaloneClient(http)
}

export { TOKEN_KEY, PANEL_KEY, detectMode }
