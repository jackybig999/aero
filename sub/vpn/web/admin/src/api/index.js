import axios from 'axios'

export const TOKEN_KEY = 'vpn_admin_token'
export const USER_KEY = 'vpn_admin_user'

const api = axios.create({ baseURL: '/api/v1', timeout: 15000 })

api.interceptors.request.use((c) => {
  const t = localStorage.getItem(TOKEN_KEY)
  if (t) c.headers.Authorization = `Bearer ${t}`
  return c
})

api.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err.response?.status === 401 && !err.config?.url?.includes('/auth/login')) {
      localStorage.removeItem(TOKEN_KEY)
      localStorage.removeItem(USER_KEY)
      if (!location.pathname.includes('/login')) location.href = '/admin/login'
    }
    return Promise.reject(err)
  },
)

export const userApi = {
  login: (u, p, portal = 'admin') => api.post('/auth/login/', { username: u, password: p, portal }),
  list: (q) => api.get('/users/', { params: q }),
  create: (d) => api.post('/users/', d),
  update: (i, d) => api.patch(`/users/${i}/`, d),
  remove: (i) => api.delete(`/users/${i}/`),
}

export const nodeApi = {
  list: () => api.get('/nodes/'),
  available: () => api.get('/nodes/available/'),
  create: (d) => api.post('/nodes/', d),
  heartbeat: (i, v) => api.post(`/nodes/${i}/heartbeat/`, { agent_version: v }),
  remove: (i) => api.delete(`/nodes/${i}/`),
  cascadeDelete: (d) =>
    api.delete('/nodes/', { params: { vps_id: d.vps_id || undefined, ip: d.ip || undefined } }),
}

/** VPS 资产（同进程 /vps，需管理员） */
export const vpsApi = {
  list: () => api.get('/vps/'),
  create: (d) => api.post('/vps/', d),
  remove: (i) => api.delete(`/vps/${i}/`),
  updatePassword: (i, ssh_password) => api.patch(`/vps/${i}/`, { ssh_password }),
  probe: (i) => api.post(`/vps/${i}/probe/`, null, { timeout: 30000 }),
}

/** AERO 部署（同进程 /aero，需管理员） */
export const aeroApi = {
  install: (vps_id) => api.post('/aero/install/', { vps_id }, { timeout: 20000 }),
  uninstall: (vps_id) => api.post('/aero/uninstall/', { vps_id }, { timeout: 20000 }),
  listTasks: () => api.get('/aero/tasks/'),
  getTask: (i) => api.get(`/aero/tasks/${i}/`),
  deleteTask: (i) => api.delete(`/aero/tasks/${i}/`),
  clearFailed: () => api.post('/aero/tasks/clear-failed/'),
  vpsOptions: () => api.get('/aero/vps-options/'),
  broadcastSubs: (subs) => api.post('/aero/subs/broadcast/', subs),
  syncVpsSubs: (vps_id, subs) => api.post(`/aero/vps/${vps_id}/subs/sync/`, subs),
}

export const subApi = {
  list: (q) => api.get('/subscriptions/', { params: q }),
  create: (d) => api.post('/subscriptions/', d),
  remove: (i) => api.delete(`/subscriptions/${i}/`),
  config: (uuid) => api.get('/subscriptions/config/', { params: { uuid } }),
  nodeStats: () => api.get('/subscriptions/stats/by-node/'),
  detachNode: (node_id) => api.post('/subscriptions/detach-node/', { node_id }),
}

export const ledgerApi = {
  summary: (d) => api.get('/ledger/summary/', { params: { date: d } }),
  list: () => api.get('/ledger/entries/unsettled/', { params: { direction: 'IN' } }),
}

export const healthApi = {
  check: () => axios.get('/health', { timeout: 8000 }),
}

export default api
