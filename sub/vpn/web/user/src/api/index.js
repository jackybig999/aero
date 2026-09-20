import axios from 'axios'

export const TOKEN_KEY = 'vpn_user_token'
export const USER_KEY = 'vpn_user_user'

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
      window.location.href = '/login'
    }
    return Promise.reject(err)
  },
)

export const userApi = {
  login: (u, p, portal = 'user') => api.post('/auth/login/', { username: u, password: p, portal }),
  register: (u, p, e) => api.post('/users/', { username: u, password: p, email: e }),
  get: (i) => api.get(`/users/${i}/`),
  list: (q) => api.get('/users/', { params: q }),
  update: (i, d) => api.patch(`/users/${i}/`),
  remove: (i) => api.delete(`/users/${i}/`),
}
export const nodeApi = {
  list: () => api.get('/nodes/'),
  available: () => api.get('/nodes/available/'),
}
export const planApi = { list: () => api.get('/plans/') }
export const subApi = {
  list: (q) => api.get('/subscriptions/', { params: q }),
  create: (d) => api.post('/subscriptions/', d),
  remove: (i) => api.delete(`/subscriptions/${i}/`),
  config: (u) => api.get('/subscriptions/config/', { params: { uuid: u } }),
  userSub: () => api.get('/user/subscription'),
}
export const payInApi = {
  order: (d) => api.post('/payments/in/orders/', d),
  channels: () => api.get('/payments/in/channels/'),
}
export const ledgerApi = {
  summary: (d) => api.get('/ledger/summary/', { params: { date: d } }),
  list: () => api.get('/ledger/entries/unsettled/?direction=IN'),
}
export default api
