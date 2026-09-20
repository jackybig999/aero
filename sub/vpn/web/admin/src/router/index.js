import { createRouter, createWebHistory } from 'vue-router'

const routes = [
  { path: '/login', component: () => import('../views/Login.vue') },
  { path: '/', component: () => import('../views/Dashboard.vue'), meta: { auth: true } },
  { path: '/:pathMatch(.*)*', redirect: '/' },
]

// base /admin/ → real URLs: /admin/login, /admin/
const router = createRouter({
  history: createWebHistory('/admin/'),
  routes,
})

router.beforeEach((to, from, next) => {
  if (to.path === '/login') return next()
  if (!localStorage.getItem('vpn_admin_token')) return next('/login')
  const user = JSON.parse(localStorage.getItem('vpn_admin_user') || '{}')
  if (!user.is_staff) return next('/login')
  next()
})

export default router
