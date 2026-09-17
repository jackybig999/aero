import { createRouter, createWebHistory } from 'vue-router'

const routes = [
  { path: '/login', component: () => import('../views/Login.vue') },
  { path: '/register', component: () => import('../views/Register.vue') },
  { path: '/', component: () => import('../views/Home.vue'), meta: { auth: true } },
  { path: '/:pathMatch(.*)*', redirect: '/login' },
]

const router = createRouter({
  history: createWebHistory('/'),
  routes,
})

router.beforeEach((to, from, next) => {
  if (to.path === '/login' || to.path === '/register') return next()
  if (!localStorage.getItem('vpn_user_token')) return next('/login')
  const user = JSON.parse(localStorage.getItem('vpn_user_user') || '{}')
  if (user.is_staff) {
    window.location.href = '/admin/'
    return
  }
  next()
})

export default router
