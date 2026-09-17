<template>
  <div class="bg">
    <div class="theme-bar">
      <el-segmented v-model="themeMode" :options="themeOptions" size="small" @change="onThemeChange" />
    </div>
    <el-card class="card" shadow="hover">
      <template #header><h2>用户登录</h2></template>
      <el-form @keyup.enter="login">
        <el-form-item><el-input v-model="u" placeholder="用户名" clearable /></el-form-item>
        <el-form-item><el-input v-model="p" type="password" placeholder="密码" show-password clearable /></el-form-item>
        <el-form-item>
          <el-button type="primary" style="width: 100%" :loading="ing" @click="login">登录</el-button>
        </el-form-item>
      </el-form>
      <p class="tip">
        没有账号？<router-link to="/register">立即注册</router-link>
        · 管理员请走 <a href="/admin/">/admin</a>
      </p>
    </el-card>
  </div>
</template>
<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { userApi } from '../api'
import { getStoredMode, applyTheme, watchSystemTheme } from '../theme'

const router = useRouter()
const u = ref(''), p = ref(''), ing = ref(false)
const themeMode = ref(getStoredMode())
const themeOptions = [
  { label: '浅色', value: 'light' },
  { label: '深色', value: 'dark' },
  { label: '系统', value: 'system' },
]
onMounted(() => { applyTheme(themeMode.value); watchSystemTheme() })
function onThemeChange(v) { applyTheme(v) }
async function login() {
  if (!u.value || !p.value) return ElMessage.warning('请输入用户名和密码')
  ing.value = true
  try {
    const r = await userApi.login(u.value, p.value)
    if (r.data?.data?.is_staff) {
      // 管理员账号请走后台
      localStorage.setItem('vpn_admin_token', r.data.data.token)
      localStorage.setItem('vpn_admin_user', JSON.stringify(r.data.data))
      window.location.href = '/admin/'
      return
    }
    localStorage.setItem('vpn_user_token', r.data.data.token)
    localStorage.setItem('vpn_user_user', JSON.stringify(r.data.data))
    router.push('/')
  } catch { ElMessage.error('登录失败') }
  finally { ing.value = false }
}
</script>
<style scoped>
.bg { min-height: 100vh; display: flex; align-items: center; justify-content: center; background: var(--app-bg); position: relative }
.theme-bar { position: absolute; top: 16px; right: 16px }
.card { width: 380px }
.tip { color: var(--app-muted); font-size: 13px; text-align: center; margin: 0 }
h2 { margin: 0; font-size: 18px }
</style>
