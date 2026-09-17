<template>
  <div class="bg">
    <div class="theme-bar">
      <el-segmented v-model="themeMode" :options="themeOptions" size="small" @change="onThemeChange" />
    </div>
    <el-card class="card" shadow="hover">
      <template #header><h2>管理后台登录</h2></template>
      <el-form @keyup.enter="login">
        <el-form-item>
          <el-input v-model="u" placeholder="管理员用户名" clearable />
        </el-form-item>
        <el-form-item>
          <el-input v-model="p" type="password" placeholder="密码" show-password clearable />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" style="width: 100%" :loading="ing" @click="login">登录</el-button>
        </el-form-item>
      </el-form>
      <p class="tip">
        仅限管理员 · 用户订阅入口
        <a href="/login">/login</a>
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
const u = ref('admin')
const p = ref('')
const ing = ref(false)
const themeMode = ref(getStoredMode())
const themeOptions = [
  { label: '浅色', value: 'light' },
  { label: '深色', value: 'dark' },
  { label: '系统', value: 'system' },
]

onMounted(() => {
  applyTheme(themeMode.value)
  watchSystemTheme()
})

function onThemeChange(v) {
  applyTheme(v)
}

async function login() {
  if (!u.value || !p.value) return ElMessage.warning('请输入账号密码')
  ing.value = true
  try {
    const r = await userApi.login(u.value, p.value)
    if (!r.data?.data?.is_staff) {
      ElMessage.error('非管理员账号')
      return
    }
    localStorage.setItem('vpn_admin_token', r.data.data.token)
    localStorage.setItem('vpn_admin_user', JSON.stringify(r.data.data))
    router.push('/')
  } catch {
    ElMessage.error('登录失败')
  } finally {
    ing.value = false
  }
}
</script>

<style scoped>
.bg {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--app-bg);
  position: relative;
}
.theme-bar {
  position: absolute;
  top: 16px;
  right: 16px;
}
.card { width: 380px }
.tip { color: var(--app-muted); font-size: 12px; text-align: center; margin: 0 }
.tip a { color: #409eff }
h2 { margin: 0; font-size: 18px }
</style>
