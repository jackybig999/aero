<template>
  <div class="bg"><el-card class="card"><template #header><h2>用户注册</h2></template>
    <el-form @keyup.enter="register">
      <el-form-item><el-input v-model="u" placeholder="用户名（3-50字符）" /></el-form-item>
      <el-form-item><el-input v-model="e" placeholder="邮箱（选填）" /></el-form-item>
      <el-form-item><el-input v-model="p" type="password" placeholder="密码（至少8位）" show-password /></el-form-item>
      <el-form-item><el-input v-model="p2" type="password" placeholder="确认密码" show-password /></el-form-item>
      <el-form-item><el-button type="primary" style="width:100%" :loading="ing" @click="register">注册</el-button></el-form-item>
    </el-form>
    <p class="tip">已有账号？<router-link to="/login">去登录</router-link></p>
  </el-card></div>
</template>
<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { userApi } from '../api'
const router = useRouter()
const u = ref(''), e = ref(''), p = ref(''), p2 = ref(''), ing = ref(false)
async function register() {
  if (!u.value || p.value.length < 8) return ElMessage.warning('用户名和密码（8位以上）必填')
  if (p.value !== p2.value) return ElMessage.warning('两次密码不一致')
  ing.value = true
  try { await userApi.register(u.value, p.value, e.value); ElMessage.success('注册成功，请登录'); router.push('/login') }
  catch (err) { ElMessage.error(err.response?.data?.message || '注册失败') }
  finally { ing.value = false }
}
</script>
<style scoped>
.bg { min-height: 100vh; display: flex; align-items: center; justify-content: center; background: linear-gradient(135deg,#667eea,#764ba2) }
.card { width: 380px }
.tip { color: #999; font-size: 13px; text-align: center }
</style>
