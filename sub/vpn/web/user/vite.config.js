import { defineConfig, loadEnv } from 'vite'
import vue from '@vitejs/plugin-vue'

// Production: served by platform at /login /register /
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const port = env.VITE_API_PORT || env.PORT || process.env.PORT || '8188'
  const target = env.VITE_API_TARGET || process.env.VITE_API_TARGET || `http://127.0.0.1:${port}`
  const uiPort = Number(env.VITE_USER_PORT || process.env.VITE_USER_PORT || 5173)

  return {
    plugins: [vue()],
    base: '/',
    server: {
      host: '0.0.0.0',
      port: uiPort,
      strictPort: false,
      proxy: {
        '/api': { target, changeOrigin: true },
        '/health': { target, changeOrigin: true },
      },
    },
    build: {
      outDir: 'dist',
      emptyOutDir: true,
    },
  }
})
