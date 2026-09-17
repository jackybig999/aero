import { defineConfig, loadEnv } from 'vite'
import vue from '@vitejs/plugin-vue'

// Production mid: served by vpsserver under /aero-ui/
// Production standalone: served by aero-panel under /
// Dev: vite proxy to mid or panel
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const apiTarget = env.VITE_API_TARGET || process.env.VITE_API_TARGET || 'http://127.0.0.1:8188'
  // Relative base: works under /aero-ui/ (mid) and / (standalone panel)
  const base = env.VITE_BASE || process.env.VITE_BASE || './'
  const uiPort = Number(env.VITE_PORT || process.env.VITE_PORT || 5176)

  return {
    plugins: [vue()],
    base,
    server: {
      host: '0.0.0.0',
      port: uiPort,
      strictPort: false,
      proxy: {
        '/api': { target: apiTarget, changeOrigin: true },
        '/health': { target: apiTarget, changeOrigin: true },
        '/admin': { target: apiTarget, changeOrigin: true },
      },
    },
    build: {
      outDir: 'dist',
      emptyOutDir: true,
    },
  }
})
