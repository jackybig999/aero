const KEY = 'vpn_user_theme_mode'

export function getStoredMode() {
  return localStorage.getItem(KEY) || 'system'
}

export function resolveDark(mode) {
  if (mode === 'dark') return true
  if (mode === 'light') return false
  return window.matchMedia('(prefers-color-scheme: dark)').matches
}

export function applyTheme(mode) {
  const m = mode || getStoredMode()
  localStorage.setItem(KEY, m)
  const dark = resolveDark(m)
  document.documentElement.classList.toggle('dark', dark)
  document.documentElement.dataset.theme = m
  return { mode: m, dark }
}

export function watchSystemTheme(cb) {
  const mq = window.matchMedia('(prefers-color-scheme: dark)')
  const handler = () => {
    if (getStoredMode() === 'system') {
      applyTheme('system')
      cb && cb(getStoredMode())
    }
  }
  mq.addEventListener?.('change', handler)
  return () => mq.removeEventListener?.('change', handler)
}
