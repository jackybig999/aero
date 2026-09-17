import { logApi } from '../../api/bridge.js'

let _reg = null
let _timer = null
let _lastLines = []

function append(text) {
  const out = document.getElementById('log-output')
  if (!out) return
  out.textContent += (out.textContent ? '\n' : '') + text
  out.scrollTop = out.scrollHeight
}

async function pollBackend() {
  const res = await logApi.get()
  if (!res.success || !res.logs) return
  const out = document.getElementById('log-output')
  if (!out) return

  const backendLines = res.logs.split('\n').filter(l => l.trim())
  for (const line of backendLines) {
    if (!_lastLines.includes(line)) {
      out.textContent += (out.textContent ? '\n' : '') + line
      _lastLines.push(line)
    }
  }
  if (_lastLines.length > 500) _lastLines = _lastLines.slice(-200)
  out.scrollTop = out.scrollHeight
}

async function clearLogs() {
  const out = document.getElementById('log-output')
  if (out) out.textContent = ''
  _lastLines = []
  try { await logApi.clear() } catch {}
}

// ─── Module descriptor ─────────────────────────────────────────────────────────

export const logModule = {
  name: 'log',

  init(reg) {
    _reg = reg

    // Bind DOM buttons
    const copyBtn = document.getElementById('btn-copy-log')
    if (copyBtn) {
      copyBtn.onclick = () => {
        const out = document.getElementById('log-output')
        if (!out) return
        navigator.clipboard.writeText(out.textContent).then(() => {
          append(`[${new Date().toLocaleTimeString()}] ${reg.i18n.t('logCopied')}`)
        }).catch(err => {
          append(`[${new Date().toLocaleTimeString()}] ${reg.i18n.t('copyFailed')}: ${err.message}`)
        })
      }
    }

    const clearBtn = document.getElementById('btn-clear')
    if (clearBtn) clearBtn.onclick = () => clearLogs()

    // Listen for in-memory log events (instant display)
    reg.bus.on('log:append', (text) => append(text))

    // Poll backend log files every 5s (real-time logs via bus.emit)
    _timer = setInterval(() => pollBackend(), 5000)
  },

  destroy() {
    if (_timer) {
      clearInterval(_timer)
      _timer = null
    }
  }
}
