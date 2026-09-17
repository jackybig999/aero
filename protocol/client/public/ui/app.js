const DEFAULT_LISTEN = '127.0.0.1:55555'
const LANG_KEY = 'aero-lang'
const MODE_KEY = 'aero-mode'
const SUB_KEY = 'aero-sub'
const $ = (id) => document.getElementById(id)

let lang = 'zh-CN'
let busy = false
let camStream = null
let camTimer = 0

function t(key) {
  const pack = I18N[lang] || I18N['zh-CN']
  return pack[key] || I18N['zh-CN'][key] || key
}

function applyI18n() {
  document.documentElement.lang = lang
  document.querySelectorAll('[data-i18n]').forEach((el) => {
    el.textContent = t(el.getAttribute('data-i18n'))
  })
  document.querySelectorAll('[data-i18n-placeholder]').forEach((el) => {
    el.placeholder = t(el.getAttribute('data-i18n-placeholder'))
  })
  const lb = $('btnLang')
  if (lb) lb.textContent = t('langName')
  paintModeCards()
}

function productMode(mode) {
  return mode === 'tun' ? 'tun' : 'sysproxy'
}

function modeLabel(mode) {
  return productMode(mode) === 'tun' ? 'TUN' : t('modeSys')
}

function selectedMode() {
  const el = document.querySelector('input[name="mode"]:checked')
  return productMode((el && el.value) || localStorage.getItem(MODE_KEY) || 'sysproxy')
}

function paintModeCards() {
  const cur = selectedMode()
  document.querySelectorAll('.mode').forEach((lab) => {
    lab.classList.toggle('selected', lab.getAttribute('data-mode') === cur)
  })
  const tip = $('modeTip')
  if (!tip) return
  tip.textContent = cur === 'tun' ? t('tipTun') : t('tipSys')
}

function setModeUI(mode) {
  mode = productMode(mode)
  const el = document.querySelector('input[name="mode"][value="' + mode + '"]')
  if (el) el.checked = true
  try {
    localStorage.setItem(MODE_KEY, mode)
  } catch {}
  paintModeCards()
}

function msg(text, kind) {
  const el = $('msg')
  el.textContent = text || ''
  el.className = 'msg' + (kind ? ' ' + kind : '')
}

function setState(kind, text) {
  const el = $('stState')
  el.className = 'pill ' + (kind || 'off')
  el.textContent = text
  const pwr = $('btnPower')
  pwr.classList.toggle('on', kind === 'on')
  pwr.classList.toggle('wait', kind === 'wait')
}

function applyProbe(p) {
  const el = $('stProbe')
  if (!p) {
    el.textContent = '—'
    el.style.color = ''
    return
  }
  if (p.ok) {
    el.textContent = t('okNet') + (p.ms != null ? ' ' + p.ms + 'ms' : '')
    el.style.color = '#3ddc97'
  } else {
    el.textContent = t('badNet')
    el.style.color = '#ff6b6b'
  }
}

async function api(method, path, body) {
  const slow = path.indexOf('/connect') >= 0 || path.indexOf('/disconnect') >= 0 || path.indexOf('/mode') >= 0
  const opt = { method, headers: {}, signal: AbortSignal.timeout(slow ? 15000 : 8000) }
  if (body != null) {
    opt.headers['Content-Type'] = 'application/json'
    opt.body = JSON.stringify(body)
  }
  const r = await fetch(path, opt)
  const text = await r.text()
  try {
    return JSON.parse(text || '{}')
  } catch {
    return { raw: text, statusCode: r.status }
  }
}

async function doProbe() {
  try {
    const p = await api('GET', '/api/v1/probe')
    applyProbe(p)
    return p
  } catch {
    applyProbe({ ok: false })
    return null
  }
}

async function refreshStatus() {
  try {
    const st = await api('GET', '/api/v1/status')
    const on = !!st.connected && (st.mode === 'tun' || st.mode === 'sysproxy')
    // Never overwrite the radio from the server while idle: default mode is
    // sysproxy, so a 2s poll used to snap TUN back before Connect.
    if (on && st.mode && !busy) setModeUI(st.mode)
    const shown = on && st.mode ? productMode(st.mode) : selectedMode()
    setState(on ? 'on' : 'off', on ? t('connected') + ' · ' + modeLabel(shown) : t('ready'))
    if ($('stMode')) $('stMode').textContent = modeLabel(shown)
    const tag = document.querySelector('.hint')
    if (tag) {
      if (on && st.hint) tag.textContent = st.hint
      else tag.textContent = t('tagline')
    }
    $('stNode').textContent = st.node || '—'
    $('stListen').textContent = st.listen || DEFAULT_LISTEN
    let rtt = st.rtt_ms
    if (!rtt && st.nodes && st.nodes.length) {
      const n = st.nodes.find((x) => x.active) || st.nodes.find((x) => x.reachable)
      if (n && n.rtt_ms) rtt = n.rtt_ms
    }
    $('stRtt').textContent = rtt ? rtt + ' ms' : on ? '…' : '—'
    if (st.sub_url && !$('subUrl').value) $('subUrl').value = st.sub_url
    if (st.probe_ok === true || st.probe_ok === false) {
      applyProbe({ ok: st.probe_ok, ms: st.probe_ms })
    }
    if (!on && !busy) applyProbe(null)
  } catch {
    if (!busy) setState('off', t('ready'))
  }
}

async function ensureImported() {
  const sub = ($('subUrl').value || '').trim()
  if (!sub) return
  try {
    localStorage.setItem(SUB_KEY, sub)
  } catch {}
  const imp = await api('POST', '/api/v1/import', { sub })
  if (imp && (imp.status === 'error' || imp.error)) throw new Error(imp.error || 'import')
}

async function onPower() {
  if (busy) return
  const on = $('btnPower').classList.contains('on')
  if (on) {
    await onDisconnect()
  } else {
    await onConnect()
  }
}

async function onConnect() {
  const sub = ($('subUrl').value || '').trim()
  if (!sub) {
    msg(t('needSub'), 'err')
    return
  }
  try {
    localStorage.setItem(SUB_KEY, sub)
  } catch {}
  busy = true
  setState('wait', t('connecting'))
  msg(t('connecting'))
  try {
    const imp = await api('POST', '/api/v1/import', { sub })
    if (imp && (imp.status === 'error' || imp.error)) throw new Error(imp.error || 'import')
    const mode = selectedMode()
    const md = await api('POST', '/api/v1/mode', { mode })
    if (md && (md.status === 'error' || md.error)) {
      throw new Error(md.error || 'mode')
    }
    const c = await api('POST', '/api/v1/connect')
    if (c && (c.status === 'error' || c.error)) throw new Error(c.error || 'connect')
    let p = null
    for (let i = 0; i < 2; i++) {
      p = await doProbe()
      if (p && p.ok) break
    }
    await refreshStatus()
    setState('on', t('connected'))
    msg(t('connectedAs') + ' · ' + modeLabel(mode), 'ok')
  } catch (e) {
    setState('err', t('ready'))
    msg(e.message || String(e), 'err')
  } finally {
    busy = false
  }
}

async function onDisconnect() {
  busy = true
  setState('wait', t('disconnecting'))
  msg(t('disconnecting'))
  try {
    await api('POST', '/api/v1/disconnect')
    applyProbe(null)
    msg('', 'ok')
  } catch (e) {
    msg(e.message || String(e), 'err')
  } finally {
    busy = false
    await refreshStatus()
  }
}

async function copyDesktop() {
  const listen = ($('stListen').textContent || DEFAULT_LISTEN).trim()
  const text = listen
  try {
    await navigator.clipboard.writeText(text)
    msg(t('copied') + '  ' + text, 'ok')
  } catch {
    msg(text, 'ok')
  }
}

async function pasteSub() {
  try {
    let text = ''
    try {
      text = (await navigator.clipboard.readText()) || ''
    } catch {}
    const m = String(text).match(/https?:\/\/\S+/i)
    if (!m) {
      msg(t('noClip'), 'err')
      return
    }
    $('subUrl').value = m[0]
    try {
      localStorage.setItem(SUB_KEY, m[0])
    } catch {}
    msg(t('pasted'), 'ok')
    ensureImported().catch((e) => msg(e.message || String(e), 'err'))
  } catch (e) {
    msg(String(e), 'err')
  }
}

function stopCam() {
  if (camTimer) {
    clearInterval(camTimer)
    camTimer = 0
  }
  if (camStream) {
    camStream.getTracks().forEach((tr) => tr.stop())
    camStream = null
  }
  const v = $('cam')
  v.classList.remove('on')
  v.srcObject = null
}

function closeSheet() {
  stopCam()
  $('scanSheet').hidden = true
}

function extractURL(s) {
  const m = String(s || '').match(/https?:\/\/\S+/i)
  return m ? m[0] : String(s || '').trim()
}

async function decodeQRFromImage(img) {
  const canvas = $('qrCanvas')
  const w = img.naturalWidth || img.videoWidth || img.width
  const h = img.naturalHeight || img.videoHeight || img.height
  if (!w || !h) throw new Error(t('scanFail'))
  canvas.width = w
  canvas.height = h
  const ctx = canvas.getContext('2d', { willReadFrequently: true })
  ctx.drawImage(img, 0, 0, w, h)
  const data = ctx.getImageData(0, 0, w, h)
  if (window.BarcodeDetector) {
    try {
      const det = new BarcodeDetector({ formats: ['qr_code'] })
      const codes = await det.detect(canvas)
      if (codes && codes[0] && codes[0].rawValue) return codes[0].rawValue
    } catch {}
  }
  if (typeof jsQR === 'function') {
    const code = jsQR(data.data, w, h)
    if (code && code.data) return code.data
  }
  throw new Error(t('scanFail'))
}

async function useQRText(raw) {
  const url = extractURL(raw)
  if (!url) throw new Error(t('scanFail'))
  $('subUrl').value = url
  try {
    localStorage.setItem(SUB_KEY, url)
  } catch {}
  closeSheet()
  msg(t('scanOk'), 'ok')
  ensureImported().catch((e) => msg(e.message || String(e), 'err'))
}

async function openCamera() {
  stopCam()
  try {
    camStream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: { ideal: 'environment' } },
      audio: false,
    })
  } catch {
    msg(t('camFail'), 'err')
    $('fileAlbum').click()
    return
  }
  const v = $('cam')
  v.srcObject = camStream
  v.classList.add('on')
  await v.play().catch(() => {})
  camTimer = setInterval(async () => {
    try {
      const raw = await decodeQRFromImage(v)
      if (raw) await useQRText(raw)
    } catch {}
  }, 400)
}

async function onAlbumFile(file) {
  if (!file) return
  const url = URL.createObjectURL(file)
  const img = new Image()
  img.onload = async () => {
    try {
      await useQRText(await decodeQRFromImage(img))
    } catch (e) {
      msg(e.message || t('scanFail'), 'err')
    }
    URL.revokeObjectURL(url)
  }
  img.onerror = () => {
    URL.revokeObjectURL(url)
    msg(t('scanFail'), 'err')
  }
  img.src = url
}

function init() {
  try {
    lang = localStorage.getItem(LANG_KEY) || 'zh-CN'
  } catch {}
  if (!I18N[lang]) lang = 'zh-CN'
  applyI18n()

  const langBtn = $('btnLang')
  const langMenu = $('langMenu')
  if (langBtn && langMenu) {
    langBtn.onclick = (e) => {
      e.stopPropagation()
      langMenu.hidden = !langMenu.hidden
    }
    langMenu.querySelectorAll('button').forEach((b) => {
      b.onclick = (e) => {
        e.stopPropagation()
        lang = b.getAttribute('data-lang')
        try {
          localStorage.setItem(LANG_KEY, lang)
        } catch {}
        langMenu.hidden = true
        applyI18n()
        refreshStatus()
      }
    })
    document.addEventListener('click', () => {
      langMenu.hidden = true
    })
  }

  try {
    const saved = localStorage.getItem(SUB_KEY)
    if (saved) $('subUrl').value = saved
  } catch {}
  try {
    setModeUI(localStorage.getItem(MODE_KEY) || 'sysproxy')
  } catch {
    setModeUI('sysproxy')
  }

  document.querySelectorAll('input[name="mode"]').forEach((inp) => {
    inp.addEventListener('change', async () => {
      const mode = selectedMode()
      setModeUI(mode)
      if (busy) return
      // Only take sysproxy/TUN when the user already pressed power.
      if (!$('btnPower').classList.contains('on')) return
      msg(t('connecting'))
      try {
        const r = await api('POST', '/api/v1/mode', { mode })
        if (r && (r.status === 'error' || r.error)) throw new Error(r.error)
        setModeUI(mode)
        msg(t('connectedAs') + ' · ' + modeLabel(mode), 'ok')
        await refreshStatus()
      } catch (e) {
        msg(e.message || String(e), 'err')
        await refreshStatus()
      }
    })
  })

  $('btnPower').onclick = onPower
  $('btnPaste').onclick = pasteSub
  $('btnDesktop').onclick = copyDesktop
  $('btnScan').onclick = () => {
    $('scanSheet').hidden = false
  }
  $('btnScanCancel').onclick = closeSheet
  $('btnCam').onclick = openCamera
  $('btnAlbum').onclick = () => $('fileAlbum').click()
  $('fileAlbum').onchange = (e) => {
    const f = e.target.files && e.target.files[0]
    e.target.value = ''
    onAlbumFile(f)
  }

  setInterval(refreshStatus, 2000)
  refreshStatus()
  ensureImported().catch((e) => msg(e.message || String(e), 'err'))
}

init()
