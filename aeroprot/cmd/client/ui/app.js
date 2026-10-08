const DEFAULT_LISTEN = '127.0.0.1:55555'
const LANG_KEY = 'aero-lang'
const MODE_KEY = 'aero-mode'
const SUB_KEY = 'aero-sub'
const $ = (id) => document.getElementById(id)

let lang = 'zh-CN'
let busy = false
let camStream = null
let camTimer = 0
let isImporting = false

function t(key, params) {
  const pack = I18N[lang] || I18N['zh-CN']
  let str = pack[key] || (I18N['zh-CN'] && I18N['zh-CN'][key]) || key
  if (params && typeof params === 'object') {
    Object.keys(params).forEach((k) => {
      str = str.replace(new RegExp('\\{' + k + '\\}', 'g'), params[k])
    })
  }
  return str
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
  if (typeof filterAndRenderNodes === 'function') {
    filterAndRenderNodes()
  }
}

function productMode(mode) {
  if (mode === 'sysproxy') return 'sysproxy'
  return 'tun' // 默认 TUN 全局模式 (零改动系统注册表)
}

function modeLabel(mode) {
  const m = productMode(mode)
  if (m === 'sysproxy') return t('modeSys')
  return t('modeTun')
}

function selectedMode() {
  const el = document.querySelector('input[name="mode"]:checked')
  return productMode(el ? el.value : 'tun')
}

function paintModeCards() {
  const cur = selectedMode()
  document.querySelectorAll('.mode').forEach((lab) => {
    lab.classList.toggle('selected', lab.getAttribute('data-mode') === cur)
  })
  const tip = $('modeTip')
  if (!tip) return
  if (cur === 'tun') tip.textContent = t('tipTun')
  else if (cur === 'sysproxy') tip.textContent = t('tipSys')
}

function setModeUI(mode) {
  mode = productMode(mode)
  document.querySelectorAll('input[name="mode"]').forEach((inp) => {
    inp.checked = inp.value === mode
  })
  try {
    localStorage.setItem(MODE_KEY, mode)
  } catch {}
  paintModeCards()
  if ($('stMode')) $('stMode').textContent = modeLabel(mode)
}

function msg(text, kind) {
  const el = $('msg')
  if (!el) return
  el.textContent = text || ''
  el.className = 'msg' + (kind ? ' ' + kind : '')
}

function setState(kind, text) {
  const el = $('stState')
  if (el) {
    el.className = 'pill ' + (kind || 'off')
    el.textContent = text
  }
  const pwr = $('btnPower')
  if (pwr) {
    pwr.classList.toggle('on', kind === 'on')
    pwr.classList.toggle('wait', kind === 'wait')
  }
}

function applyProbe(p) {
  const el = $('stProbe')
  if (!el) return
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
  if (typeof window.goClientAPI === 'function') {
    try {
      const resStr = await window.goClientAPI(method, path, body != null ? JSON.stringify(body) : '')
      return JSON.parse(resStr || '{}')
    } catch (e) {
      console.error('IPC bridge error:', e)
    }
  }
  const slow = path.indexOf('/connect') >= 0 || path.indexOf('/disconnect') >= 0 || path.indexOf('/mode') >= 0
  const opt = { method, headers: {}, signal: AbortSignal.timeout(slow ? 10000 : 5000) }
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

function getLocalIspName(isp) {
  if (!isp) return '—'
  const u = isp.toUpperCase()
  if (u === 'CT' || u.includes('电信')) return t('ispCTName')
  if (u === 'CU' || u.includes('联通')) return t('ispCUName')
  if (u === 'CM' || u.includes('移动')) return t('ispCMName')
  return t('ispBGPName')
}

async function refreshStatus() {
  if (busy) return
  try {
    const st = await api('GET', '/api/v1/status')
    const on = !!st.connected
    if (on && st.mode && !busy) setModeUI(st.mode)
    const shown = on && st.mode ? productMode(st.mode) : selectedMode()
    setState(on ? 'on' : 'off', on ? t('connected') + ' · ' + modeLabel(shown) : t('ready'))
    if ($('stMode')) $('stMode').textContent = modeLabel(shown)
    const tag = document.querySelector('.hint')
    if (tag) {
      if (on && st.hint) tag.textContent = st.hint
      else tag.textContent = t('tagline')
    }
    if ($('stNode')) $('stNode').textContent = st.node || '—'
    if ($('stISP')) $('stISP').textContent = getLocalIspName(st.isp)
    if ($('stSNI')) $('stSNI').textContent = st.sni || '—'
    if ($('stListen')) $('stListen').textContent = st.listen || DEFAULT_LISTEN
    let rtt = st.rtt_ms
    if (!rtt && st.nodes && st.nodes.length) {
      const n = st.nodes.find((x) => x.active) || st.nodes.find((x) => x.reachable)
      if (n && n.rtt_ms) rtt = n.rtt_ms
    }
    if ($('stRtt')) $('stRtt').textContent = rtt ? rtt + ' ms' : on ? '…' : '—'
    if ($('geoRuleCount') && st.geo_rule_count) {
      $('geoRuleCount').textContent = t('rulesReady', { count: st.geo_rule_count.toLocaleString() })
    }
    if (st.sub_url && !$('subUrl').value) $('subUrl').value = st.sub_url
    if (st.probe_ok === true || st.probe_ok === false) {
      applyProbe({ ok: st.probe_ok, ms: st.probe_ms })
    }
    if (!on && !busy) applyProbe(null)
    if (st.node && currentNodes.length > 0) {
      let changed = false
      currentNodes.forEach((n) => {
        const shouldBeActive = (n.address === st.node)
        const shouldBeConnected = shouldBeActive && !!st.connected
        if (n.active !== shouldBeActive || n.connected !== shouldBeConnected) {
          n.active = shouldBeActive
          n.connected = shouldBeConnected
          changed = true
        }
      })
      if (changed) filterAndRenderNodes()
    } else if (currentNodes.length === 0 && st.connected) {
      fetchNodes()
    }
  } catch {
    if (!busy) setState('off', t('ready'))
  }
}

async function checkUpfrontTUNConflict() {
  try {
    const res = await api('GET', '/api/v1/tun/status')
    if (res && res.conflict) {
      return res.vpn || t('thirdPartyVPN')
    }
  } catch (err) {
    console.warn('checkUpfrontTUNConflict err:', err)
  }
  return null
}

function showTunConflictModal(vpnName, onProceed) {
  const modal = $('tunConflictModal')
  if (!modal) {
    if (onProceed) onProceed()
    return
  }
  const desc = $('tunConflictModalDesc')
  if (desc) {
    desc.textContent = t('tunConflictDesc', { name: vpnName || t('thirdPartyVPN') })
  }
  modal.hidden = false

  $('btnTunConflictSysproxy').onclick = async () => {
    modal.hidden = true
    hideConflictBox()
    setModeUI('sysproxy')
    await api('POST', '/api/v1/mode', { mode: 'sysproxy' }).catch(() => null)
    const sub = ($('subUrl').value || '').trim()
    if (sub) {
      await proceedConnect(sub)
    } else if (onProceed) {
      onProceed()
    }
  }

  $('btnTunConflictIgnore').onclick = () => {
    modal.hidden = true
    if (onProceed) onProceed()
  }

  $('btnTunConflictCancel').onclick = () => {
    modal.hidden = true
    msg(t('tunConflictCancel'), 'info')
  }
}

async function ensureImported(strict = false) {
  if (isImporting) return
  isImporting = true
  try {
    const sub = ($('subUrl').value || '').trim()
    if (!sub) {
      if (strict) {
        msg(t('subEmptyErr'), 'err')
        throw new Error(t('subEmptyErr'))
      }
      return
    }
    if (!sub.startsWith('http://') && !sub.startsWith('https://')) {
      if (strict) {
        msg(t('subFormatErr'), 'err')
        throw new Error(t('subFormatErr'))
      }
      return
    }

    if (strict && selectedMode() === 'tun') {
      const vpn = await checkUpfrontTUNConflict()
      if (vpn) {
        showTunConflictModal(vpn, () => {
          doActualImport(sub)
        })
        return
      }
    }

    await doActualImport(sub)
  } finally {
    isImporting = false
  }
}

async function doActualImport(sub) {
  try {
    localStorage.setItem(SUB_KEY, sub)
  } catch {}
  const imp = await api('POST', '/api/v1/import', { sub })
  if (imp && (imp.status === 'error' || imp.error)) throw new Error(imp.error || 'import')
  msg(t('subLoadedOk'), 'ok')
  fetchNodes()
}

async function onPower() {
  const pwr = $('btnPower')
  if (pwr && pwr.classList.contains('wait')) {
    // 正在连接中，点击圆圈即可立即中断/取消连接！
    await onCancelConnect()
    return
  }
  if (busy) return
  const on = pwr && pwr.classList.contains('on')
  if (on) {
    await onDisconnect()
  } else {
    await onConnect()
  }
}

async function onCancelConnect() {
  busy = false
  msg(t('cancelling'))
  try {
    await api('POST', '/api/v1/cancel')
  } catch (e) {
    console.error('cancel connect err:', e)
  }
  setState('off', t('ready'))
  msg(t('ready'))
}

async function onConnect() {
  const sub = ($('subUrl').value || '').trim()
  if (!sub) {
    msg(t('needSub'), 'err')
    return
  }
  if (selectedMode() === 'tun') {
    const vpn = await checkUpfrontTUNConflict()
    if (vpn) {
      showTunConflictModal(vpn, () => proceedConnect(sub))
      return
    }
  }
  await proceedConnect(sub)
}

async function proceedConnect(sub) {
  try {
    localStorage.setItem(SUB_KEY, sub)
  } catch {}
  busy = true
  setState('wait', t('connecting'))
  msg(t('connecting'))
  try {
    // 1. 导入订阅并解析服务器与 Token
    const imp = await api('POST', '/api/v1/import', { sub })
    if (imp && (imp.status === 'error' || imp.error)) throw new Error(imp.error || 'import')
    fetchNodes()
    
    // 2. 设定工作模式
    const mode = selectedMode()
    const md = await api('POST', '/api/v1/mode', { mode })
    if (md && md.code === 'CONFLICT_TUN') {
      setModeUI(md.mode || 'sysproxy')
      handleTUNConflict(md.vpn || '')
      return
    }
    if (md && md.code === 'UDP_UNAVAILABLE') {
      handleUDPUnavailable(md.msg || '')
      return
    }
    if (md && (md.status === 'error' || md.error)) {
      throw new Error(md.error || md.msg || t('modeSwitchFailed'))
    }

    // 3. 建立秒级快速隧道连接 (异步启动，UI 永不假死)
    const c = await api('POST', '/api/v1/connect')
    if (c && c.code === 'CONFLICT_TUN') {
      handleTUNConflict(c.vpn || '')
      return
    }
    if (c && (c.code === 'UDP_UNAVAILABLE' || c.error === 'UDP_UNAVAILABLE')) {
      handleUDPUnavailable(c.msg || '')
      return
    }
    if (c && c.code === 'RATE_LIMITED') {
      throw new Error(t('connRateLimited'))
    }
    if (c && (c.status === 'error' || c.error)) {
      throw new Error(c.error || c.msg || t('connFailed'))
    }

    if (c && c.status === 'starting') {
      await pollConnectStatus()
      return
    }

    // 4. 已连通
    hideConflictBox()
    doProbe()
    await refreshStatus()
    setState('on', t('connected'))
    msg(t('connectedAs') + ' · ' + modeLabel(mode), 'ok')
  } catch (e) {
    if (e.code === 'CONFLICT_TUN') {
      handleTUNConflict(e.vpn || '')
    } else if (e.code === 'UDP_UNAVAILABLE' || (e.message && e.message.includes('UDP_UNAVAILABLE'))) {
      handleUDPUnavailable(e.message)
    } else {
      setState('err', t('ready'))
      const em = e.message || String(e)
      msg(em === 'connect' ? t('connFailed') : em, 'err')
    }
  } finally {
    busy = false
  }
}

async function pollConnectStatus() {
  const startTime = Date.now()
  const timeoutMs = 28000
  const mode = selectedMode()

  while (busy) {
    await new Promise((r) => setTimeout(r, 200))
    if (!busy) return // 用户点击了取消中断

    let st = null
    try {
      st = await api('GET', '/api/v1/status')
    } catch (e) {
      console.warn('poll status err:', e)
      continue
    }

    if (!st) continue

    if (st.connected) {
      hideConflictBox()
      doProbe()
      await refreshStatus()
      setState('on', t('connected'))
      msg(t('connectedAs') + ' · ' + modeLabel(mode), 'ok')
      return
    }

    if (st.error_code === 'CONFLICT_TUN') {
      handleTUNConflict(st.conflict_vpn || '')
      return
    }

    if (st.error_code === 'UDP_UNAVAILABLE') {
      handleUDPUnavailable(st.last_error || '')
      return
    }

    if (!st.starting && !st.stopping && st.last_error) {
      setState('err', t('ready'))
      msg(st.last_error, 'err')
      return
    }

    if (!st.starting && !st.stopping && !st.connected) {
      setState('off', t('ready'))
      msg(t('ready'))
      return
    }

    if (Date.now() - startTime > timeoutMs) {
      try {
        await api('POST', '/api/v1/cancel')
      } catch {}
      setState('err', t('ready'))
      msg(t('connTimeout') || '连接超时，请重试', 'err')
      return
    }
  }
}

async function onDisconnect() {
  hideConflictBox()
  busy = true
  setState('wait', t('disconnecting'))
  msg(t('disconnecting'))
  try {
    await api('POST', '/api/v1/disconnect')
    applyProbe(null)
    await refreshStatus()
    setState('off', t('ready'))
    msg(t('disconnected'))
  } catch (e) {
    msg(e.message || String(e), 'err')
  } finally {
    busy = false
  }
}

function handleUDPUnavailable(customMsg) {
  setState('off', 'UDP')
  msg(customMsg || t('udpUnavailableFallback'), 'err')
}

function handleTUNConflict(vpnName) {
  busy = false
  msg('') // 彻底清空「连接中…」残留
  setState('off', t('ready'))
  const box = $('conflictBox')
  if (box) {
    box.hidden = false
    const desc = $('conflictDesc')
    if (desc) {
      desc.textContent = t('conflictDesc', { name: vpnName || t('thirdPartyVPN') })
    }
  }
  const sub = ($('subUrl').value || '').trim()
  showTunConflictModal(vpnName, () => {
    if (sub) proceedConnect(sub)
  })
}

function hideConflictBox() {
  const box = $('conflictBox')
  if (box) box.hidden = true
}

async function pasteSub() {
  try {
    const text = await navigator.clipboard.readText()
    if (text && text.trim()) {
      $('subUrl').value = text.trim()
      try {
        localStorage.setItem(SUB_KEY, text.trim())
      } catch {}
      await ensureImported()
      msg(t('pasted') + ' · ' + t('scanOk'), 'ok')
    } else {
      msg(t('noClip'), 'err')
    }
  } catch (e) {
    msg(e.message || t('noClip'), 'err')
  }
}

function copyDesktop() {
  const text = DEFAULT_LISTEN
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => msg(t('copied'), 'ok')).catch(() => copyDesktopFallback(text))
  } else {
    copyDesktopFallback(text)
  }
}

function copyDesktopFallback(text) {
  const ta = document.createElement('textarea')
  ta.value = text
  ta.style.position = 'fixed'
  ta.style.opacity = '0'
  document.body.appendChild(ta)
  ta.select()
  try {
    document.execCommand('copy')
    msg(t('copied'), 'ok')
  } catch {
    msg(text)
  }
  document.body.removeChild(ta)
}

function closeSheet() {
  $('scanSheet').hidden = true
  stopCamera()
}

function stopCamera() {
  if (camTimer) {
    cancelAnimationFrame(camTimer)
    camTimer = 0
  }
  if (camStream) {
    camStream.getTracks().forEach((tr) => tr.stop())
    camStream = null
  }
  const v = $('cam')
  v.srcObject = null
  v.classList.remove('on')
}

async function openCamera() {
  msg('')
  const v = $('cam')
  try {
    camStream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: 'environment' },
    })
    v.srcObject = camStream
    v.classList.add('on')
    await v.play()
    scanLoop()
  } catch (e) {
    msg(t('camFail') + ' (' + (e.message || e) + ')', 'err')
  }
}

function scanLoop() {
  const v = $('cam')
  const canvas = $('qrCanvas')
  if (!camStream || v.readyState !== v.HAVE_ENOUGH_DATA) {
    camTimer = requestAnimationFrame(scanLoop)
    return
  }
  canvas.width = v.videoWidth
  canvas.height = v.videoHeight
  const ctx = canvas.getContext('2d')
  ctx.drawImage(v, 0, 0, canvas.width, canvas.height)
  const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height)
  if (window.jsQR) {
    const code = window.jsQR(imgData.data, imgData.width, imgData.height, {
      inversionAttempts: 'dontInvert',
    })
    if (code && code.data) {
      stopCamera()
      closeSheet()
      useQRText(code.data)
      return
    }
  }
  camTimer = requestAnimationFrame(scanLoop)
}

function decodeQRFromImage(img) {
  return new Promise((resolve, reject) => {
    const canvas = $('qrCanvas')
    canvas.width = img.naturalWidth || img.width
    canvas.height = img.naturalHeight || img.height
    const ctx = canvas.getContext('2d')
    ctx.drawImage(img, 0, 0)
    const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height)
    if (!window.jsQR) {
      reject(new Error('jsQR missing'))
      return
    }
    const code = window.jsQR(imgData.data, imgData.width, imgData.height)
    if (code && code.data) resolve(code.data)
    else reject(new Error(t('scanFail')))
  })
}

async function useQRText(raw) {
  const s = (raw || '').trim()
  if (!s) return
  $('subUrl').value = s
  try {
    localStorage.setItem(SUB_KEY, s)
  } catch {}
  try {
    await ensureImported()
    msg(t('scanOk'), 'ok')
  } catch (e) {
    msg(e.message || String(e), 'err')
  }
}

function onAlbumFile(file) {
  if (!file) return
  closeSheet()
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

async function doClientLogin() {
  const server = ($('loginServer').value || '').trim().replace(/\/+$/, '')
  const username = ($('loginUsername').value || '').trim()
  const password = ($('loginPassword').value || '').trim()
  if (!server) {
    msg(t('loginMissingServer'), 'err')
    return
  }
  if (!username || !password) {
    msg(t('loginMissingCreds'), 'err')
    return
  }
  msg(t('loginLoggingIn'), 'wait')
  try {
    try { localStorage.setItem('aero_mid_server', server) } catch {}
    const res = await fetch(`${server}/api/v1/auth/login/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, portal: 'client' })
    })
    const data = await res.json().catch(() => ({}))
    if (!res.ok || data.code !== 0) {
      throw new Error(data.message || t('loginAuthFailed'))
    }
    const u = data.data || data
    try {
      localStorage.setItem('aero_client_user', JSON.stringify({ server, username, user: u }))
    } catch {}
    renderLoggedInUser(server, u)
    msg(t('loginOk'), 'ok')
  } catch (e) {
    msg(t('loginFail', { err: e.message }), 'err')
  }
}

function renderLoggedInUser(server, user) {
  if ($('loginFormWrap')) $('loginFormWrap').style.display = 'none'
  if ($('loggedInWrap')) $('loggedInWrap').style.display = 'block'
  if ($('userDisplayName')) $('userDisplayName').textContent = user.username || t('userDefault')
  if ($('userAvatar')) $('userAvatar').textContent = (user.username || 'A')[0].toUpperCase()
  if ($('userPlanBadge')) $('userPlanBadge').textContent = user.is_staff ? t('sysAdmin') : (user.plan_name || t('monthlyPlan'))
  if ($('userServerHost')) $('userServerHost').textContent = server.replace(/^https?:\/\//, '')

  const sel = $('userSubSelect')
  if (!sel) return
  sel.innerHTML = ''

  const subs = user.subscriptions || []
  if (subs.length === 0) {
    const slug = user.sub_slug || 'superadmin'
    const opt = document.createElement('option')
    opt.value = `${server}/sub/${slug}`
    opt.textContent = `${t('defaultSub')} (${slug})`
    sel.appendChild(opt)
  } else {
    subs.forEach((s) => {
      const opt = document.createElement('option')
      opt.value = `${server}/sub/${s.sub_slug}`
      opt.textContent = `${s.plan_name || t('userPlan')} (${s.sub_slug})`
      sel.appendChild(opt)
    })
  }

  if ($('subCountBadge')) {
    $('subCountBadge').textContent = t('subsAvailable', { count: sel.options.length })
  }

  if (sel.options.length > 0) {
    $('subUrl').value = sel.value
    try {
      localStorage.setItem(SUB_KEY, sel.value)
    } catch {}
    api('POST', '/api/v1/import', { sub: sel.value }).catch(() => null)
  }

  sel.onchange = () => {
    $('subUrl').value = sel.value
    try {
      localStorage.setItem(SUB_KEY, sel.value)
    } catch {}
    api('POST', '/api/v1/import', { sub: sel.value }).then(() => {
      msg(t('subSwitched', { name: sel.options[sel.selectedIndex].text }), 'ok')
    }).catch(() => null)
  }
}

function doClientLogout() {
  try {
    localStorage.removeItem('aero_client_user')
  } catch {}
  if ($('loginFormWrap')) $('loginFormWrap').style.display = 'block'
  if ($('loggedInWrap')) $('loggedInWrap').style.display = 'none'
  if ($('loginPassword')) $('loginPassword').value = ''
  msg(t('loggedOut'))
}

let currentNodes = []
let isProbingNodes = false
let selectedISP = 'ALL'
let searchKeyword = ''

function getLatencyClass(lat, reachable, probed) {
  if (!probed) return 'lat-gray'
  if (!reachable || lat < 0) return 'lat-gray'
  if (lat < 100) return 'lat-green'
  if (lat <= 200) return 'lat-yellow'
  return 'lat-red'
}

function getIspTagClass(isp) {
  if (!isp) return 'tag-blue'
  const upper = isp.toUpperCase()
  if (upper === 'CT' || upper.includes('电信')) return 'tag-ct'
  if (upper === 'CU' || upper.includes('联通')) return 'tag-cu'
  if (upper === 'CM' || upper.includes('移动')) return 'tag-cm'
  if (upper === 'BGP') return 'tag-bgp'
  return 'tag-blue'
}

function getIspLabel(isp) {
  if (!isp) return ''
  const upper = isp.toUpperCase()
  if (upper === 'CT' || upper.includes('电信')) return t('ispCTOpt')
  if (upper === 'CU' || upper.includes('联通')) return t('ispCUOpt')
  if (upper === 'CM' || upper.includes('移动')) return t('ispCMOpt')
  if (upper === 'BGP') return t('ispBGPOpt')
  return isp
}

function filterAndRenderNodes() {
  let list = currentNodes || []
  if (selectedISP !== 'ALL') {
    list = list.filter((n) => {
      const isp = (n.isp_affinity || '').toUpperCase()
      if (selectedISP === 'CT') return isp === 'CT' || isp.includes('电信')
      if (selectedISP === 'CU') return isp === 'CU' || isp.includes('联通')
      if (selectedISP === 'CM') return isp === 'CM' || isp.includes('移动')
      return isp === selectedISP
    })
  }
  if (searchKeyword) {
    const kw = searchKeyword.toLowerCase()
    list = list.filter((n) => {
      return (n.name && n.name.toLowerCase().includes(kw)) ||
             (n.address && n.address.toLowerCase().includes(kw)) ||
             (n.ip && n.ip.toLowerCase().includes(kw)) ||
             (n.sni && n.sni.toLowerCase().includes(kw))
    })
  }
  renderNodes(list)
}

function renderNodes(nodes) {
  const container = $('nodesList')
  const badge = $('nodesCountBadge')
  if (!container) return
  if (!nodes || nodes.length === 0) {
    container.innerHTML = '<div class="empty-nodes" style="color:var(--muted);font-size:11px;text-align:center;padding:12px 0;">' + (currentNodes.length > 0 ? t('noMatchNodes') : t('emptyNodes')) + '</div>'
    if (badge) badge.textContent = t('nodesCount', { count: currentNodes ? currentNodes.length : 0 })
    return
  }
  if (badge) badge.textContent = t('nodesCount', { count: currentNodes.length })
  container.innerHTML = ''

  nodes.forEach((n) => {
    const item = document.createElement('div')
    item.className = 'node-item' + (n.active ? ' active' : '')
    item.setAttribute('data-addr', n.address)

    const infoCol = document.createElement('div')
    infoCol.className = 'node-info-col'

    const nameRow = document.createElement('div')
    nameRow.className = 'node-name-row'

    const nameSpan = document.createElement('span')
    nameSpan.className = 'node-name'
    nameSpan.textContent = n.name || n.address
    nameRow.appendChild(nameSpan)

    if (n.line_type) {
      const typeTag = document.createElement('span')
      typeTag.className = 'tag-sm tag-blue'
      typeTag.style.fontSize = '9px'
      typeTag.style.padding = '1px 4px'
      typeTag.textContent = n.line_type
      nameRow.appendChild(typeTag)
    }

    if (n.isp_affinity) {
      const ispTag = document.createElement('span')
      ispTag.className = 'tag-sm ' + getIspTagClass(n.isp_affinity)
      ispTag.style.fontSize = '9px'
      ispTag.style.padding = '1px 4px'
      ispTag.textContent = getIspLabel(n.isp_affinity)
      nameRow.appendChild(ispTag)
    }
    infoCol.appendChild(nameRow)

    const addrSpan = document.createElement('span')
    addrSpan.className = 'node-addr'
    addrSpan.textContent = n.address + (n.ip ? ' (' + n.ip + ')' : '')
    infoCol.appendChild(addrSpan)

    item.appendChild(infoCol)

    const badgeWrap = document.createElement('div')
    badgeWrap.className = 'node-badge-wrap'

    if (n.active) {
      const activeTag = document.createElement('span')
      if (n.connected) {
        activeTag.className = 'badge-connected'
        activeTag.textContent = t('nodeConnectedBadge')
      } else {
        activeTag.className = 'badge-preferred'
        activeTag.textContent = t('nodePreferredBadge')
      }
      badgeWrap.appendChild(activeTag)
    }

    const latBadge = document.createElement('span')
    const probed = !!n.last_probe_at
    latBadge.className = 'latency-badge ' + getLatencyClass(n.latency_ms, n.reachable, probed)
    if (!probed) {
      latBadge.textContent = '—'
    } else if (!n.reachable || n.latency_ms < 0) {
      latBadge.textContent = t('timeout')
    } else {
      latBadge.textContent = n.latency_ms + 'ms'
    }
    badgeWrap.appendChild(latBadge)

    item.appendChild(badgeWrap)

    item.onclick = async () => {
      if (n.active) return
      await selectNode(n.address)
    }

    container.appendChild(item)
  })
}

async function selectNode(addr) {
  try {
    msg(t('switchingNode', { addr }), 'wait')
    const res = await api('POST', '/api/v1/nodes/select', { address: addr })
    if (res && res.status === 'ok') {
      msg(t('switchNodeOk', { addr }), 'ok')
      await fetchNodes()
      await refreshStatus()
    } else {
      msg(t('switchNodeFail', { err: res.error || t('unknownErr') }), 'err')
    }
  } catch (e) {
    msg(t('switchNodeFail', { err: e.message || String(e) }), 'err')
  }
}

async function fetchNodes() {
  try {
    const res = await api('GET', '/api/v1/nodes')
    if (res && res.status === 'ok' && Array.isArray(res.nodes)) {
      currentNodes = res.nodes
      filterAndRenderNodes()
    }
  } catch {}
}

async function probeAllNodes() {
  if (isProbingNodes) return
  isProbingNodes = true
  const btn = $('btnProbeAllNodes')
  if (btn) {
    btn.classList.add('probing-pulse')
    btn.disabled = true
    btn.textContent = t('speedTesting')
  }
  msg(t('probingAll'), 'wait')
  try {
    const res = await api('POST', '/api/v1/nodes/probe')
    if (res && res.status === 'ok' && Array.isArray(res.nodes)) {
      currentNodes = res.nodes
      filterAndRenderNodes()
      msg(t('probeAllDone'), 'ok')
    } else if (res && res.code === 'RATE_LIMITED') {
      msg(t('probeTooFast'), 'err')
    } else {
      msg(t('probeFail', { err: res.error || t('unknownErr') }), 'err')
    }
  } catch (e) {
    msg(t('probeFail', { err: e.message || String(e) }), 'err')
  } finally {
    if (btn) {
      btn.classList.remove('probing-pulse')
      btn.disabled = false
      btn.textContent = t('probeAllNodes')
    }
    isProbingNodes = false
  }
}

function init() {
  try {
    lang = localStorage.getItem(LANG_KEY) || 'zh-CN'
  } catch {}
  if (!I18N[lang]) lang = 'zh-CN'
  applyI18n()

  // 1. Tab 切换：专属订阅 / 中台账号登录
  $('tabSubManual')?.addEventListener('click', () => {
    $('tabSubManual').classList.add('active')
    $('tabAuthLogin')?.classList.remove('active')
    $('paneSubManual').style.display = 'block'
    $('paneAuthLogin').style.display = 'none'
  })
  $('tabAuthLogin')?.addEventListener('click', () => {
    $('tabAuthLogin').classList.add('active')
    $('tabSubManual')?.classList.remove('active')
    $('paneAuthLogin').style.display = 'block'
    $('paneSubManual').style.display = 'none'
  })

  // 2. 账号登录操作
  $('btnDoLogin')?.addEventListener('click', doClientLogin)
  $('btnClientLogout')?.addEventListener('click', doClientLogout)

  // 3. 手动载入专属订阅 (严格前置校验，空值抛错，载入后立即全量刷新节点列表与状态)
  $('btnApplyManualSub')?.addEventListener('click', async () => {
    const btn = $('btnApplyManualSub')
    const origText = btn ? btn.textContent : t('load')
    if (btn) {
      btn.disabled = true
      btn.textContent = t('loading')
    }
    try {
      await ensureImported(true)
      await refreshStatus()
      msg(t('subLoadedOk'), 'ok')
    } catch (e) {
      msg(e.message, 'err')
    } finally {
      if (btn) {
        btn.disabled = false
        btn.textContent = origText
      }
    }
  })

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

  // 恢复保存的手动订阅链接
  try {
    const saved = localStorage.getItem(SUB_KEY)
    if (saved) $('subUrl').value = saved
  } catch {}

  // 恢复中台地址与已登录用户会话
  try {
    const savedServer = localStorage.getItem('aero_mid_server')
    if (savedServer && $('loginServer')) $('loginServer').value = savedServer
    const savedUser = localStorage.getItem('aero_client_user')
    if (savedUser) {
      const { server, user } = JSON.parse(savedUser)
      if (server && user) renderLoggedInUser(server, user)
    }
  } catch {}

  // 默认模式读取 (存盘的 socks 按 sysproxy 读)
  try {
    let saved = localStorage.getItem(MODE_KEY) || 'tun'
    if (saved === 'socks') saved = 'sysproxy'
    setModeUI(saved)
  } catch {
    setModeUI('tun')
  }

  // 模式切换与点击（即时高亮、即时生效）
  document.querySelectorAll('.mode').forEach((lab) => {
    lab.addEventListener('click', async (e) => {
      e.preventDefault()
      e.stopPropagation()
      if (busy) return
      const targetMode = lab.getAttribute('data-mode')
      const cur = selectedMode()
      if (cur === targetMode) return // 重复点击当前单选卡，直接保持，绝不跳变！

      const prevMode = cur
      if (targetMode === 'tun') {
        const vpn = await checkUpfrontTUNConflict()
        if (vpn) {
          showTunConflictModal(vpn, () => switchModeNow(targetMode, prevMode))
          return
        }
      }
      await switchModeNow(targetMode, prevMode)
    })
  })

  async function switchModeNow(targetMode, prevMode) {
    setModeUI(targetMode)
    if ($('btnPower').classList.contains('on')) {
      busy = true // 置 busy，阻断 2 秒轮询将乐观选择盖掉
      msg(t('connecting'))
      try {
        const r = await api('POST', '/api/v1/mode', { mode: targetMode })
        if (r && r.code === 'CONFLICT_TUN') {
          setModeUI(r.mode || prevMode)
          handleTUNConflict(r.vpn || '')
          return
        }
        if (r && (r.status === 'error' || r.error)) {
          setModeUI(r.mode || prevMode)
          msg(r.error || 'mode switch failed', 'err')
          await refreshStatus()
          return
        }
        if (r && r.status === 'switching') {
          busy = true
          await pollConnectStatus()
          return
        }
        if (r && r.status === 'ok') {
          await refreshStatus()
          return
        }
        await refreshStatus()
      } catch (err) {
        setModeUI(prevMode)
        msg(err.message || String(err), 'err')
        await refreshStatus()
      } finally {
        busy = false
      }
    }
  }

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

  if ($('btnPing')) {
    $('btnPing').onclick = async () => {
      $('btnPing').disabled = true
      $('btnPing').textContent = t('speedTesting')
      try {
        const res = await api('POST', '/api/v1/ping')
        if (res && res.status === 'ok') {
          if ($('stRtt')) $('stRtt').textContent = res.rtt_ms + ' ms'
        }
      } catch {}
      $('btnPing').disabled = false
      $('btnPing').textContent = t('speedTest')
    }
  }

  if ($('btnSyncGeo')) {
    $('btnSyncGeo').onclick = async () => {
      $('btnSyncGeo').disabled = true
      $('btnSyncGeo').textContent = t('syncing')
      try {
        const res = await api('POST', '/api/v1/geodata/sync')
        if (res && res.status === 'ok') {
          if ($('geoRuleCount')) $('geoRuleCount').textContent = t('rulesSynced', { count: res.count.toLocaleString() })
        }
      } catch {}
      $('btnSyncGeo').disabled = false
      $('btnSyncGeo').textContent = t('sync')
    }
  }

  if ($('btnSwitchSysproxy')) {
    $('btnSwitchSysproxy').onclick = async () => {
      hideConflictBox()
      setModeUI('sysproxy')
      const sub = ($('subUrl').value || '').trim()
      await api('POST', '/api/v1/mode', { mode: 'sysproxy' }).catch(() => null)
      if (sub) {
        await proceedConnect(sub)
      } else {
        await onConnect()
      }
    }
  }

  if ($('btnDismissConflict')) {
    $('btnDismissConflict').onclick = () => {
      hideConflictBox()
      setState('off', t('ready'))
      msg(t('closeThirdPartyTunHint'), 'info')
    }
  }

  if ($('btnProbeAllNodes')) {
    $('btnProbeAllNodes').onclick = probeAllNodes
  }

  const searchInput = $('nodeSearchInput')
  if (searchInput) {
    searchInput.oninput = (e) => {
      searchKeyword = (e.target.value || '').trim()
      filterAndRenderNodes()
    }
  }

  document.querySelectorAll('.node-isp-btn').forEach((btn) => {
    btn.onclick = () => {
      document.querySelectorAll('.node-isp-btn').forEach((b) => b.classList.remove('active'))
      btn.classList.add('active')
      selectedISP = btn.getAttribute('data-isp') || 'ALL'
      filterAndRenderNodes()
    }
  })

  // 链式代理折叠展开与配置处理
  const chainToggle = $('chainProxyToggleHeader')
  const chainBody = $('chainProxyBody')
  const chainIcon = $('chainToggleIcon')
  if (chainToggle && chainBody) {
    chainToggle.onclick = () => {
      const isHidden = chainBody.style.display === 'none'
      chainBody.style.display = isHidden ? 'block' : 'none'
      if (chainIcon) chainIcon.textContent = isHidden ? '▲' : '▼'
    }
  }

  function updateChainBadge(enabled) {
    const b = $('chainStatusBadge')
    if (!b) return
    if (enabled) {
      b.className = 'tag-sm tag-blue'
      b.textContent = t('chainEnabled')
    } else {
      b.className = 'tag-sm'
      b.style.background = '#21262d'
      b.style.color = '#8b949e'
      b.textContent = t('chainDisabled')
    }
  }

  async function loadChainProxyUI() {
    try {
      const res = await api('GET', '/api/v1/chain/config')
      if (res && res.status === 'ok' && res.config) {
        const c = res.config
        if ($('chainEnableToggle')) $('chainEnableToggle').checked = !!c.enabled
        if ($('chainProtoSelect')) $('chainProtoSelect').value = c.protocol || 'socks5'
        if ($('chainHostInput')) $('chainHostInput').value = c.host || ''
        if ($('chainPortInput')) $('chainPortInput').value = c.port ? String(c.port) : ''
        if ($('chainUserInput')) $('chainUserInput').value = c.username || ''
        if ($('chainPassInput')) $('chainPassInput').value = c.password || ''
        updateChainBadge(!!c.enabled)
      }
    } catch {}
  }

  if ($('btnSaveChainProxy')) {
    $('btnSaveChainProxy').onclick = async () => {
      const payload = {
        enabled: $('chainEnableToggle') ? $('chainEnableToggle').checked : false,
        protocol: $('chainProtoSelect') ? $('chainProtoSelect').value : 'socks5',
        host: $('chainHostInput') ? $('chainHostInput').value.trim() : '',
        port: $('chainPortInput') ? parseInt($('chainPortInput').value.trim(), 10) || 0 : 0,
        username: $('chainUserInput') ? $('chainUserInput').value.trim() : '',
        password: $('chainPassInput') ? $('chainPassInput').value : ''
      }
      try {
        const res = await api('POST', '/api/v1/chain/config', payload)
        if (res && res.status === 'ok') {
          updateChainBadge(payload.enabled)
          msg(t('chainSaveOk'), 'ok')
        } else {
          msg(res.error || 'save failed', 'err')
        }
      } catch (e) {
        msg(e.message || String(e), 'err')
      }
    }
  }

  loadChainProxyUI()

  fetchNodes()
  setInterval(refreshStatus, 2000)
  refreshStatus()
  ensureImported(false).then(() => fetchNodes()).catch(() => {})
}

init()
