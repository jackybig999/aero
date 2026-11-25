const DEFAULT_LISTEN = '127.0.0.1:55555'
let currentListen = DEFAULT_LISTEN   // 引擎实际监听的地址（默认端口不可用时会是备用端口）
let effectiveMode = 'tun'            // 引擎实际运行的模式（TUN 不可用而降级时是 sysproxy）
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
  updateChainSummary()
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

// 客户端界面统一 TUN（本地 55555 常驻代理在 TUN 下同样可用）；sysproxy 只在命令行/无头模式出现
function selectedMode() {
  return 'tun'
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
  const slow = path.indexOf('/connect') >= 0 || path.indexOf('/disconnect') >= 0 || path.indexOf('/mode') >= 0 || path.indexOf('/import') >= 0
  const opt = { method, headers: {}, signal: AbortSignal.timeout(slow ? 15000 : 5000) }
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
    paintListen(st)
    effectiveMode = productMode(st.mode || 'tun')
    paintDegraded(st)
    let rtt = st.rtt_ms
    if (!rtt && st.nodes && st.nodes.length) {
      const n = st.nodes.find((x) => x.active) || st.nodes.find((x) => x.reachable)
      if (n && n.rtt_ms) rtt = n.rtt_ms
    }
    if ($('stRtt')) $('stRtt').textContent = rtt ? rtt + ' ms' : on ? '…' : '—'
    paintGeo(st)
    if (st.sub_url && !$('subUrl').value) $('subUrl').value = st.sub_url
    updateOnboard(st)
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

// 本地常驻端口徽章：显示引擎真实监听的地址；没在监听（端口被占用/被系统禁止）时明确提示，而不是仍显示一个不可用的端口
function paintListen(st) {
  const badge = $('listenBadge')
  if (!badge) return
  if (st.resident_listening === false) {
    badge.textContent = t('residentDown')
    badge.classList.add('warn')
    return
  }
  badge.classList.remove('warn')
  if (st.listen) currentListen = st.listen
  badge.textContent = currentListen
}

// 降级提示：请求的是 TUN 但虚拟网卡不可用，隧道已连上，只有走本地代理端口的流量经过隧道。
function paintDegraded(st) {
  const box = $('degradedNotice')
  if (!box) return
  const on = !!(st.connected && st.degraded)
  box.hidden = !on
  if (!on) return
  const reason = friendlyConnectError(st.degraded_reason || '')
  $('degradedDesc').textContent = t('degradedDesc', { listen: st.listen || currentListen }) + (reason ? ' ' + t('degradedReason', { reason }) : '')
}

// 把引擎的英文错误翻成用户能照着做的说明；其余错误原样显示
function friendlyConnectError(raw) {
  if (!raw) return raw
  if (raw.includes('wintun.dll')) return t('errNoWintunDll') // 缺少或无法加载 wintun.dll
  if (raw.includes('not elevated')) return t('errNeedAdmin') // 没有管理员权限
  if (raw.includes('create wintun adapter')) return t('errTunCreate') // 驱动层创建失败
  return raw
}

// 国内直连卡片：规则条数、最近一次更新时间、失败原因
function agoText(sec) {
  if (sec < 60) return t('agoJustNow')
  if (sec < 3600) return t('agoMin', { n: Math.floor(sec / 60) })
  if (sec < 86400) return t('agoHour', { n: Math.floor(sec / 3600) })
  return t('agoDay', { n: Math.floor(sec / 86400) })
}

function geoErrText(raw) {
  if (!raw) return ''
  if (raw.includes('no geodata source')) return t('geoNoNode')
  if (raw.includes('already in progress')) return t('geoBusy')
  return raw.length > 90 ? raw.slice(0, 90) + '…' : raw
}

function paintGeo(st) {
  if ($('geoRuleCount')) {
    $('geoRuleCount').textContent = st.geo_rule_count ? t('rulesCount', { count: st.geo_rule_count.toLocaleString() }) : '—'
  }
  const line = $('geoStatusLine')
  if (!line) return
  // “订阅里还没有节点”不是故障：全新安装时显示中性提示，载入订阅后自动下载
  const noNode = !!st.geo_error && st.geo_error.includes('no geodata source')
  const err = noNode ? '' : geoErrText(st.geo_error)
  let text
  if (noNode && !st.geo_updated_at) {
    text = t('geoWaitSub')
  } else if (st.geo_updated_at) {
    text = t('geoUpdatedAgo', { ago: agoText(Math.max(0, Math.floor(Date.now() / 1000) - st.geo_updated_at)) })
    if (err) text += ' · ' + t('geoSyncFailed', { err })
  } else {
    text = err ? t('geoSyncFailed', { err }) : t('geoBuiltinOnly')
  }
  line.textContent = text
  line.classList.toggle('err', !!err)
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

// 第三方 TUN 冲突：只警告，请用户先退出对方的 TUN；不提供“忽略并继续”（两个 TUN 无法同时工作）
function showTunConflictModal(vpnName) {
  const modal = $('tunConflictModal')
  if (!modal) return
  const desc = $('tunConflictModalDesc')
  if (desc) {
    desc.textContent = t('tunConflictDesc', { name: vpnName || t('thirdPartyVPN') })
  }
  modal.hidden = false
  const ok = $('btnTunConflictOk')
  if (ok) {
    ok.onclick = () => {
      modal.hidden = true
      msg(t('closeThirdPartyTunHint'), 'info')
    }
    ok.focus()
  }
}

// restoreSavedSub 把客户端保存的订阅地址填回输入框（有保存值时优先于 localStorage）。
async function restoreSavedSub() {
  try {
    const r = await api('GET', '/api/v1/subscription')
    if (r && typeof r.sub === 'string' && r.sub) {
      $('subUrl').value = r.sub
      try { localStorage.setItem(SUB_KEY, r.sub) } catch {}
    }
  } catch {}
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

    await doActualImport(sub)   // 导入订阅不碰网卡，不受 TUN 冲突影响
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
    switchTab('settings')
    $('tabSubManual')?.click()
    $('subUrl')?.focus()
    return
  }
  if (selectedMode() === 'tun') {
    const vpn = await checkUpfrontTUNConflict()
    if (vpn) {
      showTunConflictModal(vpn)
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
    // reuse：启动界面时已导入过同一订阅的话直接复用，不再为点连接多等一次网络往返（到节点的新 TCP 连接偶尔首包丢失）
    const imp = await api('POST', '/api/v1/import', { sub, reuse: true })
    if (imp && (imp.status === 'error' || imp.error)) throw new Error(imp.error || 'import')
    fetchNodes()
    
    // 2. 设定工作模式
    const mode = selectedMode()
    const md = await api('POST', '/api/v1/mode', { mode })
    if (md && md.code === 'CONFLICT_TUN') {
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
    doProbe()
    await refreshStatus()
    setState('on', t('connected'))
    msg(t('connectedAs') + ' · ' + modeLabel(effectiveMode), 'ok')
  } catch (e) {
    if (e.code === 'CONFLICT_TUN') {
      handleTUNConflict(e.vpn || '')
    } else if (e.code === 'UDP_UNAVAILABLE' || (e.message && e.message.includes('UDP_UNAVAILABLE'))) {
      handleUDPUnavailable(e.message)
    } else {
      setState('err', t('ready'))
      const em = e.message || String(e)
      msg(em === 'connect' ? t('connFailed') : friendlyConnectError(em), 'err')
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
      doProbe()
      await refreshStatus()
      setState('on', t('connected'))
      msg(t('connectedAs') + ' · ' + modeLabel(effectiveMode), 'ok')
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
      msg(friendlyConnectError(st.last_error), 'err')
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
      const detail = st && st.last_error ? ` (${friendlyConnectError(st.last_error)})` : ''
      msg((t('connTimeout') || '连接超时，请重试') + detail, 'err')
      return
    }
  }
}

async function onDisconnect() {
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
  switchTab('home')
  showTunConflictModal(vpnName)
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
  const text = currentListen
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => msg(t('copied', { addr: text }), 'ok')).catch(() => copyDesktopFallback(text))
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
    msg(t('copied', { addr: text }), 'ok')
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

// camErrorKey 把 getUserMedia 的错误归为界面文案：系统/浏览器拒绝、没有相机、相机被占用，其余用通用提示。
function camErrorKey(e) {
  switch (e && e.name) {
    case 'NotAllowedError':
    case 'SecurityError':
      return 'camDenied'
    case 'NotFoundError':
    case 'OverconstrainedError':
      return 'camNone'
    case 'NotReadableError':
    case 'AbortError':
      return 'camBusy'
    default:
      return 'camFail'
  }
}

async function openCamera() {
  msg('')
  const v = $('cam')
  // 不是安全上下文（例如用 NavigateToString 加载的页面）时，navigator.mediaDevices 不存在，没法调相机
  if (!navigator.mediaDevices || typeof navigator.mediaDevices.getUserMedia !== 'function') {
    msg(t('camNoApi'), 'err')
    return
  }
  try {
    try {
      // 手机优先后置；桌面没有后置摄像头时 ideal 约束也能满足，不会报错
      camStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: 'environment' } } })
    } catch (e) {
      // 约束不满足时退回任意摄像头；权限被拒绝等其他错误直接抛出
      if (e && (e.name === 'OverconstrainedError' || e.name === 'NotFoundError')) {
        camStream = await navigator.mediaDevices.getUserMedia({ video: true })
      } else {
        throw e
      }
    }
    v.srcObject = camStream
    v.classList.add('on')
    await v.play()
    scanLoop()
  } catch (e) {
    stopCamera()
    const detail = e && e.name ? ' (' + e.name + ')' : ''
    msg(t(camErrorKey(e)) + detail, 'err')
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
    updateOnboard(null)
    switchTab('home')
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

function getNodeBadges(node) {
  if (Array.isArray(node.badges) && node.badges.length > 0) {
    return node.badges
  }
  const list = []
  const name = node.name || ''
  let country = (node.country || '').toUpperCase()
  if (!country) {
    if (/US|美国|🇺🇸/i.test(name)) country = 'US'
    else if (/HK|香港|🇭🇰/i.test(name)) country = 'HK'
    else if (/JP|日本|🇯🇵/i.test(name)) country = 'JP'
    else if (/SG|新加坡|🇸🇬/i.test(name)) country = 'SG'
    else if (/TW|台湾|🇹🇼/i.test(name)) country = 'TW'
    else if (/KR|韩国|🇰🇷/i.test(name)) country = 'KR'
    else if (/UK|GB|英国|🇬🇧/i.test(name)) country = 'UK'
    else if (/DE|德国|🇩🇪/i.test(name)) country = 'DE'
  }
  if (country === 'US') list.push('[🇺🇸 原生]')
  else if (country === 'HK') list.push('[🇭🇰 原生]')
  else if (country === 'JP') list.push('[🇯🇵 原生]')
  else if (country === 'SG') list.push('[🇸🇬 原生]')
  else if (country === 'TW') list.push('[🇹🇼 原生]')
  else if (country === 'KR') list.push('[🇰🇷 原生]')
  else if (country === 'UK') list.push('[🇬🇧 原生]')
  else if (country === 'DE') list.push('[🇩🇪 原生]')
  else if (country) list.push(`[${country} 原生]`)

  const purity = typeof node.purity_score === 'number' ? node.purity_score : (node.purityScore || 0)
  const aiBlocked = !!(node.ai_blocked || node.aiBlocked)
  const tagGemini = (Array.isArray(node.tags) && node.tags.some(t => /gemini/i.test(t))) || /gemini/i.test(name)
  if (tagGemini || (!aiBlocked && purity >= 80)) {
    list.push('[✨ Gemini 解锁]')
  }

  const warp = !!(node.warp_active || node.warpActive || (Array.isArray(node.tags) && node.tags.some(t => /warp/i.test(t))) || /warp/i.test(name))
  if (warp) {
    list.push('[🛡️ WARP 接管]')
  }
  return list
}

function renderNodes(nodes) {
  const container = $('nodesList')
  const badge = $('nodesCountBadge')
  if (!container) return
  if (!nodes || nodes.length === 0) {
    container.innerHTML = '<div class="empty-nodes">' + (currentNodes.length > 0 ? t('noMatchNodes') : t('emptyNodes')) + '</div>'
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

    // Feature 20: 渲染 [🇺🇸 原生] [✨ Gemini 解锁] [🛡️ WARP 接管] 徽章
    const badges = getNodeBadges(n)
    badges.forEach((b) => {
      const bSpan = document.createElement('span')
      let bClass = 'badge-default'
      if (b.includes('原生')) {
        bClass = 'badge-native'
      } else if (b.includes('Gemini') || b.includes('解锁')) {
        bClass = 'badge-gemini'
      } else if (b.includes('WARP') || b.includes('接管')) {
        bClass = 'badge-warp'
      }
      bSpan.className = 'node-badge ' + bClass
      bSpan.textContent = b
      nameRow.appendChild(bSpan)
    })
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

// 视图切换：home | nodes | settings
function switchTab(name) {
  const id = 'view' + name.charAt(0).toUpperCase() + name.slice(1)
  document.querySelectorAll('.view').forEach((v) => v.classList.toggle('active', v.id === id))
  document.querySelectorAll('.tabbar-btn').forEach((b) => b.classList.toggle('active', b.getAttribute('data-tab') === name))
  const views = document.querySelector('.views')
  if (views) views.scrollTop = 0
}

// 链式代理的详细配置在“线路”页；主页的开关行与未配置时的开关都跳到这里
function openChainConfig() {
  switchTab('nodes')
  const card = $('chainProxyCard')
  if (card) card.scrollIntoView({ block: 'start' })
}

// 首次使用引导：没有订阅（无链接、无节点、未连接）时，主页顶部显示提示卡；连接按钮始终可见
function updateOnboard(st) {
  const subEl = $('subUrl')
  const has = !!((st && (st.sub_url || st.connected)) || (subEl && subEl.value.trim()) || currentNodes.length > 0)
  if ($('onboard')) $('onboard').hidden = has
}

// 主页“链式代理”行的摘要：未配置 / 协议 主机:端口
function updateChainSummary() {
  const el = $('chainSummary')
  if (!el) return
  const host = ($('chainHostInput') && $('chainHostInput').value || '').trim()
  const port = ($('chainPortInput') && $('chainPortInput').value || '').trim()
  const proto = $('chainProtoSelect') ? $('chainProtoSelect').value : 'socks5'
  el.textContent = host && port ? proto + ' ' + host + ':' + port : t('chainNotSet')
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

  // 底部标签栏与首次引导按钮
  document.querySelectorAll('.tabbar-btn').forEach((b) => {
    b.addEventListener('click', () => switchTab(b.getAttribute('data-tab')))
  })
  $('btnOnboardSub')?.addEventListener('click', () => {
    switchTab('settings')
    $('tabSubManual')?.click()
    $('subUrl')?.focus()
  })
  $('btnOnboardLogin')?.addEventListener('click', () => {
    switchTab('settings')
    $('tabAuthLogin')?.click()
    $('loginUsername')?.focus()
  })

  // 2. 账号登录操作
  $('btnDoLogin')?.addEventListener('click', doClientLogin)
  $('btnClientLogout')?.addEventListener('click', doClientLogout)

  // 3. 手动载入专属订阅 (严格前置校验，空值抛错，载入后立即全量刷新节点列表与状态)
  $('btnApplyManualSub')?.addEventListener('click', async () => {
    const btn = $('btnApplyManualSub')
    const origText = btn ? btn.textContent : t('load')
    let timer = null
    if (btn) {
      btn.disabled = true
      btn.textContent = t('loading')
      timer = setTimeout(() => {
        if (btn && btn.disabled) {
          btn.textContent = '匹配端口中...'
        }
      }, 400)
    }
    try {
      await ensureImported(true)
      await refreshStatus()
      msg(t('subLoadedOk'), 'ok')
      updateOnboard(null)
      switchTab('home')
    } catch (e) {
      msg(e.message, 'err')
    } finally {
      if (timer) clearTimeout(timer)
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

  // 旧版本保存过模式选择：已取消，清掉
  try { localStorage.removeItem(MODE_KEY) } catch {}

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
          msg(res.updated ? t('geoUpdatedNow', { count: (res.count || 0).toLocaleString() }) : t('geoUpToDate'), 'ok')
        } else {
          msg(t('geoSyncFailed', { err: geoErrText((res && res.error) || '') }), 'err')
        }
      } catch (e) {
        msg(t('geoSyncFailed', { err: geoErrText(e.message || String(e)) }), 'err')
      }
      $('btnSyncGeo').disabled = false
      $('btnSyncGeo').textContent = t('sync')
      refreshStatus()
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

  // 链式代理：主页只放开关，详细配置在“线路”页
  document.querySelectorAll('.js-chain-open').forEach((el) => el.addEventListener('click', openChainConfig))

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
        updateChainSummary()
      }
    } catch {}
  }

  // 按表单当前值保存链式配置；enabled 由开关决定。成功返回 true。
  async function saveChain(enabled) {
    const payload = {
      enabled,
      protocol: $('chainProtoSelect') ? $('chainProtoSelect').value : 'socks5',
      host: $('chainHostInput') ? $('chainHostInput').value.trim() : '',
      port: $('chainPortInput') ? parseInt($('chainPortInput').value.trim(), 10) || 0 : 0,
      username: $('chainUserInput') ? $('chainUserInput').value.trim() : '',
      password: $('chainPassInput') ? $('chainPassInput').value : ''
    }
    try {
      const res = await api('POST', '/api/v1/chain/config', payload)
      if (res && res.status === 'ok') {
        updateChainSummary()
        msg(t('chainSaveOk'), 'ok')
        return true
      }
      msg((res && res.error) || 'save failed', 'err')
    } catch (e) {
      msg(e.message || String(e), 'err')
    }
    return false
  }

  if ($('btnSaveChainProxy')) {
    $('btnSaveChainProxy').onclick = () => saveChain($('chainEnableToggle') ? $('chainEnableToggle').checked : false)
  }

  // 主页开关：开启前必须已填地址与端口（服务端不校验），否则回弹并跳到线路页的配置卡；保存失败也回弹
  if ($('chainEnableToggle')) {
    $('chainEnableToggle').addEventListener('change', async () => {
      const sw = $('chainEnableToggle')
      const want = sw.checked
      const host = ($('chainHostInput').value || '').trim()
      const port = parseInt(($('chainPortInput').value || '').trim(), 10) || 0
      if (want && (!host || port <= 0 || port > 65535)) {
        sw.checked = false
        msg(t('chainNeedConfig'), 'err')
        openChainConfig()
        $('chainHostInput')?.focus()
        return
      }
      if (!(await saveChain(want))) sw.checked = !want
    })
  }

  loadChainProxyUI()

  fetchNodes()
  setInterval(refreshStatus, 2000)
  refreshStatus()
  // 订阅地址以客户端保存在数据目录里的为准（Windows 的 WebView2 把 localStorage 放在退出即删的临时目录，不跨启动保留）
  restoreSavedSub().then(() => ensureImported(false)).then(() => fetchNodes()).catch(() => {})
}

init()
