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
  if (mode === 'sysproxy') return 'sysproxy'
  return 'tun' // 默认 TUN 全局模式 (零改动系统注册表)
}

function modeLabel(mode) {
  const m = productMode(mode)
  if (m === 'sysproxy') return '系统代理模式'
  return 'TUN 全局模式'
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
  if (cur === 'tun') tip.textContent = t('tipTun') || 'TUN 虚拟网卡驱动接管全局流量 (零改动系统注册表)'
  else if (cur === 'sysproxy') tip.textContent = t('tipSys') || '本地 55555，供指纹浏览器填写，不改宿主机'
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
    if ($('stISP')) $('stISP').textContent = st.isp_name || st.isp || '—'
    if ($('stSNI')) $('stSNI').textContent = st.sni || '—'
    if ($('stListen')) $('stListen').textContent = st.listen || DEFAULT_LISTEN
    let rtt = st.rtt_ms
    if (!rtt && st.nodes && st.nodes.length) {
      const n = st.nodes.find((x) => x.active) || st.nodes.find((x) => x.reachable)
      if (n && n.rtt_ms) rtt = n.rtt_ms
    }
    if ($('stRtt')) $('stRtt').textContent = rtt ? rtt + ' ms' : on ? '…' : '—'
    if ($('geoRuleCount') && st.geo_rule_count) {
      $('geoRuleCount').textContent = st.geo_rule_count.toLocaleString() + ' 条 (已就绪)'
    }
    if (st.sub_url && !$('subUrl').value) $('subUrl').value = st.sub_url
    if (st.probe_ok === true || st.probe_ok === false) {
      applyProbe({ ok: st.probe_ok, ms: st.probe_ms })
    }
    if (!on && !busy) applyProbe(null)
  } catch {
    if (!busy) setState('off', t('ready'))
  }
}

async function ensureImported(strict = false) {
  if (isImporting) return
  isImporting = true
  try {
    const sub = ($('subUrl').value || '').trim()
    if (!sub) {
      if (strict) {
        msg('请先粘贴或输入专属订阅链接，输入不能为空！', 'err')
        throw new Error('请先粘贴或输入专属订阅链接，输入不能为空！')
      }
      return
    }
    if (!sub.startsWith('http://') && !sub.startsWith('https://')) {
      if (strict) {
        msg('订阅链接格式错误，必须以 http:// 或 https:// 开头！', 'err')
        throw new Error('订阅链接格式错误，必须以 http:// 或 https:// 开头！')
      }
      return
    }
    try {
      localStorage.setItem(SUB_KEY, sub)
    } catch {}
    const imp = await api('POST', '/api/v1/import', { sub })
    if (imp && (imp.status === 'error' || imp.error)) throw new Error(imp.error || 'import')
  } finally {
    isImporting = false
  }
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
    // 1. 导入订阅并解析服务器与 Token
    const imp = await api('POST', '/api/v1/import', { sub })
    if (imp && (imp.status === 'error' || imp.error)) throw new Error(imp.error || 'import')
    
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
      throw new Error(md.error || 'mode')
    }

    // 3. 建立秒级快速隧道连接
    const c = await api('POST', '/api/v1/connect')
    if (c && c.code === 'CONFLICT_TUN') {
      handleTUNConflict(c.vpn || '')
      return
    }
    if (c && (c.code === 'UDP_UNAVAILABLE' || c.error === 'UDP_UNAVAILABLE')) {
      handleUDPUnavailable(c.msg || '')
      return
    }
    if (c && (c.status === 'error' || c.error)) {
      throw new Error(c.error || 'connect')
    }

    // 4. 异步快速探测探针
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
      msg(e.message || String(e), 'err')
    }
  } finally {
    busy = false
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
  setState('off', 'UDP 不可用')
  msg(customMsg || 'UDP/443 (QUIC) 不可用，已降级防御：未开启全局 TUN，55555 代理监听中', 'err')
}

function handleTUNConflict(vpnName) {
  msg('') // 彻底清空「连接中…」残留
  setState('off', t('ready'))
  const box = $('conflictBox')
  if (box) {
    box.hidden = false
    const desc = $('conflictDesc')
    if (desc) {
      desc.textContent = (t('conflictDesc') || '检测到正在运行其他 VPN 的 TUN 模式【{name}】。两款 TUN 无法同时生效。').replace('{name}', vpnName || '第三方 VPN')
    }
  }
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
    msg('请填写中台服务地址 (如 https://myconsun.de5.net)', 'err')
    return
  }
  if (!username || !password) {
    msg('请填写中台用户名和密码', 'err')
    return
  }
  msg('正在向中台登录并同步专属订阅...', 'wait')
  try {
    try { localStorage.setItem('aero_mid_server', server) } catch {}
    const res = await fetch(`${server}/api/v1/auth/login/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, portal: 'client' })
    })
    const data = await res.json().catch(() => ({}))
    if (!res.ok || data.code !== 0) {
      throw new Error(data.message || '登录鉴权失败，请检查账号密码')
    }
    const u = data.data || data
    try {
      localStorage.setItem('aero_client_user', JSON.stringify({ server, username, user: u }))
    } catch {}
    renderLoggedInUser(server, u)
    msg('登录成功！已自动同步并就绪专属订阅', 'ok')
  } catch (e) {
    msg(`登录失败: ${e.message}`, 'err')
  }
}

function renderLoggedInUser(server, user) {
  if ($('loginFormWrap')) $('loginFormWrap').style.display = 'none'
  if ($('loggedInWrap')) $('loggedInWrap').style.display = 'block'
  if ($('userDisplayName')) $('userDisplayName').textContent = user.username || '用户'
  if ($('userAvatar')) $('userAvatar').textContent = (user.username || 'A')[0].toUpperCase()
  if ($('userPlanBadge')) $('userPlanBadge').textContent = user.is_staff ? '系统管理' : (user.plan_name || '月度套餐')
  if ($('userServerHost')) $('userServerHost').textContent = server.replace(/^https?:\/\//, '')

  const sel = $('userSubSelect')
  if (!sel) return
  sel.innerHTML = ''

  const subs = user.subscriptions || []
  if (subs.length === 0) {
    const slug = user.sub_slug || 'superadmin'
    const opt = document.createElement('option')
    opt.value = `${server}/sub/${slug}`
    opt.textContent = `默认专属订阅 (${slug})`
    sel.appendChild(opt)
  } else {
    subs.forEach((s) => {
      const opt = document.createElement('option')
      opt.value = `${server}/sub/${s.sub_slug}`
      opt.textContent = `${s.plan_name || '套餐'} (${s.sub_slug})`
      sel.appendChild(opt)
    })
  }

  if ($('subCountBadge')) {
    $('subCountBadge').textContent = `${sel.options.length} 个可用`
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
      msg(`已切换专属订阅: ${sel.options[sel.selectedIndex].text}`, 'ok')
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
  msg('已退出账号登录')
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
    const origText = btn ? btn.textContent : '载入'
    if (btn) {
      btn.disabled = true
      btn.textContent = '载入中...'
    }
    try {
      await ensureImported(true)
      await refreshStatus()
      msg('专属订阅已成功载入！节点已就绪', 'ok')
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
          msg(t('connectedAs') + ' · ' + modeLabel(targetMode), 'ok')
          await refreshStatus()
        } catch (err) {
          setModeUI(prevMode)
          msg(err.message || String(err), 'err')
          await refreshStatus()
        } finally {
          busy = false
        }
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

  if ($('btnPing')) {
    $('btnPing').onclick = async () => {
      $('btnPing').disabled = true
      $('btnPing').textContent = '⚡ 测速中'
      try {
        const res = await api('POST', '/api/v1/ping')
        if (res && res.status === 'ok') {
          if ($('stRtt')) $('stRtt').textContent = res.rtt_ms + ' ms'
        }
      } catch {}
      $('btnPing').disabled = false
      $('btnPing').textContent = '⚡ 测速'
    }
  }

  if ($('btnSyncGeo')) {
    $('btnSyncGeo').onclick = async () => {
      $('btnSyncGeo').disabled = true
      $('btnSyncGeo').textContent = '🔄 同步中'
      try {
        const res = await api('POST', '/api/v1/geodata/sync')
        if (res && res.status === 'ok') {
          if ($('geoRuleCount')) $('geoRuleCount').textContent = res.count.toLocaleString() + ' 条 (已同步)'
        }
      } catch {}
      $('btnSyncGeo').disabled = false
      $('btnSyncGeo').textContent = '🔄 同步'
    }
  }

  if ($('btnSwitchSysproxy')) {
    $('btnSwitchSysproxy').onclick = async () => {
      hideConflictBox()
      setModeUI('sysproxy')
      busy = true
      setState('wait', t('connecting'))
      msg(t('connecting'))
      try {
        const md = await api('POST', '/api/v1/mode', { mode: 'sysproxy' })
        if (md && (md.status === 'error' || md.error)) throw new Error(md.error || 'mode')
        const c = await api('POST', '/api/v1/connect')
        if (c && (c.status === 'error' || c.error)) throw new Error(c.error || 'connect')
        doProbe()
        await refreshStatus()
        setState('on', t('connected'))
        msg(t('connectedAs') + ' · ' + modeLabel('sysproxy'), 'ok')
      } catch (e) {
        setState('err', t('ready'))
        msg(e.message || String(e), 'err')
      } finally {
        busy = false
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

  setInterval(refreshStatus, 2000)
  refreshStatus()
  ensureImported(false).catch(() => {})
}

init()
