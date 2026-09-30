// AERO Console Native Application Script
const $ = (id) => document.getElementById(id);

const TOKEN_KEY = 'aerosys_admin_token';
let currentVpsId = '';
let activeTaskId = null;
let taskPollTimer = null;

function getToken() {
  const urlParams = new URLSearchParams(window.location.search);
  const qToken = urlParams.get('token');
  if (qToken) {
    try { localStorage.setItem(TOKEN_KEY, qToken); } catch (_) {}
    return qToken;
  }
  let tok = '';
  try { tok = localStorage.getItem(TOKEN_KEY); } catch (_) {}
  if (!tok) {
    try {
      if (window.parent && window.parent !== window && window.parent.localStorage) {
        tok = window.parent.localStorage.getItem(TOKEN_KEY);
        if (tok) localStorage.setItem(TOKEN_KEY, tok);
      }
    } catch (_) {}
  }
  return tok || '';
}

async function request(url, options = {}) {
  const token = getToken();
  const headers = Object.assign({}, options.headers || {});
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  if (!headers['Content-Type'] && options.body) {
    headers['Content-Type'] = 'application/json';
  }
  try {
    const res = await fetch(url, Object.assign({}, options, { headers }));
    const data = await res.json();
    if (data && typeof data === 'object' && 'code' in data && data.code !== 0) {
      throw new Error(data.message || `API Code ${data.code}`);
    }
    return data.data !== undefined ? data.data : data;
  } catch (err) {
    console.warn('Request failed:', url, err);
    throw err;
  }
}

window.addEventListener('DOMContentLoaded', async () => {
  initEvents();
  await loadSourceStatus();
  await loadVpsList();
  await loadTasks();
  if (currentVpsId) {
    await loadVpsDiagnose(currentVpsId);
  }
});

function initEvents() {
  $('btnRefresh')?.addEventListener('click', async () => {
    const btn = $('btnRefresh');
    btn.disabled = true;
    btn.textContent = '🔄 诊断探测中...';
    try {
      await loadSourceStatus();
      await loadTasks();
      if (currentVpsId) {
        await loadVpsDiagnose(currentVpsId);
      }
      btn.textContent = '✓ 诊断完成';
    } catch (e) {
      btn.textContent = '⚠️ 诊断失败';
    } finally {
      setTimeout(() => {
        btn.textContent = '🔄 全面诊断';
        btn.disabled = false;
      }, 1000);
    }
  });

  $('btnTestConn')?.addEventListener('click', async () => {
    const btn = $('btnTestConn');
    btn.disabled = true;
    btn.textContent = '探测中...';
    try {
      if (currentVpsId) await loadVpsDiagnose(currentVpsId);
      btn.textContent = '✓ 完成';
    } catch (e) {
      btn.textContent = '失败';
    } finally {
      setTimeout(() => {
        btn.textContent = '重测连通';
        btn.disabled = false;
      }, 1000);
    }
  });

  $('vpsSelect')?.addEventListener('change', async (e) => {
    currentVpsId = e.target.value;
    await loadTasks();
    if (currentVpsId) {
      await loadVpsDiagnose(currentVpsId);
    }
  });

  $('btnRestart')?.addEventListener('click', async () => {
    if (!currentVpsId) return alert('请先选择目标 VPS');
    try {
      await request(`/api/v1/aero/vps/${currentVpsId}/restart/`, { method: 'POST' });
      alert('已触发重启 Edge 容器');
      loadVpsDiagnose(currentVpsId);
    } catch (e) {
      alert(`重启失败: ${e.message}`);
    }
  });

  $('btnInstall')?.addEventListener('click', async () => {
    if (!currentVpsId) return alert('请先选择目标 VPS');
    const vpsNum = parseInt(currentVpsId, 10);
    if (!vpsNum) return alert('无效的 VPS ID');
    try {
      const task = await request('/api/v1/aero/install/', {
        method: 'POST',
        body: JSON.stringify({ vps_id: vpsNum })
      });
      if (task && task.id) {
        openTaskDrawer(task.id);
      }
      loadTasks();
    } catch (e) {
      alert(`安装升级任务启动失败: ${e.message}`);
    }
  });

  $('btnUninstall')?.addEventListener('click', async () => {
    if (!currentVpsId) return alert('请先选择目标 VPS');
    if (!confirm('确认卸载该节点上的 AERO Edge 服务？')) return;
    const vpsNum = parseInt(currentVpsId, 10);
    if (!vpsNum) return alert('无效的 VPS ID');
    try {
      const task = await request('/api/v1/aero/uninstall/', {
        method: 'POST',
        body: JSON.stringify({ vps_id: vpsNum })
      });
      if (task && task.id) {
        openTaskDrawer(task.id);
      }
      loadTasks();
    } catch (e) {
      alert(`卸载任务启动失败: ${e.message}`);
    }
  });

  $('btnCopySub')?.addEventListener('click', () => {
    const text = $('subUrlBox')?.textContent?.trim();
    if (!text || text.includes('请选择')) return;
    navigator.clipboard.writeText(text).then(() => {
      const btn = $('btnCopySub');
      const old = btn.textContent;
      btn.textContent = '✓ 已复制';
      setTimeout(() => { btn.textContent = old; }, 1500);
    });
  });

  // Modal events
  $('btnOpenAddToken')?.addEventListener('click', () => {
    $('tokenModal')?.classList.add('active');
  });
  $('btnCancelToken')?.addEventListener('click', () => {
    $('tokenModal')?.classList.remove('active');
  });
  $('btnSaveToken')?.addEventListener('click', async () => {
    if (!currentVpsId) return alert('请先选择目标 VPS');
    const tokenVal = $('newTokenVal').value.trim();
    const labelVal = $('newTokenLabel').value.trim();
    const ttlVal = parseInt($('newTokenTTL').value, 10) || 0;

    try {
      await request(`/api/v1/aero/vps/${currentVpsId}/tokens/`, {
        method: 'POST',
        body: JSON.stringify({
          token: tokenVal,
          label: labelVal || '客户端设备',
          ttl_hours: ttlVal
        })
      });
      $('tokenModal')?.classList.remove('active');
      $('newTokenVal').value = '';
      $('newTokenLabel').value = '';
      $('newTokenTTL').value = '0';
      await loadTokens(currentVpsId);
    } catch (e) {
      alert(`保存 Token 失败: ${e.message}`);
    }
  });

  $('btnCloseTaskDrawer')?.addEventListener('click', () => {
    closeTaskDrawer();
  });
}

async function loadSourceStatus() {
  try {
    const src = await request('/api/v1/aero/source-status/');
    const alertEl = $('sourceAlert');
    const textEl = $('sourceAlertText');
    if (!src || !src.has_source) {
      if (alertEl) alertEl.style.display = 'flex';
      if (textEl) textEl.textContent = `【官方源提示】检测到 GitHub 官方源（${src?.repo || 'jackybig999/aero'}）尚未发布 Release 包。系统严禁本地私拷分发，请先向 GitHub 推送 Release。点击【安装/升级】可执行前置流水线。`;
    } else {
      if (alertEl) alertEl.style.display = 'none';
    }
  } catch (e) {
    console.warn('Load source status failed:', e);
  }
}

async function loadVpsList() {
  try {
    const res = await request('/api/v1/aero/vps-options/');
    const list = Array.isArray(res) ? res : (res?.results || (res?.data && Array.isArray(res.data) ? res.data : []));
    const sel = $('vpsSelect');
    if (!sel) return;
    sel.innerHTML = '';
    if (!list || list.length === 0) {
      const opt = document.createElement('option');
      opt.value = '';
      opt.textContent = '暂无 VPS 节点，请在中台 VPS 栏目添加';
      sel.appendChild(opt);
      return;
    }
    list.forEach((vps, idx) => {
      const opt = document.createElement('option');
      opt.value = vps.id || vps.vps_id;
      opt.textContent = `${vps.name} (${vps.ip}${vps.domain ? ' · ' + vps.domain : ''})`;
      if (idx === 0 && !currentVpsId) {
        currentVpsId = String(opt.value);
        opt.selected = true;
      } else if (currentVpsId && String(opt.value) === String(currentVpsId)) {
        opt.selected = true;
      }
      sel.appendChild(opt);
    });
  } catch (e) {
    console.warn('Load VPS list failed:', e);
  }
}

async function loadVpsDiagnose(vpsId) {
  if (!vpsId) return;
  try {
    const diag = await request(`/api/v1/aero/vps/${vpsId}/diagnose/`);
    renderDiagnose(diag);
    await loadTokens(vpsId);
  } catch (e) {
    console.warn('Load diagnose failed:', e);
    renderDiagnoseError(e);
  }
}

function renderDiagnose(d) {
  if (!d) return;

  const isInstalled = d.installed !== false;
  if (!isInstalled) {
    $('kpiOverall').innerHTML = '<span class="tag tag-amber">已卸载</span>';
    $('kpiService').innerHTML = '<span class="tag tag-amber">UNINSTALLED</span>';
    $('kpiPort443').innerHTML = '<span class="tag tag-amber">CLOSED</span>';
    $('kpiCert').innerHTML = '<span class="tag tag-amber" title="未部署">未部署</span>';
    $('kpiSubLocal').innerHTML = '<span class="tag tag-amber">未部署</span>';
    $('kpiSubPublic').innerHTML = '<span class="tag tag-amber">未部署</span>';
  } else {
    const isUp = d.service?.active || d.ok;
    $('kpiOverall').innerHTML = isUp ? '<span class="tag tag-green">可运维</span>' : '<span class="tag tag-red">异常</span>';
    $('kpiService').innerHTML = d.service?.active ? '<span class="tag tag-green">ACTIVE</span>' : '<span class="tag tag-amber">' + (d.service?.status || 'INACTIVE').toUpperCase() + '</span>';

    const p443 = d.ports?.find(p => p.port === 443 && p.listen);
    $('kpiPort443').innerHTML = p443 ? '<span class="tag tag-green">LISTEN</span>' : '<span class="tag tag-amber">CLOSED</span>';

    const certOk = d.cert?.ok;
    const certDetail = d.cert?.detail || (certOk ? '正常' : '待签发');
    $('kpiCert').innerHTML = certOk ? `<span class="tag tag-green" title="${certDetail}">正常</span>` : `<span class="tag tag-amber" title="${certDetail}">待签发</span>`;

    $('kpiSubLocal').innerHTML = d.subscription?.local_ok ? '<span class="tag tag-green">可达</span>' : '<span class="tag tag-red">失败</span>';
    $('kpiSubPublic').innerHTML = d.subscription?.public_ok ? '<span class="tag tag-green">可达</span>' : '<span class="tag tag-amber">待确认</span>';
  }

  // 节点表格
  const nodesBody = $('nodesTableBody');
  if (nodesBody) {
    if (d.nodes && d.nodes.length) {
      nodesBody.innerHTML = d.nodes.map(n => `
        <tr>
          <td><span class="tag ${n.online ? 'tag-green' : (isInstalled ? 'tag-red' : 'tag-amber')}">${n.online ? '通' : (isInstalled ? '断' : '未部署')}</span></td>
          <td><b>${escapeHtml(n.name)}</b></td>
          <td><span class="tag tag-blue">${escapeHtml(n.kind || 'aero')}</span></td>
          <td class="mono" style="font-size:11px">${escapeHtml(n.detail || n.target || '—')}</td>
        </tr>
      `).join('');
    } else {
      nodesBody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--muted);padding:14px">暂无协议节点</td></tr>';
    }
  }

  // 端口标签与进程透视
  const portsRow = $('portsRow');
  if (portsRow && d.ports) {
    portsRow.innerHTML = d.ports.map(p => {
      let procInfo = p.proc ? ` · [占用:${escapeHtml(p.proc)}]` : '';
      let tagClass = p.listen ? 'tag-green' : 'tag-blue';
      if (p.port === 443 && p.proc && p.proc !== 'aero-edge' && p.proc !== 'aero') {
        tagClass = 'tag-amber'; // 第三方占用，醒目标记
      }
      return `<span class="tag ${tagClass}" style="font-size:11px">
        ${p.port}/${p.proto} · ${p.role}${procInfo} · ${p.listen ? 'LISTEN' : 'CLOSED'}
      </span>`;
    }).join('');
  }

  // 日志
  const logBox = $('logBox');
  if (logBox) {
    const certDetail = d.cert?.detail || (d.cert?.ok ? '正常' : '待签发');
    logBox.textContent = d.log_tail || `[系统指标] 诊断途径: ${d.via || 'tls-probe'}\n[网络监听] 端口响应，TLS 状态: ${certDetail}\n[共存策略] 智能端口轮试 (QUIC:443 -> QUIC:8443)，第三方应用和平共存\n[提示] 完整硬件及证书运维请前往中台 VPS 资产列表。`;
  }

  // 专属订阅区 (管理员订阅 + 用户订阅标准格式)
  const domain = d.domain || d.ip;
  const adminSubUrl = (isInstalled && domain) ? `https://${domain}/sub/superadmin` : '—';
  const userSubPattern = (isInstalled && domain) ? `https://${domain}/sub/username{6位随机码}` : '—';
  if ($('subUrlBox')) {
    $('subUrlBox').innerHTML = `
      <div style="margin-bottom:6px"><b>管理员聚合订阅:</b> <span class="mono" style="color:var(--primary)">${adminSubUrl}</span></div>
      <div style="font-size:12px;color:var(--muted)"><b>用户/游客格式:</b> <span class="mono">${userSubPattern}</span> (登录直连免复制，或输入链接即用)</div>
    `;
  }
  if ($('subSecretStatus')) $('subSecretStatus').textContent = isInstalled ? (d.subscription?.secret_set === 'yes' ? '动态票据算法就绪' : '默认就绪') : '未部署';
  if ($('subLocalStatus')) {
    $('subLocalStatus').innerHTML = isInstalled ? (d.subscription?.local_ok ? '<span class="tag tag-green">OK</span>' : '<span class="tag tag-red">FAIL</span>') : '<span class="tag tag-amber">未部署</span>';
  }
  if ($('subPublicStatus')) {
    $('subPublicStatus').innerHTML = isInstalled ? (d.subscription?.public_ok ? '<span class="tag tag-green">OK (直连畅通)</span>' : '<span class="tag tag-amber">不可达 / 超时</span>') : '<span class="tag tag-amber">未部署</span>';
  }
  if ($('subPreview')) $('subPreview').textContent = isInstalled ? (d.subscription?.preview || 'sub://aero-h3-dynamic-quic') : '—';
}

function renderDiagnoseError(e) {
  $('kpiOverall').innerHTML = '<span class="tag tag-red">异常</span>';
  $('kpiService').innerHTML = '<span class="tag tag-red">ERROR</span>';
  $('kpiPort443').innerHTML = '<span class="tag tag-amber">CLOSED</span>';
  $('kpiCert').innerHTML = '<span class="tag tag-amber">未知</span>';
  $('kpiSubLocal').innerHTML = '<span class="tag tag-red">FAIL</span>';
  $('kpiSubPublic').innerHTML = '<span class="tag tag-red">FAIL</span>';
  if ($('logBox')) $('logBox').textContent = `诊断探测失败: ${e.message}\n请核实 VPS IP 及 SSH 端口是否连通。`;
}

async function loadTokens(vpsId) {
  if (!vpsId) return;
  try {
    const res = await request(`/api/v1/aero/vps/${vpsId}/tokens/`);
    const list = res.results || res || [];
    const tbody = $('tokensTableBody');
    if (!tbody) return;
    if (!list.length) {
      tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--muted);padding:14px">暂无 Token 凭据</td></tr>';
      return;
    }
    tbody.innerHTML = list.map(t => `
      <tr>
        <td class="mono">${escapeHtml(t.token_mask || t.token || '—')}</td>
        <td>${escapeHtml(t.label || '默认用户')}</td>
        <td><span class="tag tag-blue">${t.ttl_hours ? t.ttl_hours + '小时' : '永久'}</span></td>
        <td><button class="btn btn-sm btn-danger" onclick="delToken('${escapeHtml(t.token)}')">删</button></td>
      </tr>
    `).join('');
  } catch (e) {
    console.warn('Load tokens failed:', e);
  }
}

async function delToken(token) {
  if (!currentVpsId) return;
  if (!confirm('确认删除该客户端授权 Token？')) return;
  try {
    await request(`/api/v1/aero/vps/${currentVpsId}/tokens/?token=${encodeURIComponent(token)}`, {
      method: 'DELETE'
    });
    await loadTokens(currentVpsId);
  } catch (e) {
    alert(`删除 Token 失败: ${e.message}`);
  }
}
window.delToken = delToken;

// 调度任务管理与抽屉
async function loadTasks() {
  try {
    const list = await request('/api/v1/aero/tasks/');
    const tasks = Array.isArray(list) ? list : (list?.results || []);
    const wrap = $('tasksWrap');
    const tbody = $('tasksTableBody');
    if (!wrap || !tbody) return;

    if (!tasks.length) {
      wrap.style.display = 'none';
      return;
    }

    wrap.style.display = 'block';
    tbody.innerHTML = tasks.slice(0, 5).map(t => `
      <tr style="cursor:pointer" onclick="openTaskDrawer(${t.id})">
        <td class="mono">#${t.id}</td>
        <td><span class="tag tag-blue">${escapeHtml(t.kind)}</span></td>
        <td>${escapeHtml(t.vps_name || ('VPS ' + t.vps_id))}</td>
        <td>
          <div style="display:flex;align-items:center;gap:6px">
            <div style="flex:1;height:4px;background:#090e18;border-radius:2px;overflow:hidden">
              <div style="height:100%;background:var(--blue);width:${t.progress || 0}%"></div>
            </div>
            <span style="font-size:10px;color:var(--muted)">${t.progress || 0}%</span>
          </div>
        </td>
        <td style="color:var(--muted)">${escapeHtml(t.stage || '—')}</td>
        <td>
          <span class="tag ${t.status === 'success' ? 'tag-green' : t.status === 'failed' ? 'tag-red' : 'tag-blue'}">
            ${escapeHtml(t.status)}
          </span>
        </td>
        <td><button class="btn btn-sm" onclick="event.stopPropagation();openTaskDrawer(${t.id})">查看</button></td>
      </tr>
    `).join('');
  } catch (e) {
    console.warn('Load tasks failed:', e);
  }
}

function openTaskDrawer(taskId) {
  activeTaskId = taskId;
  $('taskDrawerModal')?.classList.add('active');
  pollTaskDetail();
  if (taskPollTimer) clearInterval(taskPollTimer);
  taskPollTimer = setInterval(pollTaskDetail, 800);
}
window.openTaskDrawer = openTaskDrawer;

function closeTaskDrawer() {
  $('taskDrawerModal')?.classList.remove('active');
  activeTaskId = null;
  if (taskPollTimer) {
    clearInterval(taskPollTimer);
    taskPollTimer = null;
  }
  loadTasks();
  if (currentVpsId) {
    loadVpsDiagnose(currentVpsId);
  }
}

async function pollTaskDetail() {
  if (!activeTaskId) return;
  try {
    const task = await request(`/api/v1/aero/tasks/${activeTaskId}/`);
    if (!task) return;

    if ($('taskModalTitle')) {
      const tagClass = task.status === 'success' ? 'tag-green' : task.status === 'failed' ? 'tag-red' : 'tag-blue';
      $('taskModalTitle').innerHTML = `<span>🚀 调度流水线详情 #${task.id}</span> <span class="tag ${tagClass}">${task.status.toUpperCase()}</span>`;
    }
    if ($('taskModalSub')) {
      $('taskModalSub').textContent = `类型: ${task.kind} · 目标节点: ${task.vps_name || ('VPS ' + task.vps_id)} · 开始: ${task.created_at || '—'}`;
    }

    if ($('taskProgressStage')) $('taskProgressStage').textContent = `阶段: ${task.stage || '执行中...'}`;
    if ($('taskProgressPercent')) $('taskProgressPercent').textContent = `${task.progress || 0}%`;
    if ($('taskProgressBar')) $('taskProgressBar').style.width = `${task.progress || 0}%`;

    // 渲染步骤
    if (task.steps && task.steps.length) {
      task.steps.forEach(st => {
        const stepEl = $(`step-${st.key}`);
        if (stepEl) {
          stepEl.className = `step-item ${st.status}`;
          let tagType = 'tag-blue';
          let tagLabel = '等待中';
          if (st.status === 'running') { tagType = 'tag-blue'; tagLabel = '进行中...'; }
          else if (st.status === 'success') { tagType = 'tag-green'; tagLabel = '✓ 成功'; }
          else if (st.status === 'failed') { tagType = 'tag-red'; tagLabel = '✕ 失败'; }
          else if (st.status === 'skipped') { tagType = 'tag-amber'; tagLabel = '跳过'; }

          stepEl.innerHTML = `
            <span>${escapeHtml(st.title)} ${st.detail ? `<span style="font-size:11px;color:var(--muted)">(${escapeHtml(st.detail)})</span>` : ''}</span>
            <span class="tag ${tagType}">${tagLabel}</span>
          `;
        }
      });
    }

    // 渲染日志
    const logBox = $('taskLogBox');
    if (logBox) {
      if (task.logs && task.logs.length) {
        logBox.textContent = task.logs.join('\n');
      } else if (task.error) {
        logBox.textContent = `[错误警报] ${task.error}`;
      } else {
        logBox.textContent = '正在等待远端输出...';
      }
      logBox.scrollTop = logBox.scrollHeight;
    }

    if (task.status === 'success' || task.status === 'failed') {
      if (taskPollTimer) {
        clearInterval(taskPollTimer);
        taskPollTimer = null;
      }
      if (task.status === 'success' && currentVpsId) {
        loadVpsDiagnose(currentVpsId);
      }
    }
  } catch (e) {
    console.warn('Poll task detail failed:', e);
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
