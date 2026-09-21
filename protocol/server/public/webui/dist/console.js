// AERO Console Native Application Script
const $ = (id) => document.getElementById(id);

const TOKEN_KEY = 'vpn_admin_token';
let currentVpsId = '';

async function request(url, options = {}) {
  const token = localStorage.getItem(TOKEN_KEY);
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
  if (currentVpsId) {
    await loadVpsDiagnose(currentVpsId);
  }
});

function initEvents() {
  $('btnRefresh')?.addEventListener('click', async () => {
    $('btnRefresh').textContent = '诊断中...';
    await loadSourceStatus();
    if (currentVpsId) {
      await loadVpsDiagnose(currentVpsId);
    }
    $('btnRefresh').textContent = '🔄 全面诊断';
  });

  $('btnTestConn')?.addEventListener('click', async () => {
    if (currentVpsId) await loadVpsDiagnose(currentVpsId);
  });

  $('vpsSelect')?.addEventListener('change', async (e) => {
    currentVpsId = e.target.value;
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
    try {
      await request('/api/v1/aero/install/', {
        method: 'POST',
        body: JSON.stringify({ vps_id: currentVpsId })
      });
      alert('已触发官方源安装/升级任务流水线');
      loadVpsDiagnose(currentVpsId);
    } catch (e) {
      alert(`操作失败: ${e.message}`);
    }
  });

  $('btnUninstall')?.addEventListener('click', async () => {
    if (!currentVpsId) return alert('请先选择目标 VPS');
    if (!confirm('确认卸载该节点上的 AERO Edge 服务？')) return;
    try {
      await request('/api/v1/aero/uninstall/', {
        method: 'POST',
        body: JSON.stringify({ vps_id: currentVpsId })
      });
      alert('已触发卸载');
      loadVpsDiagnose(currentVpsId);
    } catch (e) {
      alert(`卸载失败: ${e.message}`);
    }
  });

  $('btnRenewCert')?.addEventListener('click', async () => {
    if (!currentVpsId) return alert('请先选择目标 VPS');
    try {
      await request(`/api/v1/aero/vps/${currentVpsId}/cert/renew/`, {
        method: 'POST',
        body: JSON.stringify({ force: true })
      });
      alert('证书续签任务已触发');
      loadVpsDiagnose(currentVpsId);
    } catch (e) {
      alert(`证书续签失败: ${e.message}`);
    }
  });

  // Modal events
  $('btnOpenAddToken')?.addEventListener('click', () => {
    $('tokenModal').classList.add('active');
  });
  $('btnCancelToken')?.addEventListener('click', () => {
    $('tokenModal').classList.remove('active');
  });
  $('btnSaveToken')?.addEventListener('click', async () => {
    if (!currentVpsId) return alert('请先选择 VPS');
    const token = $('newTokenVal').value.trim();
    const label = $('newTokenLabel').value.trim();
    const ttl_hours = parseInt($('newTokenTTL').value, 10) || 0;
    try {
      await request(`/api/v1/aero/vps/${currentVpsId}/tokens/`, {
        method: 'POST',
        body: JSON.stringify({ token, label, ttl_hours })
      });
      $('tokenModal').classList.remove('active');
      loadTokens(currentVpsId);
    } catch (e) {
      alert(`保存失败: ${e.message}`);
    }
  });
}

// 检查官方源 Release 状态（严格遵从 GitHub 官方源发布约束，杜绝本地私传）
async function loadSourceStatus() {
  try {
    const data = await request('/api/v1/aero/source-status/');
    const alertBox = $('sourceAlert');
    const alertText = $('sourceAlertText');
    if (data && !data.has_source) {
      alertBox.style.display = 'flex';
      alertText.textContent = `【官方源提示】检测到 GitHub 官方源（${data.repo || 'jackybig999/aero'}）尚未发布 Release 包。系统严禁本地私拷分发，请先向 GitHub 推送 Release。点击【安装/升级】可执行前置流水线。`;
    } else {
      alertBox.style.display = 'none';
    }
  } catch (err) {
    console.warn('loadSourceStatus error:', err);
  }
}

async function loadVpsList() {
  try {
    const data = await request('/api/v1/aero/vps-options/');
    const list = (data && data.results) || data || [];
    const sel = $('vpsSelect');
    sel.innerHTML = '';
    if (!list || list.length === 0) {
      sel.innerHTML = '<option value="">未录入任何 VPS 节点</option>';
      return;
    }
    list.forEach((vps, i) => {
      const opt = document.createElement('option');
      opt.value = vps.id || vps.vps_id;
      opt.textContent = `${vps.name || 'VPS-' + (vps.id || i)} (${vps.host || vps.ip || '—'})`;
      sel.appendChild(opt);
    });
    currentVpsId = sel.value;
  } catch (err) {
    console.warn('loadVpsList error:', err);
  }
}

async function loadVpsDiagnose(vpsId) {
  if (!vpsId) return;
  try {
    const diag = await request(`/api/v1/aero/vps/${vpsId}/diagnose/`);
    renderDiagnose(diag);
    loadTokens(vpsId);
  } catch (err) {
    $('kpiOverall').innerHTML = '<span class="tag tag-red">异常</span>';
    $('logBox').textContent = `诊断请求异常: ${err.message}`;
  }
}

function renderDiagnose(diag) {
  if (!diag) return;

  // KPI
  const online = diag.overall_online !== false;
  $('kpiOverall').innerHTML = `<span class="tag ${online ? 'tag-green' : 'tag-red'}">${online ? '可运维' : '异常'}</span>`;
  
  const svcActive = diag.service && diag.service.active;
  $('kpiService').innerHTML = `<span class="tag ${svcActive ? 'tag-green' : 'tag-red'}">${svcActive ? 'ACTIVE' : 'DOWN'}</span>`;

  const portListen = diag.ports && diag.ports.some(p => p.port === 443 && p.listen);
  $('kpiPort443').innerHTML = `<span class="tag ${portListen ? 'tag-green' : 'tag-amber'}">${portListen ? 'LISTEN' : 'CLOSED'}</span>`;

  const certOk = diag.cert && diag.cert.ok;
  $('kpiCert').innerHTML = `<span class="tag ${certOk ? 'tag-green' : 'tag-amber'}">${certOk ? '正常' : '待更新'}</span>`;
  if (diag.cert) {
    $('certDomainText').textContent = `当前域名: ${diag.cert.domain || '—'}`;
    $('certExpiryText').textContent = `到期时间: ${diag.cert.expire_date || '—'}`;
  }

  // Nodes Table
  const tbody = $('nodesTableBody');
  tbody.innerHTML = '';
  const nodes = diag.nodes || [];
  if (nodes.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--muted);padding:14px">暂无协议节点配置</td></tr>';
  } else {
    nodes.forEach(n => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><span class="tag ${n.online ? 'tag-green' : 'tag-red'}">${n.online ? '通' : '断'}</span></td>
        <td><b>${escapeHtml(n.name || n.proto)}</b></td>
        <td>${escapeHtml(n.kind || 'masque/h2')}</td>
        <td><span style="font-family:monospace">${escapeHtml(n.target || '—')}</span></td>
      `;
      tbody.appendChild(tr);
    });
  }

  // Log box
  $('logBox').textContent = diag.log_tail || '暂无最近活动日志';
}

async function loadTokens(vpsId) {
  try {
    const data = await request(`/api/v1/aero/vps/${vpsId}/tokens/`);
    const tokens = (data && data.results) || data || [];
    const tbody = $('tokensTableBody');
    tbody.innerHTML = '';
    if (tokens.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--muted);padding:14px">当前节点暂无授权 Token</td></tr>';
      return;
    }
    tokens.forEach(t => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><span style="font-family:monospace;color:#93c5fd">${escapeHtml(t.token)}</span></td>
        <td>${escapeHtml(t.label || '—')}</td>
        <td>${t.ttl_hours ? `${t.ttl_hours} 小时` : '永久'}</td>
        <td><button class="btn btn-sm btn-danger" onclick="delToken('${escapeHtml(t.token)}')">删除</button></td>
      `;
      tbody.appendChild(tr);
    });
  } catch (e) {
    console.warn('loadTokens error', e);
  }
}

window.delToken = async (tokenStr) => {
  if (!confirm(`确认废除此 Token (${tokenStr.slice(0, 8)}...)？`)) return;
  try {
    await request(`/api/v1/aero/vps/${currentVpsId}/tokens/?token=${encodeURIComponent(tokenStr)}`, { method: 'DELETE' });
    loadTokens(currentVpsId);
  } catch (e) {
    alert(`删除失败: ${e.message}`);
  }
};

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
