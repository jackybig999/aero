// ==============================================================================
// AERO VPN Middle-Platform Administration Console (Plan B Native Engine)
// 100% Feature-Parity Restoration: Full VPS Cards/Metrics, AERO Console, Node Registry
// ==============================================================================

const $ = (id) => document.getElementById(id);
const TOKEN_KEY = 'vpn_admin_token';

let currentTab = 'dashboard';
let userKind = 'staff';
let vpsViewMode = 'card'; // 'card' or 'table'
let cachedVpsList = [];
let cachedNodeList = [];
let cachedUserList = [];
let cfReady = false;

// ------------------------------------------------------------------------------
// API Client
// ------------------------------------------------------------------------------
async function apiCall(endpoint, options = {}) {
  const token = localStorage.getItem(TOKEN_KEY);
  const headers = Object.assign({}, options.headers || {});
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  if (!headers['Content-Type'] && options.body) {
    headers['Content-Type'] = 'application/json';
  }

  const url = endpoint.startsWith('http') ? endpoint : `/api/v1${endpoint}`;
  const res = await fetch(url, Object.assign({}, options, { headers }));

  if (res.status === 401) {
    localStorage.removeItem(TOKEN_KEY);
    showLogin(true);
    throw new Error('鉴权失效，请重新登录');
  }

  const data = await res.json();
  if (data && typeof data === 'object' && 'code' in data && data.code !== 0) {
    throw new Error(data.message || `Code ${data.code}`);
  }
  return data.data !== undefined ? data.data : data;
}

function escapeHtml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function fmtNum(n, d = 0) {
  if (n == null || isNaN(n)) return '0';
  return Number(n).toFixed(d);
}

function fmtUptime(sec) {
  if (!sec || sec <= 0) return '—';
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (d > 0) return `${d}天${h}时`;
  if (h > 0) return `${h}时${m}分`;
  return `${m}分`;
}

// ------------------------------------------------------------------------------
// Lifecycle & Navigation
// ------------------------------------------------------------------------------
window.addEventListener('DOMContentLoaded', () => {
  checkAuth();
  initEvents();
});

function checkAuth() {
  const token = localStorage.getItem(TOKEN_KEY);
  if (!token) {
    showLogin(true);
  } else {
    showLogin(false);
    loadCurrentTab();
  }
}

function showLogin(show) {
  $('loginWrap').style.display = show ? 'grid' : 'none';
  $('appLayout').style.display = show ? 'none' : 'flex';
}

function switchTab(tabId) {
  currentTab = tabId;
  document.querySelectorAll('.menu-item').forEach(b => {
    b.classList.toggle('active', b.getAttribute('data-tab') === tabId);
  });
  document.querySelectorAll('.content-pane').forEach(p => {
    p.classList.toggle('active', p.id === `pane-${tabId}`);
  });
  
  const titles = {
    dashboard: '系统总览',
    users: '用户中心',
    vps: 'VPS 节点编排',
    aero: 'AERO 管理台',
    nodes: '订阅节点',
    subs: '订阅管理',
    ledger: '财务账本',
    diag: '链路诊断'
  };
  $('pageTitle').textContent = titles[tabId] || '管理后台';
  loadCurrentTab();
}

function loadCurrentTab() {
  if (currentTab === 'dashboard') loadDashboard();
  else if (currentTab === 'users') loadUsers();
  else if (currentTab === 'vps') loadVPS();
  else if (currentTab === 'aero') loadAERO();
  else if (currentTab === 'nodes') loadNodes();
  else if (currentTab === 'subs') loadSubs();
  else if (currentTab === 'ledger') loadLedger();
  else if (currentTab === 'diag') loadDiag();
}

// ------------------------------------------------------------------------------
// Event Listeners
// ------------------------------------------------------------------------------
function initEvents() {
  // Login
  $('btnLogin')?.addEventListener('click', async () => {
    const u = $('loginUser').value.trim();
    const p = $('loginPass').value.trim();
    const errP = $('loginErr');
    errP.style.display = 'none';
    try {
      const res = await apiCall('/auth/login/', {
        method: 'POST',
        body: JSON.stringify({ username: u, password: p, portal: 'admin' })
      });
      const token = res.token || res.access_token || res.access || res;
      if (token && typeof token === 'string') {
        localStorage.setItem(TOKEN_KEY, token);
      }
      showLogin(false);
      loadCurrentTab();
    } catch (e) {
      errP.textContent = `登录失败: ${e.message}`;
      errP.style.display = 'block';
    }
  });

  // Logout
  $('btnLogout')?.addEventListener('click', () => {
    localStorage.removeItem(TOKEN_KEY);
    showLogin(true);
  });

  // Navigation
  document.querySelectorAll('.menu-item').forEach(btn => {
    btn.addEventListener('click', () => {
      switchTab(btn.getAttribute('data-tab'));
    });
  });

  // Refresh
  $('btnTopRefresh')?.addEventListener('click', () => loadCurrentTab());
  $('btnRefreshUsers')?.addEventListener('click', () => loadUsers());

  // User Tab switch
  $('btnTabStaff')?.addEventListener('click', () => {
    userKind = 'staff';
    $('btnTabStaff').style.background = 'var(--card-active)';
    $('btnTabSub').style.background = 'transparent';
    renderUsers();
  });
  $('btnTabSub')?.addEventListener('click', () => {
    userKind = 'sub';
    $('btnTabSub').style.background = 'var(--card-active)';
    $('btnTabStaff').style.background = 'transparent';
    renderUsers();
  });

  // User Modals
  $('btnOpenAddUser')?.addEventListener('click', () => $('userModal').classList.add('active'));
  $('btnCancelUser')?.addEventListener('click', () => $('userModal').classList.remove('active'));
  $('btnSaveUser')?.addEventListener('click', async () => {
    const username = $('newUsername').value.trim();
    const password = $('newUserPass').value.trim();
    const is_staff = $('newUserRole').value === 'staff';
    const plan_months = parseInt($('newUserPlan').value, 10) || 1;
    if (!username) return alert('用户名不能为空');
    try {
      await apiCall('/users/', {
        method: 'POST',
        body: JSON.stringify({ username, password, is_staff, plan_months })
      });
      $('userModal').classList.remove('active');
      $('newUsername').value = '';
      $('newUserPass').value = '';
      loadUsers();
    } catch (e) {
      alert(`保存失败: ${e.message}`);
    }
  });

  // Renew Modal
  $('btnCancelRenew')?.addEventListener('click', () => $('renewModal').classList.remove('active'));
  $('btnSubmitRenew')?.addEventListener('click', async () => {
    const id = $('renewUserId').value;
    const months = parseInt($('renewPlanMonths').value, 10) || 1;
    try {
      await apiCall(`/users/${id}/renew/`, {
        method: 'POST',
        body: JSON.stringify({ months })
      });
      alert('续费成功并已记账');
      $('renewModal').classList.remove('active');
      loadUsers();
    } catch (e) {
      alert(`续费失败: ${e.message}`);
    }
  });

  // VPS View Toggle
  $('btnVpsViewCard')?.addEventListener('click', () => {
    vpsViewMode = 'card';
    $('btnVpsViewCard').style.background = 'var(--card-active)';
    $('btnVpsViewTable').style.background = 'transparent';
    $('vpsCardGrid').style.display = 'grid';
    $('vpsTableContainer').style.display = 'none';
  });
  $('btnVpsViewTable')?.addEventListener('click', () => {
    vpsViewMode = 'table';
    $('btnVpsViewTable').style.background = 'var(--card-active)';
    $('btnVpsViewCard').style.background = 'transparent';
    $('vpsCardGrid').style.display = 'none';
    $('vpsTableContainer').style.display = 'block';
  });

  // VPS Actions & Modals
  $('btnOpenAddVPS')?.addEventListener('click', () => $('addVpsModal').classList.add('active'));
  $('btnCancelVPS')?.addEventListener('click', () => $('addVpsModal').classList.remove('active'));
  $('btnSaveVPS')?.addEventListener('click', async () => {
    const name = $('vpsName').value.trim();
    const role = $('vpsRole').value;
    const ip = $('vpsIp').value.trim();
    const ssh_port = parseInt($('vpsSshPort').value, 10) || 22;
    const ssh_username = $('vpsSshUser').value.trim() || 'root';
    const ssh_password = $('vpsSshPass').value.trim();
    const domain = $('vpsDomain').value.trim();
    const remark = $('vpsRemark').value.trim();

    if (!ip) return alert('公网 IP 不能为空');
    if (!ssh_password) return alert('SSH 密码不能为空');

    try {
      await apiCall('/vps/', {
        method: 'POST',
        body: JSON.stringify({ name, role, ip, ssh_port, ssh_username, ssh_password, domain, remark })
      });
      $('addVpsModal').classList.remove('active');
      $('vpsName').value = '';
      $('vpsIp').value = '';
      $('vpsSshPass').value = '';
      $('vpsDomain').value = '';
      $('vpsRemark').value = '';
      loadVPS();
    } catch (e) {
      alert(`录入失败: ${e.message}`);
    }
  });

  $('btnRefreshProbeAll')?.addEventListener('click', () => refreshProbeAll());
  $('btnVerifyAllDomains')?.addEventListener('click', () => verifyAllDomains());
  $('btnPurityProbeAll')?.addEventListener('click', () => purityProbeAll());

  // Edit Domain Modal
  $('btnCancelEditDomain')?.addEventListener('click', () => $('editDomainModal').classList.remove('active'));
  $('btnSaveEditDomain')?.addEventListener('click', async () => {
    const id = $('editDomainVpsId').value;
    const domain = $('editDomainVal').value.trim();
    try {
      await apiCall(`/vps/${id}/`, {
        method: 'PATCH',
        body: JSON.stringify({ domain })
      });
      $('editDomainModal').classList.remove('active');
      loadVPS();
    } catch (e) {
      alert(`修改失败: ${e.message}`);
    }
  });

  // Edit Pass Modal
  $('btnCancelEditPass')?.addEventListener('click', () => $('editPassModal').classList.remove('active'));
  $('btnSaveEditPass')?.addEventListener('click', async () => {
    const id = $('editPassVpsId').value;
    const ssh_password = $('editPassVal').value.trim();
    if (!ssh_password) return alert('密码不能为空');
    try {
      await apiCall(`/vps/${id}/`, {
        method: 'PATCH',
        body: JSON.stringify({ ssh_password })
      });
      $('editPassModal').classList.remove('active');
      $('editPassVal').value = '';
      alert('凭据更新成功');
      loadVPS();
    } catch (e) {
      alert(`保存失败: ${e.message}`);
    }
  });

  // Node Registry Modals
  $('btnOpenAddNode')?.addEventListener('click', () => $('nodeModal').classList.add('active'));
  $('btnCancelNode')?.addEventListener('click', () => $('nodeModal').classList.remove('active'));
  $('btnSaveNode')?.addEventListener('click', async () => {
    const name = $('newNodeName').value.trim();
    const ip = $('newNodeIp').value.trim();
    const port = parseInt($('newNodePort').value, 10) || 443;
    const protocol = $('newNodeProto').value;
    const max_users = parseInt($('newNodeMaxUsers').value, 10) || 100;
    if (!name || !ip) return alert('名称与 IP 不能为空');
    try {
      await apiCall('/nodes/', {
        method: 'POST',
        body: JSON.stringify({ name, ip, port, protocol, max_users })
      });
      $('nodeModal').classList.remove('active');
      $('newNodeName').value = '';
      $('newNodeIp').value = '';
      loadNodes();
    } catch (e) {
      alert(`登记失败: ${e.message}`);
    }
  });

  $('btnSyncNodes')?.addEventListener('click', () => loadNodes());
  $('btnCleanOrphanNodes')?.addEventListener('click', async () => {
    if (!confirm('确认清理所有失联无归属节点？')) return;
    try {
      await apiCall('/nodes/orphan/', { method: 'DELETE' });
      loadNodes();
    } catch (e) {
      alert(`清理失败: ${e.message}`);
    }
  });

  // Ledger Filter
  $('btnLedgerAll')?.addEventListener('click', () => filterLedger('all'));
  $('btnLedgerIn')?.addEventListener('click', () => filterLedger('in'));
  $('btnLedgerOut')?.addEventListener('click', () => filterLedger('out'));
  $('btnLedgerUnsettled')?.addEventListener('click', () => filterLedger('unsettled'));

  // Ledger Settle
  $('btnBatchSettle')?.addEventListener('click', async () => {
    if (!confirm('确认执行一键批量归集与自动结算？')) return;
    try {
      await apiCall('/ledger/settle/batch/', { method: 'POST' });
      alert('资金归集与流水结算执行完毕');
      loadLedger();
    } catch (e) {
      alert(`结算失败: ${e.message}`);
    }
  });

  // Diag
  $('btnRunAllDiag')?.addEventListener('click', () => runAllDiag());
}

// ------------------------------------------------------------------------------
// Pane 1: Dashboard
// ------------------------------------------------------------------------------
async function loadDashboard() {
  try {
    const vpsRes = await apiCall('/vps/');
    const vpsList = (vpsRes && vpsRes.results) || vpsRes || [];
    $('kpiVpsCount').textContent = vpsList.length;

    const ledger = await apiCall('/ledger/summary/');
    if (ledger) {
      $('kpiIncome').textContent = `$${((Number(ledger.total_in_cents || 0)) / 100).toFixed(2)}`;
      $('kpiExpense').textContent = `$${((Number(ledger.total_out_cents || 0)) / 100).toFixed(2)}`;
      $('kpiTxCount').textContent = ledger.entry_count || 0;
    }

    const health = await fetch('/health').then(r => r.json()).catch(() => null);
    if (health && health.services) {
      const grid = $('serviceGrid');
      grid.innerHTML = '';
      health.services.forEach(s => {
        const div = document.createElement('div');
        div.style.cssText = 'background:#090e18;border:1px solid var(--line);border-radius:6px;padding:8px 12px;display:flex;justify-content:space-between;align-items:center;';
        div.innerHTML = `
          <span style="font-size:12px;font-weight:600">${s.name}</span>
          <span class="tag ${s.status === 'ok' ? 'tag-green' : 'tag-red'}">${s.status === 'ok' ? '正常' : '异常'}</span>
        `;
        grid.appendChild(div);
      });
    }
  } catch (e) {
    console.warn('loadDashboard error', e);
  }
}

// ------------------------------------------------------------------------------
// Pane 2: Users
// ------------------------------------------------------------------------------
async function loadUsers() {
  try {
    const res = await apiCall('/users/');
    cachedUserList = (res && res.results) || res || [];
    renderUsers();
  } catch (e) {
    console.warn('loadUsers error', e);
  }
}

function renderUsers() {
  const filtered = cachedUserList.filter(u => userKind === 'staff' ? u.is_staff : !u.is_staff);
  const tbody = $('usersTableBody');
  tbody.innerHTML = '';
  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;padding:16px;color:var(--muted)">暂无${userKind === 'staff' ? '管理员' : '订阅用户'}</td></tr>`;
    return;
  }
  filtered.forEach(u => {
    const tr = document.createElement('tr');
    const subUrl = u.sub_slug ? `${location.origin}/sub/${u.sub_slug}` : '';
    tr.innerHTML = `
      <td>#${u.id}</td>
      <td><b>${escapeHtml(u.username)}</b></td>
      <td>${escapeHtml(u.email || u.phone || '—')}</td>
      <td><span class="tag ${u.is_staff ? 'tag-amber' : 'tag-blue'}">${u.is_staff ? '系统管理' : (u.plan_name || '月度套餐')}</span></td>
      <td><b>$${((u.balance_cents || 0) / 100).toFixed(2)}</b></td>
      <td>
        ${subUrl ? `
          <div style="display:flex;align-items:center;gap:4px">
            <input type="text" class="input-text" value="${subUrl}" readonly style="font-size:10px;width:180px;height:24px;padding:2px 6px" />
            <button class="btn btn-sm btn-blue" onclick="copyText('${subUrl}')">复制</button>
          </div>
        ` : '<span class="muted" style="font-size:11px">未分配</span>'}
      </td>
      <td><span class="tag tag-green">正常</span></td>
      <td>
        ${!u.is_staff ? `<button class="btn btn-sm" style="color:var(--green);border-color:var(--green)" onclick="openRenewModal(${u.id}, '${escapeHtml(u.username)}')">续费</button>` : ''}
        <button class="btn btn-sm" onclick="resetUserSlug(${u.id})">重置凭据</button>
        <button class="btn btn-sm btn-danger" onclick="delUser(${u.id})">删除</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

window.copyText = (txt) => {
  navigator.clipboard.writeText(txt).then(() => alert('订阅地址已复制到剪贴板'));
};

window.openRenewModal = (id, username) => {
  $('renewUserId').value = id;
  $('renewUsername').value = username;
  $('renewModal').classList.add('active');
};

window.resetUserSlug = async (id) => {
  try {
    await apiCall(`/users/${id}/reset-slug/`, { method: 'POST' });
    alert('已重置订阅凭据与 Slug 路由');
    loadUsers();
  } catch (e) {
    alert(`重置失败: ${e.message}`);
  }
};

window.delUser = async (id) => {
  if (!confirm(`确认彻底删除用户 #${id}？`)) return;
  try {
    await apiCall(`/users/${id}/`, { method: 'DELETE' });
    loadUsers();
  } catch (e) {
    alert(`删除失败: ${e.message}`);
  }
};

// ------------------------------------------------------------------------------
// Pane 3: VPS Assets & Metrics
// ------------------------------------------------------------------------------
async function loadVPS() {
  try {
    checkCFStatus();
    const res = await apiCall('/vps/');
    cachedVpsList = (res && res.results) || res || [];
    renderVPS();
  } catch (e) {
    console.warn('loadVPS error', e);
  }
}

async function checkCFStatus() {
  try {
    const res = await apiCall('/vps/cf-dns/status/');
    cfReady = res && res.configured;
    const badge = $('cfStatusBadge');
    if (badge) {
      badge.textContent = cfReady ? '🟢 Cloudflare 灰云自动化: 已就绪' : '⚪ Cloudflare: 未配置 Token (仅公网DNS)';
      badge.className = `tag ${cfReady ? 'tag-green' : 'tag-blue'}`;
    }
  } catch {
    cfReady = false;
  }
}

function renderVPS() {
  const cardGrid = $('vpsCardGrid');
  const tableBody = $('vpsTableBody');
  cardGrid.innerHTML = '';
  tableBody.innerHTML = '';

  if (cachedVpsList.length === 0) {
    cardGrid.innerHTML = '<div class="metric-empty" style="grid-column:1/-1">尚未登记 VPS 节点资产，请点击上方按钮录入</div>';
    tableBody.innerHTML = '<tr><td colspan="9" style="text-align:center;padding:16px;color:var(--muted)">暂无 VPS 资产</td></tr>';
    return;
  }

  cachedVpsList.forEach(v => {
    // 1. Render Card View
    const card = document.createElement('div');
    card.className = 'vps-card';

    const tierTag = v.tier === 'tier1' ? '<span class="tag tag-green">Tier 1 原生纯净</span>' : (v.tier === 'tier2' ? '<span class="tag tag-amber">Tier 2 良好</span>' : '<span class="tag tag-red">Tier 3 脏IP/风控</span>');
    const warpTag = `<span class="tag ${v.warp_enabled ? 'tag-green' : 'tag-amber'}">${v.warp_enabled ? 'WARP ON' : '直连'}</span>`;
    const dnsLabel = v.domain ? (v.dns_resolved ? '🟢 DNS正常' : '🟡 DNS未解析') : '⚪ 无域名';
    const m = v.metrics;

    let metricsHtml = '';
    if (m && m.probe_ok) {
      const cpu = clampPct(m.cpu_percent || 0);
      metricsHtml = `
        <div class="metric-compact-row">
          <div class="mc-item">
            <span class="mc-label">CPU</span>
            <span class="mc-val">${fmtNum(m.cpu_percent)}%</span>
            <div class="progress-mini"><div class="progress-mini-bar" style="width:${cpu}%"></div></div>
          </div>
          <div class="mc-divider"></div>
          <div class="mc-item">
            <span class="mc-label">内存</span>
            <span class="mc-val">${fmtNum(m.mem_percent)}%</span>
            <span class="mc-sub">(${fmtNum(m.mem_used_mb)}M)</span>
          </div>
          <div class="mc-divider"></div>
          <div class="mc-item">
            <span class="mc-label">磁盘</span>
            <span class="mc-val">${fmtNum(m.disk_percent)}%</span>
            <span class="mc-sub">(${fmtNum(m.disk_used_gb)}G)</span>
          </div>
          <div class="mc-divider"></div>
          <div class="mc-item">
            <span class="mc-label">负载</span>
            <span class="mc-val">${fmtNum(m.load_1, 2)}</span>
          </div>
          <div class="mc-divider"></div>
          <div class="mc-item">
            <span class="mc-label">网络</span>
            <span class="mc-val">↓${fmtNum(m.net_rx_mbps, 1)} / ↑${fmtNum(m.net_tx_mbps, 1)}</span>
          </div>
          <div class="mc-divider"></div>
          <div class="mc-item">
            <span class="mc-label">运行</span>
            <span class="mc-val">${fmtUptime(m.uptime_sec)}</span>
          </div>
        </div>
      `;
    } else {
      metricsHtml = `<div class="metric-empty">${m?.probe_error ? ('探测失败: ' + escapeHtml(m.probe_error)) : '尚未采集运行状态，点击「探测」执行'}</div>`;
    }

    card.innerHTML = `
      <div class="vps-card-hd">
        <div class="vps-id">
          <span class="tag tag-blue">${escapeHtml(v.role || 'node')}</span>
          <span class="vps-name">${escapeHtml(v.name || 'vps-' + v.id)}</span>
          <span class="tag tag-green">${v.status || 'online'}</span>
          <span class="tag tag-blue">${dnsLabel}</span>
          ${tierTag}
          ${warpTag}
        </div>
        <div class="vps-actions">
          <button class="btn btn-sm" onclick="probeVPS(${v.id})">探测</button>
          <button class="btn btn-sm btn-blue" onclick="purityVPS(${v.id})">打靶探测</button>
          <button class="btn btn-sm" onclick="verifyDomainVPS(${v.id})">复核域名/CF</button>
          <button class="btn btn-sm" onclick="openEditDomainModal(${v.id}, '${escapeHtml(v.ip)}', '${escapeHtml(v.domain || '')}')">改域名</button>
          <button class="btn btn-sm" onclick="openEditPassModal(${v.id}, '${escapeHtml(v.ip)}:${v.ssh_port || 22}')">改密码</button>
          <button class="btn btn-sm btn-danger" onclick="delVPS(${v.id})">删除</button>
        </div>
      </div>
      <div class="vps-meta">
        <span><b>${escapeHtml(v.ssh_username || 'root')}@${escapeHtml(v.ip)}:${v.ssh_port || 22}</b></span>
        ${v.domain ? `<span>· 域名: <b>${escapeHtml(v.domain)}</b></span>` : ''}
        ${m?.latency_ms != null ? `<span>· 延迟: <b>${m.latency_ms}ms</b></span>` : ''}
        ${m?.os ? `<span>· 系统: <b>${m.os}/${m.arch}</b></span>` : ''}
        <span>· 出口纯净分: <b>${v.purity_score || 0}分</b></span>
      </div>
      ${metricsHtml}
    `;
    cardGrid.appendChild(card);

    // 2. Render Table View
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>#${v.id}</td>
      <td><b>${escapeHtml(v.name || 'VPS-' + v.id)}</b></td>
      <td><span class="tag tag-blue">${escapeHtml(v.role || 'node')}</span></td>
      <td><span style="font-family:monospace">${escapeHtml(v.ip)}:${v.ssh_port || 22}</span></td>
      <td><b>${escapeHtml(v.domain || '—')}</b></td>
      <td>${tierTag} <span style="font-size:11px;color:var(--muted)">(${v.purity_score || 0}分)</span></td>
      <td>${warpTag}</td>
      <td><span class="tag tag-green">${v.status || 'online'}</span></td>
      <td>
        <button class="btn btn-sm" onclick="probeVPS(${v.id})">探测</button>
        <button class="btn btn-sm btn-blue" onclick="purityVPS(${v.id})">打靶</button>
        <button class="btn btn-sm" onclick="verifyDomainVPS(${v.id})">复核</button>
        <button class="btn btn-sm" onclick="openEditDomainModal(${v.id}, '${escapeHtml(v.ip)}', '${escapeHtml(v.domain || '')}')">改域名</button>
        <button class="btn btn-sm" onclick="openEditPassModal(${v.id}, '${escapeHtml(v.ip)}:${v.ssh_port || 22}')">改密</button>
        <button class="btn btn-sm btn-danger" onclick="delVPS(${v.id})">删</button>
      </td>
    `;
    tableBody.appendChild(tr);
  });
}

function clampPct(v) {
  const n = Number(v) || 0;
  return Math.min(100, Math.max(0, n));
}

window.probeVPS = async (id) => {
  try {
    await apiCall(`/vps/${id}/probe/`, { method: 'POST' });
    alert('系统指标探测完成');
    loadVPS();
  } catch (e) {
    alert(`探测失败: ${e.message}`);
  }
};

window.purityVPS = async (id) => {
  try {
    await apiCall(`/vps/${id}/probe/`, { method: 'POST' });
    alert('真实出口纯净度打靶完成');
    loadVPS();
  } catch (e) {
    alert(`打靶失败: ${e.message}`);
  }
};

window.verifyDomainVPS = async (id) => {
  try {
    await apiCall(`/vps/${id}/verify-domain/`, { method: 'POST' });
    alert('公网域名 DNS 与 Cloudflare 解析复核完成');
    loadVPS();
  } catch (e) {
    alert(`复核失败: ${e.message}`);
  }
};

window.openEditDomainModal = (id, ip, currentDomain) => {
  $('editDomainVpsId').value = id;
  $('editDomainVpsIp').value = ip;
  $('editDomainVal').value = currentDomain;
  $('editDomainModal').classList.add('active');
};

window.openEditPassModal = (id, addr) => {
  $('editPassVpsId').value = id;
  $('editPassVpsAddr').value = addr;
  $('editPassVal').value = '';
  $('editPassModal').classList.add('active');
};

window.delVPS = async (id) => {
  if (!confirm(`确认删除 VPS 节点资产 #${id}？关联节点将同步解除绑定。`)) return;
  try {
    await apiCall(`/vps/${id}/`, { method: 'DELETE' });
    loadVPS();
  } catch (e) {
    alert(`删除失败: ${e.message}`);
  }
};

async function refreshProbeAll() {
  for (const v of cachedVpsList) {
    try {
      await apiCall(`/vps/${v.id}/probe/`, { method: 'POST' });
    } catch {}
  }
  loadVPS();
  alert('全量 VPS 探测已完成');
}

async function verifyAllDomains() {
  for (const v of cachedVpsList) {
    if (v.domain) {
      try {
        await apiCall(`/vps/${v.id}/verify-domain/`, { method: 'POST' });
      } catch {}
    }
  }
  loadVPS();
  alert('全量公网域名/CF 复核已完成');
}

async function purityProbeAll() {
  for (const v of cachedVpsList) {
    try {
      await apiCall(`/vps/${v.id}/probe/`, { method: 'POST' });
    } catch {}
  }
  loadVPS();
  alert('全量纯净度打靶巡检已完成');
}

// ------------------------------------------------------------------------------
// Pane 4: AERO Console
// ------------------------------------------------------------------------------
function loadAERO() {
  const iframe = $('aeroIframe');
  if (iframe && (!iframe.src || iframe.src === 'about:blank')) {
    iframe.src = '/aero-ui/?mode=mid&embed=1';
  }
}

// ------------------------------------------------------------------------------
// Pane 5: Nodes Registry
// ------------------------------------------------------------------------------
async function loadNodes() {
  try {
    const res = await apiCall('/nodes/');
    cachedNodeList = (res && res.results) || res || [];
    renderNodes();
  } catch (e) {
    console.warn('loadNodes error', e);
  }
}

function renderNodes() {
  const tbody = $('nodesTableBody');
  tbody.innerHTML = '';
  if (cachedNodeList.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;padding:16px;color:var(--muted)">暂无订阅节点</td></tr>';
    return;
  }
  cachedNodeList.forEach(n => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>#${n.id}</td>
      <td><b>${escapeHtml(n.name)}</b></td>
      <td><span style="font-family:monospace">${escapeHtml(n.ip)}:${n.port || 443}</span></td>
      <td><span class="tag tag-blue">${escapeHtml(n.protocol || 'aero-h2')}</span></td>
      <td>${n.vps_id ? `<span class="tag tag-green">#${n.vps_id}</span>` : '<span class="tag tag-amber">独立</span>'}</td>
      <td><span class="tag ${n.status ? 'tag-green' : 'tag-amber'}">${n.status ? '在线' : '离线'}</span></td>
      <td>${n.user_count || 0} / ${n.max_users || 100}</td>
      <td>
        <button class="btn btn-sm" onclick="hbNode(${n.id})">心跳</button>
        <button class="btn btn-sm btn-danger" onclick="delNode(${n.id})">删除</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

window.hbNode = async (id) => {
  try {
    await apiCall(`/nodes/${id}/heartbeat/`, {
      method: 'POST',
      body: JSON.stringify({ agent_version: 'v2.5' })
    });
    alert('心跳上报成功');
    loadNodes();
  } catch (e) {
    alert(`心跳失败: ${e.message}`);
  }
};

window.delNode = async (id) => {
  if (!confirm(`确认删除订阅节点 #${id}？`)) return;
  try {
    await apiCall(`/nodes/${id}/`, { method: 'DELETE' });
    loadNodes();
  } catch (e) {
    alert(`删除失败: ${e.message}`);
  }
};

// ------------------------------------------------------------------------------
// Pane 6: Subscriptions
// ------------------------------------------------------------------------------
async function loadSubs() {
  try {
    const users = await apiCall('/users/');
    const list = (users && users.results) || users || [];
    const subs = list.filter(u => !u.is_staff && u.sub_slug);
    const tbody = $('subsTableBody');
    tbody.innerHTML = '';
    if (subs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:16px;color:var(--muted)">暂无订阅用户</td></tr>';
      return;
    }
    subs.forEach(u => {
      const tr = document.createElement('tr');
      const url = `${location.origin}/sub/${u.sub_slug}`;
      tr.innerHTML = `
        <td>#${u.id}</td>
        <td><b>${escapeHtml(u.username)}</b></td>
        <td><span style="font-family:monospace">${escapeHtml(u.sub_slug)}</span></td>
        <td>
          <input type="text" class="input-text" value="${url}" readonly style="font-size:11px;width:300px" />
        </td>
        <td><span class="tag tag-green">全节点自适应分流</span></td>
        <td>
          <button class="btn btn-sm btn-blue" onclick="copyText('${url}')">复制订阅</button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (e) {
    console.warn('loadSubs error', e);
  }
}

// ------------------------------------------------------------------------------
// Pane 7: Ledger
// ------------------------------------------------------------------------------
let cachedLedger = [];
async function loadLedger() {
  try {
    const res = await apiCall('/ledger/entries/');
    cachedLedger = (res && res.results) || res || [];
    renderLedger(cachedLedger);
  } catch (e) {
    console.warn('loadLedger error', e);
  }
}

function filterLedger(type) {
  $('btnLedgerAll').style.background = type === 'all' ? 'var(--card-active)' : 'transparent';
  $('btnLedgerIn').style.background = type === 'in' ? 'var(--card-active)' : 'transparent';
  $('btnLedgerOut').style.background = type === 'out' ? 'var(--card-active)' : 'transparent';
  $('btnLedgerUnsettled').style.background = type === 'unsettled' ? 'var(--card-active)' : 'transparent';

  let list = cachedLedger;
  if (type === 'in') list = cachedLedger.filter(x => x.direction === 'IN');
  else if (type === 'out') list = cachedLedger.filter(x => x.direction === 'OUT');
  else if (type === 'unsettled') list = cachedLedger.filter(x => !x.settled);
  renderLedger(list);
}

function renderLedger(list) {
  const tbody = $('ledgerTableBody');
  tbody.innerHTML = '';
  if (!list || list.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:16px;color:var(--muted)">暂无财务明细流水</td></tr>';
    return;
  }
  list.forEach(item => {
    const tr = document.createElement('tr');
    const isIn = item.direction === 'IN';
    tr.innerHTML = `
      <td><span style="font-family:monospace">${escapeHtml(item.ledger_no || 'TX-' + item.id)}</span></td>
      <td><span class="tag ${isIn ? 'tag-green' : 'tag-amber'}">${isIn ? '收入 IN' : '支出 OUT'}</span></td>
      <td><b style="color:${isIn ? 'var(--green)' : 'var(--amber)'}">${isIn ? '+' : '-'}$${((Number(item.amount_cents || 0)) / 100).toFixed(2)}</b></td>
      <td>${escapeHtml(item.channel || '系统归集')}</td>
      <td><span class="tag ${item.settled ? 'tag-blue' : 'tag-amber'}">${item.settled ? '已归集' : '待结算'}</span></td>
      <td>${escapeHtml(item.channel_ref || item.remark || '—')}</td>
      <td>${escapeHtml(item.created_at || '—')}</td>
    `;
    tbody.appendChild(tr);
  });
}

// ------------------------------------------------------------------------------
// Pane 8: Diagnostics
// ------------------------------------------------------------------------------
async function runAllDiag() {
  const box = $('diagResults');
  box.innerHTML = '<p style="color:var(--muted)">正在执行链路健康度与出口纯净度深度体检...</p>';
  try {
    const res = await apiCall('/vps/diag/purity/');
    const list = (res && res.results) || res || [];
    if (!list || list.length === 0) {
      box.innerHTML = '<p style="color:var(--muted)">体检完成：当前无可用 VPS 目标进行打靶</p>';
      return;
    }
    let html = '<div style="display:flex;flex-direction:column;gap:8px">';
    list.forEach(d => {
      html += `
        <div style="background:#090e18;border:1px solid var(--line);border-radius:6px;padding:10px 14px;display:flex;justify-content:space-between;align-items:center">
          <div>
            <b>${escapeHtml(d.name || d.ip)}</b> <span class="muted" style="margin-left:8px">${escapeHtml(d.ip)}</span>
            <div style="font-size:11px;color:var(--muted);margin-top:4px">Google: ${d.google_ok ? '🟢 畅通' : '🔴 拦截'} · Cloudflare: ${d.cf_ok ? '🟢 畅通' : '🔴 拦截'} · AI风控: ${d.ai_blocked ? '🔴 封锁' : '🟢 纯净'}</div>
          </div>
          <div>
            <span class="tag ${d.tier === 'tier1' ? 'tag-green' : (d.tier === 'tier2' ? 'tag-amber' : 'tag-red')}">${d.tier || 'Tier 3'} (${d.score || 0}分)</span>
          </div>
        </div>
      `;
    });
    html += '</div>';
    box.innerHTML = html;
  } catch (e) {
    box.innerHTML = `<p style="color:var(--red)">体检中断: ${escapeHtml(e.message)}</p>`;
  }
}
