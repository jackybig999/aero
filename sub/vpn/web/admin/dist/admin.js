// VPN Middle-Platform Administration Application Engine
const $ = (id) => document.getElementById(id);

const TOKEN_KEY = 'vpn_admin_token';
let currentTab = 'dashboard';
let userKind = 'staff';

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

  // Navigation tabs
  document.querySelectorAll('.menu-item').forEach(btn => {
    btn.addEventListener('click', () => {
      const target = btn.getAttribute('data-tab');
      switchTab(target);
    });
  });

  // Topbar refresh
  $('btnTopRefresh')?.addEventListener('click', () => {
    loadCurrentTab();
  });

  // User tab toggle (staff vs sub)
  $('btnTabStaff')?.addEventListener('click', () => {
    userKind = 'staff';
    $('btnTabStaff').style.background = 'var(--card-active)';
    $('btnTabSub').style.background = 'transparent';
    loadUsers();
  });
  $('btnTabSub')?.addEventListener('click', () => {
    userKind = 'sub';
    $('btnTabSub').style.background = 'var(--card-active)';
    $('btnTabStaff').style.background = 'transparent';
    loadUsers();
  });

  // Modals
  $('btnOpenAddUser')?.addEventListener('click', () => $('userModal').classList.add('active'));
  $('btnCancelUser')?.addEventListener('click', () => $('userModal').classList.remove('active'));
  $('btnSaveUser')?.addEventListener('click', async () => {
    const username = $('newUsername').value.trim();
    const password = $('newUserPass').value.trim();
    const is_staff = $('newUserRole').value === 'staff';
    try {
      await apiCall('/users/', {
        method: 'POST',
        body: JSON.stringify({ username, password, is_staff })
      });
      $('userModal').classList.remove('active');
      loadUsers();
    } catch (e) {
      alert(`创建用户失败: ${e.message}`);
    }
  });

  $('btnOpenAddVPS')?.addEventListener('click', () => $('vpsModal').classList.add('active'));
  $('btnCancelVps')?.addEventListener('click', () => $('vpsModal').classList.remove('active'));
  $('btnSaveVps')?.addEventListener('click', async () => {
    const name = $('newVpsName').value.trim();
    const ip = $('newVpsIP').value.trim();
    const ssh_port = parseInt($('newVpsPort').value, 10) || 22;
    const ssh_password = $('newVpsPass').value.trim();
    try {
      await apiCall('/vps/', {
        method: 'POST',
        body: JSON.stringify({ name, ip, ssh_port, ssh_password, ssh_user: 'root' })
      });
      $('vpsModal').classList.remove('active');
      loadVPS();
    } catch (e) {
      alert(`录入 VPS 失败: ${e.message}`);
    }
  });

  // Global orchestration
  $('btnBroadcastAll')?.addEventListener('click', async () => {
    try {
      await apiCall('/aero/subs/broadcast/', { method: 'POST', body: JSON.stringify({}) });
      alert('已成功触发向全量 Edge VPS 广播用户凭证');
    } catch (e) {
      alert(`广播失败: ${e.message}`);
    }
  });
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
    users: '用户管理中心',
    vps: 'VPS 资产与节点编排',
    subs: '订阅配置分发',
    ledger: '财务收益账本',
    diag: '全链路连通性诊断'
  };
  $('pageTitle').textContent = titles[tabId] || '中台管理后台';
  loadCurrentTab();
}

function loadCurrentTab() {
  if (currentTab === 'dashboard') loadDashboard();
  else if (currentTab === 'users') loadUsers();
  else if (currentTab === 'vps') loadVPS();
  else if (currentTab === 'subs') loadSubs();
  else if (currentTab === 'ledger') loadLedger();
  else if (currentTab === 'diag') loadDiag();
}

async function loadDashboard() {
  try {
    const vpsList = await apiCall('/vps/');
    $('kpiVpsCount').textContent = (vpsList && vpsList.length) || 0;
    
    const ledger = await apiCall('/ledger/summary/');
    if (ledger) {
      $('kpiIncome').textContent = `$${((Number(ledger.total_in_cents || 0)) / 100).toFixed(2)}`;
      $('kpiExpense').textContent = `$${((Number(ledger.total_out_cents || 0)) / 100).toFixed(2)}`;
      $('kpiTxCount').textContent = ledger.entry_count || 0;
    }
  } catch (e) {
    console.warn('loadDashboard error', e);
  }
}

async function loadUsers() {
  try {
    const users = await apiCall('/users/');
    const list = (users && users.results) || users || [];
    const filtered = list.filter(u => userKind === 'staff' ? u.is_staff : !u.is_staff);
    const tbody = $('usersTableBody');
    tbody.innerHTML = '';
    if (filtered.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;padding:16px;color:var(--muted)">暂无${userKind === 'staff' ? '管理员' : '订阅用户'}</td></tr>`;
      return;
    }
    filtered.forEach(u => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>#${u.id}</td>
        <td><b>${escapeHtml(u.username)}</b></td>
        <td>${escapeHtml(u.email || u.phone || '—')}</td>
        <td><span class="tag ${u.is_staff ? 'tag-amber' : 'tag-blue'}">${u.is_staff ? '系统管理' : (u.plan_name || '月度套餐')}</span></td>
        <td><b>$${((u.balance_cents || 0) / 100).toFixed(2)}</b></td>
        <td><span class="tag tag-green">正常</span></td>
        <td>
          <button class="btn btn-sm" onclick="resetUserSlug(${u.id})">重置凭据</button>
          <button class="btn btn-sm btn-danger" onclick="delUser(${u.id})">删除</button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (e) {
    console.warn('loadUsers error', e);
  }
}

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

async function loadVPS() {
  try {
    const vpsList = await apiCall('/vps/');
    const list = (vpsList && vpsList.results) || vpsList || [];
    const tbody = $('vpsTableBody');
    tbody.innerHTML = '';
    if (list.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:16px;color:var(--muted)">暂无 VPS 资产，点击上方录入</td></tr>';
      return;
    }
    list.forEach(v => {
      const tr = document.createElement('tr');
      const tierTag = v.tier === 'tier1' ? '<span class="tag tag-green">Tier 1 原生纯净</span>' : (v.tier === 'tier2' ? '<span class="tag tag-amber">Tier 2 良好</span>' : '<span class="tag tag-red">Tier 3 脏IP/风控</span>');
      tr.innerHTML = `
        <td>#${v.id}</td>
        <td><b>${escapeHtml(v.name || 'VPS-' + v.id)}</b></td>
        <td><span style="font-family:monospace">${escapeHtml(v.ip || v.host)}:${v.ssh_port || 22}</span></td>
        <td>${tierTag} <span style="font-size:11px;color:var(--muted)">(${v.purity_score || 0}分)</span></td>
        <td><span class="tag ${v.warp_enabled ? 'tag-green' : 'tag-amber'}">${v.warp_enabled ? 'WARP ON' : '直连'}</span></td>
        <td><span class="tag ${v.status === 'online' ? 'tag-green' : 'tag-amber'}">${v.status || '就绪'}</span></td>
        <td>
          <button class="btn btn-sm btn-blue" onclick="probeVPS(${v.id})">打靶探测</button>
          <button class="btn btn-sm btn-danger" onclick="delVPS(${v.id})">删除</button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (e) {
    console.warn('loadVPS error', e);
  }
}

window.probeVPS = async (id) => {
  try {
    alert(`正在对 VPS #${id} 执行 SSH 远端打靶探测...`);
    const res = await apiCall(`/vps/${id}/probe/`, { method: 'POST' });
    alert(`打靶完成! 纯净度评级: ${res.tier || 'OK'}, 出口评分: ${res.purity_score || 0}`);
    loadVPS();
  } catch (e) {
    alert(`探测失败: ${e.message}`);
  }
};

window.delVPS = async (id) => {
  if (!confirm(`确认删除 VPS 节点 #${id}？`)) return;
  try {
    await apiCall(`/vps/${id}/`, { method: 'DELETE' });
    loadVPS();
  } catch (e) {
    alert(`删除失败: ${e.message}`);
  }
};

async function loadSubs() {
  try {
    const subs = await apiCall('/subscriptions/');
    const list = (subs && subs.results) || subs || [];
    const tbody = $('subsTableBody');
    tbody.innerHTML = '';
    if (list.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;padding:16px;color:var(--muted)">暂无订阅记录</td></tr>';
      return;
    }
    list.forEach(s => {
      const tr = document.createElement('tr');
      const subUrl = `${location.origin}/sub/fetch?token=${s.uuid || s.token}`;
      tr.innerHTML = `
        <td><b>${escapeHtml(s.username || s.user)}</b></td>
        <td><span style="font-family:monospace;color:#93c5fd">${escapeHtml(s.slug || s.uuid || '—')}</span></td>
        <td><input type="text" class="input-text" style="width:280px" readonly value="${subUrl}" onclick="this.select()" /></td>
        <td>
          <button class="btn btn-sm btn-blue" onclick="navigator.clipboard.writeText('${subUrl}');alert('已复制订阅链接');">复制链接</button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (e) {
    console.warn('loadSubs error', e);
  }
}

async function loadLedger() {
  try {
    const data = await apiCall('/ledger/entries/');
    const list = (data && data.results) || data || [];
    const tbody = $('ledgerTableBody');
    tbody.innerHTML = '';
    if (list.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:16px;color:var(--muted)">暂无流水账单</td></tr>';
      return;
    }
    list.forEach(e => {
      const tr = document.createElement('tr');
      const isIncome = e.direction === 'IN';
      tr.innerHTML = `
        <td>#${e.id}</td>
        <td>${escapeHtml(e.created_at || '—')}</td>
        <td><span class="tag ${isIncome ? 'tag-green' : 'tag-red'}">${isIncome ? '入账' : '出账'}</span></td>
        <td><b>$${((e.amount_cents || 0) / 100).toFixed(2)}</b></td>
        <td>${escapeHtml(e.notes || e.description || '—')}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (e) {
    console.warn('loadLedger error', e);
  }
}

async function loadDiag() {
  try {
    $('diagOutput').textContent = '正在发起探测与全链路健康诊断...';
    const res = await apiCall('/health');
    $('diagOutput').textContent = JSON.stringify(res, null, 2);
  } catch (e) {
    $('diagOutput').textContent = `诊断请求异常: ${e.message}`;
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
