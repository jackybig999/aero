// ==============================================================================
// AERO VPN Middle-Platform Administration Console (Pure Go Native Micro-Frontend)
// 100% Full Restoration to Yesterday's Final Version (5c82197)
// ==============================================================================

const $ = (id) => document.getElementById(id);
const TOKEN_KEY = 'vpn_admin_token';
const USER_KEY = 'vpn_admin_user';

let currentTab = 'dashboard';
let userKind = 'staff'; // 'staff' | 'sub'
let cachedVpsList = [];
let cachedNodeList = [];
let cachedUserList = [];
let cachedLedgerList = [];
let ledgerFilter = 'all'; // 'all' | 'in' | 'out' | 'unsettled'
let autoProbeTimer = null;
let cfReady = false;

// ------------------------------------------------------------------------------
// Service Metadata & Classification (Matching Yesterday's Final Architecture)
// ------------------------------------------------------------------------------
const SVC_META = {
  'user-center': { label: '用户中心', group: '用户与订阅' },
  'billing': { label: '套餐计费', group: '用户与订阅' },
  'vpn-core': { label: '订阅服务', group: '用户与订阅' },
  'node-manager': { label: '节点管理', group: 'VPS 与节点' },
  'vps-manager': { label: 'VPS 资产', group: 'VPS 与节点' },
  'aero-deploy': { label: 'AERO 部署', group: 'VPS 与节点' },
  'scheduler': { label: '负载调度', group: 'VPS 与节点' },
  'failover-engine': { label: '故障切换', group: 'VPS 与节点' },
  'state-sync-engine': { label: '节点同步', group: 'VPS 与节点' },
  'payment-in': { label: '用户收款', group: '资金' },
  'payment-ledger': { label: '资金账本', group: '资金' },
  'settlement-engine': { label: '日清算', group: '资金' },
  'payment-out': { label: '企业归集', group: '资金' },
  'payment-test-module': { label: '模拟支付（测试）', group: '资金' },
  'config-center': { label: '系统配置', group: '系统' },
  'security-layer': { label: '安全防护', group: '系统' },
  'audit-log': { label: '操作审计', group: '系统' },
};

function buildSvcGroups(list) {
  const order = ['用户与订阅', 'VPS 与节点', '资金', '系统'];
  const map = {};
  for (const g of order) map[g] = [];
  for (const s of list || []) {
    const meta = SVC_META[s.name] || { label: s.name, group: '系统' };
    map[meta.group].push({ name: s.name, label: meta.label, status: s.status });
  }
  return order
    .filter(t => map[t] && map[t].length > 0)
    .map(t => {
      const items = map[t];
      const ok = items.filter(x => x.status === 'ok').length;
      return { title: t, items, ok, total: items.length, down: ok < items.length };
    });
}

// ------------------------------------------------------------------------------
// Utility Helpers
// ------------------------------------------------------------------------------
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

function fmtDate(t) {
  if (!t) return '—';
  try {
    const d = new Date(t);
    if (isNaN(d.getTime())) return String(t);
    return d.toLocaleString('zh-CN', { hour12: false });
  } catch {
    return String(t);
  }
}

function fmtUptime(sec) {
  const s = Number(sec) || 0;
  if (s <= 0) return '—';
  if (s < 60) return s + '秒';
  if (s < 3600) return Math.floor(s / 60) + '分';
  if (s < 86400) return Math.floor(s / 3600) + '时' + Math.floor((s % 3600) / 60) + '分';
  return Math.floor(s / 86400) + '天' + Math.floor((s % 86400) / 3600) + '时';
}

function clampPct(n) {
  const x = Number(n) || 0;
  return Math.max(0, Math.min(100, Math.round(x)));
}

// ------------------------------------------------------------------------------
// API Client
// ------------------------------------------------------------------------------
async function apiCall(endpoint, options = {}) {
  const token = localStorage.getItem(TOKEN_KEY);
  const headers = Object.assign({}, options.headers || {});
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  if (!headers['Content-Type'] && options.body && typeof options.body === 'string') {
    headers['Content-Type'] = 'application/json';
  }

  const url = endpoint.startsWith('http') ? endpoint : `/api/v1${endpoint}`;
  const res = await fetch(url, Object.assign({}, options, { headers }));

  if (res.status === 401 && !url.includes('/auth/login')) {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    showLogin(true);
    throw new Error('鉴权失效，请重新登录');
  }

  const data = await res.json().catch(() => ({}));
  if (data && typeof data === 'object' && 'code' in data && data.code !== 0) {
    throw new Error(data.message || `API 错误 (code ${data.code})`);
  }
  return data.data !== undefined ? data.data : data;
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
    dashboard: '总览',
    users: '用户',
    vps: 'VPS',
    aero: 'AERO',
    nodes: '节点',
    ledger: '账本',
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
  else if (currentTab === 'ledger') loadLedger();
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
      const token = res.token || res.access_token || res;
      if (token && typeof token === 'string') {
        localStorage.setItem(TOKEN_KEY, token);
        localStorage.setItem(USER_KEY, JSON.stringify(res));
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
    localStorage.removeItem(USER_KEY);
    showLogin(true);
  });

  // Sidebar Menu Clicks
  document.querySelectorAll('.menu-item').forEach(btn => {
    btn.addEventListener('click', () => {
      switchTab(btn.getAttribute('data-tab'));
    });
  });

  // Top Refresh
  $('btnTopRefresh')?.addEventListener('click', () => loadCurrentTab());

  // User Tab Buttons
  $('btnTabStaff')?.addEventListener('click', () => {
    userKind = 'staff';
    $('btnTabStaff').style.background = 'var(--card-active)';
    $('btnTabSub').style.background = 'transparent';
    $('btnOpenAddUser').textContent = '+ 新增管理员';
    $('btnBroadcastSubs').style.display = 'none';
    $('thSubUrl').style.display = 'none';
    renderUsers();
  });
  $('btnTabSub')?.addEventListener('click', () => {
    userKind = 'sub';
    $('btnTabSub').style.background = 'var(--card-active)';
    $('btnTabStaff').style.background = 'transparent';
    $('btnOpenAddUser').textContent = '+ 新增订阅用户';
    $('btnBroadcastSubs').style.display = 'inline-flex';
    $('thSubUrl').style.display = '';
    renderUsers();
  });

  // User Modals & Actions
  $('btnOpenAddUser')?.addEventListener('click', () => openUserModal());
  $('btnCancelUser')?.addEventListener('click', () => $('userModal').classList.remove('active'));
  $('btnSaveUser')?.addEventListener('click', saveUser);
  $('btnRefreshUsers')?.addEventListener('click', () => loadUsers());

  // Broadcast Subs
  $('btnBroadcastSubs')?.addEventListener('click', broadcastAllSubs);

  // Renew Modal
  $('btnCancelRenew')?.addEventListener('click', () => $('renewModal').classList.remove('active'));
  $('btnSubmitRenew')?.addEventListener('click', submitRenew);

  // VPS Modals & Actions
  $('btnOpenAddVPS')?.addEventListener('click', () => $('addVpsModal').classList.add('active'));
  $('btnCancelVPS')?.addEventListener('click', () => $('addVpsModal').classList.remove('active'));
  $('btnSaveVPS')?.addEventListener('click', saveVPS);
  $('btnRefreshProbeAll')?.addEventListener('click', () => refreshVpsAll());
  $('btnVerifyAllDomains')?.addEventListener('click', () => verifyAllDomains());

  // Auto Probe Checkbox
  $('chkAutoProbe')?.addEventListener('change', (e) => {
    if (autoProbeTimer) {
      clearInterval(autoProbeTimer);
      autoProbeTimer = null;
    }
    if (e.target.checked) {
      refreshVpsAll();
      autoProbeTimer = setInterval(() => refreshVpsAll(), 15000);
    }
  });

  // CF Sync in Add VPS Modal
  $('btnSyncCfVps')?.addEventListener('click', async () => {
    const ip = $('vpsIp').value.trim();
    const domain = $('vpsDomain').value.trim();
    if (!ip || !domain) return alert('请先填写公网 IP 和要绑定的域名');
    if (!domain.includes('.') || /^(\d{1,3}\.){3}\d{1,3}$/.test(domain)) {
      return alert('请输入有效的域名格式，严禁填写纯 IP！');
    }
    try {
      const res = await apiCall('/vps/cf-dns/sync/', {
        method: 'POST',
        body: JSON.stringify({ ip, domain })
      });
      alert(res.message || 'Cloudflare 灰云 A 记录同步成功');
    } catch (e) {
      alert(`CF 同步失败: ${e.message}`);
    }
  });

  // Edit Domain Modal
  $('btnCancelEditDomain')?.addEventListener('click', () => $('editDomainModal').classList.remove('active'));
  $('btnSaveEditDomain')?.addEventListener('click', saveEditDomain);
  $('btnSyncEditCf')?.addEventListener('click', async () => {
    const ip = $('editDomainVpsIp').value.trim();
    const domain = $('editDomainVal').value.trim();
    if (!domain) return alert('请输入域名');
    try {
      const res = await apiCall('/vps/cf-dns/sync/', {
        method: 'POST',
        body: JSON.stringify({ ip, domain })
      });
      alert(res.message || 'CF 灰云同步成功');
    } catch (e) {
      alert(`CF 同步失败: ${e.message}`);
    }
  });

  // Edit Password Modal
  $('btnCancelEditPass')?.addEventListener('click', () => $('editPassModal').classList.remove('active'));
  $('btnSaveEditPass')?.addEventListener('click', saveEditPass);

  // Nodes Modals & Actions
  $('btnOpenAddNode')?.addEventListener('click', () => $('nodeModal').classList.add('active'));
  $('btnCancelNode')?.addEventListener('click', () => $('nodeModal').classList.remove('active'));
  $('btnSaveNode')?.addEventListener('click', saveNode);
  $('btnSyncNodes')?.addEventListener('click', () => loadNodes());
  $('btnCleanOrphanNodes')?.addEventListener('click', cleanOrphanNodes);

  // Ledger Filter Buttons
  $('btnLedgerAll')?.addEventListener('click', () => filterLedger('all'));
  $('btnLedgerIn')?.addEventListener('click', () => filterLedger('in'));
  $('btnLedgerOut')?.addEventListener('click', () => filterLedger('out'));
  $('btnLedgerUnsettled')?.addEventListener('click', () => filterLedger('unsettled'));
  $('btnBatchSettle')?.addEventListener('click', doBatchSettle);
  $('btnDashSettle')?.addEventListener('click', doBatchSettle);
}

// ------------------------------------------------------------------------------
// Pane 1: Dashboard (总览)
// ------------------------------------------------------------------------------
async function loadDashboard() {
  try {
    // 1. Health & Service Classification
    const health = await fetch('/health').then(r => r.json()).catch(() => null);
    if (health && health.services) {
      const groups = buildSvcGroups(health.services);
      const total = health.services.length;
      const ok = health.services.filter(s => s.status === 'ok').length;
      $('kpiSvcCount').textContent = `${ok}/${total}`;
      
      const isAllOk = (ok === total && total > 0);
      $('dashCoreStatusTag').textContent = isAllOk ? '运行正常' : '部分异常';
      $('dashCoreStatusTag').className = `tag ${isAllOk ? 'tag-green' : 'tag-red'}`;

      const container = $('svcGroupsContainer');
      container.innerHTML = '';
      groups.forEach((g, idx) => {
        const groupEl = document.createElement('div');
        groupEl.className = 'svc-group';
        groupEl.innerHTML = `
          <div class="svc-group-hd" onclick="toggleSvcGroup(${idx})">
            <span>${g.title}</span>
            <span class="tag ${g.down ? 'tag-red' : 'tag-green'}">${g.ok}/${g.total}</span>
          </div>
          <div class="svc-group-body" id="svcGroupBody_${idx}">
            ${g.items.map(it => `
              <div class="svc-row">
                <span>${it.label}</span>
                <span class="tag ${it.status === 'ok' ? 'tag-green' : 'tag-red'}">${it.status === 'ok' ? '正常' : '异常'}</span>
              </div>
            `).join('')}
          </div>
        `;
        container.appendChild(groupEl);
      });
    }

    // 2. Ledger Summary & Unsettled
    const todayStr = new Date().toISOString().slice(0, 10);
    const summary = await apiCall(`/ledger/summary/?date=${todayStr}`).catch(() => null);
    if (summary) {
      const inVal = (Number(summary.total_in_cents || 0) / 100).toFixed(2);
      const outVal = (Number(summary.total_out_cents || 0) / 100).toFixed(2);
      $('kpiIncome').textContent = `$${inVal}`;
      $('dashLedgerIn').textContent = `+$${inVal}`;
      $('dashLedgerOut').textContent = `-$${outVal}`;
      $('dashLedgerCount').textContent = `${summary.entry_count || 0} 笔`;
    }

    const unsettled = await apiCall('/ledger/entries/unsettled/?direction=IN').catch(() => []);
    const unsettledList = (unsettled && (unsettled.results || unsettled.entries || (Array.isArray(unsettled) ? unsettled : []))) || [];
    let unsettledSum = 0;
    unsettledList.forEach(u => unsettledSum += Number(u.amount_cents || 0));
    $('dashLedgerUnsettled').textContent = `$${(unsettledSum / 100).toFixed(2)}`;

    // 3. VPS & Nodes & Users Counts
    const vpsRes = await apiCall('/vps/').catch(() => []);
    cachedVpsList = (vpsRes && vpsRes.results) || (Array.isArray(vpsRes) ? vpsRes : []);

    const nodesRes = await apiCall('/nodes/').catch(() => []);
    cachedNodeList = (nodesRes && nodesRes.results) || (Array.isArray(nodesRes) ? nodesRes : []);
    const onlineNodes = cachedNodeList.filter(n => n.status);
    $('kpiActiveNodes').textContent = `${onlineNodes.length}/${cachedNodeList.length}`;

    const usersRes = await apiCall('/users/').catch(() => []);
    cachedUserList = (usersRes && usersRes.results) || (Array.isArray(usersRes) ? usersRes : []);
    $('kpiUserCount').textContent = `${cachedUserList.length}人`;

  } catch (e) {
    console.warn('loadDashboard error', e);
  }
}

window.toggleSvcGroup = (idx) => {
  const el = $(`svcGroupBody_${idx}`);
  if (el) el.classList.toggle('collapsed');
};

// ------------------------------------------------------------------------------
// Pane 2: Users (用户)
// ------------------------------------------------------------------------------
async function loadUsers() {
  try {
    const res = await apiCall('/users/');
    cachedUserList = (res && res.results) || (Array.isArray(res) ? res : []);
    renderUsers();
  } catch (e) {
    console.warn('loadUsers error', e);
  }
}

function renderUsers() {
  const staff = cachedUserList.filter(u => u.is_staff);
  const sub = cachedUserList.filter(u => !u.is_staff);

  $('btnTabStaff').textContent = `管理员 (${staff.length})`;
  $('btnTabSub').textContent = `订阅用户 (${sub.length})`;

  const list = userKind === 'staff' ? staff : sub;
  const tbody = $('usersTableBody');
  tbody.innerHTML = '';

  if (list.length === 0) {
    tbody.innerHTML = `<tr><td colspan="10" style="text-align:center;padding:16px;color:var(--muted)">暂无${userKind === 'staff' ? '管理员' : '订阅用户'}</td></tr>`;
    return;
  }

  list.forEach(u => {
    const tr = document.createElement('tr');
    const isExp = u.expire_at && new Date(u.expire_at).getTime() < Date.now();
    const expireTag = u.is_staff
      ? '<span class="tag tag-blue">长期有效</span>'
      : (isExp
        ? `<span class="tag tag-red">已过期 (${fmtDate(u.expire_at).slice(0, 10)})</span>`
        : `<span class="tag tag-green">${u.expire_at ? fmtDate(u.expire_at).slice(0, 10) : '长期有效'}</span>`);

    const subUrl = u.sub_slug ? `${window.location.origin}/sub/${u.sub_slug}` : '';

    tr.innerHTML = `
      <td>#${u.id}</td>
      <td><b>${escapeHtml(u.username)}</b></td>
      <td>${escapeHtml(u.phone || '—')}</td>
      <td>${escapeHtml(u.email || '—')}</td>
      <td>
        <span class="tag ${u.is_staff ? 'tag-amber' : 'tag-blue'}">
          ${u.is_staff ? '系统管理' : (u.plan_name || '月度套餐')}
        </span>
      </td>
      <td>${u.is_staff ? '—' : ('$' + ((u.price_cents || 999) / 100).toFixed(2))}</td>
      <td>${expireTag}</td>
      ${userKind === 'sub' ? `
        <td>
          ${subUrl ? `
            <div style="display:flex;align-items:center;gap:6px">
              <input type="text" class="input-text" value="${subUrl}" readonly style="font-size:11px;width:180px;height:24px;padding:2px 6px;" />
              <button class="btn btn-sm btn-blue" onclick="copySubUrl('${subUrl}', '${escapeHtml(u.username)}')">复制</button>
            </div>
          ` : '<span class="tag tag-amber">未生成</span>'}
        </td>
      ` : ''}
      <td><span class="tag ${u.status ? 'tag-green' : 'tag-red'}">${u.status ? '正常' : '停用'}</span></td>
      <td>
        ${!u.is_staff ? `<button class="btn btn-sm" style="color:var(--green);border-color:var(--green)" onclick="openRenewModal(${u.id}, '${escapeHtml(u.username)}')">续费</button>` : ''}
        <button class="btn btn-sm" onclick="editUser(${u.id})">编辑</button>
        <button class="btn btn-sm btn-danger" onclick="delUser(${u.id})">删除</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

window.copySubUrl = (url, username) => {
  navigator.clipboard.writeText(url).then(() => {
    alert(`用户 [${username}] 专属订阅地址已复制到剪贴板`);
  }).catch(() => {
    prompt('请手动复制订阅地址：', url);
  });
};

function openUserModal(editUserObj = null) {
  $('editUserId').value = editUserObj ? editUserObj.id : '';
  $('userModalTitle').textContent = editUserObj ? '编辑用户' : (userKind === 'staff' ? '新增管理员' : '新增订阅用户');
  $('newUsername').value = editUserObj ? editUserObj.username : '';
  $('newUsername').disabled = !!editUserObj;
  $('pwdFieldWrap').style.display = editUserObj ? 'none' : 'block';
  $('newUserPass').value = '';
  $('newUserPhone').value = editUserObj ? (editUserObj.phone || '') : '';
  $('newUserEmail').value = editUserObj ? (editUserObj.email || '') : '';
  $('newUserRole').value = editUserObj ? (editUserObj.is_staff ? 'staff' : 'sub') : userKind;
  $('planFieldWrap').style.display = (editUserObj ? !editUserObj.is_staff : userKind !== 'staff') ? 'block' : 'none';
  $('userModal').classList.add('active');
}

window.editUser = (id) => {
  const u = cachedUserList.find(x => x.id === id);
  if (u) openUserModal(u);
};

async function saveUser() {
  const editId = $('editUserId').value;
  const username = $('newUsername').value.trim();
  const password = $('newUserPass').value.trim();
  const phone = $('newUserPhone').value.trim();
  const email = $('newUserEmail').value.trim();
  const is_staff = $('newUserRole').value === 'staff';
  const plan_months = parseInt($('newUserPlan').value, 10) || 1;

  if (!username) return alert('用户名不能为空');
  if (!editId && !password) return alert('初始密码不能为空');

  try {
    if (editId) {
      await apiCall(`/users/${editId}/`, {
        method: 'PATCH',
        body: JSON.stringify({ phone, email, is_staff, plan_months })
      });
      alert('保存成功');
    } else {
      await apiCall('/users/', {
        method: 'POST',
        body: JSON.stringify({ username, password, phone, email, is_staff, plan_months })
      });
      alert('用户创建成功');
    }
    $('userModal').classList.remove('active');
    loadUsers();
  } catch (e) {
    alert(`保存失败: ${e.message}`);
  }
}

window.openRenewModal = (id, username) => {
  $('renewUserId').value = id;
  $('renewUsername').value = username;
  $('renewModal').classList.add('active');
};

async function submitRenew() {
  const id = $('renewUserId').value;
  const months = parseInt($('renewPlanMonths').value, 10) || 1;
  try {
    await apiCall(`/users/${id}/renew/`, {
      method: 'POST',
      body: JSON.stringify({ months })
    });
    alert('续费成功并已记账入库');
    $('renewModal').classList.remove('active');
    loadUsers();
    loadDashboard();
  } catch (e) {
    alert(`续费失败: ${e.message}`);
  }
}

window.delUser = async (id) => {
  if (!confirm(`确认彻底删除用户 #${id}？`)) return;
  try {
    await apiCall(`/users/${id}/`, { method: 'DELETE' });
    alert('删除成功');
    loadUsers();
  } catch (e) {
    alert(`删除失败: ${e.message}`);
  }
};

async function broadcastAllSubs() {
  try {
    const res = await apiCall('/aero/subs/broadcast/', { method: 'POST', body: JSON.stringify({}) });
    alert(res.message || '一键同步用户凭证至所有 Edge VPS 成功');
  } catch (e) {
    alert(`同步失败: ${e.message}`);
  }
}

// ------------------------------------------------------------------------------
// Pane 3: VPS (VPS 资产与域名绑定 - 紧凑网格与实时指标)
// ------------------------------------------------------------------------------
async function loadVPS() {
  try {
    // 1. Check CF status
    const cf = await apiCall('/vps/cf-dns/status/').catch(() => null);
    cfReady = !!(cf && cf.configured);
    const badge = $('cfStatusBadge');
    if (badge) {
      badge.textContent = cfReady ? '🟢 Cloudflare 灰云自动化: 已就绪' : '⚪ Cloudflare: 未配置 Token (仅公网DNS)';
      badge.className = `tag ${cfReady ? 'tag-green' : 'tag-blue'}`;
    }

    // 2. Fetch VPS List
    const res = await apiCall('/vps/');
    cachedVpsList = (res && res.results) || (Array.isArray(res) ? res : []);
    renderVPS();
  } catch (e) {
    console.warn('loadVPS error', e);
  }
}

function renderVPS() {
  const container = $('vpsCardGrid');
  container.innerHTML = '';

  if (cachedVpsList.length === 0) {
    container.innerHTML = '<div class="metric-empty" style="grid-column:1/-1">尚未登记 VPS 节点</div>';
    return;
  }

  cachedVpsList.forEach(v => {
    const card = document.createElement('div');
    card.className = 'vps-card';

    // Status label & tag
    const isOnline = v.status === 'online';
    const statusTag = `<span class="tag ${isOnline ? 'tag-green' : 'tag-amber'}">${isOnline ? '在线' : (v.status || '离线')}</span>`;

    // DNS Tag
    let dnsTag = '<span class="tag tag-amber">🟡 DNS未解析</span>';
    if (v.dns_status === 'ok') dnsTag = '<span class="tag tag-green">🟢 DNS正常</span>';
    else if (v.dns_status === 'ip_mismatch') dnsTag = '<span class="tag tag-red">🔴 IP不匹配</span>';

    // Metrics Row
    const m = v.metrics;
    let metricsHtml = '';
    if (m && m.probe_ok) {
      const cpu = clampPct(m.cpu_percent);
      const mem = clampPct(m.mem_percent);
      const disk = clampPct(m.disk_percent);
      metricsHtml = `
        <div class="metric-compact-row">
          <div class="mc-item">
            <span class="mc-label">CPU</span>
            <span class="mc-val">${fmtNum(m.cpu_percent, 1)}%</span>
            <div class="progress-mini">
              <div class="progress-mini-bar" style="width:${cpu}%;background:${cpu >= 85 ? 'var(--red)' : (cpu >= 70 ? 'var(--amber)' : 'var(--blue)')}"></div>
            </div>
          </div>
          <div class="mc-divider"></div>
          <div class="mc-item">
            <span class="mc-label">内存</span>
            <span class="mc-val">${fmtNum(m.mem_percent, 1)}%</span>
            <span class="mc-sub">(${fmtNum(m.mem_used_mb)}M)</span>
          </div>
          <div class="mc-divider"></div>
          <div class="mc-item">
            <span class="mc-label">磁盘</span>
            <span class="mc-val">${fmtNum(m.disk_percent, 1)}%</span>
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
            <span class="mc-val">↓${fmtNum(m.net_rx_mbps, 1)} / ↑${fmtNum(m.net_tx_mbps, 1)}M</span>
          </div>
          <div class="mc-divider"></div>
          <div class="mc-item">
            <span class="mc-label">运行</span>
            <span class="mc-val">${fmtUptime(m.uptime_sec)}</span>
          </div>
        </div>
      `;
    } else {
      metricsHtml = `
        <div class="metric-empty">
          ${m && m.probe_error ? `探测失败: ${escapeHtml(m.probe_error)}` : '尚未采集运行状态，点击「探测」或开启自动探测'}
        </div>
      `;
    }

    card.innerHTML = `
      <div class="vps-card-hd">
        <div class="vps-id">
          <span class="tag tag-blue">${escapeHtml(v.role || 'node')}</span>
          <span class="vps-name">${escapeHtml(v.name)}</span>
          ${statusTag}
          ${dnsTag}
        </div>
        <div class="vps-actions">
          <button class="btn btn-sm" onclick="probeVPS(${v.id})">探测</button>
          <button class="btn btn-sm btn-blue" onclick="verifyDomainVPS(${v.id})">复核域名/CF</button>
          <button class="btn btn-sm" onclick="openEditDomain(${v.id})">改域名</button>
          <button class="btn btn-sm" onclick="openEditPass(${v.id})">改密码</button>
          <button class="btn btn-sm btn-danger" onclick="delVPS(${v.id})">删除</button>
        </div>
      </div>
      <div class="vps-meta">
        <span>${escapeHtml(v.ssh_username)}@${escapeHtml(v.ip)}:${v.ssh_port}</span>
        ${v.domain ? `<span>· <b>域名: ${escapeHtml(v.domain)}</b></span>` : ''}
        ${m && m.latency_ms != null ? `<span>· 延迟 ${m.latency_ms}ms</span>` : ''}
        ${m && m.os ? `<span>· ${escapeHtml(m.os)}/${escapeHtml(m.arch)}</span>` : ''}
        ${v.last_probe_at ? `<span>· 探测 ${fmtDate(v.last_probe_at).slice(5)}</span>` : ''}
      </div>
      ${metricsHtml}
    `;
    container.appendChild(card);
  });
}

async function saveVPS() {
  const name = $('vpsName').value.trim();
  const role = $('vpsRole').value;
  const ip = $('vpsIp').value.trim();
  const ssh_port = parseInt($('vpsSshPort').value, 10) || 22;
  const ssh_username = $('vpsSshUser').value.trim() || 'root';
  const ssh_password = $('vpsSshPass').value.trim();
  const domain = $('vpsDomain').value.trim();
  const remark = $('vpsRemark').value.trim();

  if (!name || !ip) return alert('名称和 IP 必填');
  if (!domain) return alert('节点域名为必填项：严禁未绑定域名的 VPS 接入，杜绝裸 IP 泄露！');
  if (!domain.includes('.') || /^(\d{1,3}\.){3}\d{1,3}$/.test(domain)) {
    return alert('请输入有效的公网域名格式（严禁填写纯 IP）！');
  }
  if (!ssh_password) return alert('请填写 SSH 密码（服务端 AES 加密存储，永不回显）');

  try {
    await apiCall('/vps/', {
      method: 'POST',
      body: JSON.stringify({ name, role, ip, ssh_port, ssh_username, ssh_password, domain, remark })
    });
    alert('VPS 节点已登记（域名校验通过 · 密码 AES 加密存储）');
    $('addVpsModal').classList.remove('active');
    $('vpsSshPass').value = '';
    loadVPS();
    loadDashboard();
  } catch (e) {
    alert(`登记失败: ${e.message}`);
  }
}

window.probeVPS = async (id) => {
  try {
    const res = await apiCall(`/vps/${id}/probe/`, { method: 'POST' });
    alert(`探测成功: 延迟 ${res.latency_ms || 0}ms · CPU ${res.cpu_percent || 0}%`);
    loadVPS();
  } catch (e) {
    alert(`探测异常: ${e.message}`);
  }
};

window.verifyDomainVPS = async (id) => {
  try {
    const res = await apiCall(`/vps/${id}/verify-domain/`, { method: 'POST' });
    alert(`复核完成: ${res.status || 'DNS OK'} · 对应 IP: ${res.resolved_ip || '—'}`);
    loadVPS();
  } catch (e) {
    alert(`复核失败: ${e.message}`);
  }
};

window.openEditDomain = (id) => {
  const v = cachedVpsList.find(x => x.id === id);
  if (!v) return;
  $('editDomainVpsId').value = v.id;
  $('editDomainVpsIp').value = v.ip;
  $('editDomainVal').value = v.domain || '';
  $('editDomainModalTitle').textContent = `修改 VPS [${v.name}] 域名与 CF 绑定`;
  $('editDomainModal').classList.add('active');
};

async function saveEditDomain() {
  const id = $('editDomainVpsId').value;
  const domain = $('editDomainVal').value.trim();
  if (!domain || !domain.includes('.')) return alert('请输入有效的域名');
  try {
    await apiCall(`/vps/${id}/`, {
      method: 'PATCH',
      body: JSON.stringify({ domain })
    });
    alert('域名已更新并触发 DNS 复核');
    $('editDomainModal').classList.remove('active');
    loadVPS();
  } catch (e) {
    alert(`更新失败: ${e.message}`);
  }
}

window.openEditPass = (id) => {
  const v = cachedVpsList.find(x => x.id === id);
  if (!v) return;
  $('editPassVpsId').value = v.id;
  $('editPassVpsAddr').value = `${v.name} (${v.ssh_username}@${v.ip}:${v.ssh_port})`;
  $('editPassVal').value = '';
  $('editPassModal').classList.add('active');
};

async function saveEditPass() {
  const id = $('editPassVpsId').value;
  const ssh_password = $('editPassVal').value.trim();
  if (!ssh_password) return alert('新密码不能为空');
  try {
    await apiCall(`/vps/${id}/`, {
      method: 'PATCH',
      body: JSON.stringify({ ssh_password })
    });
    alert('SSH 凭据已加密更新');
    $('editPassModal').classList.remove('active');
  } catch (e) {
    alert(`修改失败: ${e.message}`);
  }
}

window.delVPS = async (id) => {
  if (!confirm(`警告：确认彻底删除 VPS #${id}？将联动清理节点与关联订阅！`)) return;
  try {
    await apiCall(`/vps/${id}/`, { method: 'DELETE' });
    alert('已删除');
    loadVPS();
    loadDashboard();
  } catch (e) {
    alert(`删除失败: ${e.message}`);
  }
};

async function refreshVpsAll() {
  for (const v of cachedVpsList) {
    await apiCall(`/vps/${v.id}/probe/`, { method: 'POST' }).catch(() => null);
  }
  loadVPS();
}

async function verifyAllDomains() {
  for (const v of cachedVpsList) {
    await apiCall(`/vps/${v.id}/verify-domain/`, { method: 'POST' }).catch(() => null);
  }
  alert('批量复核完成');
  loadVPS();
}

// ------------------------------------------------------------------------------
// Pane 4: AERO (AERO 管理台)
// ------------------------------------------------------------------------------
function loadAERO() {
  const iframe = $('aeroIframe');
  if (iframe) {
    iframe.src = '/aero-ui/?mode=mid&embed=1';
  }
}

// ------------------------------------------------------------------------------
// Pane 5: Nodes (节点)
// ------------------------------------------------------------------------------
async function loadNodes() {
  try {
    const res = await apiCall('/nodes/');
    cachedNodeList = (res && res.results) || (Array.isArray(res) ? res : []);
    
    // Cross-check orphans
    const vpsIds = new Set(cachedVpsList.map(v => v.id));
    const vpsIps = new Set(cachedVpsList.map(v => v.ip));
    const orphans = cachedNodeList.filter(n => {
      if (n.vps_id && vpsIds.has(n.vps_id)) return false;
      if (n.ip && vpsIps.has(n.ip)) return false;
      return true;
    });

    const btnOrphan = $('btnCleanOrphanNodes');
    if (btnOrphan) {
      if (orphans.length > 0) {
        btnOrphan.style.display = 'inline-flex';
        btnOrphan.textContent = `清理失联节点 (${orphans.length})`;
      } else {
        btnOrphan.style.display = 'none';
      }
    }

    renderNodes(orphans);
  } catch (e) {
    console.warn('loadNodes error', e);
  }
}

function renderNodes(orphans = []) {
  const orphanIds = new Set(orphans.map(o => o.id));
  const tbody = $('nodesTableBody');
  tbody.innerHTML = '';

  if (cachedNodeList.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;padding:16px;color:var(--muted)">暂无节点 — 请到 VPS 页部署或手动登记</td></tr>';
    return;
  }

  cachedNodeList.forEach(n => {
    const isOrphan = orphanIds.has(n.id);
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>#${n.id}</td>
      <td><b>${escapeHtml(n.name)}</b></td>
      <td>${escapeHtml(n.ip)}:${n.port}</td>
      <td><span class="tag tag-blue">${escapeHtml(n.protocol || 'aero')}</span></td>
      <td>${isOrphan ? '<span class="tag tag-red">失联</span>' : `#${n.vps_id || '—'}`}</td>
      <td><span class="tag ${n.status ? 'tag-green' : 'tag-amber'}">${n.status ? '在线' : '离线'}</span></td>
      <td>${n.active_users || 0}/${n.max_users || 100}</td>
      <td>
        <button class="btn btn-sm" onclick="nodeHeartbeat(${n.id})">心跳</button>
        <button class="btn btn-sm btn-danger" onclick="delNode(${n.id})">删除</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

async function saveNode() {
  const name = $('newNodeName').value.trim();
  const ip = $('newNodeIp').value.trim();
  const port = parseInt($('newNodePort').value, 10) || 443;
  const protocol = $('newNodeProto').value;
  const max_users = parseInt($('newNodeMaxUsers').value, 10) || 100;
  const region = $('newNodeRegion').value.trim();

  if (!name || !ip) return alert('名称与 IP 必填');
  try {
    await apiCall('/nodes/', {
      method: 'POST',
      body: JSON.stringify({ name, ip, port, protocol, max_users, region })
    });
    alert('节点登记成功');
    $('nodeModal').classList.remove('active');
    $('newNodeName').value = '';
    $('newNodeIp').value = '';
    loadNodes();
  } catch (e) {
    alert(`登记失败: ${e.message}`);
  }
}

window.nodeHeartbeat = async (id) => {
  try {
    await apiCall(`/nodes/${id}/heartbeat/`, {
      method: 'POST',
      body: JSON.stringify({ agent_version: 'v2.5' })
    });
    alert('心跳检测已更新');
    loadNodes();
  } catch (e) {
    alert(`心跳失败: ${e.message}`);
  }
};

window.delNode = async (id) => {
  if (!confirm(`确认删除节点 #${id}？`)) return;
  try {
    await apiCall(`/nodes/${id}/`, { method: 'DELETE' });
    alert('已删除');
    loadNodes();
  } catch (e) {
    alert(`删除失败: ${e.message}`);
  }
};

async function cleanOrphanNodes() {
  if (!confirm('确认批量清理所有失联无归属节点？')) return;
  try {
    await apiCall('/nodes/orphan/', { method: 'DELETE' });
    alert('失联节点清理完毕');
    loadNodes();
  } catch (e) {
    alert(`清理失败: ${e.message}`);
  }
}

// ------------------------------------------------------------------------------
// Pane 6: Ledger (账本)
// ------------------------------------------------------------------------------
async function loadLedger() {
  try {
    const res = await apiCall('/ledger/entries/');
    cachedLedgerList = (res && (res.results || res.entries)) || (Array.isArray(res) ? res : []);
    renderLedger();
  } catch (e) {
    console.warn('loadLedger error', e);
  }
}

function filterLedger(mode) {
  ledgerFilter = mode;
  ['All', 'In', 'Out', 'Unsettled'].forEach(k => {
    const btn = $(`btnLedger${k}`);
    if (btn) btn.style.background = (mode.toLowerCase() === k.toLowerCase()) ? 'var(--card-active)' : 'transparent';
  });
  renderLedger();
}

function renderLedger() {
  let totalIn = 0;
  let totalOut = 0;
  const inEntries = [];
  const outEntries = [];
  const unsettledEntries = [];

  cachedLedgerList.forEach(item => {
    const amt = Number(item.amount_cents || 0);
    if (item.direction === 'IN') {
      totalIn += amt;
      inEntries.push(item);
      if (!item.settled) unsettledEntries.push(item);
    } else if (item.direction === 'OUT') {
      totalOut += amt;
      outEntries.push(item);
    }
  });

  $('btnLedgerAll').textContent = `全部明细 (${cachedLedgerList.length})`;
  $('btnLedgerIn').textContent = `入账 IN (${inEntries.length})`;
  $('btnLedgerOut').textContent = `出账 OUT (${outEntries.length})`;
  $('btnLedgerUnsettled').textContent = `待归集 (${unsettledEntries.length})`;
  $('ledgerCumulativeText').textContent = `累计入账: $${(totalIn / 100).toFixed(2)} · 累计出账: $${(totalOut / 100).toFixed(2)}`;

  let filtered = cachedLedgerList;
  if (ledgerFilter === 'in') filtered = inEntries;
  else if (ledgerFilter === 'out') filtered = outEntries;
  else if (ledgerFilter === 'unsettled') filtered = unsettledEntries;

  const tbody = $('ledgerTableBody');
  tbody.innerHTML = '';

  if (filtered.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:16px;color:var(--muted)">暂无账本记录</td></tr>';
    return;
  }

  filtered.forEach(e => {
    const isIncome = e.direction === 'IN';
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><code>${escapeHtml(e.ledger_no)}</code></td>
      <td>
        <span class="tag ${isIncome ? 'tag-green' : 'tag-amber'}">
          ${isIncome ? '收入 IN' : '支出 OUT'}
        </span>
      </td>
      <td>
        <b style="color:${isIncome ? 'var(--green)' : 'var(--amber)'}">
          ${isIncome ? '+' : '-'}$${((Number(e.amount_cents || 0)) / 100).toFixed(2)}
        </b>
      </td>
      <td>${escapeHtml(e.channel || 'Stripe')}</td>
      <td>
        <span class="tag ${e.settled ? 'tag-blue' : 'tag-amber'}">
          ${e.settled ? '已归集' : '待结算'}
        </span>
      </td>
      <td>${escapeHtml(e.channel_ref || '—')}</td>
      <td>${fmtDate(e.created_at)}</td>
    `;
    tbody.appendChild(tr);
  });
}

async function doBatchSettle() {
  if (!confirm('确认执行一键批量归集与自动结算？')) return;
  try {
    const res = await apiCall('/ledger/settle/batch/', {
      method: 'POST',
      body: JSON.stringify({ channel: 'PingPong', target_ref: '管理员归集操作' })
    });
    alert(res.message || '资金归集与结算执行完毕');
    loadLedger();
    loadDashboard();
  } catch (e) {
    alert(`结算失败: ${e.message}`);
  }
}
