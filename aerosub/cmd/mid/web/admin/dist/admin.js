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

function updateTopUser() {
  let name = '';
  try {
    const raw = localStorage.getItem(USER_KEY);
    if (raw) {
      const obj = JSON.parse(raw);
      name = obj.username || (obj.user && obj.user.username);
    }
  } catch {}
  if (!name) name = localStorage.getItem('last_admin_username') || 'admin';
  const el = $('topUser');
  if (el) el.textContent = name;
}

async function fetchCurrentUserFromDb() {
  try {
    const res = await apiCall('/auth/me/');
    if (res && res.username) {
      localStorage.setItem('last_admin_username', res.username);
      localStorage.setItem(USER_KEY, JSON.stringify(res));
      const el = $('topUser');
      if (el) el.textContent = res.username;
    }
  } catch (_) {}
}

function checkAuth() {
  const token = localStorage.getItem(TOKEN_KEY);
  if (!token) {
    showLogin(true);
  } else {
    showLogin(false);
    updateTopUser();
    fetchCurrentUserFromDb();
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
    subs: '订阅设置',
  };
  $('pageTitle').textContent = titles[tabId] || '管理后台';
  loadCurrentTab();
}

async function loadCurrentTab() {
  if (currentTab === 'dashboard') return await loadDashboard();
  else if (currentTab === 'users') return await loadUsers();
  else if (currentTab === 'vps') return await loadVPS();
  else if (currentTab === 'aero') return await loadAERO();
  else if (currentTab === 'nodes') return await loadNodes();
  else if (currentTab === 'ledger') return await loadLedger();
  else if (currentTab === 'subs') return await loadSubs();
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
        localStorage.setItem('last_admin_username', u);
      }
      showLogin(false);
      updateTopUser();
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

  // Sidebar Collapse Toggle
  $('btnToggleSidebar')?.addEventListener('click', () => {
    const sb = document.querySelector('.sidebar');
    if (!sb) return;
    sb.classList.toggle('collapsed');
    const isCollapsed = sb.classList.contains('collapsed');
    const icon = $('collapseIcon');
    if (icon) icon.textContent = isCollapsed ? '▶' : '◀';
    localStorage.setItem('admin_sidebar_collapsed', isCollapsed ? '1' : '0');
  });

  // Restore Sidebar Collapse State
  if (localStorage.getItem('admin_sidebar_collapsed') === '1') {
    document.querySelector('.sidebar')?.classList.add('collapsed');
    const icon = $('collapseIcon');
    if (icon) icon.textContent = '▶';
  }

  // Top Refresh with visual loading state
  $('btnTopRefresh')?.addEventListener('click', async () => {
    const btn = $('btnTopRefresh');
    if (!btn || btn.disabled) return;
    const oldText = btn.textContent;
    btn.disabled = true;
    btn.textContent = '🔄 刷新中...';
    try {
      await Promise.allSettled([
        loadCurrentTab(),
        fetchCurrentUserFromDb()
      ]);
    } finally {
      setTimeout(() => {
        btn.disabled = false;
        btn.textContent = oldText;
      }, 400);
    }
  });

  // Dashboard Svc Groups Toggle All
  $('btnToggleAllSvcGroups')?.addEventListener('click', () => toggleAllSvcGroups());

  // User Tab Buttons
  $('btnTabStaff')?.addEventListener('click', () => {
    userKind = 'staff';
    $('btnTabStaff').style.background = 'var(--card-active)';
    $('btnTabSub').style.background = 'transparent';
    $('btnOpenAddUser').textContent = '+ 新增管理员';
    $('btnBroadcastSubs').style.display = 'none';
    renderUsers();
  });
  $('btnTabSub')?.addEventListener('click', () => {
    userKind = 'sub';
    $('btnTabSub').style.background = 'var(--card-active)';
    $('btnTabStaff').style.background = 'transparent';
    $('btnOpenAddUser').textContent = '+ 新增订阅用户';
    $('btnBroadcastSubs').style.display = 'inline-flex';
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

  $('vpsSelectAll')?.addEventListener('change', (e) => {
    const on = e.target.checked;
    document.querySelectorAll('.vps-checkbox').forEach(cb => { cb.checked = on; });
    updateVpsSelectedCount();
  });

  // Cert Modal Listeners
  $('btnCloseCertModal')?.addEventListener('click', () => $('certModal')?.classList.remove('active'));
  $('btnCancelCertModal')?.addEventListener('click', () => $('certModal')?.classList.remove('active'));
  $('btnRefreshCert')?.addEventListener('click', () => {
    if (currentCertVpsId) refreshCertModal(currentCertVpsId);
  });
  $('btnRenewCertNormal')?.addEventListener('click', () => renewVpsCert(false));
  $('btnRenewCertForce')?.addEventListener('click', () => renewVpsCert(true));

  // VPS Detail Modal Listeners
  $('btnCloseVpsDetailModal')?.addEventListener('click', () => $('vpsDetailModal')?.classList.remove('active'));
  $('btnCancelVpsDetail')?.addEventListener('click', () => $('vpsDetailModal')?.classList.remove('active'));
  $('btnProbeFromDetail')?.addEventListener('click', async () => {
    if (!currentDetailVpsId) return;
    await probeVPS(currentDetailVpsId);
    const v = cachedVpsList.find(x => x.id === currentDetailVpsId);
    if (v) renderVpsDetailContent(v);
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

  // Subs Tab Events
  $('btnRefreshPlans')?.addEventListener('click', () => loadPlansTable());
  $('btnOpenAddPlan')?.addEventListener('click', () => openAddPlanModal());
  $('btnClosePlanModal')?.addEventListener('click', () => $('planModal').classList.remove('active'));
  $('btnCancelPlanModal')?.addEventListener('click', () => $('planModal').classList.remove('active'));
  $('btnSavePlanModal')?.addEventListener('click', savePlanModal);
  $('btnRefreshSubs')?.addEventListener('click', () => loadSubsTable());
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
            <span><span class="svc-arrow" id="svcArrow_${idx}">▼</span>${g.title}</span>
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

let allGroupsCollapsed = false;

window.toggleSvcGroup = (idx) => {
  const body = $(`svcGroupBody_${idx}`);
  const arrow = $(`svcArrow_${idx}`);
  if (body) {
    const isCollapsed = body.classList.toggle('collapsed');
    if (arrow) arrow.textContent = isCollapsed ? '▶' : '▼';
  }
};

window.toggleAllSvcGroups = () => {
  allGroupsCollapsed = !allGroupsCollapsed;
  const bodies = document.querySelectorAll('.svc-group-body');
  bodies.forEach(b => b.classList.toggle('collapsed', allGroupsCollapsed));
  const arrows = document.querySelectorAll('.svc-arrow');
  arrows.forEach(a => a.textContent = allGroupsCollapsed ? '▶' : '▼');
  const btn = $('btnToggleAllSvcGroups');
  if (btn) btn.textContent = allGroupsCollapsed ? '▶ 全部展开' : '▼ 全部折叠';
};

// ------------------------------------------------------------------------------
// Pane 2: Users (用户)
// ------------------------------------------------------------------------------
function getPrimaryVpsDomain() {
  if (cachedVpsList && cachedVpsList.length > 0) {
    const onlineWithDomain = cachedVpsList.find(v => v.domain && v.status === 'online');
    if (onlineWithDomain) return onlineWithDomain.domain;
    const withDomain = cachedVpsList.find(v => v.domain);
    if (withDomain) return withDomain.domain;
  }
  if (cachedNodeList && cachedNodeList.length > 0) {
    const n = cachedNodeList.find(x => x.address && !/^\d{1,3}\./.test(x.address));
    if (n) return n.address.split(':')[0];
  }
  if (window.location && window.location.hostname && !/^\d{1,3}\./.test(window.location.hostname) && window.location.hostname !== 'localhost') {
    return window.location.hostname;
  }
  return 'domain.com';
}

function subURL(slug) {
  const domain = getPrimaryVpsDomain();
  return `https://${domain}/sub/${slug}`;
}

async function loadUsers() {
  try {
    if (!cachedVpsList || cachedVpsList.length === 0) {
      const vpsRes = await apiCall('/vps/').catch(() => []);
      cachedVpsList = (vpsRes && vpsRes.results) || (Array.isArray(vpsRes) ? vpsRes : []);
    }
    if (!cachedNodeList || cachedNodeList.length === 0) {
      const nodeRes = await apiCall('/nodes/').catch(() => []);
      cachedNodeList = (nodeRes && nodeRes.results) || (Array.isArray(nodeRes) ? nodeRes : []);
    }
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

    let subUrl = '';
    if (u.is_staff) {
      const slug = u.sub_slug || 'superadmin';
      subUrl = subURL(slug);
    } else if (u.sub_slug) {
      subUrl = subURL(u.sub_slug);
    }

    let subColHtml = '';
    if (u.is_staff) {
      const slug = u.sub_slug || 'superadmin';
      subUrl = subURL(slug);
      const activeNodes = (cachedNodeList && cachedNodeList.filter(n => n.status)) || [];
      const liveCount = activeNodes.length;

      if (liveCount === 0) {
        subColHtml = `
          <td>
            <div style="display:flex;align-items:center;gap:6px">
              <input type="text" class="input-text" value="" placeholder="暂无可用节点 (0 个节点)" readonly style="font-size:11px;width:240px;height:24px;padding:2px 6px;color:var(--text-muted);background:rgba(255,255,255,0.02)" />
              <button class="btn btn-sm btn-blue" disabled style="opacity:0.5;cursor:not-allowed">复制</button>
              <span class="tag tag-red" style="white-space:nowrap">⚠️ 暂无可用节点 (0 个)</span>
            </div>
          </td>
        `;
      } else {
        subColHtml = `
          <td>
            <div style="display:flex;align-items:center;gap:6px">
              <input type="text" class="input-text" value="${subUrl}" readonly style="font-size:11px;width:240px;height:24px;padding:2px 6px;" />
              <button class="btn btn-sm btn-blue" onclick="copySubUrl('${subUrl}', '${escapeHtml(u.username)}')">复制</button>
              <span class="tag tag-amber" style="white-space:nowrap">实时管理订阅 · 已就绪 ${liveCount} 个节点</span>
            </div>
          </td>
        `;
      }
    } else if (u.subscriptions && u.subscriptions.length > 0) {
      const subItems = u.subscriptions.map((s, idx) => {
        const url = subURL(s.sub_slug);
        const nodeStr = (s.assigned_nodes && s.assigned_nodes.length) ? s.assigned_nodes.join(',') : '智能全节点';
        const isSwOn = s.switch_status === 'on';
        const branchTag = u.subscriptions.length > 1
          ? `<span style="font-family:monospace;font-size:10px;color:var(--text-muted);white-space:nowrap">分支${idx + 1} ├─</span>`
          : '';
        return `
          <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px;padding:3px 4px;background:rgba(255,255,255,0.02);border-radius:4px">
            ${branchTag}
            <input type="text" class="input-text" value="${url}" readonly style="font-size:11px;width:210px;height:22px;padding:1px 5px;" />
            <button class="btn btn-sm btn-blue" style="padding:1px 6px;font-size:11px" onclick="copySubUrl('${url}', '${escapeHtml(u.username)}')">复制</button>
            <button class="btn btn-sm ${isSwOn ? 'btn-green' : 'btn-danger'}" style="padding:1px 6px;font-size:10px" title="独立总开关" onclick="toggleSubSwitch('${s.sub_id}', '${s.switch_status}').then(() => loadUsers())">
              ${isSwOn ? 'ON' : 'OFF'}
            </button>
            <span class="tag tag-blue" style="white-space:nowrap;font-size:10px">${escapeHtml(s.plan_name || '套餐')}</span>
            <span class="tag tag-blue" style="white-space:nowrap;font-size:10px">${escapeHtml(nodeStr)}</span>
            <button class="btn btn-sm btn-danger" style="padding:1px 5px;font-size:10px" title="删除该订阅分支" onclick="deleteSub('${s.sub_id}').then(() => loadUsers())">删</button>
          </div>
        `;
      }).join('');
      subColHtml = `
        <td>
          ${subItems}
        </td>
      `;
    } else if (u.sub_slug && u.plan_name && u.expire_at && new Date(u.expire_at).getTime() > Date.now()) {
      subUrl = subURL(u.sub_slug);
      subColHtml = `
        <td>
          <div style="display:flex;align-items:center;gap:6px">
            <input type="text" class="input-text" value="${subUrl}" readonly style="font-size:11px;width:210px;height:24px;padding:2px 6px;" />
            <button class="btn btn-sm btn-blue" onclick="copySubUrl('${subUrl}', '${escapeHtml(u.username)}')">复制</button>
            <span class="tag tag-blue" style="white-space:nowrap;font-size:10px">主订阅</span>
          </div>
        </td>
      `;
    } else {
      subColHtml = `
        <td><span class="tag tag-amber">暂无订阅</span></td>
      `;
    }

    tr.innerHTML = `
      <td>#${u.id}</td>
      <td><b>${escapeHtml(u.username)}</b></td>
      <td>${escapeHtml(u.phone || '—')}</td>
      <td>${escapeHtml(u.email || '—')}</td>
      <td>
        <span class="tag ${u.is_staff ? 'tag-amber' : (u.plan_name ? 'tag-blue' : 'tag-muted')}">
          ${u.is_staff ? '系统管理' : (u.plan_name || '未开通')}
        </span>
      </td>
      <td>${u.is_staff ? '—' : (u.price_cents ? ('¥' + (u.price_cents / 100).toFixed(2)) : '—')}</td>
      <td>${expireTag}</td>
      ${subColHtml}
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
    alert(`[${username}] 专属订阅地址已复制到剪贴板:\n${url}`);
  }).catch(() => {
    prompt('请手动复制订阅地址：', url);
  });
};

function openUserModal(editUserObj = null) {
  $('editUserId').value = editUserObj ? editUserObj.id : '';
  $('userModalTitle').textContent = editUserObj ? '编辑用户' : (userKind === 'staff' ? '新增管理员' : '新增订阅用户');
  $('newUsername').value = editUserObj ? editUserObj.username : '';
  $('newUsername').disabled = false;
  $('pwdFieldWrap').style.display = 'block';
  const lblPass = $('lblUserPass');
  if (lblPass) {
    lblPass.textContent = editUserObj ? '修改密码 (留空则保持原密码不变)' : '初始密码 (至少8位字母+数字)';
  }
  $('newUserPass').value = '';
  $('newUserPass').placeholder = editUserObj ? '留空保持原密码不变' : '至少8位字母数字组合';
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
  if (!/^[a-zA-Z0-9_]{3,32}$/.test(username)) {
    return alert('用户名须为3-32位英文字母、数字或下划线');
  }

  if (!editId) {
    if (!password) return alert('初始密码不能为空');
    if (password.length < 8 || !/[a-zA-Z]/.test(password) || !/[0-9]/.test(password)) {
      return alert('密码须至少8位，且包含字母与数字组合');
    }
  } else if (password) {
    if (password.length < 8 || !/[a-zA-Z]/.test(password) || !/[0-9]/.test(password)) {
      return alert('新密码须至少8位，且包含字母与数字组合');
    }
  }

  try {
    if (editId) {
      const patchData = { username, phone, email, is_staff, plan_months };
      if (password) {
        patchData.password = password;
      }
      await apiCall(`/users/${editId}/`, {
        method: 'PATCH',
        body: JSON.stringify(patchData)
      });
      alert('更新用户成功');
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
let currentCertVpsId = null;
let currentDetailVpsId = null;
const vpsCertCache = {};

async function loadVPS() {
  try {
    // 1. Check CF status
    const cf = await apiCall('/vps/cf-dns/status/').catch(() => null);
    cfReady = !!(cf && cf.configured);
    const badge = $('cfStatusTag');
    if (badge) {
      badge.textContent = cfReady ? '🟢 Cloudflare 灰云自动化: 已就绪' : '⚪ Cloudflare: 未配置 Token (仅公网DNS)';
      badge.className = `tag ${cfReady ? 'tag-green' : 'tag-blue'}`;
    }

    // 2. Fetch VPS List
    const res = await apiCall('/vps/');
    cachedVpsList = (res && res.results) || (Array.isArray(res) ? res : []);
    renderVPS();

    // 自动对已绑定域名的节点异步获取统一 TLS 证书状态，杜绝待检测或脏缓存
    cachedVpsList.forEach(v => {
      if (v.domain) {
        apiCall(`/vps/${v.id}/diagnose/`).then(d => {
          if (d && d.cert) {
            vpsCertCache[v.id] = d.cert;
            renderVPS();
          }
        }).catch(() => {});
      }
    });
  } catch (e) {
    console.warn('loadVPS error', e);
  }
}

function updateVpsSelectedCount() {
  const all = document.querySelectorAll('.vps-checkbox');
  const checked = document.querySelectorAll('.vps-checkbox:checked');
  const countText = $('vpsCountText');
  if (countText) {
    countText.textContent = `共 ${all.length} 台 VPS 节点 · 已选中 ${checked.length} 台`;
  }
}
window.updateVpsSelectedCount = updateVpsSelectedCount;

function getSelectedVpsIds() {
  const checked = document.querySelectorAll('.vps-checkbox:checked');
  return Array.from(checked).map(cb => parseInt(cb.value, 10)).filter(Boolean);
}

function renderVPS() {
  const tbody = $('vpsTableBody');
  if (!tbody) return;
  tbody.innerHTML = '';

  if (cachedVpsList.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:24px;color:var(--muted)">尚未登记 VPS 节点</td></tr>';
    updateVpsSelectedCount();
    return;
  }

  cachedVpsList.forEach(v => {
    const tr = document.createElement('tr');
    const isOnline = v.status === 'online';
    const statusTag = `<span class="tag ${isOnline ? 'tag-green' : 'tag-amber'}">${isOnline ? '正常' : (v.status || '离线')}</span>`;

    // DNS Tag
    let dnsTag = '<span class="tag tag-amber">⚪ 待复核</span>';
    const d = v.dns_status;
    if (d) {
      if (typeof d === 'object') {
        if (d.is_cf_proxy) dnsTag = '<span class="tag tag-red">⚠️ 开启了CF代理(橙云)</span>';
        else if (d.matched) dnsTag = '<span class="tag tag-green">🟢 灰云直连正常</span>';
        else dnsTag = '<span class="tag tag-red">🔴 IP不匹配</span>';
      } else if (d === 'ok') {
        dnsTag = '<span class="tag tag-green">🟢 DNS正常</span>';
      }
    }

    // TLS Cert Tag
    const cert = vpsCertCache[v.id] || (v.metrics && v.metrics.cert);
    let certTag = '<span class="tag tag-blue">⚪ 待检测</span>';
    if (cert) {
      if (cert.ok) {
        const days = cert.days_left != null ? `${cert.days_left}天` : '有效';
        certTag = `<span class="tag tag-green" title="${escapeHtml(cert.detail || '')}">🟢 有效 (${days})</span>`;
      } else {
        certTag = `<span class="tag tag-red" title="${escapeHtml(cert.detail || '')}">🔴 异常 / 待签发</span>`;
      }
    }

    // Latency / Health Tag
    const m = v.metrics;
    let latencyTag = '<span class="tag tag-blue">⚪ 待探测</span>';
    if (m && m.probe_ok) {
      const ms = m.latency_ms;
      if (ms != null) {
        if (ms < 100) latencyTag = `<span class="tag tag-green">🟢 极速 (${ms}ms)</span>`;
        else if (ms < 250) latencyTag = `<span class="tag tag-blue">🔵 良好 (${ms}ms)</span>`;
        else latencyTag = `<span class="tag tag-amber">🟡 延迟 (${ms}ms)</span>`;
      } else {
        latencyTag = '<span class="tag tag-green">🟢 运行正常</span>';
      }
    } else if (v.status === 'offline') {
      latencyTag = '<span class="tag tag-red">🔴 离线</span>';
    }

    tr.innerHTML = `
      <td style="text-align:center"><input type="checkbox" class="vps-checkbox" value="${v.id}" onchange="updateVpsSelectedCount()" /></td>
      <td>
        <div style="display:flex;align-items:center;gap:6px">
          <span class="tag tag-blue">${escapeHtml(v.role || 'node')}</span>
          <b style="font-size:13px">${escapeHtml(v.name)}</b>
          ${statusTag}
        </div>
      </td>
      <td><span class="mono">${escapeHtml(v.ip)}:${v.ssh_port}</span></td>
      <td>
        <div style="display:flex;align-items:center;gap:6px">
          <span class="mono" style="font-weight:500">${escapeHtml(v.domain || '（未绑定）')}</span>
          ${dnsTag}
        </div>
      </td>
      <td>
        <div style="display:flex;align-items:center;gap:6px">
          ${certTag}
          <button class="btn btn-sm btn-blue" onclick="openCertModal(${v.id})">管理</button>
        </div>
      </td>
      <td>
        <div style="display:flex;align-items:center;gap:6px">
          ${latencyTag}
          <button class="btn btn-sm" onclick="openVpsDetailModal(${v.id})">详情</button>
        </div>
      </td>
      <td style="text-align:right">
        <div class="vps-row-actions">
          <button class="btn btn-sm" onclick="probeVPS(${v.id})">探测</button>
          <button class="btn btn-sm btn-blue" onclick="verifyDomainVPS(${v.id})">复核/CF</button>
          <button class="btn btn-sm" onclick="openEditDomain(${v.id})">改域名</button>
          <button class="btn btn-sm" onclick="openEditPass(${v.id})">改密码</button>
          <button class="btn btn-sm btn-danger" onclick="delVPS(${v.id})">删除</button>
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  });

  updateVpsSelectedCount();
}

window.openCertModal = async (id) => {
  const v = cachedVpsList.find(x => x.id === id);
  if (!v) return;
  currentCertVpsId = id;
  $('certModalTitle').innerHTML = `<span>🔒 TLS 证书管理 · ${escapeHtml(v.name)} (${escapeHtml(v.domain || v.ip)})</span>`;
  $('certDomainText').textContent = v.domain || '未绑定域名';
  $('certModal')?.classList.add('active');
  await refreshCertModal(id);
};

async function refreshCertModal(id) {
  const v = cachedVpsList.find(x => x.id === id);
  try {
    $('certStatusTag').innerHTML = '<span class="tag tag-blue">正在进行 443 原生 TLS 探测...</span>';
    const diag = await apiCall(`/vps/${id}/diagnose/`);
    if (diag && diag.cert) {
      vpsCertCache[id] = diag.cert;
      const c = diag.cert;
      $('certModeText').textContent = c.mode || 'autocert (Let\'s Encrypt ECC-256)';
      $('certDomainText').textContent = c.domain || (v?.domain || '—');
      $('certStatusTag').innerHTML = c.ok
        ? `<span class="tag tag-green">🟢 有效正常 (${c.detail || ''})</span>`
        : `<span class="tag tag-red">🔴 异常 / 待签发 (${c.detail || ''})</span>`;
      $('certExpiryText').textContent = c.not_after || '—';
      $('certDaysLeftText').textContent = c.days_left != null ? `${c.days_left} 天` : '—';
      $('certDirText').textContent = `${c.file_count || 1} 个证书文件 · ${c.dir || '/var/lib/aero/certs'}`;
    } else {
      $('certStatusTag').innerHTML = '<span class="tag tag-amber">未检测到有效证书</span>';
    }
    renderVPS();
  } catch (e) {
    $('certStatusTag').innerHTML = `<span class="tag tag-red">探测失败: ${escapeHtml(e.message)}</span>`;
  }
}

async function renewVpsCert(force) {
  if (!currentCertVpsId) return;
  const btn = force ? $('btnRenewCertForce') : $('btnRenewCertNormal');
  const oldText = btn.textContent;
  btn.textContent = '执行中...';
  btn.disabled = true;
  try {
    const res = await apiCall(`/vps/${currentCertVpsId}/cert/renew/`, {
      method: 'POST',
      body: JSON.stringify({ force })
    });
    alert(res.message || '证书签发/续签流程执行完毕，已通知服务重载');
    await refreshCertModal(currentCertVpsId);
  } catch (e) {
    alert(`证书操作失败: ${e.message}`);
  } finally {
    btn.textContent = oldText;
    btn.disabled = false;
  }
}

window.openVpsDetailModal = (id) => {
  const v = cachedVpsList.find(x => x.id === id);
  if (!v) return;
  currentDetailVpsId = id;
  $('vpsDetailTitle').innerHTML = `<span>🖥️ [${escapeHtml(v.name)}] 节点硬件与系统底层明细</span>`;
  renderVpsDetailContent(v);
  $('vpsDetailModal')?.classList.add('active');
};

function renderVpsDetailContent(v) {
  const m = v.metrics || {};
  const container = $('vpsDetailContent');
  if (!container) return;

  container.innerHTML = `
    <div class="detail-grid-item">
      <span class="k">操作系统 / 架构</span>
      <span class="v">${escapeHtml(m.os || 'Linux')} / ${escapeHtml(m.arch || 'x86_64')}</span>
    </div>
    <div class="detail-grid-item">
      <span class="k">系统负载 (1m / 5m / 15m)</span>
      <span class="v">${fmtNum(m.load_1, 2)} / ${fmtNum(m.load_5, 2)} / ${fmtNum(m.load_15, 2)}</span>
    </div>
    <div class="detail-grid-item">
      <span class="k">实时网络带宽</span>
      <span class="v">↓ ${fmtNum(m.net_rx_mbps, 1)} Mbps · ↑ ${fmtNum(m.net_tx_mbps, 1)} Mbps</span>
    </div>
    <div class="detail-grid-item">
      <span class="k">系统运行时间</span>
      <span class="v">${fmtUptime(m.uptime_sec)}</span>
    </div>
    <div class="detail-grid-item">
      <span class="k">物理内存使用</span>
      <span class="v">${fmtNum(m.mem_used_mb)} MB / ${fmtNum(m.mem_total_mb)} MB (${fmtNum(m.mem_percent)}%)</span>
    </div>
    <div class="detail-grid-item">
      <span class="k">磁盘存储使用</span>
      <span class="v">${fmtNum(m.disk_used_gb)} GB / ${fmtNum(m.disk_total_gb)} GB (${fmtNum(m.disk_percent)}%)</span>
    </div>
    <div class="detail-grid-item">
      <span class="k">SSH 凭证与端点</span>
      <span class="v mono">${escapeHtml(v.ssh_username)}@${escapeHtml(v.ip)}:${v.ssh_port}</span>
    </div>
    <div class="detail-grid-item" style="grid-column: 1 / -1; display:flex; justify-content:space-between; align-items:center; background:#0d1527; padding:10px 14px; border:1px solid #1f2c47; border-radius:6px">
      <div>
        <div style="font-weight:600; font-size:13px; color:#e2e8f0; margin-bottom:4px">
          🛡️ 出口 IP 纯净度评测: 
          <span style="color:${(v.purity_score >= 90) ? 'var(--green)' : ((v.purity_score >= 40) ? 'var(--blue)' : 'var(--amber)')}; font-size:15px; font-weight:700">
            ${(v.purity_score !== undefined && v.purity_score !== null && v.purity_score > 0) ? (v.purity_score + ' 分') : (v.last_purity_probe_at ? (v.purity_score + ' 分') : '待打靶 (Google/CF)')}
          </span>
        </div>
        <div style="font-size:11px; color:var(--muted); display:flex; gap:12px; flex-wrap:wrap">
          <span>Google: <b style="color:${v.google_clean ? 'var(--green)' : 'var(--amber)'}">${v.google_clean ? '🟢 畅通 (+60分)' : '🔴 拦截/未测'}</b></span>
          <span>Cloudflare: <b style="color:${v.cf_clean ? 'var(--green)' : 'var(--amber)'}">${v.cf_clean ? '🟢 畅通 (+40分)' : '🔴 拦截/未测'}</b></span>
          <span>AI 平台: <b style="color:${!v.ai_blocked ? 'var(--green)' : 'var(--red)'}">${!v.ai_blocked ? '🟢 未封锁' : '🔴 触发拦截'}</b></span>
          <span>出口状态: <b style="color:#94a3b8">${v.is_warp_egress ? 'WARP 外挂' : '双栈原生出口'}</b></span>
        </div>
      </div>
      <button class="btn btn-sm btn-blue" id="btnDetailPurityProbe" onclick="probeVpsPurityDetail(${v.id})" style="white-space:nowrap">
        🎯 立即打靶检测
      </button>
    </div>
  `;
}

window.probeVpsPurityDetail = async (id) => {
  const btn = $('btnDetailPurityProbe');
  if (btn) {
    btn.disabled = true;
    btn.textContent = '🎯 正在打靶 (Google/CF/AI)...';
  }
  try {
    const res = await apiCall(`/vps/${id}/purity-probe/`, { method: 'POST' });
    alert(`打靶完成！评分: ${res.purity_score || 0}分 · Google: ${res.google_clean ? '畅通' : '拦截'} · CF: ${res.cf_clean ? '畅通' : '拦截'}`);
    const vpsRes = await apiCall('/vps/').catch(() => []);
    cachedVpsList = (vpsRes && vpsRes.results) || (Array.isArray(vpsRes) ? vpsRes : []);
    const updated = cachedVpsList.find(x => x.id === id);
    if (updated) renderVpsDetailContent(updated);
    renderVPS();
  } catch (e) {
    alert(`打靶检测失败: ${e.message}`);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = '🎯 重新打靶';
    }
  }
};

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
    const ipStr = (res.resolved_ips && res.resolved_ips.length > 0) ? res.resolved_ips.join(', ') : '无有效公网解析';
    const tag = res.matched ? '✅ 匹配成功' : (res.is_cf_proxy ? '☁️ Cloudflare 代理' : '⚠️ 不匹配');
    alert(`【DNS 复核完成 · ${tag}】\n\n判定状态: ${res.status_text || '正常'}\n公网解析 IP: ${ipStr}\nVPS 节点 IP: ${res.vps_ip || '—'}`);
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
    loadNodes();
    loadDashboard();
  } catch (e) {
    alert(`删除失败: ${e.message}`);
  }
};

async function refreshVpsAll() {
  const selected = getSelectedVpsIds();
  const targets = selected.length ? cachedVpsList.filter(v => selected.includes(v.id)) : cachedVpsList;
  const btn = $('btnRefreshProbeAll');
  const oldText = btn ? btn.textContent : '';
  if (btn) { btn.textContent = `探测中 (${targets.length})...`; btn.disabled = true; }
  for (const v of targets) {
    await apiCall(`/vps/${v.id}/probe/`, { method: 'POST' }).catch(() => null);
  }
  if (btn) { btn.textContent = oldText; btn.disabled = false; }
  loadVPS();
}

async function verifyAllDomains() {
  const selected = getSelectedVpsIds();
  const targets = selected.length ? cachedVpsList.filter(v => selected.includes(v.id)) : cachedVpsList;
  const btn = $('btnVerifyAllDomains');
  const oldText = btn ? btn.textContent : '';
  if (btn) { btn.textContent = `复核中 (${targets.length})...`; btn.disabled = true; }
  for (const v of targets) {
    await apiCall(`/vps/${v.id}/verify-domain/`, { method: 'POST' }).catch(() => null);
  }
  if (btn) { btn.textContent = oldText; btn.disabled = false; }
  alert('批量复核域名与 Cloudflare 完成');
  loadVPS();
}

// ------------------------------------------------------------------------------
// Pane 4: AERO (AERO 原生运维控制台，零 iframe 嵌套，单端口一体化)
// ------------------------------------------------------------------------------
let currentAeroVpsId = '';
let activeAeroTaskId = null;
let aeroTaskPollTimer = null;
let aeroEventsInitialized = false;

async function loadAERO() {
  if (!aeroEventsInitialized) {
    initAeroEvents();
    aeroEventsInitialized = true;
  }
  await loadAeroSourceStatus();
  await loadAeroVpsList();
  await loadAeroTasks();
  if (currentAeroVpsId) {
    await loadAeroDiagnose(currentAeroVpsId);
  }
}

async function loadAeroSourceStatus() {
  try {
    const st = await apiCall('/aero/source-status/');
    const alertBox = $('aeroSourceAlert');
    if (alertBox) {
      if (st && st.status === 'warning') {
        alertBox.style.display = 'flex';
        $('aeroSourceAlertText').textContent = st.message || '检测到官方 Release 包未发布。';
      } else {
        alertBox.style.display = 'none';
      }
    }
  } catch (e) {
    console.warn('loadAeroSourceStatus error', e);
  }
}

async function loadAeroVpsList() {
  const sel = $('aeroVpsSelect');
  if (!sel) return;
  try {
    const list = await apiCall('/aero/vps-options/').catch(() => []);
    const items = (list && list.results) || (Array.isArray(list) ? list : []);
    if (!items.length) {
      sel.innerHTML = '<option value="">暂无已登记的 VPS 主机</option>';
      currentAeroVpsId = '';
      return;
    }
    sel.innerHTML = items.map(v => `
      <option value="${v.id}" ${String(v.id) === String(currentAeroVpsId) ? 'selected' : ''}>
        #${v.id} · ${v.name || 'VPS'} (${v.ip ? v.ip + (v.domain ? ' · ' + v.domain : '') : (v.domain || '无IP')})
      </option>
    `).join('');
    if (!currentAeroVpsId || !items.find(x => String(x.id) === String(currentAeroVpsId))) {
      currentAeroVpsId = String(items[0].id);
    }
  } catch (e) {
    sel.innerHTML = `<option value="">加载失败: ${e.message}</option>`;
  }
}

async function loadAeroDiagnose(vpsId) {
  if (!vpsId) return;
  const statusEl = $('aeroDeployStatus');
  if (statusEl) statusEl.textContent = `正在全面诊断 VPS #${vpsId}...`;

  try {
    const diag = await apiCall(`/aero/vps/${vpsId}/diagnose/`);
    if (statusEl) statusEl.textContent = `探测响应完成 (${diag.via || '本地'})`;

    // 1. Overall & Service KPI
    const isOk = diag.ok;
    const isInstalled = diag.installed;
    $('aeroKpiOverall').innerHTML = `<span class="tag ${isOk ? 'tag-green' : (isInstalled ? 'tag-amber' : 'tag-red')}">${isOk ? '正常在线' : (isInstalled ? '异常待排查' : '未安装')}</span>`;
    
    const svcActive = diag.service && diag.service.active;
    $('aeroKpiService').innerHTML = `<span class="tag ${svcActive ? 'tag-green' : 'tag-red'}">${svcActive ? 'RUNNING' : 'STOPPED'}</span>`;

    // 2. Port 443
    const p443 = diag.ports && diag.ports.find(p => p.port === 443 && p.listen);
    $('aeroKpiPort443').innerHTML = `<span class="tag ${p443 ? 'tag-green' : 'tag-amber'}">${p443 ? '443 监听' : '未监听'}</span>`;

    // 3. Cert
    const cert = diag.cert || {};
    $('aeroKpiCert').innerHTML = `<span class="tag ${cert.ok ? 'tag-green' : 'tag-amber'}">${cert.ok ? '证书正常' : '待配置'}</span>`;

    // 4. Sub Local & Public
    const sub = diag.subscription || {};
    $('aeroKpiSubLocal').innerHTML = `<span class="tag ${sub.local_ok ? 'tag-green' : 'tag-amber'}">${sub.local_ok ? 'OK (内核畅通)' : '异常'}</span>`;
    $('aeroKpiSubPublic').innerHTML = `<span class="tag ${sub.public_ok ? 'tag-green' : 'tag-amber'}">${sub.public_ok ? '直连畅通' : '未就绪'}</span>`;

    // 5. Nodes Table
    const tbody = $('aeroNodesTableBody');
    if (tbody) {
      const nodes = diag.nodes || [];
      if (!nodes.length) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--muted);padding:14px">暂无协议节点</td></tr>';
      } else {
        tbody.innerHTML = nodes.map(n => `
          <tr>
            <td><span class="tag ${n.online ? 'tag-green' : 'tag-red'}">${n.online ? '在线' : '离线'}</span></td>
            <td><b>${escapeHtml(n.name || 'AERO H3/QUIC')}</b></td>
            <td><span class="tag tag-blue">${escapeHtml(n.kind || 'aero')}</span></td>
            <td class="mono">${escapeHtml(n.target || '—')}</td>
          </tr>
        `).join('');
      }
    }

    // 6. Ports Row
    const portsRow = $('aeroPortsRow');
    if (portsRow) {
      const ports = diag.ports || [];
      portsRow.innerHTML = ports.map(p => `
        <span class="tag ${p.listen ? 'tag-green' : 'tag-muted'}" style="font-size:11px">
          ${p.proto} / ${p.port} (${p.role}) ${p.listen ? 'LISTEN' : 'CLOSED'}
        </span>
      `).join('');
    }

    // 7. Log Box
    const logBox = $('aeroLogBox');
    if (logBox) {
      logBox.textContent = diag.log_tail || '暂无内核输出';
    }

    // 8. Sub Box
    const subUrl = subURL('superadmin');
    $('aeroSubUrlBox').textContent = subUrl;
    $('aeroSubSecretStatus').textContent = sub.secret_set === 'yes' ? '已配置就绪' : '未配置';
    $('aeroSubLocalStatus').innerHTML = `<span class="tag ${sub.local_ok ? 'tag-green' : 'tag-amber'}">${sub.local_ok ? 'OK' : 'FAIL'}</span>`;
    $('aeroSubPublicStatus').innerHTML = `<span class="tag ${sub.public_ok ? 'tag-green' : 'tag-amber'}">${sub.public_ok ? 'OK (直连畅通)' : '不可达'}</span>`;
    $('aeroSubPreview').textContent = `https://${diag.domain || 'domain'}/sub/superadmin`;

    // 9. Load Tokens
    await loadAeroTokens(vpsId);
  } catch (e) {
    if (statusEl) statusEl.textContent = `诊断失败: ${e.message}`;
  }
}

async function loadAeroTokens(vpsId) {
  const tbody = $('aeroTokensTableBody');
  if (!tbody) return;
  try {
    const list = await apiCall(`/aero/vps/${vpsId}/tokens/`).catch(() => []);
    const items = (list && list.results) || (Array.isArray(list) ? list : []);
    if (!items.length) {
      tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--muted);padding:14px">暂无 Token 凭据</td></tr>';
      return;
    }
    tbody.innerHTML = items.map(t => `
      <tr>
        <td class="mono"><b>${escapeHtml(t.token)}</b></td>
        <td>${escapeHtml(t.label || '—')}</td>
        <td><span class="tag tag-blue">${t.ttl_hours ? t.ttl_hours + '小时' : '永久有效'}</span></td>
        <td><button class="btn btn-sm btn-danger" onclick="delAeroToken('${escapeHtml(t.token)}')">删</button></td>
      </tr>
    `).join('');
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="4" style="text-align:center;color:var(--red)">加载 Token 失败: ${e.message}</td></tr>`;
  }
}

async function deployAero(action, customPort = 0) {
  if (!currentAeroVpsId) return alert('请先选择目标 VPS 主机！');
  try {
    const payload = { vps_id: Number(currentAeroVpsId) };
    if (action === 'install' && customPort > 0) {
      payload.port = customPort;
    }
    const res = await apiCall(`/aero/${action}/`, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    const taskId = res.task_id || (res.data && res.data.task_id);
    if (taskId) {
      openAeroTaskDrawer(taskId, action);
    } else {
      alert(`调度指令已下发 (${action})`);
      loadAERO();
    }
  } catch (e) {
    alert(`调度指令下发失败: ${e.message}`);
  }
}

function openAeroTaskDrawer(taskId, action = 'task') {
  activeAeroTaskId = taskId;
  $('aeroTaskModalTitle').innerHTML = `<span>🚀 调度流水线详情 #${taskId}</span> <span class="tag tag-blue" id="aeroTaskModalStatusTag">RUNNING</span>`;
  const actName = action === 'install' ? '安装 / 升级 Edge' : (action === 'uninstall' ? '深度卸载 Edge' : `${action.toUpperCase()} Edge`);
  $('aeroTaskModalSub').textContent = `任务 #${taskId} · ${actName}`;
  $('aeroTaskDrawerModal').classList.add('active');
  $('aeroTaskProgressBar').style.width = '10%';
  $('aeroTaskProgressPercent').textContent = '10%';
  $('aeroTaskProgressStage').textContent = '阶段：正在初始化...';
  $('aeroTaskLogBox').textContent = '正在等待远端输出...';

  if (aeroTaskPollTimer) clearInterval(aeroTaskPollTimer);
  aeroTaskPollTimer = setInterval(() => pollAeroTask(taskId), 1500);
}

async function pollAeroTask(taskId) {
  try {
    const task = await apiCall(`/aero/tasks/${taskId}/`);
    if (!task) return;

    const percent = Math.min(100, Math.max(10, task.progress || 10));
    $('aeroTaskProgressBar').style.width = `${percent}%`;
    $('aeroTaskProgressPercent').textContent = `${percent}%`;
    $('aeroTaskProgressStage').textContent = `阶段: ${task.stage || task.action || task.kind || '执行中'}`;
    $('aeroTaskModalStatusTag').textContent = (task.status || 'RUNNING').toUpperCase();
    $('aeroTaskModalStatusTag').className = `tag ${task.status === 'success' ? 'tag-green' : (task.status === 'failed' ? 'tag-red' : 'tag-blue')}`;

    // 动态渲染任务各步骤状态，彻底消除步骤冻结在“等待中”
    if (task.steps && task.steps.length > 0) {
      const stepper = $('aeroTaskStepper');
      if (stepper) {
        stepper.innerHTML = task.steps.map((s, idx) => {
          let tagClass = 'tag-blue';
          let tagText = '等待中';
          let icon = '⚪';
          if (s.status === 'running') {
            tagClass = 'tag-blue';
            tagText = '执行中...';
            icon = '🔄';
          } else if (s.status === 'success') {
            tagClass = 'tag-green';
            tagText = '已完成';
            icon = '✅';
          } else if (s.status === 'failed') {
            tagClass = 'tag-red';
            tagText = '失败';
            icon = '❌';
          } else if (s.status === 'skipped') {
            tagClass = 'tag-amber';
            tagText = '已跳过';
            icon = '⏭️';
          }
          return `
            <div class="step-item" style="display:flex;justify-content:space-between;align-items:center;padding:8px 12px;background:var(--bg);border-radius:6px;font-size:12px;border:1px solid var(--line)">
              <div style="display:flex;align-items:center;gap:8px">
                <span>${icon}</span>
                <span style="font-weight:600">${idx + 1}. ${escapeHtml(s.title || s.key)}</span>
                ${s.detail ? `<span style="color:var(--muted);font-size:11px">(${escapeHtml(s.detail)})</span>` : ''}
              </div>
              <span class="tag ${tagClass}">${tagText}</span>
            </div>
          `;
        }).join('');
      }
    }

    if (task.logs && task.logs.length) {
      $('aeroTaskLogBox').textContent = task.logs.join('\n');
      $('aeroTaskLogBox').scrollTop = $('aeroTaskLogBox').scrollHeight;
    }

    if (task.status === 'success' || task.status === 'failed') {
      clearInterval(aeroTaskPollTimer);
      aeroTaskPollTimer = null;
      loadAeroTasks();
      loadNodes();
      loadDashboard();
      if (currentAeroVpsId) {
        loadAeroDiagnose(currentAeroVpsId);
      }
    }
  } catch (e) {
    console.warn('pollAeroTask error', e);
  }
}

async function loadAeroTasks() {
  const wrap = $('aeroTasksWrap');
  const tbody = $('aeroTasksTableBody');
  if (!wrap || !tbody) return;
  try {
    const list = await apiCall('/aero/tasks/').catch(() => []);
    const items = (list && list.results) || (Array.isArray(list) ? list : []);
    if (!items.length) {
      wrap.style.display = 'none';
      return;
    }
    wrap.style.display = 'block';
    tbody.innerHTML = items.slice(0, 5).map(t => {
      const actKey = String(t.kind || t.action || 'install').toLowerCase();
      let tagHtml = '<span class="tag tag-blue">安装 / 升级</span>';
      if (actKey.includes('uninstall') || actKey.includes('卸载')) {
        tagHtml = '<span class="tag tag-red">深度卸载</span>';
      } else if (actKey.includes('restart') || actKey.includes('重启')) {
        tagHtml = '<span class="tag tag-amber">服务重启</span>';
      }
      return `
        <tr>
          <td>#${t.id}</td>
          <td>${tagHtml}</td>
          <td>#${t.vps_id}</td>
          <td>
            <div style="background:var(--line);border-radius:2px;height:4px;width:100%;overflow:hidden">
              <div style="width:${t.progress || 0}%;height:100%;background:var(--blue)"></div>
            </div>
          </td>
          <td>${escapeHtml(t.stage || '—')}</td>
          <td><span class="tag ${t.status === 'success' ? 'tag-green' : (t.status === 'failed' ? 'tag-red' : 'tag-blue')}">${t.status}</span></td>
          <td><button class="btn btn-sm" onclick="openAeroTaskDrawer(${t.id}, '${escapeHtml(actKey)}')">查看</button></td>
        </tr>
      `;
    }).join('');
  } catch (_) {}
}

window.delAeroToken = async (tok) => {
  if (!currentAeroVpsId) return;
  if (!confirm(`确认删除 Token [${tok}]？`)) return;
  try {
    await apiCall(`/aero/vps/${currentAeroVpsId}/tokens/?token=${encodeURIComponent(tok)}`, { method: 'DELETE' });
    loadAeroTokens(currentAeroVpsId);
  } catch (e) {
    alert(`删除失败: ${e.message}`);
  }
};

function initAeroEvents() {
  $('btnAeroRefresh')?.addEventListener('click', () => {
    if (currentAeroVpsId) loadAeroDiagnose(currentAeroVpsId);
  });
  $('btnAeroTestConn')?.addEventListener('click', () => {
    if (currentAeroVpsId) loadAeroDiagnose(currentAeroVpsId);
  });
  $('aeroVpsSelect')?.addEventListener('change', (e) => {
    currentAeroVpsId = e.target.value;
    if (currentAeroVpsId) loadAeroDiagnose(currentAeroVpsId);
  });
  $('btnAeroRestart')?.addEventListener('click', () => deployAero('restart'));

  // 安装 / 升级 独立弹窗
  $('btnAeroInstall')?.addEventListener('click', () => {
    if (!currentAeroVpsId) return alert('请先在上方下拉框选择目标 VPS 主机！');
    const v = cachedVpsList.find(x => String(x.id) === String(currentAeroVpsId));
    const targetName = v ? `${v.name} (${v.domain || v.ip}:${v.ssh_port || 22})` : `VPS #${currentAeroVpsId}`;
    $('installModalVpsName').value = targetName;
    $('installModalPort').value = '443';
    $('aeroInstallModal').classList.add('active');
  });
  $('btnCancelInstallModal')?.addEventListener('click', () => $('aeroInstallModal').classList.remove('active'));
  $('btnCloseInstallModal')?.addEventListener('click', () => $('aeroInstallModal').classList.remove('active'));
  $('btnConfirmInstallModal')?.addEventListener('click', () => {
    $('aeroInstallModal').classList.remove('active');
    const port = parseInt($('installModalPort').value.trim(), 10) || 443;
    deployAero('install', port);
  });

  // 深度卸载 独立弹窗
  $('btnAeroUninstall')?.addEventListener('click', () => {
    if (!currentAeroVpsId) return alert('请先在上方下拉框选择目标 VPS 主机！');
    const v = cachedVpsList.find(x => String(x.id) === String(currentAeroVpsId));
    const targetName = v ? `${v.name} (${v.domain || v.ip})` : `VPS #${currentAeroVpsId}`;
    $('uninstallModalVpsName').value = targetName;
    $('aeroUninstallModal').classList.add('active');
  });
  $('btnCancelUninstallModal')?.addEventListener('click', () => $('aeroUninstallModal').classList.remove('active'));
  $('btnCloseUninstallModal')?.addEventListener('click', () => $('aeroUninstallModal').classList.remove('active'));
  $('btnConfirmUninstallModal')?.addEventListener('click', () => {
    $('aeroUninstallModal').classList.remove('active');
    deployAero('uninstall');
  });
  
  $('btnCloseAeroTaskDrawer')?.addEventListener('click', () => {
    $('aeroTaskDrawerModal').classList.remove('active');
    if (aeroTaskPollTimer) {
      clearInterval(aeroTaskPollTimer);
      aeroTaskPollTimer = null;
    }
  });

  $('btnOpenAddAeroToken')?.addEventListener('click', () => {
    $('newAeroTokenVal').value = '';
    $('newAeroTokenLabel').value = '';
    $('newAeroTokenTTL').value = '0';
    $('aeroTokenModal').classList.add('active');
  });

  $('btnCancelAeroToken')?.addEventListener('click', () => {
    $('aeroTokenModal').classList.remove('active');
  });

  $('btnSaveAeroToken')?.addEventListener('click', async () => {
    if (!currentAeroVpsId) return alert('请先选择 VPS 主机');
    const token = $('newAeroTokenVal').value.trim();
    const label = $('newAeroTokenLabel').value.trim();
    const ttl = parseInt($('newAeroTokenTTL').value, 10) || 0;
    try {
      await apiCall(`/aero/vps/${currentAeroVpsId}/tokens/`, {
        method: 'POST',
        body: JSON.stringify({ token, label, ttl_hours: ttl })
      });
      alert('Token 凭证已分发至目标 Edge');
      $('aeroTokenModal').classList.remove('active');
      loadAeroTokens(currentAeroVpsId);
    } catch (e) {
      alert(`保存失败: ${e.message}`);
    }
  });

  $('btnCopyAeroSub')?.addEventListener('click', () => {
    const url = $('aeroSubUrlBox').textContent.trim();
    if (url && !url.includes('请选择')) {
      copySubUrl(url, 'AERO_Superadmin');
    }
  });
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
    const vpsDomains = new Set(cachedVpsList.map(v => v.domain).filter(Boolean));
    const orphans = cachedNodeList.filter(n => {
      if (n.vps_id && vpsIds.has(n.vps_id)) return false;
      if (n.ip && vpsIps.has(n.ip)) return false;
      if (n.ip && vpsDomains.has(n.ip)) return false;
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
    const res = await apiCall(`/nodes/${id}/heartbeat/`, {
      method: 'POST',
      body: JSON.stringify({}) // 触发主动连通性探测
    });
    if (res && res.online) {
      alert(`心跳探测结果：节点正常在线！(延迟: ${res.latency_ms || 30} ms)`);
    } else {
      alert(`心跳探测结果：【节点离线不可达】\n原因: ${res.message || '网络连接超时或端口未开放'}`);
    }
    loadNodes();
  } catch (e) {
    alert(`心跳探测异常: ${e.message}`);
    loadNodes();
  }
};

window.delNode = async (id) => {
  if (!confirm(`确认彻底删除节点 #${id}？将同时终止远端服务并清理节点记录！`)) return;
  try {
    await apiCall(`/nodes/${id}/`, { method: 'DELETE' });
    alert('节点及远端服务已彻底删除清理');
    loadNodes();
    loadVPS();
    loadDashboard();
  } catch (e) {
    alert(`删除失败: ${e.message}`);
  }
};

async function cleanOrphanNodes() {
  if (!confirm('确认批量清理所有失联无归属节点？')) return;
  try {
    const validIds = cachedVpsList.map(v => v.id);
    await apiCall('/nodes/orphan/', {
      method: 'DELETE',
      body: JSON.stringify({ valid_vps_ids: validIds })
    });
    const vpsIds = new Set(cachedVpsList.map(v => v.id));
    const vpsIps = new Set(cachedVpsList.map(v => v.ip));
    const vpsDomains = new Set(cachedVpsList.map(v => v.domain).filter(Boolean));
    for (const n of cachedNodeList) {
      if (!vpsIds.has(n.vps_id) && !vpsIps.has(n.ip) && !vpsDomains.has(n.ip)) {
        await apiCall(`/nodes/${n.id}/`, { method: 'DELETE' }).catch(() => null);
      }
    }
    alert('失联节点清理完毕');
    loadNodes();
    loadDashboard();
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

// ------------------------------------------------------------------------------
// Pane 7: Subscription Settings & Maintenance (订阅设置与套餐管理)
// ------------------------------------------------------------------------------
async function loadSubs() {
  await Promise.all([loadPlansTable(), loadSubsTable()]);
}

async function loadPlansTable() {
  const tbody = $('plansTableBody');
  if (!tbody) return;
  try {
    const res = await apiCall('/plans/');
    const plans = (res && res.results) ? res.results : (Array.isArray(res) ? res : []);
    tbody.innerHTML = '';
    if (plans.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:16px;color:var(--muted)">暂无套餐配置</td></tr>';
      return;
    }
    plans.forEach(p => {
      const trafficDesc = (p.traffic_bytes === -1) ? '无限流量' : `${(p.traffic_bytes / (1024*1024*1024)).toFixed(0)} GB`;
      const priceYuan = (p.price_cents / 100).toFixed(2);
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${p.id}</td>
        <td><b>${escapeHtml(p.name)}</b></td>
        <td>${p.duration_months} 个月</td>
        <td><span class="tag ${p.traffic_bytes === -1 ? 'tag-purple' : 'tag-blue'}">${trafficDesc}</span></td>
        <td><b>¥${priceYuan}</b></td>
        <td><span class="tag ${p.status ? 'tag-green' : 'tag-muted'}">${p.status ? '在售' : '停售'}</span></td>
        <td>
          <button class="btn btn-sm" onclick="togglePlanStatus(${p.id}, ${p.status})">${p.status ? '下架' : '上架'}</button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;padding:16px;color:var(--red)">加载套餐失败: ${escapeHtml(e.message)}</td></tr>`;
  }
}

async function togglePlanStatus(id, currentStatus) {
  try {
    const newStatus = !currentStatus;
    await apiCall(`/plans/${id}/`, {
      method: 'PATCH',
      body: JSON.stringify({ status: newStatus })
    });
    loadPlansTable();
  } catch (e) {
    alert(`更新套餐状态失败: ${e.message}`);
  }
}

function openAddPlanModal() {
  $('editPlanId').value = '';
  $('planNameInput').value = '';
  $('planMonthsInput').value = '1';
  $('planPriceInput').value = '999';
  $('planTrafficInput').value = '100';
  $('planModalTitle').textContent = '新增套餐';
  $('planModal').classList.add('active');
}

async function savePlanModal() {
  const name = $('planNameInput').value.trim();
  const months = parseInt($('planMonthsInput').value, 10) || 1;
  const priceCents = parseInt($('planPriceInput').value, 10) || 0;
  const trafficGB = parseInt($('planTrafficInput').value, 10);
  if (!name) return alert('请输入套餐名称');

  let trafficBytes = -1;
  if (trafficGB > 0) {
    trafficBytes = trafficGB * 1024 * 1024 * 1024;
  }

  try {
    await apiCall('/plans/', {
      method: 'POST',
      body: JSON.stringify({
        name,
        duration_months: months,
        traffic_bytes: trafficBytes,
        price_cents: priceCents
      })
    });
    $('planModal').classList.remove('active');
    loadPlansTable();
  } catch (e) {
    alert(`保存套餐失败: ${e.message}`);
  }
}

async function loadSubsTable() {
  const tbody = $('subsTableBody');
  if (!tbody) return;
  try {
    const res = await apiCall('/subscriptions/');
    const subs = (res && res.results) ? res.results : (Array.isArray(res) ? res : []);
    tbody.innerHTML = '';
    if (subs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;padding:16px;color:var(--muted)">暂无用户订阅记录</td></tr>';
      return;
    }
    subs.forEach(s => {
      const isSwitchOn = s.switch_status !== 'off';
      const isExpired = s.expire_at && new Date(s.expire_at).getTime() < Date.now();
      const usedMB = ((s.used_bytes || 0) / (1024 * 1024)).toFixed(1);
      const limitGB = (s.limit_bytes === -1) ? '无限' : `${((s.limit_bytes || 0) / (1024 * 1024 * 1024)).toFixed(0)} GB`;

      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><code>${escapeHtml(s.sub_id)}</code></td>
        <td><code>${escapeHtml(s.user_uuid || ('u_' + s.user_id))}</code></td>
        <td><code>${escapeHtml(s.sub_slug)}</code></td>
        <td><b>${escapeHtml(s.plan_name || '默认套餐')}</b></td>
        <td>
          <button class="btn btn-sm ${isSwitchOn ? 'btn-blue' : ''}" style="min-width:60px;padding:3px 8px" onclick="toggleSubSwitch('${s.sub_id}', '${s.switch_status}')">
            ${isSwitchOn ? '🟢 ON' : '⚪ OFF'}
          </button>
        </td>
        <td>
          ${fmtDate(s.expire_at)}
          ${isExpired ? '<span class="tag tag-red" style="margin-left:4px">已到期</span>' : ''}
        </td>
        <td>${usedMB} MB / ${limitGB}</td>
        <td>
          <div style="display:flex;gap:6px">
            <button class="btn btn-sm" onclick="renewSub('${s.sub_id}')">续期</button>
            <button class="btn btn-sm btn-danger" onclick="deleteSub('${s.sub_id}')">删除</button>
          </div>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;padding:16px;color:var(--red)">加载订阅失败: ${escapeHtml(e.message)}</td></tr>`;
  }
}

async function toggleSubSwitch(subID, currentStatus) {
  const nextStatus = (currentStatus === 'off') ? 'on' : 'off';
  try {
    await apiCall(`/subscriptions/${subID}/switch/`, {
      method: 'POST',
      body: JSON.stringify({ switch_status: nextStatus })
    });
    loadSubsTable();
  } catch (e) {
    alert(`切换总开关失败: ${e.message}`);
  }
}

async function renewSub(subID) {
  const monthsStr = prompt('请输入续期月份数 (默认1个月):', '1');
  if (!monthsStr) return;
  const months = parseInt(monthsStr, 10) || 1;
  try {
    await apiCall(`/subscriptions/${subID}/renew/`, {
      method: 'POST',
      body: JSON.stringify({ plan_months: months, price_cents: 999 * months })
    });
    alert('续期成功，总开关已自动恢复开启');
    loadSubsTable();
  } catch (e) {
    alert(`续期失败: ${e.message}`);
  }
}

async function deleteSub(subID) {
  if (!confirm(`确认永久删除订阅 ${subID}？客户端拉取将立即返回 404 并清空本地连接！`)) return;
  try {
    await apiCall(`/subscriptions/${subID}/`, { method: 'DELETE' });
    loadSubsTable();
    loadUsers();
  } catch (e) {
    alert(`删除失败: ${e.message}`);
  }
}

window.toggleSubSwitch = toggleSubSwitch;
window.renewSub = renewSub;
window.deleteSub = deleteSub;


