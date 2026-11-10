// AERO Protocol Contributors - Pure Vanilla JS User Console (Zero Runtime Dependencies)
(function () {
  'use strict';

  const TOKEN_KEY = 'vpn_user_token';
  const USER_KEY = 'vpn_user_user';
  const API_BASE = '/api/v1';

  let currentUser = null;
  let activeTab = 'subs';
  let cachedNodes = [];
  let cachedPlans = [];
  let cachedChannels = [];
  let selectedPlanId = null;

  function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/[&<>"']/g, s => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    })[s]);
  }

  function init() {
    bindAuthEvents();
    bindNavEvents();
    checkAuth();
  }

  // --- Toast Messages ---
  function showToast(msg, type = 'info') {
    const el = document.createElement('div');
    el.className = `toast toast-${type}`;
    el.textContent = msg;
    document.body.appendChild(el);
    setTimeout(() => {
      el.style.opacity = '0';
      setTimeout(() => el.remove(), 300);
    }, 3000);
  }

  // --- API Client ---
  async function apiRequest(path, options = {}) {
    const token = localStorage.getItem(TOKEN_KEY);
    const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const res = await fetch(`${API_BASE}${path}`, { ...options, headers });
    if (res.status === 401 && !path.includes('/auth/login')) {
      logout();
      throw new Error('登录已过期，请重新登录');
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(data.message || data.error || `请求失败 (${res.status})`);
    }
    return data;
  }

  // --- Auth Flow ---
  function checkAuth() {
    const token = localStorage.getItem(TOKEN_KEY);
    const userStr = localStorage.getItem(USER_KEY);
    if (!token || !userStr) {
      showAuth('login');
      return;
    }
    try {
      currentUser = JSON.parse(userStr);
      showApp();
    } catch {
      logout();
    }
  }

  function showAuth(mode = 'login') {
    document.getElementById('appLayout').style.display = 'none';
    document.getElementById('authWrap').style.display = 'grid';
    document.getElementById('loginForm').style.display = mode === 'login' ? 'flex' : 'none';
    document.getElementById('registerForm').style.display = mode === 'register' ? 'flex' : 'none';
  }

  async function fetchUserFromDb() {
    try {
      const res = await apiRequest('/auth/me/');
      const u = res.data || res;
      if (u && u.username) {
        currentUser = u;
        localStorage.setItem(USER_KEY, JSON.stringify(u));
        const el = document.getElementById('userName');
        if (el) el.textContent = u.username;
        const topEl = document.getElementById('topUserName');
        if (topEl) topEl.textContent = u.username;
        const b = document.getElementById('userBadge');
        if (b) b.textContent = u.username[0].toUpperCase();
      }
    } catch (_) {}
  }

  function showApp() {
    document.getElementById('authWrap').style.display = 'none';
    document.getElementById('appLayout').style.display = 'flex';
    const uname = (currentUser && currentUser.username) || '用户';
    const uEl = document.getElementById('userName');
    if (uEl) uEl.textContent = uname;
    const topEl = document.getElementById('topUserName');
    if (topEl) topEl.textContent = uname;
    document.getElementById('userBadge').textContent = uname[0].toUpperCase();
    fetchUserFromDb();

    // Check payment redirect parameters
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('payment') === 'success') {
      showToast('🎉 支付成功！您的 AERO 专属订阅已自动生效与开通！', 'success');
      window.history.replaceState({}, document.title, window.location.pathname);
      activeTab = 'subs';
    } else if (urlParams.get('payment') === 'cancel') {
      showToast('支付已取消或已中断', 'info');
      window.history.replaceState({}, document.title, window.location.pathname);
    }

    switchTab(activeTab);
  }

  function logout() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    currentUser = null;
    showAuth('login');
  }

  function bindAuthEvents() {
    document.getElementById('toRegister').addEventListener('click', (e) => {
      e.preventDefault();
      showAuth('register');
    });
    document.getElementById('toLogin').addEventListener('click', (e) => {
      e.preventDefault();
      showAuth('login');
    });

    // Login Form Submit
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const u = document.getElementById('loginUser').value.trim();
      const p = document.getElementById('loginPass').value.trim();
      if (!u || !p) return showToast('请输入用户名和密码', 'error');

      const btn = document.getElementById('btnLogin');
      btn.disabled = true;
      btn.textContent = '登录中...';
      try {
        const resp = await apiRequest('/auth/login/', {
          method: 'POST',
          body: JSON.stringify({ username: u, password: p, portal: 'user' })
        });
        const user = resp.data || resp;
        localStorage.setItem(TOKEN_KEY, user.token);
        localStorage.setItem(USER_KEY, JSON.stringify(user));
        currentUser = user;
        showToast('登录成功', 'success');
        showApp();
      } catch (err) {
        showToast(err.message, 'error');
      } finally {
        btn.disabled = false;
        btn.textContent = '立即登录';
      }
    });

    // Register Form Submit
    document.getElementById('registerForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const u = document.getElementById('regUser').value.trim();
      const em = document.getElementById('regEmail').value.trim();
      const p = document.getElementById('regPass').value.trim();
      const pConfirm = (document.getElementById('regPassConfirm')?.value || '').trim();

      if (!u) return showToast('请输入用户名', 'error');
      if (!/^[a-zA-Z0-9_]{3,32}$/.test(u)) {
        return showToast('用户名须为3-32位英文字母、数字或下划线', 'error');
      }
      if (!em) return showToast('请输入电子邮箱', 'error');
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em)) {
        return showToast('请输入合法的电子邮箱格式', 'error');
      }
      if (!p) return showToast('请输入设置密码', 'error');
      if (p.length < 8 || !/[a-zA-Z]/.test(p) || !/[0-9]/.test(p)) {
        return showToast('密码须至少8位，且必须包含字母与数字组合', 'error');
      }
      if (p !== pConfirm) {
        return showToast('两次输入的密码不一致，请重新核对', 'error');
      }

      const btn = document.getElementById('btnReg');
      btn.disabled = true;
      btn.textContent = '注册中...';
      try {
        await apiRequest('/users/', {
          method: 'POST',
          body: JSON.stringify({ username: u, email: em, password: p })
        });
        showToast('注册成功，请使用新账号登录', 'success');
        showAuth('login');
      } catch (err) {
        showToast(err.message, 'error');
      } finally {
        btn.disabled = false;
        btn.textContent = '完成注册';
      }
    });

    document.getElementById('btnLogout').addEventListener('click', logout);
  }

  // --- Navigation ---
  function bindNavEvents() {
    document.querySelectorAll('.menu-item').forEach((item) => {
      item.addEventListener('click', () => {
        const tab = item.getAttribute('data-tab');
        if (tab) switchTab(tab);
      });
    });

    document.getElementById('btnToggleSidebar')?.addEventListener('click', () => {
      const sb = document.querySelector('.sidebar');
      if (!sb) return;
      sb.classList.toggle('collapsed');
      const isCollapsed = sb.classList.contains('collapsed');
      const icon = document.getElementById('collapseIcon');
      if (icon) icon.textContent = isCollapsed ? '▶' : '◀';
      localStorage.setItem('user_sidebar_collapsed', isCollapsed ? '1' : '0');
    });

    if (localStorage.getItem('user_sidebar_collapsed') === '1') {
      document.querySelector('.sidebar')?.classList.add('collapsed');
      const icon = document.getElementById('collapseIcon');
      if (icon) icon.textContent = '▶';
    }
  }

  function switchTab(tab) {
    activeTab = tab;
    document.querySelectorAll('.menu-item').forEach((i) => {
      i.classList.toggle('active', i.getAttribute('data-tab') === tab);
    });
    document.querySelectorAll('.tab-content').forEach((tc) => {
      tc.style.display = tc.id === `tab-${tab}` ? 'block' : 'none';
    });

    const titles = {
      subs: '我的专属订阅 (AERO Native)',
      nodes: '全球边缘节点 (Edge Nodes)',
      plans: '套餐与订购 (Plans & Orders)',
      orders: '历史账单 (Billing History)'
    };
    document.getElementById('pageTitle').textContent = titles[tab] || '控制台';

    if (tab === 'subs') loadSubscription();
    if (tab === 'nodes') loadNodes();
    if (tab === 'plans') loadPlans();
    if (tab === 'orders') loadOrders();
  }

  // --- Subscriptions Tab ---
  async function loadSubscription() {
    const listEl = document.getElementById('subList');
    listEl.innerHTML = '<div style="color:var(--muted);padding:14px">正在获取最新订阅...</div>';
    try {
      const resp = await apiRequest('/user/subscription');
      const data = resp.data || resp;
      renderSubscription(data);
    } catch (err) {
      listEl.innerHTML = `<div style="color:var(--red);padding:14px">获取订阅失败: ${err.message}</div>`;
    }
  }

  function renderSubscription(data) {
    const listEl = document.getElementById('subList');
    const hasSub = data && data.slug && Array.isArray(data.servers) && data.servers.length > 0 && data.switchStatus !== 'off';

    if (!hasSub) {
      listEl.innerHTML = `
        <div class="card" style="margin-bottom:16px;text-align:center;padding:36px 16px">
          <div style="font-size:36px;margin-bottom:12px">📦</div>
          <div style="font-weight:700;font-size:16px;margin-bottom:8px">暂无已开通的专属订阅</div>
          <div style="font-size:13px;color:var(--muted);margin-bottom:18px;max-width:440px;margin-left:auto;margin-right:auto">
            您当前尚未选购套餐或尚未分配任何边缘节点。请先前往【套餐与订购】开通套餐并选择节点线路。
          </div>
          <button class="btn btn-primary" onclick="document.querySelector('.menu-item[data-tab=\\'plans\\']').click()">
            立即选购套餐并分配节点
          </button>
        </div>
      `;
      return;
    }

    const subUrl = data.sub_url || data.subUrl || '';
    let expire = '永久有效';
    const expVal = data.expireAt || data.expire_at || data.expire;
    if (expVal && expVal > 0) {
      expire = new Date(expVal * 1000).toLocaleDateString('zh-CN');
    }
    const trafficUsed = data.traffic_used_human || '0 MB';
    const trafficLimit = data.traffic_limit_human || (data.limit_bytes ? (data.limit_bytes / (1024*1024*1024)).toFixed(0) + ' GB' : '无限制');
    const serverCount = data.servers.length;

    const serversTableHtml = `
      <div class="card" style="margin-top:16px">
        <div class="card-header">
          <span class="card-title">🌐 当前订阅已绑定的全球边缘节点 (${serverCount} 个)</span>
          <span class="tag tag-blue">纯净原生出口</span>
        </div>
        <div style="font-size:12px;color:var(--muted);margin-bottom:12px">
          以下节点已由中台节点库完成凭据授权与同步，客户端输入上方订阅链接即可自动载入并自由切换。
        </div>
        <table class="data-table">
          <thead>
            <tr>
              <th>节点名称</th>
              <th>边缘地址</th>
              <th>伪装 SNI</th>
              <th>传输协议</th>
              <th>纯净度评分</th>
              <th>节点状态</th>
            </tr>
          </thead>
          <tbody>
            ${data.servers.map(s => `
              <tr>
                <td><b>${s.name}</b></td>
                <td><code>${s.address}</code></td>
                <td><code>${s.sni || 'edge.microsoft.com'}</code></td>
                <td><span class="tag tag-blue">${(s.protocol || 'quic').toUpperCase()} (H3)</span></td>
                <td><span class="tag tag-green">${s.purityScore || 100} 分</span></td>
                <td><span class="dot dot-green"></span> 在线就绪</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;

    listEl.innerHTML = `
      <div class="card" style="margin-bottom:16px">
        <div class="card-header">
          <span class="card-title">🚀 AERO 官方专属订阅链接</span>
          <span class="tag tag-green">原生 443 HTTPS 架构</span>
        </div>
        <div style="font-size:12px;color:var(--muted);margin-bottom:12px">
          客户端输入此链接即可直接载入全部绑定的高速边缘节点。支持 Windows / macOS / Linux / iOS / Android。
        </div>
        <div style="display:flex;gap:10px;margin-bottom:14px">
          <input type="text" id="subUrlInput" class="input-text" style="flex:1" readonly value="${subUrl}" />
          <button class="btn btn-primary" id="btnCopySub">一键复制链接</button>
        </div>
        <div style="display:flex;gap:24px;font-size:12px;color:var(--muted);border-top:1px solid var(--line);padding-top:12px;flex-wrap:wrap">
          <div>到期时间: <b style="color:var(--text)">${expire}</b></div>
          <div>已用流量: <b style="color:var(--text)">${trafficUsed}</b> / ${trafficLimit}</div>
          <div>活跃节点数: <b style="color:var(--text)">${serverCount} 个</b></div>
          <div>状态: <span class="tag tag-blue">${data.switchStatus === 'off' ? '已暂停' : '生效中'}</span></div>
        </div>
      </div>
      ${serversTableHtml}
    `;

    if (subUrl) {
      document.getElementById('btnCopySub').addEventListener('click', () => {
        const input = document.getElementById('subUrlInput');
        input.select();
        navigator.clipboard.writeText(input.value);
        showToast('订阅链接已复制到剪贴板', 'success');
      });
    }
  }

  // --- Nodes Tab ---
  async function loadNodes() {
    const tbody = document.getElementById('nodesTbody');
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--muted)">加载节点中...</td></tr>';
    try {
      const resp = await apiRequest('/nodes/available/');
      cachedNodes = resp.data || (Array.isArray(resp) ? resp : []);
      renderNodes(cachedNodes);
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--red)">节点加载失败: ${err.message}</td></tr>`;
    }
  }

  function renderNodes(nodes) {
    const tbody = document.getElementById('nodesTbody');
    if (!nodes || !nodes.length) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:24px;color:var(--muted)">暂无可用边缘节点</td></tr>';
      return;
    }
    tbody.innerHTML = nodes.map((n) => `
      <tr>
        <td>
          <span class="dot ${n.status === 'online' || n.status === true ? 'dot-green' : 'dot-red'}"></span>
          <b>${n.name || n.address || '边缘节点'}</b>
        </td>
        <td>${n.region || '全球节点'}</td>
        <td><span class="tag tag-blue">${n.latency_ms ? n.latency_ms + 'ms' : (n.latency || '35ms')}</span></td>
        <td>${n.bandwidth_mbps ? n.bandwidth_mbps + ' Mbps' : (n.bandwidth || '1000 Mbps 全双工')}</td>
        <td><span class="tag tag-muted">${(n.protocol || 'quic').toUpperCase()} (H3)</span></td>
      </tr>
    `).join('');
  }

  // --- Plans Tab ---
  async function loadPlans() {
    const container = document.getElementById('plansList');
    container.innerHTML = '<div style="color:var(--muted)">加载套餐中...</div>';
    try {
      if (!cachedNodes || cachedNodes.length === 0) {
        try {
          const nResp = await apiRequest('/nodes/available/');
          cachedNodes = nResp.data || (Array.isArray(nResp) ? nResp : []);
        } catch (_) {}
      }
      try {
        const cResp = await apiRequest('/payments/in/channels/');
        cachedChannels = cResp.data || (Array.isArray(cResp) ? cResp : []);
      } catch (_) {}
      const resp = await apiRequest('/plans/');
      cachedPlans = resp.data?.results || (Array.isArray(resp.data) ? resp.data : (Array.isArray(resp) ? resp : []));
      renderPlans(cachedPlans);
    } catch (err) {
      container.innerHTML = `<div style="color:var(--red)">套餐加载失败: ${err.message}</div>`;
    }
  }

  function renderPlans(plans) {
    const container = document.getElementById('plansList');
    if (!plans || !plans.length) {
      container.innerHTML = '<div style="color:var(--muted)">暂无可选套餐</div>';
      return;
    }
    const selectedPlan = plans.find(p => p.id === selectedPlanId) || plans[0];
    selectedPlanId = selectedPlan ? selectedPlan.id : null;

    let cardsHtml = plans.map((p) => {
      const price = ((p.price_cents || 0) / 100).toFixed(2);
      const isSelected = selectedPlanId === p.id;
      return `
        <div class="plan-card ${isSelected ? 'selected' : ''}" data-id="${p.id}" style="cursor:pointer">
          <div style="font-weight:700;font-size:16px">${escapeHtml(p.name)}</div>
          <div class="plan-price">$ ${price} USD</div>
          <div style="font-size:12px;color:var(--muted)">有效期 ${p.duration_months || 1} 个月</div>
          <div style="font-size:12px;color:var(--muted)">流量: ${p.traffic_bytes && p.traffic_bytes > 0 ? (p.traffic_bytes / (1024*1024*1024)).toFixed(0) + ' GB' : '高速不限流量'}</div>
          <button class="btn ${isSelected ? 'btn-primary' : 'btn-ghost'}" style="margin-top:10px;pointer-events:none">
            ${isSelected ? '已选择' : '选购此套餐'}
          </button>
        </div>
      `;
    }).join('');

    // 全球边缘节点库选项 (从中台 NodeRegistry 动态生成)
    let nodeOptionsHtml = '';
    const hasLiveNodes = cachedNodes && cachedNodes.length > 0;
    if (hasLiveNodes) {
      nodeOptionsHtml = cachedNodes.map(n => {
        const addr = n.address || n.ip || '';
        const regionTag = n.region ? `<span style="color:var(--blue);font-size:11px">· ${escapeHtml(n.region)}</span>` : '';
        return `
        <label style="display:inline-flex;align-items:center;gap:6px;padding:8px 14px;background:var(--bg);border:1px solid var(--line);border-radius:6px;font-size:12px;cursor:pointer">
          <input type="checkbox" name="assignNode" value="${escapeHtml(n.name || addr)}" checked />
          <b>${escapeHtml(n.name || addr)}</b> ${addr ? `<span style="color:var(--muted)">(${escapeHtml(addr)})</span>` : ''} ${regionTag}
        </label>
      `;
      }).join(' ');
    } else {
      nodeOptionsHtml = '<span style="font-size:12px;color:var(--amber)">⚠️ 当前中台尚未上线任何可用边缘节点，暂不可自选接入节点</span>';
    }

    const priceFormatted = selectedPlan ? ((selectedPlan.price_cents || 0) / 100).toFixed(2) : '0.00';

    const channels = (cachedChannels && cachedChannels.length > 0) ? cachedChannels : [
      { channel: 'creem', name: '国际信用卡 / Apple Pay (极速通道 - 推荐)', icon: 'card', enabled: true },
      { channel: 'lemonsqueezy', name: 'PayPal / 全球信用卡 (保障通道)', icon: 'paypal', enabled: true }
    ];
    let channelOptionsHtml = channels.filter(c => c.enabled).map((c, idx) => `
      <label style="display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer">
        <input type="radio" name="payChannel" value="${escapeHtml(c.channel)}" ${idx === 0 ? 'checked' : ''} />
        ${c.icon === 'paypal' ? '🅿️' : '💳'} ${escapeHtml(c.name || c.display_name || c.channel)}
      </label>
    `).join(' ');

    const checkoutHtml = `
      <div class="card" style="margin-top:20px;grid-column:1 / -1">
        <div class="card-header">
          <span class="card-title">🚀 套餐开通与边缘节点调度</span>
          <span class="tag tag-blue">${selectedPlan ? escapeHtml(selectedPlan.name) : '选择套餐'}</span>
        </div>
        <div style="font-size:12px;color:var(--muted);margin-bottom:16px">
          所选节点将自动从中台节点库授权生成专属 AERO 订阅凭证，开通后即刻生效。
        </div>

        <div style="margin-bottom:16px">
          <label style="font-size:12px;color:var(--muted);display:block;margin-bottom:8px">全球边缘节点调度方式:</label>
          <div style="display:flex;gap:18px;margin-bottom:12px;flex-wrap:wrap">
            <label style="display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer">
              <input type="radio" name="nodeAllocMode" value="auto" checked onchange="document.getElementById('manualNodeWrap').style.display='none'" />
              ⚡ 全能智能优选 (自动从中台节点库分配最佳低延迟纯净节点)
            </label>
            <label style="display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer">
              <input type="radio" name="nodeAllocMode" value="manual" onchange="document.getElementById('manualNodeWrap').style.display='block'" />
              🌐 自选边缘节点 (手动勾选中台已纳管节点)
            </label>
          </div>
          <div id="manualNodeWrap" style="display:none;margin-top:10px;padding:12px;background:var(--bg);border-radius:6px;border:1px solid var(--line)">
            <div style="font-size:11px;color:var(--muted);margin-bottom:8px">从中台全球节点库勾选接入节点:</div>
            <div style="display:flex;gap:10px;flex-wrap:wrap">
              ${nodeOptionsHtml}
            </div>
          </div>
        </div>

        <div style="margin-bottom:18px">
          <label style="font-size:12px;color:var(--muted);display:block;margin-bottom:6px">全球结转收银通道 (MoR 托管合规):</label>
          <div style="display:flex;gap:16px;flex-wrap:wrap">
            ${channelOptionsHtml}
          </div>
        </div>

        <div style="display:flex;align-items:center;gap:16px;border-top:1px solid var(--line);padding-top:16px">
          <button class="btn btn-primary" id="btnConfirmCheckout" ${!hasLiveNodes ? 'disabled style="opacity:0.5;cursor:not-allowed"' : ''} style="padding:10px 24px;font-size:14px;font-weight:600">
            ${!hasLiveNodes ? '暂无可接入节点 (无法订购)' : `立即开通并绑定节点 (实付: $ ${priceFormatted} USD)`}
          </button>
          <span id="checkoutMsg" style="font-size:12px;color:var(--red)">${!hasLiveNodes ? '⚠️ 当前中台尚未上线可用边缘节点，请等待节点就绪后再订购' : ''}</span>
        </div>
      </div>
    `;

    container.innerHTML = cardsHtml + checkoutHtml;

    container.querySelectorAll('.plan-card').forEach((el) => {
      el.addEventListener('click', () => {
        selectedPlanId = parseInt(el.getAttribute('data-id'), 10);
        renderPlans(plans);
      });
    });

    const btnCheckout = document.getElementById('btnConfirmCheckout');
    if (btnCheckout) {
      btnCheckout.addEventListener('click', async () => {
        if (!selectedPlanId) {
          showToast('请先选择一个套餐', 'error');
          return;
        }
        btnCheckout.disabled = true;
        btnCheckout.innerText = '正在创建支付会话...';

        const channel = document.querySelector('input[name="payChannel"]:checked')?.value || 'creem';
        const allocMode = document.querySelector('input[name="nodeAllocMode"]:checked')?.value || 'auto';
        let assignedNodes = [];
        if (allocMode === 'manual') {
          document.querySelectorAll('input[name="assignNode"]:checked').forEach(cb => {
            assignedNodes.push(cb.value);
          });
        }

        try {
          const resp = await apiRequest('/orders/checkout/', {
            method: 'POST',
            body: JSON.stringify({
              plan_id: selectedPlanId,
              channel: channel,
              assigned_nodes: assignedNodes
            })
          });
          const checkoutUrl = resp.data?.checkout_url;
          if (checkoutUrl) {
            showToast('支付会话创建成功，正在跳转收银台...', 'info');
            setTimeout(() => {
              window.location.href = checkoutUrl;
            }, 500);
          } else {
            showToast('套餐开通成功！专属订阅已生成', 'success');
            const subBtn = document.querySelector('.menu-item[data-tab="subs"]');
            if (subBtn) subBtn.click();
          }
        } catch (err) {
          showToast('开通失败: ' + err.message, 'error');
          btnCheckout.disabled = false;
          btnCheckout.innerText = `立即开通并绑定节点 (实付: $ ${priceFormatted} USD)`;
        }
      });
    }
  }

  // --- Orders Tab ---
  async function loadOrders() {
    const tbody = document.getElementById('ordersTbody');
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--muted)">加载账单中...</td></tr>';
    try {
      const resp = await apiRequest('/orders/');
      const orders = resp.data || (Array.isArray(resp) ? resp : []);
      if (!orders.length) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--muted)">暂无历史账单</td></tr>';
        return;
      }
      tbody.innerHTML = orders.map((o) => `
        <tr>
          <td><span style="font-family:monospace">${escapeHtml(o.order_no || o.id)}</span></td>
          <td>${escapeHtml(o.plan_name || '订阅套餐')}</td>
          <td><b>$ ${((o.amount_cents || 0)/100).toFixed(2)} USD</b></td>
          <td><span class="tag ${o.status === 'completed' || o.status === 'PAID' ? 'tag-green' : 'tag-muted'}">${escapeHtml(o.status || '未支付')}</span></td>
          <td>${escapeHtml(o.created_at || '-')}</td>
        </tr>
      `).join('');
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--red)">加载失败: ${err.message}</td></tr>`;
    }
  }

  // Bootstrap on DOM ready
  document.addEventListener('DOMContentLoaded', init);
})();
