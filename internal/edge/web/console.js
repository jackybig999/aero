// AERO Edge Console - Vanilla ES6 Frontend
(() => {
  'use strict';

  // 1. Auth & State
  const params = new URLSearchParams(window.location.search);
  let adminKey = params.get('key') || sessionStorage.getItem('aero_admin_key') || '';
  if (params.get('key')) {
    sessionStorage.setItem('aero_admin_key', params.get('key'));
  }

  function getApiUrl(path) {
    if (!adminKey) return path;
    const sep = path.includes('?') ? '&' : '?';
    return `${path}${sep}key=${encodeURIComponent(adminKey)}`;
  }

  // 2. DOM Elements
  const el = {
    appVersion: document.getElementById('appVersion'),
    nodeStatus: document.getElementById('nodeStatus'),
    nodeDomain: document.getElementById('nodeDomain'),
    nodeListen: document.getElementById('nodeListen'),
    vpsUptime: document.getElementById('vpsUptime'),
    cpuPct: document.getElementById('cpuPct'),
    cpuBar: document.getElementById('cpuBar'),
    memDetail: document.getElementById('memDetail'),
    memBar: document.getElementById('memBar'),
    diskDetail: document.getElementById('diskDetail'),
    diskBar: document.getElementById('diskBar'),
    netRxRate: document.getElementById('netRxRate'),
    netTxRate: document.getElementById('netTxRate'),
    netTotal: document.getElementById('netTotal'),
    loadAvg: document.getElementById('loadAvg'),

    // Purity
    scoreCircle: document.getElementById('scoreCircle'),
    purityScore: document.getElementById('purityScore'),
    badgeEgress: document.getElementById('badgeEgress'),
    badgeYT: document.getElementById('badgeYT'),
    badgeGoogle: document.getElementById('badgeGoogle'),
    badgeGemini: document.getElementById('badgeGemini'),
    badgeWarpRescue: document.getElementById('badgeWarpRescue'),
    btnRefreshPurity: document.getElementById('btnRefreshPurity'),

    // WARP
    warpStatusBadge: document.getElementById('warpStatusBadge'),
    warpToggle: document.getElementById('warpToggle'),

    // GeoData
    geodataRulesCount: document.getElementById('geodataRulesCount'),
    geodataLastUpdated: document.getElementById('geodataLastUpdated'),
    geodataEtag: document.getElementById('geodataEtag'),
    geodataStatusBadge: document.getElementById('geodataStatusBadge'),
    btnUpdateGeoData: document.getElementById('btnUpdateGeoData'),

    // Cert
    certDomain: document.getElementById('certDomain'),
    certExpires: document.getElementById('certExpires'),
    certDaysBadge: document.getElementById('certDaysBadge'),

    // Subs
    adminSubUrl: document.getElementById('adminSubUrl'),
    btnCopyAdminSub: document.getElementById('btnCopyAdminSub'),
    createUserForm: document.getElementById('createUserForm'),
    newUsername: document.getElementById('newUsername'),
    newCode: document.getElementById('newCode'),
    btnGenCode: document.getElementById('btnGenCode'),
    newExpireDays: document.getElementById('newExpireDays'),
    newTrafficGB: document.getElementById('newTrafficGB'),
    usersTableBody: document.getElementById('usersTableBody'),

    // Modal

    toast: document.getElementById('toast'),
  };

  // Toast Utility
  function showToast(msg) {
    if (!el.toast) return;
    el.toast.textContent = msg;
    el.toast.classList.add('show');
    setTimeout(() => {
      el.toast.classList.remove('show');
    }, 2400);
  }

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(() => {
        showToast('已复制到剪贴板！');
      }).catch(() => {
        fallbackCopy(text);
      });
    } else {
      fallbackCopy(text);
    }
  }

  function fallbackCopy(text) {
    const input = document.createElement('input');
    input.value = text;
    document.body.appendChild(input);
    input.select();
    try {
      document.execCommand('copy');
      showToast('已复制到剪贴板！');
    } catch (e) {
      prompt('请手动复制链接:', text);
    }
    document.body.removeChild(input);
  }

  function genRandomCode() {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    let res = '';
    const arr = new Uint8Array(6);
    window.crypto.getRandomValues(arr);
    for (let i = 0; i < 6; i++) {
      res += chars[arr[i] % chars.length];
    }
    return res;
  }

  // 3. API Fetchers

  async function fetchStatus() {
    try {
      const res = await fetch(getApiUrl('/console/api/status'));
      if (!res.ok) {
        if (res.status === 403) el.nodeStatus.textContent = '鉴权失败 (Key无效)';
        return;
      }
      const data = await res.json();
      updateStatusUI(data);
    } catch (e) {
      console.warn('Status poll error:', e);
    }
  }

  function updateStatusUI(data) {
    if (data.version) {
      el.appVersion.textContent = `v${data.version} • ${data.protocol || 'aero/3.0'}`;
    }
    if (data.domain) {
      el.nodeDomain.textContent = data.domain;
    }
    if (data.listen) {
      el.nodeListen.textContent = data.listen;
    }

    // VPS Metrics (support vps or system keys)
    const v = data.vps || data.system;
    if (v) {
      const cpu = (v.cpu_usage_pct !== undefined ? v.cpu_usage_pct : v.cpu_usage_percent) || 0;
      el.cpuPct.textContent = `${cpu.toFixed(1)}%`;
      el.cpuBar.style.width = `${Math.min(cpu, 100)}%`;

      const memTotal = v.memory_total_mb || v.mem_total_mb || 0;
      const memUsed = v.memory_used_mb || v.mem_used_mb || 0;
      const memPct = (v.memory_usage_pct !== undefined ? v.memory_usage_pct : v.mem_usage_percent) || (memTotal ? (memUsed / memTotal * 100) : 0);
      el.memDetail.textContent = `${memUsed} / ${memTotal} MB (${memPct.toFixed(1)}%)`;
      el.memBar.style.width = `${Math.min(memPct, 100)}%`;

      const diskTotal = v.disk_total_gb || 0;
      const diskUsed = v.disk_used_gb || 0;
      const diskPct = (v.disk_usage_pct !== undefined ? v.disk_usage_pct : v.disk_usage_percent) || (diskTotal ? (diskUsed / diskTotal * 100) : 0);
      el.diskDetail.textContent = `${diskUsed.toFixed(1)} / ${diskTotal.toFixed(1)} GB (${diskPct.toFixed(1)}%)`;
      el.diskBar.style.width = `${Math.min(diskPct, 100)}%`;

      const rxRate = v.net_rx_rate_kbps || 0;
      const txRate = v.net_tx_rate_kbps || 0;
      el.netRxRate.textContent = `${rxRate.toFixed(1)} KB/s`;
      el.netTxRate.textContent = `${txRate.toFixed(1)} KB/s`;

      const totalRx = v.net_total_rx_mb || (v.net_rx_bytes ? (v.net_rx_bytes / 1048576) : 0);
      const totalTx = v.net_total_tx_mb || (v.net_tx_bytes ? (v.net_tx_bytes / 1048576) : 0);
      el.netTotal.textContent = `${(totalRx + totalTx).toFixed(1)} MB`;

      if (v.load_average && v.load_average.length >= 3) {
        el.loadAvg.textContent = `${v.load_average[0].toFixed(2)} / ${v.load_average[1].toFixed(2)} / ${v.load_average[2].toFixed(2)}`;
      }
      if (v.uptime_formatted) {
        el.vpsUptime.textContent = `Uptime: ${v.uptime_formatted}`;
      } else if (v.uptime_seconds) {
        const d = Math.floor(v.uptime_seconds / 86400);
        const h = Math.floor((v.uptime_seconds % 86400) / 3600);
        const m = Math.floor((v.uptime_seconds % 3600) / 60);
        el.vpsUptime.textContent = `Uptime: ${d}d ${h}h ${m}m`;
      }
    }

    // Cert
    if (data.cert) {
      el.certDomain.textContent = data.cert.domain || '--';
      const days = data.cert.days_remaining !== undefined ? data.cert.days_remaining : data.cert.days_left;
      if (days !== undefined) {
        el.certDaysBadge.textContent = `${days} 天到期`;
        el.certDaysBadge.className = 'badge ' + (days > 30 ? 'badge-success' : (days > 7 ? 'badge-warning' : 'badge-danger'));
      }
      if (data.cert.not_after || data.cert.expires_at) {
        const expStr = data.cert.not_after || new Date(data.cert.expires_at * 1000).toISOString();
        el.certExpires.textContent = expStr.replace('T', ' ').substring(0, 19);
      }
    }

    // Admin Sub URL
    if (data.admin_sub && data.admin_sub.url) {
      el.adminSubUrl.textContent = data.admin_sub.url;
    } else if (data.admin_sub_url) {
      el.adminSubUrl.textContent = data.admin_sub_url;
    }

    // WARP
    if (data.warp) {
      const running = !!(data.warp.running || data.warp.active);
      const installed = !!(data.warp.installed || running);
      el.warpStatusBadge.textContent = running ? '已接管出站 (SOCKS5 40000)' : (installed ? '可用，未开启' : '未检测到本机 WARP 代理');
      el.warpStatusBadge.className = 'badge ' + (running ? 'badge-success' : (installed ? 'badge-warning' : 'badge-danger'));

      if (!document.activeElement || document.activeElement !== el.warpToggle) {
        el.warpToggle.checked = !!running;
      }
    }

    // GeoData
    if (data.geodata) {
      if (el.geodataRulesCount) {
        el.geodataRulesCount.textContent = (data.geodata.rules_count || 0) + ' 条';
      }
      if (el.geodataLastUpdated) {
        const ts = data.geodata.last_updated;
        if (ts && ts > 0) {
          el.geodataLastUpdated.textContent = new Date(ts * 1000).toLocaleString('zh-CN', { hour12: false });
        } else {
          el.geodataLastUpdated.textContent = '初始化完成';
        }
      }
      if (el.geodataEtag) {
        el.geodataEtag.textContent = data.geodata.etag || '--';
      }
    }
  }

  async function fetchPurity(force = false) {
    try {
      el.btnRefreshPurity.disabled = true;
      el.btnRefreshPurity.textContent = '体检中...';
      const url = getApiUrl(`/console/api/purity${force ? '?force=1' : ''}`);
      const res = await fetch(url);
      if (res.ok) {
        const data = await res.json();
        updatePurityUI(data);
      }
    } catch (e) {
      console.warn('Purity fetch error:', e);
    } finally {
      el.btnRefreshPurity.disabled = false;
      el.btnRefreshPurity.textContent = '重新体检';
    }
  }

  function updatePurityUI(p) {
    const score = p.score !== undefined ? p.score : (p.purityScore || 0);
    el.purityScore.textContent = score;
    if (score >= 90) {
      el.scoreCircle.style.borderColor = 'var(--success)';
      el.scoreCircle.style.boxShadow = '0 0 20px rgba(16, 185, 129, 0.4)';
    } else if (score >= 60) {
      el.scoreCircle.style.borderColor = 'var(--warning)';
      el.scoreCircle.style.boxShadow = '0 0 20px rgba(245, 158, 11, 0.4)';
    } else {
      el.scoreCircle.style.borderColor = 'var(--danger)';
      el.scoreCircle.style.boxShadow = '0 0 20px rgba(239, 68, 68, 0.4)';
    }

    // Egress
    const ctry = p.ip_country || p.ipCountry || '未知';
    setBadge(el.badgeEgress, true, `物理出口: ${ctry}`);

    // YouTube
    const ytLoc = p.youtube_loc || p.youtubeLoc;
    const isYTOK = ytLoc && ytLoc !== 'CN';
    setBadge(el.badgeYT, isYTOK, `YouTube: ${isYTOK ? `[${ytLoc} 原生]` : (ytLoc === 'CN' ? '[送中 CN]' : '未检出')}`);

    // Google
    const gClean = p.google_clean !== undefined ? p.google_clean : p.googleClean;
    const gHK = p.google_hk_redirect !== undefined ? p.google_hk_redirect : p.googleHkRedirect;
    setBadge(el.badgeGoogle, gClean && !gHK, `Google: ${gHK ? '[重定向 HK]' : (gClean ? '[洁净正常]' : '[拦截/验证码]')}`);

    // Gemini
    const gemOK = p.gemini_ok !== undefined ? p.gemini_ok : (p.geminiOk !== undefined ? p.geminiOk : p.native_gemini_ok);
    const nativeGem = p.native_gemini_ok !== undefined ? p.native_gemini_ok : p.nativeGeminiOk;
    setBadge(el.badgeGemini, gemOK, `Gemini AI: ${gemOK ? (nativeGem ? '[原生解锁]' : '[WARP 解锁]') : '[区域封锁]'}`);

    // WARP Rescue
    const isWarp = p.is_warp_egress || p.isWarpEgress || (p.warp_running && p.warp_gemini_ok);
    setBadge(el.badgeWarpRescue, isWarp, `WARP 接管: ${isWarp ? '[已激活保障 AI]' : '[未激活]'}`);
  }

  function setBadge(item, isGood, text) {
    if (!item) return;
    const dot = item.querySelector('.badge-dot');
    const label = item.querySelector('span:last-child');
    if (dot) dot.className = `badge-dot ${isGood ? 'good' : 'bad'}`;
    if (label) label.textContent = text;
  }

  async function fetchUsers() {
    try {
      const res = await fetch(getApiUrl('/console/api/users'));
      if (!res.ok) return;
      const data = await res.json();
      renderUsersTable(data.users || []);
    } catch (e) {
      console.warn('Users fetch error:', e);
    }
  }

  function renderUsersTable(users) {
    if (!el.usersTableBody) return;
    if (users.length === 0) {
      el.usersTableBody.innerHTML = `<tr><td colspan="6" class="text-center" style="color: var(--text-muted); padding: 24px;">暂无用户订阅，请在上方表单中开通。</td></tr>`;
      return;
    }

    el.usersTableBody.innerHTML = users.map(u => {
      const isExp = u.is_expired || (u.expire_at > 0 && Math.floor(Date.now() / 1000) > u.expire_at);
      const isOver = u.is_traffic_exceeded || (u.traffic_limit_bytes > 0 && u.traffic_used_bytes >= u.traffic_limit_bytes);

      let statusBadge = '<span class="badge badge-success">正常有效</span>';
      if (isExp) statusBadge = '<span class="badge badge-danger">已到期</span>';
      else if (isOver) statusBadge = '<span class="badge badge-warning">流量超额</span>';

      const expDate = u.expire_at === 0 ? '永久有效' : new Date(u.expire_at * 1000).toLocaleDateString();
      const usedGB = (u.traffic_used_bytes / (1024 * 1024 * 1024)).toFixed(2);
      const limitGB = u.traffic_limit_bytes === 0 ? '无限' : `${(u.traffic_limit_bytes / (1024 * 1024 * 1024)).toFixed(0)} GB`;
      const usagePct = u.traffic_limit_bytes > 0 ? Math.min((u.traffic_used_bytes / u.traffic_limit_bytes) * 100, 100).toFixed(1) : 0;

      return `
        <tr>
          <td><strong>${escapeHtml(u.slug || u.username)}</strong></td>
          <td>${statusBadge}</td>
          <td>${expDate}</td>
          <td>
            <div style="font-size: 0.8rem; margin-bottom: 4px;">${usedGB} / ${limitGB} (${usagePct}%)</div>
            <div class="progress-bar" style="height: 6px;"><div class="progress-fill" style="width: ${usagePct}%;"></div></div>
          </td>
          <td>
            <div style="display: flex; gap: 6px; flex-wrap: wrap;">
              <button class="btn btn-secondary btn-sm" onclick="window.AeroCopy('${escapeHtml(u.sub_url)}')">复制零端口链接</button>
              ${u.direct_sub_url && u.direct_sub_url !== u.sub_url ? `<button class="btn btn-secondary btn-sm" style="border-color: var(--blue);" onclick="window.AeroCopy('${escapeHtml(u.direct_sub_url)}')">复制直连链接 (测试用)</button>` : ''}
            </div>
          </td>
          <td>
            <button class="btn btn-danger btn-sm" onclick="window.AeroDeleteUser('${escapeHtml(u.slug)}')">删除</button>
          </td>
        </tr>
      `;
    }).join('');
  }

  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  // 4. Actions
  window.AeroCopy = function(url) {
    copyText(url);
  };

  window.AeroDeleteUser = async function(slug) {
    if (!confirm(`确定要注销并删除用户 [${slug}] 的专属订阅吗？`)) return;
    try {
      const res = await fetch(getApiUrl(`/console/api/users?slug=${encodeURIComponent(slug)}`), {
        method: 'DELETE'
      });
      if (res.ok) {
        showToast(`用户 ${slug} 已删除`);
        fetchUsers();
      } else {
        alert('删除失败，请检查管理权限');
      }
    } catch (e) {
      alert(`删除请求错误: ${e.message}`);
    }
  };

  // 5. Event Listeners
  if (el.btnCopyAdminSub) {
    el.btnCopyAdminSub.addEventListener('click', () => {
      copyText(el.adminSubUrl.textContent.trim());
    });
  }

  if (el.btnGenCode) {
    el.btnGenCode.addEventListener('click', () => {
      el.newCode.value = genRandomCode();
    });
  }

  if (el.btnRefreshPurity) {
    el.btnRefreshPurity.addEventListener('click', () => {
      fetchPurity(true);
    });
  }

  if (el.createUserForm) {
    el.createUserForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = el.newUsername.value.trim();
      const code = el.newCode.value.trim();
      const expireDays = parseInt(el.newExpireDays.value, 10);
      const trafficGB = parseInt(el.newTrafficGB.value, 10);

      try {
        const payload = {
          username: username,
          expire_days: expireDays,
          traffic_limit_gb: trafficGB
        };
        if (code) {
          payload.code = code;
        }
        const res = await fetch(getApiUrl('/console/api/users'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const result = await res.json();
        if (res.ok && result.ok) {
          showToast(`用户 ${result.slug} 创建成功！`);
          copyText(result.sub_url);
          el.newUsername.value = '';
          el.newCode.value = genRandomCode();
          fetchUsers();
        } else {
          alert(`创建失败: ${result.error || '未知错误'}`);
        }
      } catch (err) {
        alert(`请求失败: ${err.message || '网络连接超时或服务未就绪'}`);
      }
    });
  }

  // WARP Toggles
  async function updateWarpToggle() {
    const enabled = el.warpToggle.checked;
    try {
      const res = await fetch(getApiUrl('/console/api/warp/toggle'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: enabled, warp_all: true })
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.error || '切换失败');
        fetchStatus();
      } else {
        showToast(enabled ? 'WARP 出站接管已开启 (全量经由 WARP)' : 'WARP 出站接管已关闭 (直连)');
      }
    } catch (e) {
      alert(`WARP 设置失败: ${e.message}`);
      fetchStatus();
    }
  }

  if (el.warpToggle) el.warpToggle.addEventListener('change', updateWarpToggle);

  // GeoData Sync Handler
  if (el.btnUpdateGeoData) {
    el.btnUpdateGeoData.addEventListener('click', async () => {
      try {
        el.btnUpdateGeoData.disabled = true;
        el.btnUpdateGeoData.textContent = '同步中...';
        const res = await fetch(getApiUrl('/console/api/geodata/update'), { method: 'POST' });
        const data = await res.json();
        if (res.ok && data.ok) {
          showToast(`GeoData 同步成功 (${data.rules_count} 条规则)`);
          fetchStatus();
        } else {
          alert(`同步失败: ${data.error || '未知错误'}`);
        }
      } catch (e) {
        alert(`请求异常: ${e.message}`);
      } finally {
        el.btnUpdateGeoData.disabled = false;
        el.btnUpdateGeoData.textContent = '立即同步上游规则';
      }
    });
  }

  // 6. Initialization
  if (el.newCode) {
    el.newCode.value = genRandomCode();
  }

  fetchStatus();
  fetchPurity();
  fetchUsers();

  setInterval(fetchStatus, 2000);
  setInterval(fetchUsers, 10000);
})();
