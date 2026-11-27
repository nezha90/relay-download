const STORAGE_KEY = 'relay_admin_token';
const WINDOW_STORAGE_KEY = 'relay_window_spec';

// Persist token in localStorage (migrating any legacy sessionStorage token).
function loadStoredToken() {
  let tok = '';
  try {
    tok = localStorage.getItem(STORAGE_KEY) || '';
    if (!tok) {
      const legacy = sessionStorage.getItem(STORAGE_KEY) || '';
      if (legacy) {
        tok = legacy;
        localStorage.setItem(STORAGE_KEY, legacy);
        sessionStorage.removeItem(STORAGE_KEY);
      }
    }
    if (window.location.hash && window.location.hash.startsWith('#token=')) {
      const fromHash = decodeURIComponent(window.location.hash.slice('#token='.length)).trim();
      if (fromHash) {
        tok = fromHash;
        localStorage.setItem(STORAGE_KEY, tok);
        history.replaceState(null, '', window.location.pathname + window.location.search);
      }
    }
  } catch {
    // Ignore storage quota / privacy mode exceptions.
  }
  return tok;
}

function saveStoredToken(tok) {
  adminToken = tok || '';
  try {
    if (adminToken) localStorage.setItem(STORAGE_KEY, adminToken);
    else localStorage.removeItem(STORAGE_KEY);
    sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    // Ignore storage errors.
  }
}

let adminToken = loadStoredToken();
let authTrustedIP = false;
let authRole = 'admin';
let authAccountID = '';
let authAccountName = '';
let authProjects = [];
let cachedReleases = [];
let cachedProjects = [];
let cachedNodes = [];
let cachedAccounts = [];
let lastAccountToken = '';
let lastAccountLoginURL = '';
let lastPrecheck = null;
let activeDeployTaskId = '';
let activeLogModalTaskId = '';
let activeProjectDetailId = '';
let lastProjectsWinHours = 24;
let selectedProjectFilter = '';
const projectViewState = {
  search: '',
  filter: 'all',      // 'all' | 'live' | 'recent' | 'attention' | 'idle'
  groupBy: 'status',  // 'status' | 'customer' | 'none'
  sortBy: 'activity', // 'activity' | 'queued' | 'bytes' | 'recent' | 'created' | 'name'
  collapsedGroups: new Set(),
  userToggledGroups: new Set(),
};
const selectedNodes = { agent_a: new Set(), agent_b: new Set() };

function getWindowSpec() {
  const sel = document.getElementById('window-select');
  const raw = (sel && sel.value) || '24:30';
  const [hStr, bStr] = raw.split(':');
  const hours = Number(hStr) || 24;
  const bucketMin = Number(bStr) || 30;
  return { raw, hours, bucketMin };
}

function windowLabel(hours) {
  if (hours === 24) return '近 24 小时';
  if (hours % 24 === 0 && hours > 24) return `近 ${hours / 24} 天`;
  return `近 ${hours} 小时`;
}

function fmtBytes(bytes) {
  if (!bytes || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let i = 0, v = bytes;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
}

function fmtSpeed(bps) {
  if (!bps || bps <= 0) return '0 B/s';
  return `${fmtBytes(bps)}/s`;
}

function fmtMbps(bps) {
  if (!bps || bps <= 0) return '0 Mbps';
  const bits = bps * 8;
  if (bits >= 1e9) return `${(bits / 1e9).toFixed(2)} Gbps`;
  if (bits >= 1e6) return `${(bits / 1e6).toFixed(1)} Mbps`;
  if (bits >= 1e3) return `${(bits / 1e3).toFixed(0)} Kbps`;
  return `${bits.toFixed(0)} bps`;
}

function fmtNum(n) {
  return Number(n || 0).toLocaleString('zh-CN');
}

function pad2(n) {
  return String(n).padStart(2, '0');
}

function fmtTimeShort(iso, showDate) {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  const hm = `${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
  if (!showDate) return hm;
  return `${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${hm}`;
}

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));
}

function generateShortId(prefix) {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
  const bytes = new Uint8Array(6);
  if (window.crypto && window.crypto.getRandomValues) {
    window.crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < bytes.length; i++) bytes[i] = Math.floor(Math.random() * 256);
  }
  let suffix = '';
  for (let i = 0; i < bytes.length; i++) {
    suffix += alphabet[bytes[i] % alphabet.length];
  }
  return `${prefix}-${suffix}`;
}

function shortId(id) {
  const s = String(id || '');
  return s.length > 14 ? `${s.slice(0, 8)}…` : s;
}

function getProjectMeta(projectId) {
  const pid = String(projectId || '');
  const found = cachedProjects.find(ps => ps.project && ps.project.id === pid)?.project;
  const name = (found && found.name) || pid;
  const desc = (found && found.description) || '';
  return { id: pid, name, desc, shortId: shortId(pid), hasDistinctName: name !== pid };
}

function formatProjectOption(p) {
  if (!p) return '';
  if (p.name && p.name !== p.id) {
    const descPart = p.description ? ` · ${p.description.slice(0, 24)}` : '';
    return `${p.name} (${shortId(p.id)})${descPart}`;
  }
  return p.id;
}

function getAccountName(accId) {
  if (!accId) return '';
  const acc = cachedAccounts.find(a => a.id === accId);
  return acc ? (acc.name || acc.id) : accId;
}

function populateOwnerAccountSelect(selectEl, currentOwner = '') {
  if (!selectEl) return;
  const opts = ['<option value="">仅管理员托管（不归属客户）</option>'];
  for (const a of cachedAccounts) {
    const st = a.enabled === false ? ' [已停用]' : '';
    opts.push(`<option value="${esc(a.id)}">${esc(a.name || a.id)} (${esc(a.id)})${st}</option>`);
  }
  if (currentOwner && !cachedAccounts.some(a => a.id === currentOwner)) {
    opts.push(`<option value="${esc(currentOwner)}">${esc(currentOwner)}</option>`);
  }
  selectEl.innerHTML = opts.join('');
  selectEl.value = currentOwner || '';
}

async function copyText(text, okMsg = '已复制到剪贴板') {
  if (!text) return false;
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      throw new Error('clipboard api unavailable');
    }
    showToast(okMsg, 'success');
    return true;
  } catch {
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand('copy');
      ta.remove();
      if (ok) {
        showToast(okMsg, 'success');
        return true;
      }
    } catch {}
    showToast('剪贴板复制失败，请手动选中文本复制', 'error');
    return false;
  }
}

function buildTerminalExecCommand(script, nodeId, rolePrefix) {
  const safeId = String(nodeId || 'node').replace(/[^A-Za-z0-9._-]/g, '_');
  const tmpFile = `/tmp/install-${rolePrefix}-${safeId}.sh`;
  let delim = `RELAY_RUN_${Math.random().toString(16).slice(2, 10).toUpperCase()}`;
  while (script.includes(delim)) {
    delim += 'X';
  }
  const body = script.endsWith('\n') ? script : script + '\n';
  return `cat > ${tmpFile} <<'${delim}'\n${body}${delim}\nchmod +x ${tmpFile} && $(command -v sudo || true) bash ${tmpFile} && rm -f ${tmpFile}`;
}

function downloadTextFile(filename, content) {
  const blob = new Blob([content], { type: 'text/x-shellscript;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function api(path, opts = {}) {
  const isFormData = opts.body instanceof FormData;
  const headers = {
    'X-Relay-UI': '1',
    ...(adminToken ? { 'X-Admin-Token': adminToken } : {}),
    ...(isFormData ? {} : { 'Content-Type': 'application/json' }),
    ...(opts.headers || {}),
  };
  const res = await fetch(path, { ...opts, headers });
  if (res.status === 401) {
    authTrustedIP = false;
    updateAuthControls();
    if (adminToken) {
      saveStoredToken('');
      showLogin('本地缓存的 Admin Token 已失效，请重新输入');
    } else {
      showLogin('');
    }
    throw new Error('unauthorized');
  }
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

function isCustomer() {
  return authRole === 'customer';
}

function isScopedCustomer() {
  // All customer accounts are strictly default-deny (no wildcard all-projects access).
  return isCustomer();
}

function updateAuthControls() {
  const trustedBadge = document.getElementById('trusted-badge');
  const roleBadge = document.getElementById('role-badge');
  const logoutBtn = document.getElementById('logout-btn');
  if (trustedBadge) trustedBadge.classList.toggle('hidden', !authTrustedIP || isCustomer());
  if (roleBadge) {
    if (isCustomer()) {
      const label = authAccountName || authAccountID || '客户账号';
      roleBadge.textContent = `客户 · ${label}`;
      const projNames = (authProjects || []).map(pid => getProjectMeta(pid).name);
      roleBadge.title = projNames.length
        ? `客户受限账号（仅限自有接收节点 · 授权项目: ${projNames.join(', ')}）`
        : '客户受限账号（暂未分配项目，请联系管理员授权）';
      roleBadge.classList.remove('hidden');
    } else {
      roleBadge.classList.add('hidden');
    }
  }
  if (logoutBtn) logoutBtn.classList.toggle('hidden', !adminToken);
}

function applyRoleUI() {
  const cust = isCustomer();
  document.querySelectorAll('[data-admin-only="1"]').forEach(el => {
    if (el.classList.contains('overlay')) {
      if (cust) el.classList.add('hidden');
      return;
    }
    el.classList.toggle('hidden', cust);
    if (el.tagName === 'OPTION') {
      el.disabled = cust;
      el.hidden = cust;
    }
  });
  if (cust && projectViewState.groupBy === 'customer') {
    projectViewState.groupBy = 'status';
    const grpSel = document.getElementById('projects-group-by');
    if (grpSel) grpSel.value = 'status';
  }
  const projDesc = document.getElementById('projects-section-desc');
  if (projDesc) {
    projDesc.textContent = cust
      ? '默认按活跃度分组置顶；点击任意项目行按需查看传输详情、节点状态与速度曲线'
      : '默认按活跃度分组置顶；点击任意项目行按需查看详情、节点积压与策略配置';
  }
  if (cust) {
    const activeTab = document.querySelector('.tab.active');
    if (activeTab && activeTab.dataset.adminOnly === '1') {
      document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
      const dashTab = document.querySelector('.tab[data-tab="dashboard"]');
      if (dashTab) dashTab.classList.add('active');
      const dashPanel = document.getElementById('tab-dashboard');
      if (dashPanel) dashPanel.classList.add('active');
    }
  }
  updateAuthControls();
}

function showLogin(msg = '') {
  document.getElementById('login-err').textContent = msg;
  document.getElementById('login-overlay').classList.remove('hidden');
}

function hideLogin() {
  document.getElementById('login-overlay').classList.add('hidden');
}

function openModal(id) { document.getElementById(id).classList.remove('hidden'); }
function closeModal(id) {
  document.getElementById(id)?.classList.add('hidden');
  if (id === 'project-detail-modal') activeProjectDetailId = '';
}

function showToast(msg, type = 'info', durationMs = 3200) {
  const stack = document.getElementById('toast-stack');
  if (!stack || !msg) return;
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.innerHTML = `<span class="toast-dot"></span><span>${esc(msg)}</span>`;
  stack.appendChild(el);
  const remove = () => {
    el.classList.add('leaving');
    setTimeout(() => el.remove(), 240);
  };
  const timer = setTimeout(remove, durationMs);
  el.addEventListener('click', () => {
    clearTimeout(timer);
    remove();
  });
}

function populateProjectSelect(selectEl, currentValue = '', includeCustomOption = true) {
  if (!selectEl) return;
  const opts = [];
  for (const ps of cachedProjects) {
    const p = ps.project;
    opts.push(`<option value="${esc(p.id)}">${esc(formatProjectOption(p))}</option>`);
  }
  if (currentValue && !cachedProjects.some(ps => ps.project.id === currentValue)) {
    opts.unshift(`<option value="${esc(currentValue)}">${esc(currentValue)}</option>`);
  }
  if (includeCustomOption) {
    opts.push('<option value="__custom__">手动输入项目 ID...</option>');
  }
  if (!opts.length) {
    opts.push('<option value="">暂无已授权项目（请联系管理员分配）</option>');
  }
  selectEl.innerHTML = opts.join('');
  if (currentValue) {
    selectEl.value = currentValue;
  }
}

async function refreshAll() {
  const btn = document.getElementById('refresh-now');
  if (btn) {
    btn.disabled = true;
    btn.classList.add('is-loading');
  }
  try {
    const { hours, bucketMin } = getWindowSpec();
    const ovQS = new URLSearchParams({
      hours: String(hours),
      bucket_min: String(bucketMin),
    });
    if (selectedProjectFilter) ovQS.set('project', selectedProjectFilter);

    const overview = await api(`/api/v1/admin/overview?${ovQS.toString()}`);

    authTrustedIP = !!overview.auth_trusted_ip;
    authRole = overview.auth_role || 'admin';
    authAccountID = overview.auth_account_id || '';
    authAccountName = overview.auth_account_name || '';
    authProjects = Array.isArray(overview.auth_projects) ? overview.auth_projects : [];
    hideLogin();
    applyRoleUI();

    const adminFetches = isCustomer()
      ? [Promise.resolve([]), Promise.resolve([])]
      : [api('/api/v1/admin/deploy/tasks'), api('/api/v1/admin/accounts')];
    const [nodes, releases, tasks, accounts] = await Promise.all([
      api(`/api/v1/admin/nodes?hours=${encodeURIComponent(hours)}`),
      api('/api/v1/admin/releases'),
      ...adminFetches,
    ]);

    const snapEl = document.getElementById('snapshot-time');
    if (snapEl && overview.generated_at) {
      snapEl.textContent = `统计截至 ${fmtTimeShort(overview.generated_at, false)}`;
    }

    cachedProjects = overview.projects || [];
    cachedNodes = nodes || [];
    cachedReleases = releases || [];
    cachedAccounts = accounts || [];
    lastProjectsWinHours = overview.window_hours || hours;
    syncProjectFilterOptions(cachedProjects);
    renderDashboard(overview);
    renderProjects(cachedProjects, lastProjectsWinHours);
    if (activeProjectDetailId && !document.getElementById('project-detail-modal')?.classList.contains('hidden')) {
      renderProjectDetailModal(activeProjectDetailId, lastProjectsWinHours);
    }
    renderNodes(cachedNodes, lastProjectsWinHours);
    renderReleases(cachedReleases);
    if (!isCustomer()) {
      renderDeployTasks(tasks || []);
      renderAccounts(cachedAccounts);
      syncProjectGuideCustomerOptions(cachedAccounts);
    }
  } catch (e) {
    if (e.message !== 'unauthorized') console.error(e);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.classList.remove('is-loading');
    }
  }
}

async function refreshCurveOnly() {
  try {
    const { hours, bucketMin } = getWindowSpec();
    const qs = new URLSearchParams({
      hours: String(hours),
      bucket_min: String(bucketMin),
    });
    if (selectedProjectFilter) qs.set('project', selectedProjectFilter);
    const intervalResp = await api(`/api/v1/admin/stats/intervals?${qs.toString()}`);
    renderSpeedCurve({
      buckets: intervalResp.buckets || [],
      windowHours: intervalResp.window_hours || hours,
      bucketMinutes: intervalResp.bucket_minutes || bucketMin,
      windowAvg: intervalResp.window_avg_speed_bps || 0,
      activeAvg: intervalResp.active_avg_speed_bps || 0,
      peakSpeed: intervalResp.peak_speed_bps || 0,
      totalBytes: intervalResp.total_bytes || 0,
      totalCompleted: intervalResp.total_completed || 0,
      totalFailed: intervalResp.total_failed || 0,
    });
  } catch (e) {
    if (e.message !== 'unauthorized') console.error(e);
  }
}

function syncProjectFilterOptions(projects) {
  const sel = document.getElementById('curve-project-filter');
  if (!sel) return;
  const opts = ['<option value="">全部可见项目</option>'];
  for (const ps of projects) {
    const p = ps.project;
    opts.push(`<option value="${esc(p.id)}">${esc(formatProjectOption(p))}</option>`);
  }
  sel.innerHTML = opts.join('');
  if (selectedProjectFilter && projects.some(ps => ps.project.id === selectedProjectFilter)) {
    sel.value = selectedProjectFilter;
  } else {
    selectedProjectFilter = '';
    sel.value = '';
  }
}

function renderDashboard(ov) {
  const winHours = ov.window_hours || 24;
  const winLbl = windowLabel(winHours);
  const kpis = [
    {
      highlight: true,
      label: `${winLbl}平均速率`,
      value: fmtSpeed(ov.window_avg_speed_bps),
      unit: fmtMbps(ov.window_avg_speed_bps),
      sub: `活跃时段均速 ${fmtSpeed(ov.active_avg_speed_bps)} · 区间峰值 ${fmtSpeed(ov.window_peak_speed_bps)}`,
    },
    {
      label: `${winLbl}完成 / 流量`,
      value: `${fmtNum(ov.window_completed)} 文件`,
      sub: `区间流量 ${fmtBytes(ov.window_bytes)} · 失败 ${fmtNum(ov.window_failed)}`,
    },
    {
      label: '今日完成 / 流量 (UTC)',
      value: `${fmtNum(ov.today_completed)} 文件`,
      sub: `今日流量 ${fmtBytes(ov.today_bytes)} · 失败 ${fmtNum(ov.today_failed)}`,
    },
    {
      label: '累计汇总完成',
      value: `${fmtNum(ov.all_time_completed)} 文件`,
      sub: `累计 ${fmtBytes(ov.all_time_bytes)} · 失败 ${fmtNum(ov.all_time_failed)}`,
    },
    isCustomer()
      ? {
          label: '在线接收节点',
          value: `${ov.online_b_nodes}/${ov.total_b_nodes}`,
          sub: `授权项目 ${ov.total_projects} · 待传输积压 ${fmtNum(ov.queued_files)} (${fmtBytes(ov.queued_bytes)})`,
        }
      : {
          label: '在线节点 (分发 / 接收)',
          value: `${ov.online_a_nodes}/${ov.total_a_nodes} · ${ov.online_b_nodes}/${ov.total_b_nodes}`,
          sub: `项目 ${ov.total_projects} · 待传输积压 ${fmtNum(ov.queued_files)} (${fmtBytes(ov.queued_bytes)})`,
        },
  ];
  document.getElementById('kpi-grid').innerHTML = kpis.map(k => `
    <div class="kpi-card${k.highlight ? ' highlight' : ''}">
      <div class="kpi-label">${esc(k.label)}</div>
      <div class="kpi-value">
        <span>${esc(k.value)}</span>
        ${k.unit ? `<span class="kpi-unit">${esc(k.unit)}</span>` : ''}
      </div>
      <div class="kpi-sub">${esc(k.sub)}</div>
    </div>
  `).join('');

  renderSpeedCurve({
    buckets: ov.interval_curve || [],
    windowHours: winHours,
    bucketMinutes: ov.bucket_minutes || 30,
    windowAvg: ov.window_avg_speed_bps || 0,
    activeAvg: ov.active_avg_speed_bps || 0,
    peakSpeed: ov.window_peak_speed_bps || 0,
    totalBytes: ov.window_bytes || 0,
    totalCompleted: ov.window_completed || 0,
    totalFailed: ov.window_failed || 0,
  });

  renderTrendChart(ov.daily_trend || []);
}

// Monotone cubic Hermite spline (Fritsch-Carlson) so the speed curve is smooth
// without overshooting below 0 or spiking past true interval peaks.
function buildMonotonePath(pts) {
  const n = pts.length;
  if (n === 0) return '';
  if (n === 1) return `M ${pts[0].x.toFixed(1)} ${pts[0].y.toFixed(1)}`;
  const dx = new Array(n - 1);
  const dy = new Array(n - 1);
  const slopes = new Array(n - 1);
  for (let i = 0; i < n - 1; i++) {
    dx[i] = pts[i + 1].x - pts[i].x;
    dy[i] = pts[i + 1].y - pts[i].y;
    slopes[i] = dx[i] !== 0 ? dy[i] / dx[i] : 0;
  }
  const m = new Array(n);
  m[0] = slopes[0];
  m[n - 1] = slopes[n - 2];
  for (let i = 1; i < n - 1; i++) {
    if (slopes[i - 1] * slopes[i] <= 0) {
      m[i] = 0;
    } else {
      m[i] = (slopes[i - 1] + slopes[i]) / 2;
    }
  }
  for (let i = 0; i < n - 1; i++) {
    if (slopes[i] === 0) {
      m[i] = 0;
      m[i + 1] = 0;
    } else {
      const a = m[i] / slopes[i];
      const b = m[i + 1] / slopes[i];
      const h = Math.hypot(a, b);
      if (h > 3) {
        const t = 3 / h;
        m[i] = t * a * slopes[i];
        m[i + 1] = t * b * slopes[i];
      }
    }
  }
  let d = `M ${pts[0].x.toFixed(1)} ${pts[0].y.toFixed(1)}`;
  for (let i = 0; i < n - 1; i++) {
    const step = dx[i] / 3;
    const cx1 = pts[i].x + step;
    const cy1 = pts[i].y + m[i] * step;
    const cx2 = pts[i + 1].x - step;
    const cy2 = pts[i + 1].y - m[i + 1] * step;
    d += ` C ${cx1.toFixed(1)} ${cy1.toFixed(1)}, ${cx2.toFixed(1)} ${cy2.toFixed(1)}, ${pts[i + 1].x.toFixed(1)} ${pts[i + 1].y.toFixed(1)}`;
  }
  return d;
}

function niceSpeedCeiling(maxBps) {
  if (!maxBps || maxBps <= 0) return 1024 * 1024;
  const raw = maxBps * 1.15;
  const pow = Math.pow(10, Math.floor(Math.log10(raw)));
  const norm = raw / pow;
  let step = 10;
  if (norm <= 1.2) step = 1.2;
  else if (norm <= 1.5) step = 1.5;
  else if (norm <= 2) step = 2;
  else if (norm <= 2.5) step = 2.5;
  else if (norm <= 3) step = 3;
  else if (norm <= 4) step = 4;
  else if (norm <= 5) step = 5;
  else if (norm <= 6) step = 6;
  else if (norm <= 8) step = 8;
  return step * pow;
}

function renderSpeedCurve(data) {
  const {
    buckets, windowHours, bucketMinutes,
    windowAvg, activeAvg, peakSpeed,
    totalBytes, totalCompleted, totalFailed,
  } = data;

  const winLbl = windowLabel(windowHours);
  const titleEl = document.getElementById('curve-title');
  const subEl = document.getElementById('curve-subtitle');
  if (titleEl) {
    const projLbl = selectedProjectFilter ? getProjectMeta(selectedProjectFilter).name : '';
    titleEl.textContent = `${winLbl}平均速度曲线${projLbl ? ` · ${projLbl}` : ''}`;
  }
  if (subEl) {
    const gran = bucketMinutes >= 60 ? `${bucketMinutes / 60} 小时` : `${bucketMinutes} 分钟`;
    subEl.textContent = `区间粒度：每 ${gran} 一点 · 仅统计已落盘校验完成字节，非瞬时抖动速率`;
  }

  document.getElementById('curve-metrics').innerHTML = `
    <div class="metric-pill">
      <div class="pill-k">${esc(winLbl)}全周期均速</div>
      <div class="pill-v">${esc(fmtSpeed(windowAvg))}</div>
      <div class="pill-s">${esc(fmtMbps(windowAvg))}</div>
    </div>
    <div class="metric-pill">
      <div class="pill-k">活跃区间平均速率</div>
      <div class="pill-v">${esc(fmtSpeed(activeAvg))}</div>
      <div class="pill-s">${esc(fmtMbps(activeAvg))} (仅计有传输时段)</div>
    </div>
    <div class="metric-pill">
      <div class="pill-k">区间峰值均速</div>
      <div class="pill-v">${esc(fmtSpeed(peakSpeed))}</div>
      <div class="pill-s">${esc(fmtMbps(peakSpeed))}</div>
    </div>
    <div class="metric-pill">
      <div class="pill-k">区间完成汇总</div>
      <div class="pill-v">${esc(fmtBytes(totalBytes))}</div>
      <div class="pill-s">${esc(fmtNum(totalCompleted))} 文件 · 失败 ${esc(fmtNum(totalFailed))}</div>
    </div>
  `;

  const chartEl = document.getElementById('speed-curve-chart');
  const tooltipEl = document.getElementById('speed-tooltip');
  tooltipEl.classList.add('hidden');

  if (!buckets || !buckets.length) {
    chartEl.innerHTML = '<div class="empty">当前时间窗口暂无阶段统计数据</div>';
    return;
  }

  const w = 960, h = 280;
  const padL = 78, padR = 24, padT = 22, padB = 38;
  const plotW = w - padL - padR;
  const plotH = h - padT - padB;

  const maxData = Math.max(peakSpeed, windowAvg, activeAvg, 0);
  const yMax = niceSpeedCeiling(maxData);
  const showDate = windowHours > 24;

  const pts = buckets.map((b, idx) => {
    const x = buckets.length === 1
      ? padL + plotW / 2
      : padL + (idx / (buckets.length - 1)) * plotW;
    const ratio = Math.min(1, Math.max(0, (b.avg_speed_bps || 0) / yMax));
    const y = padT + plotH - ratio * plotH;
    return { x, y, b, idx };
  });

  const lineD = buildMonotonePath(pts);
  const baseY = padT + plotH;
  const areaD = `${lineD} L ${pts[pts.length - 1].x.toFixed(1)} ${baseY.toFixed(1)} L ${pts[0].x.toFixed(1)} ${baseY.toFixed(1)} Z`;

  const yTicks = [0, 0.25, 0.5, 0.75, 1].map(frac => {
    const val = yMax * frac;
    const y = padT + plotH - frac * plotH;
    return `
      <line x1="${padL}" y1="${y.toFixed(1)}" x2="${w - padR}" y2="${y.toFixed(1)}" stroke="#263040" stroke-width="1" />
      <text x="${padL - 10}" y="${(y + 4).toFixed(1)}" text-anchor="end" fill="#8b949e" font-size="11">${esc(fmtSpeed(val))}</text>
    `;
  }).join('');

  const tickCount = Math.min(buckets.length, showDate ? 6 : 8);
  const xTickIdxs = new Set();
  if (tickCount <= 1) {
    xTickIdxs.add(0);
  } else {
    for (let t = 0; t < tickCount; t++) {
      xTickIdxs.add(Math.round((t * (buckets.length - 1)) / (tickCount - 1)));
    }
  }
  const xTicks = Array.from(xTickIdxs).map(idx => {
    const pt = pts[idx];
    const lbl = fmtTimeShort(pt.b.bucket_start, showDate);
    return `
      <line x1="${pt.x.toFixed(1)}" y1="${baseY}" x2="${pt.x.toFixed(1)}" y2="${baseY + 5}" stroke="#3b475a" stroke-width="1" />
      <text x="${pt.x.toFixed(1)}" y="${baseY + 20}" text-anchor="middle" fill="#8b949e" font-size="11">${esc(lbl)}</text>
    `;
  }).join('');

  let refLines = '';
  if (windowAvg > 0) {
    const avgY = padT + plotH - Math.min(1, windowAvg / yMax) * plotH;
    refLines += `
      <line x1="${padL}" y1="${avgY.toFixed(1)}" x2="${w - padR}" y2="${avgY.toFixed(1)}"
            stroke="#f59e0b" stroke-width="1.4" stroke-dasharray="5 4" opacity="0.85" />
    `;
  }
  if (activeAvg > 0 && Math.abs(activeAvg - windowAvg) > yMax * 0.04) {
    const actY = padT + plotH - Math.min(1, activeAvg / yMax) * plotH;
    refLines += `
      <line x1="${padL}" y1="${actY.toFixed(1)}" x2="${w - padR}" y2="${actY.toFixed(1)}"
            stroke="#22c55e" stroke-width="1.3" stroke-dasharray="3 4" opacity="0.75" />
    `;
  }

  const dots = pts.filter(p => (p.b.avg_speed_bps || 0) > 0).map(p => `
    <circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="2.8" fill="#38bdf8" stroke="#0d1117" stroke-width="1.2" />
  `).join('');

  const hitBands = pts.map((p, i) => {
    const prevX = i === 0 ? padL : (pts[i - 1].x + p.x) / 2;
    const nextX = i === pts.length - 1 ? w - padR : (p.x + pts[i + 1].x) / 2;
    return `<rect class="curve-hit" data-idx="${i}" x="${prevX.toFixed(1)}" y="${padT}" width="${Math.max(4, nextX - prevX).toFixed(1)}" height="${plotH}" fill="transparent" />`;
  }).join('');

  chartEl.innerHTML = `
    <svg class="speed-svg" viewBox="0 0 ${w} ${h}">
      <defs>
        <linearGradient id="speedAreaGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#38bdf8" stop-opacity="0.34" />
          <stop offset="52%" stop-color="#3b82f6" stop-opacity="0.14" />
          <stop offset="100%" stop-color="#3b82f6" stop-opacity="0" />
        </linearGradient>
        <linearGradient id="speedStrokeGrad" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stop-color="#3b82f6" />
          <stop offset="50%" stop-color="#38bdf8" />
          <stop offset="100%" stop-color="#60a5fa" />
        </linearGradient>
      </defs>
      ${yTicks}
      ${xTicks}
      ${refLines}
      <path d="${areaD}" fill="url(#speedAreaGrad)" />
      <path class="speed-line-glow" d="${lineD}" fill="none" stroke="url(#speedStrokeGrad)" stroke-width="2.6" stroke-linejoin="round" stroke-linecap="round" />
      ${dots}
      <line id="curve-hover-line" x1="0" y1="${padT}" x2="0" y2="${baseY}" stroke="#38bdf8" stroke-width="1" stroke-dasharray="3 3" visibility="hidden" />
      <circle id="curve-hover-dot" cx="0" cy="0" r="5.5" fill="#38bdf8" stroke="#ffffff" stroke-width="2" visibility="hidden" />
      ${hitBands}
    </svg>
    <div class="curve-legend">
      <span class="legend-item"><span class="legend-swatch line"></span>区间平均速率曲线</span>
      <span class="legend-item"><span class="legend-swatch avg"></span>${esc(winLbl)}均速 (${esc(fmtSpeed(windowAvg))})</span>
      ${activeAvg > 0 ? `<span class="legend-item"><span class="legend-swatch active-avg"></span>活跃时段均速 (${esc(fmtSpeed(activeAvg))})</span>` : ''}
      ${maxData === 0 ? '<span class="muted">当前时间窗内暂无已完成传输记录</span>' : ''}
    </div>
  `;

  const svgEl = chartEl.querySelector('svg');
  const hoverLine = svgEl.querySelector('#curve-hover-line');
  const hoverDot = svgEl.querySelector('#curve-hover-dot');
  const stageEl = document.getElementById('speed-curve-wrap');

  const showTip = (idx) => {
    const pt = pts[idx];
    if (!pt) return;
    const b = pt.b;
    hoverLine.setAttribute('x1', pt.x.toFixed(1));
    hoverLine.setAttribute('x2', pt.x.toFixed(1));
    hoverLine.setAttribute('visibility', 'visible');
    hoverDot.setAttribute('cx', pt.x.toFixed(1));
    hoverDot.setAttribute('cy', pt.y.toFixed(1));
    hoverDot.setAttribute('visibility', 'visible');

    const startStr = fmtTimeShort(b.bucket_start, true);
    const endStr = fmtTimeShort(b.bucket_end, false);
    tooltipEl.innerHTML = `
      <div class="tt-time">${esc(startStr)} ~ ${esc(endStr)}</div>
      <div class="tt-speed">${esc(fmtSpeed(b.avg_speed_bps))} <span class="muted">(${esc(fmtMbps(b.avg_speed_bps))})</span></div>
      <div class="tt-row"><span>区间传输流量</span><strong>${esc(fmtBytes(b.bytes_transferred))}</strong></div>
      <div class="tt-row"><span>区间完成文件</span><strong>${esc(fmtNum(b.files_completed))}</strong></div>
      <div class="tt-row"><span>区间失败次数</span><strong>${esc(fmtNum(b.files_failed))}</strong></div>
    `;
    tooltipEl.classList.remove('hidden');

    const rect = stageEl.getBoundingClientRect();
    const pxX = (pt.x / w) * rect.width;
    const pxY = (pt.y / h) * rect.height;
    const ttW = tooltipEl.offsetWidth || 220;
    let left = pxX + 14;
    if (left + ttW > rect.width - 8) left = Math.max(8, pxX - ttW - 14);
    const top = Math.max(8, Math.min(rect.height - 110, pxY - 24));
    tooltipEl.style.left = `${left.toFixed(0)}px`;
    tooltipEl.style.top = `${top.toFixed(0)}px`;
  };

  const hideTip = () => {
    hoverLine.setAttribute('visibility', 'hidden');
    hoverDot.setAttribute('visibility', 'hidden');
    tooltipEl.classList.add('hidden');
  };

  svgEl.querySelectorAll('.curve-hit').forEach(hit => {
    hit.addEventListener('mouseenter', () => showTip(Number(hit.dataset.idx)));
    hit.addEventListener('mousemove', () => showTip(Number(hit.dataset.idx)));
  });
  svgEl.addEventListener('mouseleave', hideTip);
}

function renderTrendChart(days) {
  const el = document.getElementById('trend-chart');
  const badgeEl = document.getElementById('daily-total-badge');
  const totalFiles = days.reduce((a, d) => a + (d.files_completed || 0), 0);
  const totalBytes = days.reduce((a, d) => a + (d.bytes_transferred || 0), 0);
  if (badgeEl) {
    badgeEl.textContent = `14日合计 ${fmtNum(totalFiles)} 文件 · ${fmtBytes(totalBytes)}`;
  }
  if (!days.length) {
    el.innerHTML = '<div class="empty">暂无历史汇总统计</div>';
    return;
  }
  const byDate = new Map(days.map(d => [d.date, d]));
  const series = [];
  const now = new Date();
  for (let i = 13; i >= 0; i--) {
    const dt = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - i));
    const key = dt.toISOString().slice(0, 10);
    series.push(byDate.get(key) || { date: key, files_completed: 0, bytes_transferred: 0 });
  }
  const maxBytes = Math.max(...series.map(d => d.bytes_transferred || 0), 1);
  const w = 960, h = 170, padL = 72, padR = 20, padT = 16, padB = 30;
  const plotW = w - padL - padR;
  const plotH = h - padT - padB;
  const slotW = plotW / series.length;
  const barW = Math.min(36, Math.max(14, Math.floor(slotW) - 14));

  const grid = [0, 0.5, 1].map(frac => {
    const y = padT + plotH - frac * plotH;
    return `
      <line x1="${padL}" y1="${y.toFixed(1)}" x2="${w - padR}" y2="${y.toFixed(1)}" stroke="#263040" stroke-width="1" />
      <text x="${padL - 10}" y="${(y + 4).toFixed(1)}" text-anchor="end" fill="#8b949e" font-size="10">${esc(fmtBytes(maxBytes * frac))}</text>
    `;
  }).join('');

  const bars = series.map((d, idx) => {
    const bytes = d.bytes_transferred || 0;
    const ratio = bytes / maxBytes;
    const bh = bytes > 0 ? Math.max(4, Math.round(ratio * plotH)) : 2;
    const cx = padL + idx * slotW + slotW / 2;
    const x = cx - barW / 2;
    const y = padT + plotH - bh;
    const label = d.date.slice(5);
    const fill = bytes > 0 ? '#3b82f6' : '#2d3645';
    const dayAvg = bytes / 86400;
    return `
      <g class="trend-bar">
        <title>${esc(d.date)} (UTC): 完成 ${fmtNum(d.files_completed)} 文件 · ${fmtBytes(bytes)} · 日均 ${fmtSpeed(dayAvg)}</title>
        <rect x="${x.toFixed(1)}" y="${y}" width="${barW}" height="${bh}" rx="5" fill="${fill}" />
        <text x="${cx.toFixed(1)}" y="${h - 10}" text-anchor="middle" fill="#8b949e" font-size="10">${esc(label)}</text>
      </g>
    `;
  }).join('');

  el.innerHTML = `
    <svg viewBox="0 0 ${w} ${h}" style="width:100%;height:auto;display:block">
      ${grid}
      ${bars}
    </svg>
  `;
}

function syncProjectGuideSelect(projects) {
  const sel = document.getElementById('guide-p-project-select');
  const inp = document.getElementById('guide-p-project-input');
  if (!sel || !inp) return;
  const list = (projects || []).map(ps => ps.project).filter(Boolean);
  const ids = list.map(p => p.id);
  const prev = sel.value;
  const opts = list.map(p => `<option value="${esc(p.id)}">${esc(formatProjectOption(p))}</option>`);
  opts.push('<option value="__custom__">自定义新项目 ID...</option>');
  sel.innerHTML = opts.join('');
  if (prev && (ids.includes(prev) || prev === '__custom__')) {
    sel.value = prev;
  } else if (ids.length > 0) {
    sel.value = ids[0];
    if (!inp.dataset.userEdited) {
      inp.value = ids[0];
    }
  } else {
    sel.value = '__custom__';
  }
  renderProjectGuideSnippets();
}

function syncProjectGuideCustomerOptions(accounts) {
  const sel = document.getElementById('guide-p-customer-select');
  if (!sel) return;
  const prev = sel.value;
  const list = (accounts || []).filter(a => a && a.enabled !== false);
  const opts = ['<option value="">不指定（默认仅管理员可见）</option>'];
  for (const a of list) {
    opts.push(`<option value="${esc(a.id)}">${esc(a.name || a.id)} (${esc(a.id)})</option>`);
  }
  sel.innerHTML = opts.join('');
  if (prev && list.some(a => a.id === prev)) {
    sel.value = prev;
  }
  renderProjectGuideSnippets();
}

function renderProjectGuideSnippets() {
  const inp = document.getElementById('guide-p-project-input');
  const portEl = document.getElementById('guide-p-port');
  const custEl = document.getElementById('guide-p-customer-select');
  if (!inp || !portEl) return;

  const proj = (inp.value || 'my-project').trim().replace(/[^A-Za-z0-9._-]/g, '') || 'my-project';
  const port = Math.max(1, Math.min(65535, Number(portEl.value || 18081) || 18081));
  const cust = (custEl && custEl.value || '').trim();
  const base = `http://127.0.0.1:${port}`;
  const custHdrLine = cust ? `  -H "X-Customer: ${cust}" \\\n` : '';
  const custFormLine = cust ? `  -F "customer=${cust}" \\\n` : '';
  const custJsonField = cust ? `\n    "customer": "${cust}",` : '';
  const custBatchField = cust ? `, "customer": "${cust}"` : '';

  const setText = (id, text) => {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
  };

  setText('code-p-put',
`# 单文件流式 PUT（本机回环免鉴权，新项目自动建档${cust ? `并直接分配给客户 ${cust}` : '；可选加 -H "X-Customer: <客户ID>" 自动分配客户'}）
curl -fsS -X PUT \\
${custHdrLine}  --data-binary @./sample.mp4 \\
  "${base}/local/v1/files/${proj}/videos/sample.mp4"`);

  setText('code-p-put-sha',
`# 先算 SHA256 再上传，服务端落盘前强校验
SHA=$(sha256sum ./sample.mp4 | awk '{print $1}')
curl -fsS -X PUT \\
${custHdrLine}  -H "X-Expected-SHA256: $SHA" \\
  --data-binary @./sample.mp4 \\
  "${base}/local/v1/files/${proj}/videos/sample.mp4"`);

  setText('code-p-multipart',
`# Multipart 表单上传（兼容传统上传表单）
curl -fsS -X POST \\
  -F "project=${proj}" \\
${custFormLine}  -F "filename=videos/sample.mp4" \\
  -F "file=@./sample.mp4" \\
  "${base}/local/v1/upload"`);

  setText('code-p-reg',
`# 文件已在本机磁盘时零拷贝入队（mode: move=原子移入 | hardlink=保留源文件）
curl -fsS -X POST \\
  -H "Content-Type: application/json" \\
  -d '{
    "project_id": "${proj}",${custJsonField}
    "local_path": "/data/incoming/001.opus",
    "filename": "2026/001.opus",
    "mode": "move"
  }' \\
  "${base}/local/v1/register"`);

  setText('code-p-reg-batch',
`# 批量零拷贝注册入队（单次最多 256 个文件，适合亿级海量文件）
curl -fsS -X POST \\
  -H "Content-Type: application/json" \\
  -d '{
    "items": [
      {"project_id": "${proj}"${custBatchField}, "local_path": "/data/in/v1.m4a", "filename": "v1.m4a", "mode": "move"},
      {"project_id": "${proj}"${custBatchField}, "local_path": "/data/in/v1.info.json", "filename": "v1.info.json", "mode": "move"}
    ]
  }' \\
  "${base}/local/v1/register-batch"`);

  const pyHeaders = cust
    ? `{"X-Expected-SHA256": sha, "X-Customer": "${cust}"}`
    : `{"X-Expected-SHA256": sha}`;
  setText('code-p-python',
`import time, hashlib, pathlib, requests

BASE = "${base}"
PROJECT = "${proj}"

def push_file(local_path: str, rel_name: str):
    p = pathlib.Path(local_path)
    sha = hashlib.sha256(p.read_bytes()).hexdigest()
    url = f"{BASE}/local/v1/files/{PROJECT}/{rel_name.lstrip('/')}"
    headers = ${pyHeaders}
    for attempt in range(10):
        with p.open("rb") as f:
            r = requests.put(url, headers=headers, data=f, timeout=600)
        if r.status_code == 200:
            return r.json()  # {"file_id": ..., "status": "ready"}
        if r.status_code in (503, 507):  # 待选盘激活 或 触发强制安全水位保护
            time.sleep(min(30, 2 ** attempt))
            continue
        r.raise_for_status()
    raise RuntimeError("upload retry exhausted")

print(push_file("./sample.mp4", "videos/sample.mp4"))`);

  setText('code-p-status',
`# 查询本机分发节点当前排队数与磁盘水位（summary=1 轻量模式）
curl -fsS "${base}/local/v1/status?project=${proj}&summary=1"`);
}

function openProjectQuickGuide(projectId) {
  const sel = document.getElementById('guide-p-project-select');
  const inp = document.getElementById('guide-p-project-input');
  if (projectId && inp) {
    inp.value = projectId;
    inp.dataset.userEdited = '1';
    if (sel) {
      sel.value = Array.from(sel.options).some(o => o.value === projectId) ? projectId : '__custom__';
    }
  }
  syncProjectGuideSelect(cachedProjects);
  syncProjectGuideCustomerOptions(cachedAccounts);
  renderProjectGuideSnippets();
  openModal('project-guide-modal');
}

function fmtRelativeTime(iso) {
  if (!iso) return '无记录';
  const ts = new Date(iso).getTime();
  if (Number.isNaN(ts)) return '无记录';
  const diffSec = Math.max(0, Math.floor((Date.now() - ts) / 1000));
  if (diffSec < 90) return '刚刚';
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)} 分钟前`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)} 小时前`;
  const days = Math.floor(diffSec / 86400);
  if (days < 30) return `${days} 天前`;
  return fmtTimeShort(iso, true);
}

function getProjectActivityTier(ps) {
  if (!ps) return 1;
  if ((ps.queued_files || 0) > 0 || (ps.recent_bytes || 0) > 0) return 3; // live
  if ((ps.window_bytes || 0) > 0 || (ps.window_completed || 0) > 0 || (ps.window_failed || 0) > 0) return 2; // recent
  return 1; // idle
}

function getProjectActivityEpoch(ps) {
  if (ps?.last_activity_at) {
    const t = new Date(ps.last_activity_at).getTime();
    if (!Number.isNaN(t)) return t;
  }
  if (ps?.project?.created_at) {
    const t = new Date(ps.project.created_at).getTime();
    if (!Number.isNaN(t)) return t;
  }
  return 0;
}

function getProjectAssignedAccounts(projectId) {
  if (isCustomer()) return [];
  return (cachedAccounts || []).filter(a => Array.isArray(a.projects) && a.projects.includes(projectId));
}

function projectNeedsAttention(ps, cust) {
  const hasFail = (ps.window_failed || 0) > 0 || (ps.total_failed || 0) > 0;
  const hasDiskAlarm = !cust && (ps.a_node_availability || []).some(a => a.disk_alarm);
  const unassigned = !cust && getProjectAssignedAccounts(ps.project.id).length === 0;
  return hasFail || hasDiskAlarm || unassigned;
}

function sortProjectSummaries(list, sortBy) {
  const arr = [...list];
  arr.sort((a, b) => {
    switch (sortBy) {
      case 'queued':
        if ((b.queued_bytes || 0) !== (a.queued_bytes || 0)) return (b.queued_bytes || 0) - (a.queued_bytes || 0);
        if ((b.queued_files || 0) !== (a.queued_files || 0)) return (b.queued_files || 0) - (a.queued_files || 0);
        break;
      case 'bytes':
        if ((b.total_bytes || 0) !== (a.total_bytes || 0)) return (b.total_bytes || 0) - (a.total_bytes || 0);
        if ((b.total_completed || 0) !== (a.total_completed || 0)) return (b.total_completed || 0) - (a.total_completed || 0);
        break;
      case 'recent': {
        const diff = getProjectActivityEpoch(b) - getProjectActivityEpoch(a);
        if (diff !== 0) return diff;
        break;
      }
      case 'created': {
        const ta = new Date(a.project.created_at || 0).getTime() || 0;
        const tb = new Date(b.project.created_at || 0).getTime() || 0;
        if (tb !== ta) return tb - ta;
        break;
      }
      case 'name': {
        const na = (a.project.name || a.project.id || '').toLowerCase();
        const nb = (b.project.name || b.project.id || '').toLowerCase();
        if (na !== nb) return na.localeCompare(nb, 'zh-CN');
        break;
      }
      case 'activity':
      default: {
        const ta = getProjectActivityTier(a);
        const tb = getProjectActivityTier(b);
        if (tb !== ta) return tb - ta;
        if (ta === 3) {
          if ((b.recent_speed_bps || 0) !== (a.recent_speed_bps || 0)) return (b.recent_speed_bps || 0) - (a.recent_speed_bps || 0);
          if ((b.queued_bytes || 0) !== (a.queued_bytes || 0)) return (b.queued_bytes || 0) - (a.queued_bytes || 0);
          if ((b.queued_files || 0) !== (a.queued_files || 0)) return (b.queued_files || 0) - (a.queued_files || 0);
        }
        const diff = getProjectActivityEpoch(b) - getProjectActivityEpoch(a);
        if (diff !== 0) return diff;
        if ((b.window_bytes || 0) !== (a.window_bytes || 0)) return (b.window_bytes || 0) - (a.window_bytes || 0);
        if ((b.total_bytes || 0) !== (a.total_bytes || 0)) return (b.total_bytes || 0) - (a.total_bytes || 0);
        break;
      }
    }
    return (a.project.id || '').localeCompare(b.project.id || '');
  });
  return arr;
}

function renderProjectCompactRow(ps, winHours, cust) {
  const p = ps.project;
  const tier = getProjectActivityTier(ps);
  const assignedAccs = getProjectAssignedAccounts(p.id);
  const hasDiskAlarm = !cust && (ps.a_node_availability || []).some(a => a.disk_alarm);
  const hasFail = (ps.window_failed || 0) > 0 || (ps.total_failed || 0) > 0;

  const dotCls = tier === 3 ? 'live' : (tier === 2 ? 'recent' : 'idle');
  const dotTitle = tier === 3 ? '传输中 / 实时活跃' : (tier === 2 ? `${windowLabel(winHours)}内有传输` : '静止 / 历史项目');

  const miniPills = [];
  if (p.max_total_concurrent > 0 || p.max_total_rate_mbps > 0) {
    const qp = [];
    if (p.max_total_concurrent > 0) qp.push(`并发≤${p.max_total_concurrent}`);
    if (p.max_total_rate_mbps > 0) qp.push(`${p.max_total_rate_mbps}MB/s`);
    miniPills.push(`<span class="badge accent proj-mini-pill">${esc(qp.join(' · '))}</span>`);
  }
  if (hasDiskAlarm) {
    miniPills.push('<span class="badge alarm proj-mini-pill">盘水位告警</span>');
  }
  if (hasFail) {
    miniPills.push(`<span class="badge offline proj-mini-pill">失败 ${fmtNum(ps.total_failed || ps.window_failed)}</span>`);
  }

  // Customer column (admin only)
  let custCellHtml = '';
  if (!cust) {
    if (!assignedAccs.length) {
      custCellHtml = '<td><span class="badge alarm">未分配</span></td>';
    } else {
      const shown = assignedAccs.slice(0, 2).map(a => `<span class="badge online" title="${esc(a.id)}">${esc(a.name || a.id)}</span>`).join('');
      const extra = assignedAccs.length > 2 ? `<span class="badge" title="${esc(assignedAccs.slice(2).map(a => a.name || a.id).join(', '))}">+${assignedAccs.length - 2}</span>` : '';
      custCellHtml = `<td><div class="proj-cust-pills">${shown}${extra}</div></td>`;
    }
  }

  // Queue / live status column
  let queueHtml = '';
  if ((ps.queued_files || 0) > 0) {
    queueHtml = `
      <div class="proj-cell-main" style="color:var(--cyan)">积压 ${esc(fmtNum(ps.queued_files))} 文件</div>
      <div class="proj-cell-sub">${esc(fmtBytes(ps.queued_bytes))} · 接收机 ${ps.online_b_nodes}</div>
    `;
  } else if (tier === 3) {
    queueHtml = `
      <div class="proj-cell-main" style="color:var(--green-soft)">实时传输中</div>
      <div class="proj-cell-sub">近 10 分 ${esc(fmtBytes(ps.recent_bytes))}</div>
    `;
  } else {
    const lastTxt = ps.last_activity_at ? fmtRelativeTime(ps.last_activity_at) : `创建于 ${fmtTimeShort(p.created_at, true)}`;
    queueHtml = `
      <div class="proj-cell-main muted">空闲</div>
      <div class="proj-cell-sub">${esc(lastTxt)}</div>
    `;
  }

  // Speed column
  let speedHtml = '';
  if ((ps.recent_speed_bps || 0) > 0) {
    speedHtml = `
      <div class="proj-cell-main" style="color:var(--green-soft)">${esc(fmtSpeed(ps.recent_speed_bps))}</div>
      <div class="proj-cell-sub">实时 · 窗均 ${esc(fmtSpeed(ps.active_avg_speed_bps))}</div>
    `;
  } else if ((ps.active_avg_speed_bps || 0) > 0) {
    speedHtml = `
      <div class="proj-cell-main">${esc(fmtSpeed(ps.active_avg_speed_bps))}</div>
      <div class="proj-cell-sub">${esc(windowLabel(winHours))}活跃均速</div>
    `;
  } else {
    speedHtml = '<div class="proj-cell-main muted">—</div>';
  }

  // Delivered volume column
  const winSub = (ps.window_completed || 0) > 0
    ? `${windowLabel(winHours)} +${fmtNum(ps.window_completed)} (${fmtBytes(ps.window_bytes)})`
    : (ps.total_completed > 0 ? '历史已完成' : '暂无传输记录');
  const totalHtml = `
    <div class="proj-cell-main">${esc(fmtNum(ps.total_completed))} 文件 · ${esc(fmtBytes(ps.total_bytes))}</div>
    <div class="proj-cell-sub">${esc(winSub)}</div>
  `;

  // Compact actions column (keep dangerous Delete inside Detail modal!)
  let actionsHtml = `<button type="button" class="btn sm" data-action="view-project-detail" data-id="${esc(p.id)}">详情</button>`;
  if (!cust) {
    const assignCls = assignedAccs.length === 0 ? 'btn sm primary' : 'btn sm ghost';
    const assignTxt = assignedAccs.length === 0 ? '分配客户' : '客户';
    actionsHtml = `
      <button type="button" class="${assignCls}" data-action="assign-project-accounts" data-id="${esc(p.id)}">${assignTxt}</button>
      <button type="button" class="btn sm" data-action="view-project-detail" data-id="${esc(p.id)}">详情</button>
    `;
  }

  return `
    <tr class="proj-row ${tier === 3 ? 'is-live' : ''}" data-open-project-detail="${esc(p.id)}">
      <td>
        <div class="proj-name-line">
          <span class="proj-status-dot ${dotCls}" title="${esc(dotTitle)}"></span>
          <strong class="proj-name-text" title="${esc(p.name || p.id)}">${esc(p.name || p.id)}</strong>
          ${miniPills.join('')}
        </div>
        <div class="proj-id-line">
          <button type="button" class="proj-short-id mono" data-copy-text="${esc(p.id)}" title="点击复制完整项目 ID: ${esc(p.id)}">${esc(shortId(p.id))}</button>
          ${p.description && p.description !== '上传自动发现创建' ? `<span class="proj-desc-inline" title="${esc(p.description)}">${esc(p.description)}</span>` : ''}
        </div>
      </td>
      ${custCellHtml}
      <td>${queueHtml}</td>
      <td>${speedHtml}</td>
      <td>${totalHtml}</td>
      <td>
        <div class="proj-row-actions">${actionsHtml}</div>
      </td>
    </tr>
  `;
}

function buildProjectGroups(items, groupBy, cust) {
  if (groupBy === 'none') {
    return [{
      key: 'all',
      title: '全部项目',
      badgeCls: 'accent',
      items,
      collapsible: false,
    }];
  }
  if (groupBy === 'customer' && !cust) {
    const map = new Map();
    const unassigned = [];
    for (const ps of items) {
      const accs = getProjectAssignedAccounts(ps.project.id);
      if (!accs.length) {
        unassigned.push(ps);
        continue;
      }
      for (const a of accs) {
        const k = `cust:${a.id}`;
        if (!map.has(k)) {
          map.set(k, {
            key: k,
            title: a.name ? `${a.name} (${a.id})` : a.id,
            badgeCls: a.enabled === false ? 'offline' : 'online',
            items: [],
            collapsible: true,
          });
        }
        map.get(k).items.push(ps);
      }
    }
    const groups = Array.from(map.values()).sort((a, b) => {
      const aLive = a.items.filter(x => getProjectActivityTier(x) === 3).length;
      const bLive = b.items.filter(x => getProjectActivityTier(x) === 3).length;
      if (bLive !== aLive) return bLive - aLive;
      return b.items.length - a.items.length;
    });
    if (unassigned.length) {
      groups.push({
        key: 'cust:__unassigned__',
        title: '未分配客户（仅管理员可见）',
        badgeCls: 'alarm',
        items: unassigned,
        collapsible: true,
      });
    }
    return groups;
  }

  // Default: group by live activity status
  const live = [];
  const recent = [];
  const idle = [];
  for (const ps of items) {
    const t = getProjectActivityTier(ps);
    if (t === 3) live.push(ps);
    else if (t === 2) recent.push(ps);
    else idle.push(ps);
  }
  const groups = [];
  if (live.length) {
    groups.push({ key: 'status:live', title: '传输中 · 实时活跃', badgeCls: 'online', items: live, collapsible: true });
  }
  if (recent.length) {
    groups.push({ key: 'status:recent', title: '近期活跃', badgeCls: 'accent', items: recent, collapsible: true });
  }
  if (idle.length) {
    // Auto-collapse idle group only when there are active projects AND many idle projects, unless user manually toggled it.
    if (!projectViewState.userToggledGroups.has('status:idle')) {
      if ((live.length + recent.length) > 0 && idle.length > 8) {
        projectViewState.collapsedGroups.add('status:idle');
      } else {
        projectViewState.collapsedGroups.delete('status:idle');
      }
    }
    groups.push({ key: 'status:idle', title: '静止 · 历史项目', badgeCls: '', items: idle, collapsible: true });
  }
  return groups;
}

function renderProjects(projects, winHours) {
  syncProjectGuideSelect(projects);
  const el = document.getElementById('projects-grid');
  if (!el) return;
  const cust = isCustomer();
  const all = projects || [];

  // Update status filter chip counters dynamically
  const counts = {
    all: all.length,
    live: all.filter(ps => getProjectActivityTier(ps) === 3).length,
    recent: all.filter(ps => getProjectActivityTier(ps) === 2).length,
    attention: all.filter(ps => projectNeedsAttention(ps, cust)).length,
    idle: all.filter(ps => getProjectActivityTier(ps) === 1).length,
  };
  const chipLabels = {
    all: `全部 (${counts.all})`,
    live: `传输中 (${counts.live})`,
    recent: `近期活跃 (${counts.recent})`,
    attention: cust ? `异常 (${counts.attention})` : `待分配 / 异常 (${counts.attention})`,
    idle: `静止 (${counts.idle})`,
  };
  document.querySelectorAll('#projects-status-chips .disk-chip').forEach(chip => {
    const key = chip.dataset.projFilter;
    if (chipLabels[key]) chip.textContent = chipLabels[key];
    chip.classList.toggle('active', key === projectViewState.filter);
  });

  if (!all.length) {
    const sumEl = document.getElementById('projects-summary-counter');
    if (sumEl) sumEl.textContent = '';
    el.innerHTML = cust
      ? '<div class="empty">当前账号暂未分配可见项目（默认全不可见），请联系管理员在控制台为您分配项目后即可查看数据并接入接收节点。</div>'
      : '<div class="empty">还没有项目，点击右上角「+ 新建项目」或通过 HTTP PUT 推送自动发现创建。</div>';
    return;
  }

  // Apply status filter + search
  const q = (projectViewState.search || '').trim().toLowerCase();
  const filtered = all.filter(ps => {
    const p = ps.project;
    if (projectViewState.filter === 'live' && getProjectActivityTier(ps) !== 3) return false;
    if (projectViewState.filter === 'recent' && getProjectActivityTier(ps) !== 2) return false;
    if (projectViewState.filter === 'idle' && getProjectActivityTier(ps) !== 1) return false;
    if (projectViewState.filter === 'attention' && !projectNeedsAttention(ps, cust)) return false;
    if (!q) return true;
    const accNames = getProjectAssignedAccounts(p.id).map(a => `${a.id} ${a.name || ''}`).join(' ');
    const hay = `${p.id} ${p.name || ''} ${p.description || ''} ${accNames}`.toLowerCase();
    return hay.includes(q);
  });

  const sorted = sortProjectSummaries(filtered, projectViewState.sortBy);
  const sumEl = document.getElementById('projects-summary-counter');
  if (sumEl) {
    sumEl.textContent = filtered.length === all.length
      ? `共 ${all.length} 个项目 · 传输中 ${counts.live}`
      : `筛选命中 ${filtered.length} / 共 ${all.length} 个项目`;
  }

  if (!sorted.length) {
    el.innerHTML = '<div class="empty">没有匹配当前搜索或筛选条件的项目。</div>';
    return;
  }

  const effectiveGroupBy = (cust && projectViewState.groupBy === 'customer') ? 'status' : projectViewState.groupBy;
  const groups = buildProjectGroups(sorted, effectiveGroupBy, cust);
  const theadHtml = `
    <thead>
      <tr>
        <th style="min-width:240px">项目 / 状态</th>
        ${cust ? '' : '<th style="min-width:130px">可见客户</th>'}
        <th style="min-width:140px">当前状态 / 积压</th>
        <th style="min-width:135px">吞吐速率</th>
        <th style="min-width:180px">累计交付</th>
        <th style="width:126px;text-align:right">操作</th>
      </tr>
    </thead>
  `;

  el.innerHTML = groups.map(grp => {
    const collapsed = grp.collapsible && projectViewState.collapsedGroups.has(grp.key);
    const grpQueuedFiles = grp.items.reduce((s, x) => s + (x.queued_files || 0), 0);
    const grpQueuedBytes = grp.items.reduce((s, x) => s + (x.queued_bytes || 0), 0);
    const grpTotalBytes = grp.items.reduce((s, x) => s + (x.total_bytes || 0), 0);
    const grpMetaParts = [];
    if (grpQueuedFiles > 0) grpMetaParts.push(`待传 ${fmtNum(grpQueuedFiles)} (${fmtBytes(grpQueuedBytes)})`);
    grpMetaParts.push(`累计 ${fmtBytes(grpTotalBytes)}`);
    const rowsHtml = grp.items.map(ps => renderProjectCompactRow(ps, winHours, cust)).join('');

    const headHtml = grp.collapsible ? `
      <div class="proj-group-head" data-toggle-proj-group="${esc(grp.key)}">
        <div class="proj-group-head-left">
          <span class="proj-group-caret">${collapsed ? '▸' : '▾'}</span>
          <span class="badge ${grp.badgeCls}">${esc(grp.title)}</span>
          <span class="proj-group-count">${grp.items.length} 个项目</span>
        </div>
        <div class="proj-group-meta muted">${esc(grpMetaParts.join(' · '))}</div>
      </div>
    ` : '';

    return `
      <div class="card proj-group-card">
        ${headHtml}
        <div class="table-wrap proj-group-body ${collapsed ? 'hidden' : ''}">
          <table class="data-table proj-table">
            ${theadHtml}
            <tbody>${rowsHtml}</tbody>
          </table>
        </div>
      </div>
    `;
  }).join('');
}

function openProjectDetailModal(projectId) {
  activeProjectDetailId = projectId;
  renderProjectDetailModal(projectId, lastProjectsWinHours);
  openModal('project-detail-modal');
}

function jumpToProjectCurve(projectId) {
  closeModal('project-detail-modal');
  selectedProjectFilter = projectId || '';
  const sel = document.getElementById('curve-project-filter');
  if (sel) sel.value = selectedProjectFilter;
  document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelector('.tab[data-tab="dashboard"]')?.classList.add('active');
  document.getElementById('tab-dashboard')?.classList.add('active');
  refreshCurveOnly();
  document.getElementById('speed-curve-wrap')?.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

function renderProjectDetailModal(projectId, winHours) {
  const ps = (cachedProjects || []).find(x => x.project.id === projectId);
  const titleEl = document.getElementById('proj-detail-title');
  const badgesEl = document.getElementById('proj-detail-badges');
  const subEl = document.getElementById('proj-detail-sub');
  const bodyEl = document.getElementById('proj-detail-body');
  if (!bodyEl) return;
  if (!ps) {
    titleEl.textContent = '项目不存在或已删除';
    badgesEl.innerHTML = '';
    subEl.textContent = '';
    bodyEl.innerHTML = '<div class="empty">该项目已不在当前列表中。</div>';
    return;
  }

  const p = ps.project;
  const cust = isCustomer();
  const winLbl = windowLabel(winHours);
  const tier = getProjectActivityTier(ps);
  const statusBadge = tier === 3
    ? '<span class="badge online pulse">传输中</span>'
    : (tier === 2 ? '<span class="badge accent">近期活跃</span>' : '<span class="badge">静止</span>');
  const autoBadge = p.description === '上传自动发现创建' ? '<span class="badge">自动发现</span>' : '';
  const affBadge = p.group_affinity === false
    ? '<span class="badge">自由抢占</span>'
    : '<span class="badge accent">同源亲和</span>';
  const quotaParts = [];
  if (p.max_total_concurrent > 0) quotaParts.push(`总并发 ≤ ${p.max_total_concurrent}`);
  if (p.max_total_rate_mbps > 0) quotaParts.push(`总限速 ${p.max_total_rate_mbps} MB/s`);
  const quotaBadge = quotaParts.length ? `<span class="badge alarm">${esc(quotaParts.join(' · '))}</span>` : '';

  titleEl.textContent = p.name || p.id;
  badgesEl.innerHTML = `${statusBadge}${autoBadge}${affBadge}${quotaBadge}`;
  const lastActTxt = ps.last_activity_at ? `${fmtTimeShort(ps.last_activity_at, true)} (${fmtRelativeTime(ps.last_activity_at)})` : '暂无活动记录';
  subEl.innerHTML = `
    内部 ID: <span class="mono">${esc(p.id)}</span>
    <button type="button" class="btn sm ghost" style="padding:1px 7px;font-size:11px;margin-left:4px" data-copy-text="${esc(p.id)}">复制 ID</button>
    · 创建于 ${esc(fmtTimeShort(p.created_at, true) || '-')} · 最近活跃 ${esc(lastActTxt)}
  `;

  const assignedAccs = getProjectAssignedAccounts(p.id);
  const conflictMap = { overwrite: '项目内覆盖 (overwrite)', auto_rename: '自动重命名 (auto_rename)', skip: '跳过已有 (skip)' };
  const conflictLbl = conflictMap[p.conflict_policy] || p.conflict_policy;

  const availHtml = (ps.a_node_availability || []).length
    ? (ps.a_node_availability || []).map(a => `
        <div class="proj-avail-row">
          <div>
            <strong>${esc(a.a_name || a.a_node_id)}</strong>
            <span class="muted mono" style="margin-left:6px">${esc(a.a_node_id)}</span>
            ${a.disk_alarm ? '<span class="badge alarm" style="margin-left:6px">磁盘水位告警</span>' : ''}
          </div>
          <div style="display:flex;gap:8px;align-items:center">
            <span class="badge online">待拉 ${esc(fmtNum(a.ready_count))}</span>
            ${a.claimed_count > 0 ? `<span class="badge accent">传输中 ${esc(fmtNum(a.claimed_count))}</span>` : ''}
            <span class="mono muted">${esc(fmtBytes(a.ready_bytes))}</span>
          </div>
        </div>
      `).join('')
    : '<div class="muted" style="padding:6px 0">当前所有分发节点均无待传输积压</div>';

  const quickBarHtml = `
    <div class="proj-detail-actions">
      <button type="button" class="btn sm primary" data-action="jump-project-curve" data-id="${esc(p.id)}">查看速度曲线</button>
      ${cust ? '' : `
        <button type="button" class="btn sm" data-action="assign-project-accounts" data-id="${esc(p.id)}">分配客户</button>
        <button type="button" class="btn sm" data-action="quick-integrate-project" data-id="${esc(p.id)}">HTTP 接入代码</button>
        <button type="button" class="btn sm" data-action="edit-project" data-id="${esc(p.id)}">编辑策略</button>
      `}
    </div>
  `;

  const ownerSectionHtml = cust ? '' : `
    <div class="config-section">
      <div class="config-section-title">可见客户账号</div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center">
        ${assignedAccs.length
          ? assignedAccs.map(a => `<span class="badge online">${esc(a.name || a.id)} <span class="mono" style="opacity:0.75">(${esc(a.id)})</span></span>`).join('')
          : '<span class="badge alarm">未分配客户（当前仅管理员可见）</span>'}
      </div>
    </div>
  `;

  const availSectionHtml = cust ? '' : `
    <div class="config-section">
      <div class="config-section-title">各分发节点实时积压明细（共 ${esc(fmtNum(ps.queued_files))} 文件 · ${esc(fmtBytes(ps.queued_bytes))}）</div>
      <div class="proj-avail-list">${availHtml}</div>
    </div>
  `;

  const dangerFooterHtml = cust ? '' : `
    <div class="modal-footer-reinstall" style="margin-top:14px">
      <span>高危操作：删除项目仅移除中心记录与统计，不会删除接收节点已落盘文件。</span>
      <button type="button" class="btn sm danger" data-action="delete-project" data-id="${esc(p.id)}">删除此项目</button>
    </div>
  `;

  bodyEl.innerHTML = `
    ${quickBarHtml}
    <div class="proj-stats-grid" style="margin-bottom:14px">
      <div class="proj-stat-box">
        <div class="k">实时 / 近 10 分钟速率</div>
        <div class="v">${ps.recent_speed_bps > 0 ? `${esc(fmtSpeed(ps.recent_speed_bps))} <span class="muted">(${esc(fmtMbps(ps.recent_speed_bps))})</span>` : '<span class="muted">当前空闲</span>'}</div>
        <div class="muted">近 10 分流量 ${esc(fmtBytes(ps.recent_bytes || 0))}</div>
      </div>
      <div class="proj-stat-box">
        <div class="k">${esc(winLbl)}平均速率</div>
        <div class="v">${esc(fmtSpeed(ps.window_avg_speed_bps))} <span class="muted">(${esc(fmtMbps(ps.window_avg_speed_bps))})</span></div>
        <div class="muted">活跃均速 ${esc(fmtSpeed(ps.active_avg_speed_bps))}</div>
      </div>
      <div class="proj-stat-box">
        <div class="k">${esc(winLbl)}完成汇总</div>
        <div class="v">${esc(fmtNum(ps.window_completed))} 文件 · ${esc(fmtBytes(ps.window_bytes))}</div>
        <div class="muted">窗口失败 ${esc(fmtNum(ps.window_failed))}</div>
      </div>
      <div class="proj-stat-box">
        <div class="k">累计完成总量</div>
        <div class="v">${esc(fmtNum(ps.total_completed))} 文件 · ${esc(fmtBytes(ps.total_bytes))}</div>
        <div class="muted">累计上传 ${esc(fmtNum(ps.total_uploaded))} · 累计失败 ${esc(fmtNum(ps.total_failed))}</div>
      </div>
    </div>

    <div class="config-section" style="margin-bottom:12px">
      <div class="config-section-title">隔离策略与运行环境</div>
      <div class="proj-meta-grid">
        <div><span class="muted">备注说明：</span>${esc(p.description || '无备注')}</div>
        <div><span class="muted">同名冲突策略：</span>${esc(conflictLbl)}</div>
        <div><span class="muted">抢占租约超时：</span>${p.lease_ttl_sec} 秒</div>
        <div><span class="muted">多机资产亲和：</span>${p.group_affinity === false ? '已关闭（自由抢占）' : '已开启（同素材组落同机）'}</div>
        <div><span class="muted">全局并发 / 限速：</span>${p.max_total_concurrent > 0 ? `≤ ${p.max_total_concurrent}` : '不限并发'} · ${p.max_total_rate_mbps > 0 ? `${p.max_total_rate_mbps} MB/s` : '不限速'}</div>
        <div><span class="muted">在线节点覆盖：</span>${cust ? `接收节点 ${ps.online_b_nodes}` : `分发节点 ${ps.online_a_nodes} · 接收节点 ${ps.online_b_nodes}`}</div>
      </div>
    </div>

    ${ownerSectionHtml}
    ${availSectionHtml}
    ${dangerFooterHtml}
  `;
}

function renderUpgradeBadge(n) {
  if (!n.upgrade_status) return '';
  const map = {
    pending: { cls: 'alarm', txt: `待升 → ${n.target_version}` },
    downloading: { cls: 'alarm', txt: `下载中 → ${n.target_version}` },
    restarting: { cls: 'alarm', txt: `重启中 → ${n.target_version}` },
    completed: { cls: 'online', txt: `已升级 ${n.target_version}` },
    failed: { cls: 'offline', txt: '升级失败' },
  };
  const info = map[n.upgrade_status] || { cls: '', txt: n.upgrade_status };
  const title = n.upgrade_message ? ` title="${esc(n.upgrade_message)}"` : '';
  return `<span class="badge ${info.cls}"${title}>${esc(info.txt)}</span>`;
}

function scheduleLabel(sched) {
  switch (sched) {
    case 'fair': return '公平轮询';
    case 'random': return '随机抢占';
    case 'fifo':
    default: return '按顺序逐个';
  }
}

function diskPolicyLabel(pol, activeWin = 10) {
  switch (pol) {
    case 'rolling_window': return `分批滚动 (${activeWin || 10}盘)`;
    case 'most_free': return '最大余量优先';
    case 'first': return '单盘顺序写满';
    case 'round_robin':
    case 'affinity_hash':
    default: return '多盘均衡';
  }
}

function normalizeUiDiskPolicy(pol) {
  switch (pol) {
    case 'rolling_window':
    case 'most_free':
    case 'first':
    case 'round_robin':
      return pol;
    case 'affinity_hash':
    default:
      return 'round_robin';
  }
}

function nodeDiskAffinityEnabled(node) {
  if (!node || node.disk_affinity === undefined || node.disk_affinity === null) return true;
  return !!node.disk_affinity;
}

function renderAdaptiveBadge(n) {
  const mode = n.concurrency_mode || 'auto';
  const stateMap = {
    probing: { cls: 'accent', lbl: '探优中' },
    cruising: { cls: 'online', lbl: '稳态巡航' },
    backoff: { cls: 'alarm', lbl: '拥塞退避' },
    manual: { cls: '', lbl: '手动固定' },
  };
  const info = stateMap[n.adaptive_state] || (mode === 'manual' ? stateMap.manual : stateMap.cruising);
  const concTxt = n.effective_concurrent > 0
    ? `${n.effective_concurrent}/${n.max_concurrent_cap || n.effective_concurrent}`
    : (n.max_concurrent_override > 0 ? `≤${n.max_concurrent_override}` : '自动');
  const title = n.adaptive_reason ? ` title="${esc(n.adaptive_reason)}"` : '';
  const rateVal = n.effective_rate_mbps > 0 ? n.effective_rate_mbps : (n.rate_limit_mbps || 0);
  const rateBadge = rateVal > 0 ? `<span class="badge alarm">限速 ${Number(rateVal).toFixed(0)} MB/s</span>` : '';
  return `
    <div style="margin-top:5px;display:flex;gap:4px;flex-wrap:wrap;align-items:center">
      <span class="badge ${info.cls}"${title}>${mode === 'manual' ? '手动并发' : '智能并发'} ${esc(concTxt)} · ${esc(info.lbl)}</span>
      ${rateBadge}
    </div>
  `;
}

function renderProjectScope(projects, schedule, node) {
  const adaptHtml = node ? renderAdaptiveBadge(node) : '';
  const ownerBadge = (!isCustomer() && node && node.owner_account_id)
    ? `<span class="badge accent" title="归属客户ID: ${esc(node.owner_account_id)}">客户: ${esc(getAccountName(node.owner_account_id))}</span>`
    : '';
  if (!projects || !projects.length) {
    return `
      <div style="display:flex;gap:4px;flex-wrap:wrap">
        <span class="badge online">全部项目</span>
        <span class="badge">${esc(scheduleLabel(schedule))}</span>
        ${ownerBadge}
      </div>
      <div class="muted" style="margin-top:3px">自动同步新建项目</div>
      ${adaptHtml}
    `;
  }
  if (projects.length === 1) {
    const meta = getProjectMeta(projects[0]);
    return `
      <div style="display:flex;gap:4px;flex-wrap:wrap">
        <span class="badge online">单项目专享</span>
        ${ownerBadge}
      </div>
      <div style="margin-top:3px" title="ID: ${esc(meta.id)}${meta.desc ? ' · ' + esc(meta.desc) : ''}">
        <strong>${esc(meta.name)}</strong>
        ${meta.hasDistinctName ? `<span class="mono muted" style="font-size:11px;margin-left:4px">${esc(meta.shortId)}</span>` : ''}
      </div>
      ${adaptHtml}
    `;
  }
  const namesHtml = projects.map(pid => {
    const meta = getProjectMeta(pid);
    return `<span class="badge" title="ID: ${esc(meta.id)}${meta.desc ? ' · ' + esc(meta.desc) : ''}">${esc(meta.name)}</span>`;
  }).join('');
  return `
    <div style="display:flex;gap:4px;flex-wrap:wrap">
      <span class="badge">多项目 (${projects.length})</span>
      <span class="badge">${esc(scheduleLabel(schedule))}</span>
      ${ownerBadge}
    </div>
    <div style="margin-top:4px;display:flex;gap:4px;flex-wrap:wrap">${namesHtml}</div>
    ${adaptHtml}
  `;
}

function findNewHostDisks(n) {
  if (!n || n.awaiting_disk) return [];
  const hostDisks = n.host_disks || [];
  if (!hostDisks.length) return [];
  const configured = new Set([...(n.storage_dirs || []), ...((n.disks || []).map(d => d.path))]);
  if (!configured.size) return [];
  return hostDisks.filter(hd => {
    if (hd.is_system) return false;
    if (configured.has(hd.suggested_dir)) return false;
    const mntPrefix = hd.mount_point.endsWith('/') ? hd.mount_point : hd.mount_point + '/';
    for (const p of configured) {
      if (p === hd.mount_point || p.startsWith(mntPrefix)) return false;
    }
    return true;
  });
}

function analyzeNodeDiskAlerts(n) {
  const disks = n.disks || [];
  const lockedSet = new Set(n.unplug_locked_disks || []);
  let detached = 0;
  let reinsert = 0;
  let safeEject = 0;
  for (const d of disks) {
    if (d.detached) {
      detached++;
    } else if (d.unplug_latched || lockedSet.has(d.path)) {
      reinsert++;
    } else if (d.safe_to_eject) {
      safeEject++;
    }
  }
  const newDisks = findNewHostDisks(n);
  return { detached, reinsert, safeEject, newCount: newDisks.length };
}

function renderNodeDiskAlertBadges(n) {
  const st = analyzeNodeDiskAlerts(n);
  const parts = [];
  if (st.detached > 0) parts.push(`<span class="badge detached">⚠ ${st.detached} 块盘已拔出</span>`);
  if (st.reinsert > 0) parts.push(`<span class="badge reinsert">🔌 ${st.reinsert} 块盘重插待确认</span>`);
  if (st.safeEject > 0) parts.push(`<span class="badge safe-eject">✓ ${st.safeEject} 块盘可安全拔出</span>`);
  if (st.newCount > 0) parts.push(`<span class="badge new-disk">+ 发现 ${st.newCount} 块新盘</span>`);
  return parts.join('');
}

function renderDiskMiniItem(d, disabledSet, lockedSet, watermarkPct) {
  const isLocked = !!(d.unplug_latched || lockedSet.has(d.path));
  const enabled = d.enabled !== false && !disabledSet.has(d.path) && !isLocked && !d.detached;
  const pct = Number(d.used_pct || 0);
  let itemCls = '';
  let barCls = '';
  let stTag = '';
  let detailHtml = '';

  if (d.detached) {
    itemCls = ' detached';
    stTag = '<span class="badge detached">⚠ 已拔出/未挂载</span>';
    detailHtml = `<div class="muted">${esc(d.status_reason || '已自动锁定 · 防止写进系统盘')}</div>`;
  } else if (isLocked) {
    itemCls = ' reinsert';
    stTag = '<span class="badge reinsert">🔌 重插待确认</span>';
    detailHtml = `
      <div class="bar-wrap"><div class="bar-fill" style="width:${Math.min(100, pct).toFixed(1)}%"></div></div>
      <div class="muted">${esc(d.status_reason || '已重新挂载，请在配置中人工确认启用')} · 剩 ${fmtBytes(d.free_bytes)}</div>
    `;
  } else if (!enabled) {
    itemCls = d.safe_to_eject ? ' safe-eject' : ' disabled';
    if (d.safe_to_eject) {
      stTag = '<span class="badge safe-eject">✓ 可安全拔盘</span>';
    } else if ((d.in_flight || 0) > 0) {
      stTag = `<span class="badge alarm">排空中 (${d.in_flight})</span>`;
    } else {
      stTag = '<span class="badge offline">已停用</span>';
    }
    detailHtml = `
      <div class="bar-wrap"><div class="bar-fill" style="width:${Math.min(100, pct).toFixed(1)}%"></div></div>
      <div class="muted">${esc(d.status_reason || '已停用')} · 剩 ${fmtBytes(d.free_bytes)} / ${fmtBytes(d.total_bytes)}</div>
    `;
  } else if (d.disk_role === 'full' || d.low_space) {
    barCls = 'red';
    stTag = '<span class="badge full-disk">已写满 · 可停用拔盘</span>';
    detailHtml = `
      <div class="bar-wrap"><div class="bar-fill red" style="width:${Math.min(100, pct).toFixed(1)}%"></div></div>
      <div class="muted">${esc(d.status_reason || '触达强制安全水位')} · 剩 ${fmtBytes(d.free_bytes)} (${pct.toFixed(1)}%)</div>
    `;
  } else if (d.disk_role === 'standby') {
    barCls = '';
    stTag = '<span class="badge standby">候补排队</span>';
    detailHtml = `
      <div class="bar-wrap"><div class="bar-fill" style="width:${Math.min(100, pct).toFixed(1)}%"></div></div>
      <div class="muted">剩 ${fmtBytes(d.free_bytes)} / ${fmtBytes(d.total_bytes)} (${pct.toFixed(1)}%) · 前序盘满自动顶上</div>
    `;
  } else {
    barCls = pct >= watermarkPct ? 'red' : 'green';
    const actLbl = d.status_reason && d.status_reason.startsWith('写入窗口') ? d.status_reason : '启用';
    stTag = `<span class="badge online">${esc(actLbl)}${(d.in_flight || 0) > 0 ? ` · 在途 ${d.in_flight}` : ''}</span>`;
    detailHtml = `
      <div class="bar-wrap"><div class="bar-fill ${barCls}" style="width:${Math.min(100, pct).toFixed(1)}%"></div></div>
      <div class="muted">剩 ${fmtBytes(d.free_bytes)} / ${fmtBytes(d.total_bytes)} (${pct.toFixed(1)}%)</div>
    `;
  }
  return `
    <div class="disk-mini-item${itemCls}">
      <div class="disk-mini-head">
        <span class="mono" title="${esc(d.path)}">${esc(d.path)}</span>
        ${stTag}
      </div>
      ${detailHtml}
    </div>
  `;
}

function nodeWatermarkPct(node) {
  const v = Number(node && node.max_disk_usage_pct);
  if (!Number.isFinite(v) || v <= 0) return 85;
  return Math.max(1, Math.min(99, Math.round(v * 10) / 10));
}

function parseWatermarkInput(raw) {
  const v = Number(raw);
  if (!Number.isFinite(v) || v < 1 || v > 99) return null;
  return Math.round(v * 10) / 10;
}

function updateDiskPickerWatermarkPreview(listEl, wm) {
  if (!listEl || !Number.isFinite(wm)) return;
  const clamped = Math.max(1, Math.min(99, wm));
  listEl.querySelectorAll('[data-disk-row]').forEach(row => {
    const pct = Number(row.dataset.usedPct);
    const wmSpan = row.querySelector('[data-wm-label]');
    if (wmSpan) {
      wmSpan.textContent = wmSpan.dataset.isSystem === '1'
        ? `系统盘 · 强制水位 ≤${clamped}%`
        : `数据盘 · 强制水位 ≤${clamped}%`;
    }
    if (Number.isFinite(pct)) {
      const over = pct >= clamped;
      const overBadge = row.querySelector('[data-wm-over]');
      if (overBadge) overBadge.classList.toggle('hidden', !over);
      const chk = row.querySelector('input.edit-disk-chk');
      const bar = row.querySelector('.bar-fill');
      if (bar && chk && chk.checked) {
        bar.classList.toggle('red', over);
        bar.classList.toggle('green', !over);
      }
    }
  });
}

function classifyDiskState(d, disabledSet, lockedSet) {
  const isLocked = !!(d.unplug_latched || lockedSet.has(d.path));
  if (d.detached) return 'detached';
  if (isLocked) return 'locked';
  const enabled = d.enabled !== false && !disabledSet.has(d.path);
  if (!enabled) return d.safe_to_eject ? 'safe_eject' : 'disabled';
  if (d.disk_role === 'full' || d.low_space) return 'full';
  if (d.disk_role === 'standby') return 'standby';
  return 'active';
}

function summarizeNodeDisks(n) {
  const disks = n.disks || [];
  const disabledSet = new Set(n.disabled_disks || []);
  const lockedSet = new Set(n.unplug_locked_disks || []);
  const counts = { total: disks.length, active: 0, standby: 0, full: 0, disabled: 0, safeEject: 0, detached: 0, locked: 0, inFlight: 0 };
  let sumTotal = 0;
  let sumFree = 0;
  for (const d of disks) {
    const st = classifyDiskState(d, disabledSet, lockedSet);
    counts.inFlight += (d.in_flight || 0);
    if (st === 'detached') counts.detached++;
    else if (st === 'locked') counts.locked++;
    else if (st === 'safe_eject') { counts.safeEject++; counts.disabled++; }
    else if (st === 'disabled') counts.disabled++;
    else if (st === 'full') counts.full++;
    else if (st === 'standby') counts.standby++;
    else counts.active++;
    if (!d.detached && d.total_bytes > 0) {
      sumTotal += d.total_bytes;
      sumFree += (d.free_bytes || 0);
    }
  }
  const totalBytes = n.disk_total_bytes > 0 ? n.disk_total_bytes : sumTotal;
  const freeBytes = n.disk_total_bytes > 0 ? (n.disk_free_bytes || 0) : sumFree;
  const usedBytes = Math.max(0, totalBytes - freeBytes);
  const usedPct = totalBytes > 0 ? (usedBytes / totalBytes) * 100 : Number(n.disk_used_pct || 0);
  return { counts, totalBytes, freeBytes, usedBytes, usedPct, disabledSet, lockedSet };
}

function renderReceiverDisks(n) {
  const wm = nodeWatermarkPct(n);
  const polBadge = `<span class="badge">${esc(diskPolicyLabel(n.disk_policy, n.active_disk_window))}</span>`;
  const affOn = nodeDiskAffinityEnabled(n);
  const affBadge = affOn
    ? '<span class="badge accent">同源亲和</span>'
    : '<span class="badge standby">无亲和</span>';
  const wmBadge = `<span class="badge">水位 ≤${wm}%</span>`;

  if (n.awaiting_disk) {
    const foundCnt = (n.host_disks || []).length;
    return `
      <div class="disk-overview-card">
        <div class="disk-overview-badges">
          <span class="badge awaiting">⚠ 待选盘 · 未激活</span>
          ${polBadge}${affBadge}${wmBadge}
        </div>
        <div class="muted">${foundCnt > 0 ? `已扫描到 ${foundCnt} 块物理盘，请点右侧「选择数据盘并激活」` : '请点右侧「选择数据盘并激活」'}</div>
      </div>
    `;
  }

  const s = summarizeNodeDisks(n);
  const c = s.counts;
  const hasAlert = c.detached > 0 || c.locked > 0;
  const barCls = hasAlert || s.usedPct >= wm || (c.total > 0 && c.active === 0 && c.full > 0) ? 'red' : 'green';
  const countPills = [];
  if (c.total > 0) {
    countPills.push(`<span class="badge">共 ${c.total} 盘</span>`);
    if (c.active > 0) countPills.push(`<span class="badge online">写入 ${c.active}</span>`);
    if (c.standby > 0) countPills.push(`<span class="badge standby">候补 ${c.standby}</span>`);
    if (c.full > 0) countPills.push(`<span class="badge full-disk">已满 ${c.full}</span>`);
    if (c.safeEject > 0) countPills.push(`<span class="badge safe-eject">✓ 可拔 ${c.safeEject}</span>`);
    else if (c.disabled > 0) countPills.push(`<span class="badge offline">停用 ${c.disabled}</span>`);
    if (c.detached > 0) countPills.push(`<span class="badge detached">⚠ 拔出 ${c.detached}</span>`);
    if (c.locked > 0) countPills.push(`<span class="badge reinsert">🔌 重插 ${c.locked}</span>`);
  }
  const viewBtn = (c.total > 0 || (n.host_disks && n.host_disks.length > 0))
    ? `<button type="button" class="btn sm ghost" data-action="view-node-disks" data-id="${esc(n.id)}">查看盘列表 (${c.total || n.host_disks.length}) ▸</button>`
    : '';

  return `
    <div class="disk-overview-card">
      <div class="disk-overview-badges">${polBadge}${affBadge}${wmBadge}</div>
      <div class="disk-overview-cap">
        <div class="bar-wrap"><div class="bar-fill ${barCls}" style="width:${Math.min(100, s.usedPct).toFixed(1)}%"></div></div>
        <div class="muted">剩 ${fmtBytes(s.freeBytes)} / 共 ${fmtBytes(s.totalBytes)} (${s.usedPct.toFixed(1)}% 已用)</div>
      </div>
      <div class="disk-overview-foot">
        ${countPills.join('')}
        ${viewBtn}
      </div>
    </div>
  `;
}

function renderDispatchDisks(n) {
  const wm = nodeWatermarkPct(n);
  const wmBadge = `<span class="badge">水位 ≤${wm}%</span>`;
  if (n.awaiting_disk) {
    const foundCnt = (n.host_disks || []).length;
    return `
      <div class="disk-overview-card">
        <div class="disk-overview-badges"><span class="badge awaiting">⚠ 待选缓存盘</span>${wmBadge}</div>
        <div class="muted">${foundCnt > 0 ? `已扫描到 ${foundCnt} 块物理盘，请点右侧激活` : '请点右侧「选择数据盘并激活」'}</div>
      </div>
    `;
  }
  const s = summarizeNodeDisks(n);
  const c = s.counts;
  const barCls = n.disk_alarm || c.detached > 0 || s.usedPct >= wm ? 'red' : 'green';
  const countPills = [];
  if (c.total > 0) {
    countPills.push(`<span class="badge">共 ${c.total} 盘</span>`);
    if (c.active > 0) countPills.push(`<span class="badge online">启用 ${c.active}</span>`);
    if (c.full > 0) countPills.push(`<span class="badge full-disk">已满 ${c.full}</span>`);
    if (c.safeEject > 0) countPills.push(`<span class="badge safe-eject">✓ 可拔 ${c.safeEject}</span>`);
    if (c.detached > 0) countPills.push(`<span class="badge detached">⚠ 拔出 ${c.detached}</span>`);
    if (c.locked > 0) countPills.push(`<span class="badge reinsert">🔌 重插 ${c.locked}</span>`);
  }
  const viewBtn = (c.total > 0 || (n.host_disks && n.host_disks.length > 0))
    ? `<button type="button" class="btn sm ghost" data-action="view-node-disks" data-id="${esc(n.id)}">查看盘列表 (${c.total || n.host_disks.length}) ▸</button>`
    : '';
  return `
    <div class="disk-overview-card">
      <div class="disk-overview-badges">
        ${wmBadge}
        ${c.active > 1 ? `<span class="badge accent">${c.active} 盘并发缓存</span>` : ''}
      </div>
      <div class="disk-overview-cap">
        <div class="bar-wrap"><div class="bar-fill ${barCls}" style="width:${Math.min(100, s.usedPct).toFixed(1)}%"></div></div>
        <div class="muted">剩 ${fmtBytes(s.freeBytes)} / 共 ${fmtBytes(s.totalBytes)} (${s.usedPct.toFixed(1)}% 已用)</div>
      </div>
      <div class="disk-overview-foot">
        ${countPills.join('')}
        ${viewBtn}
      </div>
    </div>
  `;
}

function renderNodes(nodes, winHours) {
  const winLbl = windowLabel(winHours);
  const thA = document.getElementById('th-a-window');
  const thBCmp = document.getElementById('th-b-completed');
  const thBSpd = document.getElementById('th-b-speed');
  if (thA) thA.textContent = `${winLbl}出站汇总`;
  if (thBCmp) thBCmp.textContent = `${winLbl}完成汇总`;
  if (thBSpd) thBSpd.textContent = `${winLbl}平均速率`;

  const as = nodes.filter(n => n.role === 'agent_a');
  const bs = nodes.filter(n => n.role === 'agent_b');

  const aIDs = new Set(as.map(n => n.id));
  for (const id of selectedNodes.agent_a) if (!aIDs.has(id)) selectedNodes.agent_a.delete(id);
  const bIDs = new Set(bs.map(n => n.id));
  for (const id of selectedNodes.agent_b) if (!bIDs.has(id)) selectedNodes.agent_b.delete(id);

  document.getElementById('nodes-a-tbody').innerHTML = as.length ? as.map(n => {
    const queued = (n.availability || []).reduce((a, x) => a + (x.ready_count || 0) + (x.claimed_count || 0), 0);
    const queuedBytes = (n.availability || []).reduce((a, x) => a + (x.ready_bytes || 0), 0);
    const verStr = n.version ? `${n.version}${n.arch ? ' · ' + n.arch : ''}` : '-';
    const checked = selectedNodes.agent_a.has(n.id) ? 'checked' : '';
    const diskAlerts = analyzeNodeDiskAlerts(n);
    const rowCls = n.awaiting_disk ? 'row-awaiting-disk' : (diskAlerts.detached > 0 ? 'row-disk-alert' : '');
    const neverConnected = !n.online && !n.last_seen_at;
    const diskBtn = n.awaiting_disk
      ? `<button class="btn sm activate" data-action="edit-a-disks" data-id="${esc(n.id)}">⚡ 选择数据盘并激活</button>`
      : `<button class="btn sm ${neverConnected ? '' : 'primary'}" data-action="edit-a-disks" data-id="${esc(n.id)}">管理数据盘</button>`;
    const pauseBtn = neverConnected ? '' : (n.paused
      ? `<button class="btn sm success" data-action="toggle-pause-node" data-id="${esc(n.id)}" data-paused="1">启动</button>`
      : `<button class="btn sm warn" data-action="toggle-pause-node" data-id="${esc(n.id)}" data-paused="0">暂停</button>`);
    const scriptBtn = neverConnected
      ? `<button class="btn sm primary" data-action="open-a-script" data-id="${esc(n.id)}">获取安装脚本</button>`
      : '';
    return `
      <tr class="${rowCls}">
        <td><input type="checkbox" class="node-chk" data-role="agent_a" data-id="${esc(n.id)}" ${checked} /></td>
        <td><strong>${esc(n.name)}</strong><div class="mono muted">${esc(n.id)}</div></td>
        <td>
          <div style="display:flex;gap:4px;flex-wrap:wrap;align-items:center">
            <span class="badge ${n.online ? 'online pulse' : 'offline'}">${n.online ? '在线' : (neverConnected ? '待装机' : '离线')}</span>
            ${n.awaiting_disk ? '<span class="badge awaiting">待选盘 · 未激活</span>' : ''}
            ${n.paused ? '<span class="badge alarm">已暂停</span>' : ''}
            ${n.disk_alarm && diskAlerts.detached === 0 ? '<span class="badge alarm">水位告警</span>' : ''}
            ${renderNodeDiskAlertBadges(n)}
            ${renderUpgradeBadge(n)}
          </div>
          <div class="mono muted" style="margin-top:3px">${esc(verStr)}</div>
        </td>
        <td class="mono">${esc(n.public_addr || '-')}</td>
        <td>${renderDispatchDisks(n)}</td>
        <td>
          <div>${fmtNum(queued)} 文件</div>
          <div class="muted">${fmtBytes(queuedBytes)}</div>
        </td>
        <td>
          <div class="mono">${fmtSpeed(n.window_avg_speed_bps)} <span class="muted">(${fmtMbps(n.window_avg_speed_bps)})</span></div>
          <div class="muted">活跃 ${fmtSpeed(n.active_avg_speed_bps)} · ${fmtNum(n.window_completed)} 文件 (${fmtBytes(n.window_bytes)})</div>
        </td>
        <td>
          <div class="btn-row">
            ${scriptBtn}
            ${diskBtn}
            ${pauseBtn}
            <button class="btn sm danger" data-action="delete-node" data-id="${esc(n.id)}">删除</button>
          </div>
        </td>
      </tr>
    `;
  }).join('') : '<tr><td colspan="8" class="empty">暂无注册的分发节点</td></tr>';

  document.getElementById('nodes-b-tbody').innerHTML = bs.length ? bs.map(n => {
    const verStr = n.version ? `${n.version}${n.arch ? ' · ' + n.arch : ''}` : '-';
    const checked = selectedNodes.agent_b.has(n.id) ? 'checked' : '';
    const diskAlerts = analyzeNodeDiskAlerts(n);
    const rowCls = n.awaiting_disk ? 'row-awaiting-disk' : (diskAlerts.detached > 0 ? 'row-disk-alert' : '');
    const neverConnected = !n.online && !n.last_seen_at;
    const cfgBtn = n.awaiting_disk
      ? `<button class="btn sm activate" data-action="edit-node-projects" data-id="${esc(n.id)}">⚡ 选择数据盘并激活</button>`
      : `<button class="btn sm ${neverConnected ? '' : 'primary'}" data-action="edit-node-projects" data-id="${esc(n.id)}">配置项目与磁盘</button>`;
    const pauseBtn = neverConnected ? '' : (n.paused
      ? `<button class="btn sm success" data-action="toggle-pause-node" data-id="${esc(n.id)}" data-paused="1">启动</button>`
      : `<button class="btn sm warn" data-action="toggle-pause-node" data-id="${esc(n.id)}" data-paused="0">暂停</button>`);
    const scriptBtn = neverConnected
      ? `<button class="btn sm primary" data-action="open-b-script" data-id="${esc(n.id)}">获取安装脚本</button>`
      : '';
    return `
      <tr class="${rowCls}">
        <td><input type="checkbox" class="node-chk" data-role="agent_b" data-id="${esc(n.id)}" ${checked} /></td>
        <td><strong>${esc(n.name)}</strong><div class="mono muted">${esc(n.id)}</div></td>
        <td>
          <div style="display:flex;gap:4px;flex-wrap:wrap;align-items:center">
            <span class="badge ${n.online ? 'online pulse' : 'offline'}">${n.online ? '在线' : (neverConnected ? '待装机' : '离线')}</span>
            ${n.awaiting_disk ? '<span class="badge awaiting">待选盘 · 未激活</span>' : ''}
            ${n.paused ? '<span class="badge alarm">已暂停</span>' : ''}
            ${renderNodeDiskAlertBadges(n)}
            ${renderUpgradeBadge(n)}
          </div>
          <div class="mono muted" style="margin-top:3px">${esc(verStr)}</div>
        </td>
        <td>${renderProjectScope(n.projects, n.project_schedule, n)}</td>
        <td>${renderReceiverDisks(n)}</td>
        <td>
          <div>${fmtNum(n.window_completed)} 文件</div>
          <div class="muted">${fmtBytes(n.window_bytes)} · 失败 ${fmtNum(n.window_failed)}</div>
        </td>
        <td>
          <div class="mono">${fmtSpeed(n.window_avg_speed_bps)} <span class="muted">(${fmtMbps(n.window_avg_speed_bps)})</span></div>
          <div class="muted">活跃均速 ${fmtSpeed(n.active_avg_speed_bps)}</div>
        </td>
        <td>
          <div class="btn-row">
            ${scriptBtn}
            ${cfgBtn}
            ${pauseBtn}
            <button class="btn sm danger" data-action="delete-node" data-id="${esc(n.id)}">删除</button>
          </div>
        </td>
      </tr>
    `;
  }).join('') : '<tr><td colspan="8" class="empty">暂无注册的接收节点</td></tr>';

  document.getElementById('chk-all-a').checked = as.length > 0 && as.every(n => selectedNodes.agent_a.has(n.id));
  document.getElementById('chk-all-b').checked = bs.length > 0 && bs.every(n => selectedNodes.agent_b.has(n.id));
}

function populateReleaseSelect(selectEl, role, emptyLabel) {
  if (!selectEl) return;
  const prev = selectEl.value;
  const list = cachedReleases.filter(r => r.role === role);
  const opts = [];
  if (emptyLabel) opts.push(`<option value="">${esc(emptyLabel)}</option>`);
  if (!list.length && !emptyLabel) {
    opts.push('<option value="">请先在「部署与版本」上传发布包</option>');
  }
  for (const r of list) {
    opts.push(`<option value="${esc(r.id)}">${esc(r.version)} (${esc(r.os)}/${esc(r.arch)} · ${fmtBytes(r.size)})</option>`);
  }
  selectEl.innerHTML = opts.join('');
  if (prev && list.some(r => r.id === prev)) {
    selectEl.value = prev;
  }
}

function renderReleases(list) {
  populateReleaseSelect(document.getElementById('batch-rel-a'), 'agent_a', '');
  populateReleaseSelect(document.getElementById('batch-rel-b'), 'agent_b', '');
  populateReleaseSelect(document.getElementById('deploy-a-release-select'), 'agent_a', '自动匹配最新分发节点发布包');
  populateReleaseSelect(document.getElementById('a-script-release-select'), 'agent_a', '自动匹配最新分发节点发布包');
  populateReleaseSelect(document.getElementById('b-script-release-select'), 'agent_b', '自动匹配最新接收节点发布包');

  const tbody = document.getElementById('releases-tbody');
  tbody.innerHTML = list.length ? list.map(r => `
    <tr>
      <td><span class="badge">${r.role === 'agent_a' ? '分发节点' : '接收节点'}</span></td>
      <td class="mono"><strong>${esc(r.version)}</strong></td>
      <td class="mono">${esc(r.os)}/${esc(r.arch)}</td>
      <td>${fmtBytes(r.size)}</td>
      <td class="mono muted">${esc((r.sha256 || '').slice(0, 14))}…</td>
      <td class="muted">${esc(r.notes || '-')}</td>
      <td><button class="btn sm danger" data-action="delete-release" data-id="${esc(r.id)}">删除</button></td>
    </tr>
  `).join('') : '<tr><td colspan="7" class="empty">暂未上传发布包，请先在上方上传 Linux 编译产物</td></tr>';
}

function renderDeployTasks(tasks) {
  const el = document.getElementById('deploy-tasks-list');
  if (!tasks.length) {
    el.innerHTML = '<div class="empty">暂无一键部署记录</div>';
    return;
  }
  el.innerHTML = tasks.slice(0, 8).map(t => {
    const cls = t.status === 'succeeded' ? 'online' : (t.status === 'failed' ? 'offline' : 'alarm');
    const lbl = t.status === 'succeeded' ? '成功' : (t.status === 'failed' ? '失败' : '部署中');
    return `
      <div class="transfer-row">
        <div class="transfer-meta">
          <div>
            <strong>${esc(t.node_id)}</strong>
            <span class="mono muted">${esc(t.host)}</span>
            <span class="badge ${cls}">${lbl}</span>
          </div>
          <button class="btn sm" data-action="view-deploy-task" data-id="${esc(t.id)}">查看日志</button>
        </div>
        <div class="muted">版本: ${esc(t.release_version || '-')} · 阶段: ${esc(t.step)}${t.error ? ' · ' + esc(t.error) : ''}</div>
      </div>
    `;
  }).join('');
}

function renderAccounts(list) {
  const tbody = document.getElementById('accounts-tbody');
  if (!tbody) return;
  tbody.innerHTML = list.length ? list.map(a => {
    const projs = a.projects || [];
    const scopeHtml = !projs.length
      ? '<span class="badge alarm">未分配项目</span> <span class="muted">默认全不可见</span>'
      : `<div style="display:flex;gap:4px;flex-wrap:wrap">${projs.map(pid => {
          const meta = getProjectMeta(pid);
          return `<span class="badge accent" title="内部 ID: ${esc(meta.id)}${meta.desc ? ' · ' + esc(meta.desc) : ''}">${esc(meta.name)}${meta.hasDistinctName ? ` <span style="opacity:0.7;font-size:10px">(${esc(meta.shortId)})</span>` : ''}</span>`;
        }).join('')}</div>`;
    const lastUsed = a.last_used_at ? fmtTimeShort(a.last_used_at, true) : '未使用';
    const created = a.created_at ? fmtTimeShort(a.created_at, true) : '-';
    return `
      <tr>
        <td><strong>${esc(a.name)}</strong><div class="mono muted">${esc(a.id)}</div></td>
        <td><span class="badge ${a.enabled ? 'online' : 'offline'}">${a.enabled ? '启用' : '已停用'}</span></td>
        <td>${scopeHtml}</td>
        <td class="muted">${esc(lastUsed)}</td>
        <td class="muted">${esc(created)}</td>
        <td>
          <div class="btn-row">
            <button class="btn sm" data-action="edit-account" data-id="${esc(a.id)}">编辑 / 分配项目</button>
            <button class="btn sm primary" data-action="rotate-account" data-id="${esc(a.id)}">重置密钥</button>
            <button class="btn sm danger" data-action="delete-account" data-id="${esc(a.id)}">删除</button>
          </div>
        </td>
      </tr>
    `;
  }).join('') : '<tr><td colspan="6" class="empty">暂无客户账号，点击右上角「+ 新建客户账号」创建</td></tr>';
}

function renderAccountProjectChecks(selectedList) {
  const wrap = document.getElementById('account-project-checks');
  if (!wrap) return;
  const selSet = new Set(selectedList || []);
  if (!cachedProjects.length) {
    wrap.innerHTML = '<div class="muted">暂无已有项目，可先在「项目视图」新建项目或下方手动输入项目 ID</div>';
    return;
  }
  wrap.innerHTML = cachedProjects.map(ps => {
    const p = ps.project;
    const chk = selSet.has(p.id) ? 'checked' : '';
    const subParts = [shortId(p.id)];
    if (p.description) subParts.push(p.description);
    return `
      <label class="proj-check-card" title="内部 ID: ${esc(p.id)}">
        <input type="checkbox" class="account-proj-chk" value="${esc(p.id)}" ${chk} />
        <span class="proj-check-meta">
          <span class="proj-check-title">${esc(p.name || p.id)}</span>
          <span class="proj-check-sub mono">${esc(subParts.join(' · '))}</span>
        </span>
      </label>
    `;
  }).join('');
}

function openAccountModal(accountId = '') {
  const form = document.getElementById('account-form');
  form.reset();
  const existing = accountId ? cachedAccounts.find(a => a.id === accountId) : null;
  form.elements.mode.value = existing ? 'edit' : 'create';
  form.elements.id.readOnly = !!existing;
  document.getElementById('btn-gen-account-id')?.classList.toggle('hidden', !!existing);
  document.getElementById('account-modal-title').textContent = existing ? `编辑客户账号: ${existing.name || existing.id}` : '新建客户账号';
  document.getElementById('account-enabled-wrap').classList.toggle('hidden', !existing);
  if (existing) {
    form.elements.id.value = existing.id;
    form.elements.name.value = existing.name || existing.id;
    form.elements.enabled.checked = existing.enabled !== false;
    const projs = existing.projects || [];
    form.elements.projects.value = projs.join(',');
    renderAccountProjectChecks(projs);
  } else {
    form.elements.projects.value = '';
    form.elements.enabled.checked = true;
    renderAccountProjectChecks([]);
  }
  const accSearch = document.getElementById('account-project-search');
  if (accSearch) accSearch.value = '';
  openModal('account-modal');
}

function openAssignProjectModal(projectId) {
  const form = document.getElementById('assign-project-form');
  const wrap = document.getElementById('assign-project-accounts-list');
  if (!form || !wrap) return;
  const meta = getProjectMeta(projectId);
  form.elements.project_id.value = projectId;
  document.getElementById('assign-project-title').textContent = `分配项目给客户: ${meta.name}`;
  document.getElementById('assign-project-sub').textContent = `内部 ID: ${meta.id}${meta.desc ? ' · ' + meta.desc : ''}（仅勾选客户可见并下载）`;
  if (!cachedAccounts.length) {
    wrap.innerHTML = '<div class="empty" style="padding:14px">暂无客户账号，请先在「客户账号」标签页新建客户。</div>';
  } else {
    wrap.innerHTML = cachedAccounts.map(a => {
      const checked = Array.isArray(a.projects) && a.projects.includes(projectId);
      const st = a.enabled === false ? ' · 已停用' : '';
      return `
        <label class="proj-check-card">
          <input type="checkbox" class="assign-acc-chk" value="${esc(a.id)}" ${checked ? 'checked' : ''} />
          <span class="proj-check-meta">
            <span class="proj-check-title">${esc(a.name || a.id)}</span>
            <span class="proj-check-sub mono">${esc(a.id)}${st}</span>
          </span>
        </label>
      `;
    }).join('');
  }
  openModal('assign-project-modal');
}

function showAccountTokenModal(account, rawToken, titleText) {
  lastAccountToken = rawToken || '';
  lastAccountLoginURL = `${window.location.origin}/#token=${encodeURIComponent(lastAccountToken)}`;
  document.getElementById('account-token-title').textContent = titleText || `客户账号密钥: ${account.name || account.id}`;
  document.getElementById('account-token-value').textContent = lastAccountToken;
  document.getElementById('account-login-url').textContent = lastAccountLoginURL;
  openModal('account-token-modal');
}

async function rotateAccountToken(id) {
  const acc = cachedAccounts.find(a => a.id === id);
  const lbl = acc ? `${acc.name} (${acc.id})` : id;
  if (!confirm(`确认重置客户账号 ${lbl} 的密钥吗？\n旧 Token 将立即失效，需将新链接发给客户。`)) return;
  try {
    const res = await api(`/api/v1/admin/accounts/${encodeURIComponent(id)}/rotate`, { method: 'POST' });
    showAccountTokenModal(res.account, res.token, `已重置客户密钥: ${res.account.name}`);
    showToast(`客户账号 ${id} 密钥已重置`, 'success');
    refreshAll();
  } catch (e) {
    if (e.message !== 'unauthorized') showToast(`重置密钥失败: ${e.message}`, 'error');
  }
}

async function deleteAccount(id) {
  const acc = cachedAccounts.find(a => a.id === id);
  const lbl = acc ? `${acc.name} (${acc.id})` : id;
  if (!confirm(`确认删除并永久吊销客户账号 ${lbl} 吗？`)) return;
  try {
    await api(`/api/v1/admin/accounts/${encodeURIComponent(id)}`, { method: 'DELETE' });
    showToast(`已吊销客户账号 ${id}`, 'success');
    refreshAll();
  } catch (e) {
    if (e.message !== 'unauthorized') showToast(`删除客户账号失败: ${e.message}`, 'error');
  }
}

async function togglePauseNode(id, currentlyPaused) {
  const nextPaused = !currentlyPaused;
  const node = cachedNodes.find(n => n.id === id);
  const roleName = node && node.role === 'agent_a' ? '分发节点' : '接收节点';
  const actionTxt = nextPaused ? '暂停' : '启动';
  try {
    await api(`/api/v1/admin/nodes/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: JSON.stringify({ paused: nextPaused }),
    });
    showToast(
      nextPaused
        ? `${roleName} ${id} 已暂停（停止分配新任务，在途传输安全落盘后即静止）`
        : `${roleName} ${id} 已启动，2 秒内自动恢复传输`,
      nextPaused ? 'info' : 'success'
    );
    refreshAll();
  } catch (e) {
    if (e.message !== 'unauthorized') showToast(`${actionTxt}节点失败: ${e.message}`, 'error');
  }
}

async function deleteNode(id) {
  if (!confirm(`确认删除节点 ${id} 吗？`)) return;
  try {
    await api(`/api/v1/admin/nodes/${encodeURIComponent(id)}`, { method: 'DELETE' });
    showToast(`已删除节点 ${id}`, 'success');
    refreshAll();
  } catch (e) {
    if (e.message !== 'unauthorized') showToast(`删除节点失败: ${e.message}`, 'error');
  }
}

async function deleteProject(id) {
  if (!confirm(`确认删除项目 ${id} 吗？`)) return;
  try {
    await api(`/api/v1/admin/projects/${encodeURIComponent(id)}`, { method: 'DELETE' });
    if (activeProjectDetailId === id) {
      activeProjectDetailId = '';
      closeModal('project-detail-modal');
    }
    showToast(`已删除项目 ${id}`, 'success');
    refreshAll();
  } catch (e) {
    if (e.message !== 'unauthorized') showToast(`删除项目失败: ${e.message}`, 'error');
  }
}

async function deleteRelease(id) {
  if (!confirm('确认删除该发布包吗？')) return;
  try {
    await api(`/api/v1/admin/releases/${encodeURIComponent(id)}`, { method: 'DELETE' });
    showToast('发布包已删除', 'success');
    refreshAll();
  } catch (e) {
    if (e.message !== 'unauthorized') showToast(`删除发布包失败: ${e.message}`, 'error');
  }
}

async function runBatchUpgrade(role) {
  const selectId = role === 'agent_a' ? 'batch-rel-a' : 'batch-rel-b';
  const msgId = role === 'agent_a' ? 'batch-msg-a' : 'batch-msg-b';
  const releaseID = document.getElementById(selectId).value;
  const nodeIDs = Array.from(selectedNodes[role]);
  if (!releaseID) {
    showToast('请先选择目标发布包（如为空，请先在「部署与版本」上传）', 'error');
    return;
  }
  if (!nodeIDs.length) {
    showToast('请先勾选至少一个节点', 'error');
    return;
  }
  if (!confirm(`确认向 ${nodeIDs.length} 个节点下发批量更新指令吗？\n目标节点: ${nodeIDs.join(', ')}`)) return;
  try {
    const res = await api('/api/v1/admin/upgrades', {
      method: 'POST',
      body: JSON.stringify({ release_id: releaseID, node_ids: nodeIDs }),
    });
    const skippedKeys = Object.keys(res.skipped || {});
    let txt = `已下发 ${res.queued.length} 个节点`;
    if (skippedKeys.length) {
      txt += `，跳过 ${skippedKeys.length} 个 (${skippedKeys.map(k => `${k}: ${res.skipped[k]}`).join('; ')})`;
    }
    document.getElementById(msgId).textContent = txt;
    showToast(txt, 'success');
    selectedNodes[role].clear();
    refreshAll();
  } catch (e) {
    if (e.message !== 'unauthorized') showToast(`批量更新下发失败: ${e.message}`, 'error');
  }
}

function openDeployAModal() {
  lastPrecheck = null;
  activeDeployTaskId = '';
  const form = document.getElementById('deploy-a-form');
  form.reset();
  document.getElementById('precheck-result').classList.add('hidden');
  document.getElementById('deploy-progress-box').classList.add('hidden');
  document.getElementById('deploy-force-wrap').classList.add('hidden');
  document.getElementById('btn-refresh-deploy-status').classList.add('hidden');
  document.getElementById('deploy-force-chk').checked = false;
  document.getElementById('btn-confirm-deploy-a').disabled = true;
  populateReleaseSelect(document.getElementById('deploy-a-release-select'), 'agent_a', '自动匹配最新分发节点发布包');
  openModal('deploy-a-modal');
}

function readDeployAForm() {
  const fd = new FormData(document.getElementById('deploy-a-form'));
  const projs = String(fd.get('projects') || '').split(',').map(s => s.trim()).filter(Boolean);
  return {
    host: String(fd.get('host') || '').trim(),
    ssh_port: Number(fd.get('ssh_port') || 22),
    ssh_user: String(fd.get('ssh_user') || 'root').trim(),
    ssh_password: String(fd.get('ssh_password') || ''),
    node_id: String(fd.get('node_id') || '').trim(),
    node_name: String(fd.get('node_name') || '').trim(),
    public_port: Number(fd.get('public_port') || 8443),
    local_port: Number(fd.get('local_port') || 18081),
    install_dir: String(fd.get('install_dir') || '/opt/relay-agent-a').trim(),
    data_dir: String(fd.get('data_dir') || '/data/relay-a').trim(),
    max_disk_usage_pct: Number(fd.get('max_disk_usage_pct') || 85),
    projects: projs,
    release_id: String(fd.get('release_id') || ''),
    force_overwrite: document.getElementById('deploy-force-chk').checked,
  };
}

function renderPrecheckResult(res) {
  const box = document.getElementById('precheck-result');
  let banner = '';
  if (res.ok) {
    banner = '<div class="banner pass">全部环境检测通过！确认参数无误后点击「2. 确认一键部署」。</div>';
  } else if (res.can_force) {
    banner = '<div class="banner warn">检测到可覆盖的警告项（例如目录非空或已有服务），请勾选「确认覆盖」后再点击部署。</div>';
  } else {
    banner = '<div class="banner fail">存在阻断性环境错误，请先解决红色 FAIL 项后重新执行预检。</div>';
  }
  const rows = (res.checks || []).map(c => {
    const cls = c.status === 'pass' ? 'online' : (c.status === 'warn' ? 'alarm' : 'offline');
    return `
      <div class="check-row">
        <div><strong>${esc(c.label)}</strong><div class="muted">${esc(c.detail)}</div></div>
        <span class="badge ${cls}">${esc(c.status.toUpperCase())}</span>
      </div>
    `;
  }).join('');
  box.innerHTML = `${banner}<div class="check-list">${rows}</div>`;
  box.classList.remove('hidden');

  const forceWrap = document.getElementById('deploy-force-wrap');
  const forceChk = document.getElementById('deploy-force-chk');
  const deployBtn = document.getElementById('btn-confirm-deploy-a');
  forceChk.checked = false;
  if (res.ok) {
    forceWrap.classList.add('hidden');
    deployBtn.disabled = false;
  } else if (res.can_force) {
    forceWrap.classList.remove('hidden');
    deployBtn.disabled = true;
  } else {
    forceWrap.classList.add('hidden');
    deployBtn.disabled = true;
  }
}

function renderDeployTaskDetail(t, targetEl) {
  const cls = t.status === 'succeeded' ? 'pass' : (t.status === 'failed' ? 'fail' : 'warn');
  const title = t.status === 'succeeded'
    ? `部署成功！公网地址: ${t.public_addr}`
    : (t.status === 'failed' ? `部署失败: ${t.error}` : `正在后台部署 (${t.step})，请点击「刷新部署状态」查看最新日志`);
  let tokHtml = '';
  if (t.status === 'succeeded') {
    tokHtml = `
      <div class="token-box" style="margin-bottom:10px">
        <strong>本机上传接口默认免鉴权：</strong>
        <div class="muted" style="margin-top:4px">分发节点仅监听 <code>127.0.0.1</code> 回环地址，本机业务方直接 <code>PUT</code> 推送即可，无需携带 <code>X-Local-Token</code>。</div>
      </div>
    `;
  }
  targetEl.innerHTML = `
    <div class="banner ${cls}">${esc(title)}</div>
    ${tokHtml}
    <div class="log-box">${esc((t.logs || []).join('\n'))}</div>
  `;
  targetEl.classList.remove('hidden');
}

async function fetchDeployStatus(taskId) {
  if (!taskId) return;
  const box = document.getElementById('deploy-progress-box');
  try {
    const t = await api(`/api/v1/admin/deploy/tasks/${encodeURIComponent(taskId)}`);
    renderDeployTaskDetail(t, box);
    if (t.status !== 'running') {
      refreshAll();
    }
  } catch (e) {
    if (e.message !== 'unauthorized') {
      box.innerHTML = `<div class="banner fail">查询部署状态失败: ${esc(e.message)}</div>`;
      box.classList.remove('hidden');
    }
  }
}

async function viewDeployTaskLog(taskId) {
  activeLogModalTaskId = taskId;
  document.getElementById('deploy-log-title').textContent = `部署任务日志: ${taskId.slice(0, 8)}`;
  const body = document.getElementById('deploy-log-body');
  body.innerHTML = '<div class="empty">加载日志...</div>';
  openModal('deploy-log-modal');
  try {
    const t = await api(`/api/v1/admin/deploy/tasks/${encodeURIComponent(taskId)}`);
    renderDeployTaskDetail(t, body);
  } catch (e) {
    body.innerHTML = `<div class="err-msg">${esc(e.message)}</div>`;
  }
}

function syncCreateNodeProjectMode() {
  const form = document.getElementById('create-node-form');
  const isReceiver = form.elements.role.value === 'agent_b';
  const mode = form.elements.project_mode.value || 'single';
  document.getElementById('node-project-mode-wrap').classList.toggle('hidden', !isReceiver);
  const useSingle = isReceiver && mode === 'single';
  const useMultiInput = !isReceiver || mode === 'multi';
  document.getElementById('node-single-project-wrap').classList.toggle('hidden', !useSingle);
  document.getElementById('node-multi-projects-wrap').classList.toggle('hidden', !useMultiInput);
  const selVal = document.getElementById('node-single-project-select').value;
  document.getElementById('node-single-project-custom-wrap').classList.toggle('hidden', !(useSingle && selVal === '__custom__'));
}

function syncEditNodeProjectMode() {
  const form = document.getElementById('edit-node-form');
  const mode = form.elements.edit_project_mode.value || 'single';
  const useSingle = mode === 'single';
  const useMulti = mode === 'multi';
  document.getElementById('edit-single-project-wrap').classList.toggle('hidden', !useSingle);
  document.getElementById('edit-multi-projects-wrap').classList.toggle('hidden', !useMulti);
  document.getElementById('edit-schedule-wrap').classList.toggle('hidden', useSingle);
  const selVal = document.getElementById('edit-single-project-select').value;
  document.getElementById('edit-single-project-custom-wrap').classList.toggle('hidden', !(useSingle && selVal === '__custom__'));
}

function renderEditProjectChecks(selectedList) {
  const wrap = document.getElementById('edit-project-checks');
  if (!wrap) return;
  const selSet = new Set(selectedList || []);
  if (!cachedProjects.length) {
    wrap.innerHTML = '<div class="muted">暂无已有项目，可在下方手动输入项目 ID</div>';
    return;
  }
  wrap.innerHTML = cachedProjects.map(ps => {
    const p = ps.project;
    const chk = selSet.has(p.id) ? 'checked' : '';
    const subParts = [shortId(p.id)];
    if (p.description) subParts.push(p.description);
    return `
      <label class="proj-check-card" title="内部 ID: ${esc(p.id)}">
        <input type="checkbox" class="edit-proj-chk" value="${esc(p.id)}" ${chk} />
        <span class="proj-check-meta">
          <span class="proj-check-title">${esc(p.name || p.id)}</span>
          <span class="proj-check-sub mono">${esc(subParts.join(' · '))}</span>
        </span>
      </label>
    `;
  }).join('');
}

function syncDiskPolicyWindowUI(selectId, wrapId) {
  const sel = document.getElementById(selectId);
  const wrap = document.getElementById(wrapId);
  if (sel && wrap) {
    wrap.classList.toggle('hidden', sel.value !== 'rolling_window');
  }
}

function updateDiskPickerCounter(listEl) {
  if (!listEl) return;
  const counterId = listEl.id === 'edit-disks-list' ? 'edit-b-disk-counter' : 'edit-a-disk-counter';
  const el = document.getElementById(counterId);
  if (!el) return;
  const all = Array.from(listEl.querySelectorAll('input.edit-disk-chk'));
  const enabled = all.filter(c => c.checked && c.closest('[data-disk-row]')?.dataset.removed !== '1').length;
  el.textContent = all.length ? `已勾选 ${enabled} / 共 ${all.length} 块` : '';
}

function matchConfiguredDirForHostDisk(hd, configuredList, allHostDisks) {
  if (configuredList.includes(hd.suggested_dir)) return hd.suggested_dir;
  if (!hd.is_system) {
    const mntPrefix = hd.mount_point.endsWith('/') ? hd.mount_point : hd.mount_point + '/';
    for (const d of configuredList) {
      if (d === hd.mount_point || d.startsWith(mntPrefix)) return d;
    }
    return '';
  }
  const otherPrefixes = allHostDisks
    .filter(x => !x.is_system)
    .map(x => (x.mount_point.endsWith('/') ? x.mount_point : x.mount_point + '/'));
  for (const d of configuredList) {
    if (!otherPrefixes.some(pfx => d === pfx.slice(0, -1) || d.startsWith(pfx))) {
      return d;
    }
  }
  return '';
}

function renderHostDiskPicker(wrap, node, watermarkPct) {
  if (!wrap) return;
  const disabledSet = new Set(node.disabled_disks || []);
  const lockedSet = new Set(node.unplug_locked_disks || []);
  const diskByPath = new Map((node.disks || []).map(d => [d.path, d]));
  const configuredList = Array.from(new Set([...(node.storage_dirs || []), ...((node.disks || []).map(d => d.path))]));
  const hostDisks = node.host_disks || [];

  if (hostDisks.length > 0) {
    const matchedConfigured = new Set();
    const hostRows = hostDisks.map(hd => {
      const cfgPath = matchConfiguredDirForHostDisk(hd, configuredList, hostDisks);
      const isConfigured = !!cfgPath;
      const targetPath = cfgPath || hd.suggested_dir;
      if (isConfigured) matchedConfigured.add(cfgPath);

      const dStat = diskByPath.get(targetPath);
      const isLocked = !!(lockedSet.has(targetPath) || (dStat && dStat.unplug_latched));
      const isDisabled = disabledSet.has(targetPath) || isLocked;
      const checked = isConfigured && !isDisabled;

      const pct = Number(hd.used_pct || 0);
      const overWM = pct >= watermarkPct;
      const barCls = !checked ? '' : (overWM ? 'red' : 'green');
      const kindBadge = hd.is_system
        ? `<span class="badge alarm" data-wm-label="1" data-is-system="1">系统盘 · 强制水位 ≤${watermarkPct}%</span>`
        : `<span class="badge accent" data-wm-label="1" data-is-system="0">数据盘 · 强制水位 ≤${watermarkPct}%</span>`;

      let stateBadge = '';
      let subText = '';
      let rowCls = '';
      if (isLocked) {
        rowCls = ' is-reinsert';
        stateBadge = '<span class="badge reinsert">🔌 曾拔出重插 · 待人工确认</span>';
        subText = '磁盘曾拔出/重挂已自动锁定 · 确认无误后打开左侧开关并保存即可恢复写入';
      } else if (isConfigured && isDisabled) {
        if (dStat && dStat.safe_to_eject) {
          stateBadge = '<span class="badge safe-eject">✓ 已排空 · 可安全卸载拔盘</span>';
          subText = '在途写入 0 · 当前可安全 umount 拔盘（或重新打开开关恢复）';
        } else if (dStat && (dStat.in_flight || 0) > 0) {
          stateBadge = `<span class="badge alarm">排空中 · 在途 ${dStat.in_flight}</span>`;
          subText = `正在等待 ${dStat.in_flight} 个在途传输完成，归零后再卸载拔盘`;
        } else {
          stateBadge = '<span class="badge offline">已停用</span>';
          subText = (dStat && dStat.status_reason) || '已停用 · 不再写入新文件';
        }
      } else if (checked) {
        if (dStat && dStat.disk_role === 'full') {
          stateBadge = '<span class="badge full-disk">已写满水位 · 可停用拔盘</span>';
        } else if (dStat && dStat.disk_role === 'standby') {
          stateBadge = '<span class="badge standby">候补排队</span>';
        } else if (dStat && (dStat.in_flight || 0) > 0) {
          stateBadge = `<span class="badge online">${esc(dStat.status_reason || '启用中')} · 在途 ${dStat.in_flight}</span>`;
        } else if (dStat && dStat.status_reason && dStat.status_reason.startsWith('写入窗口')) {
          stateBadge = `<span class="badge online">${esc(dStat.status_reason)}</span>`;
        }
        subText = (dStat && dStat.disk_role === 'standby')
          ? '候补排队中 · 前序盘写满后自动顶上（关闭开关可移出或停用）'
          : '启用中 · 允许并发写入（关闭开关可进入安全排空准备拔盘）';
      } else {
        if (!hd.is_system && !node.awaiting_disk) {
          stateBadge = '<span class="badge new-disk">✨ 新发现物理盘</span>';
        }
        subText = '未启用 · 勾选并保存即可自动建目录加入并发池';
      }

      const removeBtn = (isConfigured && isDisabled)
        ? `<button type="button" class="btn sm ghost" data-toggle-remove-disk="1">移出磁盘池</button>`
        : '';

      let diskStateTag = 'unchecked';
      if (isLocked) diskStateTag = 'alert';
      else if (isConfigured && isDisabled) diskStateTag = (dStat && dStat.safe_to_eject) ? 'alert' : 'unchecked';
      else if (checked) {
        if (dStat && (dStat.disk_role === 'full' || dStat.low_space || overWM)) diskStateTag = 'full';
        else if (dStat && dStat.disk_role === 'standby') diskStateTag = 'standby';
        else diskStateTag = 'active';
      }

      const searchHaystack = `${hd.mount_point} ${hd.device} ${hd.fs_type} ${targetPath}`.toLowerCase();
      return `
        <div class="disk-toggle-row${rowCls}" data-disk-row="1" data-disk-state="${diskStateTag}" data-used-pct="${pct.toFixed(2)}" data-search="${esc(searchHaystack)}">
          <label class="disk-toggle-left" style="cursor:pointer;flex:1">
            <input type="checkbox" class="edit-disk-chk" data-source="host" data-is-system="${hd.is_system ? '1' : '0'}" data-writable="${hd.writable === false ? '0' : '1'}" data-configured="${isConfigured ? '1' : '0'}" data-dir="${esc(targetPath)}" value="${esc(targetPath)}" ${checked ? 'checked' : ''} />
            <div>
              <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap">
                <strong class="mono">${esc(hd.mount_point)}</strong>
                <span class="muted mono">${esc(hd.device)} · ${esc(hd.fs_type)}</span>
                ${kindBadge}
                ${stateBadge}
                <span class="badge offline${overWM ? '' : ' hidden'}" data-wm-over="1">接近/超水位</span>
              </div>
              <div class="muted disk-toggle-sub" style="margin-top:3px">目录: <span class="mono">${esc(targetPath)}</span> · ${esc(subText)}${hd.writable === false ? ' · 不可写' : ''}</div>
            </div>
          </label>
          <div class="disk-toggle-right">
            <div class="bar-wrap" style="width:150px"><div class="bar-fill ${barCls}" style="width:${Math.min(100, pct).toFixed(1)}%"></div></div>
            <div class="muted">剩余 ${fmtBytes(hd.free_bytes)} / ${fmtBytes(hd.total_bytes)} (${pct.toFixed(1)}%)</div>
            ${removeBtn ? `<div class="disk-row-actions">${removeBtn}</div>` : ''}
          </div>
        </div>
      `;
    });

    // Render any configured disks that are currently UNMOUNTED / UNPLUGGED (absent from host_disks) prominently at top!
    const missingRows = configuredList
      .filter(p => !matchedConfigured.has(p))
      .map(p => {
        const dStat = diskByPath.get(p);
        const reason = (dStat && dStat.status_reason) || '未检测到该挂载点，已自动锁定并拦截写入（防止穿透写进系统盘）';
        return `
          <div class="disk-toggle-row is-detached" data-disk-row="1" data-disk-state="alert" data-search="${esc(p.toLowerCase())}">
            <div class="disk-toggle-left" style="flex:1">
              <input type="checkbox" class="edit-disk-chk" data-source="detached" data-configured="1" data-dir="${esc(p)}" value="${esc(p)}" disabled />
              <div>
                <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap">
                  <strong class="mono">${esc(p)}</strong>
                  <span class="badge detached">⚠ 已拔出 / 未挂载</span>
                  <span class="badge offline">已自动锁定</span>
                </div>
                <div class="muted disk-toggle-sub" style="margin-top:3px">${esc(reason)} · 重插挂载后点右上角「刷新物理盘」再人工勾选启用</div>
              </div>
            </div>
            <div class="disk-toggle-right">
              <button type="button" class="btn sm danger" data-toggle-remove-disk="1">移出磁盘池</button>
            </div>
          </div>
        `;
      });

    wrap.innerHTML = [...missingRows, ...hostRows].join('');
    updateDiskPickerCounter(wrap);
    applyDiskPickerFilters(wrap.id);
    return;
  }

  // Fallback for offline or pre-v1.12.0 nodes that haven't reported host_disks yet.
  const disks = node.disks || [];
  if (!disks.length) {
    wrap.innerHTML = '<div class="empty" style="padding:18px">暂未收到该节点的物理盘扫描列表：请先在目标机执行一键激活脚本上线，然后点击右上角「刷新物理盘」。</div>';
    return;
  }
  wrap.innerHTML = disks.map(d => {
    const isLocked = !!(d.unplug_latched || lockedSet.has(d.path));
    const enabled = !disabledSet.has(d.path) && !isLocked && !d.detached;
    const pct = Number(d.used_pct || 0);
    const barCls = !enabled ? '' : (d.low_space || pct >= watermarkPct ? 'red' : 'green');
    return `
      <div class="disk-toggle-row${d.detached ? ' is-detached' : (isLocked ? ' is-reinsert' : '')}" data-disk-row="1">
        <label class="disk-toggle-left" style="cursor:pointer;flex:1">
          <input type="checkbox" class="edit-disk-chk" data-source="legacy" data-configured="1" data-dir="${esc(d.path)}" value="${esc(d.path)}" ${enabled ? 'checked' : ''} ${d.detached ? 'disabled' : ''} />
          <div>
            <div class="mono"><strong>${esc(d.path)}</strong> ${d.detached ? '<span class="badge detached">⚠ 已拔出</span>' : (isLocked ? '<span class="badge reinsert">🔌 重插待确认</span>' : '')}</div>
            <div class="muted disk-toggle-sub">${esc(d.status_reason || (enabled ? '启用中 · 允许写入' : '已停用 · 不再写入新文件'))}${d.low_space ? ' · 触达安全水位' : ''}</div>
          </div>
        </label>
        <div class="disk-toggle-right">
          <div class="bar-wrap" style="width:150px"><div class="bar-fill ${barCls}" style="width:${Math.min(100, pct).toFixed(1)}%"></div></div>
          <div class="muted">剩余 ${fmtBytes(d.free_bytes)} / ${fmtBytes(d.total_bytes)} (${pct.toFixed(1)}%)</div>
        </div>
      </div>
    `;
  }).join('');
}

function collectDiskSelectionFromPicker(listEl, node) {
  const chks = Array.from(listEl.querySelectorAll('input.edit-disk-chk'));
  if (!chks.length) return { hasChks: false };
  const isLegacyOnly = chks.every(el => el.dataset.source === 'legacy');
  const storageDirs = [];
  const disabledDisks = [];
  let enabledCount = 0;

  for (const el of chks) {
    const row = el.closest('[data-disk-row]');
    if (row && row.dataset.removed === '1') {
      continue;
    }
    const dir = el.value;
    const wasConfigured = el.dataset.configured === '1';
    if (el.checked) {
      storageDirs.push(dir);
      enabledCount++;
    } else if (wasConfigured) {
      // Preserve configured disks in storage_dirs while marking disabled so operator sees live
      // in-flight drain ("可安全拔盘") or detached status until explicitly removed from pool.
      storageDirs.push(dir);
      disabledDisks.push(dir);
    }
  }
  return {
    hasChks: true,
    isLegacyOnly,
    storageDirs,
    disabledDisks,
    enabledCount,
    awaiting: !!(node && node.awaiting_disk),
  };
}

function renderEditDisksList(node, overrideWatermark) {
  const sec = document.getElementById('edit-disks-section');
  const wrap = document.getElementById('edit-disks-list');
  const tip = document.getElementById('edit-storage-pool-tip');
  if (sec) sec.classList.remove('hidden');
  if (tip) {
    const hasInfo = (node.host_disks && node.host_disks.length > 0) || (node.disks && node.disks.length > 0);
    tip.classList.toggle('hidden', !node.online || hasInfo);
  }
  const wm = Number.isFinite(overrideWatermark) ? overrideWatermark : nodeWatermarkPct(node);
  renderHostDiskPicker(wrap, node, wm);
}

function updateNodeDiskModalBanners(node, role) {
  if (role === 'agent_b') {
    const bBanner = document.getElementById('edit-b-awaiting-banner');
    const bSubmit = document.getElementById('edit-b-submit-btn');
    if (bBanner) bBanner.classList.toggle('hidden', !node.awaiting_disk);
    if (bSubmit) {
      bSubmit.textContent = node.awaiting_disk ? '⚡ 确认所选磁盘并立即激活接收节点' : '保存配置并立即下发';
      bSubmit.classList.toggle('activate', !!node.awaiting_disk);
      bSubmit.classList.toggle('primary', !node.awaiting_disk);
    }
  } else {
    const aBanner = document.getElementById('edit-a-awaiting-banner');
    const aSubmit = document.getElementById('edit-a-submit-btn');
    if (aBanner) aBanner.classList.toggle('hidden', !node.awaiting_disk);
    if (aSubmit) {
      aSubmit.textContent = node.awaiting_disk ? '⚡ 确认所选磁盘并立即激活分发节点' : '保存数据盘配置并热生效';
      aSubmit.classList.toggle('activate', !!node.awaiting_disk);
      aSubmit.classList.toggle('primary', !node.awaiting_disk);
    }
  }
}

async function refreshNodeDisksInModal(nodeId, role, btnEl) {
  if (!nodeId) return;
  if (btnEl) {
    btnEl.disabled = true;
    btnEl.classList.add('is-loading');
  }
  try {
    const fresh = await api(`/api/v1/admin/nodes/${encodeURIComponent(nodeId)}/disks`);
    const node = cachedNodes.find(n => n.id === nodeId) || { id: nodeId, role };
    node.online = !!fresh.online;
    node.awaiting_disk = !!fresh.awaiting_disk;
    node.disk_gen = fresh.disk_gen || 0;
    if (fresh.max_disk_usage_pct) node.max_disk_usage_pct = fresh.max_disk_usage_pct;
    node.storage_dirs = fresh.storage_dirs || [];
    node.disabled_disks = fresh.disabled_disks || [];
    node.unplug_locked_disks = fresh.unplug_locked_disks || [];
    node.disks = fresh.disks || [];
    node.host_disks = fresh.host_disks || [];
    if (role === 'agent_b') {
      const inpWm = parseWatermarkInput(document.getElementById('edit-b-watermark-input')?.value);
      renderEditDisksList(node, inpWm ?? nodeWatermarkPct(node));
    } else {
      const inpWm = parseWatermarkInput(document.getElementById('edit-a-watermark-input')?.value);
      renderHostDiskPicker(document.getElementById('edit-a-disks-list'), node, inpWm ?? nodeWatermarkPct(node));
    }
    updateNodeDiskModalBanners(node, role);
    const cnt = (node.host_disks || []).length;
    showToast(
      cnt > 0 ? `已刷新物理盘：共扫描到 ${cnt} 块已挂载磁盘` : '已刷新：节点暂未上报物理盘（请确认节点已在线）',
      cnt > 0 ? 'success' : 'info'
    );
  } catch (e) {
    if (e.message !== 'unauthorized') showToast(`刷新物理盘失败: ${e.message}`, 'error');
  } finally {
    if (btnEl) {
      btnEl.disabled = false;
      btnEl.classList.remove('is-loading');
    }
  }
}

function applyDiskPickerFilters(listId) {
  const listEl = document.getElementById(listId);
  if (!listEl) return;
  const searchEl = document.querySelector(`input[data-disk-filter="${listId}"]`);
  const q = (searchEl?.value || '').trim().toLowerCase();
  const activeChip = document.querySelector(`[data-picker-chips="${listId}"] .disk-chip.active`);
  const state = activeChip?.dataset?.diskState || 'all';
  listEl.querySelectorAll('[data-disk-row]').forEach(row => {
    const hay = (row.dataset.search || row.textContent || '').toLowerCase();
    const matchText = !q || hay.includes(q);
    let matchState = true;
    const chk = row.querySelector('input.edit-disk-chk');
    const rowState = row.dataset.diskState || '';
    if (state === 'checked') matchState = !!(chk && chk.checked);
    else if (state === 'unchecked') matchState = !!(chk && !chk.checked);
    else if (state !== 'all') matchState = rowState === state;
    row.classList.toggle('hidden', !(matchText && matchState));
  });
}

let activeViewDisksNodeId = '';
let activeViewDisksState = 'all';

function renderNodeDisksViewModal(node) {
  if (!node) return;
  const wm = nodeWatermarkPct(node);
  const s = summarizeNodeDisks(node);
  const c = s.counts;
  const isB = node.role === 'agent_b';

  document.getElementById('node-disks-view-title').textContent = `${isB ? '接收节点' : '分发节点'}磁盘池: ${node.name || node.id}`;
  document.getElementById('node-disks-view-sub').textContent = `节点 ${node.id} · ${node.online ? '在线' : '离线'} · 共 ${c.total} 块已配置盘`;

  const sumEl = document.getElementById('node-disks-view-summary');
  const polHtml = isB
    ? `<span class="badge">${esc(diskPolicyLabel(node.disk_policy, node.active_disk_window))}</span>
       ${nodeDiskAffinityEnabled(node) ? '<span class="badge accent">同源亲和</span>' : '<span class="badge standby">无亲和</span>'}`
    : '';
  sumEl.innerHTML = `
    <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center">
      ${polHtml}
      <span class="badge">强制水位 ≤${wm}%</span>
      <span class="badge online">写入 ${c.active}</span>
      ${c.standby > 0 ? `<span class="badge standby">候补 ${c.standby}</span>` : ''}
      ${c.full > 0 ? `<span class="badge full-disk">已满 ${c.full}</span>` : ''}
      ${c.safeEject > 0 ? `<span class="badge safe-eject">✓ 可拔盘 ${c.safeEject}</span>` : ''}
      ${c.detached > 0 ? `<span class="badge detached">⚠ 拔出 ${c.detached}</span>` : ''}
      ${c.locked > 0 ? `<span class="badge reinsert">🔌 重插 ${c.locked}</span>` : ''}
    </div>
    <div style="min-width:210px">
      <div class="bar-wrap"><div class="bar-fill ${s.usedPct >= wm ? 'red' : 'green'}" style="width:${Math.min(100, s.usedPct).toFixed(1)}%"></div></div>
      <div class="muted" style="margin-top:3px">总剩 ${fmtBytes(s.freeBytes)} / 共 ${fmtBytes(s.totalBytes)} (${s.usedPct.toFixed(1)}% 已用)</div>
    </div>
  `;

  const q = (document.getElementById('node-disks-view-search')?.value || '').trim().toLowerCase();
  const grid = document.getElementById('node-disks-view-grid');
  const disks = node.disks || [];
  const filtered = disks.filter(d => {
    const st = classifyDiskState(d, s.disabledSet, s.lockedSet);
    let stateOk = true;
    if (activeViewDisksState === 'active') stateOk = st === 'active';
    else if (activeViewDisksState === 'standby') stateOk = st === 'standby';
    else if (activeViewDisksState === 'full') stateOk = st === 'full';
    else if (activeViewDisksState === 'disabled') stateOk = st === 'disabled' || st === 'safe_eject';
    else if (activeViewDisksState === 'alert') stateOk = st === 'detached' || st === 'locked';
    if (!stateOk) return false;
    if (!q) return true;
    const hay = `${d.path || ''} ${d.status_reason || ''}`.toLowerCase();
    return hay.includes(q);
  });

  const counter = document.getElementById('node-disks-view-counter');
  if (counter) counter.textContent = `显示 ${filtered.length} / ${disks.length} 块盘`;

  if (!filtered.length) {
    grid.innerHTML = `<div class="empty" style="grid-column:1/-1;padding:24px">${disks.length ? '当前筛选条件下没有匹配的磁盘' : '该节点尚未激活或上报磁盘状态，请点右上角「勾选 / 管理数据盘」'}</div>`;
    return;
  }
  grid.innerHTML = filtered.map(d => renderDiskMiniItem(d, s.disabledSet, s.lockedSet, wm)).join('');
}

async function openNodeDisksViewModal(nodeId) {
  const node = cachedNodes.find(n => n.id === nodeId);
  if (!node) return;
  activeViewDisksNodeId = nodeId;
  activeViewDisksState = 'all';
  const searchEl = document.getElementById('node-disks-view-search');
  if (searchEl) searchEl.value = '';
  document.querySelectorAll('#node-disks-view-chips .disk-chip').forEach(b => {
    b.classList.toggle('active', b.dataset.viewState === 'all');
  });
  renderNodeDisksViewModal(node);
  openModal('node-disks-view-modal');
  if (node.online) {
    try {
      const fresh = await api(`/api/v1/admin/nodes/${encodeURIComponent(nodeId)}/disks`);
      node.online = !!fresh.online;
      node.awaiting_disk = !!fresh.awaiting_disk;
      if (fresh.max_disk_usage_pct) node.max_disk_usage_pct = fresh.max_disk_usage_pct;
      if (fresh.disk_policy) node.disk_policy = fresh.disk_policy;
      if (fresh.disk_affinity !== undefined) node.disk_affinity = fresh.disk_affinity;
      if (fresh.active_disk_window) node.active_disk_window = fresh.active_disk_window;
      node.disks = fresh.disks || [];
      node.host_disks = fresh.host_disks || [];
      node.disabled_disks = fresh.disabled_disks || [];
      node.unplug_locked_disks = fresh.unplug_locked_disks || [];
      if (activeViewDisksNodeId === nodeId) renderNodeDisksViewModal(node);
    } catch {}
  }
}

function openEditADisksModal(nodeId) {
  const node = cachedNodes.find(n => n.id === nodeId);
  if (!node) return;
  const form = document.getElementById('edit-a-disks-form');
  if (!form) return;
  form.reset();
  form.elements.node_id.value = node.id;
  const wm = nodeWatermarkPct(node);
  if (form.elements.max_disk_usage_pct) {
    form.elements.max_disk_usage_pct.value = wm;
  }
  document.getElementById('edit-a-disks-title').textContent = node.awaiting_disk
    ? `⚡ 选择分发节点数据盘并激活: ${node.name || node.id}`
    : `选择分发节点数据盘: ${node.name || node.id}`;
  renderHostDiskPicker(document.getElementById('edit-a-disks-list'), node, wm);
  updateNodeDiskModalBanners(node, 'agent_a');
  openModal('edit-a-disks-modal');
  if (node.online) {
    refreshNodeDisksInModal(node.id, 'agent_a', document.getElementById('btn-refresh-a-disks'));
  }
}

function openEditNodeProjectsModal(nodeId) {
  const node = cachedNodes.find(n => n.id === nodeId);
  if (!node) return;
  const form = document.getElementById('edit-node-form');
  form.reset();
  form.elements.node_id.value = node.id;
  form.elements.name.value = node.name || node.id;
  if (!isCustomer()) {
    populateOwnerAccountSelect(document.getElementById('edit-node-owner-select'), node.owner_account_id || '');
  }
  form.elements.project_schedule.value = node.project_schedule || 'fifo';
  form.elements.disk_policy.value = normalizeUiDiskPolicy(node.disk_policy);
  if (form.elements.disk_affinity) {
    form.elements.disk_affinity.checked = nodeDiskAffinityEnabled(node);
  }
  if (form.elements.active_disk_window) {
    form.elements.active_disk_window.value = node.active_disk_window || 10;
  }
  if (form.elements.max_disk_usage_pct) {
    form.elements.max_disk_usage_pct.value = nodeWatermarkPct(node);
  }
  syncDiskPolicyWindowUI('edit-disk-policy-select', 'edit-disk-window-wrap');
  const bSearch = document.getElementById('edit-b-disk-search');
  if (bSearch) bSearch.value = '';
  document.querySelectorAll('[data-picker-chips="edit-disks-list"] .disk-chip').forEach(b => {
    b.classList.toggle('active', b.dataset.diskState === 'all');
  });
  form.elements.concurrency_mode.value = node.concurrency_mode || 'auto';
  form.elements.max_concurrent_override.value = node.max_concurrent_override || 0;
  form.elements.rate_limit_mbps.value = node.rate_limit_mbps || 0;
  const liveBanner = document.getElementById('edit-adaptive-live-banner');
  if (liveBanner) {
    if (node.online && node.effective_concurrent > 0) {
      liveBanner.textContent = `当前实时调度：并发 ${node.effective_concurrent} / ${node.max_concurrent_cap || node.effective_concurrent} · 并发流上限 ${node.effective_streams || '-'} · 状态：${node.adaptive_reason || node.adaptive_state || '运行中'}`;
      liveBanner.classList.remove('hidden');
    } else {
      liveBanner.classList.add('hidden');
    }
  }
  document.getElementById('edit-node-title').textContent = node.awaiting_disk
    ? `⚡ 选择接收节点数据盘并激活: ${node.name || node.id}`
    : `配置接收节点: ${node.name || node.id}`;

  const projs = node.projects || [];
  const defaultSingle = projs.length === 1 ? projs[0] : (cachedProjects[0]?.project?.id || '');
  const scopedCust = isScopedCustomer();
  const editAllOpt = document.getElementById('edit-node-mode-all-opt');
  if (editAllOpt) editAllOpt.classList.toggle('hidden', scopedCust);
  populateProjectSelect(document.getElementById('edit-single-project-select'), defaultSingle, !scopedCust);

  if (projs.length === 1) {
    form.elements.edit_project_mode.value = 'single';
  } else if (projs.length > 1 || scopedCust) {
    form.elements.edit_project_mode.value = 'multi';
  } else {
    form.elements.edit_project_mode.value = 'all';
  }
  form.elements.projects.value = projs.join(',');
  const projSearch = document.getElementById('edit-project-search');
  if (projSearch) projSearch.value = '';
  renderEditProjectChecks(projs);
  renderEditDisksList(node);
  updateNodeDiskModalBanners(node, 'agent_b');
  syncEditNodeProjectMode();
  openModal('edit-node-modal');
  if (node.online) {
    refreshNodeDisksInModal(node.id, 'agent_b', document.getElementById('btn-refresh-b-disks'));
  }
}

function syncBScriptMode() {
  const form = document.getElementById('b-script-form');
  if (!form) return;
  const mode = form.elements.script_mode.value || 'await';
  const isManual = mode === 'manual';
  document.getElementById('b-script-await-wrap')?.classList.toggle('hidden', isManual);
  document.getElementById('b-script-manual-wrap')?.classList.toggle('hidden', !isManual);
  if (isManual) {
    const sub = form.elements.manual_submode?.value || 'pool';
    document.getElementById('b-script-pool-wrap')?.classList.toggle('hidden', sub !== 'pool');
    document.getElementById('b-script-single-wrap')?.classList.toggle('hidden', sub !== 'single');
    document.getElementById('b-script-multi-wrap')?.classList.toggle('hidden', sub !== 'multi');
  }
}

function openBScriptModal(nodeId, presetToken = '') {
  const node = cachedNodes.find(n => n.id === nodeId);
  const form = document.getElementById('b-script-form');
  form.reset();
  form.elements.node_id.value = nodeId;
  form.elements.node_token.value = presetToken;
  if (!presetToken && node && !node.online) {
    form.elements.rotate_token.checked = true;
  }
  const isReinstall = !!(node && (node.online || node.last_seen_at));
  document.getElementById('b-script-title').textContent = isReinstall
    ? `内网接收节点重装 / 迁移脚本: ${node.name || nodeId}`
    : `内网接收节点一键安装脚本: ${(node && node.name) || nodeId}`;
  document.getElementById('b-script-running-warn')?.classList.toggle('hidden', !(node && node.online));
  const advDet = document.getElementById('b-script-adv-details');
  if (advDet) advDet.open = false;
  document.getElementById('b-script-output').classList.add('hidden');
  document.getElementById('b-script-steps-tip').classList.add('hidden');
  document.getElementById('btn-copy-b-exec').classList.add('hidden');
  document.getElementById('btn-copy-b-script').classList.add('hidden');
  document.getElementById('btn-download-b-script').classList.add('hidden');
  populateReleaseSelect(document.getElementById('b-script-release-select'), 'agent_b', '自动匹配最新接收节点发布包');

  const nodeProjs = (node && node.projects) || [];
  const defaultProj = nodeProjs.length === 1 ? nodeProjs[0] : (cachedProjects[0]?.project?.id || '');
  populateProjectSelect(document.getElementById('b-script-single-project'), defaultProj, false);
  form.elements.script_mode.value = 'await';
  if (form.elements.manual_submode) form.elements.manual_submode.value = 'pool';
  form.elements.storage_dirs.value = (node && node.storage_dirs && node.storage_dirs.length)
    ? node.storage_dirs.join('\n')
    : '/mnt/sda/relay-delivery\n/mnt/sdb/relay-delivery';
  if (defaultProj) {
    form.elements.single_dest_dirs.value = `/data/relay-delivery/${defaultProj}`;
  }
  syncBScriptMode();
  openModal('b-script-modal');
}

function openAScriptModal(nodeId, presetToken = '') {
  const node = cachedNodes.find(n => n.id === nodeId);
  const form = document.getElementById('a-script-form');
  if (!form) return;
  form.reset();
  form.elements.node_id.value = nodeId;
  form.elements.node_token.value = presetToken;
  form.elements.public_addr.value = (node && node.public_addr) || '';
  form.elements.rotate_token.checked = !presetToken && !(node && node.online);
  form.elements.await_disk_selection.checked = true;
  document.getElementById('a-script-datadir-wrap')?.classList.add('hidden');
  const isReinstall = !!(node && (node.online || node.last_seen_at));
  document.getElementById('a-script-title').textContent = isReinstall
    ? `分发节点重装 / 迁移脚本: ${node.name || nodeId}`
    : `分发节点一键安装脚本: ${(node && node.name) || nodeId}`;
  document.getElementById('a-script-running-warn')?.classList.toggle('hidden', !(node && node.online));
  const advDet = document.getElementById('a-script-adv-details');
  if (advDet) advDet.open = false;
  document.getElementById('a-script-output').classList.add('hidden');
  document.getElementById('a-script-token-box').classList.add('hidden');
  document.getElementById('btn-copy-a-exec').classList.add('hidden');
  document.getElementById('btn-copy-a-script').classList.add('hidden');
  document.getElementById('btn-download-a-script').classList.add('hidden');
  populateReleaseSelect(document.getElementById('a-script-release-select'), 'agent_a', '自动匹配最新分发节点发布包');
  openModal('a-script-modal');
}

function setupEvents() {
  const winSel = document.getElementById('window-select');
  try {
    const savedWin = localStorage.getItem(WINDOW_STORAGE_KEY);
    if (savedWin && Array.from(winSel.options).some(o => o.value === savedWin)) {
      winSel.value = savedWin;
    }
  } catch {
    // Ignore storage errors.
  }

  winSel.addEventListener('change', () => {
    try { localStorage.setItem(WINDOW_STORAGE_KEY, winSel.value); } catch {}
    refreshAll();
  });

  document.getElementById('curve-project-filter').addEventListener('change', (e) => {
    selectedProjectFilter = e.target.value || '';
    refreshCurveOnly();
  });

  document.addEventListener('click', (e) => {
    const closeBtn = e.target.closest('button[data-close-modal]');
    if (closeBtn) {
      closeModal(closeBtn.dataset.closeModal);
      return;
    }
    const guideToggle = e.target.closest('[data-toggle-guide]');
    if (guideToggle) {
      const targetId = guideToggle.dataset.toggleGuide;
      const bodyEl = document.getElementById(targetId);
      const cardEl = guideToggle.closest('.guide-card');
      const btnEl = cardEl ? cardEl.querySelector(`button[data-toggle-guide="${targetId}"]`) : guideToggle;
      if (bodyEl) {
        const nowHidden = bodyEl.classList.toggle('hidden');
        if (btnEl) btnEl.textContent = nowHidden ? '展开指南' : '收起指南';
      }
      return;
    }
    const guidePBtn = e.target.closest('button[data-guide-p-mode]');
    if (guidePBtn) {
      const mode = guidePBtn.dataset.guidePMode;
      document.querySelectorAll('button[data-guide-p-mode]').forEach(b => {
        b.classList.toggle('active', b.dataset.guidePMode === mode);
      });
      ['http', 'register', 'python', 'status'].forEach(k => {
        document.getElementById(`guide-p-pane-${k}`)?.classList.toggle('hidden', k !== mode);
      });
      return;
    }
    const copyElBtn = e.target.closest('button[data-copy-el]');
    if (copyElBtn) {
      const srcEl = document.getElementById(copyElBtn.dataset.copyEl);
      if (srcEl) copyText(srcEl.textContent || '', '接入代码已复制到剪贴板');
      return;
    }
    const guideModeBtn = e.target.closest('button[data-guide-a-mode]');
    if (guideModeBtn) {
      const mode = guideModeBtn.dataset.guideAMode;
      document.querySelectorAll('button[data-guide-a-mode]').forEach(b => {
        b.classList.toggle('active', b.dataset.guideAMode === mode);
      });
      document.getElementById('guide-a-steps-ssh')?.classList.toggle('hidden', mode !== 'ssh');
      document.getElementById('guide-a-steps-manual')?.classList.toggle('hidden', mode !== 'manual');
      return;
    }
    const copyBtn = e.target.closest('button[data-copy-text]');
    if (copyBtn) {
      const msg = copyBtn.classList.contains('proj-short-id') || copyBtn.textContent?.includes('ID')
        ? '项目 ID 已复制到剪贴板'
        : '命令已复制到剪贴板';
      copyText(copyBtn.dataset.copyText, msg);
      return;
    }
    const swTabBtn = e.target.closest('button[data-switch-tab]');
    if (swTabBtn) {
      const targetTab = document.querySelector(`.tab[data-tab="${swTabBtn.dataset.switchTab}"]`);
      if (targetTab) targetTab.click();
      return;
    }
    const trigBtn = e.target.closest('button[data-trigger-click]');
    if (trigBtn) {
      document.getElementById(trigBtn.dataset.triggerClick)?.click();
      return;
    }
    const genIdBtn = e.target.closest('button[data-gen-id]');
    if (genIdBtn) {
      let pfx = genIdBtn.dataset.genId || 'id';
      if (pfx === 'node') {
        const roleVal = document.querySelector('#create-node-form input[name="role"]')?.value;
        pfx = roleVal === 'agent_a' ? 'edge' : 'nas';
      }
      const target = genIdBtn.dataset.genTarget ? document.querySelector(genIdBtn.dataset.genTarget) : null;
      if (target && !target.readOnly) {
        target.value = generateShortId(pfx);
        target.dispatchEvent(new Event('input', { bubbles: true }));
      }
      return;
    }
    const selAllBtn = e.target.closest('button[data-disk-select-all]');
    if (selAllBtn) {
      const listEl = document.getElementById(selAllBtn.dataset.diskSelectAll);
      if (listEl) {
        listEl.querySelectorAll('input.edit-disk-chk[data-source="host"]').forEach(chk => {
          if (chk.disabled) return;
          if (chk.dataset.isSystem !== '1' && chk.dataset.writable !== '0') {
            chk.checked = true;
            chk.dispatchEvent(new Event('change', { bubbles: true }));
          }
        });
        updateDiskPickerCounter(listEl);
      }
      return;
    }
    const clearAllBtn = e.target.closest('button[data-disk-clear-all]');
    if (clearAllBtn) {
      const listEl = document.getElementById(clearAllBtn.dataset.diskClearAll);
      if (listEl) {
        listEl.querySelectorAll('input.edit-disk-chk').forEach(chk => {
          if (chk.disabled) return;
          chk.checked = false;
          chk.dispatchEvent(new Event('change', { bubbles: true }));
        });
        updateDiskPickerCounter(listEl);
      }
      return;
    }
    const toggleGrp = e.target.closest('[data-toggle-proj-group]');
    if (toggleGrp) {
      const k = toggleGrp.dataset.toggleProjGroup;
      if (k) {
        projectViewState.userToggledGroups.add(k);
        if (projectViewState.collapsedGroups.has(k)) projectViewState.collapsedGroups.delete(k);
        else projectViewState.collapsedGroups.add(k);
        renderProjects(cachedProjects, lastProjectsWinHours);
      }
      return;
    }
    const projFilterBtn = e.target.closest('#projects-status-chips button[data-proj-filter]');
    if (projFilterBtn) {
      projectViewState.filter = projFilterBtn.dataset.projFilter || 'all';
      renderProjects(cachedProjects, lastProjectsWinHours);
      return;
    }
    const btn = e.target.closest('button[data-action]');
    if (btn) {
      const id = btn.dataset.id || '';
      switch (btn.dataset.action) {
        case 'view-project-detail': openProjectDetailModal(id); break;
        case 'jump-project-curve': jumpToProjectCurve(id); break;
        case 'assign-project-accounts': openAssignProjectModal(id); break;
        case 'quick-integrate-project': openProjectQuickGuide(id); break;
        case 'edit-project': openProjectModal(id); break;
        case 'delete-project': deleteProject(id); break;
        case 'toggle-pause-node': togglePauseNode(id, btn.dataset.paused === '1'); break;
        case 'delete-node': deleteNode(id); break;
        case 'delete-release': deleteRelease(id); break;
        case 'view-deploy-task': viewDeployTaskLog(id); break;
        case 'open-a-script': openAScriptModal(id); break;
        case 'open-b-script': openBScriptModal(id); break;
        case 'edit-a-disks': openEditADisksModal(id); break;
        case 'edit-node-projects': openEditNodeProjectsModal(id); break;
        case 'view-node-disks': openNodeDisksViewModal(id); break;
        case 'edit-account': openAccountModal(id); break;
        case 'rotate-account': rotateAccountToken(id); break;
        case 'delete-account': deleteAccount(id); break;
      }
      return;
    }
    const projRow = e.target.closest('tr[data-open-project-detail]');
    if (projRow && !e.target.closest('button, a, input, select')) {
      openProjectDetailModal(projRow.dataset.openProjectDetail);
      return;
    }
  });

  // Compact Projects Toolbar controls & HTTP Guide modal trigger
  document.getElementById('open-project-guide-btn')?.addEventListener('click', () => {
    openProjectQuickGuide('');
  });
  document.getElementById('projects-search')?.addEventListener('input', (e) => {
    projectViewState.search = e.target.value || '';
    renderProjects(cachedProjects, lastProjectsWinHours);
  });
  document.getElementById('projects-group-by')?.addEventListener('change', (e) => {
    projectViewState.groupBy = e.target.value || 'status';
    renderProjects(cachedProjects, lastProjectsWinHours);
  });
  document.getElementById('projects-sort-by')?.addEventListener('change', (e) => {
    projectViewState.sortBy = e.target.value || 'activity';
    renderProjects(cachedProjects, lastProjectsWinHours);
  });
  document.addEventListener('input', (e) => {
    const inp = e.target.closest('input[data-proj-picker-filter]');
    if (!inp) return;
    const targetId = inp.dataset.projPickerFilter;
    const grid = document.getElementById(targetId);
    if (!grid) return;
    const kw = (inp.value || '').trim().toLowerCase();
    grid.querySelectorAll('.proj-check-card').forEach(card => {
      const txt = `${card.textContent || ''} ${card.title || ''}`.toLowerCase();
      card.classList.toggle('hidden', kw !== '' && !txt.includes(kw));
    });
  });

  // Dynamic center healthz probe command in receiver onboarding guide
  const checkCmd = `curl -kI ${window.location.origin}/healthz`;
  const checkCmdEl = document.getElementById('guide-b-check-cmd');
  if (checkCmdEl) checkCmdEl.textContent = checkCmd;
  document.getElementById('btn-copy-b-check-cmd')?.addEventListener('click', () => {
    copyText(checkCmd, '连通性探测命令已复制到剪贴板');
  });

  // Project HTTP quick integration live snippet inputs
  document.getElementById('guide-p-project-select')?.addEventListener('change', (e) => {
    const inp = document.getElementById('guide-p-project-input');
    if (inp && e.target.value && e.target.value !== '__custom__') {
      inp.value = e.target.value;
      inp.dataset.userEdited = '1';
    }
    renderProjectGuideSnippets();
  });
  document.getElementById('guide-p-project-input')?.addEventListener('input', (e) => {
    e.target.dataset.userEdited = '1';
    renderProjectGuideSnippets();
  });
  document.getElementById('guide-p-port')?.addEventListener('input', renderProjectGuideSnippets);
  document.getElementById('guide-p-customer-select')?.addEventListener('change', renderProjectGuideSnippets);
  renderProjectGuideSnippets();

  document.addEventListener('change', (e) => {
    const chk = e.target.closest('input.node-chk');
    if (chk) {
      const role = chk.dataset.role;
      const id = chk.dataset.id;
      if (chk.checked) selectedNodes[role].add(id);
      else selectedNodes[role].delete(id);
    }
  });

  const bindSelectAll = (chkId, role) => {
    document.getElementById(chkId).addEventListener('change', (e) => {
      document.querySelectorAll(`input.node-chk[data-role="${role}"]`).forEach(el => {
        el.checked = e.target.checked;
        if (e.target.checked) selectedNodes[role].add(el.dataset.id);
        else selectedNodes[role].delete(el.dataset.id);
      });
    });
  };
  bindSelectAll('chk-all-a', 'agent_a');
  bindSelectAll('chk-all-b', 'agent_b');

  document.getElementById('btn-batch-upgrade-a').addEventListener('click', () => runBatchUpgrade('agent_a'));
  document.getElementById('btn-batch-upgrade-b').addEventListener('click', () => runBatchUpgrade('agent_b'));

  document.querySelectorAll('.tab').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById(`tab-${btn.dataset.tab}`).classList.add('active');
    });
  });

  const doLogin = async (e) => {
    if (e) e.preventDefault();
    const v = document.getElementById('login-token').value.trim();
    if (!v) return;
    adminToken = v;
    try {
      await api('/api/v1/admin/overview?hours=24&bucket_min=30');
      saveStoredToken(v);
      hideLogin();
      updateAuthControls();
      refreshAll();
    } catch {
      saveStoredToken('');
    }
  };
  document.getElementById('login-form').addEventListener('submit', doLogin);

  document.getElementById('logout-btn').addEventListener('click', () => {
    saveStoredToken('');
    authRole = 'admin';
    authAccountID = '';
    authAccountName = '';
    authProjects = [];
    document.getElementById('login-token').value = '';
    applyRoleUI();
    refreshAll();
  });

  document.getElementById('refresh-now').addEventListener('click', refreshAll);

  document.getElementById('btn-refresh-log-modal').addEventListener('click', () => {
    if (activeLogModalTaskId) viewDeployTaskLog(activeLogModalTaskId);
  });

  document.getElementById('btn-refresh-deploy-status').addEventListener('click', () => {
    if (activeDeployTaskId) fetchDeployStatus(activeDeployTaskId);
  });

  const openProjectModal = (projectId = '') => {
    const form = document.getElementById('create-project-form');
    form.reset();
    const existing = projectId ? cachedProjects.find(ps => ps.project.id === projectId)?.project : null;
    document.getElementById('project-modal-title').textContent = existing ? `编辑项目策略: ${existing.name || existing.id}` : '新建项目';
    form.elements.id.readOnly = !!existing;
    document.getElementById('btn-gen-project-id')?.classList.toggle('hidden', !!existing);
    if (existing) {
      form.elements.id.value = existing.id;
      form.elements.name.value = existing.name || existing.id;
      form.elements.description.value = existing.description || '';
      form.elements.conflict_policy.value = existing.conflict_policy || 'overwrite';
      form.elements.lease_ttl_sec.value = existing.lease_ttl_sec || 300;
      form.elements.group_affinity.checked = existing.group_affinity !== false;
      form.elements.max_total_concurrent.value = existing.max_total_concurrent || 0;
      form.elements.max_total_rate_mbps.value = existing.max_total_rate_mbps || 0;
    } else {
      form.elements.group_affinity.checked = true;
      form.elements.max_total_concurrent.value = 0;
      form.elements.max_total_rate_mbps.value = 0;
    }
    openModal('project-modal');
  };

  document.getElementById('open-create-project').addEventListener('click', () => openProjectModal(''));

  // Backdrop click & Escape key to close any open modal (except login overlay).
  document.querySelectorAll('.overlay').forEach(ov => {
    if (ov.id === 'login-overlay') return;
    ov.addEventListener('click', (e) => {
      if (e.target === ov) ov.classList.add('hidden');
    });
  });
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    document.querySelectorAll('.overlay:not(.hidden)').forEach(ov => {
      if (ov.id !== 'login-overlay') ov.classList.add('hidden');
    });
  });

  const bindDiskPickerEvents = (listId) => {
    const el = document.getElementById(listId);
    if (!el) return;
    el.addEventListener('change', (e) => {
      const chk = e.target.closest('input.edit-disk-chk');
      if (!chk) return;
      const row = chk.closest('.disk-toggle-row');
      const sub = row && row.querySelector('.disk-toggle-sub');
      const dir = chk.dataset.dir || chk.value || '';
      if (sub) {
        const msg = chk.checked
          ? '已勾选启用 · 保存后立即生效（重插锁定将同步解除）'
          : (chk.dataset.configured === '1'
            ? '保存后停用写入 · 等待在途写入归零即可安全卸载拔盘'
            : '未启用 · 不会写入该磁盘');
        sub.innerHTML = `目录: <span class="mono">${esc(dir)}</span> · ${esc(msg)}`;
      }
      updateDiskPickerCounter(el);
    });
    el.addEventListener('click', (e) => {
      const btn = e.target.closest('button[data-toggle-remove-disk]');
      if (!btn) return;
      const row = btn.closest('[data-disk-row]');
      if (!row) return;
      const nowRemoved = row.dataset.removed !== '1';
      row.dataset.removed = nowRemoved ? '1' : '0';
      row.classList.toggle('is-removed', nowRemoved);
      btn.textContent = nowRemoved ? '撤销移出' : '移出磁盘池';
      updateDiskPickerCounter(el);
    });
  };
  bindDiskPickerEvents('edit-disks-list');
  bindDiskPickerEvents('edit-a-disks-list');

  document.querySelectorAll('input[data-disk-filter]').forEach(inp => {
    inp.addEventListener('input', () => applyDiskPickerFilters(inp.dataset.diskFilter));
  });
  document.querySelectorAll('[data-picker-chips]').forEach(bar => {
    bar.addEventListener('click', (e) => {
      const chip = e.target.closest('button.disk-chip');
      if (!chip) return;
      bar.querySelectorAll('.disk-chip').forEach(b => b.classList.toggle('active', b === chip));
      applyDiskPickerFilters(bar.dataset.pickerChips);
    });
  });

  // Scrollable All-Disks Overview Modal controls
  document.getElementById('node-disks-view-search')?.addEventListener('input', () => {
    const node = cachedNodes.find(n => n.id === activeViewDisksNodeId);
    if (node) renderNodeDisksViewModal(node);
  });
  document.getElementById('node-disks-view-chips')?.addEventListener('click', (e) => {
    const chip = e.target.closest('button.disk-chip');
    if (!chip) return;
    activeViewDisksState = chip.dataset.viewState || 'all';
    document.querySelectorAll('#node-disks-view-chips .disk-chip').forEach(b => b.classList.toggle('active', b === chip));
    const node = cachedNodes.find(n => n.id === activeViewDisksNodeId);
    if (node) renderNodeDisksViewModal(node);
  });
  document.getElementById('btn-refresh-view-disks')?.addEventListener('click', () => {
    if (activeViewDisksNodeId) openNodeDisksViewModal(activeViewDisksNodeId);
  });
  document.getElementById('btn-manage-from-view-disks')?.addEventListener('click', () => {
    const node = cachedNodes.find(n => n.id === activeViewDisksNodeId);
    if (!node) return;
    closeModal('node-disks-view-modal');
    if (node.role === 'agent_b') openEditNodeProjectsModal(node.id);
    else openEditADisksModal(node.id);
  });

  document.getElementById('create-disk-policy-select')?.addEventListener('change', () => {
    syncDiskPolicyWindowUI('create-disk-policy-select', 'create-disk-window-wrap');
  });
  document.getElementById('edit-disk-policy-select')?.addEventListener('change', () => {
    syncDiskPolicyWindowUI('edit-disk-policy-select', 'edit-disk-window-wrap');
  });
  document.getElementById('edit-b-watermark-input')?.addEventListener('input', (e) => {
    const v = parseWatermarkInput(e.target.value);
    if (v !== null) updateDiskPickerWatermarkPreview(document.getElementById('edit-disks-list'), v);
  });
  document.getElementById('edit-a-watermark-input')?.addEventListener('input', (e) => {
    const v = parseWatermarkInput(e.target.value);
    if (v !== null) updateDiskPickerWatermarkPreview(document.getElementById('edit-a-disks-list'), v);
  });

  document.getElementById('create-project-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      await api('/api/v1/admin/projects', {
        method: 'POST',
        body: JSON.stringify({
          id: fd.get('id'),
          name: fd.get('name'),
          description: fd.get('description'),
          conflict_policy: fd.get('conflict_policy'),
          lease_ttl_sec: Number(fd.get('lease_ttl_sec') || 300),
          group_affinity: fd.get('group_affinity') === 'on',
          max_total_concurrent: Number(fd.get('max_total_concurrent') || 0),
          max_total_rate_mbps: Number(fd.get('max_total_rate_mbps') || 0),
        }),
      });
      closeModal('project-modal');
      showToast(`项目 ${fd.get('id')} 策略已保存`, 'success');
      refreshAll();
    } catch (err) {
      if (err.message !== 'unauthorized') showToast(`保存项目失败: ${err.message}`, 'error');
    }
  });

  // Create node modal
  const openNodeModal = (role) => {
    const form = document.getElementById('create-node-form');
    form.reset();
    form.elements.role.value = role;
    document.getElementById('node-modal-title').textContent = role === 'agent_a' ? '手动注册分发节点' : '注册内网接收节点';
    const expEl = document.getElementById('node-modal-explainer');
    if (expEl) {
      expEl.innerHTML = role === 'agent_a'
        ? '<strong>什么是分发节点？</strong> 负责接收上游文件并对外高速直传的中转机。注册后点「生成一键安装脚本」即可全自动安装并签发证书（若无公网 IP，公网地址请填 NAT/FRP 映射后的 <code>https://IP或域名:端口</code>）。'
        : '<strong>什么是接收节点？</strong> 你本地机房/NAS 上用来落盘存文件的 Linux 机器（<strong>无需公网 IP</strong>）。这里先登记节点编号并生成密钥，创建后直接点「生成一键安装脚本」放到目标机执行即可自动上线。';
    }
    document.getElementById('node-public-addr-wrap').classList.toggle('hidden', role !== 'agent_a');
    document.getElementById('create-node-owner-wrap')?.classList.toggle('hidden', role !== 'agent_b' || isCustomer());
    if (role === 'agent_b' && !isCustomer()) {
      populateOwnerAccountSelect(document.getElementById('create-node-owner-select'), '');
    }
    syncDiskPolicyWindowUI('create-disk-policy-select', 'create-disk-window-wrap');
    document.getElementById('node-token-result').classList.add('hidden');
    const scopedCust = isScopedCustomer();
    const createAllOpt = document.getElementById('create-node-mode-all-opt');
    if (createAllOpt) createAllOpt.classList.toggle('hidden', scopedCust);
    populateProjectSelect(document.getElementById('node-single-project-select'), cachedProjects[0]?.project?.id || '', !scopedCust);
    form.elements.project_mode.value = 'single';
    syncCreateNodeProjectMode();
    openModal('node-modal');
  };
  document.getElementById('open-create-node-a').addEventListener('click', () => openNodeModal('agent_a'));
  document.getElementById('open-create-node-b').addEventListener('click', () => openNodeModal('agent_b'));

  document.querySelectorAll('input[name="project_mode"]').forEach(el => {
    el.addEventListener('change', syncCreateNodeProjectMode);
  });
  document.getElementById('node-single-project-select').addEventListener('change', syncCreateNodeProjectMode);

  document.querySelectorAll('input[name="edit_project_mode"]').forEach(el => {
    el.addEventListener('change', syncEditNodeProjectMode);
  });
  document.getElementById('edit-single-project-select').addEventListener('change', syncEditNodeProjectMode);

  document.querySelectorAll('input[name="script_mode"]').forEach(el => {
    el.addEventListener('change', syncBScriptMode);
  });

  document.getElementById('edit-project-checks').addEventListener('change', (e) => {
    const chk = e.target.closest('input.edit-proj-chk');
    if (!chk) return;
    const form = document.getElementById('edit-node-form');
    const cur = String(form.elements.projects.value || '').split(',').map(s => s.trim()).filter(Boolean);
    const val = chk.value;
    let next = cur.filter(x => x !== val);
    if (chk.checked) next.push(val);
    form.elements.projects.value = next.join(',');
  });

  document.getElementById('create-node-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const role = fd.get('role');
    let projs = [];
    if (role === 'agent_b') {
      const pmode = String(fd.get('project_mode') || 'single');
      if (pmode === 'single') {
        let chosen = String(fd.get('single_project') || '').trim();
        if (chosen === '__custom__') {
          chosen = String(fd.get('single_project_custom') || '').trim();
        }
        if (!chosen) {
          showToast('请选择或输入该接收节点要专享下载的项目 ID', 'error');
          return;
        }
        projs = [chosen];
      } else if (pmode === 'all') {
        projs = [];
      } else {
        projs = String(fd.get('projects') || '').split(',').map(s => s.trim()).filter(Boolean);
      }
    } else {
      projs = String(fd.get('projects') || '').split(',').map(s => s.trim()).filter(Boolean);
    }

    const maxDiskPct = parseWatermarkInput(fd.get('max_disk_usage_pct') || 85);
    if (maxDiskPct === null) {
      showToast('强制安全水位必须在 1% ~ 99% 之间', 'error');
      return;
    }

    try {
      const payload = {
        id: fd.get('id'),
        name: fd.get('name'),
        role,
        public_addr: fd.get('public_addr'),
        projects: projs,
        max_disk_usage_pct: maxDiskPct,
      };
      if (role === 'agent_b') {
        payload.project_schedule = String(fd.get('project_schedule') || 'fifo');
        payload.disk_policy = String(fd.get('disk_policy') || 'round_robin');
        payload.disk_affinity = fd.get('disk_affinity') === 'on';
        payload.active_disk_window = Number(fd.get('active_disk_window') || 10);
        if (!isCustomer()) {
          payload.owner_account_id = String(fd.get('owner_account_id') || '').trim();
        }
      }
      const res = await api('/api/v1/admin/nodes', {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      const box = document.getElementById('node-token-result');
      const genBtnId = role === 'agent_b' ? 'btn-gen-b-after-create' : 'btn-gen-a-after-create';
      const extraBtn = `<div class="btn-row" style="margin-top:8px"><button type="button" class="btn sm primary" id="${genBtnId}">下一步：生成一键安装脚本</button><button type="button" class="btn sm" data-copy-text="${esc(res.token)}">复制 Token</button></div>`;
      box.innerHTML = `<strong>节点已创建！请妥善保存接入 Token（仅展示一次）：</strong><div class="mono" style="margin-top:6px">${esc(res.token)}</div>${extraBtn}`;
      box.classList.remove('hidden');
      showToast(`节点 ${res.node.id} 创建成功，请点击生成一键安装脚本`, 'success');
      await refreshAll();
      document.getElementById(genBtnId).addEventListener('click', () => {
        closeModal('node-modal');
        if (role === 'agent_b') {
          openBScriptModal(res.node.id, res.token);
        } else {
          openAScriptModal(res.node.id, res.token);
        }
      });
    } catch (err) {
      if (err.message !== 'unauthorized') showToast(`创建节点失败: ${err.message}`, 'error');
    }
  });

  // Edit receiver node projects, scheduling & disk pool modal
  document.getElementById('edit-node-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const nodeId = String(fd.get('node_id') || '').trim();
    const name = String(fd.get('name') || '').trim();
    const mode = String(fd.get('edit_project_mode') || 'single');
    const projectSchedule = String(fd.get('project_schedule') || 'fifo');
    const diskPolicy = String(fd.get('disk_policy') || 'affinity_hash');

    let projs = [];
    if (mode === 'single') {
      let chosen = String(fd.get('single_project') || '').trim();
      if (chosen === '__custom__') {
        chosen = String(fd.get('single_project_custom') || '').trim();
      }
      if (!chosen) {
        showToast('请选择或输入该接收节点专享下载的项目 ID', 'error');
        return;
      }
      projs = [chosen];
    } else if (mode === 'multi') {
      projs = String(fd.get('projects') || '').split(',').map(s => s.trim()).filter(Boolean);
      if (!projs.length) {
        showToast('请至少勾选或输入一个项目，或切换为「全部项目」模式', 'error');
        return;
      }
    } else {
      projs = [];
    }

    const maxDiskPct = parseWatermarkInput(fd.get('max_disk_usage_pct') || 85);
    if (maxDiskPct === null) {
      showToast('强制安全水位必须在 1% ~ 99% 之间', 'error');
      return;
    }

    const node = cachedNodes.find(n => n.id === nodeId);
    const sel = collectDiskSelectionFromPicker(document.getElementById('edit-disks-list'), node);
    const body = {
      name,
      projects: projs,
      project_schedule: projectSchedule,
      disk_policy: diskPolicy,
      disk_affinity: fd.get('disk_affinity') === 'on',
      active_disk_window: Number(fd.get('active_disk_window') || 10),
      max_disk_usage_pct: maxDiskPct,
      concurrency_mode: String(fd.get('concurrency_mode') || 'auto'),
      max_concurrent_override: Number(fd.get('max_concurrent_override') || 0),
      rate_limit_mbps: Number(fd.get('rate_limit_mbps') || 0),
    };
    if (!isCustomer()) {
      body.owner_account_id = String(fd.get('owner_account_id') || '').trim();
    }
    if (sel.hasChks) {
      if (sel.awaiting && sel.enabledCount === 0) {
        showToast('请至少勾选 1 块已挂载的物理磁盘才能激活接收节点', 'error');
        return;
      }
      if (!sel.awaiting && sel.enabledCount === 0) {
        if (!confirm('当前没有处于启用状态的磁盘，保存后该节点将在排空在途写入后暂停拉取，直到重新启用至少一块磁盘。确认保存（准备拔盘）吗？')) {
          return;
        }
      }
      if (!sel.isLegacyOnly) {
        body.storage_dirs = sel.storageDirs;
      }
      body.disabled_disks = sel.disabledDisks;
    }

    try {
      await api(`/api/v1/admin/nodes/${encodeURIComponent(nodeId)}`, {
        method: 'PUT',
        body: JSON.stringify(body),
      });
      closeModal('edit-node-modal');
      showToast(`节点 ${nodeId} 磁盘与配置已保存，2 秒内自动建目录并热生效`, 'success');
      refreshAll();
    } catch (err) {
      if (err.message !== 'unauthorized') showToast(`更新节点配置失败: ${err.message}`, 'error');
    }
  });

  // Live physical disk refresh buttons inside Receiver & Dispatch modals
  document.getElementById('btn-refresh-b-disks')?.addEventListener('click', (e) => {
    const nodeId = document.getElementById('edit-node-form')?.elements?.node_id?.value;
    refreshNodeDisksInModal(nodeId, 'agent_b', e.currentTarget);
  });
  document.getElementById('btn-refresh-a-disks')?.addEventListener('click', (e) => {
    const nodeId = document.getElementById('edit-a-disks-form')?.elements?.node_id?.value;
    refreshNodeDisksInModal(nodeId, 'agent_a', e.currentTarget);
  });

  // Save Dispatch Node multi-disk selection (supports safe-eject disable & unplug re-confirm)
  document.getElementById('edit-a-disks-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const nodeId = String(fd.get('node_id') || '').trim();
    const node = cachedNodes.find(n => n.id === nodeId);
    const sel = collectDiskSelectionFromPicker(document.getElementById('edit-a-disks-list'), node);
    if (!sel.hasChks) {
      showToast('暂未检测到物理盘，请先在目标分发机执行激活脚本上线后再刷新选择', 'error');
      return;
    }
    if (sel.awaiting && sel.enabledCount === 0) {
      showToast('请至少勾选 1 块已挂载的物理磁盘才能激活分发节点', 'error');
      return;
    }
    if (!sel.awaiting && sel.enabledCount === 0) {
      if (!confirm('当前没有启用的缓存盘，保存后该分发节点将停止接收新上传直到重新启用磁盘。确认保存（准备拔盘）吗？')) {
        return;
      }
    }
    const maxDiskPct = parseWatermarkInput(fd.get('max_disk_usage_pct') || 85);
    if (maxDiskPct === null) {
      showToast('强制安全水位必须在 1% ~ 99% 之间', 'error');
      return;
    }
    const payload = {
      disabled_disks: sel.disabledDisks,
      max_disk_usage_pct: maxDiskPct,
    };
    if (!sel.isLegacyOnly) {
      payload.storage_dirs = sel.storageDirs;
    }
    try {
      await api(`/api/v1/admin/nodes/${encodeURIComponent(nodeId)}`, {
        method: 'PUT',
        body: JSON.stringify(payload),
      });
      closeModal('edit-a-disks-modal');
      showToast(
        sel.enabledCount > 0
          ? `分发节点 ${nodeId} 数据盘配置已生效（启用 ${sel.enabledCount} 块盘，2 秒内同步）`
          : `分发节点 ${nodeId} 磁盘已停用排空，待在途写入归零即可安全拔盘`,
        'success'
      );
      refreshAll();
    } catch (err) {
      if (err.message !== 'unauthorized') showToast(`保存分发数据盘失败: ${err.message}`, 'error');
    }
  });

  // Release upload
  document.getElementById('upload-release-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const msgEl = document.getElementById('release-upload-msg');
    msgEl.textContent = '正在上传并校验 SHA256...';
    const fd = new FormData(e.target);
    try {
      const rel = await api('/api/v1/admin/releases', { method: 'POST', body: fd });
      const roleLbl = rel.role === 'agent_a' ? '分发节点' : '接收节点';
      const okMsg = `上传成功: ${roleLbl} ${rel.version} (${rel.os}/${rel.arch}, ${fmtBytes(rel.size)})`;
      msgEl.textContent = okMsg;
      showToast(okMsg, 'success');
      e.target.reset();
      refreshAll();
    } catch (err) {
      msgEl.textContent = '';
      if (err.message !== 'unauthorized') showToast(`上传发布包失败: ${err.message}`, 'error');
    }
  });

  // One-click Deploy Dispatch Node wizard
  document.getElementById('open-deploy-a-modal').addEventListener('click', openDeployAModal);
  document.getElementById('open-deploy-a-from-tab').addEventListener('click', openDeployAModal);

  document.getElementById('deploy-force-chk').addEventListener('change', (e) => {
    if (lastPrecheck && lastPrecheck.can_force && !lastPrecheck.ok) {
      document.getElementById('btn-confirm-deploy-a').disabled = !e.target.checked;
    }
  });

  document.getElementById('btn-run-precheck').addEventListener('click', async () => {
    const payload = readDeployAForm();
    if (!payload.host) {
      showToast('请先输入目标服务器公网 IP', 'error');
      return;
    }
    const btn = document.getElementById('btn-run-precheck');
    const box = document.getElementById('precheck-result');
    btn.disabled = true;
    btn.textContent = '正在连接预检...';
    box.innerHTML = '<div class="empty">正在通过 SSH 探测目标主机 root 权限、端口、目录、磁盘与服务...</div>';
    box.classList.remove('hidden');
    document.getElementById('btn-confirm-deploy-a').disabled = true;
    try {
      const res = await api('/api/v1/admin/deploy/precheck', {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      lastPrecheck = res;
      renderPrecheckResult(res);
    } catch (err) {
      box.innerHTML = `<div class="banner fail">预检请求失败: ${esc(err.message)}</div>`;
    } finally {
      btn.disabled = false;
      btn.textContent = '1. 执行环境预检';
    }
  });

  document.getElementById('deploy-a-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const payload = readDeployAForm();
    if (!payload.node_id) {
      showToast('请输入节点 ID', 'error');
      return;
    }
    if (!lastPrecheck || (!lastPrecheck.ok && !(lastPrecheck.can_force && payload.force_overwrite))) {
      showToast('请先完成环境预检并确认通过', 'error');
      return;
    }
    document.getElementById('btn-confirm-deploy-a').disabled = true;
    try {
      const task = await api('/api/v1/admin/deploy/agent-a', {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      activeDeployTaskId = task.id;
      document.getElementById('btn-refresh-deploy-status').classList.remove('hidden');
      renderDeployTaskDetail(task, document.getElementById('deploy-progress-box'));
      showToast(`已启动节点 ${payload.node_id} 一键部署任务`, 'info');
    } catch (err) {
      if (err.message !== 'unauthorized') showToast(`启动部署失败: ${err.message}`, 'error');
      document.getElementById('btn-confirm-deploy-a').disabled = false;
    }
  });

  document.getElementById('b-script-manual-submode')?.addEventListener('change', syncBScriptMode);
  document.getElementById('btn-open-b-reinstall-script')?.addEventListener('click', () => {
    const nodeId = document.getElementById('edit-node-form')?.elements?.node_id?.value;
    if (!nodeId) return;
    closeModal('edit-node-modal');
    openBScriptModal(nodeId);
  });
  document.getElementById('btn-open-a-reinstall-script')?.addEventListener('click', () => {
    const nodeId = document.getElementById('edit-a-disks-form')?.elements?.node_id?.value;
    if (!nodeId) return;
    closeModal('edit-a-disks-modal');
    openAScriptModal(nodeId);
  });

  // Receiver Install Script generator
  let lastBScript = '';
  let lastBScriptNodeId = '';
  document.getElementById('b-script-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const topMode = String(fd.get('script_mode') || 'await');
    const scriptMode = topMode === 'manual' ? String(fd.get('manual_submode') || 'pool') : 'await';
    const body = {
      node_id: fd.get('node_id'),
      node_token: fd.get('node_token'),
      rotate_token: fd.get('rotate_token') === 'on',
      install_dir: fd.get('install_dir'),
      state_dir: fd.get('state_dir'),
      release_id: fd.get('release_id'),
    };
    if (scriptMode === 'await') {
      body.await_disk_selection = true;
    } else if (scriptMode === 'pool') {
      const storageDirs = String(fd.get('storage_dirs') || '')
        .split(/[\n,]/)
        .map(s => s.trim())
        .filter(Boolean);
      if (!storageDirs.length) {
        showToast('请至少填写一个物理磁盘根目录', 'error');
        return;
      }
      body.storage_dirs = storageDirs;
    } else if (scriptMode === 'single') {
      const onlyProj = String(fd.get('only_project') || '').trim();
      if (!onlyProj || onlyProj === '__custom__') {
        showToast('请选择要绑定的单个项目', 'error');
        return;
      }
      body.only_project = onlyProj;
      body.dest_dirs = String(fd.get('single_dest_dirs') || '')
        .split(/[\n,]/)
        .map(s => s.trim())
        .filter(Boolean);
    } else {
      const projects = {};
      String(fd.get('projects_map') || '').split('\n').forEach(line => {
        const trimmed = line.trim();
        if (!trimmed || !trimmed.includes('=')) return;
        const idx = trimmed.indexOf('=');
        const k = trimmed.slice(0, idx).trim();
        const v = trimmed.slice(idx + 1).trim();
        if (k && v) projects[k] = v;
      });
      body.projects = projects;
    }
    try {
      const res = await api('/api/v1/admin/deploy/agent-b-script', {
        method: 'POST',
        body: JSON.stringify(body),
      });
      lastBScript = res.script || '';
      lastBScriptNodeId = res.node_id || String(body.node_id || 'receiver');
      const out = document.getElementById('b-script-output');
      out.innerHTML = `<div class="log-box">${esc(lastBScript)}</div>`;
      out.classList.remove('hidden');
      document.getElementById('b-script-steps-tip').classList.remove('hidden');
      document.getElementById('btn-copy-b-exec').classList.remove('hidden');
      document.getElementById('btn-copy-b-script').classList.remove('hidden');
      document.getElementById('btn-download-b-script').classList.remove('hidden');
      showToast('接收节点自动化安装脚本已生成', 'success');
    } catch (err) {
      if (err.message !== 'unauthorized') showToast(`生成安装脚本失败: ${err.message}`, 'error');
    }
  });

  document.getElementById('btn-copy-b-exec').addEventListener('click', () => {
    if (!lastBScript) return;
    copyText(buildTerminalExecCommand(lastBScript, lastBScriptNodeId, 'agent-b'), '一键终端执行命令已复制，直接粘贴到接收机终端回车即可');
  });
  document.getElementById('btn-copy-b-script').addEventListener('click', () => {
    if (!lastBScript) return;
    copyText(lastBScript, '完整安装脚本已复制到剪贴板');
  });
  document.getElementById('btn-download-b-script').addEventListener('click', () => {
    if (!lastBScript) return;
    downloadTextFile(`install-agent-b-${lastBScriptNodeId}.sh`, lastBScript);
  });

  // Dispatch Node Automated Install Script generator (Admin only)
  let lastAScript = '';
  let lastAScriptNodeId = '';
  const aScriptForm = document.getElementById('a-script-form');
  if (aScriptForm) {
    aScriptForm.elements.await_disk_selection?.addEventListener('change', (e) => {
      document.getElementById('a-script-datadir-wrap')?.classList.toggle('hidden', e.target.checked);
    });
    aScriptForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      const awaitDisk = fd.get('await_disk_selection') === 'on';
      const body = {
        node_id: String(fd.get('node_id') || '').trim(),
        node_token: String(fd.get('node_token') || '').trim(),
        rotate_token: fd.get('rotate_token') === 'on',
        await_disk_selection: awaitDisk,
        public_addr: String(fd.get('public_addr') || '').trim(),
        public_port: Number(fd.get('public_port') || 8443),
        local_port: Number(fd.get('local_port') || 18081),
        install_dir: String(fd.get('install_dir') || '/opt/relay-agent-a').trim(),
        data_dir: awaitDisk ? '' : String(fd.get('data_dir') || '/data/relay-a').trim(),
        release_id: String(fd.get('release_id') || '').trim(),
      };
      try {
        const res = await api('/api/v1/admin/deploy/agent-a-script', {
          method: 'POST',
          body: JSON.stringify(body),
        });
        lastAScript = res.script || '';
        lastAScriptNodeId = res.node_id || body.node_id || 'dispatch';
        const uploadCmd = `curl -fsS -X PUT --data-binary @test.bin "http://127.0.0.1:${body.local_port}/local/v1/files/my-project/test.bin"`;
        const tokBox = document.getElementById('a-script-token-box');
        tokBox.innerHTML = `
          <div><strong>本机推流测试命令（仅限 127.0.0.1 回环访问，免鉴权直传）：</strong></div>
          <div class="mono" style="margin:6px 0">${esc(uploadCmd)}</div>
          <div class="btn-row">
            <button type="button" class="btn sm" data-copy-text="${esc(uploadCmd)}">复制本机推送测试命令</button>
          </div>
        `;
        tokBox.classList.remove('hidden');
        const out = document.getElementById('a-script-output');
        out.innerHTML = `<div class="log-box">${esc(lastAScript)}</div>`;
        out.classList.remove('hidden');
        document.getElementById('btn-copy-a-exec').classList.remove('hidden');
        document.getElementById('btn-copy-a-script').classList.remove('hidden');
        document.getElementById('btn-download-a-script').classList.remove('hidden');
        showToast('分发节点自动化安装脚本已生成', 'success');
      } catch (err) {
        if (err.message !== 'unauthorized') showToast(`生成分发脚本失败: ${err.message}`, 'error');
      }
    });
    document.getElementById('btn-copy-a-exec')?.addEventListener('click', () => {
      if (!lastAScript) return;
      copyText(buildTerminalExecCommand(lastAScript, lastAScriptNodeId, 'agent-a'), '一键终端执行命令已复制，直接粘贴到分发机终端回车即可');
    });
    document.getElementById('btn-copy-a-script')?.addEventListener('click', () => {
      if (!lastAScript) return;
      copyText(lastAScript, '完整分发安装脚本已复制到剪贴板');
    });
    document.getElementById('btn-download-a-script')?.addEventListener('click', () => {
      if (!lastAScript) return;
      downloadTextFile(`install-agent-a-${lastAScriptNodeId}.sh`, lastAScript);
    });
  }

  // Customer Account management (Admin only)
  const openAccBtn = document.getElementById('open-create-account');
  if (openAccBtn) {
    openAccBtn.addEventListener('click', () => openAccountModal(''));
  }
  const accChecks = document.getElementById('account-project-checks');
  if (accChecks) {
    accChecks.addEventListener('change', (e) => {
      const chk = e.target.closest('input.account-proj-chk');
      if (!chk) return;
      const form = document.getElementById('account-form');
      const cur = String(form.elements.projects.value || '').split(',').map(s => s.trim()).filter(Boolean);
      const val = chk.value;
      const next = cur.filter(x => x !== val);
      if (chk.checked) next.push(val);
      form.elements.projects.value = next.join(',');
    });
  }
  const accForm = document.getElementById('account-form');
  if (accForm) {
    accForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      const mode = String(fd.get('mode') || 'create');
      const id = String(fd.get('id') || '').trim();
      const name = String(fd.get('name') || '').trim();
      const projs = String(fd.get('projects') || '').split(',').map(s => s.trim()).filter(Boolean);
      try {
        if (mode === 'edit') {
          await api(`/api/v1/admin/accounts/${encodeURIComponent(id)}`, {
            method: 'PUT',
            body: JSON.stringify({
              name,
              projects: projs,
              enabled: fd.get('enabled') === 'on',
            }),
          });
          closeModal('account-modal');
          showToast(`客户账号 ${name || id} 已更新（授权 ${projs.length} 个项目）`, 'success');
          refreshAll();
        } else {
          const res = await api('/api/v1/admin/accounts', {
            method: 'POST',
            body: JSON.stringify({ id, name, projects: projs }),
          });
          closeModal('account-modal');
          showAccountTokenModal(res.account, res.token, `客户账号已创建: ${res.account.name}`);
          showToast(`客户账号 ${res.account.id} 创建成功（授权 ${projs.length} 个项目）`, 'success');
          refreshAll();
        }
      } catch (err) {
        if (err.message !== 'unauthorized') showToast(`保存客户账号失败: ${err.message}`, 'error');
      }
    });
  }

  document.getElementById('assign-project-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const projectId = String(fd.get('project_id') || '').trim();
    const accountIds = Array.from(document.querySelectorAll('#assign-project-accounts-list input.assign-acc-chk:checked')).map(el => el.value);
    try {
      await api(`/api/v1/admin/projects/${encodeURIComponent(projectId)}/accounts`, {
        method: 'PUT',
        body: JSON.stringify({ account_ids: accountIds }),
      });
      closeModal('assign-project-modal');
      const meta = getProjectMeta(projectId);
      showToast(
        accountIds.length
          ? `项目 ${meta.name} 已分配给 ${accountIds.length} 个客户账号`
          : `项目 ${meta.name} 已收回全部客户可见权限（仅管理员可见）`,
        'success'
      );
      refreshAll();
    } catch (err) {
      if (err.message !== 'unauthorized') showToast(`分配项目失败: ${err.message}`, 'error');
    }
  });
  const copyUrlBtn = document.getElementById('btn-copy-account-url');
  if (copyUrlBtn) {
    copyUrlBtn.addEventListener('click', () => {
      if (lastAccountLoginURL) copyText(lastAccountLoginURL, '免输直达登录链接已复制到剪贴板');
    });
  }
  const copyTokBtn = document.getElementById('btn-copy-account-token');
  if (copyTokBtn) {
    copyTokBtn.addEventListener('click', () => {
      if (lastAccountToken) copyText(lastAccountToken, '客户 Token 已复制到剪贴板');
    });
  }
}

setupEvents();
updateAuthControls();
refreshAll();
