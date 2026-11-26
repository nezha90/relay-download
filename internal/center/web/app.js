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
let cachedReleases = [];
let cachedProjects = [];
let cachedNodes = [];
let lastPrecheck = null;
let activeDeployTaskId = '';
let activeLogModalTaskId = '';
let selectedProjectFilter = '';
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

async function api(path, opts = {}) {
  const isFormData = opts.body instanceof FormData;
  const headers = {
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

function updateAuthControls() {
  const trustedBadge = document.getElementById('trusted-badge');
  const logoutBtn = document.getElementById('logout-btn');
  if (trustedBadge) trustedBadge.classList.toggle('hidden', !authTrustedIP);
  if (logoutBtn) logoutBtn.classList.toggle('hidden', !adminToken);
}

function showLogin(msg = '') {
  document.getElementById('login-err').textContent = msg;
  document.getElementById('login-overlay').classList.remove('hidden');
}

function hideLogin() {
  document.getElementById('login-overlay').classList.add('hidden');
}

function openModal(id) { document.getElementById(id).classList.remove('hidden'); }
function closeModal(id) { document.getElementById(id).classList.add('hidden'); }
window.closeModal = closeModal;

function populateProjectSelect(selectEl, currentValue = '', includeCustomOption = true) {
  if (!selectEl) return;
  const opts = [];
  for (const ps of cachedProjects) {
    const p = ps.project;
    opts.push(`<option value="${esc(p.id)}">${esc(p.name)} (${esc(p.id)})</option>`);
  }
  if (currentValue && !cachedProjects.some(ps => ps.project.id === currentValue)) {
    opts.unshift(`<option value="${esc(currentValue)}">${esc(currentValue)}</option>`);
  }
  if (includeCustomOption) {
    opts.push('<option value="__custom__">手动输入项目 ID...</option>');
  }
  if (!opts.length) {
    opts.push('<option value="__custom__">暂无项目，请手动输入项目 ID</option>');
  }
  selectEl.innerHTML = opts.join('');
  if (currentValue) {
    selectEl.value = currentValue;
  }
}

async function refreshAll() {
  const btn = document.getElementById('refresh-now');
  if (btn) btn.disabled = true;
  try {
    const { hours, bucketMin } = getWindowSpec();
    const ovQS = new URLSearchParams({
      hours: String(hours),
      bucket_min: String(bucketMin),
    });
    if (selectedProjectFilter) ovQS.set('project', selectedProjectFilter);

    const [overview, nodes, releases, tasks] = await Promise.all([
      api(`/api/v1/admin/overview?${ovQS.toString()}`),
      api(`/api/v1/admin/nodes?hours=${encodeURIComponent(hours)}`),
      api('/api/v1/admin/releases'),
      api('/api/v1/admin/deploy/tasks'),
    ]);

    authTrustedIP = !!overview.auth_trusted_ip;
    hideLogin();
    updateAuthControls();

    const snapEl = document.getElementById('snapshot-time');
    if (snapEl && overview.generated_at) {
      snapEl.textContent = `统计截至 ${fmtTimeShort(overview.generated_at, false)}`;
    }

    cachedProjects = overview.projects || [];
    cachedNodes = nodes || [];
    cachedReleases = releases || [];
    syncProjectFilterOptions(cachedProjects);
    renderDashboard(overview);
    renderProjects(cachedProjects, overview.window_hours || hours);
    renderNodes(cachedNodes, overview.window_hours || hours);
    renderReleases(cachedReleases);
    renderDeployTasks(tasks || []);
  } catch (e) {
    if (e.message !== 'unauthorized') console.error(e);
  } finally {
    if (btn) btn.disabled = false;
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
  const opts = ['<option value="">全部项目</option>'];
  for (const ps of projects) {
    const p = ps.project;
    opts.push(`<option value="${esc(p.id)}">${esc(p.name)} (${esc(p.id)})</option>`);
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
    {
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
    titleEl.textContent = `${winLbl}平均速度曲线${selectedProjectFilter ? ` · ${selectedProjectFilter}` : ''}`;
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
          <stop offset="0%" stop-color="#3b82f6" stop-opacity="0.38" />
          <stop offset="85%" stop-color="#3b82f6" stop-opacity="0.04" />
          <stop offset="100%" stop-color="#3b82f6" stop-opacity="0" />
        </linearGradient>
      </defs>
      ${yTicks}
      ${xTicks}
      ${refLines}
      <path d="${areaD}" fill="url(#speedAreaGrad)" />
      <path d="${lineD}" fill="none" stroke="#3b82f6" stroke-width="2.4" stroke-linejoin="round" stroke-linecap="round" />
      ${dots}
      <line id="curve-hover-line" x1="0" y1="${padT}" x2="0" y2="${baseY}" stroke="#38bdf8" stroke-width="1" stroke-dasharray="3 3" visibility="hidden" />
      <circle id="curve-hover-dot" cx="0" cy="0" r="5" fill="#38bdf8" stroke="#ffffff" stroke-width="2" visibility="hidden" />
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
      <g>
        <title>${esc(d.date)} (UTC): 完成 ${fmtNum(d.files_completed)} 文件 · ${fmtBytes(bytes)} · 日均 ${fmtSpeed(dayAvg)}</title>
        <rect x="${x.toFixed(1)}" y="${y}" width="${barW}" height="${bh}" rx="4" fill="${fill}" />
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

function renderProjects(projects, winHours) {
  const el = document.getElementById('projects-grid');
  const winLbl = windowLabel(winHours);
  if (!projects.length) {
    el.innerHTML = '<div class="empty">还没有项目，点击右上角「新建项目」开始。</div>';
    return;
  }
  el.innerHTML = projects.map(ps => {
    const p = ps.project;
    const avail = (ps.a_node_availability || []).map(a => `
      <span class="avail-chip">
        <span>${esc(a.a_node_id)}</span>
        <span class="badge online">积压 ${fmtNum(a.ready_count + a.claimed_count)}</span>
        <span class="muted">${fmtBytes(a.ready_bytes)}</span>
      </span>
    `).join('') || '<span class="muted">当前无待传输积压</span>';

    const autoBadge = p.description === '上传自动发现创建' ? '<span class="badge">自动发现</span>' : '';
    return `
      <div class="card">
        <div class="card-head">
          <div>
            <h3>${esc(p.name)} <span class="mono muted">(${esc(p.id)})</span> ${autoBadge}</h3>
            <div class="muted">${esc(p.description || '无描述')} · 策略: ${esc(p.conflict_policy)} · 租约: ${p.lease_ttl_sec}s</div>
          </div>
          <div style="display:flex;gap:6px">
            <button class="btn sm danger" data-action="delete-project" data-id="${esc(p.id)}">删除</button>
          </div>
        </div>
        <div class="proj-stats-grid">
          <div class="proj-stat-box">
            <div class="k">${esc(winLbl)}平均速率</div>
            <div class="v">${esc(fmtSpeed(ps.window_avg_speed_bps))} <span class="muted">(${esc(fmtMbps(ps.window_avg_speed_bps))})</span></div>
            <div class="muted">活跃均速 ${esc(fmtSpeed(ps.active_avg_speed_bps))}</div>
          </div>
          <div class="proj-stat-box">
            <div class="k">${esc(winLbl)}完成汇总</div>
            <div class="v">${esc(fmtNum(ps.window_completed))} 文件 · ${esc(fmtBytes(ps.window_bytes))}</div>
            <div class="muted">失败 ${esc(fmtNum(ps.window_failed))}</div>
          </div>
          <div class="proj-stat-box">
            <div class="k">累计完成总量</div>
            <div class="v">${esc(fmtNum(ps.total_completed))} 文件 · ${esc(fmtBytes(ps.total_bytes))}</div>
            <div class="muted">累计失败 ${esc(fmtNum(ps.total_failed))}</div>
          </div>
          <div class="proj-stat-box">
            <div class="k">在线节点</div>
            <div class="v">分发节点 ${ps.online_a_nodes} · 接收节点 ${ps.online_b_nodes}</div>
            <div class="muted">待传输 ${esc(fmtNum(ps.queued_files))} (${esc(fmtBytes(ps.queued_bytes))})</div>
          </div>
        </div>
        <div>
          <div class="muted" style="margin-bottom:4px">各分发节点待传输积压汇总：</div>
          ${avail}
        </div>
      </div>
    `;
  }).join('');
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

function diskPolicyLabel(pol) {
  switch (pol) {
    case 'most_free': return '最大余量优先';
    case 'round_robin': return '逐文件轮询';
    case 'first': return '首盘写满再切';
    case 'affinity_hash':
    default: return '同源均匀';
  }
}

function renderProjectScope(projects, schedule) {
  if (!projects || !projects.length) {
    return `
      <div style="display:flex;gap:4px;flex-wrap:wrap">
        <span class="badge online">全部项目</span>
        <span class="badge">${esc(scheduleLabel(schedule))}</span>
      </div>
      <div class="muted" style="margin-top:3px">自动同步新建项目</div>
    `;
  }
  if (projects.length === 1) {
    return `
      <div><span class="badge online">单项目专享</span></div>
      <div class="mono muted" style="margin-top:3px">${esc(projects[0])}</div>
    `;
  }
  return `
    <div style="display:flex;gap:4px;flex-wrap:wrap">
      <span class="badge">多项目 (${projects.length})</span>
      <span class="badge">${esc(scheduleLabel(schedule))}</span>
    </div>
    <div class="mono muted" style="margin-top:3px">${esc(projects.join(', '))}</div>
  `;
}

function renderReceiverDisks(n) {
  const polBadge = `<span class="badge">${esc(diskPolicyLabel(n.disk_policy))}</span>`;
  const disks = n.disks || [];
  if (!disks.length) {
    return `
      <div>${fmtBytes(n.disk_free_bytes)} <span class="muted">(${(n.disk_used_pct || 0).toFixed(1)}% 已用)</span></div>
      <div style="margin-top:4px">${polBadge}</div>
    `;
  }
  const disabledSet = new Set(n.disabled_disks || []);
  const items = disks.map(d => {
    const enabled = d.enabled !== false && !disabledSet.has(d.path);
    const pct = Number(d.used_pct || 0);
    const barCls = !enabled ? '' : (d.low_space || pct >= 90 ? 'red' : 'green');
    const stTag = !enabled
      ? '<span class="badge offline">已停用</span>'
      : (d.low_space ? '<span class="badge alarm">低空间</span>' : '<span class="badge online">启用</span>');
    return `
      <div class="disk-mini-item${enabled ? '' : ' disabled'}">
        <div class="disk-mini-head">
          <span class="mono" title="${esc(d.path)}">${esc(d.path)}</span>
          ${stTag}
        </div>
        <div class="bar-wrap"><div class="bar-fill ${barCls}" style="width:${Math.min(100, pct).toFixed(1)}%"></div></div>
        <div class="muted">剩 ${fmtBytes(d.free_bytes)} / ${fmtBytes(d.total_bytes)} (${pct.toFixed(1)}%)</div>
      </div>
    `;
  }).join('');
  return `
    <div style="margin-bottom:5px;display:flex;gap:4px;flex-wrap:wrap;align-items:center">
      ${polBadge}
      ${n.storage_dirs && n.storage_dirs.length ? '<span class="badge online">磁盘池托管</span>' : ''}
    </div>
    <div class="disk-mini-list">${items}</div>
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
    const pct = (n.disk_used_pct || 0).toFixed(1);
    const verStr = n.version ? `${n.version}${n.arch ? ' · ' + n.arch : ''}` : '-';
    const checked = selectedNodes.agent_a.has(n.id) ? 'checked' : '';
    return `
      <tr>
        <td><input type="checkbox" class="node-chk" data-role="agent_a" data-id="${esc(n.id)}" ${checked} /></td>
        <td><strong>${esc(n.name)}</strong><div class="mono muted">${esc(n.id)}</div></td>
        <td>
          <div style="display:flex;gap:4px;flex-wrap:wrap;align-items:center">
            <span class="badge ${n.online ? 'online' : 'offline'}">${n.online ? '在线' : '离线'}</span>
            ${n.disk_alarm ? '<span class="badge alarm">水位告警</span>' : ''}
            ${renderUpgradeBadge(n)}
          </div>
          <div class="mono muted" style="margin-top:3px">${esc(verStr)}</div>
        </td>
        <td class="mono">${esc(n.public_addr || '-')}</td>
        <td>
          <div class="bar-wrap"><div class="bar-fill ${n.disk_alarm ? 'red' : ''}" style="width:${Math.min(100, pct)}%"></div></div>
          <div class="muted">${pct}% (剩余 ${fmtBytes(n.disk_free_bytes)})</div>
        </td>
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
            <button class="btn sm danger" data-action="delete-node" data-id="${esc(n.id)}">删除</button>
          </div>
        </td>
      </tr>
    `;
  }).join('') : '<tr><td colspan="8" class="empty">暂无注册的分发节点</td></tr>';

  document.getElementById('nodes-b-tbody').innerHTML = bs.length ? bs.map(n => {
    const verStr = n.version ? `${n.version}${n.arch ? ' · ' + n.arch : ''}` : '-';
    const checked = selectedNodes.agent_b.has(n.id) ? 'checked' : '';
    return `
      <tr>
        <td><input type="checkbox" class="node-chk" data-role="agent_b" data-id="${esc(n.id)}" ${checked} /></td>
        <td><strong>${esc(n.name)}</strong><div class="mono muted">${esc(n.id)}</div></td>
        <td>
          <div style="display:flex;gap:4px;flex-wrap:wrap;align-items:center">
            <span class="badge ${n.online ? 'online' : 'offline'}">${n.online ? '在线' : '离线'}</span>
            ${renderUpgradeBadge(n)}
          </div>
          <div class="mono muted" style="margin-top:3px">${esc(verStr)}</div>
        </td>
        <td>${renderProjectScope(n.projects, n.project_schedule)}</td>
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
            <button class="btn sm primary" data-action="edit-node-projects" data-id="${esc(n.id)}">配置项目与磁盘</button>
            <button class="btn sm" data-action="open-b-script" data-id="${esc(n.id)}">安装脚本</button>
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

async function deleteNode(id) {
  if (!confirm(`确认删除节点 ${id} 吗？`)) return;
  try {
    await api(`/api/v1/admin/nodes/${encodeURIComponent(id)}`, { method: 'DELETE' });
    refreshAll();
  } catch (e) {
    if (e.message !== 'unauthorized') alert(`删除节点失败: ${e.message}`);
  }
}

async function deleteProject(id) {
  if (!confirm(`确认删除项目 ${id} 吗？`)) return;
  try {
    await api(`/api/v1/admin/projects/${encodeURIComponent(id)}`, { method: 'DELETE' });
    refreshAll();
  } catch (e) {
    if (e.message !== 'unauthorized') alert(`删除项目失败: ${e.message}`);
  }
}

async function deleteRelease(id) {
  if (!confirm('确认删除该发布包吗？')) return;
  try {
    await api(`/api/v1/admin/releases/${encodeURIComponent(id)}`, { method: 'DELETE' });
    refreshAll();
  } catch (e) {
    if (e.message !== 'unauthorized') alert(`删除发布包失败: ${e.message}`);
  }
}

async function runBatchUpgrade(role) {
  const selectId = role === 'agent_a' ? 'batch-rel-a' : 'batch-rel-b';
  const msgId = role === 'agent_a' ? 'batch-msg-a' : 'batch-msg-b';
  const releaseID = document.getElementById(selectId).value;
  const nodeIDs = Array.from(selectedNodes[role]);
  if (!releaseID) {
    alert('请先选择目标发布包（如为空，请先在「部署与版本」页签上传）');
    return;
  }
  if (!nodeIDs.length) {
    alert('请先勾选至少一个节点');
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
    selectedNodes[role].clear();
    refreshAll();
  } catch (e) {
    if (e.message !== 'unauthorized') alert(`批量更新下发失败: ${e.message}`);
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
  if (t.local_token) {
    tokHtml = `
      <div class="token-box" style="margin-bottom:10px">
        <strong>请保存该分发节点的本机上传密钥 X-Local-Token（仅展示一次）：</strong>
        <div class="mono" style="margin-top:6px">${esc(t.local_token)}</div>
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
    return `
      <label class="proj-check-item">
        <input type="checkbox" class="edit-proj-chk" value="${esc(p.id)}" ${chk} />
        <span class="mono">${esc(p.id)}</span>
      </label>
    `;
  }).join('');
}

function renderEditDisksList(node) {
  const sec = document.getElementById('edit-disks-section');
  const wrap = document.getElementById('edit-disks-list');
  const tip = document.getElementById('edit-storage-pool-tip');
  const disks = node.disks || [];
  const disabledSet = new Set(node.disabled_disks || []);

  if (tip) {
    const hasPool = !!(node.storage_dirs && node.storage_dirs.length);
    tip.classList.toggle('hidden', !node.online || hasPool);
  }
  if (!disks.length) {
    sec.classList.remove('hidden');
    wrap.innerHTML = '<div class="muted">等待接收节点上报磁盘信息（升级至 v1.8.0 后自动展示每块挂载盘容量与启停开关）</div>';
    return;
  }
  sec.classList.remove('hidden');
  wrap.innerHTML = disks.map(d => {
    const enabled = !disabledSet.has(d.path);
    const pct = Number(d.used_pct || 0);
    const barCls = !enabled ? '' : (d.low_space || pct >= 90 ? 'red' : 'green');
    return `
      <label class="disk-toggle-row">
        <div class="disk-toggle-left">
          <input type="checkbox" class="edit-disk-chk" value="${esc(d.path)}" ${enabled ? 'checked' : ''} />
          <div>
            <div class="mono"><strong>${esc(d.path)}</strong></div>
            <div class="muted">${enabled ? '启用中 · 允许落盘' : '已停用 · 不再写入新文件'}${d.low_space ? ' · 低于安全余量水位' : ''}${d.writable === false ? ' · 目录不可写' : ''}</div>
          </div>
        </div>
        <div class="disk-toggle-right">
          <div class="bar-wrap" style="width:140px"><div class="bar-fill ${barCls}" style="width:${Math.min(100, pct).toFixed(1)}%"></div></div>
          <div class="muted">剩余 ${fmtBytes(d.free_bytes)} / ${fmtBytes(d.total_bytes)} (${pct.toFixed(1)}%)</div>
        </div>
      </label>
    `;
  }).join('');
}

function openEditNodeProjectsModal(nodeId) {
  const node = cachedNodes.find(n => n.id === nodeId);
  if (!node) return;
  const form = document.getElementById('edit-node-form');
  form.reset();
  form.elements.node_id.value = node.id;
  form.elements.name.value = node.name || node.id;
  form.elements.project_schedule.value = node.project_schedule || 'fifo';
  form.elements.disk_policy.value = node.disk_policy || 'affinity_hash';
  document.getElementById('edit-node-title').textContent = `配置接收节点: ${node.name || node.id}`;

  const projs = node.projects || [];
  const defaultSingle = projs.length === 1 ? projs[0] : (cachedProjects[0]?.project?.id || '');
  populateProjectSelect(document.getElementById('edit-single-project-select'), defaultSingle, true);

  if (projs.length === 1) {
    form.elements.edit_project_mode.value = 'single';
  } else if (projs.length > 1) {
    form.elements.edit_project_mode.value = 'multi';
  } else {
    form.elements.edit_project_mode.value = 'all';
  }
  form.elements.projects.value = projs.join(',');
  renderEditProjectChecks(projs);
  renderEditDisksList(node);
  syncEditNodeProjectMode();
  openModal('edit-node-modal');
}

function syncBScriptMode() {
  const form = document.getElementById('b-script-form');
  const mode = form.elements.script_mode.value || 'pool';
  document.getElementById('b-script-pool-wrap').classList.toggle('hidden', mode !== 'pool');
  document.getElementById('b-script-single-wrap').classList.toggle('hidden', mode !== 'single');
  document.getElementById('b-script-multi-wrap').classList.toggle('hidden', mode !== 'multi');
}

function openBScriptModal(nodeId, presetToken = '') {
  const node = cachedNodes.find(n => n.id === nodeId);
  const form = document.getElementById('b-script-form');
  form.reset();
  form.elements.node_id.value = nodeId;
  form.elements.node_token.value = presetToken;
  document.getElementById('b-script-title').textContent = `内网接收节点一键安装脚本: ${nodeId}`;
  document.getElementById('b-script-output').classList.add('hidden');
  document.getElementById('btn-copy-b-script').classList.add('hidden');
  populateReleaseSelect(document.getElementById('b-script-release-select'), 'agent_b', '自动匹配最新接收节点发布包');

  const nodeProjs = (node && node.projects) || [];
  const defaultProj = nodeProjs.length === 1 ? nodeProjs[0] : (cachedProjects[0]?.project?.id || '');
  populateProjectSelect(document.getElementById('b-script-single-project'), defaultProj, false);
  form.elements.script_mode.value = 'pool';
  form.elements.storage_dirs.value = (node && node.storage_dirs && node.storage_dirs.length)
    ? node.storage_dirs.join('\n')
    : '/mnt/sda/relay-delivery\n/mnt/sdb/relay-delivery';
  if (defaultProj) {
    form.elements.single_dest_dirs.value = `/data/relay-b/files/${defaultProj}`;
  }
  syncBScriptMode();
  openModal('b-script-modal');
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
    const btn = e.target.closest('button[data-action]');
    if (!btn) return;
    const id = btn.dataset.id || '';
    switch (btn.dataset.action) {
      case 'delete-project': deleteProject(id); break;
      case 'delete-node': deleteNode(id); break;
      case 'delete-release': deleteRelease(id); break;
      case 'view-deploy-task': viewDeployTaskLog(id); break;
      case 'open-b-script': openBScriptModal(id); break;
      case 'edit-node-projects': openEditNodeProjectsModal(id); break;
    }
  });

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
    document.getElementById('login-token').value = '';
    updateAuthControls();
    if (!authTrustedIP) {
      showLogin();
    }
  });

  document.getElementById('refresh-now').addEventListener('click', refreshAll);

  document.getElementById('btn-refresh-log-modal').addEventListener('click', () => {
    if (activeLogModalTaskId) viewDeployTaskLog(activeLogModalTaskId);
  });

  document.getElementById('btn-refresh-deploy-status').addEventListener('click', () => {
    if (activeDeployTaskId) fetchDeployStatus(activeDeployTaskId);
  });

  document.getElementById('open-create-project').addEventListener('click', () => {
    document.getElementById('create-project-form').reset();
    openModal('project-modal');
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
        }),
      });
      closeModal('project-modal');
      refreshAll();
    } catch (err) {
      if (err.message !== 'unauthorized') alert(`保存项目失败: ${err.message}`);
    }
  });

  // Create node modal
  const openNodeModal = (role) => {
    const form = document.getElementById('create-node-form');
    form.reset();
    form.elements.role.value = role;
    document.getElementById('node-modal-title').textContent = role === 'agent_a' ? '手动注册公网分发节点' : '注册内网接收节点';
    document.getElementById('node-public-addr-wrap').classList.toggle('hidden', role !== 'agent_a');
    document.getElementById('node-token-result').classList.add('hidden');
    populateProjectSelect(document.getElementById('node-single-project-select'), cachedProjects[0]?.project?.id || '', true);
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
          alert('请选择或输入该接收节点要专享下载的项目 ID');
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

    try {
      const payload = {
        id: fd.get('id'),
        name: fd.get('name'),
        role,
        public_addr: fd.get('public_addr'),
        projects: projs,
      };
      if (role === 'agent_b') {
        payload.project_schedule = String(fd.get('project_schedule') || 'fifo');
        payload.disk_policy = String(fd.get('disk_policy') || 'affinity_hash');
      }
      const res = await api('/api/v1/admin/nodes', {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      const box = document.getElementById('node-token-result');
      const extraBtn = role === 'agent_b'
        ? '<div style="margin-top:8px"><button type="button" class="btn sm primary" id="btn-gen-b-after-create">生成一键安装脚本</button></div>'
        : '';
      box.innerHTML = `<strong>节点已创建！请妥善保存接入 Token（仅展示一次）：</strong><div class="mono" style="margin-top:6px">${esc(res.token)}</div>${extraBtn}`;
      box.classList.remove('hidden');
      await refreshAll();
      if (role === 'agent_b') {
        document.getElementById('btn-gen-b-after-create').addEventListener('click', () => {
          closeModal('node-modal');
          openBScriptModal(res.node.id, res.token);
        });
      }
    } catch (err) {
      if (err.message !== 'unauthorized') alert(`创建节点失败: ${err.message}`);
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
        alert('请选择或输入该接收节点专享下载的项目 ID');
        return;
      }
      projs = [chosen];
    } else if (mode === 'multi') {
      projs = String(fd.get('projects') || '').split(',').map(s => s.trim()).filter(Boolean);
      if (!projs.length) {
        alert('请至少勾选或输入一个项目，或切换为「全部项目」模式');
        return;
      }
    } else {
      projs = [];
    }

    const diskChks = Array.from(document.querySelectorAll('#edit-disks-list input.edit-disk-chk'));
    const body = {
      name,
      projects: projs,
      project_schedule: projectSchedule,
      disk_policy: diskPolicy,
    };
    if (diskChks.length > 0) {
      const disabledDisks = diskChks.filter(el => !el.checked).map(el => el.value);
      if (disabledDisks.length === diskChks.length) {
        if (!confirm('你已停用该节点的全部磁盘，保存后该节点将暂停下载直到重新启用至少一块磁盘。确认保存吗？')) {
          return;
        }
      }
      body.disabled_disks = disabledDisks;
    }

    try {
      await api(`/api/v1/admin/nodes/${encodeURIComponent(nodeId)}`, {
        method: 'PUT',
        body: JSON.stringify(body),
      });
      closeModal('edit-node-modal');
      refreshAll();
    } catch (err) {
      if (err.message !== 'unauthorized') alert(`更新节点配置失败: ${err.message}`);
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
      msgEl.textContent = `上传成功: ${roleLbl} ${rel.version} (${rel.os}/${rel.arch}, ${fmtBytes(rel.size)})`;
      e.target.reset();
      refreshAll();
    } catch (err) {
      msgEl.textContent = '';
      if (err.message !== 'unauthorized') alert(`上传发布包失败: ${err.message}`);
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
      alert('请先输入目标服务器公网 IP');
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
      alert('请输入节点 ID');
      return;
    }
    if (!lastPrecheck || (!lastPrecheck.ok && !(lastPrecheck.can_force && payload.force_overwrite))) {
      alert('请先完成环境预检并确认通过');
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
    } catch (err) {
      if (err.message !== 'unauthorized') alert(`启动部署失败: ${err.message}`);
      document.getElementById('btn-confirm-deploy-a').disabled = false;
    }
  });

  // Receiver Install Script generator
  let lastBScript = '';
  document.getElementById('b-script-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const scriptMode = String(fd.get('script_mode') || 'pool');
    const body = {
      node_id: fd.get('node_id'),
      node_token: fd.get('node_token'),
      rotate_token: fd.get('rotate_token') === 'on',
      install_dir: fd.get('install_dir'),
      state_dir: fd.get('state_dir'),
      release_id: fd.get('release_id'),
    };
    if (scriptMode === 'pool') {
      const storageDirs = String(fd.get('storage_dirs') || '')
        .split(/[\n,]/)
        .map(s => s.trim())
        .filter(Boolean);
      if (!storageDirs.length) {
        alert('请至少填写一个物理磁盘根目录 (storage_dirs)');
        return;
      }
      body.storage_dirs = storageDirs;
    } else if (scriptMode === 'single') {
      const onlyProj = String(fd.get('only_project') || '').trim();
      if (!onlyProj || onlyProj === '__custom__') {
        alert('请选择要绑定的单个项目');
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
      const out = document.getElementById('b-script-output');
      out.innerHTML = `<div class="log-box">${esc(lastBScript)}</div>`;
      out.classList.remove('hidden');
      document.getElementById('btn-copy-b-script').classList.remove('hidden');
    } catch (err) {
      if (err.message !== 'unauthorized') alert(`生成安装脚本失败: ${err.message}`);
    }
  });

  document.getElementById('btn-copy-b-script').addEventListener('click', async () => {
    if (!lastBScript) return;
    try {
      await navigator.clipboard.writeText(lastBScript);
      const b = document.getElementById('btn-copy-b-script');
      b.textContent = '已复制！';
      setTimeout(() => { b.textContent = '复制脚本'; }, 1500);
    } catch {
      alert('剪贴板复制失败，请手动选中下方脚本复制');
    }
  });
}

setupEvents();
updateAuthControls();
refreshAll();
