const STORAGE_KEY = 'relay_admin_token';
let adminToken = sessionStorage.getItem(STORAGE_KEY) || '';
let refreshTimer = null;

function fmtBytes(bytes) {
  if (!bytes || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0, v = bytes;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
}

function fmtSpeed(bps) {
  return `${fmtBytes(bps)}/s`;
}

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
}

async function api(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    headers: {
      'Content-Type': 'application/json',
      'X-Admin-Token': adminToken,
      ...(opts.headers || {}),
    },
  });
  if (res.status === 401) {
    showLogin('鉴权失败，请重新输入 Admin Token');
    throw new Error('unauthorized');
  }
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
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

async function refreshAll() {
  if (!adminToken) return;
  try {
    const [overview, nodes] = await Promise.all([
      api('/api/v1/admin/overview'),
      api('/api/v1/admin/nodes'),
    ]);
    renderDashboard(overview);
    renderProjects(overview.projects || []);
    renderNodes(nodes || []);
  } catch (e) {
    if (e.message !== 'unauthorized') console.error(e);
  }
}

function renderDashboard(ov) {
  const kpis = [
    { label: '在途待下载文件 (A节点)', value: ov.live_ready_files, sub: `总体积 ${fmtBytes(ov.live_ready_bytes)}` },
    { label: '当前实时总速率', value: fmtSpeed(ov.live_total_speed_bps), sub: `正在传输 ${ov.live_active_files} 个文件` },
    { label: '今日完成 / 流量', value: ov.today_completed, sub: `${fmtBytes(ov.today_bytes)} · 失败 ${ov.today_failed}` },
    { label: '累计汇总完成', value: ov.all_time_completed, sub: `累计 ${fmtBytes(ov.all_time_bytes)} · 失败 ${ov.all_time_failed}` },
    { label: '在线节点 (A / B)', value: `${ov.online_a_nodes}/${ov.total_a_nodes} · ${ov.online_b_nodes}/${ov.total_b_nodes}`, sub: `项目总数 ${ov.total_projects}` },
  ];
  document.getElementById('kpi-grid').innerHTML = kpis.map(k => `
    <div class="kpi-card">
      <div class="kpi-label">${esc(k.label)}</div>
      <div class="kpi-value">${esc(k.value)}</div>
      <div class="kpi-sub">${esc(k.sub)}</div>
    </div>
  `).join('');

  const active = ov.active_transfers || [];
  document.getElementById('active-count-badge').textContent = active.length;
  const activeEl = document.getElementById('active-transfers-list');
  if (active.length === 0) {
    activeEl.innerHTML = '<div class="empty">当前没有正在进行的文件直传</div>';
  } else {
    activeEl.innerHTML = active.map(t => {
      const pct = t.total_bytes > 0 ? Math.min(100, (t.transferred_bytes / t.total_bytes) * 100) : 0;
      return `
        <div class="transfer-row">
          <div class="transfer-meta">
            <div>
              <strong>${esc(t.filename)}</strong>
              <span class="badge">${esc(t.project_id)}</span>
            </div>
            <div class="mono">${esc(t.b_node_id)} ◄── ${esc(t.a_node_id)}</div>
          </div>
          <div class="bar-wrap"><div class="bar-fill green" style="width:${pct.toFixed(1)}%"></div></div>
          <div class="transfer-meta muted" style="margin-top:4px;margin-bottom:0">
            <span>${fmtBytes(t.transferred_bytes)} / ${fmtBytes(t.total_bytes)} (${pct.toFixed(1)}%)</span>
            <span>${fmtSpeed(t.speed_bps)}</span>
          </div>
        </div>
      `;
    }).join('');
  }

  renderTrendChart(ov.daily_trend || []);
}

function renderTrendChart(days) {
  const el = document.getElementById('trend-chart');
  if (!days.length) {
    el.innerHTML = '<div class="empty">暂无历史汇总统计</div>';
    return;
  }
  const maxBytes = Math.max(...days.map(d => d.bytes_transferred || 0), 1);
  const w = 520, h = 180, pad = 26;
  const barW = Math.max(12, Math.floor((w - pad * 2) / days.length) - 8);
  const bars = days.map((d, idx) => {
    const ratio = (d.bytes_transferred || 0) / maxBytes;
    const bh = Math.max(4, Math.round(ratio * (h - 52)));
    const x = pad + idx * ((w - pad * 2) / days.length) + 4;
    const y = h - 26 - bh;
    const label = d.date.slice(5);
    return `
      <g>
        <title>${esc(d.date)}: 完成 ${d.files_completed} 文件 (${fmtBytes(d.bytes_transferred)})</title>
        <rect x="${x}" y="${y}" width="${barW}" height="${bh}" rx="3" fill="#3b82f6" />
        <text x="${x + barW / 2}" y="${h - 8}" text-anchor="middle" fill="#8b949e" font-size="10">${esc(label)}</text>
      </g>
    `;
  }).join('');
  el.innerHTML = `
    <svg viewBox="0 0 ${w} ${h}" style="width:100%;height:auto">
      ${bars}
    </svg>
    <div class="muted" style="margin-top:6px">
      近期累计: ${days.reduce((a, d) => a + d.files_completed, 0)} 文件 · ${fmtBytes(days.reduce((a, d) => a + d.bytes_transferred, 0))}
    </div>
  `;
}

function renderProjects(projects) {
  const el = document.getElementById('projects-grid');
  if (!projects.length) {
    el.innerHTML = '<div class="empty">还没有项目，点击右上角「新建项目」开始。</div>';
    return;
  }
  el.innerHTML = projects.map(ps => {
    const p = ps.project;
    const avail = (ps.a_node_availability || []).map(a => `
      <span class="avail-chip">
        <span>${esc(a.a_node_id)}</span>
        <span class="badge online">待下 ${a.ready_count}</span>
        ${a.claimed_count ? `<span class="badge">传中 ${a.claimed_count}</span>` : ''}
        <span class="muted">${fmtBytes(a.ready_bytes)}</span>
      </span>
    `).join('') || '<span class="muted">当前无待下载积压</span>';

    return `
      <div class="card">
        <div class="card-head">
          <div>
            <h3>${esc(p.name)} <span class="mono muted">(${esc(p.id)})</span></h3>
            <div class="muted">${esc(p.description || '无描述')} · 策略: ${esc(p.conflict_policy)} · 租约: ${p.lease_ttl_sec}s</div>
          </div>
          <button class="btn sm" onclick="viewProjectLive('${esc(p.id)}')">穿透看实时队列</button>
        </div>
        <div style="display:flex;gap:16px;margin-bottom:10px" class="muted">
          <span>在线 A: <strong>${ps.online_a_nodes}</strong></span>
          <span>在线 B: <strong>${ps.online_b_nodes}</strong></span>
          <span>累计完成: <strong>${ps.total_completed}</strong> (${fmtBytes(ps.total_bytes)})</span>
        </div>
        <div>
          <div class="muted" style="margin-bottom:4px">当前可下载 A 节点分布：</div>
          ${avail}
        </div>
      </div>
    `;
  }).join('');
}

function renderNodes(nodes) {
  const as = nodes.filter(n => n.role === 'agent_a');
  const bs = nodes.filter(n => n.role === 'agent_b');

  document.getElementById('nodes-a-tbody').innerHTML = as.length ? as.map(n => {
    const ready = (n.availability || []).reduce((a, x) => a + x.ready_count, 0);
    const claimed = (n.availability || []).reduce((a, x) => a + x.claimed_count, 0);
    const pct = (n.disk_used_pct || 0).toFixed(1);
    return `
      <tr>
        <td><strong>${esc(n.name)}</strong><div class="mono muted">${esc(n.id)}</div></td>
        <td>
          <span class="badge ${n.online ? 'online' : 'offline'}">${n.online ? '在线' : '离线'}</span>
          ${n.disk_alarm ? '<span class="badge alarm">水位告警</span>' : ''}
        </td>
        <td class="mono">${esc(n.public_addr || '-')}</td>
        <td>
          <div class="bar-wrap"><div class="bar-fill ${n.disk_alarm ? 'red' : ''}" style="width:${Math.min(100, pct)}%"></div></div>
          <div class="muted">${pct}% (剩余 ${fmtBytes(n.disk_free_bytes)})</div>
        </td>
        <td>${ready} 待下 / ${claimed} 传中</td>
        <td class="mono">${fmtSpeed(n.speed_bps)}</td>
        <td>
          <button class="btn sm" onclick="viewNodeLive('${esc(n.id)}')">实时队列</button>
          <button class="btn sm danger" onclick="deleteNode('${esc(n.id)}')">删除</button>
        </td>
      </tr>
    `;
  }).join('') : '<tr><td colspan="7" class="empty">暂无注册的 A 节点</td></tr>';

  document.getElementById('nodes-b-tbody').innerHTML = bs.length ? bs.map(n => `
    <tr>
      <td><strong>${esc(n.name)}</strong><div class="mono muted">${esc(n.id)}</div></td>
      <td><span class="badge ${n.online ? 'online' : 'offline'}">${n.online ? '在线' : '离线'}</span></td>
      <td class="mono">${(n.projects && n.projects.length) ? esc(n.projects.join(', ')) : '全部'}</td>
      <td>${fmtBytes(n.disk_free_bytes)} <span class="muted">(${(n.disk_used_pct || 0).toFixed(1)}% 已用)</span></td>
      <td>${n.active_streams} 个任务</td>
      <td class="mono">${fmtSpeed(n.speed_bps)}</td>
      <td><button class="btn sm danger" onclick="deleteNode('${esc(n.id)}')">删除</button></td>
    </tr>
  `).join('') : '<tr><td colspan="7" class="empty">暂无注册的 B 节点</td></tr>';
}

window.viewNodeLive = async function(nodeId) {
  document.getElementById('live-modal-title').textContent = `A 节点实时队列: ${nodeId}`;
  document.getElementById('live-modal-body').innerHTML = '<div class="empty">正在穿透查询 A 节点...</div>';
  openModal('live-modal');
  try {
    const res = await api(`/api/v1/admin/nodes/${encodeURIComponent(nodeId)}/live-files`);
    document.getElementById('live-modal-body').innerHTML = renderLiveBlock(res);
  } catch (e) {
    document.getElementById('live-modal-body').innerHTML = `<div class="err-msg">${esc(e.message)}</div>`;
  }
};

window.viewProjectLive = async function(projectId) {
  document.getElementById('live-modal-title').textContent = `项目实时队列穿透: ${projectId}`;
  document.getElementById('live-modal-body').innerHTML = '<div class="empty">正在并发穿透查询相关 A 节点...</div>';
  openModal('live-modal');
  try {
    const list = await api(`/api/v1/admin/projects/${encodeURIComponent(projectId)}/live-files`);
    if (!list || !list.length) {
      document.getElementById('live-modal-body').innerHTML = '<div class="empty">该项目当前所有在线 A 节点均无待下载文件</div>';
      return;
    }
    document.getElementById('live-modal-body').innerHTML = list.map(renderLiveBlock).join('<hr style="border-color:var(--border);margin:16px 0"/>');
  } catch (e) {
    document.getElementById('live-modal-body').innerHTML = `<div class="err-msg">${esc(e.message)}</div>`;
  }
};

function renderLiveBlock(res) {
  if (res.error) {
    return `<div style="margin-bottom:8px"><strong>${esc(res.a_node_id)}</strong> (${esc(res.public_addr)}) <span class="badge offline">查询失败: ${esc(res.error)}</span></div>`;
  }
  const files = res.files || [];
  if (!files.length) {
    return `<div class="muted">${esc(res.a_node_id)}: 当前队列为空</div>`;
  }
  return `
    <div style="margin-bottom:8px">
      <strong>${esc(res.a_node_id)}</strong> <span class="mono muted">${esc(res.public_addr || '')}</span>
      · 剩余磁盘 ${fmtBytes(res.disk_free_bytes)}
    </div>
    <table class="data-table">
      <thead><tr><th>文件名</th><th>项目</th><th>大小</th><th>状态</th><th>抢占者</th><th>SHA256</th></tr></thead>
      <tbody>
        ${files.map(f => `
          <tr>
            <td class="mono">${esc(f.filename)}</td>
            <td>${esc(f.project_id)}</td>
            <td>${fmtBytes(f.size)}</td>
            <td><span class="badge ${f.status === 'ready' ? 'online' : ''}">${esc(f.status)}</span></td>
            <td class="mono">${esc(f.claimed_by || '-')}</td>
            <td class="mono muted">${esc((f.sha256 || '').slice(0, 12))}…</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;
}

window.deleteNode = async function(id) {
  if (!confirm(`确认删除节点 ${id} 吗？`)) return;
  await api(`/api/v1/admin/nodes/${encodeURIComponent(id)}`, { method: 'DELETE' });
  refreshAll();
};

function setupEvents() {
  document.querySelectorAll('.tab').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById(`tab-${btn.dataset.tab}`).classList.add('active');
    });
  });

  document.getElementById('login-btn').addEventListener('click', async () => {
    const v = document.getElementById('login-token').value.trim();
    if (!v) return;
    adminToken = v;
    try {
      await api('/api/v1/admin/overview');
      sessionStorage.setItem(STORAGE_KEY, adminToken);
      hideLogin();
      refreshAll();
    } catch {
      adminToken = '';
    }
  });

  document.getElementById('logout-btn').addEventListener('click', () => {
    adminToken = '';
    sessionStorage.removeItem(STORAGE_KEY);
    showLogin();
  });

  document.getElementById('refresh-now').addEventListener('click', refreshAll);

  document.getElementById('auto-refresh').addEventListener('change', (e) => {
    if (e.target.checked) startTimer();
    else stopTimer();
  });

  document.getElementById('open-create-project').addEventListener('click', () => {
    document.getElementById('create-project-form').reset();
    openModal('project-modal');
  });

  document.getElementById('create-project-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
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
  });

  const openNodeModal = (role) => {
    const form = document.getElementById('create-node-form');
    form.reset();
    form.elements.role.value = role;
    document.getElementById('node-modal-title').textContent = role === 'agent_a' ? '注册公网 A 节点' : '注册内网 B 节点';
    document.getElementById('node-public-addr-wrap').classList.toggle('hidden', role !== 'agent_a');
    document.getElementById('node-token-result').classList.add('hidden');
    openModal('node-modal');
  };
  document.getElementById('open-create-node-a').addEventListener('click', () => openNodeModal('agent_a'));
  document.getElementById('open-create-node-b').addEventListener('click', () => openNodeModal('agent_b'));

  document.getElementById('create-node-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const projs = String(fd.get('projects') || '').split(',').map(s => s.trim()).filter(Boolean);
    const res = await api('/api/v1/admin/nodes', {
      method: 'POST',
      body: JSON.stringify({
        id: fd.get('id'),
        name: fd.get('name'),
        role: fd.get('role'),
        public_addr: fd.get('public_addr'),
        projects: projs,
      }),
    });
    const box = document.getElementById('node-token-result');
    box.innerHTML = `<strong>节点已创建！请妥善保存接入 Token（仅展示一次）：</strong><div class="mono" style="margin-top:6px">${esc(res.token)}</div>`;
    box.classList.remove('hidden');
    refreshAll();
  });
}

function startTimer() {
  stopTimer();
  refreshTimer = setInterval(refreshAll, 3000);
}
function stopTimer() {
  if (refreshTimer) { clearInterval(refreshTimer); refreshTimer = null; }
}

setupEvents();
if (!adminToken) {
  showLogin();
} else {
  refreshAll();
}
startTimer();
