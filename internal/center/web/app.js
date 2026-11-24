const STORAGE_KEY = 'relay_admin_token';
let adminToken = sessionStorage.getItem(STORAGE_KEY) || '';
let refreshTimer = null;
let deployPollTimer = null;
let cachedReleases = [];
let lastPrecheck = null;
const selectedNodes = { agent_a: new Set(), agent_b: new Set() };

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
  const isFormData = opts.body instanceof FormData;
  const headers = {
    'X-Admin-Token': adminToken,
    ...(isFormData ? {} : { 'Content-Type': 'application/json' }),
    ...(opts.headers || {}),
  };
  const res = await fetch(path, { ...opts, headers });
  if (res.status === 401) {
    adminToken = '';
    sessionStorage.removeItem(STORAGE_KEY);
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
function closeModal(id) {
  document.getElementById(id).classList.add('hidden');
  if (id === 'deploy-a-modal' && deployPollTimer) {
    clearInterval(deployPollTimer);
    deployPollTimer = null;
  }
}
window.closeModal = closeModal;

async function refreshAll() {
  if (!adminToken) return;
  try {
    const [overview, nodes, releases, tasks] = await Promise.all([
      api('/api/v1/admin/overview'),
      api('/api/v1/admin/nodes'),
      api('/api/v1/admin/releases'),
      api('/api/v1/admin/deploy/tasks'),
    ]);
    cachedReleases = releases || [];
    renderDashboard(overview);
    renderProjects(overview.projects || []);
    renderNodes(nodes || []);
    renderReleases(cachedReleases);
    renderDeployTasks(tasks || []);
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
  const byDate = new Map(days.map(d => [d.date, d]));
  const series = [];
  const now = new Date();
  for (let i = 13; i >= 0; i--) {
    const dt = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - i));
    const key = dt.toISOString().slice(0, 10);
    series.push(byDate.get(key) || { date: key, files_completed: 0, bytes_transferred: 0 });
  }
  const maxBytes = Math.max(...series.map(d => d.bytes_transferred || 0), 1);
  const w = 520, h = 180, pad = 22;
  const slotW = (w - pad * 2) / series.length;
  const barW = Math.min(24, Math.max(10, Math.floor(slotW) - 8));
  const bars = series.map((d, idx) => {
    const bytes = d.bytes_transferred || 0;
    const ratio = bytes / maxBytes;
    const bh = bytes > 0 ? Math.max(4, Math.round(ratio * (h - 52))) : 2;
    const cx = pad + idx * slotW + slotW / 2;
    const x = cx - barW / 2;
    const y = h - 26 - bh;
    const label = d.date.slice(5);
    const fill = bytes > 0 ? '#3b82f6' : '#2d3645';
    return `
      <g>
        <title>${esc(d.date)}: 完成 ${d.files_completed} 文件 (${fmtBytes(bytes)})</title>
        <rect x="${x.toFixed(1)}" y="${y}" width="${barW}" height="${bh}" rx="3" fill="${fill}" />
        ${idx % 2 === 1 || idx === series.length - 1 ? `<text x="${cx.toFixed(1)}" y="${h - 8}" text-anchor="middle" fill="#8b949e" font-size="9">${esc(label)}</text>` : ''}
      </g>
    `;
  }).join('');
  el.innerHTML = `
    <svg viewBox="0 0 ${w} ${h}" style="width:100%;height:auto">
      ${bars}
    </svg>
    <div class="muted" style="margin-top:6px">
      近 14 日累计: ${days.reduce((a, d) => a + d.files_completed, 0)} 文件 · ${fmtBytes(days.reduce((a, d) => a + d.bytes_transferred, 0))}
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
          <div style="display:flex;gap:6px">
            <button class="btn sm" data-action="view-project-live" data-id="${esc(p.id)}">穿透看实时队列</button>
            <button class="btn sm danger" data-action="delete-project" data-id="${esc(p.id)}">删除</button>
          </div>
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

function renderUpgradeBadge(n) {
  if (!n.upgrade_status) return '';
  const map = {
    pending: { cls: 'alarm', txt: `待升 → ${n.target_version}` },
    downloading: { cls: 'alarm', txt: `下载中 → ${n.target_version}` },
    restarting: { cls: 'alarm', txt: `重启中 → ${n.target_version}` },
    completed: { cls: 'online', txt: `已升级 ${n.target_version}` },
    failed: { cls: 'offline', txt: `升级失败` },
  };
  const info = map[n.upgrade_status] || { cls: '', txt: n.upgrade_status };
  const title = n.upgrade_message ? ` title="${esc(n.upgrade_message)}"` : '';
  return `<span class="badge ${info.cls}"${title}>${esc(info.txt)}</span>`;
}

function renderNodes(nodes) {
  const as = nodes.filter(n => n.role === 'agent_a');
  const bs = nodes.filter(n => n.role === 'agent_b');

  // Drop deleted IDs from selection sets.
  const aIDs = new Set(as.map(n => n.id));
  for (const id of selectedNodes.agent_a) if (!aIDs.has(id)) selectedNodes.agent_a.delete(id);
  const bIDs = new Set(bs.map(n => n.id));
  for (const id of selectedNodes.agent_b) if (!bIDs.has(id)) selectedNodes.agent_b.delete(id);

  document.getElementById('nodes-a-tbody').innerHTML = as.length ? as.map(n => {
    const ready = (n.availability || []).reduce((a, x) => a + x.ready_count, 0);
    const claimed = (n.availability || []).reduce((a, x) => a + x.claimed_count, 0);
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
        <td>${ready} 待下 / ${claimed} 传中</td>
        <td class="mono">${fmtSpeed(n.speed_bps)}</td>
        <td>
          <div class="btn-row">
            <button class="btn sm" data-action="view-node-live" data-id="${esc(n.id)}">实时队列</button>
            <button class="btn sm danger" data-action="delete-node" data-id="${esc(n.id)}">删除</button>
          </div>
        </td>
      </tr>
    `;
  }).join('') : '<tr><td colspan="8" class="empty">暂无注册的 A 节点</td></tr>';

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
        <td class="mono">${(n.projects && n.projects.length) ? esc(n.projects.join(', ')) : '全部'}</td>
        <td>${fmtBytes(n.disk_free_bytes)} <span class="muted">(${(n.disk_used_pct || 0).toFixed(1)}% 已用)</span></td>
        <td>${n.active_streams} 个任务</td>
        <td class="mono">${fmtSpeed(n.speed_bps)}</td>
        <td>
          <div class="btn-row">
            <button class="btn sm" data-action="open-b-script" data-id="${esc(n.id)}">安装脚本</button>
            <button class="btn sm danger" data-action="delete-node" data-id="${esc(n.id)}">删除</button>
          </div>
        </td>
      </tr>
    `;
  }).join('') : '<tr><td colspan="8" class="empty">暂无注册的 B 节点</td></tr>';

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
  populateReleaseSelect(document.getElementById('deploy-a-release-select'), 'agent_a', '自动匹配最新 agent_a 发布包');
  populateReleaseSelect(document.getElementById('b-script-release-select'), 'agent_b', '自动匹配最新 agent_b 发布包');

  const tbody = document.getElementById('releases-tbody');
  tbody.innerHTML = list.length ? list.map(r => `
    <tr>
      <td><span class="badge">${r.role === 'agent_a' ? 'A 节点' : 'B 节点'}</span></td>
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
  const form = document.getElementById('deploy-a-form');
  form.reset();
  document.getElementById('precheck-result').classList.add('hidden');
  document.getElementById('deploy-progress-box').classList.add('hidden');
  document.getElementById('deploy-force-wrap').classList.add('hidden');
  document.getElementById('deploy-force-chk').checked = false;
  document.getElementById('btn-confirm-deploy-a').disabled = true;
  populateReleaseSelect(document.getElementById('deploy-a-release-select'), 'agent_a', '自动匹配最新 agent_a 发布包');
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
    : (t.status === 'failed' ? `部署失败: ${t.error}` : `正在部署 (${t.step})...`);
  let tokHtml = '';
  if (t.local_token) {
    tokHtml = `
      <div class="token-box" style="margin-bottom:10px">
        <strong>请保存该 A 节点的本机上传密钥 X-Local-Token（仅展示一次）：</strong>
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

function startDeployPolling(taskId) {
  if (deployPollTimer) clearInterval(deployPollTimer);
  const box = document.getElementById('deploy-progress-box');
  const poll = async () => {
    try {
      const t = await api(`/api/v1/admin/deploy/tasks/${encodeURIComponent(taskId)}`);
      renderDeployTaskDetail(t, box);
      if (t.status !== 'running') {
        clearInterval(deployPollTimer);
        deployPollTimer = null;
        refreshAll();
      }
    } catch (e) {
      clearInterval(deployPollTimer);
      deployPollTimer = null;
    }
  };
  poll();
  deployPollTimer = setInterval(poll, 1000);
}

async function viewDeployTaskLog(taskId) {
  document.getElementById('live-modal-title').textContent = `部署任务日志: ${taskId.slice(0, 8)}`;
  const body = document.getElementById('live-modal-body');
  body.innerHTML = '<div class="empty">加载日志...</div>';
  openModal('live-modal');
  try {
    const t = await api(`/api/v1/admin/deploy/tasks/${encodeURIComponent(taskId)}`);
    renderDeployTaskDetail(t, body);
  } catch (e) {
    body.innerHTML = `<div class="err-msg">${esc(e.message)}</div>`;
  }
}

function openBScriptModal(nodeId, presetToken = '') {
  const form = document.getElementById('b-script-form');
  form.reset();
  form.elements.node_id.value = nodeId;
  form.elements.node_token.value = presetToken;
  document.getElementById('b-script-title').textContent = `内网 B 节点一键安装脚本: ${nodeId}`;
  document.getElementById('b-script-output').classList.add('hidden');
  document.getElementById('btn-copy-b-script').classList.add('hidden');
  populateReleaseSelect(document.getElementById('b-script-release-select'), 'agent_b', '自动匹配最新 agent_b 发布包');
  openModal('b-script-modal');
}

function setupEvents() {
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-action]');
    if (!btn) return;
    const id = btn.dataset.id || '';
    switch (btn.dataset.action) {
      case 'view-project-live': window.viewProjectLive(id); break;
      case 'delete-project': deleteProject(id); break;
      case 'view-node-live': window.viewNodeLive(id); break;
      case 'delete-node': deleteNode(id); break;
      case 'delete-release': deleteRelease(id); break;
      case 'view-deploy-task': viewDeployTaskLog(id); break;
      case 'open-b-script': openBScriptModal(id); break;
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
      await api('/api/v1/admin/overview');
      sessionStorage.setItem(STORAGE_KEY, adminToken);
      hideLogin();
      refreshAll();
    } catch {
      adminToken = '';
    }
  };
  document.getElementById('login-form').addEventListener('submit', doLogin);

  document.getElementById('logout-btn').addEventListener('click', () => {
    adminToken = '';
    sessionStorage.removeItem(STORAGE_KEY);
    document.getElementById('login-token').value = '';
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

  const openNodeModal = (role) => {
    const form = document.getElementById('create-node-form');
    form.reset();
    form.elements.role.value = role;
    document.getElementById('node-modal-title').textContent = role === 'agent_a' ? '手动注册公网 A 节点' : '注册内网 B 节点';
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
    const role = fd.get('role');
    try {
      const res = await api('/api/v1/admin/nodes', {
        method: 'POST',
        body: JSON.stringify({
          id: fd.get('id'),
          name: fd.get('name'),
          role,
          public_addr: fd.get('public_addr'),
          projects: projs,
        }),
      });
      const box = document.getElementById('node-token-result');
      const extraBtn = role === 'agent_b'
        ? `<div style="margin-top:8px"><button type="button" class="btn sm primary" id="btn-gen-b-after-create">生成一键安装脚本</button></div>`
        : '';
      box.innerHTML = `<strong>节点已创建！请妥善保存接入 Token（仅展示一次）：</strong><div class="mono" style="margin-top:6px">${esc(res.token)}</div>${extraBtn}`;
      box.classList.remove('hidden');
      if (role === 'agent_b') {
        document.getElementById('btn-gen-b-after-create').addEventListener('click', () => {
          closeModal('node-modal');
          openBScriptModal(res.node.id, res.token);
        });
      }
      refreshAll();
    } catch (err) {
      if (err.message !== 'unauthorized') alert(`创建节点失败: ${err.message}`);
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
      msgEl.textContent = `上传成功: ${rel.role} ${rel.version} (${rel.os}/${rel.arch}, ${fmtBytes(rel.size)})`;
      e.target.reset();
      refreshAll();
    } catch (err) {
      msgEl.textContent = '';
      if (err.message !== 'unauthorized') alert(`上传发布包失败: ${err.message}`);
    }
  });

  // One-click Deploy A wizard
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
      startDeployPolling(task.id);
    } catch (err) {
      if (err.message !== 'unauthorized') alert(`启动部署失败: ${err.message}`);
      document.getElementById('btn-confirm-deploy-a').disabled = false;
    }
  });

  // Agent B Install Script generator
  let lastBScript = '';
  document.getElementById('b-script-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const projects = {};
    String(fd.get('projects_map') || '').split('\n').forEach(line => {
      const trimmed = line.trim();
      if (!trimmed || !trimmed.includes('=')) return;
      const idx = trimmed.indexOf('=');
      const k = trimmed.slice(0, idx).trim();
      const v = trimmed.slice(idx + 1).trim();
      if (k && v) projects[k] = v;
    });
    try {
      const res = await api('/api/v1/admin/deploy/agent-b-script', {
        method: 'POST',
        body: JSON.stringify({
          node_id: fd.get('node_id'),
          node_token: fd.get('node_token'),
          rotate_token: fd.get('rotate_token') === 'on',
          install_dir: fd.get('install_dir'),
          state_dir: fd.get('state_dir'),
          release_id: fd.get('release_id'),
          projects,
        }),
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
