'use strict';
// ══════════════════════════════════════════════════
// CheckVibe — Frontend App
// ══════════════════════════════════════════════════

// ── Auth state + nav rendering ──
function getAuthSlot() { return document.getElementById('navAuthSlot'); }

function updateNavAuth() {
  const slot = getAuthSlot();
  if (!slot) return;
  const user = window.sb?.auth?.getUser();
  if (user) {
    slot.innerHTML = `
      <span class="nav-user">${esc(user.email || user.user_metadata?.full_name || 'Account')}</span>
      <button class="btn btn-ghost nav-btn" onclick="window.sb.auth.signOut().then(()=>updateNavAuth())">Sign out</button>`;
  } else {
    slot.innerHTML = `<a href="/login" class="nav-cta">Sign in</a>`;
  }
}

// Listen for auth changes (Supabase fires onAuthStateChange)
if (window.sb) {
  window.sb.auth.onAuthStateChange(() => updateNavAuth());
}
// Fallback: poll for late SDK load
const authPoll = setInterval(() => {
  if (window.sb) { clearInterval(authPoll); window.sb.auth.onAuthStateChange(() => updateNavAuth()); updateNavAuth(); }
}, 500);
setTimeout(() => clearInterval(authPoll), 5000);
// Run immediately in case DOM already has the slot
document.addEventListener('DOMContentLoaded', updateNavAuth);

// ── Close modal on overlay click (only if modal exists on this page) ──
(function() {
  const overlay = document.getElementById('modalOverlay');
  if (!overlay) return;
  overlay.addEventListener('click', e => { if (e.target === e.currentTarget) closeModal(); });
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });
})();
function closeModal() {
  const m = document.getElementById('modalOverlay');
  if (m) m.classList.remove('open');
}

// ── Scan entry point ──
async function runScan(e) {
  e.preventDefault();
  let url = document.getElementById('scanUrl').value.trim();
  if (!url) return false;
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
  document.getElementById('scanUrl').value = url;

  const btn = document.getElementById('scanBtn');
  btn.disabled = true;
  btn.innerHTML = `<div style="width:16px;height:16px;border:2px solid rgba(0,0,0,0.3);border-top-color:#000;border-radius:50%;animation:spin .7s linear infinite"></div> Scanning…`;

  showLoadingUI(url);
  document.getElementById('modalOverlay').classList.add('open');

  const stages = [
    { id: 's0', label: '🔒 SSL / TLS' },
    { id: 's1', label: '🛡️ Security Headers' },
    { id: 's2', label: '💉 Injection Tests' },
    { id: 's3', label: '📁 Exposed Files' },
    { id: 's4', label: '🌐 DNS & Email' },
    { id: 's5', label: '🔑 Authentication' },
    { id: 's6', label: '🚀 Performance' },
    { id: 's7', label: '🔍 SEO Analysis' },
    { id: 's8', label: '🔗 Supply Chain' },
    { id: 's9', label: '📊 API Security' },
    { id: 's10', label: '♿ Accessibility' },
    { id: 's11', label: '🔐 Privacy / GDPR' },
  ];
  let si = 0;
  const ticker = setInterval(() => {
    if (si < stages.length) {
      if (si > 0) setStage(stages[si - 1].id, 'done');
      setStage(stages[si].id, 'active');
      setProgress(((si + 1) / stages.length) * 90);
      si++;
    }
  }, 900);

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    const data = await res.json();
    clearInterval(ticker);
    stages.forEach(s => setStage(s.id, 'done'));
    setProgress(100);
    setTimeout(() => renderResults(data), 400);
  } catch (err) {
    clearInterval(ticker);
    document.getElementById('scanResults').innerHTML = `
      <div style="padding:40px;text-align:center">
        <div style="font-size:48px;margin-bottom:16px">⚠️</div>
        <div style="font-size:18px;font-weight:700;margin-bottom:8px">Scan Failed</div>
        <div style="color:var(--text2)">${err.message}</div>
        <button class="btn" style="margin-top:24px" onclick="closeModal()">Close</button>
      </div>`;
  }

  btn.disabled = false;
  btn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg> Deep Scan`;
  return false;
}

// ── Loading screen ──
function showLoadingUI(url) {
  document.getElementById('scanResults').innerHTML = `
    <div class="scan-loading">
      <div class="loading-spinner"></div>
      <div class="loading-title">Scanning ${esc(url)}</div>
      <div class="loading-sub" id="loadSub">Running 150+ security checks...</div>
      <div class="progress-bar"><div class="progress-fill" id="progressFill"></div></div>
      <div class="stage-grid">
        <div class="stage" id="s0">🔒 SSL/TLS</div>
        <div class="stage" id="s1">🛡️ Headers</div>
        <div class="stage" id="s2">💉 Injections</div>
        <div class="stage" id="s3">📁 Files</div>
        <div class="stage" id="s4">🌐 DNS</div>
        <div class="stage" id="s5">🔑 Auth</div>
        <div class="stage" id="s6">⚡ Performance</div>
        <div class="stage" id="s7">🔍 SEO</div>
        <div class="stage" id="s8">🔗 Supply Chain</div>
        <div class="stage" id="s9">📊 API</div>
        <div class="stage" id="s10">♿ Accessibility</div>
        <div class="stage" id="s11">🔐 Privacy</div>
      </div>
    </div>`;
}

function setStage(id, state) {
  const el = document.getElementById(id);
  if (!el) return;
  el.className = 'stage ' + state;
  if (state === 'done') el.innerHTML = el.innerHTML.replace('<span class="stage-dot"></span>', '✓ ');
  if (state === 'active') document.getElementById('loadSub').textContent = 'Running: ' + el.textContent.trim() + '…';
}

function setProgress(pct) {
  const el = document.getElementById('progressFill');
  if (el) el.style.width = pct + '%';
}

// ── Score colour ──
function scoreColor(s) {
  if (s >= 80) return 'var(--green)';
  if (s >= 60) return 'var(--yellow)';
  if (s >= 40) return 'var(--orange)';
  return 'var(--red)';
}

// ── Severity colour helpers ──
const sevColor = { critical: 'var(--red)', high: 'var(--orange)', medium: 'var(--yellow)', low: 'var(--blue)' };
const sevBg = { critical: 'rgba(248,113,113,.12)', high: 'rgba(251,146,60,.12)', medium: 'rgba(250,204,21,.12)', low: 'rgba(96,165,250,.12)' };
const sevBorder = { critical: 'rgba(248,113,113,.3)', high: 'rgba(251,146,60,.3)', medium: 'rgba(250,204,21,.3)', low: 'rgba(96,165,250,.3)' };

// ── HTML escape ──
function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ── Main render ──
// renderReport renders a full scan report into any container.
// Shared by the landing-page modal AND the /scan detail page (no duplication).
function renderReport(data, container) {
  if (!container) container = document.getElementById('scanResults');
  const sc = scoreColor(data.score);
  const cats = Object.keys(data.categories || {});

  // Category score breakdown
  const catScores = cats.map(cat => {
    const items = data.categories[cat];
    const passed = items.filter(i => i.passed).length;
    const pct = items.length ? Math.round((passed / items.length) * 100) : 100;
    return { cat, pct, total: items.length, passed, failed: items.length - passed };
  }).sort((a, b) => a.pct - b.pct);

  const categoryBars = catScores.map(c => `
    <div class="cat-bar-item">
      <div class="cat-bar-label">
        <span>${esc(c.cat)}</span>
        <span style="color:${scoreColor(c.pct)};font-weight:700">${c.pct}</span>
      </div>
      <div class="cat-bar-track">
        <div class="cat-bar-fill" style="width:${c.pct}%;background:${scoreColor(c.pct)}"></div>
      </div>
      <div class="cat-bar-meta">${c.failed} fail · ${c.passed} pass · ${c.total} total</div>
    </div>`).join('');

  // Issues table rows
  const rows = (data.issues || []).map((issue, idx) => `
    <tr class="issue-row" data-sev="${issue.severity}" data-cat="${esc(issue.cat)}" data-pass="${issue.passed}">
      <td><span class="sev-tag ${issue.severity}">${issue.severity}</span></td>
      <td><span class="cat-tag">${esc(issue.cat || '')}</span></td>
      <td class="issue-title">${esc(issue.title)}</td>
      <td class="issue-desc">${esc(issue.description)}</td>
      <td class="${issue.passed ? 'pass-cell' : 'fail-cell'}">${issue.passed ? '✓' : '✗'}</td>
      ${issue.fix ? `<td><button class="fix-btn" onclick="toggleFix(${idx})">Fix</button></td>` : '<td></td>'}
    </tr>
    ${issue.fix ? `<tr class="fix-row" id="fix-${idx}" style="display:none">
      <td colspan="6" class="fix-td">
        <div class="fix-block">
          <div class="fix-block-header">
            <span>Recommended Fix</span>
            <button class="copy-btn" onclick="copyFix(${idx})">Copy</button>
          </div>
          <pre class="fix-pre" id="fix-code-${idx}">${esc(issue.fix)}</pre>
        </div>
      </td>
    </tr>` : ''}
  `).join('');

  container.innerHTML = `
    <div class="results-header">
      <div>
        <div class="results-title">Scan Complete</div>
        <div class="results-url">${esc(data.url)}</div>
      </div>
      <div class="header-actions">
        <button class="btn btn-green" onclick="exportJSON()">⬇ JSON</button>
        <button class="btn btn-green" onclick="exportReport()">⬇ Report</button>
        ${document.getElementById('modalOverlay') ? '<button class="btn btn-close" onclick="closeModal()" title="Close">✕</button>' : ''}
      </div>
    </div>

    <div class="score-row">
      <div class="score-circle" style="border-color:${sc}">
        <div class="score-num" style="color:${sc}">${data.score}</div>
        <div class="score-label">SCORE</div>
      </div>
      <div class="score-stats">
        <div class="stat-item"><div class="stat-num">${data.totalChecks}</div><div class="stat-desc">Total Checks</div></div>
        <div class="stat-item"><div class="stat-num" style="color:var(--green)">${data.passedChecks}</div><div class="stat-desc">Passed</div></div>
        <div class="stat-item"><div class="stat-num" style="color:var(--red)">${data.failedChecks}</div><div class="stat-desc">Failed</div></div>
        <div class="stat-item"><div class="stat-num" style="color:var(--text2)">${data.responseTime}ms</div><div class="stat-desc">Response</div></div>
        <div class="stat-item"><div class="stat-num" style="color:var(--text2)">${(data.pageSize / 1024).toFixed(1)}KB</div><div class="stat-desc">Page Size</div></div>
      </div>
      <div class="sev-badges">
        <div class="sev-badge critical"><div class="sn">${data.severityCounts.critical}</div><div class="sl">Critical</div></div>
        <div class="sev-badge high"><div class="sn">${data.severityCounts.high}</div><div class="sl">High</div></div>
        <div class="sev-badge medium"><div class="sn">${data.severityCounts.medium}</div><div class="sl">Medium</div></div>
        <div class="sev-badge low"><div class="sn">${data.severityCounts.low}</div><div class="sl">Low</div></div>
      </div>
    </div>

    <div class="results-body">
      <div class="results-sidebar">
        <div class="sidebar-section">
          <div class="sidebar-title">Category Scores</div>
          <div class="cat-bars">${categoryBars}</div>
        </div>
        <div class="sidebar-section">
          <div class="sidebar-title">Quick Stats</div>
          <div class="meta-list">
            <div class="meta-row"><span>Status Code</span><span class="${data.statusCode === 200 ? 'val-ok' : 'val-warn'}">${data.statusCode}</span></div>
            <div class="meta-row"><span>Server</span><span class="val-mono">${esc(data.server || 'Hidden')}</span></div>
            <div class="meta-row"><span>Scan Time</span><span>${new Date(data.scannedAt).toLocaleTimeString()}</span></div>
            <div class="meta-row"><span>Fixes Available</span><span style="color:var(--green)">${(data.fixPrompts || []).length}</span></div>
          </div>
        </div>
      </div>

      <div class="results-main">
        <div class="tab-bar">
          <button class="tab active" onclick="switchTab('all',this)">All (${data.totalChecks})</button>
          <button class="tab" onclick="switchTab('failed',this)">Failed (${data.failedChecks})</button>
          <button class="tab" onclick="switchTab('critical',this)">🔴 Critical (${data.severityCounts.critical})</button>
          <button class="tab" onclick="switchTab('high',this)">🟠 High (${data.severityCounts.high})</button>
          <button class="tab" onclick="switchTab('medium',this)">🟡 Medium (${data.severityCounts.medium})</button>
          <button class="tab" onclick="switchTab('fixes',this)">🔧 Fixes (${(data.fixPrompts || []).length})</button>
        </div>

        <div id="tab-all" class="tab-content active">
          <div class="filter-row">
            <input class="search-input" type="text" placeholder="Search checks…" oninput="filterTable(this.value)">
            <select class="cat-select" onchange="filterByCat(this.value)">
              <option value="">All Categories</option>
              ${cats.map(c => `<option value="${esc(c)}">${esc(c)}</option>`).join('')}
            </select>
          </div>
          <div class="table-wrap">
            <table class="issues-table" id="issuesTable">
              <thead><tr><th>Severity</th><th>Category</th><th>Check</th><th>Description</th><th>Status</th><th>Fix</th></tr></thead>
              <tbody id="issuesTbody">${rows}</tbody>
            </table>
          </div>
        </div>

        <div id="tab-failed" class="tab-content" style="display:none">
          <div class="table-wrap">
            <table class="issues-table">
              <thead><tr><th>Severity</th><th>Category</th><th>Check</th><th>Description</th><th>Fix</th></tr></thead>
              <tbody>${buildFilteredRows(data.issues, i => !i.passed, true)}</tbody>
            </table>
          </div>
        </div>

        <div id="tab-critical" class="tab-content" style="display:none">
          <div class="table-wrap"><table class="issues-table">
            <thead><tr><th>Category</th><th>Check</th><th>Description</th><th>Fix</th></tr></thead>
            <tbody>${buildCriticalRows(data.issues, 'critical')}</tbody>
          </table></div>
        </div>

        <div id="tab-high" class="tab-content" style="display:none">
          <div class="table-wrap"><table class="issues-table">
            <thead><tr><th>Category</th><th>Check</th><th>Description</th><th>Fix</th></tr></thead>
            <tbody>${buildCriticalRows(data.issues, 'high')}</tbody>
          </table></div>
        </div>

        <div id="tab-medium" class="tab-content" style="display:none">
          <div class="table-wrap"><table class="issues-table">
            <thead><tr><th>Category</th><th>Check</th><th>Description</th><th>Fix</th></tr></thead>
            <tbody>${buildCriticalRows(data.issues, 'medium')}</tbody>
          </table></div>
        </div>

        <div id="tab-fixes" class="tab-content" style="display:none">
          ${buildFixCards(data.fixPrompts || [])}
        </div>
      </div>
    </div>`;

  // Store data globally for export
  window._lastScanData = data;
}

// Landing-page modal wrapper — renders into #scanResults, then offers to save.
function renderResults(data) {
  renderReport(data, document.getElementById('scanResults'));
  offerSave(data);
}

// ── Save-after-scan prompt ──
function offerSave(data) {
  if (!window.sb) return; // no-op when Supabase not configured
  const user = window.sb.auth?.getUser();
  if (!user) return; // only offer to signed-in users
  const container = document.getElementById('savePrompt');
  if (!container) return;
  container.style.display = '';
  container.innerHTML = `
    <div class="save-prompt">
      <span>💾 Save this scan to your history?</span>
      <div style="display:flex;gap:8px;margin-top:8px">
        <button class="btn btn-primary" id="saveScanBtn">Save</button>
        <button class="btn btn-ghost" id="skipSaveBtn">Skip</button>
      </div>
    </div>`;
  document.getElementById('saveScanBtn').onclick = () => saveScan(data);
  document.getElementById('skipSaveBtn').onclick = () => { container.style.display = 'none'; };
}

async function saveScan(data) {
  const container = document.getElementById('savePrompt');
  if (!window.sb) return;
  try {
    const { error } = await window.sb.from('scans').insert({
      user_id: window.sb.auth.getUser().id,
      url: data.url,
      score: data.score,
      total_checks: data.totalChecks,
      passed_checks: data.passedChecks,
      failed_checks: data.failedChecks,
      severity_counts: data.severityCounts,
      result: data,
      scanned_at: data.scannedAt,
    });
    if (error) throw error;
    container.innerHTML = `<div class="save-prompt" style="color:var(--green)">✓ Scan saved to <a href="/dashboard">Dashboard</a></div>`;
  } catch (err) {
    container.innerHTML = `<div class="save-prompt" style="color:var(--red)">Save failed: ${esc(err.message)}</div>`;
  }
}

// ── Build helper: filtered rows for failed/severity tabs ──
function buildFilteredRows(issues, filterFn, skipSev = false) {
  return issues.filter(filterFn).map((issue, idx) => `
    <tr>
      ${skipSev ? '' : `<td><span class="sev-tag ${issue.severity}">${issue.severity}</span></td>`}
      <td><span class="cat-tag">${esc(issue.cat || '')}</span></td>
      <td class="issue-title">${esc(issue.title)}</td>
      <td class="issue-desc">${esc(issue.description)}</td>
      <td>${issue.fix ? `<button class="fix-btn" onclick="showInlineFixFailed(this,'${esc(issue.fix).replace(/'/g, "&#39;")}')">Fix</button>` : ''}</td>
    </tr>
    <tr class="fix-row-inline" style="display:none">
      <td colspan="5">
        <div class="fix-block">
          <div class="fix-block-header"><span>Fix</span><button class="copy-btn" onclick="copyFromPre(this)">Copy</button></div>
          <pre class="fix-pre">${esc(issue.fix || '')}</pre>
        </div>
      </td>
    </tr>`).join('');
}

function buildCriticalRows(issues, sev) {
  return buildFilteredRows(issues.filter(i => i.severity === sev && !i.passed), () => true, true);
}

// ── Fix cards in the Fixes tab ──
function buildFixCards(fixPrompts) {
  if (!fixPrompts.length) return `<div style="padding:40px;text-align:center;color:var(--text2)">No fix recommendations — or no issues found with fixes.</div>`;
  return `<div class="fix-cards">${fixPrompts.map((f, i) => `
    <div class="fix-card">
      <div class="fix-card-head">
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
          <span class="sev-tag ${f.severity}">${f.severity}</span>
          <span class="cat-tag">${esc(f.cat || '')}</span>
          <span class="fix-card-title">${esc(f.title)}</span>
        </div>
        <button class="copy-btn" onclick="copyFromId('fxc-${i}')">Copy</button>
      </div>
      <div class="fix-card-desc">${esc(f.description)}</div>
      ${f.fix ? `<pre class="fix-pre" id="fxc-${i}">${esc(f.fix)}</pre>` : ''}
    </div>`).join('')}</div>`;
}

// ── Tab switching ──
function switchTab(id, btn) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => { t.style.display = 'none'; t.classList.remove('active'); });
  btn.classList.add('active');
  const el = document.getElementById('tab-' + id);
  if (el) { el.style.display = ''; el.classList.add('active'); }
}

// ── Table filter ──
function filterTable(q) {
  const rows = document.querySelectorAll('#issuesTbody .issue-row');
  const ql = q.toLowerCase();
  rows.forEach(row => {
    const text = row.textContent.toLowerCase();
    row.style.display = text.includes(ql) ? '' : 'none';
    const fixRow = row.nextElementSibling;
    if (fixRow && fixRow.classList.contains('fix-row')) fixRow.style.display = 'none';
  });
}

function filterByCat(cat) {
  const rows = document.querySelectorAll('#issuesTbody .issue-row');
  rows.forEach(row => {
    const show = !cat || row.dataset.cat === cat;
    row.style.display = show ? '' : 'none';
    const fixRow = row.nextElementSibling;
    if (fixRow && fixRow.classList.contains('fix-row')) fixRow.style.display = 'none';
  });
}

// ── Toggle inline fix ──
function toggleFix(idx) {
  const row = document.getElementById('fix-' + idx);
  if (!row) return;
  row.style.display = row.style.display === 'none' ? '' : 'none';
}

function showInlineFixFailed(btn, fixCode) {
  const tr = btn.closest('tr');
  const next = tr.nextElementSibling;
  if (next && next.classList.contains('fix-row-inline')) {
    next.style.display = next.style.display === 'none' ? '' : 'none';
  }
}

// ── Copy helpers ──
async function copyFix(idx) {
  const el = document.getElementById('fix-code-' + idx);
  if (!el) return;
  await copyText(el.textContent, document.querySelector(`#fix-${idx} .copy-btn`));
}

async function copyFromId(id) {
  const el = document.getElementById(id);
  if (!el) return;
  await copyText(el.textContent, document.querySelector(`#${id} ~ .fix-block-header .copy-btn`) || null);
}

async function copyFromPre(btn) {
  const pre = btn.closest('.fix-block').querySelector('.fix-pre');
  if (pre) await copyText(pre.textContent, btn);
}

async function copyText(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
    if (btn) { const orig = btn.textContent; btn.textContent = 'Copied!'; btn.style.background = 'var(--green)'; btn.style.color = '#000'; setTimeout(() => { btn.textContent = orig; btn.style.background = ''; btn.style.color = ''; }, 2000); }
  } catch { }
}

// ── Export JSON ──
function exportJSON() {
  if (!window._lastScanData) return;
  const blob = new Blob([JSON.stringify(window._lastScanData, null, 2)], { type: 'application/json' });
  download(blob, `vulnscan-${Date.now()}.json`);
}

// ── Export plain-text report ──
function exportReport() {
  const d = window._lastScanData;
  if (!d) return;
  const lines = [
    '═══════════════════════════════════════════════════',
    '  VULNSCAN PRO — SECURITY SCAN REPORT',
    '═══════════════════════════════════════════════════',
    `  URL:     ${d.url}`,
    `  Scanned: ${new Date(d.scannedAt).toLocaleString()}`,
    `  Score:   ${d.score}/100`,
    `  Checks:  ${d.totalChecks} total · ${d.passedChecks} passed · ${d.failedChecks} failed`,
    '',
    '  SEVERITY SUMMARY',
    '  ─────────────────',
    `  Critical : ${d.severityCounts.critical}`,
    `  High     : ${d.severityCounts.high}`,
    `  Medium   : ${d.severityCounts.medium}`,
    `  Low      : ${d.severityCounts.low}`,
    '',
    '  FAILED CHECKS',
    '  ─────────────────',
    ...d.issues.filter(i => !i.passed).map((i, n) =>
      `\n  ${n + 1}. [${i.severity.toUpperCase()}] [${i.cat}] ${i.title}\n     ${i.description}`
    ),
    '',
    '  FIX RECOMMENDATIONS',
    '  ─────────────────────',
    ...(d.fixPrompts || []).map((f, n) =>
      `\n  ${n + 1}. [${f.severity.toUpperCase()}] ${f.title}\n     ${f.description}\n\n${f.fix ? f.fix.split('\n').map(l => '     ' + l).join('\n') : ''}`
    ),
    '',
    '═══════════════════════════════════════════════════',
    '  Generated by VulnScan Pro · vulnscan.local',
    '═══════════════════════════════════════════════════',
  ];
  download(new Blob([lines.join('\n')], { type: 'text/plain' }), `vulnscan-report-${Date.now()}.txt`);
}

function download(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
