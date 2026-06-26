'use strict';
// ══════════════════════════════════════════════════
// CheckVibe — Dashboard (scan history, stats, rescan)
// ══════════════════════════════════════════════════

(async function loadDashboard() {
  // Wait for Supabase SDK to settle
  await new Promise(r => setTimeout(r, 600));

  if (!window.sb) {
    document.getElementById('scanHistory').innerHTML =
      '<div class="empty-state"><h3>Auth not configured</h3><p>Connect Supabase in supabase-client.js to enable dashboard.</p></div>';
    return;
  }

  const user = window.sb.auth.getUser();
  if (!user) {
    window.location.href = '/login';
    return;
  }

  try {
    const { data: scans, error } = await window.sb
      .from('scans')
      .select('*')
      .eq('user_id', user.id)
      .order('scanned_at', { ascending: false })
      .limit(50);

    if (error) throw error;

    // Stats
    const total = scans.length;
    const avgScore = total ? Math.round(scans.reduce((s, sc) => s + sc.score, 0) / total) : 0;
    const totalCrit = scans.reduce((s, sc) => s + (sc.severity_counts?.critical || 0), 0);
    const totalHigh = scans.reduce((s, sc) => s + (sc.severity_counts?.high || 0), 0);

    document.getElementById('statTotal').textContent = total;
    document.getElementById('statAvg').textContent = total ? avgScore : '—';
    document.getElementById('statAvg').style.color = avgScore >= 80 ? 'var(--green)' : avgScore >= 60 ? 'var(--yellow)' : 'var(--red)';
    document.getElementById('statCrit').textContent = totalCrit;
    document.getElementById('statHigh').textContent = totalHigh;

    if (!total) return; // empty state already in HTML

    // Build table
    const rows = scans.map(sc => {
      const date = new Date(sc.scanned_at).toLocaleString();
      const scColor = sc.score >= 80 ? 'var(--green)' : sc.score >= 60 ? 'var(--yellow)' : sc.score >= 40 ? 'var(--orange)' : 'var(--red)';
      return `<tr>
        <td class="scan-url-cell" title="${esc(sc.url)}"><a href="/scan?url=${encodeURIComponent(sc.url)}" style="color:var(--text2);text-decoration:none">${esc(sc.url)}</a></td>
        <td class="scan-score-cell" style="color:${scColor}">${sc.score}</td>
        <td>${sc.failed_checks} / ${sc.total_checks}</td>
        <td class="scan-date-cell">${date}</td>
        <td><button class="btn btn-ghost rescan-btn" onclick="rescan('${esc(sc.url)}')">Rescan</button></td>
      </tr>`;
    }).join('');

    document.getElementById('scanHistory').innerHTML = `
      <div style="overflow-x:auto">
        <table class="scan-table">
          <thead><tr><th>URL</th><th>Score</th><th>Failed</th><th>Date</th><th></th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;
  } catch (err) {
    document.getElementById('scanHistory').innerHTML =
      `<div class="empty-state" style="color:var(--red)"><h3>Error loading scans</h3><p>${esc(err.message)}</p></div>`;
  }
})();

function rescan(url) {
  window.location.href = '/?scan=' + encodeURIComponent(url);
}
