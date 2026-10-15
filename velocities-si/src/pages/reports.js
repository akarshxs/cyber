/**
 * pages/reports.js — Reports and audit with filtering, JSON/CSV export,
 * printable HTML report with XSS-safe rendering.
 */
'use strict';

import { getMeta, getPrefs } from '../modules/store.js';
import { esc, formatTs, relativeTime, icon, showToast, downloadBlob } from '../modules/ui.js';
import { scoreToBand } from '../modules/risk.js';
import { eventsToCSV, toCSVLine } from '../modules/ingest.js';

const PAGE_SIZE = 50;
let _state = { search: '', category: 'all', incidentId: 'all', page: 1, dateFrom: '', dateTo: '' };

export function renderReports(container) {
  const meta = getMeta();
  const prefs = getPrefs();

  let log = [...meta.auditLog];

  // Filters
  const search = _state.search.toLowerCase();
  if (search) log = log.filter(a => [a.action, a.entity, a.actor, a.category].some(v => String(v||'').toLowerCase().includes(search)));
  if (_state.category !== 'all') log = log.filter(a => a.category === _state.category);
  if (_state.incidentId !== 'all') log = log.filter(a => a.entity === _state.incidentId || a.details?.includes(_state.incidentId));
  if (_state.dateFrom) log = log.filter(a => new Date(a.ts) >= new Date(_state.dateFrom));
  if (_state.dateTo) log = log.filter(a => new Date(a.ts) <= new Date(_state.dateTo + 'T23:59:59'));

  const total = log.length;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  if (_state.page > totalPages) _state.page = totalPages;
  const paged = log.slice((_state.page - 1) * PAGE_SIZE, _state.page * PAGE_SIZE);

  const categories = [...new Set(meta.auditLog.map(a => a.category).filter(Boolean))];
  const incidents = meta.incidents;

  container.innerHTML = `
    <section class="panel" aria-labelledby="reports-heading">
      <div class="panel-head">
        <h2 id="reports-heading">Audit log &amp; reports</h2>
        <div class="panel-actions">
          <button class="btn-secondary btn-sm" data-action="export-log-json">${icon('export')} Export JSON</button>
          <button class="btn-secondary btn-sm" data-action="export-log-csv">${icon('export')} Export CSV</button>
          <button class="btn-secondary btn-sm" data-action="print-report">${icon('reports')} Print report</button>
        </div>
      </div>

      <div class="info-box small">
        <strong>Scope notice:</strong> This is browser-local session history. It is editable by anyone with device access and is not a tamper-evident or authenticated production audit trail.
      </div>

      <div class="toolbar">
        <div class="search-wrap">
          ${icon('search')}
          <input type="search" id="rep-search" class="search-input" placeholder="Search audit log…" value="${esc(_state.search)}" aria-label="Search audit log">
        </div>
        <select id="rep-category" class="select-sm" aria-label="Filter by category">
          <option value="all">All categories</option>
          ${categories.map(c => `<option value="${esc(c)}" ${_state.category === c ? 'selected' : ''}>${esc(c)}</option>`).join('')}
        </select>
        <select id="rep-incident" class="select-sm" aria-label="Filter by incident">
          <option value="all">All incidents</option>
          ${incidents.map(i => `<option value="${esc(i.id)}" ${_state.incidentId === i.id ? 'selected' : ''}>${esc(i.id)}</option>`).join('')}
        </select>
        <div class="date-range">
          <input type="date" id="rep-date-from" class="input-sm" value="${esc(_state.dateFrom)}" aria-label="From date">
          <span class="muted">to</span>
          <input type="date" id="rep-date-to" class="input-sm" value="${esc(_state.dateTo)}" aria-label="To date">
        </div>
      </div>

      <div class="table-wrap" tabindex="0">
        <table aria-label="Audit log">
          <thead>
            <tr>
              <th>TIME</th>
              <th>ACTOR</th>
              <th>CATEGORY</th>
              <th>ACTION</th>
              <th>ENTITY</th>
            </tr>
          </thead>
          <tbody>
            ${paged.length ? paged.map(a => `
              <tr>
                <td><time datetime="${esc(a.ts)}" title="${esc(a.ts)}">${new Date(a.ts).toLocaleString()}</time></td>
                <td>${esc(a.actor)}</td>
                <td><span class="category-badge">${esc(a.category || 'general')}</span></td>
                <td>${esc(a.action)}</td>
                <td class="mono-sm">${esc(a.entity)}</td>
              </tr>`).join('') : `<tr><td colspan="5" class="empty-cell">No audit entries match the current filters.</td></tr>`}
          </tbody>
        </table>
      </div>

      <div class="pagination">
        <span class="result-count">${total} entries</span>
        <div class="pg-controls">
          <button class="pg-btn" data-pg-rep="first" ${_state.page === 1 ? 'disabled' : ''}>«</button>
          <button class="pg-btn" data-pg-rep="prev" ${_state.page === 1 ? 'disabled' : ''}>‹</button>
          <span class="pg-label">Page ${_state.page} of ${totalPages}</span>
          <button class="pg-btn" data-pg-rep="next" ${_state.page === totalPages ? 'disabled' : ''}>›</button>
          <button class="pg-btn" data-pg-rep="last" ${_state.page === totalPages ? 'disabled' : ''}>»</button>
        </div>
      </div>
    </section>

    <!-- Incident summary report -->
    <section class="panel" aria-labelledby="inc-summary-heading">
      <div class="panel-head">
        <h2 id="inc-summary-heading">Incident summary</h2>
        <button class="btn-secondary btn-sm" data-action="export-incidents-csv">${icon('export')} Export incidents CSV</button>
      </div>
      <div class="table-wrap" tabindex="0">
        <table aria-label="Incident summary">
          <thead>
            <tr><th>ID</th><th>TITLE</th><th>STATUS</th><th>PRIORITY</th><th>RISK</th><th>CREATED</th><th>UPDATED</th></tr>
          </thead>
          <tbody>
            ${incidents.length ? incidents.map(i => {
              const { band } = scoreToBand(i.risk);
              return `<tr>
                <td class="mono-sm">${esc(i.id)}</td>
                <td>${esc(i.title)}</td>
                <td>${esc(i.status)}</td>
                <td>${esc(i.priority)}</td>
                <td><span class="text-${band}">${i.risk}</span></td>
                <td>${new Date(i.createdAt).toLocaleDateString()}</td>
                <td>${new Date(i.updatedAt).toLocaleDateString()}</td>
              </tr>`;
            }).join('') : `<tr><td colspan="7" class="empty-cell">No incidents.</td></tr>`}
          </tbody>
        </table>
      </div>
    </section>
  `;

  bindReportHandlers(container, log, incidents);
}

function bindReportHandlers(container, log, incidents) {
  container.querySelector('#rep-search')?.addEventListener('input', e => { _state.search = e.target.value; _state.page = 1; renderReports(container); });
  container.querySelector('#rep-category')?.addEventListener('change', e => { _state.category = e.target.value; _state.page = 1; renderReports(container); });
  container.querySelector('#rep-incident')?.addEventListener('change', e => { _state.incidentId = e.target.value; _state.page = 1; renderReports(container); });
  container.querySelector('#rep-date-from')?.addEventListener('change', e => { _state.dateFrom = e.target.value; _state.page = 1; renderReports(container); });
  container.querySelector('#rep-date-to')?.addEventListener('change', e => { _state.dateTo = e.target.value; _state.page = 1; renderReports(container); });

  container.querySelectorAll('[data-pg-rep]').forEach(btn => {
    btn.addEventListener('click', () => {
      const totalPages = Math.max(1, Math.ceil(log.length / PAGE_SIZE));
      if (btn.dataset.pgRep === 'first') _state.page = 1;
      if (btn.dataset.pgRep === 'prev') _state.page = Math.max(1, _state.page - 1);
      if (btn.dataset.pgRep === 'next') _state.page = Math.min(totalPages, _state.page + 1);
      if (btn.dataset.pgRep === 'last') _state.page = totalPages;
      renderReports(container);
    });
  });

  container.querySelector('[data-action="export-log-json"]')?.addEventListener('click', () => {
    downloadBlob(JSON.stringify({ notice: 'Browser-local audit log export. Not tamper-evident.', log }, null, 2), 'vsi-audit-log.json', 'application/json');
    showToast('Audit log exported as JSON', 'success');
  });

  container.querySelector('[data-action="export-log-csv"]')?.addEventListener('click', () => {
    const headers = ['ts','actor','category','action','entity'];
    const lines = [headers.join(','), ...log.map(a => toCSVLine(headers.map(h => a[h] ?? '')))];
    downloadBlob(lines.join('\n'), 'vsi-audit-log.csv', 'text/csv');
    showToast('Audit log exported as CSV', 'success');
  });

  container.querySelector('[data-action="export-incidents-csv"]')?.addEventListener('click', () => {
    const headers = ['id','title','status','priority','risk','host','user','ip','createdAt','updatedAt','owner'];
    const lines = [headers.join(','), ...incidents.map(i => toCSVLine(headers.map(h => i[h] ?? '')))];
    downloadBlob(lines.join('\n'), 'vsi-incidents.csv', 'text/csv');
    showToast('Incidents exported as CSV', 'success');
  });

  container.querySelector('[data-action="print-report"]')?.addEventListener('click', () => {
    printReport(log, incidents);
  });
}

function printReport(log, incidents) {
  const meta = getMeta();
  const now = new Date().toLocaleString();

  // Build safe HTML report (all user data escaped)
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Velocities SI — Incident Report ${esc(now)}</title>
<style>
body { font-family: system-ui, Arial, sans-serif; color: #111; background: #fff; margin: 32px; font-size: 14px; }
h1, h2, h3 { color: #1a2535; }
table { border-collapse: collapse; width: 100%; margin-bottom: 24px; }
th { background: #f0f3f7; text-align: left; padding: 8px; font-size: 11px; letter-spacing: 0.5px; }
td { padding: 8px; border-bottom: 1px solid #e0e5ee; font-size: 13px; }
.notice { background: #fff8e1; border: 1px solid #ffe082; padding: 12px; border-radius: 4px; margin-bottom: 24px; font-size: 12px; }
.critical { color: #c0392b; } .high { color: #d35400; } .medium { color: #7d6608; } .low { color: #1a7342; }
</style>
</head>
<body>
<h1>Velocities SI — Demo Incident Report</h1>
<div class="notice">
  <strong>Scope notice:</strong> This is a browser-local simulation export. Data is synthetic, not from real systems.
  All events, incidents, and decisions are simulated. This report is not tamper-evident or authenticated.
  Generated: ${esc(now)}
</div>

<h2>Incident Summary (${incidents.length})</h2>
<table>
<tr><th>ID</th><th>Title</th><th>Status</th><th>Priority</th><th>Risk</th><th>Host</th><th>User</th><th>Created</th></tr>
${incidents.map(i => `<tr>
  <td>${esc(i.id)}</td>
  <td>${esc(i.title)}</td>
  <td>${esc(i.status)}</td>
  <td class="${esc(i.priority)}">${esc(i.priority)}</td>
  <td class="${esc(i.priority)}">${i.risk}/100</td>
  <td>${esc(i.host)}</td>
  <td>${esc(i.user)}</td>
  <td>${new Date(i.createdAt).toLocaleString()}</td>
</tr>`).join('')}
</table>

<h2>Risk History</h2>
${incidents.map(i => `
<h3>${esc(i.id)}: ${esc(i.title)}</h3>
<table>
<tr><th>Time</th><th>Score</th><th>Previous</th><th>Rationale</th><th>Formula v</th></tr>
${i.riskHistory.map(h => `<tr>
  <td>${new Date(h.ts).toLocaleString()}</td>
  <td>${h.score}</td>
  <td>${h.before}</td>
  <td>${esc(h.rationale || '')}</td>
  <td>v${h.formulaVersion}</td>
</tr>`).join('')}
</table>`).join('')}

<h2>Audit Log (last 100 entries)</h2>
<table>
<tr><th>Time</th><th>Actor</th><th>Category</th><th>Action</th><th>Entity</th></tr>
${log.slice(0,100).map(a => `<tr>
  <td>${new Date(a.ts).toLocaleString()}</td>
  <td>${esc(a.actor)}</td>
  <td>${esc(a.category || '')}</td>
  <td>${esc(a.action)}</td>
  <td>${esc(a.entity)}</td>
</tr>`).join('')}
</table>

<p style="color:#888;font-size:11px;margin-top:32px">Generated by Velocities SI · Team Velocities · ABCS-03 · Browser-local simulation only</p>
</body>
</html>`;

  const w = window.open('', '_blank');
  if (!w) { showToast('Pop-up blocked. Allow pop-ups to print report.', 'error'); return; }
  w.document.write(html);
  w.document.close();
  setTimeout(() => w.print(), 500);
}
