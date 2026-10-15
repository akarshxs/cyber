/**
 * pages/detection.js — Detection rule catalog with searchable table,
 * evidence detail drawer, and run-replay capability.
 */
'use strict';

import { getMeta, getPrefs, idbGetById } from '../modules/store.js';
import { RULE_CATALOG } from '../modules/detection.js';
import { esc, severityBadge, formatTs, relativeTime, icon, showToast, openDialog } from '../modules/ui.js';

const PAGE_SIZE = 30;
let _state = { search: '', ruleId: 'all', severity: 'all', page: 1 };

export function renderDetection(container) {
  const meta = getMeta();
  const prefs = getPrefs();

  let detections = [...meta.detections];

  // Filter
  const search = _state.search.toLowerCase();
  if (search) detections = detections.filter(d => [d.id, d.ruleName, d.host, d.user, d.ip, d.explanation].some(v => String(v||'').toLowerCase().includes(search)));
  if (_state.ruleId !== 'all') detections = detections.filter(d => d.ruleId === _state.ruleId);
  if (_state.severity !== 'all') detections = detections.filter(d => d.severity === _state.severity);

  detections.sort((a, b) => new Date(b.ts) - new Date(a.ts));

  const total = detections.length;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  if (_state.page > totalPages) _state.page = totalPages;
  const paged = detections.slice((_state.page - 1) * PAGE_SIZE, _state.page * PAGE_SIZE);

  container.innerHTML = `
    <div class="split-layout">
      <!-- Rule catalog -->
      <section class="panel" aria-labelledby="rules-heading">
        <div class="panel-head">
          <h2 id="rules-heading">Detection rules</h2>
          <span class="tag">RULE ENGINE v1</span>
        </div>
        <p class="small muted">Versioned rules operate on normalized event windows. All rules run on simulator and imported events through the same pipeline. ML is not implemented; no accuracy, calibration, or latency claims are made.</p>
        <div class="rule-grid">
          ${RULE_CATALOG.map(r => `
            <article class="rule-card" aria-label="Rule ${esc(r.id)}: ${esc(r.name)}">
              <div class="rule-card-head">
                <span class="rule-id">${esc(r.id)} · ${esc(r.version)}</span>
                ${severityBadge(r.severity)}
              </div>
              <h3>${esc(r.name)}</h3>
              <p class="small">${esc(r.description)}</p>
              <div class="rule-meta">
                <span class="mitre-chip">${esc(r.mitreTechnique)}: ${esc(r.mitreName)}</span>
                <span class="muted small">${esc(r.windowMinutes || 5)} min window · threshold: ${prefs.ruleThresholds[r.thresholdKey] ?? r.defaultThreshold}</span>
              </div>
              <p class="small muted">MITRE mapping is a hypothesis; this rule has no calibrated false-positive rate.</p>
            </article>`).join('')}
        </div>
      </section>

      <!-- Detections table -->
      <section class="panel" aria-labelledby="det-heading">
        <div class="panel-head">
          <h2 id="det-heading">Detection log</h2>
          <span class="muted small">${total} detection${total !== 1 ? 's' : ''}</span>
        </div>

        <div class="toolbar">
          <div class="search-wrap">
            ${icon('search')}
            <input type="search" id="det-search" class="search-input" placeholder="Search detections…" value="${esc(_state.search)}" aria-label="Search detections">
          </div>
          <select id="det-rule-filter" class="select-sm" aria-label="Filter by rule">
            <option value="all">All rules</option>
            ${RULE_CATALOG.map(r => `<option value="${esc(r.id)}" ${_state.ruleId === r.id ? 'selected' : ''}>${esc(r.id)}: ${esc(r.name)}</option>`).join('')}
          </select>
          <select id="det-severity-filter" class="select-sm" aria-label="Filter by severity">
            <option value="all">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>

        <div class="table-wrap" tabindex="0">
          <table aria-label="Detection log">
            <thead>
              <tr>
                <th>DETECTION ID</th>
                <th>TIME</th>
                <th>RULE</th>
                <th>HOST / USER</th>
                <th>SEVERITY</th>
                <th>MATCHED</th>
                <th>INCIDENT</th>
                <th>DETAIL</th>
              </tr>
            </thead>
            <tbody>
              ${paged.length ? paged.map(d => `
                <tr ${d.suppressed ? 'class="row-suppressed"' : ''}>
                  <td class="mono-sm">${esc(d.id)}</td>
                  <td><time datetime="${esc(d.ts)}">${relativeTime(d.ts)}</time></td>
                  <td><strong>${esc(d.ruleName)}</strong><small>${esc(d.ruleId)} · ${esc(d.ruleVersion)}</small></td>
                  <td>${esc(d.host)}<small>${esc(d.user)}</small></td>
                  <td>${severityBadge(d.severity)}</td>
                  <td><span class="matched-count">${d.matched}</span> <span class="muted">/ ${d.threshold}</span></td>
                  <td>${d.incidentId ? `<a href="#incidents" class="text-link">${esc(d.incidentId)}</a>` : '<span class="muted">—</span>'}</td>
                  <td><button class="text-link" data-det-detail="${esc(d.id)}" aria-label="View detection ${esc(d.id)}">Evidence ↗</button></td>
                </tr>`).join('') : `<tr><td colspan="8" class="empty-cell">No detections yet. Run a scenario or import events to trigger rules.</td></tr>`}
            </tbody>
          </table>
        </div>

        <div class="pagination">
          <span class="result-count">${total} detections</span>
          <div class="pg-controls">
            <button class="pg-btn" data-pg-det="first" ${_state.page === 1 ? 'disabled' : ''}>«</button>
            <button class="pg-btn" data-pg-det="prev" ${_state.page === 1 ? 'disabled' : ''}>‹</button>
            <span class="pg-label">Page ${_state.page} of ${totalPages}</span>
            <button class="pg-btn" data-pg-det="next" ${_state.page === totalPages ? 'disabled' : ''}>›</button>
            <button class="pg-btn" data-pg-det="last" ${_state.page === totalPages ? 'disabled' : ''}>»</button>
          </div>
        </div>
      </section>
    </div>
  `;

  bindDetectionHandlers(container, detections, paged);
}

function bindDetectionHandlers(container, detections, paged) {
  container.querySelector('#det-search')?.addEventListener('input', e => {
    _state.search = e.target.value; _state.page = 1; renderDetection(container);
  });
  container.querySelector('#det-rule-filter')?.addEventListener('change', e => {
    _state.ruleId = e.target.value; _state.page = 1; renderDetection(container);
  });
  container.querySelector('#det-severity-filter')?.addEventListener('change', e => {
    _state.severity = e.target.value; _state.page = 1; renderDetection(container);
  });

  container.querySelectorAll('[data-pg-det]').forEach(btn => {
    btn.addEventListener('click', () => {
      const totalPages = Math.max(1, Math.ceil(detections.length / PAGE_SIZE));
      if (btn.dataset.pgDet === 'first') _state.page = 1;
      if (btn.dataset.pgDet === 'prev') _state.page = Math.max(1, _state.page - 1);
      if (btn.dataset.pgDet === 'next') _state.page = Math.min(totalPages, _state.page + 1);
      if (btn.dataset.pgDet === 'last') _state.page = totalPages;
      renderDetection(container);
    });
  });

  container.querySelectorAll('[data-det-detail]').forEach(btn => {
    btn.addEventListener('click', () => {
      const det = detections.find(d => d.id === btn.dataset.detDetail);
      if (!det) return;
      const rule = RULE_CATALOG.find(r => r.id === det.ruleId);
      openDialog(`Detection ${esc(det.id)}`, `
        <div class="detail-kv">
          <span>Rule</span><span>${esc(det.ruleName)} (${esc(det.ruleId)} ${esc(det.ruleVersion)})</span>
          <span>Severity</span><span>${severityBadge(det.severity)}</span>
          <span>Host</span><span>${esc(det.host)}</span>
          <span>User</span><span>${esc(det.user)}</span>
          <span>Source IP</span><span>${esc(det.ip)}</span>
          <span>Window</span><span>${det.windowMinutes} minutes</span>
          <span>Matched</span><span>${det.matched} / threshold ${det.threshold}</span>
          <span>Time</span><span>${new Date(det.ts).toLocaleString()}</span>
          <span>MITRE</span><span>${esc(det.mitreTechnique)}: ${esc(det.mitreName)} <em class="small muted">(hypothesis)</em></span>
          <span>Incident</span><span>${det.incidentId || '—'}</span>
          <span>Suppressed</span><span>${det.suppressed ? 'Yes' : 'No'}</span>
        </div>
        <div class="detail-section">
          <h3>Explanation</h3>
          <p>${esc(det.explanation)}</p>
        </div>
        <div class="detail-section">
          <h3>Triggering events (${det.triggeringEventIds.length})</h3>
          <p class="mono small">${det.triggeringEventIds.slice(0,20).map(esc).join(', ')}${det.triggeringEventIds.length > 20 ? '…' : ''}</p>
        </div>
        <div class="detail-section">
          <h3>Rule details</h3>
          ${rule ? `<p class="small">${esc(rule.description)}</p>` : ''}
          <p class="small muted">No trained ML model. No false-positive rate, precision, recall, or accuracy measurements are available.</p>
        </div>
      `);
    });
  });
}
