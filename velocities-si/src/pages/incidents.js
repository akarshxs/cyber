/**
 * pages/incidents.js — Incident center with full state machine, assignment,
 * notes, filters, bulk operations, and audited transitions.
 */
'use strict';

import { getMeta, getPrefs, saveMeta, appendAudit, idbGetById } from '../modules/store.js';
import { esc, severityBadge, statusBadge, formatTs, relativeTime, icon, showToast, openDialog, closeDialog } from '../modules/ui.js';
import { scoreToBand } from '../modules/risk.js';

const PAGE_SIZE = 25;
const ANALYSTS = ['Demo analyst', 'alice@velocities', 'bob@velocities', 'carol@velocities'];

// Allowed status transitions
const TRANSITIONS = {
  'New': ['Investigating'],
  'Investigating': ['Contained', 'Resolved', 'False positive'],
  'Contained': ['Resolved', 'Investigating'],
  'Resolved': ['Investigating'], // reopen
  'False positive': ['Investigating'], // reclassify
};

let _state = {
  search: '',
  status: 'all',
  priority: 'all',
  owner: 'all',
  sortBy: 'risk',
  sortDir: 'desc',
  page: 1,
  selected: new Set(),
};

// Accept URL params for pre-filtering (from overview metric clicks)
export function setFilter(params) {
  if (params.status === 'active') _state.status = 'active';
  if (params.priority) _state.priority = params.priority;
}

export function renderIncidents(container) {
  const meta = getMeta();
  let items = [...meta.incidents];

  // Filter
  const search = _state.search.toLowerCase();
  if (search) items = items.filter(i => [i.id, i.title, i.host, i.user, i.ip, i.owner||''].some(v => String(v).toLowerCase().includes(search)));

  if (_state.status === 'active') items = items.filter(i => ['New','Investigating','Contained'].includes(i.status));
  else if (_state.status !== 'all') items = items.filter(i => i.status === _state.status);

  if (_state.priority !== 'all') items = items.filter(i => (i.priority||'') === _state.priority);
  if (_state.owner !== 'all') {
    if (_state.owner === 'unassigned') items = items.filter(i => !i.owner);
    else items = items.filter(i => i.owner === _state.owner);
  }

  // Sort
  items.sort((a, b) => {
    const dir = _state.sortDir === 'asc' ? 1 : -1;
    if (_state.sortBy === 'risk') return dir * (b.risk - a.risk);
    if (_state.sortBy === 'status') return dir * (a.status||'').localeCompare(b.status||'');
    if (_state.sortBy === 'created') return dir * (new Date(a.createdAt) - new Date(b.createdAt));
    return 0;
  });

  const total = items.length;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  if (_state.page > totalPages) _state.page = totalPages;
  const paged = items.slice((_state.page - 1) * PAGE_SIZE, _state.page * PAGE_SIZE);
  const selectedCount = _state.selected.size;

  container.innerHTML = `
    <section class="panel" aria-labelledby="inc-heading">
      <div class="panel-head">
        <h2 id="inc-heading">Incident center</h2>
        <div class="panel-actions">
          <span class="muted small">${total} result${total !== 1 ? 's' : ''}</span>
        </div>
      </div>

      <div class="toolbar">
        <div class="search-wrap">
          ${icon('search')}
          <input type="search" id="inc-search" class="search-input" placeholder="Search incidents…" value="${esc(_state.search)}" aria-label="Search incidents">
        </div>
        <select id="inc-status-filter" class="select-sm" aria-label="Filter by status">
          <option value="all" ${_state.status === 'all' ? 'selected' : ''}>All statuses</option>
          <option value="active" ${_state.status === 'active' ? 'selected' : ''}>Active only</option>
          <option value="New" ${_state.status === 'New' ? 'selected' : ''}>New</option>
          <option value="Investigating" ${_state.status === 'Investigating' ? 'selected' : ''}>Investigating</option>
          <option value="Contained" ${_state.status === 'Contained' ? 'selected' : ''}>Contained</option>
          <option value="Resolved" ${_state.status === 'Resolved' ? 'selected' : ''}>Resolved</option>
          <option value="False positive" ${_state.status === 'False positive' ? 'selected' : ''}>False positive</option>
        </select>
        <select id="inc-priority-filter" class="select-sm" aria-label="Filter by priority">
          <option value="all" ${_state.priority === 'all' ? 'selected' : ''}>All priorities</option>
          <option value="critical" ${_state.priority === 'critical' ? 'selected' : ''}>Critical</option>
          <option value="high" ${_state.priority === 'high' ? 'selected' : ''}>High</option>
          <option value="medium" ${_state.priority === 'medium' ? 'selected' : ''}>Medium</option>
          <option value="low" ${_state.priority === 'low' ? 'selected' : ''}>Low</option>
        </select>
        <select id="inc-owner-filter" class="select-sm" aria-label="Filter by owner">
          <option value="all" ${_state.owner === 'all' ? 'selected' : ''}>All owners</option>
          <option value="unassigned" ${_state.owner === 'unassigned' ? 'selected' : ''}>Unassigned</option>
          ${ANALYSTS.map(a => `<option value="${esc(a)}" ${_state.owner === a ? 'selected' : ''}>${esc(a)}</option>`).join('')}
        </select>
      </div>

      ${selectedCount > 0 ? `
      <div class="bulk-bar" role="region" aria-live="polite">
        <span>${selectedCount} selected</span>
        <button class="btn-secondary btn-sm" data-bulk="assign">Assign…</button>
        <button class="btn-secondary btn-sm" data-bulk="resolve" aria-describedby="bulk-warn">Mark resolved</button>
        <span id="bulk-warn" class="sr-only">This will change status for all ${selectedCount} selected incidents</span>
        <button class="btn-ghost btn-sm" data-bulk="clear">Clear selection</button>
      </div>` : ''}

      <div class="table-wrap" tabindex="0" aria-label="Incidents table">
        <table aria-label="Incidents list">
          <thead>
            <tr>
              <th><input type="checkbox" id="select-all-chk" aria-label="Select all incidents on this page" ${paged.every(i => _state.selected.has(i.id)) ? 'checked' : ''}></th>
              <th>ID</th>
              <th>TITLE</th>
              <th><button class="sort-btn" data-sort-inc="risk" aria-sort="${_state.sortBy === 'risk' ? _state.sortDir : 'none'}">RISK ${_state.sortBy === 'risk' ? (_state.sortDir === 'asc' ? '↑' : '↓') : ''}</button></th>
              <th>PRIORITY</th>
              <th><button class="sort-btn" data-sort-inc="status">STATUS</button></th>
              <th>OWNER</th>
              <th><button class="sort-btn" data-sort-inc="created">CREATED</button></th>
              <th>ACTIONS</th>
            </tr>
          </thead>
          <tbody>
            ${paged.length ? paged.map(i => renderIncRow(i)).join('') : `<tr><td colspan="9" class="empty-cell">No incidents match the current filters.</td></tr>`}
          </tbody>
        </table>
      </div>

      <div class="pagination">
        <span class="result-count">${total} incidents</span>
        <div class="pg-controls">
          <button class="pg-btn" data-pg-inc="first" ${_state.page === 1 ? 'disabled' : ''}>«</button>
          <button class="pg-btn" data-pg-inc="prev" ${_state.page === 1 ? 'disabled' : ''}>‹</button>
          <span class="pg-label">Page ${_state.page} of ${totalPages}</span>
          <button class="pg-btn" data-pg-inc="next" ${_state.page === totalPages ? 'disabled' : ''}>›</button>
          <button class="pg-btn" data-pg-inc="last" ${_state.page === totalPages ? 'disabled' : ''}>»</button>
        </div>
      </div>
    </section>
  `;

  bindIncidentHandlers(container, items, paged);
}

function renderIncRow(i) {
  const { band, label } = scoreToBand(i.risk);
  const isSelected = _state.selected.has(i.id);
  const allowedNext = TRANSITIONS[i.status] || [];

  return `<tr class="${isSelected ? 'row-selected' : ''}">
    <td><input type="checkbox" class="row-chk" data-inc-id="${esc(i.id)}" ${isSelected ? 'checked' : ''} aria-label="Select incident ${esc(i.id)}"></td>
    <td><button class="text-link mono-sm" data-inc-detail="${esc(i.id)}">${esc(i.id)}</button></td>
    <td>
      <strong>${esc(i.title)}</strong>
      <small>${esc(i.host)} · ${esc(i.user)}</small>
    </td>
    <td><span class="risk-score text-${band}">${i.risk}</span><span class="muted">/100</span></td>
    <td>${severityBadge(i.priority)}</td>
    <td>${statusBadge(i.status)}</td>
    <td>${i.owner ? `<span class="owner-chip">${esc(i.owner)}</span>` : '<span class="muted">—</span>'}</td>
    <td><time datetime="${esc(i.createdAt)}" title="${esc(i.createdAt)}">${relativeTime(i.createdAt)}</time></td>
    <td>
      <div class="row-actions">
        <button class="btn-secondary btn-xs" data-inc-detail="${esc(i.id)}" aria-label="Investigate incident ${esc(i.id)}">Investigate</button>
        ${allowedNext.length ? `<select class="select-xs" data-inc-transition="${esc(i.id)}" aria-label="Transition status of ${esc(i.id)}">
          <option value="">Transition…</option>
          ${allowedNext.map(s => `<option value="${esc(s)}">${esc(s)}</option>`).join('')}
        </select>` : `<span class="muted small">${esc(i.status)}</span>`}
      </div>
    </td>
  </tr>`;
}

function bindIncidentHandlers(container, items, paged) {
  // Search
  container.querySelector('#inc-search')?.addEventListener('input', e => {
    _state.search = e.target.value; _state.page = 1; renderIncidents(container);
  });

  // Filters
  ['inc-status-filter','inc-priority-filter','inc-owner-filter'].forEach(id => {
    container.querySelector(`#${id}`)?.addEventListener('change', e => {
      if (id === 'inc-status-filter') _state.status = e.target.value;
      if (id === 'inc-priority-filter') _state.priority = e.target.value;
      if (id === 'inc-owner-filter') _state.owner = e.target.value;
      _state.page = 1; renderIncidents(container);
    });
  });

  // Sort
  container.querySelectorAll('[data-sort-inc]').forEach(btn => {
    btn.addEventListener('click', () => {
      const col = btn.dataset.sortInc;
      _state.sortDir = _state.sortBy === col ? (_state.sortDir === 'asc' ? 'desc' : 'asc') : 'desc';
      _state.sortBy = col;
      renderIncidents(container);
    });
  });

  // Pagination
  container.querySelectorAll('[data-pg-inc]').forEach(btn => {
    btn.addEventListener('click', () => {
      const totalPages = Math.max(1, Math.ceil(items.length / PAGE_SIZE));
      if (btn.dataset.pgInc === 'first') _state.page = 1;
      if (btn.dataset.pgInc === 'prev') _state.page = Math.max(1, _state.page - 1);
      if (btn.dataset.pgInc === 'next') _state.page = Math.min(totalPages, _state.page + 1);
      if (btn.dataset.pgInc === 'last') _state.page = totalPages;
      renderIncidents(container);
    });
  });

  // Checkboxes
  container.querySelector('#select-all-chk')?.addEventListener('change', e => {
    if (e.target.checked) paged.forEach(i => _state.selected.add(i.id));
    else paged.forEach(i => _state.selected.delete(i.id));
    renderIncidents(container);
  });
  container.querySelectorAll('.row-chk').forEach(chk => {
    chk.addEventListener('change', e => {
      const id = chk.dataset.incId;
      e.target.checked ? _state.selected.add(id) : _state.selected.delete(id);
      renderIncidents(container);
    });
  });

  // Bulk operations
  container.querySelector('[data-bulk="clear"]')?.addEventListener('click', () => {
    _state.selected.clear(); renderIncidents(container);
  });
  container.querySelector('[data-bulk="resolve"]')?.addEventListener('click', () => {
    if (!confirm(`Mark ${_state.selected.size} selected incident(s) as Resolved? This action affects all selected.`)) return;
    const meta = getMeta();
    for (const id of _state.selected) {
      const inc = meta.incidents.find(i => i.id === id);
      if (!inc) continue;
      if (TRANSITIONS[inc.status]?.includes('Resolved')) {
        inc.status = 'Resolved';
        inc.updatedAt = new Date().toISOString();
        appendAudit('Bulk resolved', id, 'incident');
      }
    }
    saveMeta();
    _state.selected.clear();
    showToast('Selected incidents marked as Resolved', 'success');
    renderIncidents(container);
  });
  container.querySelector('[data-bulk="assign"]')?.addEventListener('click', () => {
    openDialog('Assign incidents', `
      <p>Assign ${_state.selected.size} selected incident(s) to:</p>
      <select id="bulk-assignee" class="select-sm">
        ${ANALYSTS.map(a => `<option value="${esc(a)}">${esc(a)}</option>`).join('')}
      </select>
      <div class="dialog-actions">
        <button class="btn-primary" id="bulk-assign-confirm">Assign</button>
        <button class="btn-secondary" id="bulk-assign-cancel">Cancel</button>
      </div>
    `);
    document.getElementById('bulk-assign-confirm')?.addEventListener('click', () => {
      const analyst = document.getElementById('bulk-assignee')?.value;
      if (!analyst) return;
      const meta = getMeta();
      for (const id of _state.selected) {
        const inc = meta.incidents.find(i => i.id === id);
        if (inc) { inc.owner = analyst; inc.updatedAt = new Date().toISOString(); appendAudit(`Bulk assigned to ${analyst}`, id, 'incident'); }
      }
      saveMeta();
      _state.selected.clear();
      closeDialog();
      showToast(`Assigned to ${analyst}`, 'success');
      renderIncidents(container);
    });
    document.getElementById('bulk-assign-cancel')?.addEventListener('click', closeDialog);
  });

  // Inline status transitions
  container.querySelectorAll('[data-inc-transition]').forEach(sel => {
    sel.addEventListener('change', e => {
      const newStatus = e.target.value;
      if (!newStatus) return;
      transitionIncident(container, sel.dataset.incTransition, newStatus);
    });
  });

  // Detail buttons
  container.querySelectorAll('[data-inc-detail]').forEach(btn => {
    btn.addEventListener('click', () => openIncidentDetail(container, btn.dataset.incDetail));
  });
}

function transitionIncident(container, incId, newStatus) {
  const meta = getMeta();
  const inc = meta.incidents.find(i => i.id === incId);
  if (!inc) return;

  const allowed = TRANSITIONS[inc.status] || [];
  if (!allowed.includes(newStatus)) {
    showToast(`Transition from "${inc.status}" to "${newStatus}" is not allowed.`, 'error');
    return;
  }

  const oldStatus = inc.status;
  inc.status = newStatus;
  inc.updatedAt = new Date().toISOString();
  saveMeta();
  appendAudit(`Status: ${oldStatus} → ${newStatus}`, incId, 'incident');
  showToast(`${incId}: ${oldStatus} → ${newStatus}`, 'success');
  renderIncidents(container);
}

async function openIncidentDetail(container, incId) {
  const meta = getMeta();
  const inc = meta.incidents.find(i => i.id === incId);
  if (!inc) return;

  const { band, label } = scoreToBand(inc.risk);
  const allowedNext = TRANSITIONS[inc.status] || [];
  const notesHtml = inc.notes.length
    ? inc.notes.map(n => `<div class="note-entry"><span class="note-author">${esc(n.author)}</span><span class="note-time muted">${relativeTime(n.ts)}</span><p>${esc(n.text)}</p></div>`).join('')
    : '<p class="muted">No notes yet.</p>';

  openDialog(
    `${esc(inc.id)} — ${esc(inc.title)}`,
    `
    <div class="inc-detail-grid">
      <div class="inc-detail-main">
        <div class="detail-kv">
          <span>Host</span><span>${esc(inc.host)}</span>
          <span>User</span><span>${esc(inc.user)}</span>
          <span>Source IP</span><span>${esc(inc.ip)}</span>
          <span>Risk</span><span class="risk-score text-${band}">${inc.risk}/100 ${severityBadge(inc.priority)}</span>
          <span>Status</span><span>${statusBadge(inc.status)}</span>
          <span>Owner</span><span>${inc.owner || '<em>Unassigned</em>'}</span>
          <span>Created</span><span>${new Date(inc.createdAt).toLocaleString()}</span>
          <span>Updated</span><span>${new Date(inc.updatedAt).toLocaleString()}</span>
          <span>Events</span><span>${inc.eventIds.length} linked</span>
          <span>Detections</span><span>${inc.detectionIds.length} correlated</span>
        </div>

        <div class="detail-section">
          <h3>MITRE hypotheses <span class="tag">Hypothesis, not confirmed</span></h3>
          ${inc.mitreHypotheses.length ? inc.mitreHypotheses.map(m => `
            <div class="mitre-chip"><strong>${esc(m.technique)}</strong> ${esc(m.name)} <span class="muted">via ${esc(m.ruleId)}</span></div>`).join('') : '<p class="muted">None</p>'}
        </div>

        <div class="detail-section">
          <h3>Risk history</h3>
          ${inc.riskHistory.slice(-5).map(h => `<div class="history-entry"><span class="history-time">${new Date(h.ts).toLocaleTimeString()}</span><span class="history-score">${h.before}→<strong>${h.score}</strong></span><span class="muted">${esc(h.rationale)}</span></div>`).join('')}
        </div>

        <div class="detail-section">
          <h3>Transition</h3>
          ${allowedNext.length ? `
            <div class="transition-actions">
              ${allowedNext.map(s => `<button class="btn-secondary btn-sm" data-transition-to="${esc(s)}" data-transition-id="${esc(inc.id)}">${esc(s)}</button>`).join('')}
            </div>` : `<p class="muted">No further transitions from "${esc(inc.status)}".</p>`}
          
          <div class="assign-row">
            <label for="detail-assignee">Assign to</label>
            <select id="detail-assignee" class="select-sm">
              <option value="">—</option>
              ${ANALYSTS.map(a => `<option value="${esc(a)}" ${inc.owner === a ? 'selected' : ''}>${esc(a)}</option>`).join('')}
            </select>
            <button class="btn-secondary btn-sm" id="assign-btn">Assign</button>
          </div>
        </div>

        <div class="detail-section">
          <h3>Notes</h3>
          ${notesHtml}
          <div class="note-add">
            <textarea id="note-text" class="textarea-sm" placeholder="Add a note…" rows="2" maxlength="2048" aria-label="Add note to incident"></textarea>
            <button class="btn-secondary btn-sm" id="add-note-btn">Add note</button>
          </div>
        </div>
      </div>
    </div>
    `,
    { wide: true }
  );

  // Bind transition buttons
  document.querySelectorAll('[data-transition-to]').forEach(btn => {
    btn.addEventListener('click', () => {
      const to = btn.dataset.transitionTo;
      const id = btn.dataset.transitionId;
      transitionIncident(container, id, to);
      closeDialog();
    });
  });

  // Assign
  document.getElementById('assign-btn')?.addEventListener('click', () => {
    const analyst = document.getElementById('detail-assignee')?.value;
    if (!analyst) return;
    const m = getMeta();
    const i2 = m.incidents.find(i => i.id === incId);
    if (i2) { i2.owner = analyst; i2.updatedAt = new Date().toISOString(); }
    saveMeta();
    appendAudit(`Assigned to ${analyst}`, incId, 'incident');
    showToast(`Assigned to ${analyst}`, 'success');
    closeDialog();
    renderIncidents(container);
  });

  // Add note
  document.getElementById('add-note-btn')?.addEventListener('click', () => {
    const text = document.getElementById('note-text')?.value?.trim();
    if (!text) return;
    const m = getMeta();
    const i2 = m.incidents.find(i => i.id === incId);
    if (i2) {
      i2.notes.push({ ts: new Date().toISOString(), author: 'Demo analyst', text: text.slice(0,2048) });
      i2.updatedAt = new Date().toISOString();
      saveMeta();
      appendAudit('Note added', incId, 'incident');
      showToast('Note added', 'success');
      closeDialog();
      openIncidentDetail(container, incId);
    }
  });
}
