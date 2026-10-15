/**
 * pages/events.js — Event explorer with search, filter, pagination, sort,
 * pause/resume display, JSON/CSV import, and export.
 */
'use strict';

import { getMeta, getPrefs, idbGetAll, idbCount } from '../modules/store.js';
import { processImport, eventsToCSV, MAX_FILE_BYTES, MAX_BATCH } from '../modules/ingest.js';
import { esc, severityBadge, formatTs, icon, showToast, openDialog, downloadBlob } from '../modules/ui.js';

const PAGE_SIZE = 50;

let _state = {
  search: '',
  source: 'all',
  outcome: 'all',
  severity: 'all',
  sortBy: 'ts',
  sortDir: 'desc',
  page: 1,
  paused: false,
  bufferedCount: 0,
  activeTab: 'normalized',
};

export async function renderEvents(container) {
  const prefs = getPrefs();

  // Load events
  let events = await idbGetAll('events', { sortBy: 'ts', direction: _state.sortDir === 'desc' ? 'prev' : 'next', limit: 5000 });

  // Apply filters
  const search = _state.search.toLowerCase();
  if (search) {
    events = events.filter(e =>
      [e.id, e.type, e.host, e.user, e.ip, e.source, e.outcome, e.stage].some(v => String(v||'').toLowerCase().includes(search))
    );
  }
  if (_state.source !== 'all') events = events.filter(e => e.source === _state.source);
  if (_state.outcome !== 'all') events = events.filter(e => e.outcome?.toLowerCase().includes(_state.outcome.toLowerCase()));
  if (_state.severity !== 'all') events = events.filter(e => e.severity === _state.severity);

  // Sort
  events.sort((a, b) => {
    const dir = _state.sortDir === 'asc' ? 1 : -1;
    if (_state.sortBy === 'ts') return dir * (new Date(a.ts) - new Date(b.ts));
    if (_state.sortBy === 'host') return dir * (a.host||'').localeCompare(b.host||'');
    if (_state.sortBy === 'severity') {
      const order = { critical:3, high:2, medium:1, low:0 };
      return dir * ((order[b.severity]||0) - (order[a.severity]||0));
    }
    return 0;
  });

  const total = events.length;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  if (_state.page > totalPages) _state.page = totalPages;
  const paged = events.slice((_state.page - 1) * PAGE_SIZE, _state.page * PAGE_SIZE);

  // Unique sources for filter
  const allEvents = await idbGetAll('events', { limit: 5000 });
  const sources = [...new Set(allEvents.map(e => e.source).filter(Boolean))];

  container.innerHTML = `
    <section class="panel" aria-labelledby="events-heading">
      <div class="panel-head">
        <h2 id="events-heading">Event explorer</h2>
        <div class="panel-actions">
          <label class="file-label" aria-label="Import events from file">
            ${icon('upload')} Import
            <input type="file" id="import-file" accept=".json,.csv" aria-label="Select event file to import" hidden>
          </label>
          <button class="btn-secondary" data-action="export-json" aria-label="Export filtered events as JSON">${icon('export')} Export JSON</button>
          <button class="btn-secondary" data-action="export-csv" aria-label="Export filtered events as CSV">${icon('export')} Export CSV</button>
        </div>
      </div>

      <!-- Import size info -->
      <p class="small muted">File import limit: ${MAX_FILE_BYTES / 1024 / 1024} MB, max ${MAX_BATCH} records per batch. Supports JSON array and CSV (with quoted fields). <a href="fixtures/" class="text-link">Sample fixtures</a></p>

      <!-- Toolbar -->
      <div class="toolbar" role="search">
        <div class="search-wrap">
          ${icon('search')}
          <input type="search" id="event-search" class="search-input" placeholder="Search ID, type, host, user, IP…" value="${esc(_state.search)}" aria-label="Search events">
        </div>
        <select id="event-source-filter" class="select-sm" aria-label="Filter by source">
          <option value="all">All sources</option>
          ${sources.map(s => `<option value="${esc(s)}" ${_state.source === s ? 'selected' : ''}>${esc(s)}</option>`).join('')}
        </select>
        <select id="event-outcome-filter" class="select-sm" aria-label="Filter by outcome">
          <option value="all">All outcomes</option>
          <option value="success" ${_state.outcome === 'success' ? 'selected' : ''}>Success</option>
          <option value="failure" ${_state.outcome === 'failure' ? 'selected' : ''}>Failure</option>
          <option value="denied" ${_state.outcome === 'denied' ? 'selected' : ''}>Denied</option>
        </select>
        <select id="event-severity-filter" class="select-sm" aria-label="Filter by severity">
          <option value="all">All severities</option>
          <option value="critical" ${_state.severity === 'critical' ? 'selected' : ''}>Critical</option>
          <option value="high" ${_state.severity === 'high' ? 'selected' : ''}>High</option>
          <option value="medium" ${_state.severity === 'medium' ? 'selected' : ''}>Medium</option>
          <option value="low" ${_state.severity === 'low' ? 'selected' : ''}>Low</option>
        </select>
        <button class="btn-${_state.paused ? 'primary' : 'secondary'}" id="pause-btn" aria-pressed="${_state.paused}">
          ${_state.paused ? '▶ Resume display' : '⏸ Pause display'}
          ${_state.paused && _state.bufferedCount > 0 ? `<span class="badge-count">${_state.bufferedCount} buffered</span>` : ''}
        </button>
      </div>

      <!-- Tabs: Normalized / Raw -->
      <div class="tab-bar" role="tablist" aria-label="Event view mode">
        <button role="tab" aria-selected="${_state.activeTab === 'normalized'}" id="tab-normalized" data-tab="normalized" class="tab-btn ${_state.activeTab === 'normalized' ? 'active' : ''}">Normalized</button>
        <button role="tab" aria-selected="${_state.activeTab === 'raw'}" id="tab-raw" data-tab="raw" class="tab-btn ${_state.activeTab === 'raw' ? 'active' : ''}">Raw</button>
      </div>

      <!-- Table -->
      <div class="table-wrap" id="events-table-wrap" tabindex="0" aria-label="Events table">
        <table aria-label="Events list">
          <thead>
            <tr>
              <th><button class="sort-btn" data-sort="id">EVENT ID</button></th>
              <th><button class="sort-btn" data-sort="ts" aria-sort="${_state.sortBy === 'ts' ? _state.sortDir : 'none'}">TIME ${_state.sortBy === 'ts' ? (_state.sortDir === 'asc' ? '↑' : '↓') : ''}</button></th>
              <th>TYPE / STAGE</th>
              <th><button class="sort-btn" data-sort="host">HOST / USER</button></th>
              <th>SOURCE IP</th>
              <th><button class="sort-btn" data-sort="severity">SEVERITY</button></th>
              <th>OUTCOME</th>
              ${_state.activeTab === 'raw' ? '<th>RAW</th>' : ''}
            </tr>
          </thead>
          <tbody>
            ${paged.length ? paged.map(e => renderEventRow(e, prefs)).join('') : `<tr><td colspan="7" class="empty-cell">No events match the current filters.</td></tr>`}
          </tbody>
        </table>
      </div>

      <!-- Pagination -->
      <div class="pagination">
        <span class="result-count">${total} event${total !== 1 ? 's' : ''} (${paged.length} shown)</span>
        <div class="pg-controls">
          <button class="pg-btn" data-pg="first" ${_state.page === 1 ? 'disabled' : ''}>«</button>
          <button class="pg-btn" data-pg="prev" ${_state.page === 1 ? 'disabled' : ''}>‹</button>
          <span class="pg-label">Page ${_state.page} of ${totalPages}</span>
          <button class="pg-btn" data-pg="next" ${_state.page === totalPages ? 'disabled' : ''}>›</button>
          <button class="pg-btn" data-pg="last" ${_state.page === totalPages ? 'disabled' : ''}>»</button>
        </div>
      </div>
    </section>
  `;

  // Bind events
  bindEventHandlers(container, events, paged);
}

function renderEventRow(e, prefs) {
  return `<tr>
    <td><button class="text-link" data-event-id="${esc(e.id)}" aria-label="View event ${esc(e.id)}">${esc(e.id)}</button></td>
    <td class="ts-cell"><time datetime="${esc(e.ts)}" title="${esc(e.ts)}">${new Date(e.ts).toLocaleTimeString()}</time><small>${new Date(e.ts).toLocaleDateString()}</small></td>
    <td><strong>${esc(e.type)}</strong><small>${esc(e.stage)}</small></td>
    <td><span>${esc(e.host)}</span><small>${esc(e.user)}</small></td>
    <td>${esc(e.ip)}</td>
    <td>${severityBadge(e.severity)}</td>
    <td><span class="outcome-${e.outcome?.includes('success') ? 'ok' : e.outcome?.includes('fail') || e.outcome?.includes('deni') ? 'bad' : 'neutral'}">${esc(e.outcome)}</span></td>
  </tr>`;
}

function bindEventHandlers(container, filteredEvents, paged) {
  // Search
  const searchInput = container.querySelector('#event-search');
  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      _state.search = e.target.value;
      _state.page = 1;
      renderEvents(container);
    });
  }

  // Filters
  ['event-source-filter','event-outcome-filter','event-severity-filter'].forEach(id => {
    const el = container.querySelector(`#${id}`);
    if (!el) return;
    el.addEventListener('change', (e) => {
      if (id === 'event-source-filter') _state.source = e.target.value;
      if (id === 'event-outcome-filter') _state.outcome = e.target.value;
      if (id === 'event-severity-filter') _state.severity = e.target.value;
      _state.page = 1;
      renderEvents(container);
    });
  });

  // Pause/resume
  const pauseBtn = container.querySelector('#pause-btn');
  if (pauseBtn) {
    pauseBtn.addEventListener('click', () => {
      _state.paused = !_state.paused;
      if (!_state.paused) _state.bufferedCount = 0;
      renderEvents(container);
    });
  }

  // Tab switch
  container.querySelectorAll('[data-tab]').forEach(btn => {
    btn.addEventListener('click', () => {
      _state.activeTab = btn.dataset.tab;
      renderEvents(container);
    });
  });

  // Sort buttons
  container.querySelectorAll('[data-sort]').forEach(btn => {
    btn.addEventListener('click', () => {
      const col = btn.dataset.sort;
      if (_state.sortBy === col) _state.sortDir = _state.sortDir === 'asc' ? 'desc' : 'asc';
      else { _state.sortBy = col; _state.sortDir = 'desc'; }
      renderEvents(container);
    });
  });

  // Pagination
  container.querySelectorAll('[data-pg]').forEach(btn => {
    btn.addEventListener('click', () => {
      const totalPages = Math.max(1, Math.ceil(filteredEvents.length / PAGE_SIZE));
      if (btn.dataset.pg === 'first') _state.page = 1;
      if (btn.dataset.pg === 'prev') _state.page = Math.max(1, _state.page - 1);
      if (btn.dataset.pg === 'next') _state.page = Math.min(totalPages, _state.page + 1);
      if (btn.dataset.pg === 'last') _state.page = totalPages;
      renderEvents(container);
    });
  });

  // Event detail
  container.querySelectorAll('[data-event-id]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const ev = filteredEvents.find(e => e.id === btn.dataset.eventId);
      if (!ev) return;
      openDialog(`Event <strong>${esc(ev.id)}</strong>`, `
        <div class="detail-kv">
          <span>Time</span><span>${new Date(ev.ts).toLocaleString()}</span>
          <span>Type</span><span>${esc(ev.type)}</span>
          <span>Stage</span><span>${esc(ev.stage)}</span>
          <span>Host</span><span>${esc(ev.host)}</span>
          <span>User</span><span>${esc(ev.user)}</span>
          <span>Source IP</span><span>${esc(ev.ip)}</span>
          <span>Outcome</span><span>${esc(ev.outcome)}</span>
          <span>Severity</span><span>${severityBadge(ev.severity)}</span>
          <span>Source</span><span>${esc(ev.source)}</span>
          <span>Synthetic</span><span>${ev.synthetic ? 'Yes' : 'No'}</span>
          ${ev.destinationPort ? `<span>Dest. Port</span><span>${ev.destinationPort}</span>` : ''}
          ${ev.contentHash ? `<span>Content hash</span><span class="mono small">${esc(ev.contentHash)}</span>` : ''}
        </div>
        ${ev.raw ? `<details class="raw-detail"><summary>Raw input</summary><pre>${esc(ev.raw)}</pre></details>` : ''}
      `);
    });
  });

  // Export
  container.querySelector('[data-action="export-json"]')?.addEventListener('click', () => {
    downloadBlob(JSON.stringify(filteredEvents, null, 2), 'vsi-events.json', 'application/json');
    showToast('Events exported as JSON', 'success');
  });
  container.querySelector('[data-action="export-csv"]')?.addEventListener('click', () => {
    downloadBlob(eventsToCSV(filteredEvents), 'vsi-events.csv', 'text/csv');
    showToast('Events exported as CSV', 'success');
  });

  // Import
  const importFile = container.querySelector('#import-file');
  if (importFile) {
    importFile.addEventListener('change', async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      if (file.size > MAX_FILE_BYTES) {
        showToast(`File too large. Maximum is ${MAX_FILE_BYTES / 1024 / 1024} MB.`, 'error');
        return;
      }
      showToast('Processing import…', 'info');
      const text = await file.text();
      const result = await processImport(text, file.name);
      const msg = `Import complete: ${result.accepted} accepted, ${result.duplicates} duplicates, ${result.rejected} rejected.`;
      showToast(msg, result.rejected > 0 ? 'warn' : 'success');
      if (result.errors.length) {
        openDialog('Import results', `
          <p>${esc(msg)}</p>
          <ul>${result.errors.slice(0,20).map(er => `<li>${esc(er)}</li>`).join('')}</ul>
        `);
      }
      _state.page = 1;
      renderEvents(container);
    });
  }
}

// Called on simulator tick (when not paused)
export function onNewEvent() {
  if (_state.paused) { _state.bufferedCount++; return; }
  // Container is re-rendered by main app on tick
}
