/**
 * ui.js — shared UI utilities: escaping, icons, components, toast, dialog, focus management.
 */
'use strict';

/* ── Security ────────────────────────────────────────────────────────── */
export function esc(v) {
  return String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

export function setText(el, text) {
  if (!el) return;
  el.textContent = String(text ?? '');
}

/* ── SVG icon set ─────────────────────────────────────────────────── */
// Consistent 16×16 inline SVG icons; no external dependencies
export const ICONS = {
  overview: `<svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true"><rect x="1" y="1" width="6" height="6" rx="1" fill="currentColor" opacity=".9"/><rect x="9" y="1" width="6" height="6" rx="1" fill="currentColor" opacity=".6"/><rect x="1" y="9" width="6" height="6" rx="1" fill="currentColor" opacity=".6"/><rect x="9" y="9" width="6" height="6" rx="1" fill="currentColor" opacity=".9"/></svg>`,
  events: `<svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M2 4h12M2 8h8M2 12h10" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>`,
  detection: `<svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true"><circle cx="8" cy="8" r="5" stroke="currentColor" stroke-width="1.5"/><path d="M8 5v3.5l2 1" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>`,
  incidents: `<svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M8 2L14 13H2L8 2z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/><path d="M8 6v4M8 11.5v.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>`,
  chain: `<svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true"><circle cx="3" cy="8" r="2" stroke="currentColor" stroke-width="1.5"/><circle cx="13" cy="8" r="2" stroke="currentColor" stroke-width="1.5"/><circle cx="8" cy="4" r="2" stroke="currentColor" stroke-width="1.5"/><path d="M5 8h6M8 6v2" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg>`,
  risk: `<svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M2 13 Q4 3, 8 7 Q12 11, 14 3" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" fill="none"/></svg>`,
  responses: `<svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M8 1L2 4v5c0 3 2.7 5.4 6 6 3.3-.6 6-3 6-6V4L8 1z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/><path d="M5.5 8l2 2 3-3" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
  reports: `<svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true"><rect x="3" y="1" width="10" height="14" rx="1.5" stroke="currentColor" stroke-width="1.5"/><path d="M6 5h4M6 8h4M6 11h2" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg>`,
  settings: `<svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true"><circle cx="8" cy="8" r="2.5" stroke="currentColor" stroke-width="1.5"/><path d="M8 1v2M8 13v2M1 8h2M13 8h2M3.1 3.1l1.4 1.4M11.5 11.5l1.4 1.4M3.1 12.9l1.4-1.4M11.5 4.5l1.4-1.4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>`,
  demo: `<svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M3 3l10 5-10 5V3z" fill="currentColor" opacity=".85"/></svg>`,
  ai: `<svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true"><circle cx="8" cy="8" r="3" stroke="currentColor" stroke-width="1.5"/><path d="M8 1v3M8 12v3M1 8h3M12 8h3M3 3l2.2 2.2M10.8 10.8L13 13M3 13l2.2-2.2M10.8 5.2L13 3" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg>`,
  close: `<svg width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden="true"><path d="M1 1l12 12M13 1L1 13" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>`,
  search: `<svg width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden="true"><circle cx="6" cy="6" r="4.5" stroke="currentColor" stroke-width="1.5"/><path d="M10 10l2.5 2.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>`,
  filter: `<svg width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden="true"><path d="M1 3h12M3 7h8M5 11h4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>`,
  export: `<svg width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden="true"><path d="M7 1v8M4 6l3 3 3-3" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/><path d="M1 10v2a1 1 0 001 1h10a1 1 0 001-1v-2" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>`,
  upload: `<svg width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden="true"><path d="M7 9V1M4 4l3-3 3 3" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/><path d="M1 10v2a1 1 0 001 1h10a1 1 0 001-1v-2" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>`,
  check: `<svg width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden="true"><path d="M2 7l4 4 6-6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
  info: `<svg width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden="true"><circle cx="7" cy="7" r="6" stroke="currentColor" stroke-width="1.5"/><path d="M7 6v4M7 4.5v.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>`,
  warn: `<svg width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden="true"><path d="M7 1L1 12h12L7 1z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/><path d="M7 5.5v3M7 10v.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>`,
  sort: `<svg width="12" height="12" viewBox="0 0 12 12" fill="none" aria-hidden="true"><path d="M3 4l3-3 3 3M3 8l3 3 3-3" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
  chevronDown: `<svg width="12" height="12" viewBox="0 0 12 12" fill="none" aria-hidden="true"><path d="M2 4l4 4 4-4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
  menu: `<svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M2 4h12M2 8h12M2 12h12" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>`,
  sim: `<svg width="8" height="8" viewBox="0 0 8 8" fill="none" aria-hidden="true"><circle cx="4" cy="4" r="3.5" fill="currentColor"/></svg>`,
};

export function icon(name, cls = '') {
  return `<span class="icon${cls ? ' ' + cls : ''}" aria-hidden="true">${ICONS[name] || ''}</span>`;
}

/* ── Badge / severity ────────────────────────────────────────────────── */
export function severityBadge(band) {
  const labels = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
  const b = band?.toLowerCase() || 'low';
  return `<span class="badge badge-${b}" title="Severity: ${labels[b] || b}">${labels[b] || esc(b)}</span>`;
}

export function statusBadge(status) {
  const cls = {
    'New': 'status-new',
    'Investigating': 'status-investigating',
    'Contained': 'status-contained',
    'Resolved': 'status-resolved',
    'False positive': 'status-fp',
    'pending': 'status-new',
    'approved': 'status-contained',
    'rejected': 'status-fp',
    'expired': 'status-fp',
    'superseded': 'status-investigating',
    'verified': 'status-resolved',
  }[status] || 'status-new';
  return `<span class="status-badge ${cls}">${esc(status)}</span>`;
}

/* ── Toast notifications ─────────────────────────────────────────────── */
let _toastTimer = null;
export function showToast(message, type = 'info') {
  const el = document.getElementById('toast');
  if (!el) return;
  el.innerHTML = `${icon(type === 'error' ? 'warn' : type === 'success' ? 'check' : 'info')} <span>${esc(message)}</span>`;
  el.className = `toast toast-${type} visible`;
  el.removeAttribute('hidden');
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => { el.className = 'toast'; }, 4500);
}

/* ── Dialog ─────────────────────────────────────────────────────────── */
let _dialogReturnFocus = null;

export function openDialog(titleHtml, bodyHtml, { wide = false } = {}) {
  const dlg = document.getElementById('detail');
  if (!dlg) return;
  _dialogReturnFocus = document.activeElement;
  const titleEl = document.getElementById('detail-title');
  const bodyEl = document.getElementById('detail-body');
  if (titleEl) titleEl.innerHTML = titleHtml;
  if (bodyEl) bodyEl.innerHTML = bodyHtml;
  dlg.classList.toggle('dialog-wide', wide);
  dlg.showModal();
  // Move focus to first focusable element
  const firstFocus = dlg.querySelector('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
  if (firstFocus) firstFocus.focus();
}

export function closeDialog() {
  const dlg = document.getElementById('detail');
  if (dlg && dlg.open) dlg.close();
  if (_dialogReturnFocus) { _dialogReturnFocus.focus(); _dialogReturnFocus = null; }
}

/* ── Table helpers ───────────────────────────────────────────────────── */
export function emptyRow(cols, message = 'No results.') {
  return `<tr><td colspan="${cols}" class="empty-cell">${esc(message)}</td></tr>`;
}

export function sortIndicator(col, currentSort, currentDir) {
  if (col !== currentSort) return `<span class="sort-icon">${ICONS.sort}</span>`;
  const arrow = currentDir === 'asc' ? '↑' : '↓';
  return `<span class="sort-icon active">${arrow}</span>`;
}

export function paginationBar({ page, totalPages, resultCount, itemsPerPage, id = 'pg' }) {
  if (totalPages <= 1) return `<div class="result-count">${resultCount} result${resultCount !== 1 ? 's' : ''}</div>`;
  return `
    <div class="pagination">
      <span class="result-count">${resultCount} results</span>
      <div class="pg-controls">
        <button class="pg-btn" data-pg-action="first" data-pg-id="${esc(id)}" ${page === 1 ? 'disabled' : ''} aria-label="First page">«</button>
        <button class="pg-btn" data-pg-action="prev" data-pg-id="${esc(id)}" ${page === 1 ? 'disabled' : ''} aria-label="Previous page">‹</button>
        <span class="pg-label">Page ${page} of ${totalPages}</span>
        <button class="pg-btn" data-pg-action="next" data-pg-id="${esc(id)}" ${page === totalPages ? 'disabled' : ''} aria-label="Next page">›</button>
        <button class="pg-btn" data-pg-action="last" data-pg-id="${esc(id)}" ${page === totalPages ? 'disabled' : ''} aria-label="Last page">»</button>
      </div>
    </div>`;
}

/* ── Date formatting ─────────────────────────────────────────────────── */
export function formatTs(isoStr, { prefs } = {}) {
  if (!isoStr) return 'N/A';
  const d = new Date(isoStr);
  if (isNaN(d)) return 'Invalid date';
  const tz = prefs?.timezone === 'utc' ? 'UTC' : undefined;
  return d.toLocaleString(undefined, tz ? { timeZone: tz } : {});
}

export function formatDate(isoStr, prefs) {
  if (!isoStr) return 'N/A';
  const d = new Date(isoStr);
  if (isNaN(d)) return 'Invalid date';
  const tz = prefs?.timezone === 'utc' ? 'UTC' : undefined;
  return d.toLocaleDateString(undefined, tz ? { timeZone: tz } : {});
}

export function relativeTime(isoStr) {
  if (!isoStr) return '';
  const diff = Date.now() - new Date(isoStr);
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

/* ── Focus trap ──────────────────────────────────────────────────────── */
export function trapFocus(el) {
  const focusable = el.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  el.addEventListener('keydown', (e) => {
    if (e.key !== 'Tab') return;
    if (e.shiftKey) {
      if (document.activeElement === first) { e.preventDefault(); last?.focus(); }
    } else {
      if (document.activeElement === last) { e.preventDefault(); first?.focus(); }
    }
  });
}

/* ── Download helpers ────────────────────────────────────────────────── */
export function downloadBlob(content, filename, type) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/* ── Scroll preservation ─────────────────────────────────────────────── */
export function preserveScroll(id, fn) {
  const el = document.getElementById(id);
  const top = el ? el.scrollTop : 0;
  fn();
  const el2 = document.getElementById(id);
  if (el2) el2.scrollTop = top;
}

/* ── Announce to screen readers ──────────────────────────────────────── */
export function announce(msg) {
  const el = document.getElementById('a11y-live');
  if (!el) return;
  el.textContent = '';
  setTimeout(() => { el.textContent = String(msg); }, 10);
}
