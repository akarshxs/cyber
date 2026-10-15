/**
 * ingest.js — shared ingestion pipeline for simulator events and file imports.
 * Both paths use identical normalization, hashing, deduplication, and detection triggering.
 */
'use strict';

import { getMeta, getPrefs, nextId, idbPut, idbPutBatch, idbGetById, contentHash, validateEvent, saveMeta, appendAudit } from './store.js';
import { runDetectionRules } from './detection.js';
import { correlateDetections } from './correlation.js';

export const MAX_FILE_BYTES = 5 * 1024 * 1024; // 5 MB documented limit
export const MAX_BATCH = 500;

/* ── Normalize a raw record into a canonical event ──────────────────── */
export async function normalizeRecord(raw, source = 'import') {
  // Accept various field aliases
  const obj = typeof raw === 'object' && raw !== null ? raw : {};
  const ts = normalizeTimestamp(obj.ts || obj.timestamp || obj.time || obj.datetime);
  const type = String(obj.type || obj.event_type || obj.eventType || obj.action || 'Unknown').slice(0, 128);
  const host = String(obj.host || obj.hostname || obj.machine || 'unknown').slice(0, 128);
  const user = String(obj.user || obj.username || obj.account || 'unknown').slice(0, 128);
  const ip = String(obj.ip || obj.source_ip || obj.sourceIp || obj.src_ip || '0.0.0.0').slice(0, 64);
  const outcome = String(obj.outcome || obj.result || obj.status || 'unknown').slice(0, 64);
  const stage = String(obj.stage || obj.category || obj.phase || 'Unknown').slice(0, 64);
  const severity = normalizeSeverity(obj.severity || obj.level || obj.priority);
  const destinationPort = parseInt(obj.destinationPort || obj.dest_port || obj.dport || '', 10) || undefined;

  // Canonical content for deduplication
  const canonical = JSON.stringify({ type, host, user, ip, outcome, stage, ts, destinationPort });
  const hash = await contentHash(canonical);

  const normalized = {
    id: null, // assigned after dedup
    ts,
    type,
    host,
    user,
    ip,
    outcome,
    stage,
    source: String(source).slice(0, 128),
    severity,
    synthetic: false,
    destinationPort,
    contentHash: hash,
    raw: JSON.stringify(raw).slice(0, 4096),
  };

  return normalized;
}

function normalizeTimestamp(v) {
  if (!v) return new Date().toISOString();
  if (typeof v === 'number') {
    // Unix seconds or milliseconds
    const ms = v > 1e12 ? v : v * 1000;
    const d = new Date(ms);
    return isNaN(d) ? new Date().toISOString() : d.toISOString();
  }
  const d = new Date(v);
  return isNaN(d) ? new Date().toISOString() : d.toISOString();
}

function normalizeSeverity(v) {
  const s = String(v || '').toLowerCase();
  if (['critical','high','medium','low'].includes(s)) return s;
  if (s === 'info' || s === 'informational') return 'low';
  if (s === 'warn' || s === 'warning') return 'medium';
  if (s === 'error' || s === 'err') return 'high';
  if (s === 'fatal' || s === 'emerg') return 'critical';
  return 'low';
}

/* ── Ingest a single simulator-generated event ──────────────────────── */
export async function ingestSimulatorEvent(fields) {
  // Simulator events already have proper fields
  const ts = new Date().toISOString();
  const canonical = JSON.stringify({ type: fields.type, host: fields.host, user: fields.user, ip: fields.ip, outcome: fields.outcome, stage: fields.stage, ts, destinationPort: fields.destinationPort });
  const hash = await contentHash(canonical);

  const meta = getMeta();
  const id = nextId('EV');

  const event = validateEvent({
    id,
    ts,
    type: String(fields.type || 'Unknown').slice(0, 128),
    host: String(fields.host || 'unknown').slice(0, 128),
    user: String(fields.user || 'unknown').slice(0, 128),
    ip: String(fields.ip || '0.0.0.0').slice(0, 64),
    outcome: String(fields.outcome || 'unknown').slice(0, 64),
    stage: String(fields.stage || 'Unknown').slice(0, 64),
    source: 'Built-in simulator',
    severity: fields.severity || 'medium',
    synthetic: true,
    destinationPort: fields.destinationPort,
    contentHash: hash,
  });

  await idbPut('events', event);
  saveMeta();

  // Run detection rules on this event
  const newDetections = await runDetectionRules([event]);
  if (newDetections.length) {
    meta.detections.push(...newDetections);
    await correlateDetections(newDetections);
    saveMeta();
  }

  return event;
}

/* ── Parse CSV with quoted field support ────────────────────────────── */
export function parseCSV(text) {
  const lines = text.replace(/\r\n?/g, '\n').split('\n');
  if (lines.length < 2) return { headers: [], rows: [] };

  const headers = parseCSVRow(lines[0]);
  const rows = [];

  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    const values = parseCSVRow(line);
    const obj = {};
    headers.forEach((h, idx) => { obj[h.trim()] = values[idx] !== undefined ? values[idx] : ''; });
    rows.push(obj);
  }

  return { headers, rows };
}

function parseCSVRow(line) {
  const fields = [];
  let current = '';
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') { current += '"'; i++; }
      else inQuotes = !inQuotes;
    } else if (ch === ',' && !inQuotes) {
      fields.push(current); current = '';
    } else {
      current += ch;
    }
  }
  fields.push(current);
  return fields;
}

/* ── Validate import row ────────────────────────────────────────────── */
function validateImportRow(row, idx) {
  const errors = [];
  if (!row.type && !row.event_type && !row.eventType && !row.action) {
    errors.push(`Row ${idx}: missing event type field`);
  }
  if (row.ts || row.timestamp || row.time) {
    const ts = row.ts || row.timestamp || row.time;
    if (typeof ts === 'string' && ts.length > 64) errors.push(`Row ${idx}: timestamp too long`);
  }
  // Hostile text check: reject embedded script
  const allValues = Object.values(row).join(' ');
  if (/<script/i.test(allValues)) errors.push(`Row ${idx}: rejected — contains script tag`);
  if (allValues.length > 10000) errors.push(`Row ${idx}: row too large`);
  return errors;
}

/* ── Process imported file (JSON or CSV) ────────────────────────────── */
export async function processImport(fileContent, fileName, source = 'file-import') {
  const result = { accepted: 0, duplicates: 0, rejected: 0, errors: [], events: [] };

  // Parse
  let rows = [];
  const isCSV = fileName.toLowerCase().endsWith('.csv');
  try {
    if (isCSV) {
      const parsed = parseCSV(fileContent);
      rows = parsed.rows;
    } else {
      const parsed = JSON.parse(fileContent);
      rows = Array.isArray(parsed) ? parsed : [parsed];
    }
  } catch (e) {
    result.errors.push(`Parse error: ${e.message}`);
    result.rejected++;
    return result;
  }

  // Process in bounded chunks
  const chunk = rows.slice(0, MAX_BATCH);
  if (rows.length > MAX_BATCH) {
    result.errors.push(`File contains ${rows.length} rows; processing first ${MAX_BATCH}. Re-import remaining rows separately.`);
  }

  const toStore = [];

  for (let i = 0; i < chunk.length; i++) {
    const raw = chunk[i];

    // Row validation
    const rowErrors = validateImportRow(raw, i + 1);
    if (rowErrors.length) {
      result.errors.push(...rowErrors);
      result.rejected++;
      continue;
    }

    try {
      const normalized = await normalizeRecord(raw, source);

      // Check duplicate by content hash
      const existing = await idbFilter_byHash(normalized.contentHash);
      if (existing) {
        result.duplicates++;
        continue;
      }

      normalized.id = nextId('EV');
      const validated = validateEvent(normalized);
      if (!validated || !validated.id) { result.rejected++; continue; }

      toStore.push(validated);
      result.accepted++;
    } catch (e) {
      result.errors.push(`Row ${i + 1}: processing error — ${e.message}`);
      result.rejected++;
    }
  }

  // Batch store
  if (toStore.length) {
    await idbPutBatch('events', toStore);
    // Run detection rules on imported events
    const meta = getMeta();
    const newDetections = await runDetectionRules(toStore);
    if (newDetections.length) {
      meta.detections.push(...newDetections);
      await correlateDetections(newDetections);
      saveMeta();
    }
    result.events = toStore;
  }

  appendAudit(`Imported ${result.accepted} events (${result.duplicates} dupe, ${result.rejected} rejected)`, fileName, 'import');
  return result;
}

async function idbFilter_byHash(hash) {
  if (!hash) return null;
  const db = await import('./store.js').then(m => m.openIDB());
  return new Promise((resolve, reject) => {
    const tx = db.transaction('events', 'readonly');
    const idx = tx.objectStore('events').index('contentHash');
    const req = idx.get(hash);
    req.onsuccess = (e) => resolve(e.target.result || null);
    req.onerror = (e) => reject(e.target.error);
  });
}

/* ── CSV export with injection protection ───────────────────────────── */
export function toCSVLine(values) {
  return values.map(v => {
    let s = String(v ?? '');
    // Formula injection protection: prefix dangerous starts
    if (/^[=+\-@|%]/.test(s)) s = "'" + s;
    // Escape quotes, wrap in quotes if needed
    if (s.includes(',') || s.includes('"') || s.includes('\n')) {
      s = '"' + s.replace(/"/g, '""') + '"';
    }
    return s;
  }).join(',');
}

export function eventsToCSV(events) {
  const headers = ['id','ts','type','host','user','ip','outcome','stage','source','severity','synthetic'];
  const lines = [headers.join(',')];
  for (const e of events) {
    lines.push(toCSVLine(headers.map(h => e[h] ?? '')));
  }
  return lines.join('\n');
}
