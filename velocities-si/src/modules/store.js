/**
 * store.js — authoritative data store with versioned migrations and deep validation.
 * Uses IndexedDB for events/evidence (large, growing), localStorage for preferences
 * and bounded metadata (incidents, audit, settings).
 */
'use strict';

export const STORE_VERSION = 2;
const LS_META_KEY = 'vsi-meta-v2';
const LS_PREFS_KEY = 'vsi-prefs-v2';
const IDB_NAME = 'velocities-si';
const IDB_VERSION = 1;

/* ── Default state ───────────────────────────────────────────────────── */
export function defaultMeta() {
  return {
    version: STORE_VERSION,
    incidents: [],
    detections: [],
    approvalRequests: [],
    executionRecords: [],
    riskHistory: [],
    simulatedTargets: {},
    auditLog: [],
    simState: { scenario: null, step: 0, running: false, seed: 0, cursor: 0 },
    nextId: 1,
  };
}

export function defaultPrefs() {
  return {
    theme: 'dark',
    density: 'comfortable',
    timezone: 'local',
    correlationWindowMinutes: 30,
    ruleThresholds: {
      failedLoginBurst: 5,
      portScanDistinct: 10,
      firewallDenySpike: 8,
      sprayAccounts: 3,
      sprayWindow: 5,
    },
    riskWeights: {
      severity: 0.25,
      confidence: 0.20,
      assetImportance: 0.20,
      impact: 0.20,
      evidenceSupport: 0.15,
    },
    assetImportance: {
      'lab-web-01': 90,
      'lab-web-02': 85,
      'lab-web-03': 80,
      'lab-dc-01': 95,
      'lab-db-01': 90,
    },
    labAllowlist: ['192.0.2.10', '192.0.2.11', '198.51.100.42', '198.51.100.43'],
    riskWeightsVersion: 1,
  };
}

/* ── Validation helpers ──────────────────────────────────────────────── */
function isStr(v) { return typeof v === 'string'; }
function isNum(v) { return typeof v === 'number' && isFinite(v); }
function isBool(v) { return typeof v === 'boolean'; }
function isArr(v) { return Array.isArray(v); }
function isObj(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }

export function validateEvent(e) {
  if (!isObj(e)) return null;
  const id = isStr(e.id) ? e.id.slice(0, 32) : null;
  const ts = isStr(e.ts) && !isNaN(Date.parse(e.ts)) ? e.ts : new Date().toISOString();
  const type = isStr(e.type) ? e.type.slice(0, 128) : 'Unknown';
  const host = isStr(e.host) ? e.host.slice(0, 128) : 'unknown';
  const user = isStr(e.user) ? e.user.slice(0, 128) : 'unknown';
  const ip = isStr(e.ip) ? e.ip.slice(0, 64) : '0.0.0.0';
  const outcome = isStr(e.outcome) ? e.outcome.slice(0, 64) : 'unknown';
  const stage = isStr(e.stage) ? e.stage.slice(0, 64) : 'Unknown';
  const source = isStr(e.source) ? e.source.slice(0, 128) : 'Unknown';
  const severity = ['critical','high','medium','low'].includes(e.severity) ? e.severity : 'low';
  return { id, ts, type, host, user, ip, outcome, stage, source, severity,
    synthetic: !!e.synthetic, raw: isStr(e.raw) ? e.raw.slice(0, 4096) : undefined,
    destinationPort: isNum(e.destinationPort) ? e.destinationPort : undefined,
    contentHash: isStr(e.contentHash) ? e.contentHash : undefined };
}

export function validateIncident(i) {
  if (!isObj(i)) return null;
  const ALLOWED_STATUSES = ['New','Investigating','Contained','Resolved','False positive'];
  return {
    id: isStr(i.id) ? i.id.slice(0, 32) : null,
    title: isStr(i.title) ? i.title.slice(0, 256) : 'Untitled',
    host: isStr(i.host) ? i.host.slice(0, 128) : 'unknown',
    user: isStr(i.user) ? i.user.slice(0, 128) : 'unknown',
    ip: isStr(i.ip) ? i.ip.slice(0, 64) : '0.0.0.0',
    status: ALLOWED_STATUSES.includes(i.status) ? i.status : 'New',
    priority: ['critical','high','medium','low'].includes(i.priority) ? i.priority : 'medium',
    owner: isStr(i.owner) ? i.owner.slice(0, 128) : null,
    notes: isArr(i.notes) ? i.notes.slice(0,100).map(n => isObj(n) ? {
      ts: isStr(n.ts) ? n.ts : new Date().toISOString(),
      author: isStr(n.author) ? n.author.slice(0,128) : 'analyst',
      text: isStr(n.text) ? n.text.slice(0,2048) : ''
    } : null).filter(Boolean) : [],
    risk: isNum(i.risk) ? Math.max(0, Math.min(100, i.risk)) : 0,
    inputs: isObj(i.inputs) ? {
      severity: isNum(i.inputs.severity) ? Math.max(0, Math.min(100, i.inputs.severity)) : 0,
      confidence: isNum(i.inputs.confidence) ? Math.max(0, Math.min(100, i.inputs.confidence)) : 0,
      assetImportance: isNum(i.inputs.assetImportance) ? Math.max(0, Math.min(100, i.inputs.assetImportance)) : 50,
      impact: isNum(i.inputs.impact) ? Math.max(0, Math.min(100, i.inputs.impact)) : 0,
      evidenceSupport: isNum(i.inputs.evidenceSupport) ? Math.max(0, Math.min(100, i.inputs.evidenceSupport)) : 0,
    } : { severity:0, confidence:0, assetImportance:50, impact:0, evidenceSupport:0 },
    riskHistory: isArr(i.riskHistory) ? i.riskHistory.slice(0,200).map(h => isObj(h) ? {
      ts: isStr(h.ts) ? h.ts : new Date().toISOString(),
      score: isNum(h.score) ? h.score : 0,
      before: isNum(h.before) ? h.before : 0,
      inputs: isObj(h.inputs) ? h.inputs : {},
      formulaVersion: isNum(h.formulaVersion) ? h.formulaVersion : 1,
      rationale: isStr(h.rationale) ? h.rationale.slice(0,512) : '',
    } : null).filter(Boolean) : [],
    detectionIds: isArr(i.detectionIds) ? i.detectionIds.filter(isStr) : [],
    eventIds: isArr(i.eventIds) ? i.eventIds.filter(isStr) : [],
    correlationKey: isStr(i.correlationKey) ? i.correlationKey : '',
    createdAt: isStr(i.createdAt) ? i.createdAt : new Date().toISOString(),
    updatedAt: isStr(i.updatedAt) ? i.updatedAt : new Date().toISOString(),
    mitreHypotheses: isArr(i.mitreHypotheses) ? i.mitreHypotheses.slice(0,20).map(m => isObj(m) ? {
      technique: isStr(m.technique) ? m.technique.slice(0,32) : '',
      name: isStr(m.name) ? m.name.slice(0,128) : '',
      stage: isStr(m.stage) ? m.stage.slice(0,64) : '',
      ruleId: isStr(m.ruleId) ? m.ruleId.slice(0,32) : '',
    } : null).filter(Boolean) : [],
  };
}

export function validateDetection(d) {
  if (!isObj(d)) return null;
  return {
    id: isStr(d.id) ? d.id.slice(0,32) : null,
    ruleId: isStr(d.ruleId) ? d.ruleId.slice(0,32) : '',
    ruleVersion: isStr(d.ruleVersion) ? d.ruleVersion.slice(0,16) : 'v1',
    ruleName: isStr(d.ruleName) ? d.ruleName.slice(0,128) : '',
    severity: ['critical','high','medium','low'].includes(d.severity) ? d.severity : 'medium',
    ts: isStr(d.ts) && !isNaN(Date.parse(d.ts)) ? d.ts : new Date().toISOString(),
    host: isStr(d.host) ? d.host.slice(0,128) : 'unknown',
    user: isStr(d.user) ? d.user.slice(0,128) : 'unknown',
    ip: isStr(d.ip) ? d.ip.slice(0,64) : '',
    triggeringEventIds: isArr(d.triggeringEventIds) ? d.triggeringEventIds.filter(isStr).slice(0,200) : [],
    windowMinutes: isNum(d.windowMinutes) ? d.windowMinutes : 5,
    threshold: isNum(d.threshold) ? d.threshold : 1,
    matched: isNum(d.matched) ? d.matched : 1,
    explanation: isStr(d.explanation) ? d.explanation.slice(0,1024) : '',
    mitreTechnique: isStr(d.mitreTechnique) ? d.mitreTechnique.slice(0,32) : '',
    mitreName: isStr(d.mitreName) ? d.mitreName.slice(0,128) : '',
    incidentId: isStr(d.incidentId) ? d.incidentId.slice(0,32) : null,
    suppressed: isBool(d.suppressed) ? d.suppressed : false,
  };
}

/* ── Meta (localStorage) ─────────────────────────────────────────────── */
let _meta = null;

export function loadMeta() {
  try {
    const raw = localStorage.getItem(LS_META_KEY);
    if (!raw) { _meta = defaultMeta(); return _meta; }
    const parsed = JSON.parse(raw);
    if (!isObj(parsed) || parsed.version !== STORE_VERSION) {
      _meta = migrateMeta(parsed); return _meta;
    }
    _meta = repairMeta(parsed);
  } catch {
    _meta = defaultMeta();
  }
  return _meta;
}

function migrateMeta(old) {
  // v1 → v2: add new fields
  const m = defaultMeta();
  if (!isObj(old)) return m;
  // Attempt to import old incidents
  if (isArr(old.incidents)) {
    m.incidents = old.incidents.map(validateIncident).filter(Boolean);
  }
  if (isArr(old.audit)) {
    m.auditLog = old.audit.slice(0,5000).map(a => isObj(a) ? {
      ts: isStr(a.time) ? a.time : new Date().toISOString(),
      actor: isStr(a.actor) ? a.actor : 'analyst',
      action: isStr(a.action) ? a.action : '',
      entity: isStr(a.entity) ? a.entity : '',
      category: 'migrated',
    } : null).filter(Boolean);
  }
  if (isNum(old.next)) m.nextId = old.next;
  return m;
}

function repairMeta(m) {
  const def = defaultMeta();
  return {
    version: STORE_VERSION,
    incidents: isArr(m.incidents) ? m.incidents.map(validateIncident).filter(Boolean) : def.incidents,
    detections: isArr(m.detections) ? m.detections.map(validateDetection).filter(Boolean) : def.detections,
    approvalRequests: isArr(m.approvalRequests) ? m.approvalRequests.slice(0,1000) : def.approvalRequests,
    executionRecords: isArr(m.executionRecords) ? m.executionRecords.slice(0,1000) : def.executionRecords,
    riskHistory: isArr(m.riskHistory) ? m.riskHistory.slice(0,5000) : def.riskHistory,
    simulatedTargets: isObj(m.simulatedTargets) ? m.simulatedTargets : def.simulatedTargets,
    auditLog: isArr(m.auditLog) ? m.auditLog.slice(0,10000) : def.auditLog,
    simState: isObj(m.simState) ? {
      scenario: isStr(m.simState.scenario) ? m.simState.scenario : null,
      step: isNum(m.simState.step) ? m.simState.step : 0,
      running: false, // always restore as paused
      seed: isNum(m.simState.seed) ? m.simState.seed : 0,
      cursor: isNum(m.simState.cursor) ? m.simState.cursor : 0,
    } : def.simState,
    nextId: isNum(m.nextId) ? m.nextId : def.nextId,
  };
}

export function getMeta() {
  if (!_meta) loadMeta();
  return _meta;
}

export function saveMeta() {
  try {
    localStorage.setItem(LS_META_KEY, JSON.stringify(_meta));
    return true;
  } catch (e) {
    console.error('Storage save failed:', e);
    return false;
  }
}

export function nextId(prefix = 'ID') {
  const n = _meta.nextId++;
  return `${prefix}-${String(n).padStart(5, '0')}`;
}

/* ── Preferences (localStorage) ─────────────────────────────────────── */
let _prefs = null;

export function loadPrefs() {
  try {
    const raw = localStorage.getItem(LS_PREFS_KEY);
    if (!raw) { _prefs = defaultPrefs(); return _prefs; }
    const parsed = JSON.parse(raw);
    _prefs = mergePrefs(parsed);
  } catch {
    _prefs = defaultPrefs();
  }
  return _prefs;
}

function mergePrefs(p) {
  const def = defaultPrefs();
  if (!isObj(p)) return def;
  const weights = isObj(p.riskWeights) ? p.riskWeights : def.riskWeights;
  // Validate weights sum to ~1
  const wSum = Object.values(weights).reduce((a, b) => a + (isNum(b) ? b : 0), 0);
  const validWeights = Math.abs(wSum - 1.0) < 0.01 ? weights : def.riskWeights;
  return {
    theme: ['dark','light'].includes(p.theme) ? p.theme : def.theme,
    density: ['comfortable','compact','spacious'].includes(p.density) ? p.density : def.density,
    timezone: ['local','utc'].includes(p.timezone) ? p.timezone : def.timezone,
    correlationWindowMinutes: isNum(p.correlationWindowMinutes) && p.correlationWindowMinutes > 0 ? p.correlationWindowMinutes : def.correlationWindowMinutes,
    ruleThresholds: isObj(p.ruleThresholds) ? {
      failedLoginBurst: isNum(p.ruleThresholds.failedLoginBurst) ? Math.max(2, p.ruleThresholds.failedLoginBurst) : def.ruleThresholds.failedLoginBurst,
      portScanDistinct: isNum(p.ruleThresholds.portScanDistinct) ? Math.max(2, p.ruleThresholds.portScanDistinct) : def.ruleThresholds.portScanDistinct,
      firewallDenySpike: isNum(p.ruleThresholds.firewallDenySpike) ? Math.max(2, p.ruleThresholds.firewallDenySpike) : def.ruleThresholds.firewallDenySpike,
      sprayAccounts: isNum(p.ruleThresholds.sprayAccounts) ? Math.max(2, p.ruleThresholds.sprayAccounts) : def.ruleThresholds.sprayAccounts,
      sprayWindow: isNum(p.ruleThresholds.sprayWindow) ? Math.max(1, p.ruleThresholds.sprayWindow) : def.ruleThresholds.sprayWindow,
    } : def.ruleThresholds,
    riskWeights: validWeights,
    assetImportance: isObj(p.assetImportance) ? { ...def.assetImportance, ...p.assetImportance } : def.assetImportance,
    labAllowlist: isArr(p.labAllowlist) ? p.labAllowlist.filter(isStr) : def.labAllowlist,
    riskWeightsVersion: isNum(p.riskWeightsVersion) ? p.riskWeightsVersion : def.riskWeightsVersion,
  };
}

export function getPrefs() {
  if (!_prefs) loadPrefs();
  return _prefs;
}

export function savePrefs() {
  try {
    localStorage.setItem(LS_PREFS_KEY, JSON.stringify(_prefs));
    return true;
  } catch (e) {
    console.error('Prefs save failed:', e);
    return false;
  }
}

/* ── IndexedDB for events ────────────────────────────────────────────── */
let _db = null;

export async function openIDB() {
  if (_db) return _db;
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(IDB_NAME, IDB_VERSION);
    req.onupgradeneeded = (e) => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains('events')) {
        const store = db.createObjectStore('events', { keyPath: 'id' });
        store.createIndex('ts', 'ts');
        store.createIndex('host', 'host');
        store.createIndex('user', 'user');
        store.createIndex('ip', 'ip');
        store.createIndex('contentHash', 'contentHash');
      }
      if (!db.objectStoreNames.contains('rawImports')) {
        db.createObjectStore('rawImports', { keyPath: 'id' });
      }
    };
    req.onsuccess = (e) => { _db = e.target.result; resolve(_db); };
    req.onerror = (e) => reject(e.target.error);
  });
}

export async function idbPut(storeName, record) {
  const db = await openIDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    tx.objectStore(storeName).put(record).onsuccess = (e) => resolve(e.target.result);
    tx.onerror = (e) => reject(e.target.error);
  });
}

export async function idbPutBatch(storeName, records) {
  const db = await openIDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    const store = tx.objectStore(storeName);
    let done = 0;
    for (const r of records) store.put(r);
    tx.oncomplete = () => resolve(done);
    tx.onerror = (e) => reject(e.target.error);
  });
}

export async function idbGetAll(storeName, { sortBy = 'ts', direction = 'prev', limit = 2000, offset = 0 } = {}) {
  const db = await openIDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const store = tx.objectStore(storeName);
    const index = store.index(sortBy);
    const results = [];
    let skipped = 0;
    const req = index.openCursor(null, direction);
    req.onsuccess = (e) => {
      const cursor = e.target.result;
      if (!cursor || results.length >= limit) { resolve(results); return; }
      if (skipped < offset) { skipped++; cursor.continue(); return; }
      results.push(cursor.value);
      cursor.continue();
    };
    req.onerror = (e) => reject(e.target.error);
  });
}

export async function idbCount(storeName) {
  const db = await openIDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const req = tx.objectStore(storeName).count();
    req.onsuccess = (e) => resolve(e.target.result);
    req.onerror = (e) => reject(e.target.error);
  });
}

export async function idbGetById(storeName, id) {
  const db = await openIDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const req = tx.objectStore(storeName).get(id);
    req.onsuccess = (e) => resolve(e.target.result || null);
    req.onerror = (e) => reject(e.target.error);
  });
}

export async function idbClear(storeName) {
  const db = await openIDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    tx.objectStore(storeName).clear().onsuccess = resolve;
    tx.onerror = (e) => reject(e.target.error);
  });
}

export async function idbFilter(storeName, predicate, { limit = 500 } = {}) {
  const db = await openIDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const results = [];
    const req = tx.objectStore(storeName).openCursor(null, 'prev');
    req.onsuccess = (e) => {
      const cursor = e.target.result;
      if (!cursor || results.length >= limit) { resolve(results); return; }
      if (predicate(cursor.value)) results.push(cursor.value);
      cursor.continue();
    };
    req.onerror = (e) => reject(e.target.error);
  });
}

/* ── Audit helpers ──────────────────────────────────────────────────── */
export function appendAudit(action, entity, category = 'general', details = null) {
  const m = getMeta();
  m.auditLog.unshift({
    ts: new Date().toISOString(),
    actor: 'Demo analyst',
    action: String(action).slice(0, 256),
    entity: String(entity).slice(0, 128),
    category: String(category).slice(0, 64),
    details: details ? JSON.stringify(details).slice(0, 1024) : null,
  });
  if (m.auditLog.length > 10000) m.auditLog.length = 10000;
  saveMeta();
}

/* ── Content hashing ─────────────────────────────────────────────────── */
export async function contentHash(str) {
  const buf = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2,'0')).join('').slice(0,32);
}

/* ── Full reset ─────────────────────────────────────────────────────── */
export async function fullReset() {
  _meta = defaultMeta();
  saveMeta();
  try { await idbClear('events'); } catch {}
  try { await idbClear('rawImports'); } catch {}
}
