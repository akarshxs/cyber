/**
 * response.js — response center with separate request, approval, execution records.
 * Simulated targets are mutable local records; execution mutates and re-reads state.
 */
'use strict';

import { getMeta, getPrefs, nextId, saveMeta, appendAudit } from './store.js';

/* ── Simulated target registry ──────────────────────────────────────── */
export function initSimulatedTargets() {
  const meta = getMeta();
  const defaults = {
    'lab-web-01': { host: 'lab-web-01', ip: '192.0.2.10', networkIsolated: false, sessionsActive: true, blockedIPs: [] },
    'lab-web-02': { host: 'lab-web-02', ip: '192.0.2.11', networkIsolated: false, sessionsActive: true, blockedIPs: [] },
    'lab-web-03': { host: 'lab-web-03', ip: '192.0.2.12', networkIsolated: false, sessionsActive: true, blockedIPs: [] },
    'lab-dc-01': { host: 'lab-dc-01', ip: '192.0.2.20', networkIsolated: false, sessionsActive: true, blockedIPs: [] },
    'lab-db-01': { host: 'lab-db-01', ip: '192.0.2.30', networkIsolated: false, sessionsActive: true, blockedIPs: [] },
  };
  for (const [k, v] of Object.entries(defaults)) {
    if (!meta.simulatedTargets[k]) meta.simulatedTargets[k] = v;
  }
  saveMeta();
}

/* ── Approval state machine ─────────────────────────────────────────── */
export const APPROVAL_EXPIRY_MS = 30 * 60 * 1000; // 30 minutes

export function createRequest(incidentId, playbook, scope, requestedBy = 'Demo analyst') {
  const meta = getMeta();
  const reqId = nextId('REQ');
  const req = {
    id: reqId,
    incidentId,
    playbook,
    scope, // { type: 'isolate'|'block-ip'|'revoke-sessions'|'collect-evidence', target: string }
    status: 'pending', // pending | approved | rejected | expired | superseded
    requestedBy,
    requestedAt: new Date().toISOString(),
    decidedBy: null,
    decidedAt: null,
    decisionReason: null,
    expiresAt: null,
    approvalId: null,
    executionId: null,
    scopeHash: hashScope(scope),
  };
  meta.approvalRequests.push(req);
  saveMeta();
  appendAudit(`Response request created: ${playbook}`, reqId, 'response', { incidentId, scope });
  return req;
}

function hashScope(scope) {
  return JSON.stringify(scope);
}

export function approveRequest(reqId, decidedBy = 'Demo approver', reason = '') {
  const meta = getMeta();
  const req = meta.approvalRequests.find(r => r.id === reqId);
  if (!req) return { ok: false, error: 'Request not found' };
  if (req.status !== 'pending') return { ok: false, error: `Cannot approve: status is ${req.status}` };

  // Supersede any other active approvals for the same incident
  for (const other of meta.approvalRequests) {
    if (other.id !== reqId && other.incidentId === req.incidentId && other.status === 'approved') {
      other.status = 'superseded';
      appendAudit('Prior approval superseded', other.id, 'response');
    }
  }

  req.status = 'approved';
  req.decidedBy = decidedBy;
  req.decidedAt = new Date().toISOString();
  req.decisionReason = reason || 'Approved by demo persona';
  req.expiresAt = new Date(Date.now() + APPROVAL_EXPIRY_MS).toISOString();
  saveMeta();
  appendAudit(`Request approved by ${decidedBy}`, reqId, 'response', { reason });
  return { ok: true, req };
}

export function rejectRequest(reqId, decidedBy = 'Demo approver', reason = '') {
  const meta = getMeta();
  const req = meta.approvalRequests.find(r => r.id === reqId);
  if (!req) return { ok: false, error: 'Request not found' };
  if (req.status !== 'pending') return { ok: false, error: `Cannot reject: status is ${req.status}` };
  req.status = 'rejected';
  req.decidedBy = decidedBy;
  req.decidedAt = new Date().toISOString();
  req.decisionReason = reason || 'Rejected by demo persona';
  saveMeta();
  appendAudit(`Request rejected by ${decidedBy}`, reqId, 'response', { reason });
  return { ok: true, req };
}

/* ── Execution ──────────────────────────────────────────────────────── */
export function executeAction(reqId, executedBy = 'Demo analyst') {
  const meta = getMeta();
  const prefs = getPrefs();
  const req = meta.approvalRequests.find(r => r.id === reqId);

  if (!req) return { ok: false, error: 'Request not found', blocked: true };
  if (req.status !== 'approved') return { ok: false, error: `Blocked: approval status is "${req.status}"`, blocked: true };

  // Recheck expiry
  if (new Date(req.expiresAt) < new Date()) {
    req.status = 'expired';
    saveMeta();
    appendAudit('Execution blocked: approval expired', reqId, 'response');
    return { ok: false, error: 'Blocked: approval has expired', blocked: true };
  }

  // Recheck scope has not changed
  const currentHash = hashScope(req.scope);
  if (currentHash !== req.scopeHash) {
    req.status = 'superseded';
    saveMeta();
    appendAudit('Execution blocked: scope modified', reqId, 'response');
    return { ok: false, error: 'Blocked: scope was modified after approval', blocked: true };
  }

  // Allowlist check
  const target = req.scope?.target;
  if (req.scope?.type === 'block-ip') {
    if (!prefs.labAllowlist.includes(target)) {
      appendAudit(`Execution blocked: IP not in lab allowlist`, reqId, 'response', { target });
      return { ok: false, error: `Blocked: ${target} is not in the lab allowlist. Only allowlisted IPs can be blocked in simulation.`, blocked: true };
    }
  }
  if (req.scope?.type === 'isolate') {
    const hostKey = Object.keys(meta.simulatedTargets).find(k => k === target || meta.simulatedTargets[k].ip === target);
    if (!hostKey) {
      appendAudit(`Execution blocked: host not in simulated targets`, reqId, 'response', { target });
      return { ok: false, error: `Blocked: ${target} is not a known lab host. Only lab hosts may be isolated.`, blocked: true };
    }
  }

  // Prevent duplicate execution
  if (req.executionId) {
    return { ok: false, error: `Already executed: ${req.executionId}`, blocked: true };
  }

  // Mutate simulated target
  const execId = nextId('EXEC');
  const execRecord = {
    id: execId,
    reqId,
    incidentId: req.incidentId,
    playbook: req.playbook,
    scope: req.scope,
    executedBy,
    executedAt: new Date().toISOString(),
    outcome: null,
    verified: false,
    verificationMessage: null,
    rollbackId: null,
    priorState: null,
  };

  // Perform mutation and read back
  const mutationResult = mutateTarget(req.scope, meta);
  execRecord.priorState = mutationResult.priorState;
  execRecord.outcome = mutationResult.outcome;

  // Re-read and verify
  const verResult = verifyTarget(req.scope, meta);
  execRecord.verified = verResult.passed;
  execRecord.verificationMessage = verResult.message;

  req.executionId = execId;
  req.status = req.status; // stays approved until execution result
  meta.executionRecords.push(execRecord);
  saveMeta();

  const outcome = execRecord.verified ? 'Simulation verified' : 'Simulation unverified';
  appendAudit(`${outcome}: ${req.playbook}`, execId, 'response', { reqId, incidentId: req.incidentId });
  return { ok: true, execRecord, outcome };
}

function mutateTarget(scope, meta) {
  const { type, target } = scope;
  let priorState = null;

  if (type === 'isolate') {
    const t = findTarget(target, meta);
    if (t) {
      priorState = { ...t };
      t.networkIsolated = true;
    }
    return { outcome: `Lab host ${target} set to network-isolated in simulation`, priorState };
  }

  if (type === 'block-ip') {
    const t = findTargetByIp(target, meta) || findTarget(target, meta);
    if (t) {
      priorState = { ...t, blockedIPs: [...t.blockedIPs] };
      if (!t.blockedIPs.includes(target)) t.blockedIPs.push(target);
    }
    return { outcome: `IP ${target} added to blocked list in simulation`, priorState };
  }

  if (type === 'revoke-sessions') {
    const t = findTarget(target, meta);
    if (t) {
      priorState = { ...t };
      t.sessionsActive = false;
    }
    return { outcome: `Active sessions revoked for ${target} in simulation`, priorState };
  }

  if (type === 'collect-evidence') {
    return { outcome: `Evidence collected for ${target} in simulation`, priorState: null };
  }

  return { outcome: `Unknown action type: ${type}`, priorState };
}

function verifyTarget(scope, meta) {
  const { type, target } = scope;

  if (type === 'isolate') {
    const t = findTarget(target, meta);
    if (t && t.networkIsolated === true) {
      return { passed: true, message: `Verified: ${target}.networkIsolated = true` };
    }
    return { passed: false, message: `Verification failed: ${target} not found or not isolated` };
  }

  if (type === 'block-ip') {
    const t = findTargetByIp(target, meta) || findTarget(target, meta);
    if (t && t.blockedIPs.includes(target)) {
      return { passed: true, message: `Verified: ${target} in blockedIPs list` };
    }
    return { passed: false, message: `Verification failed: ${target} not in blocked list` };
  }

  if (type === 'revoke-sessions') {
    const t = findTarget(target, meta);
    if (t && t.sessionsActive === false) {
      return { passed: true, message: `Verified: ${target}.sessionsActive = false` };
    }
    return { passed: false, message: `Verification failed: ${target} sessions still active` };
  }

  return { passed: true, message: 'No verification step for this action type' };
}

function findTarget(host, meta) {
  return meta.simulatedTargets[host] || null;
}

function findTargetByIp(ip, meta) {
  return Object.values(meta.simulatedTargets).find(t => t.ip === ip) || null;
}

/* ── Rollback ─────────────────────────────────────────────────────── */
export function rollbackExecution(execId, rolledBackBy = 'Demo analyst') {
  const meta = getMeta();
  const exec = meta.executionRecords.find(e => e.id === execId);
  if (!exec) return { ok: false, error: 'Execution record not found' };
  if (exec.rollbackId) return { ok: false, error: `Already rolled back: ${exec.rollbackId}` };
  if (!exec.priorState) return { ok: false, error: 'No prior state captured; rollback unavailable' };

  const rbId = nextId('RB');
  // Restore prior state
  const key = exec.priorState.host;
  if (key && meta.simulatedTargets[key]) {
    meta.simulatedTargets[key] = { ...exec.priorState };
  }

  // Verify rollback
  const verResult = verifyRollback(exec, meta);

  const rbRecord = {
    id: rbId,
    execId,
    rolledBackBy,
    rolledBackAt: new Date().toISOString(),
    verified: verResult.passed,
    verificationMessage: verResult.message,
  };

  exec.rollbackId = rbId;
  meta.executionRecords.push(rbRecord);
  saveMeta();
  appendAudit(`Rollback ${verResult.passed ? 'verified' : 'unverified'}`, rbId, 'response', { execId });
  return { ok: true, rbRecord, verified: verResult.passed };
}

function verifyRollback(exec, meta) {
  const { type, target } = exec.scope || {};
  if (type === 'isolate') {
    const t = findTarget(target, meta);
    if (t && t.networkIsolated === false) {
      return { passed: true, message: `Rollback verified: ${target}.networkIsolated = false` };
    }
    return { passed: false, message: `Rollback verification failed: ${target} still isolated` };
  }
  if (type === 'revoke-sessions') {
    const t = findTarget(target, meta);
    if (t && t.sessionsActive === true) {
      return { passed: true, message: `Rollback verified: ${target}.sessionsActive = true` };
    }
    return { passed: false, message: `Rollback verification failed` };
  }
  return { passed: true, message: 'Rollback state restored' };
}

/* ── Check and expire stale approvals ───────────────────────────────── */
export function checkApprovalExpiry() {
  const meta = getMeta();
  let changed = false;
  const now = new Date();
  for (const req of meta.approvalRequests) {
    if (req.status === 'approved' && req.expiresAt && new Date(req.expiresAt) < now) {
      req.status = 'expired';
      appendAudit('Approval expired', req.id, 'response');
      changed = true;
    }
  }
  if (changed) saveMeta();
}
