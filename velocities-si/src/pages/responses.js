/**
 * pages/responses.js — Response center with separate request/approval/execution records,
 * four playbooks, expiry checking, allowlist enforcement.
 */
'use strict';

import { getMeta, getPrefs, saveMeta, appendAudit } from '../modules/store.js';
import { createRequest, approveRequest, rejectRequest, executeAction, rollbackExecution, checkApprovalExpiry, initSimulatedTargets } from '../modules/response.js';
import { esc, statusBadge, severityBadge, relativeTime, icon, showToast, openDialog, closeDialog } from '../modules/ui.js';

const PLAYBOOKS = [
  {
    id: 'collect-evidence',
    name: 'Collect evidence',
    type: 'collect-evidence',
    scope_type: 'collect-evidence',
    description: 'Capture memory, logs, and forensic artifacts from the target host for offline analysis.',
    prerequisites: ['Incident must be in Investigating or Contained status', 'Host must be in lab allowlist'],
    impact: 'Read-only. No host state change.',
    rollback: 'No rollback needed.',
    verification: 'Evidence package created in simulation.',
    severity: 'low',
  },
  {
    id: 'revoke-sessions',
    name: 'Revoke simulated sessions',
    type: 'revoke-sessions',
    scope_type: 'revoke-sessions',
    description: 'Terminate active sessions for the compromised account on the lab host.',
    prerequisites: ['Incident must be in Investigating or Contained status', 'Target host in simulated target registry'],
    impact: 'Active sessions set to false in simulated target. Any in-progress work would be interrupted.',
    rollback: 'Restore sessions to active in simulated state.',
    verification: 'host.sessionsActive verified as false.',
    severity: 'medium',
  },
  {
    id: 'block-ip',
    name: 'Block lab IP',
    type: 'block-ip',
    scope_type: 'block-ip',
    description: 'Add source IP to the lab deny list in simulation.',
    prerequisites: ['IP must be in lab allowlist', 'Approval required before execution'],
    impact: 'IP added to blockedIPs in simulated target. Does not affect real firewall.',
    rollback: 'Remove IP from blocked list in simulated state.',
    verification: 'IP verified in blockedIPs list.',
    severity: 'medium',
  },
  {
    id: 'isolate-host',
    name: 'Isolate lab host',
    type: 'isolate',
    scope_type: 'isolate',
    description: 'Set the lab host to network-isolated in the simulation. Simulates cutting network connectivity.',
    prerequisites: ['Host must be in simulated target registry', 'Approval required', 'Approval must not be expired', 'Scope must not have changed after approval'],
    impact: 'host.networkIsolated set to true. Simulates service outage for that host.',
    rollback: 'Restore host.networkIsolated to false and verify.',
    verification: 'host.networkIsolated verified as true.',
    severity: 'high',
  },
];

export function renderResponses(container) {
  checkApprovalExpiry();
  initSimulatedTargets();
  const meta = getMeta();
  const prefs = getPrefs();

  const incidents = meta.incidents.filter(i => !['Resolved','False positive'].includes(i.status));
  const requests = meta.approvalRequests || [];
  const executions = meta.executionRecords || [];
  const targets = meta.simulatedTargets || {};

  container.innerHTML = `
    <div class="responses-layout">
      <!-- Playbooks -->
      <section class="panel" aria-labelledby="playbooks-heading">
        <div class="panel-head">
          <h2 id="playbooks-heading">Response playbooks</h2>
          <span class="tag">BROWSER SIMULATION</span>
        </div>
        <p class="small muted">Demo persona separation illustrates four-eyes review but is not enforced. No real infrastructure is contacted. Scope, prerequisites, and allowlists are checked at execution time.</p>
        
        ${!incidents.length ? '<div class="empty-state"><p class="muted">No active incidents. Run a scenario to generate response opportunities.</p></div>' : ''}

        ${incidents.map(inc => renderIncidentPlaybooks(inc, requests, executions, prefs)).join('')}
      </section>

      <!-- Simulated targets -->
      <section class="panel" aria-labelledby="targets-heading">
        <div class="panel-head">
          <h2 id="targets-heading">Lab environment state</h2>
          <span class="muted small">Simulated only</span>
        </div>
        <div class="table-wrap" tabindex="0">
          <table aria-label="Simulated lab targets">
            <thead>
              <tr><th>HOST</th><th>IP</th><th>ISOLATED</th><th>SESSIONS</th><th>BLOCKED IPS</th></tr>
            </thead>
            <tbody>
              ${Object.values(targets).map(t => `
                <tr>
                  <td>${esc(t.host)}</td>
                  <td>${esc(t.ip)}</td>
                  <td><span class="${t.networkIsolated ? 'text-red' : 'text-teal'}">${t.networkIsolated ? 'Isolated' : 'Connected'}</span></td>
                  <td><span class="${t.sessionsActive ? 'text-teal' : 'text-amber'}">${t.sessionsActive ? 'Active' : 'Revoked'}</span></td>
                  <td>${t.blockedIPs?.length ? t.blockedIPs.map(esc).join(', ') : '<span class="muted">—</span>'}</td>
                </tr>`).join('')}
            </tbody>
          </table>
        </div>

        <!-- Approval queue -->
        <div class="panel-head" style="margin-top:24px">
          <h3>Approval queue</h3>
        </div>
        ${requests.filter(r => r.status === 'pending').length === 0
          ? '<p class="muted small">No pending approvals.</p>'
          : requests.filter(r => r.status === 'pending').map(r => renderApprovalQueueItem(r)).join('')}

        <!-- Execution history -->
        <div class="panel-head" style="margin-top:24px">
          <h3>Execution history</h3>
        </div>
        ${executions.length === 0
          ? '<p class="muted small">No executions yet.</p>'
          : `<div class="table-wrap"><table><thead><tr><th>ID</th><th>PLAYBOOK</th><th>TIME</th><th>VERIFIED</th><th>ROLLBACK</th></tr></thead><tbody>
            ${executions.slice(-10).reverse().map(e => `
              <tr>
                <td class="mono-sm">${esc(e.id)}</td>
                <td>${esc(e.playbook)}</td>
                <td>${relativeTime(e.executedAt)}</td>
                <td><span class="${e.verified ? 'text-teal' : 'text-red'}">${e.verified ? 'Simulation verified' : 'Unverified'}</span></td>
                <td>${e.rollbackId ? `<span class="text-teal">${esc(e.rollbackId)}</span>` : '<span class="muted">—</span>'}</td>
              </tr>`).join('')}
          </tbody></table></div>`}
      </section>
    </div>
  `;

  bindResponseHandlers(container, incidents, requests, executions, prefs);
}

function renderIncidentPlaybooks(inc, requests, executions, prefs) {
  return `
    <div class="incident-playbook-group">
      <div class="ipg-header">
        <strong>${esc(inc.id)}: ${esc(inc.title)}</strong>
        <span class="muted small">${esc(inc.host)} · ${esc(inc.ip)}</span>
      </div>
      <div class="playbook-grid">
        ${PLAYBOOKS.map(pb => renderPlaybookCard(pb, inc, requests, executions, prefs)).join('')}
      </div>
    </div>`;
}

function renderPlaybookCard(pb, inc, requests, executions, prefs) {
  // Find the most recent request for this incident+playbook
  const req = [...requests].filter(r => r.incidentId === inc.id && r.playbook === pb.name).sort((a,b) => new Date(b.requestedAt)-new Date(a.requestedAt))[0];
  const exec = req?.executionId ? executions.find(e => e.id === req.executionId) : null;

  const canRequest = !req || req.status === 'rejected' || req.status === 'expired' || req.status === 'superseded';
  const canApprove = req?.status === 'pending';
  const canReject = req?.status === 'pending';
  const canExecute = req?.status === 'approved' && !req.executionId;
  const canRollback = exec && exec.verified && !exec.rollbackId;
  const expiresAt = req?.expiresAt ? new Date(req.expiresAt) : null;
  const isExpired = expiresAt && expiresAt < new Date();

  let statusLine = '';
  if (req) {
    if (req.status === 'pending') statusLine = `<span class="status-badge status-new">Pending approval</span>`;
    else if (req.status === 'approved' && !isExpired) statusLine = `<span class="status-badge status-contained">Approved — expires ${expiresAt?.toLocaleTimeString()}</span>`;
    else if (req.status === 'approved' && isExpired) statusLine = `<span class="status-badge status-fp">Approval expired</span>`;
    else if (req.status === 'rejected') statusLine = `<span class="status-badge status-fp">Rejected: ${esc(req.decisionReason?.slice(0,40) || '')}</span>`;
    else if (exec?.verified) statusLine = `<span class="status-badge status-resolved">Simulation verified</span>`;
    else if (exec) statusLine = `<span class="status-badge status-investigating">Execution: ${esc(exec.verificationMessage?.slice(0,40)||'')}</span>`;
    else statusLine = statusBadge(req.status);
  }

  return `
    <article class="playbook-card" aria-labelledby="pb-${esc(pb.id)}-${esc(inc.id)}">
      <div class="pb-head">
        <span class="pb-severity" style="color:var(--${pb.severity === 'high' ? 'amber' : pb.severity === 'medium' ? 'yellow' : 'teal'})">${pb.severity.toUpperCase()}</span>
        ${severityBadge(pb.severity)}
      </div>
      <h3 id="pb-${esc(pb.id)}-${esc(inc.id)}">${esc(pb.name)}</h3>
      <p class="small">${esc(pb.description)}</p>

      <details class="pb-details">
        <summary class="small">Scope &amp; prerequisites</summary>
        <ul class="small">${pb.prerequisites.map(p => `<li>${esc(p)}</li>`).join('')}</ul>
        <p class="small"><strong>Impact:</strong> ${esc(pb.impact)}</p>
        <p class="small"><strong>Rollback:</strong> ${esc(pb.rollback)}</p>
        <p class="small"><strong>Verification:</strong> ${esc(pb.verification)}</p>
      </details>

      ${statusLine ? `<div class="pb-status">${statusLine}</div>` : ''}

      <div class="pb-actions">
        <button class="btn-secondary btn-sm" data-pb-request="${esc(pb.id)}" data-pb-inc="${esc(inc.id)}"
          ${canRequest ? '' : 'disabled'} ${!canRequest ? `title="A ${req?.status} request exists for this playbook"` : ''}>
          ${icon('check')} Request
        </button>
        <button class="btn-secondary btn-sm" data-pb-approve="${req?.id || ''}" ${canApprove ? '' : 'disabled'}>
          Approve
        </button>
        <button class="btn-ghost btn-sm text-red" data-pb-reject="${req?.id || ''}" ${canReject ? '' : 'disabled'}>
          Reject
        </button>
        <button class="btn-primary btn-sm" data-pb-execute="${req?.id || ''}" ${canExecute ? '' : 'disabled'}
          ${!canExecute && req?.status === 'approved' && req.executionId ? 'title="Already executed"' : ''}>
          Simulate
        </button>
        <button class="btn-secondary btn-sm" data-pb-rollback="${exec?.id || ''}" ${canRollback ? '' : 'disabled'}>
          Rollback
        </button>
      </div>
    </article>
  `;
}

function renderApprovalQueueItem(r) {
  return `
    <div class="approval-queue-item">
      <span class="muted small">${esc(r.id)}</span>
      <strong>${esc(r.playbook)}</strong>
      <span class="muted small">for ${esc(r.incidentId)}</span>
      <span class="muted small">${relativeTime(r.requestedAt)}</span>
    </div>`;
}

function bindResponseHandlers(container, incidents, requests, executions, prefs) {
  // Request
  container.querySelectorAll('[data-pb-request]').forEach(btn => {
    btn.addEventListener('click', () => {
      const pbId = btn.dataset.pbRequest;
      const incId = btn.dataset.pbInc;
      const pb = PLAYBOOKS.find(p => p.id === pbId);
      const inc = incidents.find(i => i.id === incId);
      if (!pb || !inc) return;

      // Determine target
      let target = inc.host;
      if (pb.scope_type === 'block-ip') target = inc.ip;

      const req = createRequest(incId, pb.name, { type: pb.scope_type, target });
      showToast(`Request created: ${pb.name} for ${incId}. Awaiting approval.`, 'success');
      renderResponses(container);
    });
  });

  // Approve
  container.querySelectorAll('[data-pb-approve]').forEach(btn => {
    btn.addEventListener('click', () => {
      const reqId = btn.dataset.pbApprove;
      if (!reqId) return;
      const result = approveRequest(reqId, 'Demo approver', 'Approved via demo persona');
      if (result.ok) showToast('Request approved. Valid for 30 minutes.', 'success');
      else showToast(result.error, 'error');
      renderResponses(container);
    });
  });

  // Reject
  container.querySelectorAll('[data-pb-reject]').forEach(btn => {
    btn.addEventListener('click', () => {
      const reqId = btn.dataset.pbReject;
      if (!reqId) return;
      openDialog('Reject request', `
        <p>Provide a reason for rejection:</p>
        <textarea id="reject-reason" class="textarea-sm" rows="2" placeholder="Reason…" aria-label="Rejection reason"></textarea>
        <div class="dialog-actions">
          <button class="btn-primary" id="confirm-reject">Confirm rejection</button>
          <button class="btn-secondary" id="cancel-reject">Cancel</button>
        </div>
      `);
      document.getElementById('confirm-reject')?.addEventListener('click', () => {
        const reason = document.getElementById('reject-reason')?.value || 'Rejected by demo persona';
        const result = rejectRequest(reqId, 'Demo approver', reason);
        closeDialog();
        if (result.ok) showToast('Request rejected.', 'info');
        else showToast(result.error, 'error');
        renderResponses(container);
      });
      document.getElementById('cancel-reject')?.addEventListener('click', closeDialog);
    });
  });

  // Execute
  container.querySelectorAll('[data-pb-execute]').forEach(btn => {
    btn.addEventListener('click', () => {
      const reqId = btn.dataset.pbExecute;
      if (!reqId) return;
      const result = executeAction(reqId, 'Demo analyst');
      if (result.ok) {
        const msg = result.execRecord.verified
          ? `Simulation verified: ${result.execRecord.verificationMessage}`
          : `Simulation completed (unverified): ${result.execRecord.verificationMessage}`;
        showToast(msg, result.execRecord.verified ? 'success' : 'warn');
      } else {
        showToast(result.error, 'error');
      }
      renderResponses(container);
    });
  });

  // Rollback
  container.querySelectorAll('[data-pb-rollback]').forEach(btn => {
    btn.addEventListener('click', () => {
      const execId = btn.dataset.pbRollback;
      if (!execId) return;
      const { rollbackExecution: rb } = { rollbackExecution };
      const result = rollbackExecution(execId, 'Demo analyst');
      if (result.ok) {
        showToast(result.verified ? `Rollback simulation verified: ${result.rbRecord.verificationMessage}` : `Rollback completed (unverified)`, result.verified ? 'success' : 'warn');
      } else {
        showToast(result.error, 'error');
      }
      renderResponses(container);
    });
  });
}
