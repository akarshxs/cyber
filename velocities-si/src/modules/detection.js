/**
 * detection.js — versioned rule engine operating on normalized event windows.
 * Rules: failed-login burst, success-after-burst, privilege-change-after-suspicious,
 * distinct-port scan, firewall-deny spike, cross-account password spraying.
 * All rules are data-driven and reusable across simulator and import paths.
 */
'use strict';

import { getMeta, getPrefs, nextId, saveMeta, appendAudit } from './store.js';
import { idbFilter } from './store.js';

export const RULE_CATALOG = [
  {
    id: 'R-001', version: 'v1', name: 'Failed-login burst',
    description: 'Multiple failed login attempts from the same source IP within the window, targeting the same account.',
    mitreTechnique: 'T1110', mitreName: 'Brute Force',
    severity: 'high',
    thresholdKey: 'failedLoginBurst',
    defaultThreshold: 5,
    windowMinutes: 10,
  },
  {
    id: 'R-002', version: 'v1', name: 'Success after burst',
    description: 'Successful login from the same source IP that previously triggered a failed-login burst.',
    mitreTechnique: 'T1078', mitreName: 'Valid Accounts',
    severity: 'critical',
    thresholdKey: null,
    defaultThreshold: 1,
    windowMinutes: 30,
  },
  {
    id: 'R-003', version: 'v1', name: 'Privilege change after suspicious login',
    description: 'Privilege escalation operation detected after a suspicious successful login for the same user/host.',
    mitreTechnique: 'T1548', mitreName: 'Abuse Elevation Control Mechanism',
    severity: 'critical',
    thresholdKey: null,
    defaultThreshold: 1,
    windowMinutes: 60,
  },
  {
    id: 'R-004', version: 'v1', name: 'Distinct-port scan',
    description: 'Connection attempts to many distinct destination ports from the same source IP within the window.',
    mitreTechnique: 'T1046', mitreName: 'Network Service Discovery',
    severity: 'medium',
    thresholdKey: 'portScanDistinct',
    defaultThreshold: 10,
    windowMinutes: 5,
  },
  {
    id: 'R-005', version: 'v1', name: 'Firewall deny spike',
    description: 'High volume of firewall deny events from the same source IP within the window.',
    mitreTechnique: 'T1046', mitreName: 'Network Service Discovery',
    severity: 'medium',
    thresholdKey: 'firewallDenySpike',
    defaultThreshold: 8,
    windowMinutes: 5,
  },
  {
    id: 'R-006', version: 'v1', name: 'Cross-account password spraying',
    description: 'Failed login attempts from the same source IP targeting multiple distinct accounts within the window.',
    mitreTechnique: 'T1110.003', mitreName: 'Password Spraying',
    severity: 'high',
    thresholdKey: 'sprayAccounts',
    defaultThreshold: 3,
    windowMinutes: 5,
  },
];

/* ── Run all rules against a batch of new events ────────────────────── */
export async function runDetectionRules(newEvents) {
  const prefs = getPrefs();
  const meta = getMeta();
  const detections = [];

  // Collect recent events from IDB for window-based rules
  // We'll work with the batch plus a window of recent stored events
  const windowMs = 60 * 60 * 1000; // 1 hour context window max
  const cutoff = new Date(Date.now() - windowMs).toISOString();

  // Group new events with context
  const allContext = [...newEvents]; // For simulator, context is provided inline

  // Run each rule
  for (const rule of RULE_CATALOG) {
    const threshold = prefs.ruleThresholds[rule.thresholdKey] ?? rule.defaultThreshold;
    const windowMs2 = rule.windowMinutes * 60 * 1000;

    try {
      const found = await applyRule(rule, newEvents, allContext, threshold, windowMs2, meta);
      for (const det of found) {
        // Suppress duplicates: same rule, same user+host+ip within 5 minutes
        const dupKey = `${det.ruleId}|${det.user}|${det.host}|${det.ip}`;
        const recentDup = meta.detections.find(d =>
          `${d.ruleId}|${d.user}|${d.host}|${d.ip}` === dupKey &&
          Math.abs(new Date(d.ts) - new Date(det.ts)) < 5 * 60 * 1000 &&
          !d.suppressed
        );
        if (!recentDup) {
          det.id = nextId('DET');
          detections.push(det);
        }
      }
    } catch (e) {
      console.error(`Rule ${rule.id} error:`, e);
    }
  }

  if (detections.length) {
    appendAudit(`Detection engine: ${detections.length} new detections`, detections.map(d=>d.ruleId).join(', '), 'detection');
  }

  return detections;
}

async function applyRule(rule, newEvents, context, threshold, windowMs, meta) {
  const detections = [];
  const now = Date.now();

  if (rule.id === 'R-001') {
    // Failed-login burst: group by user+ip, count failures in window
    const groups = {};
    for (const e of newEvents) {
      if (!isFailedLogin(e)) continue;
      const key = `${e.user}|${e.ip}`;
      if (!groups[key]) groups[key] = { events: [], host: e.host };
      groups[key].events.push(e);
    }
    for (const [key, g] of Object.entries(groups)) {
      const windowEvents = g.events.filter(e => now - new Date(e.ts) <= windowMs);
      if (windowEvents.length >= threshold) {
        const [user, ip] = key.split('|');
        detections.push(makeDetection(rule, {
          user, ip, host: g.host,
          triggeringEventIds: windowEvents.map(e=>e.id),
          matched: windowEvents.length,
          threshold,
          explanation: `${windowEvents.length} failed login attempts for "${user}" from ${ip} within ${rule.windowMinutes} minutes (threshold: ${threshold}).`,
        }));
      }
    }
  }

  else if (rule.id === 'R-002') {
    // Success after burst: look for a success event where prior R-001 detection exists for same user+ip
    const successEvents = newEvents.filter(e => isSuccessLogin(e));
    for (const e of successEvents) {
      const priorBurst = meta.detections.find(d =>
        d.ruleId === 'R-001' && d.user === e.user && d.ip === e.ip &&
        new Date(e.ts) - new Date(d.ts) <= windowMs && !d.suppressed
      );
      if (priorBurst) {
        detections.push(makeDetection(rule, {
          user: e.user, ip: e.ip, host: e.host,
          triggeringEventIds: [e.id, ...priorBurst.triggeringEventIds.slice(0,5)],
          matched: 1, threshold: 1,
          explanation: `Successful login for "${e.user}" from ${e.ip} after ${priorBurst.matched} failed attempts (rule ${priorBurst.id}).`,
        }));
      }
    }
  }

  else if (rule.id === 'R-003') {
    // Privilege change after suspicious login
    const privEvents = newEvents.filter(e => isPrivilegeChange(e));
    for (const e of privEvents) {
      const priorLogin = meta.detections.find(d =>
        d.ruleId === 'R-002' && d.user === e.user && d.host === e.host &&
        new Date(e.ts) - new Date(d.ts) <= windowMs && !d.suppressed
      );
      if (priorLogin) {
        detections.push(makeDetection(rule, {
          user: e.user, ip: e.ip, host: e.host,
          triggeringEventIds: [e.id, ...priorLogin.triggeringEventIds.slice(0,5)],
          matched: 1, threshold: 1,
          explanation: `Privilege change for "${e.user}" on ${e.host} after suspicious login from ${e.ip} (rule ${priorLogin.id}).`,
        }));
      }
    }
  }

  else if (rule.id === 'R-004') {
    // Distinct port scan
    const groups = {};
    for (const e of newEvents) {
      if (!isFirewallEvent(e) && !isPortScanEvent(e)) continue;
      if (!e.destinationPort) continue;
      const key = `${e.ip}|${e.host}`;
      if (!groups[key]) groups[key] = { ports: new Set(), events: [], user: e.user };
      groups[key].ports.add(e.destinationPort);
      groups[key].events.push(e);
    }
    for (const [key, g] of Object.entries(groups)) {
      if (g.ports.size >= threshold) {
        const [ip, host] = key.split('|');
        detections.push(makeDetection(rule, {
          user: g.user, ip, host,
          triggeringEventIds: g.events.map(e=>e.id),
          matched: g.ports.size, threshold,
          explanation: `${g.ports.size} distinct destination ports scanned from ${ip} targeting ${host} (threshold: ${threshold}).`,
        }));
      }
    }
  }

  else if (rule.id === 'R-005') {
    // Firewall deny spike
    const groups = {};
    for (const e of newEvents) {
      if (!isFirewallDeny(e)) continue;
      const key = `${e.ip}|${e.host}`;
      if (!groups[key]) groups[key] = { events: [], user: e.user };
      groups[key].events.push(e);
    }
    for (const [key, g] of Object.entries(groups)) {
      const windowEvents = g.events.filter(e => now - new Date(e.ts) <= windowMs);
      if (windowEvents.length >= threshold) {
        const [ip, host] = key.split('|');
        detections.push(makeDetection(rule, {
          user: g.user, ip, host,
          triggeringEventIds: windowEvents.map(e=>e.id),
          matched: windowEvents.length, threshold,
          explanation: `${windowEvents.length} firewall deny events from ${ip} within ${rule.windowMinutes} minutes (threshold: ${threshold}).`,
        }));
      }
    }
  }

  else if (rule.id === 'R-006') {
    // Cross-account password spraying
    const byIp = {};
    for (const e of newEvents) {
      if (!isFailedLogin(e)) continue;
      if (!byIp[e.ip]) byIp[e.ip] = { accounts: new Set(), events: [], host: e.host };
      byIp[e.ip].accounts.add(e.user);
      byIp[e.ip].events.push(e);
    }
    for (const [ip, g] of Object.entries(byIp)) {
      if (g.accounts.size >= threshold) {
        detections.push(makeDetection(rule, {
          user: [...g.accounts].join(', ').slice(0,128), ip, host: g.host,
          triggeringEventIds: g.events.map(e=>e.id),
          matched: g.accounts.size, threshold,
          explanation: `${g.accounts.size} distinct accounts targeted from ${ip} (password spraying, threshold: ${threshold}).`,
        }));
      }
    }
  }

  return detections;
}

function makeDetection(rule, { user, ip, host, triggeringEventIds, matched, threshold, explanation }) {
  return {
    id: null, // will be assigned
    ruleId: rule.id,
    ruleVersion: rule.version,
    ruleName: rule.name,
    severity: rule.severity,
    ts: new Date().toISOString(),
    host: host || 'unknown',
    user: user || 'unknown',
    ip: ip || '',
    triggeringEventIds: triggeringEventIds || [],
    windowMinutes: Math.round((rule.windowMinutes || 5)),
    threshold,
    matched,
    explanation: explanation || '',
    mitreTechnique: rule.mitreTechnique,
    mitreName: rule.mitreName,
    incidentId: null,
    suppressed: false,
  };
}

/* ── Event classification helpers ──────────────────────────────────── */
function isFailedLogin(e) {
  return /fail|denied|denied|reject|error/i.test(e.outcome) &&
    /login|logon|auth|sign.?in|password|credential/i.test(e.type);
}

function isSuccessLogin(e) {
  return /success|ok|allow/i.test(e.outcome) &&
    /login|logon|auth|sign.?in/i.test(e.type);
}

function isPrivilegeChange(e) {
  return /privilege|escalat|sudo|admin|elevation|role/i.test(e.type) ||
    /Privilege/i.test(e.stage);
}

function isFirewallEvent(e) {
  return /firewall|fw|acl|deny|block|drop/i.test(e.type) || /firewall/i.test(e.source);
}

function isFirewallDeny(e) {
  return isFirewallEvent(e) && /deny|block|drop|reject/i.test(e.outcome);
}

function isPortScanEvent(e) {
  return e.destinationPort !== undefined;
}
