/**
 * simulator.js — deterministic seeded scenario engine.
 * Scenarios: S0 normal, S1 credential compromise, S2 reconnaissance,
 * S3 password spraying, S4 benign maintenance.
 * All generated events go through the shared ingest pipeline.
 * Persists schedule, seed, cursor, run status. Single-tab enforcement via BroadcastChannel.
 */
'use strict';

import { getMeta, saveMeta, appendAudit } from './store.js';
import { ingestSimulatorEvent } from './ingest.js';

const SCENARIOS = {
  S0: {
    name: 'S0 — Normal baseline',
    description: 'Normal day-to-day authentication and system operations. No incidents expected.',
    steps: buildS0Steps(),
  },
  S1: {
    name: 'S1 — Credential compromise',
    description: '25 failed logins → successful login → privilege change. Triggers R-001, R-002, R-003.',
    steps: buildS1Steps(),
  },
  S2: {
    name: 'S2 — Reconnaissance',
    description: 'Port scan (16 ports) + firewall deny spike → successful login. Triggers R-004, R-005, R-002.',
    steps: buildS2Steps(),
  },
  S3: {
    name: 'S3 — Password spraying',
    description: 'Failed logins against multiple accounts from single IP. Triggers R-006.',
    steps: buildS3Steps(),
  },
  S4: {
    name: 'S4 — Benign maintenance',
    description: 'Authorized maintenance window. Legitimate admin activities. No detections expected.',
    steps: buildS4Steps(),
  },
};

/* ── Scenario definitions ──────────────────────────────────────────── */
function buildS0Steps() {
  const steps = [];
  for (let i = 0; i < 12; i++) {
    steps.push({
      type: 'Successful login',
      host: `lab-web-0${(i % 3) + 1}`,
      user: `test.user${(i % 4) + 1}`,
      ip: '192.0.2.10',
      outcome: 'success',
      stage: 'Baseline',
      severity: 'low',
    });
  }
  return steps;
}

function buildS1Steps() {
  const steps = [];
  // 25 failed logins
  for (let i = 0; i < 25; i++) {
    steps.push({
      type: 'Failed login',
      host: 'lab-web-01',
      user: 'test.alex',
      ip: '198.51.100.42',
      outcome: 'failure',
      stage: 'Credential Access',
      severity: 'medium',
    });
  }
  // 1 success
  steps.push({
    type: 'Successful login',
    host: 'lab-web-01',
    user: 'test.alex',
    ip: '198.51.100.42',
    outcome: 'success',
    stage: 'Initial Access',
    severity: 'high',
  });
  // privilege change
  steps.push({
    type: 'Privilege change',
    host: 'lab-web-01',
    user: 'test.alex',
    ip: '198.51.100.42',
    outcome: 'success',
    stage: 'Privilege Escalation',
    severity: 'critical',
  });
  return steps;
}

function buildS2Steps() {
  const steps = [];
  // 16 distinct port scan events
  for (let i = 0; i < 16; i++) {
    steps.push({
      type: 'Firewall deny',
      host: 'lab-web-02',
      user: 'unknown',
      ip: '198.51.100.43',
      outcome: 'denied',
      stage: 'Discovery',
      severity: 'medium',
      destinationPort: 20 + i,
    });
  }
  // Successful login after scan
  steps.push({
    type: 'Successful login',
    host: 'lab-web-02',
    user: 'test.morgan',
    ip: '198.51.100.43',
    outcome: 'success',
    stage: 'Initial Access',
    severity: 'high',
  });
  return steps;
}

function buildS3Steps() {
  const accounts = ['test.alice', 'test.bob', 'test.carol', 'test.dave', 'test.eve'];
  const steps = [];
  for (const user of accounts) {
    for (let i = 0; i < 3; i++) {
      steps.push({
        type: 'Failed login',
        host: 'lab-dc-01',
        user,
        ip: '198.51.100.42',
        outcome: 'failure',
        stage: 'Credential Access',
        severity: 'high',
      });
    }
  }
  return steps;
}

function buildS4Steps() {
  const steps = [];
  const actions = [
    { type: 'Scheduled backup', host: 'lab-db-01', user: 'svc.backup', outcome: 'success', stage: 'Maintenance' },
    { type: 'Patch applied', host: 'lab-web-01', user: 'svc.patching', outcome: 'success', stage: 'Maintenance' },
    { type: 'Service restart', host: 'lab-web-02', user: 'svc.ops', outcome: 'success', stage: 'Maintenance' },
    { type: 'Config change', host: 'lab-dc-01', user: 'svc.admin', outcome: 'success', stage: 'Maintenance' },
    { type: 'Health check', host: 'lab-db-01', user: 'svc.monitor', outcome: 'success', stage: 'Maintenance' },
    { type: 'Log rotation', host: 'lab-web-03', user: 'svc.ops', outcome: 'success', stage: 'Maintenance' },
  ];
  for (const a of actions) {
    steps.push({ ...a, ip: '192.0.2.10', severity: 'low' });
  }
  return steps;
}

/* ── Public API ──────────────────────────────────────────────────────── */
let _timer = null;
let _channel = null;
const TICK_MS = 1200;

export function getScenarios() { return SCENARIOS; }

export function getSimState() {
  return getMeta().simState;
}

export async function startScenario(scenarioKey) {
  const meta = getMeta();
  if (_timer) return false;

  // Single-tab coordination
  if (_channel) _channel.close();
  _channel = new BroadcastChannel('vsi-sim');
  _channel.onmessage = (e) => {
    if (e.data === 'running') {
      stopScenario();
    }
  };

  if (!SCENARIOS[scenarioKey]) return false;

  if (meta.simState.scenario !== scenarioKey) {
    meta.simState.scenario = scenarioKey;
    meta.simState.step = 0;
    meta.simState.cursor = 0;
    meta.simState.seed = Date.now();
  }

  meta.simState.running = true;
  saveMeta();
  appendAudit('Scenario started', scenarioKey, 'simulation');

  _timer = setInterval(async () => {
    _channel.postMessage('running');
    await tick();
  }, TICK_MS);

  return true;
}

export function pauseScenario() {
  if (_timer) { clearInterval(_timer); _timer = null; }
  const meta = getMeta();
  meta.simState.running = false;
  saveMeta();
  appendAudit('Scenario paused', meta.simState.scenario || '', 'simulation');
}

export function stopScenario() {
  if (_timer) { clearInterval(_timer); _timer = null; }
  if (_channel) { _channel.close(); _channel = null; }
  const meta = getMeta();
  meta.simState.running = false;
  meta.simState.step = 0;
  meta.simState.cursor = 0;
  saveMeta();
  appendAudit('Scenario stopped', meta.simState.scenario || '', 'simulation');
}

export function resetSimulator() {
  stopScenario();
  const meta = getMeta();
  meta.simState = { scenario: null, step: 0, running: false, seed: 0, cursor: 0 };
  saveMeta();
}

export function isRunning() { return _timer !== null; }

async function tick() {
  const meta = getMeta();
  const { scenario, cursor } = meta.simState;
  if (!scenario) { pauseScenario(); return; }

  const scen = SCENARIOS[scenario];
  if (!scen) { pauseScenario(); return; }

  const steps = scen.steps;
  if (cursor >= steps.length) {
    // Scenario complete
    appendAudit('Scenario completed', scenario, 'simulation');
    stopScenario();
    // Notify UI
    window.dispatchEvent(new CustomEvent('vsi:sim-complete', { detail: { scenario } }));
    return;
  }

  const step = steps[cursor];
  const event = await ingestSimulatorEvent(step);

  meta.simState.cursor = cursor + 1;
  meta.simState.step = cursor + 1;
  saveMeta();

  // Notify UI
  window.dispatchEvent(new CustomEvent('vsi:tick', { detail: { event, cursor: cursor + 1, total: steps.length } }));
}

/* ── Restore paused state on load ─────────────────────────────────── */
export function restoreSimState() {
  const meta = getMeta();
  // Always restore as paused per spec
  meta.simState.running = false;
  saveMeta();
  return meta.simState;
}
