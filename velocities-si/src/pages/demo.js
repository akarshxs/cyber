/**
 * pages/demo.js — Demo control panel with S0-S4 scenarios, speed control,
 * persist/resume, and scenario walkthroughs.
 */
'use strict';

import { getMeta, getPrefs } from '../modules/store.js';
import { getScenarios, getSimState, startScenario, pauseScenario, stopScenario, isRunning } from '../modules/simulator.js';
import { esc, icon, showToast } from '../modules/ui.js';

export function renderDemo(container) {
  const simState = getSimState();
  const scenarios = getScenarios();
  const running = isRunning();

  const selectedKey = simState.scenario || 'S1';
  const scen = scenarios[selectedKey];
  const totalSteps = scen?.steps?.length || 0;
  const cursor = simState.cursor || 0;
  const progress = totalSteps > 0 ? Math.round((cursor / totalSteps) * 100) : 0;

  container.innerHTML = `
    <div class="demo-layout">
      <section class="panel" aria-labelledby="demo-heading">
        <div class="panel-head">
          <h2 id="demo-heading">Demo control</h2>
          <div class="demo-persona">
            <span class="tag">Demo persona</span>
            <span class="muted small">Not a security boundary — role selector illustrates workflow only</span>
          </div>
        </div>

        <div class="sim-indicator">
          <span class="sim-dot ${running ? 'sim-running' : simState.cursor > 0 ? 'sim-paused' : ''}"></span>
          <span class="sim-status">
            ${running ? 'Running' : simState.cursor > 0 ? `Paused (step ${cursor}/${totalSteps})` : 'Ready'}
          </span>
          ${simState.cursor > 0 ? `<span class="muted small">Paused state persisted — click Resume to continue without duplicating events</span>` : ''}
        </div>

        <div class="demo-controls">
          <div class="demo-scenario-select">
            <label for="scenario-select">Scenario</label>
            <select id="scenario-select" class="select-sm" aria-label="Select scenario" ${running ? 'disabled' : ''}>
              ${Object.entries(scenarios).map(([key, s]) => `
                <option value="${esc(key)}" ${selectedKey === key ? 'selected' : ''}>${esc(key)}: ${esc(s.name.replace(/^S\d+ — /, ''))}</option>`).join('')}
            </select>
          </div>

          <div class="sim-controls">
            <button class="btn-primary" id="sim-start" ${running ? 'disabled' : ''} aria-label="${cursor > 0 ? 'Resume scenario' : 'Start scenario'}">
              ${cursor > 0 ? '▶ Resume' : '▶ Start'}
            </button>
            <button class="btn-secondary" id="sim-pause" ${!running ? 'disabled' : ''} aria-label="Pause scenario">
              ⏸ Pause
            </button>
            <button class="btn-secondary" id="sim-stop" aria-label="Stop scenario">
              ⏹ Stop
            </button>
          </div>
        </div>

        <!-- Progress bar -->
        ${totalSteps > 0 ? `
        <div class="sim-progress-wrap">
          <div class="sim-progress-bar" role="progressbar" aria-valuenow="${progress}" aria-valuemin="0" aria-valuemax="100" aria-label="Scenario progress">
            <div class="sim-progress-fill" style="width:${progress}%"></div>
          </div>
          <span class="muted small">${cursor} / ${totalSteps} events generated (${progress}%)</span>
        </div>` : ''}

        <!-- Scenario walkthrough -->
        ${scen ? `
        <div class="scenario-card">
          <h3>${esc(scen.name)}</h3>
          <p>${esc(scen.description)}</p>
          <div class="walkthrough">
            <h4>What to expect</h4>
            ${getWalkthrough(selectedKey)}
          </div>
        </div>` : ''}
      </section>

      <!-- Scenario catalog -->
      <section class="panel" aria-labelledby="scenarios-heading">
        <h2 id="scenarios-heading">Available scenarios</h2>
        <div class="scenario-catalog">
          ${Object.entries(scenarios).map(([key, s]) => `
            <article class="scenario-item ${key === selectedKey ? 'scenario-selected' : ''}" data-select-scenario="${esc(key)}" role="button" tabindex="0" aria-pressed="${key === selectedKey}">
              <div class="scenario-key">${esc(key)}</div>
              <div>
                <h3>${esc(s.name)}</h3>
                <p class="small muted">${esc(s.description)}</p>
                <span class="muted small">${s.steps?.length || 0} events</span>
              </div>
            </article>`).join('')}
        </div>

        <div class="info-box small" style="margin-top:16px">
          <strong>Single-tab enforcement:</strong> Only one browser tab advances the simulation at a time. If another tab is detected running, this tab will pause automatically. Reload restores as paused; click Resume to continue without duplicating events.
        </div>
      </section>
    </div>
  `;

  bindDemoHandlers(container, simState, scenarios);
}

function getWalkthrough(key) {
  const walkthroughs = {
    S0: `<ol><li>Generates 12 normal login events across lab hosts</li><li>No detections or incidents expected</li><li>Useful to establish baseline activity in the Event Explorer</li></ol>`,
    S1: `<ol><li><strong>25 failed logins</strong> for test.alex from 198.51.100.42 → triggers Rule R-001 (failed-login burst)</li><li><strong>Successful login</strong> from same IP → triggers R-002 (success after burst) → incident created</li><li><strong>Privilege change</strong> → triggers R-003 → risk escalates to critical</li><li>Review in Incident Center, view Attack Chain, approve isolation in Response Center</li></ol>`,
    S2: `<ol><li><strong>16 distinct ports scanned</strong> from 198.51.100.43 → triggers R-004 (port scan) and R-005 (firewall deny spike)</li><li><strong>Successful login</strong> from same IP → triggers R-002 → second incident</li><li>Explore Attack Chain graph, check Risk Intelligence</li></ol>`,
    S3: `<ol><li><strong>Failed logins across 5 accounts</strong> (alice, bob, carol, dave, eve) from same IP → triggers R-006 (password spraying)</li><li>Incident created; review spray targets in Incident Center</li><li>Use Response Center to block the spray source IP</li></ol>`,
    S4: `<ol><li><strong>Authorized maintenance events</strong>: backup, patching, service restart, config change, health check</li><li>No detections expected — demonstrates normal admin activity</li><li>Events appear in Event Explorer as "Maintenance" stage</li></ol>`,
  };
  return walkthroughs[key] || '<p class="muted">No walkthrough available.</p>';
}

function bindDemoHandlers(container, simState, scenarios) {
  // Scenario selection
  container.querySelector('#scenario-select')?.addEventListener('change', e => {
    if (isRunning()) { showToast('Stop the current scenario before changing.', 'warn'); renderDemo(container); return; }
    const meta = getMeta();
    meta.simState.scenario = e.target.value;
    meta.simState.step = 0;
    meta.simState.cursor = 0;
    const { saveMeta } = await_import_store();
    // Use dynamic import to get saveMeta
    import('../modules/store.js').then(({ saveMeta }) => { saveMeta(); renderDemo(container); });
  });

  // Scenario catalog clicks
  container.querySelectorAll('[data-select-scenario]').forEach(card => {
    const select = () => {
      if (isRunning()) { showToast('Stop the current scenario before changing.', 'warn'); return; }
      import('../modules/store.js').then(({ getMeta, saveMeta }) => {
        const meta = getMeta();
        meta.simState.scenario = card.dataset.selectScenario;
        meta.simState.step = 0;
        meta.simState.cursor = 0;
        saveMeta();
        renderDemo(container);
      });
    };
    card.addEventListener('click', select);
    card.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); select(); } });
  });

  // Start/Resume
  container.querySelector('#sim-start')?.addEventListener('click', async () => {
    const meta = getMeta();
    const key = meta.simState.scenario || 'S1';
    const started = await startScenario(key);
    if (started) {
      showToast(`Scenario ${key} ${simState.cursor > 0 ? 'resumed' : 'started'}.`, 'success');
      renderDemo(container);
    } else {
      showToast('Could not start scenario.', 'error');
    }
  });

  // Pause
  container.querySelector('#sim-pause')?.addEventListener('click', () => {
    pauseScenario();
    showToast('Scenario paused. Progress saved.', 'info');
    renderDemo(container);
  });

  // Stop
  container.querySelector('#sim-stop')?.addEventListener('click', () => {
    stopScenario();
    showToast('Scenario stopped and reset.', 'info');
    renderDemo(container);
  });
}

// Helper to get saveMeta synchronously (fallback)
function await_import_store() { return {}; }
