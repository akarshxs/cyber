/**
 * pages/settings.js — Fully functional settings: theme, density, timezone,
 * rule thresholds, correlation window, risk weights, asset importance, allowlist.
 */
'use strict';

import { getPrefs, savePrefs, loadPrefs, defaultPrefs, appendAudit } from '../modules/store.js';
import { recomputeAllRisks } from '../modules/risk.js';
import { esc, showToast, icon } from '../modules/ui.js';

export function renderSettings(container, onThemeChange) {
  const prefs = getPrefs();

  container.innerHTML = `
    <div class="settings-layout">

      <!-- Appearance -->
      <section class="panel settings-section" aria-labelledby="s-appearance">
        <h2 id="s-appearance">Appearance</h2>
        <div class="settings-grid">
          <label for="s-theme">Theme</label>
          <select id="s-theme" class="select-sm" aria-label="Color theme">
            <option value="dark" ${prefs.theme === 'dark' ? 'selected' : ''}>Dark</option>
            <option value="light" ${prefs.theme === 'light' ? 'selected' : ''}>Light</option>
          </select>

          <label for="s-density">Density</label>
          <select id="s-density" class="select-sm" aria-label="UI density">
            <option value="comfortable" ${prefs.density === 'comfortable' ? 'selected' : ''}>Comfortable</option>
            <option value="compact" ${prefs.density === 'compact' ? 'selected' : ''}>Compact</option>
            <option value="spacious" ${prefs.density === 'spacious' ? 'selected' : ''}>Spacious</option>
          </select>

          <label for="s-timezone">Timestamp display</label>
          <select id="s-timezone" class="select-sm" aria-label="Timezone display">
            <option value="local" ${prefs.timezone === 'local' ? 'selected' : ''}>Local time</option>
            <option value="utc" ${prefs.timezone === 'utc' ? 'selected' : ''}>UTC</option>
          </select>
        </div>
        <div class="settings-actions">
          <button class="btn-primary btn-sm" id="save-appearance">Save appearance</button>
        </div>
      </section>

      <!-- Detection thresholds -->
      <section class="panel settings-section" aria-labelledby="s-thresholds">
        <h2 id="s-thresholds">Detection thresholds</h2>
        <p class="small muted">Changes affect new detections only. Existing detections are not retroactively suppressed.</p>
        <div class="settings-grid">
          <label for="s-th-login">Failed-login burst</label>
          <input type="number" id="s-th-login" class="input-sm" value="${prefs.ruleThresholds.failedLoginBurst}" min="2" max="1000" aria-label="Failed login burst threshold">

          <label for="s-th-port">Port scan (distinct ports)</label>
          <input type="number" id="s-th-port" class="input-sm" value="${prefs.ruleThresholds.portScanDistinct}" min="2" max="65535" aria-label="Port scan distinct threshold">

          <label for="s-th-fw">Firewall deny spike</label>
          <input type="number" id="s-th-fw" class="input-sm" value="${prefs.ruleThresholds.firewallDenySpike}" min="2" max="1000" aria-label="Firewall deny spike threshold">

          <label for="s-th-spray">Password spray (accounts)</label>
          <input type="number" id="s-th-spray" class="input-sm" value="${prefs.ruleThresholds.sprayAccounts}" min="2" max="100" aria-label="Password spray accounts threshold">

          <label for="s-corr-win">Correlation window (minutes)</label>
          <input type="number" id="s-corr-win" class="input-sm" value="${prefs.correlationWindowMinutes}" min="1" max="1440" aria-label="Correlation window in minutes">
        </div>
        <div class="settings-actions">
          <button class="btn-primary btn-sm" id="save-thresholds">Save thresholds</button>
        </div>
      </section>

      <!-- Risk weights -->
      <section class="panel settings-section" aria-labelledby="s-weights">
        <h2 id="s-weights">Risk weights</h2>
        <p class="small muted">Weights must sum to exactly 1.0 (100%). Changing weights creates a new formula version and triggers recomputation of all incident scores.</p>
        <div id="weight-sum-display" class="weight-sum-display">
          Sum: <strong id="weight-sum-val">1.00</strong>
          <span id="weight-sum-status" class="muted small"></span>
        </div>
        <div class="settings-grid">
          <label for="s-w-severity">Severity weight</label>
          <input type="number" id="s-w-severity" class="input-sm" value="${prefs.riskWeights.severity}" min="0" max="1" step="0.01" aria-label="Severity weight">

          <label for="s-w-confidence">Confidence weight</label>
          <input type="number" id="s-w-confidence" class="input-sm" value="${prefs.riskWeights.confidence}" min="0" max="1" step="0.01" aria-label="Confidence weight">

          <label for="s-w-asset">Asset importance weight</label>
          <input type="number" id="s-w-asset" class="input-sm" value="${prefs.riskWeights.assetImportance}" min="0" max="1" step="0.01" aria-label="Asset importance weight">

          <label for="s-w-impact">Impact weight</label>
          <input type="number" id="s-w-impact" class="input-sm" value="${prefs.riskWeights.impact}" min="0" max="1" step="0.01" aria-label="Impact weight">

          <label for="s-w-evidence">Evidence support weight</label>
          <input type="number" id="s-w-evidence" class="input-sm" value="${prefs.riskWeights.evidenceSupport}" min="0" max="1" step="0.01" aria-label="Evidence support weight">
        </div>
        <div class="settings-actions">
          <button class="btn-primary btn-sm" id="save-weights">Save weights &amp; recompute</button>
        </div>
        <p class="small muted">Current formula version: <strong>${prefs.riskWeightsVersion}</strong></p>
      </section>

      <!-- Asset importance -->
      <section class="panel settings-section" aria-labelledby="s-assets">
        <h2 id="s-assets">Asset importance (0–100)</h2>
        <p class="small muted">Higher values increase risk score for incidents targeting that host.</p>
        <div class="settings-grid">
          ${Object.entries(prefs.assetImportance).map(([host, val]) => `
            <label for="s-asset-${esc(host)}">${esc(host)}</label>
            <input type="number" id="s-asset-${esc(host)}" class="input-sm asset-input" data-asset-host="${esc(host)}" value="${val}" min="0" max="100" aria-label="Asset importance for ${esc(host)}">`).join('')}
        </div>
        <div class="settings-actions">
          <button class="btn-primary btn-sm" id="save-assets">Save asset importance</button>
        </div>
      </section>

      <!-- Lab allowlist -->
      <section class="panel settings-section" aria-labelledby="s-allowlist">
        <h2 id="s-allowlist">Lab allowlist</h2>
        <p class="small muted">Only allowlisted IPs may be blocked in simulation. One IP per line.</p>
        <textarea id="s-allowlist-ta" class="textarea-sm" rows="5" aria-label="Lab IP allowlist, one per line">${prefs.labAllowlist.map(esc).join('\n')}</textarea>
        <div class="settings-actions">
          <button class="btn-primary btn-sm" id="save-allowlist">Save allowlist</button>
        </div>
      </section>

      <!-- Workspace -->
      <section class="panel settings-section" aria-labelledby="s-workspace">
        <h2 id="s-workspace">Workspace</h2>
        <div class="settings-actions-col">
          <button class="btn-secondary btn-sm" id="export-workspace">${icon('export')} Export workspace JSON</button>
          <button class="btn-secondary btn-sm" id="restore-defaults">Restore default settings</button>
          <button class="btn-danger btn-sm" id="reset-all">Reset all demo data</button>
        </div>
        <div class="settings-info">
          <p class="small">Storage: <strong>localStorage</strong> for preferences and metadata · <strong>IndexedDB</strong> for events. Capacity limits depend on browser. Private browsing may prevent persistence.</p>
          <div id="storage-status" class="storage-status"></div>
        </div>
      </section>

    </div>
  `;

  checkStorageAvailability(container);
  bindSettingsHandlers(container, prefs, onThemeChange);
  bindWeightSumUpdater(container);
}

function bindSettingsHandlers(container, prefs, onThemeChange) {
  // Appearance
  container.querySelector('#save-appearance')?.addEventListener('click', () => {
    const p = getPrefs();
    p.theme = container.querySelector('#s-theme').value;
    p.density = container.querySelector('#s-density').value;
    p.timezone = container.querySelector('#s-timezone').value;
    if (savePrefs()) {
      showToast('Appearance saved.', 'success');
      appendAudit('Appearance settings saved', p.theme, 'settings');
      onThemeChange(p.theme, p.density);
    } else {
      showToast('Storage unavailable. Settings not saved.', 'error');
    }
  });

  // Thresholds
  container.querySelector('#save-thresholds')?.addEventListener('click', () => {
    const p = getPrefs();
    const login = parseInt(container.querySelector('#s-th-login').value);
    const port = parseInt(container.querySelector('#s-th-port').value);
    const fw = parseInt(container.querySelector('#s-th-fw').value);
    const spray = parseInt(container.querySelector('#s-th-spray').value);
    const corrWin = parseInt(container.querySelector('#s-corr-win').value);

    const errors = [];
    if (isNaN(login) || login < 2) errors.push('Failed-login burst must be ≥ 2');
    if (isNaN(port) || port < 2) errors.push('Port scan threshold must be ≥ 2');
    if (isNaN(fw) || fw < 2) errors.push('Firewall deny threshold must be ≥ 2');
    if (isNaN(spray) || spray < 2) errors.push('Spray accounts must be ≥ 2');
    if (isNaN(corrWin) || corrWin < 1) errors.push('Correlation window must be ≥ 1 minute');

    if (errors.length) { showToast(errors.join('; '), 'error'); return; }

    p.ruleThresholds.failedLoginBurst = login;
    p.ruleThresholds.portScanDistinct = port;
    p.ruleThresholds.firewallDenySpike = fw;
    p.ruleThresholds.sprayAccounts = spray;
    p.correlationWindowMinutes = corrWin;
    if (savePrefs()) { showToast('Detection thresholds saved.', 'success'); appendAudit('Thresholds updated', '', 'settings'); }
    else showToast('Storage unavailable.', 'error');
  });

  // Weights
  container.querySelector('#save-weights')?.addEventListener('click', () => {
    const p = getPrefs();
    const wSev = parseFloat(container.querySelector('#s-w-severity').value);
    const wConf = parseFloat(container.querySelector('#s-w-confidence').value);
    const wAsset = parseFloat(container.querySelector('#s-w-asset').value);
    const wImpact = parseFloat(container.querySelector('#s-w-impact').value);
    const wEvid = parseFloat(container.querySelector('#s-w-evidence').value);

    const vals = [wSev, wConf, wAsset, wImpact, wEvid];
    if (vals.some(v => isNaN(v) || v < 0 || v > 1)) { showToast('All weights must be between 0 and 1.', 'error'); return; }
    const sum = vals.reduce((a, b) => a + b, 0);
    if (Math.abs(sum - 1.0) > 0.001) { showToast(`Weights sum to ${sum.toFixed(3)}, not 1.0. Adjust values.`, 'error'); return; }

    p.riskWeights = { severity: wSev, confidence: wConf, assetImportance: wAsset, impact: wImpact, evidenceSupport: wEvid };
    p.riskWeightsVersion++;
    if (savePrefs()) {
      const count = recomputeAllRisks(`Weights updated to v${p.riskWeightsVersion}`);
      showToast(`Weights saved (v${p.riskWeightsVersion}). ${count} incidents recomputed.`, 'success');
    } else {
      showToast('Storage unavailable.', 'error');
    }
  });

  // Asset importance
  container.querySelector('#save-assets')?.addEventListener('click', () => {
    const p = getPrefs();
    const errors = [];
    container.querySelectorAll('.asset-input').forEach(inp => {
      const host = inp.dataset.assetHost;
      const v = parseInt(inp.value);
      if (isNaN(v) || v < 0 || v > 100) { errors.push(`${host}: must be 0–100`); return; }
      p.assetImportance[host] = v;
    });
    if (errors.length) { showToast(errors.join('; '), 'error'); return; }
    if (savePrefs()) { showToast('Asset importance saved.', 'success'); appendAudit('Asset importance updated', '', 'settings'); }
    else showToast('Storage unavailable.', 'error');
  });

  // Allowlist
  container.querySelector('#save-allowlist')?.addEventListener('click', () => {
    const p = getPrefs();
    const raw = container.querySelector('#s-allowlist-ta').value;
    const ips = raw.split('\n').map(s => s.trim()).filter(Boolean);
    // Basic IP format check
    const valid = ips.filter(ip => /^[\d.:/a-fA-F]+$/.test(ip));
    const invalid = ips.filter(ip => !/^[\d.:/a-fA-F]+$/.test(ip));
    if (invalid.length) { showToast(`Invalid entries: ${invalid.join(', ')}`, 'error'); return; }
    p.labAllowlist = valid;
    if (savePrefs()) { showToast('Lab allowlist saved.', 'success'); appendAudit('Lab allowlist updated', '', 'settings'); }
    else showToast('Storage unavailable.', 'error');
  });

  // Workspace
  container.querySelector('#export-workspace')?.addEventListener('click', () => {
    const { getMeta: gm } = require('../modules/store.js');
    // Dynamic import
    import('../modules/store.js').then(({ getMeta, getPrefs }) => {
      const data = { notice: 'Browser-local synthetic demonstration workspace export', meta: getMeta(), prefs: getPrefs(), exportedAt: new Date().toISOString() };
      const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
      const a = document.createElement('a'); a.href = url; a.download = 'vsi-workspace.json'; a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      showToast('Workspace exported.', 'success');
    });
  });

  container.querySelector('#restore-defaults')?.addEventListener('click', () => {
    if (!confirm('Restore all settings to defaults? This will not delete incidents or events.')) return;
    const def = defaultPrefs();
    Object.assign(getPrefs(), def);
    if (savePrefs()) {
      showToast('Settings restored to defaults.', 'success');
      renderSettings(container, onThemeChange);
    }
  });

  container.querySelector('#reset-all')?.addEventListener('click', async () => {
    if (!confirm('Delete ALL demo data including events, incidents, detections, approvals, and audit history? This cannot be undone.')) return;
    if (!confirm('Are you sure? This will delete everything in this browser workspace.')) return;
    const { fullReset } = await import('../modules/store.js');
    await fullReset();
    showToast('All demo data deleted. Fresh workspace ready.', 'info');
    // Reload to re-seed
    window.location.reload();
  });
}

function bindWeightSumUpdater(container) {
  const weightInputs = ['#s-w-severity','#s-w-confidence','#s-w-asset','#s-w-impact','#s-w-evidence'];
  const updateSum = () => {
    const vals = weightInputs.map(id => parseFloat(container.querySelector(id)?.value || 0));
    const sum = vals.reduce((a, b) => a + b, 0);
    const sumEl = container.querySelector('#weight-sum-val');
    const statusEl = container.querySelector('#weight-sum-status');
    if (sumEl) sumEl.textContent = sum.toFixed(3);
    if (statusEl) {
      const ok = Math.abs(sum - 1.0) < 0.001;
      statusEl.textContent = ok ? '✓ Valid' : `⚠ Off by ${(sum - 1.0).toFixed(3)}`;
      statusEl.className = ok ? 'text-teal small' : 'text-red small';
    }
  };
  weightInputs.forEach(id => container.querySelector(id)?.addEventListener('input', updateSum));
  updateSum();
}

function checkStorageAvailability(container) {
  const statusEl = container.querySelector('#storage-status');
  if (!statusEl) return;
  try {
    localStorage.setItem('_vsi_test', '1');
    localStorage.removeItem('_vsi_test');
    statusEl.innerHTML = `<span class="text-teal small">✓ localStorage available</span>`;
  } catch {
    statusEl.innerHTML = `<span class="text-red">⚠ localStorage unavailable. Settings and state will not persist across page loads. Try disabling private browsing or checking storage permissions.</span>`;
  }
}
