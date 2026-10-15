/**
 * pages/risk.js — Risk intelligence with history chart, driver breakdown,
 * affected assets. Shows actual history chart, not just current score.
 */
'use strict';

import { getMeta, getPrefs } from '../modules/store.js';
import { esc, severityBadge, relativeTime, icon } from '../modules/ui.js';
import { scoreToBand, FACTOR_LABELS, calculateRisk } from '../modules/risk.js';

export function renderRisk(container) {
  const meta = getMeta();
  const prefs = getPrefs();

  if (!meta.incidents.length) {
    container.innerHTML = `
      <section class="panel">
        <div class="panel-head"><h2>Risk intelligence</h2></div>
        <div class="empty-state">${icon('risk')}<p>No incidents to assess. Run a scenario to generate risk data.</p></div>
      </section>`;
    return;
  }

  const active = meta.incidents.filter(i => !['Resolved','False positive'].includes(i.status));

  container.innerHTML = `
    <section class="panel" aria-labelledby="risk-heading">
      <div class="panel-head">
        <h2 id="risk-heading">Risk intelligence</h2>
        <span class="muted small">Formula: score = Σ(weight × input) · inputs are 0–100 · weights must sum to 1</span>
      </div>

      <div class="risk-formula-card">
        <h3>Risk formula (v${prefs.riskWeightsVersion})</h3>
        <div class="formula-weights">
          ${Object.entries(prefs.riskWeights).map(([k, w]) => `
            <div class="formula-factor">
              <span class="formula-label">${esc(FACTOR_LABELS[k] || k)}</span>
              <span class="formula-weight">${Math.round(w * 100)}%</span>
            </div>`).join('')}
        </div>
        <p class="small muted">Detection confidence is a heuristic, not a calibrated probability. It is kept separate from potential impact to avoid double-counting.</p>
      </div>

      ${active.map(inc => renderIncidentRisk(inc, prefs)).join('')}

      ${active.length === 0 ? '<div class="empty-state"><p class="muted">All incidents are resolved or classified as false positives.</p></div>' : ''}
    </section>
  `;
}

function renderIncidentRisk(inc, prefs) {
  const { band, label } = scoreToBand(inc.risk);
  const { score, errors } = calculateRisk(inc.inputs, prefs.riskWeights);

  // History chart SVG
  const history = inc.riskHistory;
  const histSvg = buildHistoryChart(history);

  // Driver breakdown bars
  const drivers = Object.entries(inc.inputs).map(([k, v]) => ({
    key: k,
    label: FACTOR_LABELS[k] || k,
    value: v,
    weight: prefs.riskWeights[k] || 0,
    contribution: Math.round((prefs.riskWeights[k] || 0) * v),
  }));

  return `
    <article class="risk-card" aria-labelledby="risk-inc-${esc(inc.id)}">
      <div class="risk-card-head">
        <div>
          <h3 id="risk-inc-${esc(inc.id)}">${esc(inc.id)} — ${esc(inc.title)}</h3>
          <p class="small muted">${esc(inc.host)} · ${esc(inc.user)}</p>
        </div>
        <div class="risk-score-large">
          <span class="risk-number text-${band}">${inc.risk}</span>
          <span class="muted">/100</span>
          ${severityBadge(inc.priority)}
        </div>
      </div>

      ${errors.length ? `<div class="warn-box">${errors.map(e => `<p class="small">${esc(e)}</p>`).join('')}</div>` : ''}

      <div class="risk-layout">
        <div class="risk-drivers">
          <h4>Factor breakdown</h4>
          ${drivers.map(d => `
            <div class="driver-row">
              <span class="driver-label">${esc(d.label)}</span>
              <div class="driver-bar-wrap">
                <div class="driver-bar" style="width:${d.value}%" aria-label="${esc(d.label)}: ${d.value}/100"></div>
              </div>
              <span class="driver-value">${d.value}</span>
              <span class="driver-contrib muted">(${d.contribution} pts)</span>
            </div>`).join('')}
          ${inc.inputs.confidence !== undefined ? `<p class="small muted">Confidence (${inc.inputs.confidence}%) is a heuristic — not a measured false-positive rate or posterior probability.</p>` : ''}
        </div>

        <div class="risk-history">
          <h4>Score history (${history.length} entries)</h4>
          ${histSvg}
          ${history.slice(-3).reverse().map(h => `
            <div class="history-entry">
              <span class="history-time muted">${relativeTime(h.ts)}</span>
              <span class="history-score">${h.before} → <strong>${h.score}</strong></span>
              <span class="history-rationale small muted">${esc(h.rationale?.slice(0,80) || '')}</span>
              <span class="history-formula muted small">Formula v${h.formulaVersion}</span>
            </div>`).join('')}
        </div>
      </div>
    </article>
  `;
}

function buildHistoryChart(history) {
  if (history.length < 2) {
    return `<div class="history-chart-empty muted small">Need 2+ data points for chart.</div>`;
  }

  const W = 280;
  const H = 100;
  const pad = 12;
  const innerW = W - pad * 2;
  const innerH = H - pad * 2;

  const scores = history.map(h => h.score);
  const minS = Math.max(0, Math.min(...scores) - 5);
  const maxS = Math.min(100, Math.max(...scores) + 5);
  const range = maxS - minS || 1;

  const points = history.map((h, i) => {
    const x = pad + (i / (history.length - 1)) * innerW;
    const y = pad + innerH - ((h.score - minS) / range) * innerH;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');

  // Y-axis labels
  const yLabels = [minS, Math.round((minS+maxS)/2), maxS].map((v, i) => {
    const y = pad + innerH - (i / 2) * innerH;
    return `<text x="${pad - 3}" y="${y.toFixed(1)}" text-anchor="end" font-size="8" fill="var(--muted)">${v}</text>`;
  });

  return `
    <svg viewBox="0 0 ${W} ${H}" class="history-chart-svg" aria-label="Risk score history chart">
      <defs>
        <linearGradient id="hist-grad-${history.length}" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="var(--teal)" stop-opacity="0.3"/>
          <stop offset="100%" stop-color="var(--teal)" stop-opacity="0"/>
        </linearGradient>
      </defs>
      <rect x="${pad}" y="${pad}" width="${innerW}" height="${innerH}" fill="var(--surface-1)"/>
      ${yLabels.join('')}
      <polyline points="${points}" fill="none" stroke="var(--teal)" stroke-width="1.5" stroke-linejoin="round"/>
      ${history.map((h, i) => {
        const x = pad + (i / (history.length - 1)) * innerW;
        const y = pad + innerH - ((h.score - minS) / range) * innerH;
        return `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="3" fill="var(--teal)"><title>Score: ${h.score} — ${h.rationale?.slice(0,60)}</title></circle>`;
      }).join('')}
    </svg>`;
}
