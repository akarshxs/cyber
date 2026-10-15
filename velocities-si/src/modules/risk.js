/**
 * risk.js — risk calculation with validated weights and immutable-by-application history.
 * Formula: score = sum(weight_i * input_i) for all factors.
 * Formula version is stored with every history entry.
 */
'use strict';

import { getMeta, getPrefs, saveMeta, appendAudit } from './store.js';

export const FORMULA_VERSION = 1;

export const FACTOR_LABELS = {
  severity: 'Severity',
  confidence: 'Detection confidence (uncalibrated heuristic)',
  assetImportance: 'Asset importance',
  impact: 'Potential impact',
  evidenceSupport: 'Evidence support',
};

/* ── Calculate risk score ────────────────────────────────────────────── */
export function calculateRisk(inputs, weights) {
  // Validate all inputs 0-100
  const validated = {};
  const errors = [];
  for (const [k, v] of Object.entries(inputs)) {
    const n = Number(v);
    if (isNaN(n) || n < 0 || n > 100) {
      errors.push(`${k}: must be 0–100 (got ${v})`);
      validated[k] = Math.max(0, Math.min(100, isNaN(n) ? 0 : n));
    } else {
      validated[k] = n;
    }
  }

  // Validate weights sum to 1
  const wSum = Object.values(weights).reduce((a, b) => a + (Number(b) || 0), 0);
  if (Math.abs(wSum - 1.0) > 0.01) {
    errors.push(`Weights sum to ${wSum.toFixed(3)}, not 1.0`);
  }

  const score = Math.round(
    (weights.severity || 0.25) * (validated.severity || 0) +
    (weights.confidence || 0.20) * (validated.confidence || 0) +
    (weights.assetImportance || 0.20) * (validated.assetImportance || 0) +
    (weights.impact || 0.20) * (validated.impact || 0) +
    (weights.evidenceSupport || 0.15) * (validated.evidenceSupport || 0)
  );

  return { score: Math.max(0, Math.min(100, score)), errors };
}

/* ── Score → band label ─────────────────────────────────────────────── */
export function scoreToBand(score) {
  if (score >= 85) return { band: 'critical', label: 'Critical' };
  if (score >= 65) return { band: 'high', label: 'High' };
  if (score >= 40) return { band: 'medium', label: 'Medium' };
  return { band: 'low', label: 'Low' };
}

/* ── Recompute risk for all incidents (called after weight change) ─── */
export function recomputeAllRisks(rationale = 'Weight configuration updated') {
  const meta = getMeta();
  const prefs = getPrefs();
  let count = 0;

  for (const inc of meta.incidents) {
    const oldScore = inc.risk;
    const { score } = calculateRisk(inc.inputs, prefs.riskWeights);
    inc.risk = score;
    inc.riskHistory.push({
      ts: new Date().toISOString(),
      score,
      before: oldScore,
      inputs: { ...inc.inputs },
      formulaVersion: prefs.riskWeightsVersion,
      rationale,
    });
    count++;
  }

  saveMeta();
  appendAudit(`Risk recomputed for ${count} incidents`, 'all', 'risk', { rationale, formulaVersion: prefs.riskWeightsVersion });
  return count;
}

/* ── Asset importance validation ────────────────────────────────────── */
export function validateAssetImportance(v) {
  const n = Number(v);
  return !isNaN(n) && n >= 0 && n <= 100;
}

export function getCurrentRisk() {
  const meta = getMeta();
  const incidents = meta.incidents || [];
  if (!incidents.length) return { score: 0, band: 'low', label: 'Low' };
  const maxScore = Math.max(...incidents.map(i => i.risk || 0));
  return { score: maxScore, ...scoreToBand(maxScore) };
}

