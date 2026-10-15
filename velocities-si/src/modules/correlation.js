/**
 * correlation.js — correlates detections into incidents.
 * Shared entities: user, host, source IP, configurable time window.
 * Suppresses duplicate incident creation on replay.
 */
'use strict';

import { getMeta, getPrefs, nextId, saveMeta, appendAudit } from './store.js';
import { calculateRisk } from './risk.js';

/* ── Correlate a batch of new detections into incidents ─────────────── */
export async function correlateDetections(newDetections) {
  if (!newDetections.length) return [];
  const meta = getMeta();
  const prefs = getPrefs();
  const windowMs = prefs.correlationWindowMinutes * 60 * 1000;
  const created = [];

  for (const det of newDetections) {
    // Try to find an existing open incident that shares context
    const match = meta.incidents.find(inc => {
      if (['Resolved','False positive'].includes(inc.status)) return false;
      const withinWindow = Math.abs(new Date(inc.createdAt) - new Date(det.ts)) <= windowMs;
      return withinWindow && (
        inc.user === det.user || inc.host === det.host || inc.ip === det.ip
      );
    });

    if (match) {
      // Append detection to existing incident
      if (!match.detectionIds.includes(det.id)) {
        match.detectionIds.push(det.id);
      }
      det.incidentId = match.id;

      // Add MITRE hypothesis if not already present
      const alreadyMapped = match.mitreHypotheses.some(h => h.technique === det.mitreTechnique && h.ruleId === det.ruleId);
      if (!alreadyMapped) {
        match.mitreHypotheses.push({
          technique: det.mitreTechnique,
          name: det.mitreName,
          stage: det.ruleName,
          ruleId: det.ruleId,
        });
      }

      // Recalculate risk
      const oldRisk = match.risk;
      updateIncidentInputs(match, det);
      const { score } = calculateRisk(match.inputs, prefs.riskWeights);
      match.risk = score;
      match.priority = scoreToPriority(score);
      match.riskHistory.push({
        ts: new Date().toISOString(),
        score,
        before: oldRisk,
        inputs: { ...match.inputs },
        formulaVersion: prefs.riskWeightsVersion,
        rationale: `Detection ${det.id} (${det.ruleName}) correlated.`,
      });
      match.updatedAt = new Date().toISOString();

      appendAudit(`Detection correlated to existing incident`, match.id, 'correlation');
    } else {
      // Create new incident
      const incId = nextId('INC');
      const inputs = detectionToInputs(det, prefs);
      const { score } = calculateRisk(inputs, prefs.riskWeights);
      const priority = scoreToPriority(score);

      const inc = {
        id: incId,
        title: `${det.ruleName} — ${det.host}`,
        host: det.host,
        user: det.user,
        ip: det.ip,
        status: 'New',
        priority,
        owner: null,
        notes: [],
        risk: score,
        inputs,
        riskHistory: [{
          ts: new Date().toISOString(),
          score,
          before: 0,
          inputs: { ...inputs },
          formulaVersion: prefs.riskWeightsVersion,
          rationale: `Initial detection: ${det.explanation}`,
        }],
        detectionIds: [det.id],
        eventIds: [...det.triggeringEventIds],
        correlationKey: `${det.user}|${det.host}|${det.ip}`,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        mitreHypotheses: [{
          technique: det.mitreTechnique,
          name: det.mitreName,
          stage: det.ruleName,
          ruleId: det.ruleId,
        }],
      };

      det.incidentId = incId;
      meta.incidents.unshift(inc);
      created.push(inc);
      appendAudit(`New incident created`, incId, 'correlation', { ruleId: det.ruleId, risk: score });
    }
  }

  saveMeta();
  return created;
}

function detectionToInputs(det, prefs) {
  const severityScore = { critical: 95, high: 75, medium: 50, low: 25 }[det.severity] || 50;
  const assetScore = prefs.assetImportance[det.host] || 60;
  return {
    severity: severityScore,
    confidence: 65, // uncalibrated heuristic
    assetImportance: assetScore,
    impact: severityScore * 0.8,
    evidenceSupport: Math.min(100, det.matched * 10),
  };
}

function updateIncidentInputs(inc, det) {
  const severityScore = { critical: 95, high: 75, medium: 50, low: 25 }[det.severity] || 50;
  inc.inputs.severity = Math.max(inc.inputs.severity, severityScore);
  inc.inputs.evidenceSupport = Math.min(100, inc.inputs.evidenceSupport + det.matched * 5);
  inc.inputs.impact = Math.max(inc.inputs.impact, severityScore * 0.8);
  // confidence slightly increases with more correlated detections
  inc.inputs.confidence = Math.min(90, inc.inputs.confidence + 5);

  // Append triggering event IDs
  for (const eid of det.triggeringEventIds) {
    if (!inc.eventIds.includes(eid)) inc.eventIds.push(eid);
  }
}

function scoreToPriority(score) {
  if (score >= 85) return 'critical';
  if (score >= 65) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
}
