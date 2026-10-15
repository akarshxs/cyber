/**
 * seed.js — Comprehensive Seed Data Generator for Velocities SI
 * Automatically populates high-fidelity defensive security data across:
 * - Incident Center (Critical, High, Medium, Contained, Investigating)
 * - Live Events Explorer (IndexedDB events with realistic telemetry)
 * - Threat Detection (Rules with active matches)
 * - Attack Chain (Correlated stages & MITRE ATT&CK mappings)
 * - Risk Intelligence (Historical risk progression)
 * - Response Center (Pending & approved containment actions)
 * - Audit Logs (Realistic SOC analyst decisions)
 */
'use strict';

import { getMeta, saveMeta, idbPutBatch, idbCount } from './store.js';

export async function checkAndSeedData(force = false) {
  const meta = getMeta();
  const eventCount = await idbCount('events');

  if (!force && meta.incidents && meta.incidents.length > 0 && eventCount > 10) {
    return; // Already seeded with data
  }

  const now = Date.now();

  // 1. Incidents
  meta.incidents = [
    {
      id: 'INC-2025-001',
      title: 'Domain Controller Privilege Escalation via Token Impersonation',
      host: 'lab-dc-01',
      user: 'test.alex',
      ip: '198.51.100.42',
      status: 'New',
      priority: 'critical',
      severity: 'critical',
      risk: 94,
      owner: 'Analyst Alpha',
      correlationKey: 'corr-198.51.100.42-token',
      createdAt: new Date(now - 14 * 60 * 1000).toISOString(),
      updatedAt: new Date(now - 2 * 60 * 1000).toISOString(),
      detectionIds: ['DET-001', 'DET-002'],
      eventIds: ['EVT-101', 'EVT-102', 'EVT-103'],
      hypothesis: 'Adversary leveraged SeDebugPrivilege to extract LSASS memory tokens and impersonate Domain Admin account.',
      mitreHypotheses: [
        { technique: 'T1134', name: 'Access Token Manipulation', stage: 'Privilege Escalation', ruleId: 'R-003' },
        { technique: 'T1003.001', name: 'LSASS Memory Dumping', stage: 'Credential Access', ruleId: 'R-001' }
      ],
      inputs: { severity: 95, confidence: 92, assetImportance: 95, impact: 95, evidenceSupport: 90 },
      riskHistory: [
        { ts: new Date(now - 14 * 60 * 1000).toISOString(), score: 75, before: 0, inputs: {}, formulaVersion: 1, rationale: 'Initial detection' },
        { ts: new Date(now - 2 * 60 * 1000).toISOString(), score: 94, before: 75, inputs: {}, formulaVersion: 1, rationale: 'Token manipulation correlated' }
      ],
      notes: [
        { ts: new Date(now - 10 * 60 * 1000).toISOString(), author: 'System Triage', text: 'Automated correlation matched 3 related telemetry signals.' },
        { ts: new Date(now - 4 * 60 * 1000).toISOString(), author: 'Analyst Alpha', text: 'Confirmed suspicious PowerShell invoking Sekurlsa. Host isolation requested.' }
      ]
    },
    {
      id: 'INC-2025-002',
      title: 'Ransomware Precursor: Shadow Copy Deletion (vssadmin)',
      host: 'lab-web-01',
      user: 'svc.backup',
      ip: '198.51.100.88',
      status: 'Investigating',
      priority: 'critical',
      severity: 'critical',
      risk: 91,
      owner: 'Analyst Bravo',
      correlationKey: 'corr-198.51.100.88-vss',
      createdAt: new Date(now - 26 * 60 * 1000).toISOString(),
      updatedAt: new Date(now - 7 * 60 * 1000).toISOString(),
      detectionIds: ['DET-003'],
      eventIds: ['EVT-104', 'EVT-105'],
      hypothesis: 'Ransomware inhibitor: Execution of vssadmin delete shadows /all /quiet and bcdedit recovery disabled.',
      mitreHypotheses: [
        { technique: 'T1490', name: 'Inhibit System Recovery', stage: 'Impact', ruleId: 'R-005' },
        { technique: 'T1486', name: 'Data Encrypted for Impact', stage: 'Impact', ruleId: 'R-005' }
      ],
      inputs: { severity: 95, confidence: 90, assetImportance: 90, impact: 90, evidenceSupport: 88 },
      riskHistory: [{ ts: new Date(now - 26 * 60 * 1000).toISOString(), score: 91, before: 0, inputs: {}, formulaVersion: 1, rationale: 'Ransomware inhibitor rule triggered' }],
      notes: [{ ts: new Date(now - 18 * 60 * 1000).toISOString(), author: 'Analyst Bravo', text: 'Process tree shows cmd.exe spawning vssadmin. Network isolation pending approval.' }]
    },
    {
      id: 'INC-2025-003',
      title: 'Suspicious PowerShell In-Memory C2 Download Cradle',
      host: 'lab-web-02',
      user: 'svc.ops',
      ip: '203.0.113.15',
      status: 'Investigating',
      priority: 'high',
      severity: 'high',
      risk: 78,
      owner: 'Analyst Alpha',
      correlationKey: 'corr-203.0.113.15-ps',
      createdAt: new Date(now - 38 * 60 * 1000).toISOString(),
      updatedAt: new Date(now - 12 * 60 * 1000).toISOString(),
      detectionIds: ['DET-004'],
      eventIds: ['EVT-106', 'EVT-107'],
      hypothesis: 'PowerShell hidden download cradle fetching remote payload from 203.0.113.15:443.',
      mitreHypotheses: [
        { technique: 'T1059.001', name: 'PowerShell Execution', stage: 'Execution', ruleId: 'R-002' },
        { technique: 'T1105', name: 'Ingress Tool Transfer', stage: 'Command and Control', ruleId: 'R-002' }
      ],
      inputs: { severity: 80, confidence: 85, assetImportance: 85, impact: 75, evidenceSupport: 70 },
      riskHistory: [{ ts: new Date(now - 38 * 60 * 1000).toISOString(), score: 78, before: 0, inputs: {}, formulaVersion: 1, rationale: 'C2 beacon detected' }],
      notes: [{ ts: new Date(now - 30 * 60 * 1000).toISOString(), author: 'Analyst Alpha', text: 'Base64 encoded string decoded to IEX DownloadString.' }]
    },
    {
      id: 'INC-2025-004',
      title: 'Stealth SYN Reconnaissance & Port Probe Burst',
      host: 'lab-web-03',
      user: 'anonymous',
      ip: '198.51.100.199',
      status: 'Contained',
      priority: 'high',
      severity: 'high',
      risk: 72,
      owner: 'Analyst Gamma',
      correlationKey: 'corr-198.51.100.199-scan',
      createdAt: new Date(now - 48 * 60 * 1000).toISOString(),
      updatedAt: new Date(now - 18 * 60 * 1000).toISOString(),
      detectionIds: ['DET-005'],
      eventIds: ['EVT-108', 'EVT-109'],
      hypothesis: 'Probing across TCP ports 22, 80, 443, 3389, 8080 from untrusted external subnet.',
      mitreHypotheses: [
        { technique: 'T1046', name: 'Network Service Discovery', stage: 'Reconnaissance', ruleId: 'R-004' }
      ],
      inputs: { severity: 70, confidence: 80, assetImportance: 80, impact: 65, evidenceSupport: 75 },
      riskHistory: [{ ts: new Date(now - 48 * 60 * 1000).toISOString(), score: 72, before: 0, inputs: {}, formulaVersion: 1, rationale: 'Firewall deny burst' }],
      notes: [{ ts: new Date(now - 22 * 60 * 1000).toISOString(), author: 'Analyst Gamma', text: 'Edge ACL drop rule successfully enacted. Source IP blackholed.' }]
    },
    {
      id: 'INC-2025-005',
      title: 'Horizontal Password Spraying Against Directory Services',
      host: 'lab-dc-01',
      user: 'multiple (5 accounts)',
      ip: '198.51.100.77',
      status: 'Contained',
      priority: 'medium',
      severity: 'medium',
      risk: 58,
      owner: 'Analyst Bravo',
      correlationKey: 'corr-198.51.100.77-spray',
      createdAt: new Date(now - 58 * 60 * 1000).toISOString(),
      updatedAt: new Date(now - 28 * 60 * 1000).toISOString(),
      detectionIds: ['DET-006'],
      eventIds: ['EVT-110'],
      hypothesis: 'Low-and-slow authentication attempts using single common password across 5 distinct directory accounts.',
      mitreHypotheses: [
        { technique: 'T1110.003', name: 'Password Spraying', stage: 'Credential Access', ruleId: 'R-006' }
      ],
      inputs: { severity: 55, confidence: 75, assetImportance: 95, impact: 45, evidenceSupport: 60 },
      riskHistory: [{ ts: new Date(now - 58 * 60 * 1000).toISOString(), score: 58, before: 0, inputs: {}, formulaVersion: 1, rationale: 'Password spray burst detected' }],
      notes: [{ ts: new Date(now - 35 * 60 * 1000).toISOString(), author: 'Analyst Bravo', text: 'Affected accounts flagged for mandatory credential rotation.' }]
    },
    {
      id: 'INC-2025-006',
      title: 'Anomalous High-Frequency DNS TXT Exfiltration Query',
      host: 'lab-db-01',
      user: 'svc.sql',
      ip: '192.0.2.15',
      status: 'Resolved',
      priority: 'low',
      severity: 'low',
      risk: 34,
      owner: 'Analyst Alpha',
      correlationKey: 'corr-192.0.2.15-dns',
      createdAt: new Date(now - 90 * 60 * 1000).toISOString(),
      updatedAt: new Date(now - 40 * 60 * 1000).toISOString(),
      detectionIds: ['DET-007'],
      eventIds: ['EVT-111'],
      hypothesis: 'Data chunking encoded within subdomains of external NS query.',
      mitreHypotheses: [
        { technique: 'T1071.004', name: 'DNS Exfiltration', stage: 'Exfiltration', ruleId: 'R-007' }
      ],
      inputs: { severity: 40, confidence: 60, assetImportance: 90, impact: 30, evidenceSupport: 40 },
      riskHistory: [{ ts: new Date(now - 90 * 60 * 1000).toISOString(), score: 34, before: 0, inputs: {}, formulaVersion: 1, rationale: 'DNS entropy burst' }],
      notes: [{ ts: new Date(now - 45 * 60 * 1000).toISOString(), author: 'Analyst Alpha', text: 'Verified test query generated during benign database benchmark. Whitelisted.' }]
    }
  ];

  // 2. Detections
  meta.detections = [
    {
      id: 'DET-001',
      ruleId: 'R-003',
      ruleVersion: 'v1.2',
      ruleName: 'Privilege change after suspicious authentication',
      severity: 'critical',
      ts: new Date(now - 14 * 60 * 1000).toISOString(),
      host: 'lab-dc-01',
      user: 'test.alex',
      ip: '198.51.100.42',
      triggeringEventIds: ['EVT-101'],
      windowMinutes: 15,
      threshold: 1,
      matched: 1,
      explanation: 'User test.alex escalated to Domain Admins group following anomalous credential access.',
      mitreTechnique: 'T1134',
      mitreName: 'Access Token Manipulation',
      incidentId: 'INC-2025-001',
      suppressed: false
    },
    {
      id: 'DET-002',
      ruleId: 'R-001',
      ruleVersion: 'v1.0',
      ruleName: 'Failed login burst threshold exceeded',
      severity: 'high',
      ts: new Date(now - 17 * 60 * 1000).toISOString(),
      host: 'lab-dc-01',
      user: 'test.alex',
      ip: '198.51.100.42',
      triggeringEventIds: ['EVT-102', 'EVT-103'],
      windowMinutes: 5,
      threshold: 5,
      matched: 25,
      explanation: '25 failed authentication attempts within 3 minutes from IP 198.51.100.42.',
      mitreTechnique: 'T1110.001',
      mitreName: 'Password Guessing',
      incidentId: 'INC-2025-001',
      suppressed: false
    },
    {
      id: 'DET-003',
      ruleId: 'R-005',
      ruleVersion: 'v2.0',
      ruleName: 'Ransomware backup shadow deletion (vssadmin)',
      severity: 'critical',
      ts: new Date(now - 26 * 60 * 1000).toISOString(),
      host: 'lab-web-01',
      user: 'svc.backup',
      ip: '198.51.100.88',
      triggeringEventIds: ['EVT-104'],
      windowMinutes: 5,
      threshold: 1,
      matched: 1,
      explanation: 'vssadmin.exe executed with flags "delete shadows /all /quiet".',
      mitreTechnique: 'T1490',
      mitreName: 'Inhibit System Recovery',
      incidentId: 'INC-2025-002',
      suppressed: false
    },
    {
      id: 'DET-004',
      ruleId: 'R-002',
      ruleVersion: 'v1.1',
      ruleName: 'PowerShell hidden encoded download cradle',
      severity: 'high',
      ts: new Date(now - 38 * 60 * 1000).toISOString(),
      host: 'lab-web-02',
      user: 'svc.ops',
      ip: '203.0.113.15',
      triggeringEventIds: ['EVT-106'],
      windowMinutes: 10,
      threshold: 1,
      matched: 1,
      explanation: 'powershell.exe -w hidden -enc IEX (New-Object Net.WebClient).',
      mitreTechnique: 'T1059.001',
      mitreName: 'Command and Scripting Interpreter: PowerShell',
      incidentId: 'INC-2025-003',
      suppressed: false
    },
    {
      id: 'DET-005',
      ruleId: 'R-004',
      ruleVersion: 'v1.0',
      ruleName: 'Port scan probing distinct ports threshold',
      severity: 'high',
      ts: new Date(now - 48 * 60 * 1000).toISOString(),
      host: 'lab-web-03',
      user: 'anonymous',
      ip: '198.51.100.199',
      triggeringEventIds: ['EVT-108'],
      windowMinutes: 5,
      threshold: 10,
      matched: 16,
      explanation: '16 distinct port connection attempts blocked at border firewall within 60 seconds.',
      mitreTechnique: 'T1046',
      mitreName: 'Network Service Discovery',
      incidentId: 'INC-2025-004',
      suppressed: false
    },
    {
      id: 'DET-006',
      ruleId: 'R-006',
      ruleVersion: 'v1.0',
      ruleName: 'Password spray across multiple distinct accounts',
      severity: 'medium',
      ts: new Date(now - 58 * 60 * 1000).toISOString(),
      host: 'lab-dc-01',
      user: 'multiple',
      ip: '198.51.100.77',
      triggeringEventIds: ['EVT-110'],
      windowMinutes: 15,
      threshold: 3,
      matched: 5,
      explanation: 'Failed login attempts against 5 distinct directory accounts from single source IP.',
      mitreTechnique: 'T1110.003',
      mitreName: 'Password Spraying',
      incidentId: 'INC-2025-005',
      suppressed: false
    }
  ];

  // 3. Response Center (Approval Requests & Executions)
  meta.approvalRequests = [
    {
      id: 'REQ-2025-001',
      actionType: 'isolate_host',
      target: 'lab-dc-01',
      incidentId: 'INC-2025-001',
      requestedBy: 'Analyst Alpha',
      requestedAt: new Date(now - 8 * 60 * 1000).toISOString(),
      expiresAt: new Date(now + 22 * 60 * 1000).toISOString(),
      status: 'pending',
      rationale: 'Domain Controller compromise suspected; isolate from corporate LAN to prevent Kerberoasting.',
      parameters: { host: 'lab-dc-01', isolateInterfaces: ['eth0', 'eth1'] }
    },
    {
      id: 'REQ-2025-002',
      actionType: 'block_ip',
      target: '198.51.100.42',
      incidentId: 'INC-2025-001',
      requestedBy: 'Analyst Alpha',
      requestedAt: new Date(now - 10 * 60 * 1000).toISOString(),
      expiresAt: new Date(now + 20 * 60 * 1000).toISOString(),
      status: 'approved',
      approvedBy: 'Lead Analyst',
      approvedAt: new Date(now - 6 * 60 * 1000).toISOString(),
      rationale: 'Attacker command & control external proxy address.',
      parameters: { ip: '198.51.100.42', direction: 'both' }
    },
    {
      id: 'REQ-2025-003',
      actionType: 'kill_process',
      target: 'PID:4912 (powershell.exe)',
      incidentId: 'INC-2025-003',
      requestedBy: 'Analyst Bravo',
      requestedAt: new Date(now - 22 * 60 * 1000).toISOString(),
      expiresAt: new Date(now + 8 * 60 * 1000).toISOString(),
      status: 'approved',
      approvedBy: 'Lead Analyst',
      approvedAt: new Date(now - 18 * 60 * 1000).toISOString(),
      rationale: 'Terminate malicious in-memory download cradle process.',
      parameters: { pid: 4912, processName: 'powershell.exe' }
    }
  ];

  meta.executionRecords = [
    {
      id: 'EXEC-2025-001',
      requestId: 'REQ-2025-002',
      actionType: 'block_ip',
      target: '198.51.100.42',
      status: 'success',
      executedAt: new Date(now - 5 * 60 * 1000).toISOString(),
      durationMs: 420,
      result: 'Firewall ACL rule #9042 successfully committed across perimeter cluster.',
      simulated: true
    },
    {
      id: 'EXEC-2025-002',
      requestId: 'REQ-2025-003',
      actionType: 'kill_process',
      target: 'PID:4912 (powershell.exe)',
      status: 'success',
      executedAt: new Date(now - 17 * 60 * 1000).toISOString(),
      durationMs: 180,
      result: 'Process PID 4912 terminated via EDR agent. Memory image dumped for forensics.',
      simulated: true
    }
  ];

  // 4. Audit Log
  meta.auditLog = [
    { ts: new Date(now - 5 * 60 * 1000).toISOString(), actor: 'Lead Analyst', action: 'Approved host isolation request REQ-2025-002', entity: '198.51.100.42', category: 'response' },
    { ts: new Date(now - 8 * 60 * 1000).toISOString(), actor: 'Analyst Alpha', action: 'Requested host isolation for lab-dc-01', entity: 'REQ-2025-001', category: 'response' },
    { ts: new Date(now - 10 * 60 * 1000).toISOString(), actor: 'Analyst Alpha', action: 'Assigned incident INC-2025-001 to Analyst Alpha', entity: 'INC-2025-001', category: 'incident' },
    { ts: new Date(now - 14 * 60 * 1000).toISOString(), actor: 'Rule Engine', action: 'Triggered detection DET-001 (R-003: Access Token Manipulation)', entity: 'lab-dc-01', category: 'detection' },
    { ts: new Date(now - 18 * 60 * 1000).toISOString(), actor: 'Lead Analyst', action: 'Approved process termination request REQ-2025-003', entity: 'PID:4912', category: 'response' },
    { ts: new Date(now - 26 * 60 * 1000).toISOString(), actor: 'Rule Engine', action: 'Triggered detection DET-003 (R-005: Ransomware Recovery Inhibition)', entity: 'lab-web-01', category: 'detection' },
    { ts: new Date(now - 38 * 60 * 1000).toISOString(), actor: 'Rule Engine', action: 'Triggered detection DET-004 (R-002: PowerShell Download Cradle)', entity: 'lab-web-02', category: 'detection' },
    { ts: new Date(now - 48 * 60 * 1000).toISOString(), actor: 'Analyst Gamma', action: 'Contained incident INC-2025-004 via perimeter block', entity: 'INC-2025-004', category: 'incident' }
  ];

  // 5. Risk History progression
  meta.riskHistory = [
    { ts: new Date(now - 60 * 60 * 1000).toISOString(), score: 28, before: 20, inputs: {}, formulaVersion: 1, rationale: 'Normal operational baseline' },
    { ts: new Date(now - 48 * 60 * 1000).toISOString(), score: 54, before: 28, inputs: {}, formulaVersion: 1, rationale: 'Port reconnaissance detected' },
    { ts: new Date(now - 38 * 60 * 1000).toISOString(), score: 72, before: 54, inputs: {}, formulaVersion: 1, rationale: 'PowerShell C2 cradle detected' },
    { ts: new Date(now - 26 * 60 * 1000).toISOString(), score: 88, before: 72, inputs: {}, formulaVersion: 1, rationale: 'Ransomware inhibitor rule triggered' },
    { ts: new Date(now - 14 * 60 * 1000).toISOString(), score: 94, before: 88, inputs: {}, formulaVersion: 1, rationale: 'Domain Controller compromise correlated' }
  ];

  saveMeta();

  // 6. Generate and batch-insert 120+ events into IndexedDB
  const events = [];
  const eventTypes = [
    { type: 'Failed login', stage: 'Credential Access', severity: 'medium', outcome: 'failure' },
    { type: 'Successful login', stage: 'Initial Access', severity: 'low', outcome: 'success' },
    { type: 'Firewall deny', stage: 'Reconnaissance', severity: 'high', outcome: 'blocked' },
    { type: 'Privilege change', stage: 'Privilege Escalation', severity: 'critical', outcome: 'success' },
    { type: 'Process created', stage: 'Execution', severity: 'high', outcome: 'success' },
    { type: 'DNS query', stage: 'Command and Control', severity: 'medium', outcome: 'success' },
    { type: 'File modified', stage: 'Impact', severity: 'critical', outcome: 'success' },
    { type: 'Registry key modified', stage: 'Persistence', severity: 'high', outcome: 'success' }
  ];
  const hosts = ['lab-dc-01', 'lab-web-01', 'lab-web-02', 'lab-web-03', 'lab-db-01'];
  const users = ['test.alex', 'svc.backup', 'svc.ops', 'svc.sql', 'admin', 'anonymous'];
  const ips = ['198.51.100.42', '198.51.100.88', '203.0.113.15', '198.51.100.199', '198.51.100.77', '192.0.2.10'];

  // Seed linked incident events first
  events.push(
    { id: 'EVT-101', ts: new Date(now - 14 * 60 * 1000).toISOString(), type: 'Privilege change', host: 'lab-dc-01', user: 'test.alex', ip: '198.51.100.42', outcome: 'success', stage: 'Privilege Escalation', source: 'SecurityLog', severity: 'critical', synthetic: true },
    { id: 'EVT-102', ts: new Date(now - 16 * 60 * 1000).toISOString(), type: 'Failed login', host: 'lab-dc-01', user: 'test.alex', ip: '198.51.100.42', outcome: 'failure', stage: 'Credential Access', source: 'AuthDaemon', severity: 'medium', synthetic: true },
    { id: 'EVT-103', ts: new Date(now - 17 * 60 * 1000).toISOString(), type: 'Failed login', host: 'lab-dc-01', user: 'test.alex', ip: '198.51.100.42', outcome: 'failure', stage: 'Credential Access', source: 'AuthDaemon', severity: 'medium', synthetic: true },
    { id: 'EVT-104', ts: new Date(now - 26 * 60 * 1000).toISOString(), type: 'Process created', host: 'lab-web-01', user: 'svc.backup', ip: '198.51.100.88', outcome: 'success', stage: 'Impact', source: 'Sysmon', severity: 'critical', synthetic: true, raw: 'cmd.exe /c vssadmin delete shadows /all /quiet' },
    { id: 'EVT-105', ts: new Date(now - 27 * 60 * 1000).toISOString(), type: 'File modified', host: 'lab-web-01', user: 'svc.backup', ip: '198.51.100.88', outcome: 'success', stage: 'Impact', source: 'FIM', severity: 'critical', synthetic: true },
    { id: 'EVT-106', ts: new Date(now - 38 * 60 * 1000).toISOString(), type: 'Process created', host: 'lab-web-02', user: 'svc.ops', ip: '203.0.113.15', outcome: 'success', stage: 'Execution', source: 'Sysmon', severity: 'high', synthetic: true, raw: 'powershell.exe -w hidden -enc IEX' },
    { id: 'EVT-107', ts: new Date(now - 39 * 60 * 1000).toISOString(), type: 'DNS query', host: 'lab-web-02', user: 'svc.ops', ip: '203.0.113.15', outcome: 'success', stage: 'Command and Control', source: 'DNSLogs', severity: 'high', synthetic: true },
    { id: 'EVT-108', ts: new Date(now - 48 * 60 * 1000).toISOString(), type: 'Firewall deny', host: 'lab-web-03', user: 'anonymous', ip: '198.51.100.199', outcome: 'blocked', stage: 'Reconnaissance', source: 'EdgeFirewall', severity: 'high', synthetic: true, destinationPort: 443 },
    { id: 'EVT-109', ts: new Date(now - 49 * 60 * 1000).toISOString(), type: 'Firewall deny', host: 'lab-web-03', user: 'anonymous', ip: '198.51.100.199', outcome: 'blocked', stage: 'Reconnaissance', source: 'EdgeFirewall', severity: 'high', synthetic: true, destinationPort: 3389 },
    { id: 'EVT-110', ts: new Date(now - 58 * 60 * 1000).toISOString(), type: 'Failed login', host: 'lab-dc-01', user: 'test.user1', ip: '198.51.100.77', outcome: 'failure', stage: 'Credential Access', source: 'AuthDaemon', severity: 'medium', synthetic: true },
    { id: 'EVT-111', ts: new Date(now - 90 * 60 * 1000).toISOString(), type: 'DNS query', host: 'lab-db-01', user: 'svc.sql', ip: '192.0.2.15', outcome: 'success', stage: 'Exfiltration', source: 'DNSLogs', severity: 'low', synthetic: true }
  );

  // Generate 120 more realistic events across the last 60 minutes
  for (let i = 0; i < 120; i++) {
    const template = eventTypes[i % eventTypes.length];
    const offsetMs = Math.floor(Math.random() * 60 * 60 * 1000);
    const host = hosts[i % hosts.length];
    const user = users[i % users.length];
    const ip = ips[i % ips.length];

    events.push({
      id: `EVT-${200 + i}`,
      ts: new Date(now - offsetMs).toISOString(),
      type: template.type,
      host,
      user,
      ip,
      outcome: template.outcome,
      stage: template.stage,
      source: 'DefenseCollector',
      severity: template.severity,
      synthetic: true,
      raw: JSON.stringify({ event: template.type, host, user, ip, timestamp: new Date(now - offsetMs).toISOString() })
    });
  }

  try {
    await idbPutBatch('events', events);
  } catch (e) {
    console.warn('Unable to batch put seed events in IDB:', e);
  }

  console.info('Velocities SI seed dataset successfully initialized.');
}
