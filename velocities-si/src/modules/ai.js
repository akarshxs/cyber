/**
 * ai.js — OpenAI-compatible Cyber Intelligence & AI Copilot Module
 * Endpoint: https://radoxai.com/v1
 * Default Model: deepseek-v4-flash-0731
 */
'use strict';

const LS_KEY_STORAGE = 'vsi-ai-apikey-v1';
const LS_CONFIG_STORAGE = 'vsi-ai-config-v1';

// Default provided environment settings
export const DEFAULT_AI_CONFIG = {
  baseUrl: 'https://radoxai.com/v1',
  model: 'deepseek-v4-flash-0731',
  temperature: 0.3,
  systemPrompt: `You are Velocities SI Cyber Copilot, an expert AI defense analyst specialized in ABCS-03 adaptive cyber operations.
You provide precise, evidence-led threat triage, MITRE ATT&CK correlation, and defensive containment playbooks.
Keep answers concise, structured in Markdown, and actionable for human security analysts.`,
};

// Fallback provided default key from environment if not yet overridden in localStorage
const FALLBACK_ENV_KEY = 'cc_mgYOZtNGAhr69h2KrCJOFIWWrmv5SQi6QSLbSNlmcVrWL2NS';

export function getApiKey() {
  try {
    const saved = localStorage.getItem(LS_KEY_STORAGE);
    return saved && saved.trim() ? saved.trim() : FALLBACK_ENV_KEY;
  } catch {
    return FALLBACK_ENV_KEY;
  }
}

export function saveApiKey(key) {
  try {
    if (key && key.trim()) {
      localStorage.setItem(LS_KEY_STORAGE, key.trim());
    } else {
      localStorage.removeItem(LS_KEY_STORAGE);
    }
  } catch (e) {
    console.warn('Unable to persist API key:', e);
  }
}

export function getAIConfig() {
  let saved = {};
  try {
    const raw = localStorage.getItem(LS_CONFIG_STORAGE);
    if (raw) saved = JSON.parse(raw);
  } catch {}

  return {
    baseUrl: saved.baseUrl || DEFAULT_AI_CONFIG.baseUrl,
    model: saved.model || DEFAULT_AI_CONFIG.model,
    temperature: saved.temperature ?? DEFAULT_AI_CONFIG.temperature,
    systemPrompt: saved.systemPrompt || DEFAULT_AI_CONFIG.systemPrompt,
  };
}

export function saveAIConfig(cfg) {
  try {
    const current = getAIConfig();
    const updated = { ...current, ...cfg };
    localStorage.setItem(LS_CONFIG_STORAGE, JSON.stringify(updated));
    return updated;
  } catch (e) {
    console.warn('Unable to save AI config:', e);
    return getAIConfig();
  }
}

export function maskApiKey(key) {
  if (!key) return '(not configured)';
  if (key.length <= 8) return '••••••••';
  return `${key.slice(0, 5)}••••••••••••${key.slice(-4)}`;
}

/**
 * Core OpenAI-compatible chat completion caller.
 */
export async function callOpenAI({ messages, model, temperature, signal }) {
  const config = getAIConfig();
  const apiKey = getApiKey();
  const targetModel = model || config.model;
  const baseUrl = (config.baseUrl || DEFAULT_AI_CONFIG.baseUrl).replace(/\/+$/, '');

  const fullMessages = [
    { role: 'system', content: config.systemPrompt },
    ...messages
  ];

  const payload = {
    model: targetModel,
    messages: fullMessages,
    temperature: temperature ?? config.temperature,
    max_tokens: 1200,
  };

  const headers = {
    'Content-Type': 'application/json',
  };

  if (apiKey) {
    headers['Authorization'] = `Bearer ${apiKey}`;
  }

  const endpoint = `${baseUrl}/chat/completions`;

  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
      signal,
    });

    if (!res.ok) {
      let errText = '';
      try {
        const errJson = await res.json();
        errText = errJson.error?.message || errJson.message || JSON.stringify(errJson);
      } catch {
        errText = await res.text();
      }
      throw new Error(`API HTTP ${res.status}: ${errText || res.statusText}`);
    }

    const data = await res.json();
    const choice = data.choices?.[0];
    const content = choice?.message?.content || choice?.text || 'No response generated.';
    const usage = data.usage || null;

    return {
      success: true,
      content,
      model: data.model || targetModel,
      usage,
    };
  } catch (err) {
    console.error('OpenAI call failed:', err);
    throw err;
  }
}

/**
 * Fetch available models from /v1/models
 */
export async function fetchAvailableModels() {
  const config = getAIConfig();
  const apiKey = getApiKey();
  const baseUrl = (config.baseUrl || DEFAULT_AI_CONFIG.baseUrl).replace(/\/+$/, '');

  try {
    const res = await fetch(`${baseUrl}/models`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
      },
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (Array.isArray(data.data)) {
      return data.data.map(m => m.id);
    }
    return [config.model];
  } catch (e) {
    console.warn('Could not fetch models list, using defaults:', e);
    return [
      'deepseek-v4-flash-0731',
      'deepseek-v4-pro-0813',
      'gpt-5.6-luna',
      'claude-sonnet-5',
      'claude-opus-5',
      'qwen3.8-max',
      'gemini-3.7-flash',
    ];
  }
}

/**
 * One-click AI Incident Triage
 */
export async function triageIncidentAI(incident, relatedEvents = []) {
  const prompt = `Analyze this security incident from Velocities SI defensive lab:
- ID: ${incident.id}
- Title: ${incident.title}
- Severity: ${incident.severity}
- State: ${incident.status}
- Hypothesis: ${incident.hypothesis || 'Unspecified'}
- Affected Assets: ${JSON.stringify(incident.affectedAssets || [])}
- Events Count: ${relatedEvents.length}

Provide a concise assessment covering:
1. Threat Analysis & MITRE ATT&CK alignment
2. Probable Blast Radius & Asset Impact
3. Concrete Step-by-Step Containment Actions`;

  return await callOpenAI({
    messages: [{ role: 'user', content: prompt }]
  });
}

/**
 * Triage all active incidents
 */
export async function triageAllActiveIncidents(incidents = [], currentRisk = null) {
  const prompt = `Provide an Executive Security Intelligence Assessment for the active SOC workspace:
- Total Active Incidents: ${incidents.length}
- Current Calculated Risk Score: ${currentRisk ? currentRisk.score : 'N/A'}/100
- Incidents Summary:
${incidents.map(i => `  • [${i.id}] (${i.severity.toUpperCase()}) ${i.title} - Status: ${i.status}`).join('\n')}

Synthesize:
1. Overall Threat Posture & Attack Vectors observed
2. Highest priority threat requiring immediate containment
3. Strategic defense advice`;

  return await callOpenAI({
    messages: [{ role: 'user', content: prompt }]
  });
}

/**
 * Calculate SHA-256 hash from ArrayBuffer
 */
export async function calculateSHA256(buffer) {
  try {
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  } catch (e) {
    console.warn('Crypto subtle SHA-256 failed:', e);
    return 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  }
}

/**
 * Calculate Shannon Entropy of a byte array (0 - 8).
 * Entropy > 7.0 typically signifies encrypted, packed, or heavily obfuscated malware.
 */
export function calculateEntropy(uint8Array) {
  if (!uint8Array || !uint8Array.length) return 0;
  const freq = new Array(256).fill(0);
  for (let i = 0; i < uint8Array.length; i++) {
    freq[uint8Array[i]]++;
  }
  let entropy = 0;
  const len = uint8Array.length;
  for (let i = 0; i < 256; i++) {
    if (freq[i] > 0) {
      const p = freq[i] / len;
      entropy -= p * Math.log2(p);
    }
  }
  return parseFloat(entropy.toFixed(3));
}

/**
 * Static Heuristic Scanner for suspicious APIs, commands, and script patterns.
 */
export function scanHeuristics(content = '', filename = '') {
  const flags = [];
  const text = String(content);

  // PowerShell stealth & execution bypass
  if (/powershell(\.exe)?\s+(-(enc|encodedcommand|executionpolicy\s+bypass|nop|w\s+hidden))/i.test(text)) {
    flags.push({ severity: 'critical', desc: 'PowerShell hidden window / execution policy bypass detected' });
  }

  // Process injection & memory manipulation
  if (/(virtualalloc|writeprocessmemory|createremotethread|ntunmapviewofsection|ptr_to_func)/i.test(text)) {
    flags.push({ severity: 'critical', desc: 'Direct memory allocation & process injection primitives (VirtualAlloc / WriteProcessMemory)' });
  }

  // Web client cradles / Remote file execution
  if (/(invoke-expression|iex\s*\(|downloadstring|downloaddata|net\.webclient|curl\s+-[fsSL]|wget\s+-[qO])/i.test(text)) {
    flags.push({ severity: 'high', desc: 'Remote payload download & in-memory script execution cradle (IEX / WebClient)' });
  }

  // Interactive reverse shells & sockets
  if (/(cmd\.exe\s+\/c|bash\s+-i|nc\s+-e|\/dev\/tcp\/|socket\.socket|reverse_tcp)/i.test(text)) {
    flags.push({ severity: 'critical', desc: 'Interactive reverse shell or spawned command execution handler' });
  }

  // Persistence mechanisms
  if (/(reg\s+add|currentversion\\run|schtasks\s+\/create|systemd\/system|crontab)/i.test(text)) {
    flags.push({ severity: 'high', desc: 'Host persistence mechanism (Windows Run Key / Cron / Scheduled Task)' });
  }

  // Shadow copy deletion / Ransomware defense inhibition
  if (/(vssadmin\s+delete\s+shadows|wbadmin\s+delete|bcdedit.*recoveryenabled\s+no|cipher\s+\/w)/i.test(text)) {
    flags.push({ severity: 'critical', desc: 'Ransomware inhibitor: Volume shadow copy & backup recovery destruction' });
  }

  // Obfuscated Base64 blobs
  if (/([A-Za-z0-9+/]{64,}={0,2})/.test(text)) {
    flags.push({ severity: 'medium', desc: 'Long Base64 encoded payload stream detected (potential packed binary/shellcode)' });
  }

  // Hardcoded IP addresses
  if (/\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/.test(text)) {
    flags.push({ severity: 'medium', desc: 'Hardcoded remote IPv4 address found (potential C2 beacon address)' });
  }

  // Executable / dangerous script extensions
  const ext = (filename.split('.').pop() || '').toLowerCase();
  if (['exe', 'dll', 'sys', 'scr', 'vbs', 'ps1', 'bat', 'cmd', 'hta', 'sh', 'py', 'elf'].includes(ext)) {
    flags.push({ severity: 'low', desc: `Script or executable file extension (.${ext})` });
  }

  return flags;
}

/**
 * AI Deep Forensic Malware & File Threat Inspector
 * Sends file telemetry, hashes, heuristics, and extracted strings to the RadoxAI LLM for deep verdict.
 */
export async function analyzeFileThreatAI({ filename, size, hash, entropy, sampleContent, heuristics = [] }) {
  const truncatedSample = sampleContent.slice(0, 3000);

  const prompt = `Perform an authoritative cybersecurity static forensic analysis and malware threat inspection on the following target file:

[TARGET FILE TELEMETRY]
- Filename: ${filename}
- File Size: ${size} bytes
- SHA-256 Hash: ${hash}
- Shannon Entropy: ${entropy} / 8.0 ${entropy > 7.0 ? '(HIGH ENTROPY - LIKELY PACKED OR ENCRYPTED)' : '(NORMAL ENTROPY)'}
- Static Heuristic Findings: ${heuristics.length ? heuristics.map(h => `[${h.severity.toUpperCase()}] ${h.desc}`).join('; ') : 'None triggered'}

[EXTRACTED STRINGS / CONTENT SAMPLE (UP TO 3KB)]:
\`\`\`
${truncatedSample}
\`\`\`

Analyze whether this file contains a virus, malware, backdoor, exploit, or is dangerous to use.
Format your response clearly with these sections:

### 1. VERDICT & THREAT CLASSIFICATION
State clearly whether this file is **MALICIOUS / DANGEROUS TO USE**, **SUSPICIOUS**, or **BENIGN / SAFE TO USE**, with a Threat Score (0-100).

### 2. WHY IS THIS FILE DANGEROUS? (OR BENIGN)
Explain the exact malicious mechanisms, payload intent, and what harm executing this file would cause to the operating system or network.

### 3. MITRE ATT&CK TECHNIQUES
List mapped MITRE ATT&CK techniques (e.g. T1059 Command and Scripting Interpreter, T1055 Process Injection, T1486 Data Encrypted for Impact).

### 4. RECOMMENDED DEFENSIVE & CONTAINMENT ACTIONS
Step-by-step containment instructions for the SOC analyst (quarantine, firewall block, endpoint isolation).`;

  return await callOpenAI({
    messages: [{ role: 'user', content: prompt }]
  });
}

