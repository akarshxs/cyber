/**
 * app.js — Main application entry point.
 * Wires routing, navigation, events, and module initialization.
 * Uses ES modules; requires a static file server (not file: protocol) for CORS.
 */
'use strict';

import { loadMeta, loadPrefs, getMeta, getPrefs, openIDB, appendAudit, saveMeta } from './src/modules/store.js';
import { checkAndSeedData } from './src/modules/seed.js';
import { initSimulatedTargets, checkApprovalExpiry } from './src/modules/response.js';
import { restoreSimState, getSimState, isRunning } from './src/modules/simulator.js';
import { ICONS, esc, showToast, closeDialog } from './src/modules/ui.js';

// Page renderers (lazy-loaded via dynamic import for modularity)
const PAGE_RENDERERS = {
  hero: () => import('./src/pages/hero.js'),
  overview: () => import('./src/pages/overview.js'),
  events: () => import('./src/pages/events.js'),
  detection: () => import('./src/pages/detection.js'),
  incidents: () => import('./src/pages/incidents.js'),
  chain: () => import('./src/pages/chain.js'),
  risk: () => import('./src/pages/risk.js'),
  responses: () => import('./src/pages/responses.js'),
  reports: () => import('./src/pages/reports.js'),
  settings: () => import('./src/pages/settings.js'),
  demo: () => import('./src/pages/demo.js'),
  ai: () => import('./src/pages/ai.js'),
};

const NAV_ITEMS = [
  { id: 'hero', label: '⚡ Sisyphus Hero', icon: 'overview' },
  { id: 'overview', label: 'Overview', icon: 'overview' },
  { id: 'ai', label: 'AI Cyber Copilot', icon: 'ai' },
  { id: 'events', label: 'Live Events', icon: 'events' },
  { id: 'detection', label: 'Threat Detection', icon: 'detection' },
  { id: 'incidents', label: 'Incident Center', icon: 'incidents' },
  { id: 'chain', label: 'Attack Chain', icon: 'chain' },
  { id: 'risk', label: 'Risk Intelligence', icon: 'risk' },
  { id: 'responses', label: 'Response Center', icon: 'responses' },
  { id: 'reports', label: 'Reports & Audit', icon: 'reports' },
  { id: 'settings', label: 'Settings', icon: 'settings' },
  { id: 'demo', label: 'Demo Control', icon: 'demo' },
];

const PAGE_TITLES = {
  hero: ['Sisyphus Protocol', 'Adaptive & Intelligent Cyber Defense // ABCS-03'],
  overview: ['Security overview', 'A clear picture of your security posture. Every signal, connected.'],
  ai: ['AI Cyber Copilot', 'OpenAI-compatible autonomous cyber defense advisor and incident triage engine.'],
  events: ['Event explorer', 'Search, filter, and import the synthetic evidence behind every signal.'],
  detection: ['Threat detection', 'Versioned rules on normalized events. Predictions are not proof.'],
  incidents: ['Incident center', 'Investigate, assign, note, and resolve your demo incidents.'],
  chain: ['Attack chain explorer', 'Connected evidence and MITRE ATT&CK hypotheses (unconfirmed).'],
  risk: ['Risk intelligence', 'Transparent risk formula with traceable history. Inputs are illustrative.'],
  responses: ['Response center', 'Review recommendations. Request, approve, and simulate actions.'],
  reports: ['Reports & audit', 'Export your local evidence and decision history.'],
  settings: ['Workspace settings', 'Configure detection thresholds, risk weights, and preferences.'],
  demo: ['Demo control', 'Generate reproducible synthetic security scenarios.'],
};

let _currentPage = 'overview';

/* ── Bootstrap ───────────────────────────────────────────────────────── */
async function init() {
  try {
    await openIDB();
  } catch (e) {
    console.warn('IndexedDB unavailable:', e);
    // Fall back gracefully — events won't persist but app still works
  }

  loadMeta();
  await checkAndSeedData();
  loadPrefs();
  restoreSimState();
  checkApprovalExpiry();
  initSimulatedTargets();

  const prefs = getPrefs();
  applyTheme(prefs.theme, prefs.density);
  buildNav();
  buildHeader();
  attachGlobalHandlers();

  // Initial page render
  await navigateTo(getPageFromHash());

  // Listen for simulator events
  window.addEventListener('vsi:tick', async () => {
    if (_currentPage === 'overview' || _currentPage === 'events') {
      await renderCurrentPage();
    }
  });
  window.addEventListener('vsi:sim-complete', async () => {
    showToast('Scenario complete! Review Incident Center and Risk Intelligence.', 'success');
    await renderCurrentPage();
  });

  // Expiry check every 30 seconds
  setInterval(() => {
    checkApprovalExpiry();
    if (_currentPage === 'responses') renderCurrentPage();
  }, 30000);

  // Handle reduced motion preference
  const motionMQ = window.matchMedia('(prefers-reduced-motion: reduce)');
  document.documentElement.classList.toggle('reduced-motion', motionMQ.matches);
  motionMQ.addEventListener('change', e => document.documentElement.classList.toggle('reduced-motion', e.matches));
}

/* ── Theme ─────────────────────────────────────────────────────────── */
function applyTheme(theme, density) {
  document.documentElement.setAttribute('data-theme', theme || 'dark');
  document.documentElement.setAttribute('data-density', density || 'comfortable');
}

/* ── Navigation ─────────────────────────────────────────────────────── */
function buildNav() {
  const nav = document.getElementById('nav');
  if (!nav) return;
  nav.innerHTML = NAV_ITEMS.map(({ id, label, icon }) => `
    <a href="#${id}" id="nav-${id}" class="nav-link ${id === _currentPage ? 'active' : ''}" ${id === _currentPage ? 'aria-current="page"' : ''}>
      <span class="nav-icon" aria-hidden="true">${ICONS[icon] || ''}</span>
      <span class="nav-label">${esc(label)}</span>
    </a>`).join('');
}

function updateNavActive(page) {
  document.querySelectorAll('.nav-link').forEach(a => {
    const isActive = a.id === `nav-${page}`;
    a.classList.toggle('active', isActive);
    if (isActive) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  });
}

function getPageFromHash() {
  const hash = location.hash.slice(1).split('?')[0];
  if (!hash || hash === '/' || hash === 'hero') return 'hero';
  return PAGE_TITLES[hash] ? hash : 'overview';
}

async function navigateTo(page) {
  if (document.getElementById('detail')?.open) closeDialog();

  _currentPage = page;
  updateNavActive(page);

  if (page === 'hero') {
    document.body.classList.add('hero-active');
  } else {
    document.body.classList.remove('hero-active');
  }

  // Update breadcrumb and title
  const [title, subtitle] = PAGE_TITLES[page] || ['Overview', ''];
  const titleEl = document.getElementById('page-title');
  const subtitleEl = document.getElementById('page-subtitle');
  const breadcrumbEl = document.getElementById('breadcrumb');
  if (titleEl) titleEl.textContent = title;
  if (subtitleEl) subtitleEl.textContent = subtitle;
  if (breadcrumbEl) breadcrumbEl.textContent = NAV_ITEMS.find(n => n.id === page)?.label || title;

  await renderCurrentPage();

  // Scroll to top on navigation
  const main = document.querySelector('main');
  if (main) main.scrollTop = 0;

  // Screen reader announcement
  const liveEl = document.getElementById('a11y-live');
  if (liveEl) liveEl.textContent = `Navigated to ${title}`;
}

async function renderCurrentPage() {
  const content = document.getElementById('content');
  if (!content) return;

  const loader = PAGE_RENDERERS[_currentPage];
  if (!loader) { content.innerHTML = `<div class="empty-state"><p>Page not found.</p></div>`; return; }

  try {
    const module = await loader();

    // Parse URL params for filter pre-selection
    const hashParams = location.hash.includes('?')
      ? Object.fromEntries(new URLSearchParams(location.hash.split('?')[1]))
      : {};

    switch (_currentPage) {
      case 'hero': await module.renderHero(content); break;
      case 'overview': await module.renderOverview(content); break;
      case 'ai': await module.renderAI(content); break;
      case 'events': await module.renderEvents(content); break;
      case 'detection': module.renderDetection(content); break;
      case 'incidents':
        if (hashParams.priority || hashParams.status) module.setFilter?.(hashParams);
        module.renderIncidents(content);
        break;
      case 'chain': module.renderChain(content); break;
      case 'risk': module.renderRisk(content); break;
      case 'responses': module.renderResponses(content); break;
      case 'reports': module.renderReports(content); break;
      case 'settings':
        module.renderSettings(content, (theme, density) => applyTheme(theme, density));
        break;
      case 'demo': module.renderDemo(content); break;
    }
  } catch (e) {
    console.error(`Error rendering page ${_currentPage}:`, e);
    content.innerHTML = `<div class="panel"><div class="empty-state">
      <p class="text-red">Error loading page.</p>
      <details><summary>Technical details</summary><pre>${esc(e.stack || e.message)}</pre></details>
    </div></div>`;
  }
}

/* ── Header ─────────────────────────────────────────────────────────── */
function buildHeader() {
  const header = document.getElementById('main-header');
  if (!header) return;
  // Quick "Run scenario" button
  const runBtn = document.getElementById('run-demo-btn');
  if (runBtn) {
    runBtn.addEventListener('click', () => {
      if (isRunning()) { location.hash = '#demo'; return; }
      const meta = getMeta();
      if (!meta.simState.scenario) meta.simState.scenario = 'S1';
      saveMeta();
      location.hash = '#demo';
      import('./src/modules/simulator.js').then(({ startScenario, getMeta: gm }) => {
        startScenario(getMeta().simState.scenario);
      });
    });
  }
}

/* ── Global handlers ─────────────────────────────────────────────────── */
function attachGlobalHandlers() {
  // Hash navigation
  window.addEventListener('hashchange', async () => {
    await navigateTo(getPageFromHash());
  });

  // Dialog keyboard handling
  const dialog = document.getElementById('detail');
  if (dialog) {
    dialog.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') closeDialog();
    });
    document.getElementById('close-dialog')?.addEventListener('click', closeDialog);
  }

  // Mobile menu toggle
  const menuBtn = document.getElementById('mobile-menu-btn');
  const sidebar = document.getElementById('sidebar');
  if (menuBtn && sidebar) {
    menuBtn.addEventListener('click', () => {
      const open = sidebar.classList.toggle('sidebar-open');
      menuBtn.setAttribute('aria-expanded', String(open));
      menuBtn.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
    });
    // Close on nav link click on mobile
    sidebar.querySelectorAll('.nav-link').forEach(a => {
      a.addEventListener('click', () => {
        if (window.innerWidth < 768) {
          sidebar.classList.remove('sidebar-open');
          menuBtn.setAttribute('aria-expanded', 'false');
        }
      });
    });
  }

  // Info panel button
  document.getElementById('info-btn')?.addEventListener('click', () => {
    import('./src/modules/ui.js').then(({ openDialog }) => {
      openDialog('Local simulation — scope and limitations', `
        <h3>What this is</h3>
        <p>Velocities SI is a browser-local defensive lab demonstration. All events are synthetic. No real systems are monitored or changed.</p>
        <h3>What is not included</h3>
        <ul>
          <li>Real monitoring or authentication</li>
          <li>Enforced RBAC or four-eyes authorization</li>
          <li>Immutable audit records</li>
          <li>Trained ML models (no accuracy or calibration claims)</li>
          <li>External infrastructure execution</li>
          <li>Shared or externally ingested data</li>
        </ul>
        <h3>Storage</h3>
        <p>Events use IndexedDB. Preferences and metadata use localStorage. Private browsing or storage restrictions may prevent persistence. Different browsers and devices have separate workspaces.</p>
        <h3>Persona separation</h3>
        <p>The "Demo persona" selector illustrates four-eyes review workflow. It is not a security boundary and does not enforce user identity.</p>
        <p class="small muted">Team Velocities · ABCS-03 · Version 2.0</p>
      `);
    });
  });
}

// Start the application
init().catch(e => {
  console.error('Application init failed:', e);
  document.body.innerHTML = `<div style="padding:40px;font-family:system-ui;color:#e8eef6;background:#0b111b;min-height:100vh">
    <h1>Velocities SI — Startup error</h1>
    <p>The application could not initialize. This may be due to browser restrictions on ES modules (file: protocol) or missing storage permissions.</p>
    <p><strong>Try:</strong> Serve this directory with a local web server (e.g., <code>python -m http.server 8080</code>)</p>
    <details><summary>Error details</summary><pre style="color:#abc5c8">${esc(e.stack || e.message)}</pre></details>
  </div>`;
});
