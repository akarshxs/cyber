/**
 * pages/overview.js — Security Operations Overview with hero intro section,
 * live metrics, activity chart, severity breakdown, and priority queue.
 * Uses only defined CSS variables and design tokens.
 */
'use strict';

import { getMeta, getPrefs } from '../modules/store.js';
import { idbGetAll, idbCount } from '../modules/store.js';
import { esc, severityBadge, statusBadge, formatTs, relativeTime, icon } from '../modules/ui.js';
import { scoreToBand } from '../modules/risk.js';

const ACTIVE_STATUSES = new Set(['New', 'Investigating', 'Contained']);
let _timeRange = '60'; // minutes

export async function renderOverview(container) {
  const meta = getMeta();
  const events = await idbGetAll('events', { limit: 2000 });
  const totalEvents = await idbCount('events');

  const now = Date.now();
  const rangeMs = parseInt(_timeRange) * 60 * 1000;
  const rangeEvents = events.filter(e => now - new Date(e.ts) <= rangeMs);

  const allIncidents = meta.incidents || [];
  const activeIncidents = allIncidents.filter(i => ACTIVE_STATUSES.has(i.status));
  const criticalActive = activeIncidents.filter(i => (i.priority || i.severity) === 'critical');
  const pendingApprovals = (meta.approvalRequests || []).filter(r => r.status === 'pending');
  const scenario = meta.simState?.scenario;

  // Activity chart — 12 buckets
  const bucketCount = 12;
  const bucketMs = rangeMs / bucketCount;
  const bins = Array.from({ length: bucketCount }, (_, n) => {
    const start = now - rangeMs + n * bucketMs;
    const end = start + bucketMs;
    return rangeEvents.filter(e => {
      const t = new Date(e.ts).getTime();
      return t >= start && t < end;
    }).length;
  });
  const maxBin = Math.max(...bins, 1);

  // Severity counts
  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const i of activeIncidents) {
    const b = i.priority || i.severity || scoreToBand(i.risk || 0).band;
    if (sevCounts[b] !== undefined) sevCounts[b]++;
  }
  const sevTotal = Object.values(sevCounts).reduce((a, b) => a + b, 0);

  // Recent decisions
  const decisions = (meta.auditLog || [])
    .filter(a => ['approved', 'rejected', 'Resolved', 'Investigating', 'Contained', 'False positive'].some(k => a.action?.includes(k)))
    .slice(-5)
    .reverse();

  // --- SVG Activity Chart (Pixel-perfect with correct vars) ---
  const chartW = 560;
  const chartH = 160;
  const padL = 42;
  const padB = 26;
  const innerW = chartW - padL - 10;
  const innerH = chartH - padB - 10;
  const barW = Math.max(2, Math.floor(innerW / bucketCount) - 4);

  const yTicks = [0, 0.25, 0.5, 0.75, 1].map(f => ({ frac: f, val: Math.round(f * maxBin) }));
  const yLines = yTicks.map(({ frac, val }) => {
    const y = (10 + (1 - frac) * innerH).toFixed(1);
    return `<line x1="${padL}" y1="${y}" x2="${chartW - 10}" y2="${y}" stroke="rgba(255,255,255,0.08)" stroke-dasharray="3 4" stroke-width="0.7"/>
            <text x="${padL - 5}" y="${(parseFloat(y) + 4).toFixed(1)}" text-anchor="end" fill="rgba(255,255,255,0.38)" font-size="9" font-family="monospace">${val}</text>`;
  });

  const sevColorMap = { critical: '#ff6584', high: '#ffa756', medium: '#eedc66', low: '#6de2c7' };

  const bars = bins.map((v, n) => {
    const x = (padL + n * (innerW / bucketCount) + 2).toFixed(1);
    const h = v === 0 ? 2 : Math.max(4, (v / maxBin) * innerH);
    const y = (10 + innerH - h).toFixed(1);
    const col = v > 0 ? '#ffffff' : 'rgba(255,255,255,0.18)';
    return `<rect x="${x}" y="${y}" width="${barW}" height="${h.toFixed(1)}" rx="1" fill="${col}">
      <title>${v} event${v !== 1 ? 's' : ''} in bucket ${n + 1}</title>
    </rect>`;
  });

  const xLabels = [
    '−' + _timeRange + 'm',
    '−' + Math.round(parseInt(_timeRange) * 0.75) + 'm',
    '−' + Math.round(parseInt(_timeRange) * 0.5) + 'm',
    '−' + Math.round(parseInt(_timeRange) * 0.25) + 'm',
    'NOW'
  ];
  const xLabelEls = xLabels.map((label, i) => {
    const x = (padL + (i / (xLabels.length - 1)) * innerW).toFixed(1);
    return `<text x="${x}" y="${chartH - 4}" text-anchor="middle" fill="rgba(255,255,255,0.38)" font-size="9" font-family="monospace">${esc(label)}</text>`;
  });

  const svgChart = `<svg viewBox="0 0 ${chartW} ${chartH}" class="activity-chart" role="img" aria-label="Event activity: ${bins.join(', ')} per bucket" style="width:100%;height:auto;display:block;">
    ${yLines.join('')}
    ${bars.join('')}
    <line x1="${padL}" y1="10" x2="${padL}" y2="${10 + innerH}" stroke="rgba(255,255,255,0.22)" stroke-width="1"/>
    <line x1="${padL}" y1="${10 + innerH}" x2="${chartW - 10}" y2="${10 + innerH}" stroke="rgba(255,255,255,0.22)" stroke-width="1"/>
    ${xLabelEls.join('')}
  </svg>`;

  // --- Donut chart ---
  const donutSegs = buildDonutSegments(sevCounts, sevTotal, sevColorMap);

  // --- Severity rows ---
  const sevLabels = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
  const sevRows = ['critical', 'high', 'medium', 'low'].map(b => `
    <div class="sev-row">
      <span class="sev-dot-hud" style="background:${sevColorMap[b]}; box-shadow: 0 0 6px ${sevColorMap[b]}"></span>
      <span class="sev-label-txt font-mono">${sevLabels[b]}</span>
      <span class="sev-count-num font-mono"><strong style="color:${sevColorMap[b]}">${sevCounts[b]}</strong></span>
      <a href="#incidents?status=active&priority=${b}" class="sev-link font-mono" aria-label="View ${sevLabels[b]} incidents">↗</a>
    </div>`).join('');

  // --- Priority queue ---
  const topIncidents = [...activeIncidents].sort((a, b) => (b.risk || 0) - (a.risk || 0)).slice(0, 5);
  const priorityRows = topIncidents.length
    ? topIncidents.map(i => `
      <tr>
        <td><button class="text-link font-mono" data-incident="${esc(i.id)}">${esc(i.id)}</button></td>
        <td>
          <span class="font-mono" style="color:#fff;font-weight:600">${esc(i.title)}</span>
          <small class="font-mono" style="display:block;color:rgba(255,255,255,0.45);font-size:10px">${esc(i.host || '')} · ${esc(i.user || '')}</small>
        </td>
        <td>${severityBadge(i.priority || i.severity)}</td>
        <td><span class="risk-score-hud font-mono">${i.risk || 0}</span><span style="color:rgba(255,255,255,0.38);font-size:10px">/100</span></td>
        <td>${statusBadge(i.status)}</td>
        <td><a href="#incidents" class="text-link font-mono" aria-label="Open incident ${esc(i.id)}">Open ↗</a></td>
      </tr>`).join('')
    : `<tr><td colspan="6" class="empty-cell font-mono">No active incidents. Run a scenario to generate data.</td></tr>`;

  const recentDecisions = decisions.length
    ? decisions.map(d => `
      <div class="decision-row">
        <span class="decision-time font-mono">${relativeTime(d.ts)}</span>
        <span class="decision-action font-mono">${esc(d.action)}</span>
        <span class="decision-entity font-mono" style="color:rgba(255,255,255,0.45)">${esc(d.entity || '')}</span>
      </div>`).join('')
    : '<div class="empty-cell font-mono" style="padding:16px;color:rgba(255,255,255,0.38)">No recent analyst decisions.</div>';

  // --- Render full page ---
  container.innerHTML = `
    <!-- ══ HERO SECTION — Sisyphus Protocol Intro ══ -->
    <section class="overview-hero-section" aria-label="Defense posture overview">
      <!-- Animated background canvas via UnicornStudio -->
      <div class="overview-hero-canvas" aria-hidden="true">
        <div data-us-project="OMzqyUv6M3kSnv0JeAtC" style="width:100%;height:100%;min-height:100%"></div>
      </div>

      <!-- Corner accents inside hero -->
      <div class="hero-corner hero-corner-tl" aria-hidden="true"></div>
      <div class="hero-corner hero-corner-tr" aria-hidden="true"></div>
      <div class="hero-corner hero-corner-bl" aria-hidden="true"></div>
      <div class="hero-corner hero-corner-br" aria-hidden="true"></div>

      <!-- Hero Content -->
      <div class="overview-hero-content">
        <!-- Top decorative line -->
        <div class="hero-deco-line">
          <div class="hero-line-segment"></div>
          <span class="hero-infinity font-mono">∞</span>
          <div class="hero-line-full"></div>
        </div>

        <!-- Eyebrow tag -->
        <div class="hero-eyebrow font-mono">
          ABCS-03 // ADAPTIVE CYBER DEFENSE PROTOCOL — SISYPHUS.ACTIVE
        </div>

        <!-- Main headline -->
        <h1 class="hero-headline font-mono">ENDLESS<br><span style="color:#ffffff">PURSUIT</span></h1>

        <!-- Subtext -->
        <p class="hero-subtext font-mono">
          Real-time cyber defense intelligence. Every alert triaged, every signal correlated, every decision logged.
          <br>Human-supervised. Evidence-led. Relentlessly adaptive.
        </p>

        <!-- Live stats HUD strip -->
        <div class="hero-live-strip font-mono">
          <div class="hero-stat-pill ${criticalActive.length > 0 ? 'pill-danger' : ''}">
            <span class="pill-val" style="color:${criticalActive.length > 0 ? '#ff6584' : '#ffffff'}">${criticalActive.length}</span>
            <span class="pill-label">CRITICAL</span>
          </div>
          <div class="hero-stat-divider"></div>
          <div class="hero-stat-pill ${activeIncidents.length > 0 ? 'pill-warn' : ''}">
            <span class="pill-val" style="color:#ffa756">${activeIncidents.length}</span>
            <span class="pill-label">ACTIVE INC.</span>
          </div>
          <div class="hero-stat-divider"></div>
          <div class="hero-stat-pill">
            <span class="pill-val" style="color:#ffffff">${rangeEvents.length}</span>
            <span class="pill-label">EVENTS / ${_timeRange}M</span>
          </div>
          <div class="hero-stat-divider"></div>
          <div class="hero-stat-pill">
            <span class="pill-val" style="color:rgba(255,255,255,0.7)">${pendingApprovals.length}</span>
            <span class="pill-label">PENDING</span>
          </div>
          ${scenario ? `<div class="hero-stat-divider"></div>
          <div class="hero-stat-pill">
            <span class="pulse-dot" aria-hidden="true"></span>
            <span class="pill-val" style="color:#ffffff">${esc(scenario)}</span>
            <span class="pill-label">SCENARIO</span>
          </div>` : ''}
        </div>

        <!-- CTA Buttons -->
        <div class="hero-cta-strip font-mono">
          <a href="#ai" class="hero-btn hero-btn-primary">⚡ AI CYBER COPILOT</a>
          <a href="#incidents" class="hero-btn hero-btn-secondary">INCIDENT CENTER ↗</a>
          <a href="#demo" class="hero-btn hero-btn-secondary">▷ RUN SCENARIO</a>
        </div>

        <!-- Bottom protocol notation -->
        <div class="hero-deco-bottom font-mono">
          <span>∞</span>
          <div class="hero-line-full"></div>
          <span>SISYPHUS.PROTOCOL // V2.0 // ABCS-03</span>
        </div>
      </div>
    </section>

    <!-- ══ TIME RANGE CONTROL ══ -->
    <div class="toolbar overview-toolbar font-mono" style="margin-top:24px">
      <label for="time-range-select" style="color:rgba(255,255,255,0.55);font-size:11px">TIME WINDOW</label>
      <select id="time-range-select" class="select-sm font-mono" aria-label="Select time range">
        <option value="15" ${_timeRange === '15' ? 'selected' : ''}>LAST 15 MIN</option>
        <option value="30" ${_timeRange === '30' ? 'selected' : ''}>LAST 30 MIN</option>
        <option value="60" ${_timeRange === '60' ? 'selected' : ''}>LAST 60 MIN</option>
        <option value="240" ${_timeRange === '240' ? 'selected' : ''}>LAST 4 HOURS</option>
        <option value="1440" ${_timeRange === '1440' ? 'selected' : ''}>LAST 24 HOURS</option>
      </select>
      <span class="font-mono" style="color:rgba(255,255,255,0.38);font-size:10px">
        WINDOW: ${new Date(Date.now() - rangeMs).toLocaleTimeString()} → NOW
      </span>
      <span class="font-mono" style="color:rgba(255,255,255,0.38);font-size:10px;margin-left:auto">
        ${totalEvents.toLocaleString()} TOTAL EVENTS STORED
      </span>
    </div>

    <!-- ══ KPI CARDS ══ -->
    <section class="stats" aria-label="Key metrics" style="margin-bottom:24px">
      <article class="stat stat-hud" role="button" tabindex="0" data-metric-link="#events" aria-label="${rangeEvents.length} events">
        <div class="stat-top font-mono">
          <span>EVENTS / PERIOD</span>${icon('events')}
        </div>
        <strong class="stat-value-hud font-mono">${rangeEvents.length}</strong>
        <small class="font-mono">${esc(_timeRange)}-MIN WINDOW · ${totalEvents.toLocaleString()} TOTAL</small>
      </article>

      <article class="stat stat-hud" role="button" tabindex="0" data-metric-link="#incidents" aria-label="${activeIncidents.length} active incidents">
        <div class="stat-top font-mono">
          <span>ACTIVE INCIDENTS</span>${icon('incidents')}
        </div>
        <strong class="stat-value-hud font-mono" style="color:${activeIncidents.length > 0 ? '#ffa756' : '#55ddba'}">${activeIncidents.length}</strong>
        <small class="font-mono">EXCLUDES RESOLVED / FP</small>
      </article>

      <article class="stat stat-hud ${criticalActive.length > 0 ? 'stat-hud-danger' : ''}" role="button" tabindex="0" data-metric-link="#incidents?priority=critical" aria-label="${criticalActive.length} critical">
        <div class="stat-top font-mono">
          <span>CRITICAL PRIORITY</span>${icon('warn')}
        </div>
        <strong class="stat-value-hud font-mono" style="color:${criticalActive.length > 0 ? '#ff6584' : '#55ddba'}">${criticalActive.length}</strong>
        <small class="font-mono">REQUIRES ANALYST REVIEW</small>
      </article>

      <article class="stat stat-hud ${pendingApprovals.length > 0 ? 'stat-hud-warn' : ''}" role="button" tabindex="0" data-metric-link="#responses" aria-label="${pendingApprovals.length} pending approvals">
        <div class="stat-top font-mono">
          <span>PENDING APPROVALS</span>${icon('responses')}
        </div>
        <strong class="stat-value-hud font-mono" style="color:${pendingApprovals.length > 0 ? '#eedc66' : '#55ddba'}">${pendingApprovals.length}</strong>
        <small class="font-mono">RESPONSE CENTER</small>
      </article>
    </section>

    <!-- ══ CHART + SEVERITY ══ -->
    <div class="overview-grid-2">
      <!-- Activity Chart -->
      <section class="panel panel-hud" aria-labelledby="chart-heading">
        <div class="panel-head">
          <h2 id="chart-heading" class="font-mono" style="font-size:13px;letter-spacing:0.08em">
            <span style="color:#55ddba">◈</span> EVENT ACTIVITY STREAM
          </h2>
          <span class="font-mono" style="color:rgba(255,255,255,0.38);font-size:10px">
            LAST ${esc(_timeRange)} MIN · ${bucketCount} BUCKETS
          </span>
        </div>
        <div class="chart-wrap" style="padding:4px 0 0">
          ${svgChart}
        </div>
        <div class="chart-legend font-mono" style="padding-top:8px;display:flex;align-items:center;gap:8px">
          <span style="width:10px;height:10px;background:#55ddba;display:inline-block;border-radius:1px"></span>
          <span style="color:rgba(255,255,255,0.45);font-size:10px">SYNTHETIC EVENTS PER BUCKET</span>
        </div>
      </section>

      <!-- Severity Breakdown -->
      <section class="panel panel-hud" aria-labelledby="sev-heading">
        <div class="panel-head">
          <h2 id="sev-heading" class="font-mono" style="font-size:13px;letter-spacing:0.08em">
            <span style="color:#55ddba">◈</span> SEVERITY BREAKDOWN
          </h2>
          <span class="font-mono" style="color:rgba(255,255,255,0.38);font-size:10px">${sevTotal} ACTIVE</span>
        </div>
        <div class="sev-breakdown-hud">
          <div class="sev-donut-wrap" aria-hidden="true">
            <svg viewBox="0 0 100 100" class="donut-svg" style="width:140px;height:140px">
              ${donutSegs}
              <circle cx="50" cy="50" r="28" fill="#000" />
              <text x="50" y="47" text-anchor="middle" font-size="15" font-weight="700" fill="#fff" font-family="monospace">${sevTotal}</text>
              <text x="50" y="58" text-anchor="middle" font-size="7" fill="rgba(255,255,255,0.5)" font-family="monospace">INCIDENTS</text>
            </svg>
          </div>
          <div class="sev-list-hud">${sevRows}</div>
        </div>
      </section>
    </div>

    <!-- ══ PRIORITY QUEUE ══ -->
    <section class="panel panel-hud" aria-labelledby="queue-heading">
      <div class="panel-head">
        <h2 id="queue-heading" class="font-mono" style="font-size:13px;letter-spacing:0.08em">
          <span style="color:#55ddba">◈</span> PRIORITY QUEUE
        </h2>
        <a href="#incidents" class="text-link font-mono" style="font-size:11px">VIEW ALL INCIDENTS ↗</a>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th class="font-mono">ID</th>
              <th class="font-mono">TITLE</th>
              <th class="font-mono">PRIORITY</th>
              <th class="font-mono">RISK</th>
              <th class="font-mono">STATUS</th>
              <th class="font-mono">ACTION</th>
            </tr>
          </thead>
          <tbody>${priorityRows}</tbody>
        </table>
      </div>
    </section>

    <!-- ══ RECENT DECISIONS ══ -->
    <section class="panel panel-hud" aria-labelledby="decisions-heading">
      <div class="panel-head">
        <h2 id="decisions-heading" class="font-mono" style="font-size:13px;letter-spacing:0.08em">
          <span style="color:#55ddba">◈</span> RECENT ANALYST DECISIONS
        </h2>
        <a href="#reports" class="text-link font-mono" style="font-size:11px">FULL AUDIT LOG ↗</a>
      </div>
      <div class="decisions-list-hud">${recentDecisions}</div>
    </section>
  `;

  // Initialize UnicornStudio for the hero canvas
  _initHeroAnimation();

  // Bind time range selector
  const sel = container.querySelector('#time-range-select');
  if (sel) {
    sel.addEventListener('change', e => {
      _timeRange = e.target.value;
      renderOverview(container);
    });
  }

  // Bind metric card clicks
  container.querySelectorAll('[data-metric-link]').forEach(el => {
    el.style.cursor = 'pointer';
    el.addEventListener('click', () => { location.hash = el.dataset.metricLink; });
    el.addEventListener('keydown', e => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); location.hash = el.dataset.metricLink; }
    });
  });
}

function _initHeroAnimation() {
  if (window.UnicornStudio?.isInitialized) {
    try { window.UnicornStudio.init(); } catch (_) {}
    return;
  }
  if (document.querySelector('script[src*="unicornStudio"]')) return;
  const s = document.createElement('script');
  s.src = 'https://cdn.jsdelivr.net/gh/hiunicornstudio/unicornstudio.js@v1.4.33/dist/unicornStudio.umd.js';
  s.onload = () => {
    if (!window.UnicornStudio?.isInitialized) {
      window.UnicornStudio = window.UnicornStudio || {};
      window.UnicornStudio.isInitialized = true;
      try { window.UnicornStudio.init(); } catch (_) {}
    }
  };
  (document.head || document.body).appendChild(s);
}

function buildDonutSegments(sevCounts, total, colors) {
  if (total === 0) {
    return `<circle cx="50" cy="50" r="40" fill="rgba(255,255,255,0.07)" stroke="rgba(255,255,255,0.15)" stroke-width="0.5"/>`;
  }
  const bands = ['critical', 'high', 'medium', 'low'];
  let cumAngle = -Math.PI / 2;
  const segments = [];
  for (const b of bands) {
    const count = sevCounts[b] || 0;
    if (!count) continue;
    const frac = count / total;
    const angle = frac * 2 * Math.PI;
    const x1 = 50 + 40 * Math.cos(cumAngle);
    const y1 = 50 + 40 * Math.sin(cumAngle);
    const x2 = 50 + 40 * Math.cos(cumAngle + angle);
    const y2 = 50 + 40 * Math.sin(cumAngle + angle);
    const largeArc = angle > Math.PI ? 1 : 0;
    segments.push(`<path d="M50 50 L${x1.toFixed(2)} ${y1.toFixed(2)} A40 40 0 ${largeArc} 1 ${x2.toFixed(2)} ${y2.toFixed(2)} Z" fill="${colors[b]}" opacity="0.9"/>`);
    cumAngle += angle;
  }
  return segments.join('');
}
