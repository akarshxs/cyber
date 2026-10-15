/**
 * pages/chain.js — Attack chain with SVG relationship graph, zoom/pan,
 * selection, detail panel, MITRE hypotheses labeled as hypotheses.
 */
'use strict';

import { getMeta } from '../modules/store.js';
import { idbGetById } from '../modules/store.js';
import { esc, icon, showToast } from '../modules/ui.js';
import { RULE_CATALOG } from '../modules/detection.js';

let _selectedIncident = null;
let _selectedNode = null;
let _viewMode = 'graph'; // 'graph' | 'list'
let _zoom = 1;
let _panX = 0;
let _panY = 0;
let _isPanning = false;
let _lastPan = null;

export function renderChain(container) {
  const meta = getMeta();

  if (!meta.incidents.length) {
    container.innerHTML = `
      <section class="panel">
        <div class="panel-head"><h2>Attack chain explorer</h2></div>
        <div class="empty-state">
          ${icon('chain')}
          <p>No incidents available. Run a scenario to generate attack chain data.</p>
        </div>
      </section>`;
    return;
  }

  if (!_selectedIncident) _selectedIncident = meta.incidents[0]?.id;
  const inc = meta.incidents.find(i => i.id === _selectedIncident) || meta.incidents[0];
  if (!inc) return;

  container.innerHTML = `
    <div class="chain-layout">
      <section class="panel chain-panel" aria-labelledby="chain-heading">
        <div class="panel-head">
          <h2 id="chain-heading">Attack chain explorer</h2>
          <div class="panel-actions">
            <select id="chain-incident-sel" class="select-sm" aria-label="Select incident">
              ${meta.incidents.map(i => `<option value="${esc(i.id)}" ${i.id === _selectedIncident ? 'selected' : ''}>${esc(i.id)}: ${esc(i.title.slice(0,40))}</option>`).join('')}
            </select>
            <button class="btn-secondary btn-sm" id="chain-view-graph" aria-pressed="${_viewMode === 'graph'}">Graph</button>
            <button class="btn-secondary btn-sm" id="chain-view-list" aria-pressed="${_viewMode === 'list'}">List</button>
          </div>
        </div>

        <div class="chain-info">
          <div class="chain-path">
            <span class="chain-node-label ip">${esc(inc.ip)}</span>
            <span class="chain-arrow">→</span>
            <span class="chain-node-label user">${esc(inc.user)}</span>
            <span class="chain-arrow">→</span>
            <span class="chain-node-label host">${esc(inc.host)}</span>
          </div>
          <span class="tag">MITRE mappings are hypotheses only — not confirmed attribution</span>
        </div>

        ${_viewMode === 'graph' ? renderGraph(inc) : renderListView(inc)}

        <div class="graph-controls" role="toolbar" aria-label="Graph controls">
          <button class="btn-ghost btn-sm" id="zoom-in" aria-label="Zoom in">+</button>
          <button class="btn-ghost btn-sm" id="zoom-out" aria-label="Zoom out">−</button>
          <button class="btn-ghost btn-sm" id="zoom-reset" aria-label="Reset view">Reset</button>
          <span class="muted small">Drag to pan · Scroll to zoom · Click node to inspect</span>
        </div>
      </section>

      <aside class="chain-detail-panel" id="chain-detail" aria-labelledby="chain-detail-heading" aria-live="polite">
        <h3 id="chain-detail-heading">Select a node to inspect</h3>
        <div id="chain-detail-body">
          <p class="muted">Click any node in the graph to view its details and linked evidence.</p>
        </div>
      </aside>
    </div>
  `;

  bindChainHandlers(container, inc);
}

function renderGraph(inc) {
  // Layout: IP → User → Host, with event nodes
  const W = 700;
  const H = 380;
  const nodes = buildGraphNodes(inc);
  const edges = buildGraphEdges(nodes, inc);

  const nodesSvg = nodes.map(n => renderGraphNode(n)).join('');
  const edgesSvg = edges.map(e => renderGraphEdge(e, nodes)).join('');
  const mitreLabels = inc.mitreHypotheses.slice(0,4).map((m, idx) => {
    const x = 60 + idx * 160;
    return `<text x="${x}" y="${H - 10}" font-size="9" fill="var(--muted)" text-anchor="middle">${esc(m.technique)}: ${esc(m.name.slice(0,18))}</text>`;
  }).join('');

  return `
    <div class="graph-container" id="graph-container" role="img" aria-label="Attack chain graph showing ${nodes.length} nodes">
      <svg id="chain-svg" viewBox="0 0 ${W} ${H}" class="chain-svg" tabindex="0" aria-label="Attack chain relationship graph">
        <defs>
          <marker id="arrowhead" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
            <polygon points="0 0, 8 3, 0 6" fill="var(--border-strong)"/>
          </marker>
        </defs>
        <g id="graph-g" transform="translate(${_panX}, ${_panY}) scale(${_zoom})">
          ${edgesSvg}
          ${nodesSvg}
        </g>
        <text x="10" y="${H - 10}" font-size="9" fill="var(--muted)">Hypotheses:</text>
        ${mitreLabels}
      </svg>
    </div>`;
}

function buildGraphNodes(inc) {
  const nodes = [];
  // Main entities
  nodes.push({ id: 'ip', type: 'ip', label: inc.ip, x: 80, y: 190, color: 'var(--amber)' });
  nodes.push({ id: 'user', type: 'account', label: inc.user, x: 280, y: 190, color: 'var(--teal)' });
  nodes.push({ id: 'host', type: 'host', label: inc.host, x: 480, y: 190, color: 'var(--blue-light)' });

  // Detection nodes
  inc.mitreHypotheses.forEach((m, idx) => {
    const yOffset = idx % 2 === 0 ? 80 : 300;
    const xOffset = 150 + idx * 120;
    nodes.push({ id: `mitre-${idx}`, type: 'detection', label: m.technique, sublabel: m.name.slice(0,16), x: Math.min(xOffset, 620), y: yOffset, color: 'var(--red-dim)', ruleId: m.ruleId });
  });

  return nodes;
}

function buildGraphEdges(nodes, inc) {
  const edges = [];
  edges.push({ from: 'ip', to: 'user', label: `${inc.eventIds.length} events` });
  edges.push({ from: 'user', to: 'host', label: 'lateral' });
  inc.mitreHypotheses.forEach((m, idx) => {
    edges.push({ from: 'ip', to: `mitre-${idx}`, dashed: true, label: '' });
  });
  return edges;
}

function renderGraphNode(n) {
  const isSelected = _selectedNode === n.id;
  const rx = n.type === 'ip' ? 6 : n.type === 'host' ? 6 : n.type === 'detection' ? 4 : 50;
  const nodeW = n.type === 'detection' ? 80 : 90;
  const nodeH = n.type === 'detection' ? 44 : 44;
  const border = isSelected ? 'var(--teal)' : n.color;
  const icon = { ip: '⊕', account: '⊙', host: '▦', detection: '⚑' }[n.type] || '•';

  return `<g class="graph-node ${isSelected ? 'selected' : ''}" data-node-id="${esc(n.id)}" data-node-type="${esc(n.type)}" tabindex="0" role="button" aria-label="Node: ${esc(n.label)}">
    <rect x="${n.x - nodeW/2}" y="${n.y - nodeH/2}" width="${nodeW}" height="${nodeH}" rx="${rx}" fill="var(--surface-2)" stroke="${border}" stroke-width="${isSelected ? 2 : 1}" class="node-rect"/>
    <text x="${n.x}" y="${n.y - 8}" text-anchor="middle" font-size="11" fill="var(--text)" font-weight="500">${esc(n.label.slice(0,12))}</text>
    ${n.sublabel ? `<text x="${n.x}" y="${n.y + 8}" text-anchor="middle" font-size="9" fill="var(--muted)">${esc(n.sublabel)}</text>` : `<text x="${n.x}" y="${n.y + 8}" text-anchor="middle" font-size="9" fill="${n.color}">${esc(n.type.toUpperCase())}</text>`}
  </g>`;
}

function renderGraphEdge(e, nodes) {
  const from = nodes.find(n => n.id === e.from);
  const to = nodes.find(n => n.id === e.to);
  if (!from || !to) return '';
  const dx = to.x - from.x;
  const dy = to.y - from.y;
  const dist = Math.sqrt(dx*dx + dy*dy);
  const nx = dx/dist * 48; const ny = dy/dist * 48;
  const x1 = from.x + nx; const y1 = from.y + ny;
  const x2 = to.x - nx; const y2 = to.y - ny;
  const cx = (x1+x2)/2; const cy = (y1+y2)/2 - 20;
  const dash = e.dashed ? 'stroke-dasharray="4 4"' : '';

  return `<g>
    <path d="M${x1} ${y1} Q${cx} ${cy} ${x2} ${y2}" stroke="var(--border-strong)" stroke-width="1.5" fill="none" ${dash} marker-end="url(#arrowhead)"/>
    ${e.label ? `<text x="${cx}" y="${cy - 5}" text-anchor="middle" font-size="9" fill="var(--muted)">${esc(e.label)}</text>` : ''}
  </g>`;
}

function renderListView(inc) {
  const rule = RULE_CATALOG;
  const stages = inc.mitreHypotheses;
  if (!stages.length) return '<p class="muted">No MITRE hypotheses available.</p>';

  return `<div class="chain-list" role="list" aria-label="Attack chain timeline">
    ${stages.map((m, idx) => `
      <div class="chain-list-item" role="listitem" data-mitre-idx="${idx}">
        <div class="chain-list-marker" style="border-color:${idx === 0 ? 'var(--red)' : idx === stages.length-1 ? 'var(--amber)' : 'var(--teal)'}"></div>
        <div class="chain-list-body">
          <div class="chain-list-header">
            <span class="tag">${esc(m.technique)} — hypothesis</span>
            <span class="muted small">${esc(m.ruleId)}</span>
          </div>
          <h3>${esc(m.name)}</h3>
          <p class="muted">${esc(m.stage)}</p>
          <p class="small">MITRE ATT&amp;CK: <strong>${esc(m.technique)}</strong> — <em>This mapping is a hypothesis based on triggering rule ${esc(m.ruleId)}, not confirmed attribution.</em></p>
        </div>
      </div>`).join('')}
  </div>`;
}

function bindChainHandlers(container, inc) {
  // Incident selector
  container.querySelector('#chain-incident-sel')?.addEventListener('change', e => {
    _selectedIncident = e.target.value;
    _selectedNode = null;
    renderChain(container);
  });

  // View mode
  container.querySelector('#chain-view-graph')?.addEventListener('click', () => {
    _viewMode = 'graph'; renderChain(container);
  });
  container.querySelector('#chain-view-list')?.addEventListener('click', () => {
    _viewMode = 'list'; renderChain(container);
  });

  // Graph controls
  const svg = container.querySelector('#chain-svg');
  if (svg) {
    container.querySelector('#zoom-in')?.addEventListener('click', () => { _zoom = Math.min(3, _zoom * 1.25); updateTransform(svg); });
    container.querySelector('#zoom-out')?.addEventListener('click', () => { _zoom = Math.max(0.3, _zoom / 1.25); updateTransform(svg); });
    container.querySelector('#zoom-reset')?.addEventListener('click', () => { _zoom = 1; _panX = 0; _panY = 0; updateTransform(svg); });

    svg.addEventListener('wheel', (e) => {
      e.preventDefault();
      const delta = e.deltaY > 0 ? 0.9 : 1.1;
      _zoom = Math.max(0.3, Math.min(3, _zoom * delta));
      updateTransform(svg);
    }, { passive: false });

    // Pan
    svg.addEventListener('mousedown', (e) => {
      if (e.target.closest('.graph-node')) return;
      _isPanning = true;
      _lastPan = { x: e.clientX, y: e.clientY };
    });
    window.addEventListener('mousemove', (e) => {
      if (!_isPanning || !_lastPan) return;
      _panX += e.clientX - _lastPan.x;
      _panY += e.clientY - _lastPan.y;
      _lastPan = { x: e.clientX, y: e.clientY };
      updateTransform(svg);
    });
    window.addEventListener('mouseup', () => { _isPanning = false; _lastPan = null; });

    // Node selection
    container.querySelectorAll('.graph-node').forEach(node => {
      const handler = () => {
        _selectedNode = node.dataset.nodeId;
        renderNodeDetail(container, inc, node.dataset.nodeId, node.dataset.nodeType);
        // Update visual
        container.querySelectorAll('.graph-node').forEach(n => n.classList.toggle('selected', n.dataset.nodeId === _selectedNode));
      };
      node.addEventListener('click', handler);
      node.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); handler(); } });
    });
  }
}

function updateTransform(svg) {
  const g = svg.querySelector('#graph-g');
  if (g) g.setAttribute('transform', `translate(${_panX}, ${_panY}) scale(${_zoom})`);
}

function renderNodeDetail(container, inc, nodeId, nodeType) {
  const detailBody = container.querySelector('#chain-detail-body');
  if (!detailBody) return;

  if (nodeType === 'ip') {
    detailBody.innerHTML = `
      <div class="detail-kv">
        <span>Entity type</span><span>Source IP</span>
        <span>Address</span><span class="mono">${esc(inc.ip)}</span>
        <span>Events</span><span>${inc.eventIds.length} linked</span>
        <span>Incidents</span><span>${inc.id}</span>
      </div>
      <p class="small muted">This IP address is the observed source of activity. Attribution requires external verification beyond this simulation.</p>`;
  } else if (nodeType === 'account') {
    detailBody.innerHTML = `
      <div class="detail-kv">
        <span>Entity type</span><span>Account</span>
        <span>Username</span><span>${esc(inc.user)}</span>
        <span>Incident</span><span>${esc(inc.id)}</span>
      </div>`;
  } else if (nodeType === 'host') {
    detailBody.innerHTML = `
      <div class="detail-kv">
        <span>Entity type</span><span>Host</span>
        <span>Hostname</span><span>${esc(inc.host)}</span>
        <span>Risk score</span><span>${inc.risk}/100</span>
      </div>`;
  } else if (nodeType === 'detection') {
    const idx = parseInt(nodeId.replace('mitre-',''));
    const m = inc.mitreHypotheses[idx];
    if (m) {
      detailBody.innerHTML = `
        <div class="detail-kv">
          <span>MITRE technique</span><span>${esc(m.technique)}</span>
          <span>Name</span><span>${esc(m.name)}</span>
          <span>Stage</span><span>${esc(m.stage)}</span>
          <span>Triggering rule</span><span>${esc(m.ruleId)}</span>
        </div>
        <p class="small warn-text">This MITRE mapping is a <strong>hypothesis</strong> generated by detection rule ${esc(m.ruleId)}. It has not been confirmed by external intelligence or forensic investigation.</p>`;
    }
  }
}
