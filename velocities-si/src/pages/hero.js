/**
 * pages/hero.js — Full-Screen Sisyphus ASCII Hero Landing Page
 * Faithfully matches 21st.dev/@larsen65/components/hero-ascii-one aesthetic:
 * Pure monochrome white, UnicornStudio ASCII Sisyphus animation, technical
 * corner frame brackets, precision alignment, and Velocities SI (ABCS-03) data.
 */
'use strict';

let _brandInterval = null;

export async function renderHero(container) {
  // Clear any existing interval
  if (_brandInterval) {
    clearInterval(_brandInterval);
    _brandInterval = null;
  }

  container.innerHTML = `
    <div class="hero-fullscreen-root">
      <!-- Background UnicornStudio Animation -->
      <div class="hero-us-bg" aria-hidden="true">
        <div data-us-project="OMzqyUv6M3kSnv0JeAtC" style="width:100%;height:100%;min-height:100vh;"></div>
      </div>

      <!-- Viewport Corner Frame Accents -->
      <div class="hero-frame-corner hero-frame-tl" aria-hidden="true"></div>
      <div class="hero-frame-corner hero-frame-tr" aria-hidden="true"></div>
      <div class="hero-frame-corner hero-frame-bl" aria-hidden="true"></div>
      <div class="hero-frame-corner hero-frame-br" aria-hidden="true"></div>

      <!-- Top Header Bar -->
      <header class="hero-top-header font-mono">
        <div class="hero-header-left">
          <span class="hero-brand-logo italic">UIMIX</span>
          <div class="hero-v-divider"></div>
          <span class="hero-brand-title">VELOCITIES <b>SI</b></span>
          <div class="hero-v-divider"></div>
          <span class="hero-est-tag">EST. 2025</span>
        </div>

        <div class="hero-header-right font-mono">
          <span>LAT: 37.7749°</span>
          <span class="hero-header-dot"></span>
          <span>LONG: 122.4194°</span>
          <div class="hero-v-divider"></div>
          <span class="hero-active-badge">SYSTEM.ACTIVE</span>
        </div>
      </header>

      <!-- Main CTA Hero Content (Aligned on Right Half) -->
      <div class="hero-main-layout">
        <div class="hero-cta-card">
          <!-- Top Decorative Line -->
          <div class="hero-line-deco font-mono">
            <div class="hero-line-short"></div>
            <span class="hero-infinity-sym">∞</span>
            <div class="hero-line-long"></div>
          </div>

          <!-- Main Title -->
          <div class="hero-title-wrap">
            <h1 class="hero-title-text font-mono">ENDLESS PURSUIT</h1>
          </div>

          <!-- Technical Dot Matrix Line -->
          <div class="hero-dots-matrix" aria-hidden="true">
            ${Array.from({ length: 42 }).map(() => '<span class="hero-matrix-dot"></span>').join('')}
          </div>

          <!-- Project Description Text -->
          <p class="hero-desc-text font-mono">
            Like Sisyphus, cyber defense never rests. In the ABCS-03 autonomous security environment,
            every alert is triaged, every signal correlated, and every adversary contained.
            Human-supervised. Relentlessly adaptive.
          </p>

          <!-- Technical Corner Accent Marker -->
          <div class="hero-technical-accent font-mono" aria-hidden="true">
            <span class="tech-plus">+</span>
            <span class="tech-label">PROTOCOL.ABCS-03</span>
          </div>

          <!-- Action Buttons -->
          <div class="hero-actions-group font-mono">
            <a href="#overview" class="hero-btn-action hero-btn-enter">
              <span class="btn-corner-t"></span>
              <span class="btn-corner-b"></span>
              <span>ENTER COMMAND CENTER</span>
            </a>

            <a href="#ai" class="hero-btn-action hero-btn-secondary">
              <span>LAUNCH AI COPILOT ↗</span>
            </a>
          </div>

          <!-- Bottom Technical Notation -->
          <div class="hero-bottom-notation font-mono">
            <span class="hero-infinity-sym">∞</span>
            <div class="hero-line-long"></div>
            <span class="hero-notation-txt">SISYPHUS.DEFENSE.PROTOCOL // ABCS-03</span>
          </div>
        </div>
      </div>

      <!-- Bottom Status Footer Bar -->
      <footer class="hero-bottom-footer font-mono">
        <div class="hero-footer-left">
          <span class="hero-footer-item">SYSTEM.ACTIVE</span>
          <div class="hero-wave-bars" aria-hidden="true">
            <span style="height:12px"></span>
            <span style="height:7px"></span>
            <span style="height:14px"></span>
            <span style="height:9px"></span>
            <span style="height:16px"></span>
            <span style="height:11px"></span>
            <span style="height:8px"></span>
            <span style="height:13px"></span>
          </div>
          <span class="hero-footer-item text-dim">V2.0.0 (ABCS-03)</span>
        </div>

        <div class="hero-footer-right">
          <span class="hero-footer-item">◐ NEURAL TRIAGE</span>
          <div class="hero-pulsing-leds" aria-hidden="true">
            <span class="led-dot led-1"></span>
            <span class="led-dot led-2"></span>
            <span class="led-dot led-3"></span>
          </div>
          <span class="hero-footer-item text-dim">FRAME: ∞</span>
        </div>
      </footer>
    </div>
  `;

  // Initialize UnicornStudio and branding remover
  _initUnicornStudio();
  _startBrandingRemoval();
}

function _initUnicornStudio() {
  // If already initialized in window, re-init for the newly rendered DOM node
  if (window.UnicornStudio?.init) {
    try {
      window.UnicornStudio.init();
    } catch (e) {
      console.warn('UnicornStudio re-init error:', e);
    }
  }

  if (document.querySelector('script[src*="unicornStudio"]')) return;

  const script = document.createElement('script');
  script.type = 'text/javascript';
  script.src = 'https://cdn.jsdelivr.net/gh/hiunicornstudio/unicornstudio.js@v1.4.33/dist/unicornStudio.umd.js';
  script.onload = () => {
    if (window.UnicornStudio) {
      window.UnicornStudio.isInitialized = true;
      try {
        window.UnicornStudio.init();
      } catch (e) {
        console.warn('UnicornStudio script onload error:', e);
      }
    }
  };
  (document.head || document.body).appendChild(script);
}

function _startBrandingRemoval() {
  const hideBranding = () => {
    const selectors = [
      '[data-us-project]',
      '.unicorn-studio-container',
      'canvas[aria-label*="Unicorn"]'
    ];

    selectors.forEach(selector => {
      const containers = document.querySelectorAll(selector);
      containers.forEach(container => {
        const allElements = container.querySelectorAll('*');
        allElements.forEach(el => {
          const text = (el.textContent || '').toLowerCase();
          const title = (el.getAttribute('title') || '').toLowerCase();
          const href = (el.getAttribute('href') || '').toLowerCase();

          if (
            text.includes('made with') ||
            text.includes('unicorn') ||
            title.includes('made with') ||
            title.includes('unicorn') ||
            href.includes('unicorn.studio')
          ) {
            el.style.display = 'none';
            el.style.visibility = 'hidden';
            el.style.opacity = '0';
            el.style.pointerEvents = 'none';
            el.style.position = 'absolute';
            el.style.left = '-9999px';
            try { el.remove(); } catch (_) {}
          }
        });
      });
    });
  };

  hideBranding();
  _brandInterval = setInterval(hideBranding, 80);

  setTimeout(hideBranding, 500);
  setTimeout(hideBranding, 1200);
  setTimeout(hideBranding, 2500);
  setTimeout(hideBranding, 5000);
}
