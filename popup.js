/**
 * TechStack Detector — Popup Script
 *
 * Handles:
 *  • Scan initiation and result polling
 *  • Rendering detected technologies with confidence badges
 *  • Search / filter with debounce
 *  • Loading skeleton management
 *  • Animated card rendering
 */
(() => {
  'use strict';

  /* ── DOM references ──────────────────────────────────────────────── */
  const scanBtn        = document.getElementById('scanBtn');
  const statusEl       = document.getElementById('status');
  const statusDot      = document.getElementById('statusIndicator');
  const summaryEl      = document.getElementById('summary');
  const resultsEl      = document.getElementById('results');
  const pageLabelEl    = document.getElementById('pageLabel');
  const searchBarEl    = document.getElementById('searchBar');
  const searchInputEl  = document.getElementById('searchInput');
  const skeletonEl     = document.getElementById('skeleton');
  const scanTimeEl     = document.getElementById('scanTime');

  let currentPageKey = '';
  let currentTabId   = null;
  let lastResult     = null;

  /* ── Category metadata ───────────────────────────────────────────── */
  const CATEGORY_META = {
    frontend:  { label: 'Frontend Frameworks',            icon: '🖥️' },
    libraries: { label: 'JavaScript Libraries',           icon: '📚' },
    cms:       { label: 'CMS / Commerce',                 icon: '📝' },
    backend:   { label: 'Backend Frameworks (Inferred)',   icon: '⚙️' },
    webserver: { label: 'Web Servers',                     icon: '🌐' },
    hosting:   { label: 'Hosting',                         icon: '☁️' },
    cdn:       { label: 'CDN',                             icon: '🚀' },
    analytics: { label: 'Analytics & Tracking',            icon: '📊' },
    security:  { label: 'Security & Monitoring',           icon: '🛡️' },
    payments:  { label: 'Payments',                        icon: '💳' },
  };

  const CATEGORY_ORDER = [
    'frontend', 'libraries', 'cms', 'backend', 'webserver',
    'hosting', 'cdn', 'analytics', 'security', 'payments',
  ];

  /* ── Utilities ───────────────────────────────────────────────────── */
  function escapeHtml(value) {
    return String(value)
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#39;');
  }

  function normalizePageKey(rawUrl) {
    try {
      const url = new URL(rawUrl);
      return `${url.origin}${url.pathname}`;
    } catch {
      return rawUrl || '';
    }
  }

  function formatHost(rawUrl) {
    try { return new URL(rawUrl).host; }
    catch { return rawUrl || 'Unknown site'; }
  }

  /* ── Status helpers ──────────────────────────────────────────────── */
  function setStatus(text, state = 'idle') {
    statusEl.textContent = text;
    statusDot.className  = `status-dot ${state}`;
  }

  function showSkeleton() {
    skeletonEl.classList.remove('hidden');
    resultsEl.innerHTML = '';
    searchBarEl.classList.add('hidden');
  }

  function hideSkeleton() {
    skeletonEl.classList.add('hidden');
  }

  /* ── Confidence badge ────────────────────────────────────────────── */
  function confBadge(confidence) {
    const pct = Math.round(confidence * 100);
    let cls = 'conf-low';
    if (pct >= 80) cls = 'conf-high';
    else if (pct >= 60) cls = 'conf-med';

    return `<span class="conf-badge ${cls}">
      <span class="conf-dot"></span>${pct}%
    </span>`;
  }

  /* ── Render empty state ──────────────────────────────────────────── */
  function renderEmpty(message) {
    summaryEl.textContent = message;
    resultsEl.innerHTML = `<div class="empty-state">${escapeHtml(message)}</div>`;
    searchBarEl.classList.add('hidden');
  }

  /* ── Render results ──────────────────────────────────────────────── */
  function renderResult(payload, filterText = '') {
    const result = payload?.result || payload;
    const groups = result?.groups || {};
    const categoryCounts = result?.categoryCounts || {};
    const totalDetected  = result?.totalDetected ?? 0;
    const filter = filterText.toLowerCase().trim();

    /* Summary text */
    if (totalDetected > 0) {
      const parts = Object.entries(categoryCounts)
        .filter(([, c]) => c > 0)
        .map(([cat, c]) => `${CATEGORY_META[cat]?.label || cat} (${c})`);
      summaryEl.textContent = `${totalDetected} technologies detected • ${parts.join(', ')}`;
    } else {
      summaryEl.textContent = 'No technologies detected from public signals.';
    }

    /* Show search bar if we have results */
    if (totalDetected > 0) {
      searchBarEl.classList.remove('hidden');
    }

    /* Build category cards */
    let html = '';
    let delay = 0;
    let visibleCount = 0;

    for (const catKey of CATEGORY_ORDER) {
      let items = groups[catKey] || [];
      if (!items.length) continue;

      /* Apply search filter */
      if (filter) {
        items = items.filter(item =>
          item.name.toLowerCase().includes(filter) ||
          (item.evidence || []).some(e => e.toLowerCase().includes(filter))
        );
      }
      if (!items.length) continue;

      visibleCount += items.length;
      const meta = CATEGORY_META[catKey] || { label: catKey, icon: '🔹' };
      const isBackend = catKey === 'backend';

      const techRows = items.map(item => {
        const evidence = (item.evidence || [])
          .map(e => `<div class="evidence-item">
            <span class="evidence-bullet">●</span>
            <span>${escapeHtml(e)}</span>
          </div>`)
          .join('');

        const versionTag = item.version
          ? `<span class="tech-version">v${escapeHtml(item.version)}</span>`
          : '';

        const impliedTag = item.implied
          ? `<div class="implied-tag">↳ Implied</div>`
          : '';

        return `<div class="tech-row">
          <div class="tech-top">
            <div class="tech-name-group">
              <span class="tech-emoji">${item.icon || '🔹'}</span>
              <span class="tech-name">${escapeHtml(item.name)}</span>
              ${versionTag}
            </div>
            ${confBadge(item.confidence)}
          </div>
          ${evidence ? `<div class="tech-evidence">${evidence}</div>` : ''}
          ${impliedTag}
        </div>`;
      }).join('');

      const noteHtml = isBackend
        ? `<span class="category-note">Inferred from public fingerprints. Not a certainty.</span>`
        : '';

      html += `<article class="category-card" style="animation-delay: ${delay}ms">
        <div class="category-header">
          <div class="category-left">
            <span class="category-icon">${meta.icon}</span>
            <span class="category-title">${escapeHtml(meta.label)}</span>
          </div>
          <span class="category-badge">${items.length}</span>
        </div>
        ${noteHtml}
        <div class="tech-list">${techRows}</div>
      </article>`;

      delay += 60;
    }

    if (!html && filter) {
      html = `<div class="no-match">No technologies matching "${escapeHtml(filter)}"</div>`;
    } else if (!html) {
      html = `<div class="empty-state">No common technologies were detected.</div>`;
    }

    resultsEl.innerHTML = html;
  }

  /* ── Tab helpers ─────────────────────────────────────────────────── */
  async function getActiveTab() {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    return tabs[0] || null;
  }

  /* ── Wait for result in storage ──────────────────────────────────── */
  async function waitForResult(pageKey, timeoutMs = 15000) {
    const storageKey = `scan:${pageKey}`;
    const started = Date.now();

    return new Promise(resolve => {
      const timer = setInterval(async () => {
        const stored = await chrome.storage.local.get(storageKey);
        const payload = stored[storageKey];

        if (payload) {
          clearInterval(timer);
          resolve(payload);
          return;
        }

        if (Date.now() - started >= timeoutMs) {
          clearInterval(timer);
          resolve(null);
        }
      }, 250);
    });
  }

  /* ── Run Scan ────────────────────────────────────────────────────── */
  async function runScan() {
    const scanStart = performance.now();

    try {
      scanBtn.disabled = true;
      setStatus('Scanning…', 'scanning');
      showSkeleton();
      summaryEl.textContent = 'Analyzing the current page…';

      const tab = await getActiveTab();
      if (!tab?.id || !tab?.url) {
        setStatus('No tab', 'error');
        hideSkeleton();
        renderEmpty('Open a website tab first.');
        scanBtn.disabled = false;
        return;
      }

      /* Reject chrome:// and extension pages */
      if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://') || tab.url.startsWith('edge://')) {
        setStatus('Unsupported page', 'error');
        hideSkeleton();
        renderEmpty('Cannot scan browser internal pages.');
        scanBtn.disabled = false;
        return;
      }

      currentTabId   = tab.id;
      currentPageKey = normalizePageKey(tab.url);
      pageLabelEl.textContent = formatHost(tab.url);

      /* Clear previous result for this page */
      await chrome.storage.local.remove(`scan:${currentPageKey}`);

      /* Request background to inject scripts */
      const response = await chrome.runtime.sendMessage({
        type: 'SCAN_ACTIVE_TAB',
        tabId: currentTabId,
      });

      if (!response?.ok) {
        throw new Error(response?.error || 'Scan injection failed');
      }

      /* Poll for result */
      const payload = await waitForResult(currentPageKey, 15000);

      hideSkeleton();

      if (!payload) {
        setStatus('Timed out', 'error');
        renderEmpty('The scan did not return results in time. Try again.');
        scanBtn.disabled = false;
        return;
      }

      if (payload.error) {
        setStatus('Scan failed', 'error');
        renderEmpty(`Error: ${payload.error}`);
        scanBtn.disabled = false;
        return;
      }

      /* Success */
      const elapsed = ((performance.now() - scanStart) / 1000).toFixed(1);
      setStatus('Scan complete', 'done');
      scanTimeEl.textContent = `${elapsed}s`;
      lastResult = payload;
      renderResult(payload);

    } catch (error) {
      hideSkeleton();
      setStatus('Error', 'error');
      renderEmpty(error?.message || String(error));
    } finally {
      scanBtn.disabled = false;
    }
  }

  /* ── Search / Filter ─────────────────────────────────────────────── */
  let searchTimeout = null;
  searchInputEl.addEventListener('input', () => {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => {
      if (lastResult) {
        renderResult(lastResult, searchInputEl.value);
      }
    }, 200);
  });

  /* ── Hydrate label on popup open ─────────────────────────────────── */
  async function hydrate() {
    try {
      const tab = await getActiveTab();
      if (tab?.url) {
        pageLabelEl.textContent = formatHost(tab.url);
        currentPageKey = normalizePageKey(tab.url);

        /* Check if we already have a cached result */
        const storageKey = `scan:${currentPageKey}`;
        const stored = await chrome.storage.local.get(storageKey);
        const payload = stored[storageKey];

        if (payload?.result && !payload.error) {
          const age = Date.now() - (payload.storedAt || 0);
          if (age < 5 * 60 * 1000) { // less than 5 minutes old
            setStatus('Cached result', 'done');
            lastResult = payload;
            renderResult(payload);
            return;
          }
        }
      }
    } catch { /* ignore */ }
  }

  /* ── Init ────────────────────────────────────────────────────────── */
  scanBtn.addEventListener('click', runScan);
  hydrate();
})();