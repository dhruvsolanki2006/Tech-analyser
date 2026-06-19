/**
 * TechStack Detector — Central Scan Engine
 *
 * Orchestrates all detector modules. Collects page signals, tests
 * each signature against the appropriate signal source, computes
 * weighted confidence, handles deduplication and "implies" relationships,
 * and returns structured results.
 *
 * Signal sources:
 *   html           – full document.documentElement.outerHTML
 *   scriptSrcs     – script tag src attributes (URLs only)
 *   scriptContents – inline script text (capped per script)
 *   metaTags       – meta name + property + content + http-equiv
 *   linkHrefs      – link tag rel + href
 *   resourceUrls   – performance.getEntriesByType('resource') names
 *   cookies        – document.cookie
 *   globals        – detected window globals (from globals-probe.js)
 *   headers        – response headers (from globals-probe.js MAIN world fetch)
 *   classes        – body + html class names
 */
(() => {
  'use strict';

  /* Allow re-initialization so re-scans work */

  /* ────────────────────────────────────────────────────────────────── */
  /*  Signal Collection                                                */
  /* ────────────────────────────────────────────────────────────────── */

  /**
   * Collect all page signals for detection.
   * @returns {Object} signal map keyed by source name
   */
  function collectSignals() {
    /* Script elements */
    const scriptEls = Array.from(document.scripts || []);
    const scriptSrcs = scriptEls
      .map(s => s.src || '')
      .filter(Boolean)
      .join('\n');
    const scriptContents = scriptEls
      .map(s => (s.textContent || '').slice(0, 2000))
      .join('\n');

    /* Meta tags */
    const metaTags = Array.from(document.querySelectorAll('meta'))
      .map(m => [m.name, m.getAttribute('property'), m.content, m.httpEquiv]
        .filter(Boolean).join(' '))
      .join('\n');

    /* Link tags */
    const linkHrefs = Array.from(document.querySelectorAll('link'))
      .map(l => `${l.rel || ''} ${l.href || ''}`)
      .join('\n');

    /* Resource timing — includes dynamically loaded scripts, images, fonts */
    const resourceUrls = performance
      .getEntriesByType('resource')
      .map(r => r.name)
      .join('\n');

    /* Cookies */
    const cookies = document.cookie || '';

    /* Full HTML (for attribute / element detection) */
    const html = document.documentElement
      ? document.documentElement.outerHTML
      : '';

    /* Body / HTML classes */
    const classes = [
      document.documentElement?.className || '',
      document.body?.className || ''
    ].join(' ');

    /* Globals from globals-probe.js (written as a data attribute in MAIN world) */
    let globals = '';
    let globalVersions = {};
    try {
      const attr = document.documentElement.getAttribute('data-techstack-globals');
      if (attr) {
        const parsed = JSON.parse(attr);
        globals = Object.entries(parsed.found || {})
          .filter(([, v]) => v)
          .map(([k]) => k)
          .join(' ');
        globalVersions = parsed.versions || {};
      }
    } catch { /* ignore parse errors */ }

    /*
     * Headers from globals-probe.js MAIN world HEAD fetch.
     * The probe writes headers to data-techstack-headers because
     * MAIN world fetch is same-origin (full header access),
     * whereas ISOLATED world fetch gets CORS-filtered headers.
     */
    let headers = '';
    try {
      headers = document.documentElement.getAttribute('data-techstack-headers') || '';
    } catch { /* ignore */ }

    return {
      html,
      scriptSrcs,
      scriptContents,
      metaTags,
      linkHrefs,
      resourceUrls,
      cookies,
      globals,
      classes,
      headers,
      globalVersions,
    };
  }

  /* ────────────────────────────────────────────────────────────────── */
  /*  Fallback Header Fetching                                         */
  /* ────────────────────────────────────────────────────────────────── */

  /**
   * Fallback: try fetching headers from the ISOLATED world.
   * May return limited headers due to CORS, but better than nothing.
   */
  async function fetchHeadersFallback() {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 2000);
      const res = await fetch(location.href, {
        method: 'HEAD',
        cache: 'no-store',
        signal: controller.signal,
      });
      clearTimeout(timeout);
      const lines = [];
      res.headers.forEach((value, key) => {
        lines.push(`${key}: ${value}`);
      });
      return lines.join('\n');
    } catch {
      return '';
    }
  }

  /* ────────────────────────────────────────────────────────────────── */
  /*  Detection Logic                                                  */
  /* ────────────────────────────────────────────────────────────────── */

  /** Category display order and labels */
  const CATEGORY_META = {
    frontend:  { label: 'Frontend Frameworks', order: 0 },
    libraries: { label: 'JavaScript Libraries', order: 1 },
    cms:       { label: 'CMS / Commerce', order: 2 },
    backend:   { label: 'Backend Frameworks (Inferred)', order: 3 },
    webserver: { label: 'Web Servers', order: 4 },
    hosting:   { label: 'Hosting', order: 5 },
    cdn:       { label: 'CDN', order: 6 },
    analytics: { label: 'Analytics & Tracking', order: 7 },
    security:  { label: 'Security & Monitoring', order: 8 },
    payments:  { label: 'Payments', order: 9 },
  };

  /**
   * Run all registered detectors against collected signals.
   * @param {Object} signals — output from collectSignals()
   * @returns {Object} structured results
   */
  function runDetection(signals) {
    const detectors = self.TechDetectors || {};
    const groups = {};
    const seenNames = new Set();
    const impliedTechs = [];

    /* Initialise empty groups */
    for (const cat of Object.keys(CATEGORY_META)) {
      groups[cat] = [];
    }

    /* Iterate every category / signature */
    for (const [category, signatures] of Object.entries(detectors)) {
      if (!Array.isArray(signatures)) continue;
      if (!groups[category]) groups[category] = [];

      for (const sig of signatures) {
        const matchedEvidence = [];
        let totalWeight = 0;
        let matchCount = 0;

        for (const pattern of sig.patterns) {
          const signalText = signals[pattern.source] || '';
          if (!signalText) continue;

          if (pattern.regex.test(signalText)) {
            matchCount++;
            totalWeight += pattern.weight;
            matchedEvidence.push(pattern.evidence);
          }
        }

        const minMatches = sig.requiredMatches || 1;
        if (matchCount < minMatches) continue;

        const confidence = Math.min(totalWeight, 1.0);

        /* Minimum confidence threshold */
        if (confidence < 0.30) continue;

        const result = {
          name: sig.name,
          icon: sig.icon || '🔹',
          confidence: Math.round(confidence * 100) / 100,
          evidence: matchedEvidence.slice(0, 5),
          inferred: !!sig.inferred,
          headerOnly: !!sig.headerOnly,
        };

        /* Check version info */
        const versionKey = Object.keys(signals.globalVersions || {}).find(
          k => sig.name.toLowerCase().includes(k.toLowerCase()) ||
               k.toLowerCase().includes(sig.name.toLowerCase().split('.')[0].split(' ')[0])
        );
        if (versionKey && signals.globalVersions[versionKey]) {
          result.version = signals.globalVersions[versionKey];
        }

        groups[category].push(result);
        seenNames.add(sig.name);

        /* Queue implied technologies */
        if (Array.isArray(sig.implies)) {
          for (const implied of sig.implies) {
            impliedTechs.push({ name: implied, fromCategory: category, via: sig.name });
          }
        }
      }
    }

    /* Process implied technologies */
    for (const imp of impliedTechs) {
      if (seenNames.has(imp.name)) continue;

      let impliedCategory = imp.fromCategory;
      let impliedIcon = '🔹';
      for (const [cat, sigs] of Object.entries(detectors)) {
        if (!Array.isArray(sigs)) continue;
        const found = sigs.find(s => s.name === imp.name);
        if (found) {
          impliedCategory = cat;
          impliedIcon = found.icon || '🔹';
          break;
        }
      }

      groups[impliedCategory] = groups[impliedCategory] || [];
      groups[impliedCategory].push({
        name: imp.name,
        icon: impliedIcon,
        confidence: 0.40,
        evidence: [`Implied by ${imp.via}`],
        inferred: false,
        implied: true,
      });
      seenNames.add(imp.name);
    }

    /* Sort each group by confidence descending */
    for (const cat of Object.keys(groups)) {
      groups[cat].sort((a, b) => b.confidence - a.confidence || a.name.localeCompare(b.name));
    }

    /* Calculate summary stats */
    const categoryCounts = {};
    let totalDetected = 0;
    for (const [cat, items] of Object.entries(groups)) {
      categoryCounts[cat] = items.length;
      totalDetected += items.length;
    }

    return {
      groups,
      categoryCounts,
      totalDetected,
      categoryMeta: CATEGORY_META,
    };
  }

  /* ────────────────────────────────────────────────────────────────── */
  /*  Public API                                                       */
  /* ────────────────────────────────────────────────────────────────── */

  self.TechScanEngine = {
    /**
     * Run a full scan: collect signals, detect technologies.
     * @returns {Promise<Object>} detection results
     */
    async scan() {
      const utils = self.TechStackUtils || {};
      const signals = collectSignals();

      /* If MAIN world probe didn't provide headers, try fallback fetch */
      if (!signals.headers) {
        signals.headers = await fetchHeadersFallback();
      }

      /* Run detection */
      const detection = runDetection(signals);

      return {
        url: location.href,
        pageKey: utils.normalizePageKey
          ? utils.normalizePageKey(location.href)
          : location.href,
        title: document.title || '',
        scannedAt: new Date().toISOString(),
        ...detection,
      };
    },

    getCategoryMeta() {
      return CATEGORY_META;
    },
  };
})();
