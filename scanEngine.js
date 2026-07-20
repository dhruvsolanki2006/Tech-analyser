/**
 * CyberScope — Central Scan Engine (High Accuracy & Deep Inspection)
 *
 * Orchestrates all detector modules. Collects page signals, tests
 * each signature against the appropriate signal source, computes
 * weighted confidence, handles deduplication and "implies" relationships,
 * extracts deep technology metadata, performs security posture audits,
 * and returns structured results.
 */
(() => {
  'use strict';

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

    /* Globals & Deep Data from globals-probe.js */
    let globals = '';
    let globalVersions = {};
    let deepData = {};
    try {
      const attr = document.documentElement.getAttribute('data-techstack-globals');
      if (attr) {
        const parsed = JSON.parse(attr);
        globals = Object.entries(parsed.found || {})
          .filter(([, v]) => v)
          .map(([k]) => k)
          .join(' ');
        globalVersions = parsed.versions || {};
        deepData = parsed.deepData || {};
      }
    } catch { /* ignore parse errors */ }

    /* Headers from globals-probe.js MAIN world HEAD fetch */
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
      deepData,
    };
  }

  /* ────────────────────────────────────────────────────────────────── */
  /*  Fallback Header Fetching                                         */
  /* ────────────────────────────────────────────────────────────────── */

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
  /*  Security Posture Audit                                           */
  /* ────────────────────────────────────────────────────────────────── */

  /**
   * Perform deep audit of response security headers.
   * @param {string} headersText 
   * @returns {Object} security posture summary
   */
  function auditSecurityHeaders(headersText) {
    if (!headersText) return null;

    const lower = headersText.toLowerCase();
    const checks = [
      {
        key: 'hsts',
        label: 'HTTP Strict Transport Security (HSTS)',
        present: lower.includes('strict-transport-security:'),
        detail: lower.match(/strict-transport-security:\s*([^\r\n]+)/i)?.[1] || null
      },
      {
        key: 'csp',
        label: 'Content Security Policy (CSP)',
        present: lower.includes('content-security-policy:'),
        detail: lower.includes('content-security-policy:') ? 'Active' : null
      },
      {
        key: 'xfo',
        label: 'X-Frame-Options',
        present: lower.includes('x-frame-options:'),
        detail: lower.match(/x-frame-options:\s*([^\r\n]+)/i)?.[1] || null
      },
      {
        key: 'cto',
        label: 'X-Content-Type-Options',
        present: lower.includes('x-content-type-options:'),
        detail: lower.match(/x-content-type-options:\s*([^\r\n]+)/i)?.[1] || null
      },
      {
        key: 'rp',
        label: 'Referrer Policy',
        present: lower.includes('referrer-policy:'),
        detail: lower.match(/referrer-policy:\s*([^\r\n]+)/i)?.[1] || null
      },
      {
        key: 'pp',
        label: 'Permissions Policy',
        present: lower.includes('permissions-policy:'),
        detail: lower.includes('permissions-policy:') ? 'Active' : null
      }
    ];

    const passedCount = checks.filter(c => c.present).length;
    const scorePct = Math.round((passedCount / checks.length) * 100);

    return {
      scorePct,
      passedCount,
      totalCount: checks.length,
      checks
    };
  }

  /* ────────────────────────────────────────────────────────────────── */
  /*  Detection Logic                                                  */
  /* ────────────────────────────────────────────────────────────────── */

  const CATEGORY_META = {
    frontend:    { label: 'Frontend Frameworks', order: 0 },
    libraries:   { label: 'JavaScript Libraries', order: 1 },
    cms:         { label: 'CMS / Commerce', order: 2 },
    backend:     { label: 'Backend Frameworks (Inferred)', order: 3 },
    webserver:   { label: 'Web Servers', order: 4 },
    hosting:     { label: 'Hosting', order: 5 },
    cdn:         { label: 'CDN', order: 6 },
    analytics:   { label: 'Analytics & Tracking', order: 7 },
    security:    { label: 'Security & Monitoring', order: 8 },
    payments:    { label: 'Payments', order: 9 },
    fonts:       { label: 'Fonts & Icons', order: 10 },
    tagmanagers: { label: 'Tag Managers & Consent', order: 11 },
    marketing:   { label: 'Marketing & Chat', order: 12 },
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
    const deepData = signals.deepData || {};

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
          details: [],
        };

        /* Check version info */
        const versionKey = Object.keys(signals.globalVersions || {}).find(
          k => sig.name.toLowerCase().includes(k.toLowerCase()) ||
               k.toLowerCase().includes(sig.name.toLowerCase().split('.')[0].split(' ')[0])
        );
        if (versionKey && signals.globalVersions[versionKey]) {
          result.version = signals.globalVersions[versionKey];
        }

        /* Extract Header Versions for Web Servers / CDNs */
        if (category === 'webserver' && signals.headers) {
          const serverHeader = signals.headers.match(/^server:\s*(.+)$/im)?.[1];
          if (serverHeader && serverHeader.toLowerCase().includes(sig.name.toLowerCase())) {
            const verMatch = serverHeader.match(/[\d.]+/);
            if (verMatch && !result.version) {
              result.version = verMatch[0];
            }
          }
        }

        /* Deep Technology Specific Details */
        if (sig.name === 'Google Analytics') {
          if (deepData.ga4Id) result.details.push(`GA4 Measurement ID: ${deepData.ga4Id}`);
          if (deepData.uaId) result.details.push(`Universal Analytics ID: ${deepData.uaId}`);
        }
        if (sig.name === 'Google Tag Manager' && deepData.gtmId) {
          result.details.push(`Container ID: ${deepData.gtmId}`);
        }
        if (sig.name === 'Meta Pixel' && deepData.metaPixelId) {
          result.details.push(`Pixel ID: ${deepData.metaPixelId}`);
        }
        if (sig.name === 'Hotjar' && deepData.hotjarId) {
          result.details.push(`Site ID: ${deepData.hotjarId}`);
        }
        if (sig.name === 'Microsoft Clarity' && deepData.clarityId) {
          result.details.push(`Project ID: ${deepData.clarityId}`);
        }
        if (sig.name === 'Next.js') {
          if (deepData.nextBuildId) result.details.push(`Build ID: ${deepData.nextBuildId.slice(0, 16)}`);
          if (deepData.nextPage) result.details.push(`Route: ${deepData.nextPage}`);
        }
        if (sig.name === 'WordPress') {
          if (deepData.wpTheme) result.details.push(`Active Theme: ${deepData.wpTheme}`);
          if (deepData.wpPlugins && deepData.wpPlugins.length > 0) {
            result.details.push(`Active Plugins (${deepData.wpPlugins.length}): ${deepData.wpPlugins.slice(0, 8).join(', ')}${deepData.wpPlugins.length > 8 ? '...' : ''}`);
          }
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
        details: [],
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

    /* Security Audit */
    const securityAudit = auditSecurityHeaders(signals.headers);

    return {
      groups,
      categoryCounts,
      totalDetected,
      categoryMeta: CATEGORY_META,
      securityAudit,
    };
  }

  /* ────────────────────────────────────────────────────────────────── */
  /*  Public API                                                       */
  /* ────────────────────────────────────────────────────────────────── */

  self.TechScanEngine = {
    /**
     * Run a full scan: collect signals, detect technologies, extract deep insights.
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
