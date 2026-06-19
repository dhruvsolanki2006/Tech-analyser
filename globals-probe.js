/**
 * TechStack Detector — Globals & Headers Probe
 *
 * Injected into the page's MAIN world so it can:
 *  1. Inspect window.* globals (React, jQuery, etc.)
 *  2. Fetch response headers via same-origin HEAD request
 *     (MAIN world has page's origin → full header access,
 *      unlike ISOLATED content-script world which gets CORS-filtered headers)
 *
 * Results are serialized to data-attributes on <html> for the
 * content script to read from the isolated world.
 */
(async () => {
  'use strict';

  /* ── SYNC: Probe globals ──────────────────────────────────────────── */
  const CHECKS = [
    // Frontend frameworks
    'React', 'ReactDOM', '__REACT_DEVTOOLS_GLOBAL_HOOK__',
    'Vue', '__VUE__', '__VUE_DEVTOOLS_GLOBAL_HOOK__',
    'angular', 'ng', 'getAllAngularRootElements',
    '__SVELTE_DEV__', '__svelte_meta',
    '__NEXT_DATA__', '__NEXT_LOADED_PAGES__',
    '__NUXT__', '$nuxt',
    '___gatsby', '__GATSBY',
    '__remixContext', '__remixManifest',
    '_$HY',
    '__PREACT_DEVTOOLS__',

    // JS Libraries
    'jQuery', 'Zepto',
    '_',
    'moment',
    'dayjs',
    'axios',
    'Alpine',
    'THREE',
    'gsap', 'TweenMax', 'TweenLite',
    'd3',
    'Chart',
    'echarts',
    'anime',
    'Swiper',
    '__REACT_QUERY_DEVTOOLS__', '__REACT_QUERY_STATE__',
    '__REDUX_DEVTOOLS_EXTENSION__', '__REDUX_STATE__',
    'io',
    'webpackJsonp', '__webpack_modules__', 'webpackChunk',
    '__vite_plugin_react_preamble_installed__',
    'requirejs', 'define',

    // Analytics
    'ga', 'gtag', 'google_tag_manager', 'dataLayer',
    'hj',
    'mixpanel',
    'posthog',
    'plausible',
    'analytics',
    'FS',
    'clarity',
    'fbq',

    // Security / Monitoring
    'grecaptcha',
    'hcaptcha',
    'Sentry', '__SENTRY__',
    'DD_RUM',
    'NREUM', 'newrelic',

    // Payments
    'Stripe',
    'PayPal', 'paypal',
    'Razorpay',

    // CMS globals
    'Shopify',
    'Drupal',
    'Joomla',
    'wp',
    'Mage',
    'squarespace',
    '_wq',
  ];

  const found = {};
  for (const name of CHECKS) {
    try {
      found[name] = typeof window[name] !== 'undefined' && window[name] !== null;
    } catch {
      found[name] = false;
    }
  }

  /* Version extraction (best-effort) */
  const versions = {};
  const safe = (fn) => { try { fn(); } catch { /* ignore */ } };
  safe(() => { if (found.jQuery)  versions.jQuery  = window.jQuery?.fn?.jquery || ''; });
  safe(() => { if (found.React)   versions.React   = window.React?.version || ''; });
  safe(() => { if (found.Vue)     versions.Vue     = window.Vue?.version || ''; });
  safe(() => { if (found.angular) versions.Angular = window.angular?.version?.full || ''; });
  safe(() => { if (found.moment)  versions.moment  = window.moment?.version || ''; });
  safe(() => { if (found.d3)      versions.d3      = window.d3?.version || ''; });
  safe(() => { if (found.THREE)   versions.THREE   = window.THREE?.REVISION || ''; });
  safe(() => { if (found.Chart)   versions.Chart   = window.Chart?.version || ''; });
  safe(() => { if (found.Alpine)  versions.Alpine  = window.Alpine?.version || ''; });
  safe(() => { if (found.gsap)    versions.gsap    = window.gsap?.version || ''; });
  safe(() => { if (found.echarts) versions.echarts = window.echarts?.version || ''; });
  safe(() => { if (found.dayjs)   versions.dayjs   = window.dayjs?.version || ''; });

  /* Write globals immediately (sync — available before content script runs) */
  document.documentElement.setAttribute(
    'data-techstack-globals',
    JSON.stringify({ found, versions })
  );

  /* ── ASYNC: Fetch response headers ────────────────────────────────── */
  /*
   * This runs in MAIN world, so fetch() is same-origin.
   * All response headers (Server, X-Powered-By, CF-Ray, etc.)
   * are visible — unlike ISOLATED world where CORS filters them.
   */
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);

    const res = await fetch(location.href, {
      method: 'HEAD',
      cache: 'no-store',
      signal: controller.signal,
    });
    clearTimeout(timeout);

    const headerLines = [];
    res.headers.forEach((value, key) => {
      headerLines.push(`${key}: ${value}`);
    });

    document.documentElement.setAttribute(
      'data-techstack-headers',
      headerLines.join('\n')
    );
  } catch {
    /* Timeout, network error, or blocked by CSP — set empty marker */
    document.documentElement.setAttribute('data-techstack-headers', '');
  }
})();
