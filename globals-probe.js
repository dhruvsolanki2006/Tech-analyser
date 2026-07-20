/**
 * TechStack Detector — Globals & Headers Probe (High Precision & Deep Inspection)
 *
 * Injected into the page's MAIN world so it can:
 *  1. Inspect window.* globals with strict validation to prevent false positives
 *  2. Extract deep inspection data (Tracking IDs, Build IDs, Framework states)
 *  3. Fetch response headers via same-origin HEAD request
 *
 * Results are serialized to data-attributes on <html> for the
 * content script to read from the isolated world.
 */
(async () => {
  'use strict';

  /* ── SYNC: Precision global validator ──────────────────────────────── */
  const VALIDATORS = {
    // Frontend & Frameworks
    React: () => typeof window.React === 'object' && window.React !== null,
    ReactDOM: () => typeof window.ReactDOM === 'object' && window.ReactDOM !== null,
    __REACT_DEVTOOLS_GLOBAL_HOOK__: () => typeof window.__REACT_DEVTOOLS_GLOBAL_HOOK__ === 'object',
    Vue: () => typeof window.Vue !== 'undefined',
    __VUE__: () => window.__VUE__ === true || typeof window.__VUE__ === 'object',
    __VUE_DEVTOOLS_GLOBAL_HOOK__: () => typeof window.__VUE_DEVTOOLS_GLOBAL_HOOK__ === 'object',
    angular: () => typeof window.angular === 'object' && window.angular !== null,
    ng: () => typeof window.ng === 'object' && window.ng !== null,
    getAllAngularRootElements: () => typeof window.getAllAngularRootElements === 'function',
    __SVELTE_DEV__: () => typeof window.__SVELTE_DEV__ !== 'undefined',
    __svelte_meta: () => typeof window.__svelte_meta !== 'undefined',
    __NEXT_DATA__: () => typeof window.__NEXT_DATA__ === 'object' && window.__NEXT_DATA__ !== null,
    __NEXT_LOADED_PAGES__: () => Array.isArray(window.__NEXT_LOADED_PAGES__),
    __NUXT__: () => typeof window.__NUXT__ !== 'undefined',
    $nuxt: () => typeof window.$nuxt !== 'undefined',
    ___gatsby: () => typeof window.___gatsby !== 'undefined',
    __GATSBY: () => typeof window.__GATSBY !== 'undefined',
    __remixContext: () => typeof window.__remixContext === 'object',
    __remixManifest: () => typeof window.__remixManifest === 'object',
    _$HY: () => typeof window._$HY === 'object',
    __PREACT_DEVTOOLS__: () => typeof window.__PREACT_DEVTOOLS__ !== 'undefined',
    Ember: () => typeof window.Ember === 'object' && window.Ember !== null,
    htmx: () => typeof window.htmx === 'object' && window.htmx !== null,
    Turbo: () => typeof window.Turbo === 'object' && window.Turbo !== null,
    Stimulus: () => typeof window.Stimulus === 'object' && window.Stimulus !== null,
    Foundation: () => typeof window.Foundation === 'object' || typeof window.Foundation === 'function',

    // JS Libraries — strictly validate methods/properties to avoid false positives
    jQuery: () => typeof window.jQuery === 'function' || typeof window.jQuery === 'object',
    Zepto: () => typeof window.Zepto === 'function' || typeof window.Zepto === 'object',
    _: () => typeof window._ === 'function' && (typeof window._.each === 'function' || typeof window._.template === 'function' || typeof window._.map === 'function'),
    moment: () => typeof window.moment === 'function' && typeof window.moment.utc === 'function',
    dayjs: () => typeof window.dayjs === 'function' && typeof window.dayjs.isDayjs === 'function',
    axios: () => typeof window.axios === 'function' || (typeof window.axios === 'object' && typeof window.axios.get === 'function'),
    Alpine: () => typeof window.Alpine === 'object' && window.Alpine !== null,
    THREE: () => typeof window.THREE === 'object' && window.THREE !== null,
    gsap: () => typeof window.gsap === 'object' && window.gsap !== null,
    TweenMax: () => typeof window.TweenMax === 'function' || typeof window.TweenMax === 'object',
    TweenLite: () => typeof window.TweenLite === 'function' || typeof window.TweenLite === 'object',
    ScrollTrigger: () => typeof window.ScrollTrigger === 'function' || typeof window.ScrollTrigger === 'object',
    ScrollSmoother: () => typeof window.ScrollSmoother === 'function' || typeof window.ScrollSmoother === 'object',
    Draggable: () => typeof window.Draggable === 'function',
    d3: () => typeof window.d3 === 'object' && window.d3 !== null && typeof window.d3.select === 'function',
    Chart: () => typeof window.Chart === 'function' || typeof window.Chart === 'object',
    echarts: () => typeof window.echarts === 'object' && typeof window.echarts.init === 'function',
    anime: () => typeof window.anime === 'function',
    Swiper: () => typeof window.Swiper === 'function',
    __REACT_QUERY_DEVTOOLS__: () => typeof window.__REACT_QUERY_DEVTOOLS__ !== 'undefined',
    __REACT_QUERY_STATE__: () => typeof window.__REACT_QUERY_STATE__ !== 'undefined',
    __REDUX_DEVTOOLS_EXTENSION__: () => typeof window.__REDUX_DEVTOOLS_EXTENSION__ !== 'undefined',
    __REDUX_STATE__: () => typeof window.__REDUX_STATE__ !== 'undefined',
    io: () => typeof window.io === 'function' || (typeof window.io === 'object' && typeof window.io.connect === 'function'),
    webpackJsonp: () => typeof window.webpackJsonp !== 'undefined',
    __webpack_modules__: () => typeof window.__webpack_modules__ !== 'undefined',
    webpackChunk: () => typeof window.webpackChunk !== 'undefined' || Array.isArray(window.webpackChunk),
    __vite_plugin_react_preamble_installed__: () => window.__vite_plugin_react_preamble_installed__ === true,
    requirejs: () => typeof window.requirejs === 'function',
    define: () => typeof window.define === 'function' && window.define.amd,
    Backbone: () => typeof window.Backbone === 'object' && window.Backbone !== null && typeof window.Backbone.Model === 'function',
    ko: () => typeof window.ko === 'object' && typeof window.ko.applyBindings === 'function',
    lottie: () => typeof window.lottie === 'object' && typeof window.lottie.loadAnimation === 'function',
    bodymovin: () => typeof window.bodymovin === 'object',
    Highcharts: () => typeof window.Highcharts === 'object' && typeof window.Highcharts.chart === 'function',
    L: () => typeof window.L === 'object' && window.L !== null && typeof window.L.map === 'function',
    mapboxgl: () => typeof window.mapboxgl === 'object' && window.mapboxgl !== null,
    Hammer: () => typeof window.Hammer === 'function',
    Popper: () => typeof window.Popper === 'object' || typeof window.Popper === 'function',
    Sortable: () => typeof window.Sortable === 'function' || typeof window.Sortable === 'object',
    Masonry: () => typeof window.Masonry === 'function',
    Prism: () => typeof window.Prism === 'object' && typeof window.Prism.highlight === 'function',
    hljs: () => typeof window.hljs === 'object' && typeof window.hljs.highlight === 'function',
    Turbolinks: () => typeof window.Turbolinks === 'object' && typeof window.Turbolinks.visit === 'function',
    barba: () => typeof window.barba === 'object' && typeof window.barba.init === 'function',
    ScrollReveal: () => typeof window.ScrollReveal === 'function',
    AOS: () => typeof window.AOS === 'object' && typeof window.AOS.init === 'function',
    Typed: () => typeof window.Typed === 'function',
    particlesJS: () => typeof window.particlesJS === 'function',
    tsParticles: () => typeof window.tsParticles === 'object',
    marked: () => typeof window.marked === 'function' || (typeof window.marked === 'object' && typeof window.marked.parse === 'function'),

    // Analytics
    ga: () => typeof window.ga === 'function',
    gtag: () => typeof window.gtag === 'function',
    google_tag_manager: () => typeof window.google_tag_manager === 'object',
    dataLayer: () => Array.isArray(window.dataLayer),
    hj: () => typeof window.hj === 'function',
    mixpanel: () => typeof window.mixpanel === 'object' && typeof window.mixpanel.init === 'function',
    posthog: () => typeof window.posthog === 'object' && typeof window.posthog.init === 'function',
    plausible: () => typeof window.plausible === 'function',
    analytics: () => typeof window.analytics === 'object' && (typeof window.analytics.identify === 'function' || typeof window.analytics.track === 'function'),
    FS: () => typeof window.FS === 'function' || (typeof window.FS === 'object' && typeof window.FS.identify === 'function'),
    clarity: () => typeof window.clarity === 'function',
    fbq: () => typeof window.fbq === 'function',
    heap: () => typeof window.heap === 'object' && typeof window.heap.track === 'function',
    amplitude: () => typeof window.amplitude === 'object',
    pendo: () => typeof window.pendo === 'object',
    _paq: () => Array.isArray(window._paq),
    clicky: () => typeof window.clicky === 'object',
    __lo_site_id: () => typeof window.__lo_site_id !== 'undefined',
    CE2: () => typeof window.CE2 === 'object',
    s_account: () => typeof window.s_account !== 'undefined',
    s_gi: () => typeof window.s_gi === 'function',

    // Security & Monitoring
    grecaptcha: () => typeof window.grecaptcha === 'object',
    hcaptcha: () => typeof window.hcaptcha === 'object',
    Sentry: () => typeof window.Sentry === 'object',
    __SENTRY__: () => typeof window.__SENTRY__ === 'object',
    DD_RUM: () => typeof window.DD_RUM === 'object' && typeof window.DD_RUM.init === 'function',
    NREUM: () => typeof window.NREUM === 'object',
    newrelic: () => typeof window.newrelic === 'object',
    Bugsnag: () => typeof window.Bugsnag === 'object',
    LogRocket: () => typeof window.LogRocket === 'object',
    Rollbar: () => typeof window.Rollbar === 'object',
    rg4js: () => typeof window.rg4js === 'function',
    dtrum: () => typeof window.dtrum === 'object',
    ADRUM: () => typeof window.ADRUM === 'object',
    elasticApm: () => typeof window.elasticApm === 'object',

    // Payments
    Stripe: () => typeof window.Stripe === 'function',
    PayPal: () => typeof window.PayPal === 'object' || typeof window.paypal === 'object',
    paypal: () => typeof window.paypal === 'object',
    Razorpay: () => typeof window.Razorpay === 'function',
    Square: () => typeof window.Square === 'object' || typeof window.Square === 'function',
    braintree: () => typeof window.braintree === 'object',
    AdyenCheckout: () => typeof window.AdyenCheckout === 'function',
    Klarna: () => typeof window.Klarna === 'object',
    Afterpay: () => typeof window.Afterpay === 'object',
    ApplePaySession: () => typeof window.ApplePaySession === 'function',

    // CMS Globals
    Shopify: () => typeof window.Shopify === 'object',
    Drupal: () => typeof window.Drupal === 'object',
    Joomla: () => typeof window.Joomla === 'object',
    wp: () => typeof window.wp === 'object' && (typeof window.wp.element !== 'undefined' || typeof window.wp.blocks !== 'undefined' || typeof window.wp.hooks !== 'undefined'),
    Mage: () => typeof window.Mage === 'object',
    squarespace: () => typeof window.squarespace === 'object',
    _wq: () => Array.isArray(window._wq),
    prismic: () => typeof window.prismic === 'object',

    // Tag Managers & Consent
    utag: () => typeof window.utag === 'object',
    OneTrust: () => typeof window.OneTrust === 'object',
    OptanonWrapper: () => typeof window.OptanonWrapper === 'function',
    Cookiebot: () => typeof window.Cookiebot === 'object',
    Osano: () => typeof window.Osano === 'object',
    UC_UI: () => typeof window.UC_UI === 'object',
    Didomi: () => typeof window.Didomi === 'object',

    // Marketing & Chat
    Intercom: () => typeof window.Intercom === 'function',
    drift: () => typeof window.drift === 'object',
    CRISP_WEBSITE_ID: () => typeof window.CRISP_WEBSITE_ID !== 'undefined',
    $crisp: () => typeof window.$crisp === 'object' || Array.isArray(window.$crisp),
    zE: () => typeof window.zE === 'function',
    Tawk_API: () => typeof window.Tawk_API === 'object',
    LC_API: () => typeof window.LC_API === 'object',
    LiveChat: () => typeof window.LiveChat === 'object',
    HubSpotConversations: () => typeof window.HubSpotConversations === 'object',
  };

  const found = {};
  for (const [name, validator] of Object.entries(VALIDATORS)) {
    try {
      found[name] = validator();
    } catch {
      found[name] = false;
    }
  }

  /* ── Version Extraction (Safe & Best Effort) ────────────────────────── */
  const versions = {};
  const safe = (fn) => { try { fn(); } catch { /* ignore */ } };

  safe(() => { if (found.jQuery)      versions.jQuery      = window.jQuery?.fn?.jquery || ''; });
  safe(() => { if (found.React)       versions.React       = window.React?.version || ''; });
  safe(() => { if (found.Vue)         versions.Vue         = window.Vue?.version || ''; });
  safe(() => { if (found.angular)     versions.Angular     = window.angular?.version?.full || ''; });
  safe(() => { if (found.moment)      versions.moment      = window.moment?.version || ''; });
  safe(() => { if (found.d3)          versions.d3          = window.d3?.version || ''; });
  safe(() => { if (found.THREE)       versions.THREE       = window.THREE?.REVISION ? `r${window.THREE.REVISION}` : ''; });
  safe(() => { if (found.Chart)       versions.Chart       = window.Chart?.version || ''; });
  safe(() => { if (found.Alpine)      versions.Alpine      = window.Alpine?.version || ''; });
  safe(() => { if (found.gsap)        versions.gsap        = window.gsap?.version || ''; });
  safe(() => { if (found.echarts)     versions.echarts     = window.echarts?.version || ''; });
  safe(() => { if (found.dayjs)       versions.dayjs       = window.dayjs?.version || ''; });
  safe(() => { if (found.Backbone)    versions.Backbone    = window.Backbone?.VERSION || ''; });
  safe(() => { if (found.Ember)       versions.Ember       = window.Ember?.VERSION || ''; });
  safe(() => { if (found.Highcharts)  versions.Highcharts  = window.Highcharts?.version || ''; });
  safe(() => { if (found.Sentry)      versions.Sentry      = window.Sentry?.SDK_VERSION || ''; });
  safe(() => { if (found.mapboxgl)    versions.mapboxgl    = window.mapboxgl?.version || ''; });
  safe(() => { if (found.Swiper)      versions.Swiper      = window.Swiper?.version || ''; });
  safe(() => { if (found.lottie)      versions.lottie      = window.lottie?.version || ''; });

  /* ── Deep Inspection Extraction ──────────────────────────────────── */
  const deepData = {};

  // 1. Google Analytics IDs (GA4 G-*, UA-*)
  safe(() => {
    const ga4Match = document.documentElement.outerHTML.match(/\b(G-[A-Z0-9]{8,12})\b/);
    if (ga4Match) deepData.ga4Id = ga4Match[1];

    const uaMatch = document.documentElement.outerHTML.match(/\b(UA-\d+-\d+)\b/);
    if (uaMatch) deepData.uaId = uaMatch[1];
  });

  // 2. Google Tag Manager Container ID (GTM-*)
  safe(() => {
    const gtmMatch = document.documentElement.outerHTML.match(/\b(GTM-[A-Z0-9]{5,10})\b/);
    if (gtmMatch) deepData.gtmId = gtmMatch[1];
  });

  // 3. Meta Pixel ID
  safe(() => {
    const fbMatch = document.documentElement.outerHTML.match(/fbq\(\s*['"]init['"]\s*,\s*['"](\d{10,18})['"]/);
    if (fbMatch) deepData.metaPixelId = fbMatch[1];
  });

  // 4. Hotjar Site ID
  safe(() => {
    if (window._hjSettings?.hjid) deepData.hotjarId = String(window._hjSettings.hjid);
  });

  // 5. Microsoft Clarity ID
  safe(() => {
    const clarityMatch = document.documentElement.outerHTML.match(/clarity\s*\(\s*["']js["']\s*,\s*["']([a-z0-9]+)["']\)/i);
    if (clarityMatch) deepData.clarityId = clarityMatch[1];
  });

  // 6. Next.js Build ID & Page Route
  safe(() => {
    if (window.__NEXT_DATA__) {
      if (window.__NEXT_DATA__.buildId) deepData.nextBuildId = window.__NEXT_DATA__.buildId;
      if (window.__NEXT_DATA__.page) deepData.nextPage = window.__NEXT_DATA__.page;
    }
  });

  // 7. WordPress Theme & Plugins (Parsed from DOM URLs)
  safe(() => {
    const html = document.documentElement.outerHTML || '';
    const pluginMatches = Array.from(html.matchAll(/\/wp-content\/plugins\/([a-zA-Z0-9_-]+)\//g))
      .map(m => m[1])
      .filter(p => !['js', 'css', 'assets', 'includes'].includes(p.toLowerCase()));
    
    const uniquePlugins = Array.from(new Set(pluginMatches)).slice(0, 15);
    if (uniquePlugins.length > 0) deepData.wpPlugins = uniquePlugins;

    const themeMatch = html.match(/\/wp-content\/themes\/([a-zA-Z0-9_-]+)\//);
    if (themeMatch) deepData.wpTheme = themeMatch[1];
  });

  /* Write globals & deepData synchronously to data attribute */
  document.documentElement.setAttribute(
    'data-techstack-globals',
    JSON.stringify({ found, versions, deepData })
  );

  /* ── ASYNC: Fetch Response Headers (MAIN world same-origin fetch) ───── */
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
    document.documentElement.setAttribute('data-techstack-headers', '');
  }
})();
