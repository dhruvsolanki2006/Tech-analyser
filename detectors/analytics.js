/**
 * TechStack Detector — Analytics & Tracking Signatures
 *
 * Detection uses CDN-specific script URLs, resource timing entries,
 * initialization globals, AND raw HTML fallback patterns to catch
 * both static and dynamically loaded analytics scripts.
 */
(() => {
  'use strict';
  self.TechDetectors = self.TechDetectors || {};

  self.TechDetectors.analytics = [
    /* ── Google Analytics ──────────────────────────────────────────── */
    {
      name: 'Google Analytics',
      icon: '📊',
      patterns: [
        { source: 'scriptSrcs',    regex: /google-analytics\.com\/analytics\.js/i, weight: 0.55, evidence: 'GA Universal analytics.js loaded' },
        { source: 'scriptSrcs',    regex: /googletagmanager\.com\/gtag/i,        weight: 0.50, evidence: 'GA4 gtag script loaded' },
        { source: 'resourceUrls',  regex: /google-analytics\.com/i,              weight: 0.50, evidence: 'Google Analytics resources loaded' },
        { source: 'resourceUrls',  regex: /googletagmanager\.com\/gtag/i,        weight: 0.50, evidence: 'GA4 gtag resources loaded' },
        { source: 'html',          regex: /google-analytics\.com\/analytics\.js/i, weight: 0.45, evidence: 'GA analytics.js reference in HTML' },
        { source: 'html',          regex: /googletagmanager\.com\/gtag/i,        weight: 0.40, evidence: 'GA4 gtag reference in HTML' },
        { source: 'scriptContents', regex: /gtag\(\s*['"]config['"],\s*['"](?:G|UA)-/i, weight: 0.45, evidence: 'gtag config with GA measurement ID' },
        { source: 'globals',       regex: /\bgtag\b/,                            weight: 0.35, evidence: 'window.gtag function present' },
        { source: 'globals',       regex: /\bga\b/,                              weight: 0.20, evidence: 'window.ga function present' },
        { source: 'globals',       regex: /\bdataLayer\b/,                       weight: 0.15, evidence: 'dataLayer array present' },
      ],
      requiredMatches: 1,
    },

    /* ── Google Tag Manager ────────────────────────────────────────── */
    {
      name: 'Google Tag Manager',
      icon: '🏷️',
      patterns: [
        { source: 'scriptSrcs',    regex: /googletagmanager\.com\/gtm\.js/i,     weight: 0.55, evidence: 'GTM container script loaded' },
        { source: 'resourceUrls',  regex: /googletagmanager\.com\/gtm\.js/i,     weight: 0.55, evidence: 'GTM container resources loaded' },
        { source: 'html',          regex: /googletagmanager\.com\/gtm\.js/i,     weight: 0.50, evidence: 'GTM script reference in HTML' },
        { source: 'scriptContents', regex: /GTM-[A-Z0-9]+/,                     weight: 0.45, evidence: 'GTM container ID found' },
        { source: 'globals',       regex: /\bgoogle_tag_manager\b/,              weight: 0.45, evidence: 'window.google_tag_manager global' },
        { source: 'html',          regex: /noscript[^>]*googletagmanager/i,      weight: 0.35, evidence: 'GTM noscript fallback iframe' },
      ],
      requiredMatches: 1,
    },

    /* ── Hotjar ────────────────────────────────────────────────────── */
    {
      name: 'Hotjar',
      icon: '🔥',
      patterns: [
        { source: 'scriptSrcs',    regex: /static\.hotjar\.com/i,                weight: 0.55, evidence: 'Hotjar tracking script loaded' },
        { source: 'resourceUrls',  regex: /hotjar\.com/i,                        weight: 0.55, evidence: 'Hotjar resources loaded' },
        { source: 'html',          regex: /static\.hotjar\.com/i,                weight: 0.45, evidence: 'Hotjar script reference in HTML' },
        { source: 'globals',       regex: /\bhj\b/,                              weight: 0.40, evidence: 'window.hj function present' },
        { source: 'html',          regex: /_hjSettings/,                         weight: 0.40, evidence: '_hjSettings configuration found' },
        { source: 'scriptContents', regex: /hotjar/i,                            weight: 0.30, evidence: 'Hotjar reference in inline script' },
      ],
      requiredMatches: 1,
    },

    /* ── Mixpanel ──────────────────────────────────────────────────── */
    {
      name: 'Mixpanel',
      icon: '🟣',
      patterns: [
        { source: 'scriptSrcs',    regex: /cdn\.mxpnl\.com/i,                   weight: 0.55, evidence: 'Mixpanel CDN script loaded' },
        { source: 'resourceUrls',  regex: /mxpnl\.com/i,                        weight: 0.55, evidence: 'Mixpanel CDN resources loaded' },
        { source: 'resourceUrls',  regex: /api\.mixpanel\.com/i,                weight: 0.50, evidence: 'Mixpanel API resources loaded' },
        { source: 'html',          regex: /cdn\.mxpnl\.com/i,                   weight: 0.45, evidence: 'Mixpanel CDN reference in HTML' },
        { source: 'globals',       regex: /\bmixpanel\b/,                        weight: 0.50, evidence: 'window.mixpanel global present' },
        { source: 'scriptContents', regex: /mixpanel\.init/i,                    weight: 0.45, evidence: 'mixpanel.init() call found' },
      ],
      requiredMatches: 1,
    },

    /* ── PostHog ───────────────────────────────────────────────────── */
    {
      name: 'PostHog',
      icon: '🦔',
      patterns: [
        { source: 'scriptSrcs',    regex: /posthog\.com/i,                       weight: 0.55, evidence: 'PostHog script loaded' },
        { source: 'resourceUrls',  regex: /posthog\.com/i,                       weight: 0.55, evidence: 'PostHog resources loaded' },
        { source: 'html',          regex: /posthog\.com/i,                       weight: 0.40, evidence: 'PostHog reference in HTML' },
        { source: 'globals',       regex: /\bposthog\b/,                         weight: 0.50, evidence: 'window.posthog global present' },
        { source: 'scriptContents', regex: /posthog\.init/i,                     weight: 0.45, evidence: 'posthog.init() call found' },
      ],
      requiredMatches: 1,
    },

    /* ── Plausible ─────────────────────────────────────────────────── */
    {
      name: 'Plausible',
      icon: '📈',
      patterns: [
        { source: 'scriptSrcs',    regex: /plausible\.io\/js\//i,               weight: 0.55, evidence: 'Plausible analytics script loaded' },
        { source: 'resourceUrls',  regex: /plausible\.io/i,                     weight: 0.55, evidence: 'Plausible resources loaded' },
        { source: 'html',          regex: /plausible\.io\/js/i,                 weight: 0.45, evidence: 'Plausible script reference in HTML' },
        { source: 'globals',       regex: /\bplausible\b/,                       weight: 0.40, evidence: 'window.plausible global' },
      ],
      requiredMatches: 1,
    },

    /* ── Segment ───────────────────────────────────────────────────── */
    {
      name: 'Segment',
      icon: '🟢',
      patterns: [
        { source: 'scriptSrcs',    regex: /cdn\.segment\.com/i,                  weight: 0.55, evidence: 'Segment CDN script loaded' },
        { source: 'resourceUrls',  regex: /segment\.com/i,                       weight: 0.50, evidence: 'Segment resources loaded' },
        { source: 'html',          regex: /cdn\.segment\.com/i,                  weight: 0.45, evidence: 'Segment CDN reference in HTML' },
        { source: 'scriptContents', regex: /analytics\.identify/i,               weight: 0.35, evidence: 'analytics.identify() call found' },
        { source: 'resourceUrls',  regex: /api\.segment\.io/i,                   weight: 0.50, evidence: 'Segment API endpoint' },
      ],
      requiredMatches: 1,
    },

    /* ── FullStory ─────────────────────────────────────────────────── */
    {
      name: 'FullStory',
      icon: '📹',
      patterns: [
        { source: 'scriptSrcs',    regex: /fullstory\.com/i,                     weight: 0.55, evidence: 'FullStory script loaded' },
        { source: 'resourceUrls',  regex: /fullstory\.com/i,                     weight: 0.55, evidence: 'FullStory resources loaded' },
        { source: 'html',          regex: /fullstory\.com\/s\/fs\.js/i,          weight: 0.50, evidence: 'FullStory script reference in HTML' },
        { source: 'globals',       regex: /\bFS\b/,                              weight: 0.30, evidence: 'window.FS global (FullStory)' },
        { source: 'resourceUrls',  regex: /edge\.fullstory\.com/i,               weight: 0.50, evidence: 'FullStory edge resources' },
      ],
      requiredMatches: 1,
    },

    /* ── Microsoft Clarity ─────────────────────────────────────────── */
    {
      name: 'Microsoft Clarity',
      icon: '🔍',
      patterns: [
        { source: 'scriptSrcs',    regex: /clarity\.ms\/tag\//i,                 weight: 0.55, evidence: 'Microsoft Clarity script loaded' },
        { source: 'resourceUrls',  regex: /clarity\.ms/i,                        weight: 0.55, evidence: 'Clarity resources loaded' },
        { source: 'html',          regex: /clarity\.ms\/tag/i,                   weight: 0.50, evidence: 'Clarity script reference in HTML' },
        { source: 'globals',       regex: /\bclarity\b/,                         weight: 0.35, evidence: 'window.clarity global' },
        { source: 'scriptContents', regex: /clarity\s*\(\s*["']set["']/i,        weight: 0.40, evidence: 'clarity("set") call found' },
      ],
      requiredMatches: 1,
    },

    /* ── Meta Pixel (Facebook) ─────────────────────────────────────── */
    {
      name: 'Meta Pixel',
      icon: '📘',
      patterns: [
        { source: 'scriptSrcs',    regex: /connect\.facebook\.net\/[^/]+\/fbevents\.js/i, weight: 0.55, evidence: 'Meta Pixel fbevents.js script' },
        { source: 'resourceUrls',  regex: /facebook\.net.*fbevents/i,            weight: 0.55, evidence: 'Meta Pixel resources loaded' },
        { source: 'html',          regex: /fbevents\.js/i,                       weight: 0.45, evidence: 'fbevents.js reference in HTML' },
        { source: 'globals',       regex: /\bfbq\b/,                             weight: 0.50, evidence: 'window.fbq tracking function' },
        { source: 'scriptContents', regex: /fbq\(\s*['"]init['"]/i,              weight: 0.45, evidence: 'fbq("init") call found' },
        { source: 'html',          regex: /facebook\.com\/tr\?/i,                weight: 0.40, evidence: 'Meta tracking pixel URL' },
        { source: 'resourceUrls',  regex: /facebook\.com\/tr\?/i,                weight: 0.45, evidence: 'Meta tracking pixel in resources' },
      ],
      requiredMatches: 1,
    },
  ];
})();
