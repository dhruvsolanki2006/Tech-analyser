/**
 * TechStack Detector — Tag Managers & Consent Management Signatures
 *
 * Detects tag management systems and GDPR/CCPA consent management
 * platforms via script URLs, cookies, and DOM patterns.
 */
(() => {
  'use strict';
  self.TechDetectors = self.TechDetectors || {};

  self.TechDetectors.tagmanagers = [
    /* ── Tealium ───────────────────────────────────────────────────── */
    {
      name: 'Tealium',
      icon: '🏷️',
      patterns: [
        { source: 'scriptSrcs',    regex: /tags\.tiqcdn\.com/i,                 weight: 0.55, evidence: 'Tealium tag script loaded' },
        { source: 'resourceUrls',  regex: /tiqcdn\.com/i,                       weight: 0.55, evidence: 'Tealium CDN resources loaded' },
        { source: 'globals',       regex: /\butag\b/,                           weight: 0.50, evidence: 'window.utag global (Tealium)' },
        { source: 'scriptContents', regex: /utag\.track/i,                      weight: 0.40, evidence: 'utag.track() call found' },
        { source: 'html',          regex: /tiqcdn\.com/i,                       weight: 0.40, evidence: 'Tealium CDN reference in HTML' },
      ],
      requiredMatches: 1,
    },

    /* ── OneTrust ──────────────────────────────────────────────────── */
    {
      name: 'OneTrust',
      icon: '🔒',
      patterns: [
        { source: 'scriptSrcs',    regex: /cdn\.cookielaw\.org|onetrust/i,      weight: 0.55, evidence: 'OneTrust/CookieLaw script loaded' },
        { source: 'resourceUrls',  regex: /cookielaw\.org|onetrust/i,           weight: 0.55, evidence: 'OneTrust resources loaded' },
        { source: 'globals',       regex: /\bOneTrust\b/,                       weight: 0.55, evidence: 'window.OneTrust global' },
        { source: 'globals',       regex: /\bOptanonWrapper\b/,                 weight: 0.50, evidence: 'OptanonWrapper function (OneTrust)' },
        { source: 'cookies',       regex: /\bOptanonConsent\b/,                 weight: 0.50, evidence: 'OptanonConsent cookie' },
        { source: 'html',          regex: /onetrust-consent/i,                  weight: 0.40, evidence: 'OneTrust consent elements in DOM' },
      ],
      requiredMatches: 1,
    },

    /* ── Cookiebot ─────────────────────────────────────────────────── */
    {
      name: 'Cookiebot',
      icon: '🍪',
      patterns: [
        { source: 'scriptSrcs',    regex: /consent\.cookiebot\.com/i,           weight: 0.55, evidence: 'Cookiebot consent script loaded' },
        { source: 'resourceUrls',  regex: /cookiebot\.com/i,                    weight: 0.55, evidence: 'Cookiebot resources loaded' },
        { source: 'globals',       regex: /\bCookiebot\b/,                      weight: 0.55, evidence: 'window.Cookiebot global' },
        { source: 'cookies',       regex: /\bCookieConsent\b/,                  weight: 0.40, evidence: 'CookieConsent cookie' },
        { source: 'html',          regex: /cookiebot|CookiebotDialog/i,         weight: 0.40, evidence: 'Cookiebot elements in DOM' },
      ],
      requiredMatches: 1,
    },

    /* ── TrustArc ──────────────────────────────────────────────────── */
    {
      name: 'TrustArc',
      icon: '🛡️',
      patterns: [
        { source: 'scriptSrcs',    regex: /consent\.trustarc\.com/i,            weight: 0.55, evidence: 'TrustArc consent script loaded' },
        { source: 'resourceUrls',  regex: /trustarc\.com/i,                     weight: 0.50, evidence: 'TrustArc resources loaded' },
        { source: 'html',          regex: /trustarc|truste/i,                   weight: 0.35, evidence: 'TrustArc reference in HTML' },
        { source: 'cookies',       regex: /\bnotice_preferences\b/,             weight: 0.35, evidence: 'TrustArc notice_preferences cookie' },
        { source: 'html',          regex: /consent\.trustarc\.com/i,            weight: 0.45, evidence: 'TrustArc consent iframe' },
      ],
      requiredMatches: 1,
    },

    /* ── Osano ─────────────────────────────────────────────────────── */
    {
      name: 'Osano',
      icon: '🔒',
      patterns: [
        { source: 'scriptSrcs',    regex: /cmp\.osano\.com/i,                   weight: 0.55, evidence: 'Osano CMP script loaded' },
        { source: 'resourceUrls',  regex: /osano\.com/i,                        weight: 0.50, evidence: 'Osano resources loaded' },
        { source: 'globals',       regex: /\bOsano\b/,                          weight: 0.55, evidence: 'window.Osano global' },
        { source: 'html',          regex: /osano/i,                             weight: 0.30, evidence: 'Osano reference in HTML' },
      ],
      requiredMatches: 1,
    },

    /* ── Usercentrics ──────────────────────────────────────────────── */
    {
      name: 'Usercentrics',
      icon: '🔐',
      patterns: [
        { source: 'scriptSrcs',    regex: /usercentrics/i,                      weight: 0.55, evidence: 'Usercentrics script loaded' },
        { source: 'resourceUrls',  regex: /usercentrics/i,                      weight: 0.50, evidence: 'Usercentrics resources loaded' },
        { source: 'globals',       regex: /\bUC_UI\b/,                          weight: 0.55, evidence: 'window.UC_UI global (Usercentrics)' },
        { source: 'html',          regex: /usercentrics/i,                      weight: 0.35, evidence: 'Usercentrics reference in HTML' },
        { source: 'cookies',       regex: /\buc_user_interaction\b/,            weight: 0.45, evidence: 'Usercentrics interaction cookie' },
      ],
      requiredMatches: 1,
    },

    /* ── Didomi ────────────────────────────────────────────────────── */
    {
      name: 'Didomi',
      icon: '🛡️',
      patterns: [
        { source: 'scriptSrcs',    regex: /sdk\.privacy-center\.org|didomi/i,   weight: 0.55, evidence: 'Didomi consent script loaded' },
        { source: 'resourceUrls',  regex: /didomi/i,                            weight: 0.50, evidence: 'Didomi resources loaded' },
        { source: 'globals',       regex: /\bDidomi\b/,                         weight: 0.55, evidence: 'window.Didomi global' },
        { source: 'html',          regex: /didomi/i,                            weight: 0.30, evidence: 'Didomi reference in HTML' },
        { source: 'cookies',       regex: /\bdidomi_token\b/,                   weight: 0.50, evidence: 'Didomi token cookie' },
      ],
      requiredMatches: 1,
    },

    /* ── Cookie Notice (Generic GDPR Banners) ──────────────────────── */
    {
      name: 'Cookie Notice',
      icon: '🍪',
      patterns: [
        { source: 'html',          regex: /id="cookie-notice"|class="cookie-notice"/i, weight: 0.45, evidence: 'Cookie notice banner element' },
        { source: 'html',          regex: /class="[^"]*cookie-consent|cookie-banner/i, weight: 0.35, evidence: 'Cookie consent/banner class' },
        { source: 'cookies',       regex: /\bcookie_notice_accepted\b/,         weight: 0.50, evidence: 'cookie_notice_accepted cookie' },
        { source: 'scriptSrcs',    regex: /cookie-notice|cookie-consent/i,      weight: 0.45, evidence: 'Cookie notice/consent script' },
      ],
      requiredMatches: 2,
    },
  ];
})();
