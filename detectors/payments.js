/**
 * TechStack Detector — Payment Provider Signatures
 *
 * Uses CDN-specific script URLs, resource timing, globals, AND
 * raw HTML fallback patterns to catch both static and dynamically
 * loaded payment SDK scripts.
 */
(() => {
  'use strict';
  self.TechDetectors = self.TechDetectors || {};

  self.TechDetectors.payments = [
    /* ── Stripe ────────────────────────────────────────────────────── */
    {
      name: 'Stripe',
      icon: '💳',
      patterns: [
        { source: 'scriptSrcs',    regex: /js\.stripe\.com\/v3/i,               weight: 0.55, evidence: 'Stripe.js v3 script loaded' },
        { source: 'resourceUrls',  regex: /js\.stripe\.com/i,                   weight: 0.55, evidence: 'Stripe.js resources loaded' },
        { source: 'html',          regex: /js\.stripe\.com\/v3/i,               weight: 0.50, evidence: 'Stripe.js v3 reference in HTML' },
        { source: 'globals',       regex: /\bStripe\b/,                          weight: 0.50, evidence: 'window.Stripe constructor present' },
        { source: 'html',          regex: /stripe-button/i,                      weight: 0.35, evidence: 'Stripe checkout button element' },
        { source: 'scriptContents', regex: /Stripe\(\s*['"]pk_/i,               weight: 0.50, evidence: 'Stripe() initialized with publishable key' },
        { source: 'resourceUrls',  regex: /stripe\.com/i,                        weight: 0.30, evidence: 'Stripe domain in resources' },
        { source: 'html',          regex: /stripe-payment-element/i,             weight: 0.45, evidence: 'Stripe Payment Element in DOM' },
      ],
      requiredMatches: 1,
    },

    /* ── PayPal ────────────────────────────────────────────────────── */
    {
      name: 'PayPal',
      icon: '🅿️',
      patterns: [
        { source: 'scriptSrcs',    regex: /paypal\.com\/sdk\/js/i,               weight: 0.55, evidence: 'PayPal SDK script loaded' },
        { source: 'resourceUrls',  regex: /paypal\.com\/sdk/i,                   weight: 0.55, evidence: 'PayPal SDK resources loaded' },
        { source: 'html',          regex: /paypal\.com\/sdk\/js/i,               weight: 0.50, evidence: 'PayPal SDK reference in HTML' },
        { source: 'globals',       regex: /\bPayPal\b/,                          weight: 0.50, evidence: 'window.PayPal global present' },
        { source: 'html',          regex: /paypal-button/i,                      weight: 0.40, evidence: 'PayPal button element' },
        { source: 'scriptSrcs',    regex: /paypalobjects\.com/i,                 weight: 0.50, evidence: 'Script from paypalobjects.com' },
        { source: 'resourceUrls',  regex: /paypalobjects\.com/i,                 weight: 0.45, evidence: 'PayPal objects CDN resources' },
      ],
      requiredMatches: 1,
    },

    /* ── Razorpay ──────────────────────────────────────────────────── */
    {
      name: 'Razorpay',
      icon: '💰',
      patterns: [
        { source: 'scriptSrcs',    regex: /checkout\.razorpay\.com/i,             weight: 0.55, evidence: 'Razorpay checkout script loaded' },
        { source: 'resourceUrls',  regex: /razorpay\.com/i,                       weight: 0.55, evidence: 'Razorpay resources loaded' },
        { source: 'html',          regex: /checkout\.razorpay\.com/i,             weight: 0.50, evidence: 'Razorpay checkout reference in HTML' },
        { source: 'globals',       regex: /\bRazorpay\b/,                         weight: 0.50, evidence: 'window.Razorpay constructor present' },
        { source: 'scriptContents', regex: /Razorpay\(/i,                         weight: 0.45, evidence: 'Razorpay() instantiation in script' },
      ],
      requiredMatches: 1,
    },
  ];
})();
