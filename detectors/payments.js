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

    /* ══════════════════════════════════════════════════════════════════
     *  NEW ADDITIONS BELOW
     * ══════════════════════════════════════════════════════════════════ */

    /* ── Square ────────────────────────────────────────────────────── */
    {
      name: 'Square',
      icon: '⬜',
      patterns: [
        { source: 'scriptSrcs',    regex: /squareup\.com/i,                      weight: 0.55, evidence: 'Square script from squareup.com' },
        { source: 'resourceUrls',  regex: /squareup\.com|square\.site/i,         weight: 0.50, evidence: 'Square resources loaded' },
        { source: 'globals',       regex: /\bSquare\b/,                          weight: 0.40, evidence: 'window.Square global' },
        { source: 'scriptSrcs',    regex: /web\/v1\/square\.js/i,                weight: 0.55, evidence: 'Square Web Payments SDK' },
      ],
      requiredMatches: 1,
    },

    /* ── Braintree ─────────────────────────────────────────────────── */
    {
      name: 'Braintree',
      icon: '🌳',
      patterns: [
        { source: 'scriptSrcs',    regex: /braintreegateway\.com|braintree-api/i, weight: 0.55, evidence: 'Braintree gateway script loaded' },
        { source: 'resourceUrls',  regex: /braintreegateway\.com|braintree/i,    weight: 0.50, evidence: 'Braintree resources loaded' },
        { source: 'globals',       regex: /\bbraintree\b/,                       weight: 0.50, evidence: 'window.braintree global' },
        { source: 'html',          regex: /braintree/i,                          weight: 0.25, evidence: 'Braintree reference in HTML' },
        { source: 'scriptSrcs',    regex: /js\.braintreegateway\.com/i,          weight: 0.55, evidence: 'Braintree JS SDK loaded' },
      ],
      requiredMatches: 1,
    },

    /* ── Adyen ─────────────────────────────────────────────────────── */
    {
      name: 'Adyen',
      icon: '💚',
      patterns: [
        { source: 'scriptSrcs',    regex: /checkoutshopper.*adyen/i,             weight: 0.55, evidence: 'Adyen checkout script loaded' },
        { source: 'resourceUrls',  regex: /adyen\.com/i,                         weight: 0.50, evidence: 'Adyen resources loaded' },
        { source: 'globals',       regex: /\bAdyenCheckout\b/,                   weight: 0.55, evidence: 'window.AdyenCheckout global' },
        { source: 'linkHrefs',     regex: /adyen/i,                              weight: 0.35, evidence: 'Adyen stylesheet loaded' },
        { source: 'html',          regex: /adyen-checkout/i,                     weight: 0.45, evidence: 'Adyen checkout element in DOM' },
      ],
      requiredMatches: 1,
    },

    /* ── Klarna ────────────────────────────────────────────────────── */
    {
      name: 'Klarna',
      icon: '🩷',
      patterns: [
        { source: 'scriptSrcs',    regex: /klarna\.com/i,                        weight: 0.55, evidence: 'Klarna script loaded' },
        { source: 'resourceUrls',  regex: /klarna\.com/i,                        weight: 0.50, evidence: 'Klarna resources loaded' },
        { source: 'globals',       regex: /\bKlarna\b/,                          weight: 0.50, evidence: 'window.Klarna global' },
        { source: 'html',          regex: /klarna-placement|klarna-/i,           weight: 0.40, evidence: 'Klarna element in DOM' },
      ],
      requiredMatches: 1,
    },

    /* ── Afterpay / Clearpay ───────────────────────────────────────── */
    {
      name: 'Afterpay',
      icon: '🟢',
      patterns: [
        { source: 'scriptSrcs',    regex: /afterpay\.com|clearpay\.com/i,        weight: 0.55, evidence: 'Afterpay/Clearpay script loaded' },
        { source: 'resourceUrls',  regex: /afterpay|clearpay/i,                  weight: 0.50, evidence: 'Afterpay/Clearpay resources loaded' },
        { source: 'globals',       regex: /\bAfterpay\b/,                        weight: 0.50, evidence: 'window.Afterpay global' },
        { source: 'html',          regex: /afterpay-placement|afterpay-/i,       weight: 0.40, evidence: 'Afterpay element in DOM' },
      ],
      requiredMatches: 1,
    },

    /* ── Apple Pay ─────────────────────────────────────────────────── */
    {
      name: 'Apple Pay',
      icon: '🍎',
      patterns: [
        { source: 'scriptSrcs',    regex: /apple-pay-sdk|applepay/i,             weight: 0.55, evidence: 'Apple Pay SDK loaded' },
        { source: 'globals',       regex: /\bApplePaySession\b/,                 weight: 0.50, evidence: 'window.ApplePaySession available' },
        { source: 'html',          regex: /apple-pay-button/i,                   weight: 0.50, evidence: 'Apple Pay button element' },
        { source: 'resourceUrls',  regex: /apple\.com\/apple-pay/i,              weight: 0.45, evidence: 'Apple Pay resources loaded' },
        { source: 'linkHrefs',     regex: /apple-pay/i,                          weight: 0.30, evidence: 'Apple Pay stylesheet reference' },
      ],
      requiredMatches: 1,
    },

    /* ── Google Pay ────────────────────────────────────────────────── */
    {
      name: 'Google Pay',
      icon: '🔵',
      patterns: [
        { source: 'scriptSrcs',    regex: /pay\.google\.com/i,                   weight: 0.55, evidence: 'Google Pay script loaded' },
        { source: 'resourceUrls',  regex: /pay\.google\.com/i,                   weight: 0.50, evidence: 'Google Pay resources loaded' },
        { source: 'globals',       regex: /\bgoogle\.payments/,                  weight: 0.50, evidence: 'google.payments namespace' },
        { source: 'html',          regex: /gpay-button|google-pay-button/i,      weight: 0.50, evidence: 'Google Pay button element' },
      ],
      requiredMatches: 1,
    },
  ];
})();
