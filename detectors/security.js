/**
 * TechStack Detector — Security & Monitoring Signatures
 *
 * Detects CAPTCHAs, error tracking, and APM tools.
 * Uses scriptSrcs, resourceUrls, globals, AND html fallback patterns
 * to catch both static and dynamically loaded scripts.
 */
(() => {
  'use strict';
  self.TechDetectors = self.TechDetectors || {};

  self.TechDetectors.security = [
    /* ── reCAPTCHA ─────────────────────────────────────────────────── */
    {
      name: 'reCAPTCHA',
      icon: '🛡️',
      patterns: [
        { source: 'scriptSrcs',    regex: /google\.com\/recaptcha\//i,          weight: 0.55, evidence: 'Google reCAPTCHA script loaded' },
        { source: 'resourceUrls',  regex: /google\.com\/recaptcha/i,            weight: 0.55, evidence: 'reCAPTCHA resources loaded' },
        { source: 'html',          regex: /google\.com\/recaptcha/i,            weight: 0.45, evidence: 'reCAPTCHA script reference in HTML' },
        { source: 'globals',       regex: /\bgrecaptcha\b/,                     weight: 0.50, evidence: 'window.grecaptcha global' },
        { source: 'html',          regex: /class="g-recaptcha"/,                weight: 0.45, evidence: 'g-recaptcha widget element' },
        { source: 'html',          regex: /data-sitekey=/,                      weight: 0.20, evidence: 'reCAPTCHA data-sitekey attribute' },
      ],
      requiredMatches: 1,
    },

    /* ── hCaptcha ──────────────────────────────────────────────────── */
    {
      name: 'hCaptcha',
      icon: '🔐',
      patterns: [
        { source: 'scriptSrcs',    regex: /hcaptcha\.com\/1\/api\.js/i,         weight: 0.55, evidence: 'hCaptcha API script loaded' },
        { source: 'resourceUrls',  regex: /hcaptcha\.com/i,                     weight: 0.55, evidence: 'hCaptcha resources loaded' },
        { source: 'html',          regex: /hcaptcha\.com\/1\/api\.js/i,         weight: 0.45, evidence: 'hCaptcha script reference in HTML' },
        { source: 'globals',       regex: /\bhcaptcha\b/,                       weight: 0.50, evidence: 'window.hcaptcha global' },
        { source: 'html',          regex: /class="h-captcha"/,                  weight: 0.45, evidence: 'h-captcha widget element' },
      ],
      requiredMatches: 1,
    },

    /* ── Cloudflare Turnstile ──────────────────────────────────────── */
    {
      name: 'Cloudflare Turnstile',
      icon: '☁️',
      patterns: [
        { source: 'scriptSrcs',    regex: /challenges\.cloudflare\.com\/turnstile/i, weight: 0.55, evidence: 'Cloudflare Turnstile script loaded' },
        { source: 'resourceUrls',  regex: /challenges\.cloudflare\.com\/turnstile/i, weight: 0.55, evidence: 'Turnstile resources loaded' },
        { source: 'html',          regex: /challenges\.cloudflare\.com\/turnstile/i, weight: 0.45, evidence: 'Turnstile script reference in HTML' },
        { source: 'html',          regex: /class="cf-turnstile"/,               weight: 0.50, evidence: 'cf-turnstile widget element' },
      ],
      requiredMatches: 1,
    },

    /* ── Sentry ────────────────────────────────────────────────────── */
    {
      name: 'Sentry',
      icon: '🐛',
      patterns: [
        { source: 'scriptSrcs',    regex: /browser\.sentry-cdn\.com/i,          weight: 0.55, evidence: 'Sentry browser SDK loaded from CDN' },
        { source: 'resourceUrls',  regex: /sentry-cdn\.com/i,                   weight: 0.55, evidence: 'Sentry CDN resources loaded' },
        { source: 'resourceUrls',  regex: /sentry\.io/i,                        weight: 0.45, evidence: 'Sentry.io resources loaded' },
        { source: 'html',          regex: /sentry-cdn\.com/i,                   weight: 0.40, evidence: 'Sentry CDN reference in HTML' },
        { source: 'globals',       regex: /\bSentry\b/,                         weight: 0.50, evidence: 'window.Sentry global present' },
        { source: 'globals',       regex: /\b__SENTRY__\b/,                     weight: 0.50, evidence: 'window.__SENTRY__ global present' },
        { source: 'scriptContents', regex: /Sentry\.init/i,                     weight: 0.40, evidence: 'Sentry.init() call in script' },
        { source: 'headers',       regex: /sentry-trace/i,                      weight: 0.45, evidence: 'sentry-trace header' },
        { source: 'html',          regex: /sentry[^a-z]*\.js/i,                weight: 0.30, evidence: 'Sentry JS bundle reference in HTML' },
      ],
      requiredMatches: 1,
    },

    /* ── Datadog ───────────────────────────────────────────────────── */
    {
      name: 'Datadog',
      icon: '🐶',
      patterns: [
        { source: 'scriptSrcs',    regex: /datadoghq\.com/i,                    weight: 0.55, evidence: 'Datadog script from datadoghq.com' },
        { source: 'resourceUrls',  regex: /datadoghq\.com/i,                    weight: 0.55, evidence: 'Datadog resources loaded' },
        { source: 'html',          regex: /datadoghq\.com/i,                    weight: 0.40, evidence: 'Datadog reference in HTML' },
        { source: 'globals',       regex: /\bDD_RUM\b/,                         weight: 0.55, evidence: 'window.DD_RUM global (Datadog RUM)' },
        { source: 'scriptContents', regex: /DD_RUM\.init/i,                     weight: 0.45, evidence: 'DD_RUM.init() call in script' },
        { source: 'resourceUrls',  regex: /datadog-rum/i,                       weight: 0.45, evidence: 'Datadog RUM resources loaded' },
      ],
      requiredMatches: 1,
    },

    /* ── New Relic ──────────────────────────────────────────────────── */
    {
      name: 'New Relic',
      icon: '🟢',
      patterns: [
        { source: 'scriptSrcs',    regex: /js-agent\.newrelic\.com/i,            weight: 0.55, evidence: 'New Relic JS agent loaded' },
        { source: 'resourceUrls',  regex: /newrelic\.com/i,                      weight: 0.50, evidence: 'New Relic resources loaded' },
        { source: 'html',          regex: /js-agent\.newrelic\.com/i,            weight: 0.45, evidence: 'New Relic agent reference in HTML' },
        { source: 'globals',       regex: /\bNREUM\b/,                           weight: 0.50, evidence: 'window.NREUM global (New Relic)' },
        { source: 'globals',       regex: /\bnewrelic\b/,                        weight: 0.45, evidence: 'window.newrelic global' },
        { source: 'scriptContents', regex: /NREUM/,                              weight: 0.35, evidence: 'NREUM in inline script' },
      ],
      requiredMatches: 1,
    },
  ];
})();
