/**
 * TechStack Detector — Security & Monitoring Signatures
 *
 * Detects CAPTCHAs, error tracking, APM tools, and WAF services.
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

    /* ══════════════════════════════════════════════════════════════════
     *  NEW ADDITIONS BELOW
     * ══════════════════════════════════════════════════════════════════ */

    /* ── Bugsnag ───────────────────────────────────────────────────── */
    {
      name: 'Bugsnag',
      icon: '🐛',
      patterns: [
        { source: 'scriptSrcs',    regex: /d2wy8f7a9ursnm\.cloudfront\.net.*bugsnag|bugsnag(?:\.min)?\.js/i, weight: 0.55, evidence: 'Bugsnag script loaded' },
        { source: 'resourceUrls',  regex: /bugsnag/i,                            weight: 0.45, evidence: 'Bugsnag resources loaded' },
        { source: 'globals',       regex: /\bBugsnag\b/,                         weight: 0.55, evidence: 'window.Bugsnag global present' },
        { source: 'scriptContents', regex: /Bugsnag\.start/i,                    weight: 0.45, evidence: 'Bugsnag.start() call' },
      ],
      requiredMatches: 1,
    },

    /* ── LogRocket ─────────────────────────────────────────────────── */
    {
      name: 'LogRocket',
      icon: '🚀',
      patterns: [
        { source: 'scriptSrcs',    regex: /cdn\.logrocket\.(?:com|io)/i,         weight: 0.55, evidence: 'LogRocket CDN script loaded' },
        { source: 'resourceUrls',  regex: /logrocket\.com|logrocket\.io/i,       weight: 0.55, evidence: 'LogRocket resources loaded' },
        { source: 'globals',       regex: /\bLogRocket\b/,                       weight: 0.55, evidence: 'window.LogRocket global' },
        { source: 'scriptContents', regex: /LogRocket\.init/i,                   weight: 0.45, evidence: 'LogRocket.init() call' },
      ],
      requiredMatches: 1,
    },

    /* ── Rollbar ───────────────────────────────────────────────────── */
    {
      name: 'Rollbar',
      icon: '📋',
      patterns: [
        { source: 'scriptSrcs',    regex: /cdn\.rollbar\.com/i,                  weight: 0.55, evidence: 'Rollbar CDN script loaded' },
        { source: 'resourceUrls',  regex: /rollbar\.com/i,                       weight: 0.50, evidence: 'Rollbar resources loaded' },
        { source: 'globals',       regex: /\bRollbar\b/,                         weight: 0.55, evidence: 'window.Rollbar global' },
        { source: 'scriptContents', regex: /rollbar\.init|_rollbarConfig/i,      weight: 0.45, evidence: 'Rollbar init or config in script' },
      ],
      requiredMatches: 1,
    },

    /* ── Raygun ────────────────────────────────────────────────────── */
    {
      name: 'Raygun',
      icon: '🔫',
      patterns: [
        { source: 'scriptSrcs',    regex: /cdn\.raygun\.io|raygun4js/i,          weight: 0.55, evidence: 'Raygun script loaded' },
        { source: 'resourceUrls',  regex: /raygun\.io|raygun\.com/i,             weight: 0.50, evidence: 'Raygun resources loaded' },
        { source: 'globals',       regex: /\brg4js\b/,                           weight: 0.50, evidence: 'window.rg4js global (Raygun)' },
        { source: 'scriptContents', regex: /raygun4js|rg4js/i,                   weight: 0.40, evidence: 'Raygun in inline script' },
      ],
      requiredMatches: 1,
    },

    /* ── Dynatrace ─────────────────────────────────────────────────── */
    {
      name: 'Dynatrace',
      icon: '🔷',
      patterns: [
        { source: 'scriptSrcs',    regex: /dynatrace/i,                          weight: 0.50, evidence: 'Dynatrace script loaded' },
        { source: 'resourceUrls',  regex: /dynatrace/i,                          weight: 0.45, evidence: 'Dynatrace resources loaded' },
        { source: 'globals',       regex: /\bdtrum\b/,                           weight: 0.55, evidence: 'window.dtrum global (Dynatrace RUM)' },
        { source: 'scriptContents', regex: /dtrum/i,                             weight: 0.40, evidence: 'Dynatrace dtrum in inline script' },
        { source: 'html',          regex: /dynatrace/i,                          weight: 0.30, evidence: 'Dynatrace reference in HTML' },
      ],
      requiredMatches: 1,
    },

    /* ── AppDynamics ───────────────────────────────────────────────── */
    {
      name: 'AppDynamics',
      icon: '📱',
      patterns: [
        { source: 'scriptSrcs',    regex: /appdynamics/i,                        weight: 0.55, evidence: 'AppDynamics script loaded' },
        { source: 'resourceUrls',  regex: /appdynamics/i,                        weight: 0.50, evidence: 'AppDynamics resources loaded' },
        { source: 'globals',       regex: /\bADRUM\b/,                           weight: 0.55, evidence: 'window.ADRUM global (AppDynamics RUM)' },
        { source: 'scriptContents', regex: /ADRUM/,                              weight: 0.40, evidence: 'AppDynamics ADRUM in inline script' },
      ],
      requiredMatches: 1,
    },

    /* ── Elastic APM ───────────────────────────────────────────────── */
    {
      name: 'Elastic APM',
      icon: '🟡',
      patterns: [
        { source: 'scriptSrcs',    regex: /elastic-apm-rum/i,                    weight: 0.55, evidence: 'Elastic APM RUM script loaded' },
        { source: 'resourceUrls',  regex: /elastic.*apm/i,                       weight: 0.45, evidence: 'Elastic APM resources loaded' },
        { source: 'globals',       regex: /\belasticApm\b/,                      weight: 0.55, evidence: 'window.elasticApm global' },
        { source: 'scriptContents', regex: /elasticApm\.init/i,                  weight: 0.45, evidence: 'elasticApm.init() call' },
      ],
      requiredMatches: 1,
    },

    /* ── Imperva WAF ───────────────────────────────────────────────── */
    {
      name: 'Imperva WAF',
      icon: '🔒',
      patterns: [
        { source: 'headers',       regex: /x-iinfo:/i,                           weight: 0.50, evidence: 'X-Iinfo header (Imperva WAF)' },
        { source: 'cookies',       regex: /\bvisid_incap_/,                      weight: 0.50, evidence: 'Incapsula visitor cookie' },
        { source: 'cookies',       regex: /\bincap_ses_/,                        weight: 0.50, evidence: 'Incapsula session cookie' },
        { source: 'headers',       regex: /x-cdn:\s*imperva/i,                  weight: 0.55, evidence: 'X-CDN: Imperva header' },
      ],
      requiredMatches: 1,
    },
  ];
})();
