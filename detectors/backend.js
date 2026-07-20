/**
 * TechStack Detector — Backend Framework Signatures (Inferred)
 *
 * Backend technologies cannot be definitively detected from the client.
 * These signatures look for publicly visible fingerprints only:
 *   • Specific cookies (e.g., laravel_session, JSESSIONID)
 *   • Hidden form inputs (e.g., __VIEWSTATE, csrfmiddlewaretoken)
 *   • Framework-specific meta tags and DOM patterns
 *   • Response headers (when available)
 *
 * Results are ALWAYS labeled "Inferred from public fingerprints."
 * Generic word matches (e.g., /express/i) are deliberately excluded.
 */
(() => {
  'use strict';
  self.TechDetectors = self.TechDetectors || {};

  self.TechDetectors.backend = [
    /* ── Express.js ────────────────────────────────────────────────── */
    {
      name: 'Express.js',
      icon: '🟢',
      inferred: true,
      patterns: [
        { source: 'headers',      regex: /x-powered-by:\s*express/i,           weight: 0.55, evidence: 'X-Powered-By: Express header' },
        { source: 'cookies',      regex: /\bconnect\.sid\b/,                   weight: 0.45, evidence: 'connect.sid session cookie (Express/Connect)' },
      ],
      requiredMatches: 1,
    },

    /* ── NestJS ────────────────────────────────────────────────────── */
    {
      name: 'NestJS',
      icon: '🐈',
      inferred: true,
      patterns: [
        { source: 'headers',      regex: /x-powered-by:\s*nestjs/i,            weight: 0.55, evidence: 'X-Powered-By: NestJS header' },
        { source: 'html',         regex: /nestjs/i,                            weight: 0.25, evidence: 'NestJS reference in page' },
        { source: 'scriptContents', regex: /nestjs/i,                          weight: 0.30, evidence: 'NestJS in inline scripts' },
      ],
      requiredMatches: 1,
    },

    /* ── Laravel ───────────────────────────────────────────────────── */
    {
      name: 'Laravel',
      icon: '🔴',
      inferred: true,
      patterns: [
        { source: 'cookies',      regex: /\blaravel_session\b/,                weight: 0.55, evidence: 'laravel_session cookie' },
        { source: 'cookies',      regex: /\bXSRF-TOKEN\b/,                    weight: 0.30, evidence: 'XSRF-TOKEN cookie (Laravel default)' },
        { source: 'html',         regex: /<meta[^>]+name="csrf-token"[^>]+content="/i, weight: 0.35, evidence: 'Laravel CSRF meta tag' },
        { source: 'html',         regex: /<input[^>]+name="_token"[^>]+type="hidden"/i, weight: 0.35, evidence: 'Laravel _token hidden input' },
        { source: 'scriptContents', regex: /laravel/i,                         weight: 0.15, evidence: 'laravel reference in inline script' },
      ],
      requiredMatches: 2,
    },

    /* ── Django ────────────────────────────────────────────────────── */
    {
      name: 'Django',
      icon: '🐍',
      inferred: true,
      patterns: [
        { source: 'html',         regex: /name="csrfmiddlewaretoken"/,         weight: 0.50, evidence: 'Django CSRF middleware token input' },
        { source: 'cookies',      regex: /\bcsrftoken\b/,                     weight: 0.40, evidence: 'Django csrftoken cookie' },
        { source: 'html',         regex: /djdt/,                              weight: 0.45, evidence: 'Django Debug Toolbar (djdt) present' },
        { source: 'headers',      regex: /x-frame-options:\s*(?:deny|sameorigin)/i, weight: 0.10, evidence: 'X-Frame-Options header (common in Django)' },
        { source: 'html',         regex: /\/static\/admin\//,                  weight: 0.35, evidence: 'Django admin static path' },
      ],
      requiredMatches: 2,
    },

    /* ── Flask ─────────────────────────────────────────────────────── */
    {
      name: 'Flask',
      icon: '🧪',
      inferred: true,
      patterns: [
        { source: 'headers',      regex: /server:\s*werkzeug/i,                weight: 0.55, evidence: 'Server: Werkzeug header (Flask dev)' },
        { source: 'headers',      regex: /x-powered-by:\s*flask/i,             weight: 0.55, evidence: 'X-Powered-By: Flask header' },
        { source: 'cookies',      regex: /\bsession=\.eJ/,                     weight: 0.40, evidence: 'Flask itsdangerous session cookie format' },
      ],
      requiredMatches: 1,
    },

    /* ── FastAPI ───────────────────────────────────────────────────── */
    {
      name: 'FastAPI',
      icon: '⚡',
      inferred: true,
      patterns: [
        { source: 'html',         regex: /fastapi/i,                           weight: 0.35, evidence: 'FastAPI reference in page' },
        { source: 'resourceUrls', regex: /\/openapi\.json/,                    weight: 0.30, evidence: '/openapi.json endpoint' },
        { source: 'html',         regex: /swagger-ui[^>]*fastapi/i,            weight: 0.50, evidence: 'Swagger UI with FastAPI branding' },
        { source: 'scriptContents', regex: /fastapi/i,                         weight: 0.30, evidence: 'FastAPI in inline scripts' },
      ],
      requiredMatches: 2,
    },

    /* ── Ruby on Rails ─────────────────────────────────────────────── */
    {
      name: 'Ruby on Rails',
      icon: '💎',
      inferred: true,
      patterns: [
        { source: 'html',         regex: /<meta[^>]+name="csrf-param"[^>]+content="authenticity_token"/i, weight: 0.55, evidence: 'Rails CSRF authenticity_token meta' },
        { source: 'html',         regex: /turbo-frame/,                        weight: 0.40, evidence: 'Turbo Frame element (Rails Hotwire)' },
        { source: 'html',         regex: /data-turbo-track/,                   weight: 0.35, evidence: 'data-turbo-track attribute (Turbo)' },
        { source: 'cookies',      regex: /\b_[a-z]+_session\b/,               weight: 0.20, evidence: 'Rails-style session cookie pattern' },
        { source: 'headers',      regex: /x-powered-by:\s*phusion passenger/i, weight: 0.45, evidence: 'Phusion Passenger header (Rails)' },
        { source: 'html',         regex: /data-controller=/,                   weight: 0.25, evidence: 'Stimulus controller attribute' },
      ],
      requiredMatches: 2,
    },

    /* ── Spring Boot ───────────────────────────────────────────────── */
    {
      name: 'Spring Boot',
      icon: '🌱',
      inferred: true,
      patterns: [
        { source: 'cookies',      regex: /\bJSESSIONID\b/,                    weight: 0.35, evidence: 'JSESSIONID cookie (Java servlet)' },
        { source: 'resourceUrls', regex: /\/actuator\//,                       weight: 0.45, evidence: 'Spring Boot Actuator endpoint' },
        { source: 'html',         regex: /springframework/i,                   weight: 0.40, evidence: 'Spring Framework reference' },
        { source: 'headers',      regex: /x-application-context/i,             weight: 0.50, evidence: 'X-Application-Context header' },
      ],
      requiredMatches: 2,
    },

    /* ── ASP.NET ───────────────────────────────────────────────────── */
    {
      name: 'ASP.NET',
      icon: '🟦',
      inferred: true,
      patterns: [
        { source: 'html',         regex: /__VIEWSTATE/,                        weight: 0.55, evidence: '__VIEWSTATE hidden field' },
        { source: 'html',         regex: /__RequestVerificationToken/,         weight: 0.45, evidence: 'ASP.NET anti-forgery token' },
        { source: 'headers',      regex: /x-powered-by:\s*asp\.net/i,          weight: 0.55, evidence: 'X-Powered-By: ASP.NET header' },
        { source: 'headers',      regex: /x-aspnet-version/i,                  weight: 0.55, evidence: 'X-AspNet-Version header' },
        { source: 'cookies',      regex: /\.aspnetcore\./i,                    weight: 0.40, evidence: '.AspNetCore session cookie' },
        { source: 'resourceUrls', regex: /\.aspx/i,                            weight: 0.35, evidence: '.aspx page extension' },
      ],
      requiredMatches: 1,
    },

    /* ── Phoenix (Elixir) ──────────────────────────────────────────── */
    {
      name: 'Phoenix',
      icon: '🦅',
      inferred: true,
      patterns: [
        { source: 'html',         regex: /phx-/,                               weight: 0.45, evidence: 'phx-* LiveView attribute' },
        { source: 'scriptContents', regex: /LiveSocket/i,                      weight: 0.50, evidence: 'Phoenix LiveSocket in script' },
        { source: 'html',         regex: /data-phx-main/,                     weight: 0.50, evidence: 'data-phx-main LiveView container' },
        { source: 'cookies',      regex: /\b_csrf_token\b/,                   weight: 0.20, evidence: 'Phoenix _csrf_token cookie' },
      ],
      requiredMatches: 2,
    },

    /* ── Symfony ────────────────────────────────────────────────────── */
    {
      name: 'Symfony',
      icon: '🎵',
      inferred: true,
      patterns: [
        { source: 'html',         regex: /sf-toolbar/i,                        weight: 0.55, evidence: 'Symfony profiler toolbar element' },
        { source: 'cookies',      regex: /\b_sf2_/,                            weight: 0.50, evidence: 'Symfony _sf2_ session cookie' },
        { source: 'html',         regex: /_wdt\//,                             weight: 0.35, evidence: 'Symfony web debug toolbar path' },
        { source: 'headers',      regex: /x-debug-token/i,                     weight: 0.50, evidence: 'X-Debug-Token header (Symfony)' },
      ],
      requiredMatches: 1,
    },

    /* ══════════════════════════════════════════════════════════════════
     *  NEW ADDITIONS BELOW
     * ══════════════════════════════════════════════════════════════════ */

    /* ── Koa.js ────────────────────────────────────────────────────── */
    {
      name: 'Koa.js',
      icon: '🟢',
      inferred: true,
      patterns: [
        { source: 'headers',      regex: /x-powered-by:\s*koa/i,               weight: 0.55, evidence: 'X-Powered-By: Koa header' },
        { source: 'cookies',      regex: /\bkoa:sess\b|koa\.sess/,             weight: 0.50, evidence: 'Koa session cookie' },
      ],
      requiredMatches: 1,
    },

    /* ── Hapi.js ───────────────────────────────────────────────────── */
    {
      name: 'Hapi.js',
      icon: '🟡',
      inferred: true,
      patterns: [
        { source: 'headers',      regex: /x-powered-by:\s*hapi/i,              weight: 0.55, evidence: 'X-Powered-By: hapi header' },
        { source: 'cookies',      regex: /\bsid-hapi\b/,                      weight: 0.50, evidence: 'Hapi session cookie' },
      ],
      requiredMatches: 1,
    },

    /* ── AdonisJS ──────────────────────────────────────────────────── */
    {
      name: 'AdonisJS',
      icon: '💜',
      inferred: true,
      patterns: [
        { source: 'headers',      regex: /x-powered-by:\s*adonisjs/i,          weight: 0.55, evidence: 'X-Powered-By: AdonisJS header' },
        { source: 'cookies',      regex: /\badonis-session\b/,                weight: 0.50, evidence: 'AdonisJS session cookie' },
        { source: 'cookies',      regex: /\bXSRF-TOKEN\b/,                    weight: 0.15, evidence: 'XSRF-TOKEN cookie (AdonisJS pattern)' },
      ],
      requiredMatches: 1,
    },

    /* ── Go (net/http) ─────────────────────────────────────────────── */
    {
      name: 'Go',
      icon: '🐹',
      inferred: true,
      patterns: [
        { source: 'headers',      regex: /^server:\s*Go\b/m,                   weight: 0.55, evidence: 'Server: Go header' },
        { source: 'headers',      regex: /x-powered-by:\s*go/i,                weight: 0.50, evidence: 'X-Powered-By: Go header' },
      ],
      requiredMatches: 1,
    },

    /* ── Gin (Go) ──────────────────────────────────────────────────── */
    {
      name: 'Gin',
      icon: '🍸',
      inferred: true,
      patterns: [
        { source: 'headers',      regex: /x-powered-by:\s*gin/i,               weight: 0.55, evidence: 'X-Powered-By: Gin header' },
        { source: 'headers',      regex: /^server:\s*gin/im,                   weight: 0.55, evidence: 'Server: Gin header' },
      ],
      requiredMatches: 1,
    },

    /* ── FastHTTP (Go) ─────────────────────────────────────────────── */
    {
      name: 'FastHTTP',
      icon: '⚡',
      inferred: true,
      patterns: [
        { source: 'headers',      regex: /^server:\s*fasthttp/im,              weight: 0.60, evidence: 'Server: fasthttp header' },
      ],
      requiredMatches: 1,
    },

    /* ── Actix Web (Rust) ──────────────────────────────────────────── */
    {
      name: 'Actix Web',
      icon: '🦀',
      inferred: true,
      patterns: [
        { source: 'headers',      regex: /x-powered-by:\s*actix/i,             weight: 0.55, evidence: 'X-Powered-By: Actix header' },
        { source: 'headers',      regex: /^server:\s*actix-web/im,             weight: 0.60, evidence: 'Server: Actix-Web header' },
      ],
      requiredMatches: 1,
    },

    /* ── CakePHP ───────────────────────────────────────────────────── */
    {
      name: 'CakePHP',
      icon: '🍰',
      inferred: true,
      patterns: [
        { source: 'cookies',      regex: /\bcakephp\b/i,                       weight: 0.55, evidence: 'CakePHP session cookie' },
        { source: 'cookies',      regex: /\bcsrfToken\b/,                      weight: 0.20, evidence: 'CakePHP CSRF token cookie' },
        { source: 'html',         regex: /cakephp/i,                           weight: 0.30, evidence: 'CakePHP reference in page' },
      ],
      requiredMatches: 1,
    },

    /* ── CodeIgniter ───────────────────────────────────────────────── */
    {
      name: 'CodeIgniter',
      icon: '🔥',
      inferred: true,
      patterns: [
        { source: 'cookies',      regex: /\bci_session\b/,                     weight: 0.55, evidence: 'CodeIgniter ci_session cookie' },
        { source: 'cookies',      regex: /\bcsrf_cookie_name\b/,               weight: 0.30, evidence: 'CodeIgniter CSRF cookie' },
        { source: 'headers',      regex: /x-powered-by:\s*codeigniter/i,       weight: 0.55, evidence: 'X-Powered-By: CodeIgniter header' },
      ],
      requiredMatches: 1,
    },

    /* ── Next.js API Routes (Server-Side) ──────────────────────────── */
    {
      name: 'Next.js API',
      icon: '▲',
      inferred: true,
      patterns: [
        { source: 'headers',      regex: /x-nextjs-/i,                         weight: 0.55, evidence: 'X-Nextjs-* response header' },
        { source: 'headers',      regex: /x-middleware-/i,                      weight: 0.35, evidence: 'X-Middleware-* header (Next.js edge)' },
        { source: 'headers',      regex: /x-powered-by:\s*next\.js/i,          weight: 0.55, evidence: 'X-Powered-By: Next.js header' },
      ],
      requiredMatches: 1,
    },
  ];
})();
