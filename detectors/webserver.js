/**
 * TechStack Detector — Web Server Signatures
 *
 * Detection relies EXCLUSIVELY on response headers.
 * The `Server` header is the primary signal; framework-specific
 * headers (x-envoy-*, x-haproxy-*) provide additional evidence.
 *
 * If no headers are available the scan engine shows:
 *   "Not Publicly Exposed"
 */

(() => {
  'use strict';
  self.TechDetectors = self.TechDetectors || {};

  self.TechDetectors.webserver = [
    /* ── Nginx ─────────────────────────────────────────────────────── */
    {
      name: 'Nginx',
      icon: '🟩',
      headerOnly: true,
      patterns: [
        { source: 'headers', regex: /^server:\s*nginx/im,                      weight: 0.60, evidence: 'Server: nginx header' },
        { source: 'headers', regex: /^server:\s*nginx\/[\d.]+/im,              weight: 0.60, evidence: 'Server: nginx with version' },
      ],
      requiredMatches: 1,
    },

    /* ── Apache ────────────────────────────────────────────────────── */
    {
      name: 'Apache',
      icon: '🪶',
      headerOnly: true,
      patterns: [
        { source: 'headers', regex: /^server:\s*apache/im,                     weight: 0.60, evidence: 'Server: Apache header' },
        { source: 'headers', regex: /^server:\s*apache\/[\d.]+/im,             weight: 0.60, evidence: 'Server: Apache with version' },
      ],
      requiredMatches: 1,
    },

    /* ── LiteSpeed ─────────────────────────────────────────────────── */
    {
      name: 'LiteSpeed',
      icon: '⚡',
      headerOnly: true,
      patterns: [
        { source: 'headers', regex: /^server:\s*litespeed/im,                  weight: 0.60, evidence: 'Server: LiteSpeed header' },
        { source: 'headers', regex: /x-litespeed/i,                            weight: 0.50, evidence: 'X-LiteSpeed header' },
      ],
      requiredMatches: 1,
    },

    /* ── OpenResty ─────────────────────────────────────────────────── */
    {
      name: 'OpenResty',
      icon: '🟩',
      headerOnly: true,
      patterns: [
        { source: 'headers', regex: /^server:\s*openresty/im,                  weight: 0.60, evidence: 'Server: openresty header' },
      ],
      requiredMatches: 1,
    },

    /* ── Caddy ─────────────────────────────────────────────────────── */
    {
      name: 'Caddy',
      icon: '🔒',
      headerOnly: true,
      patterns: [
        { source: 'headers', regex: /^server:\s*caddy/im,                      weight: 0.60, evidence: 'Server: Caddy header' },
      ],
      requiredMatches: 1,
    },

    /* ── IIS (Microsoft) ───────────────────────────────────────────── */
    {
      name: 'IIS',
      icon: '🟦',
      headerOnly: true,
      patterns: [
        { source: 'headers', regex: /^server:\s*microsoft-iis/im,              weight: 0.60, evidence: 'Server: Microsoft-IIS header' },
        { source: 'headers', regex: /x-powered-by:\s*iis/i,                    weight: 0.50, evidence: 'X-Powered-By: IIS header' },
      ],
      requiredMatches: 1,
    },

    /* ── Cloudflare Server ─────────────────────────────────────────── */
    {
      name: 'Cloudflare Server',
      icon: '☁️',
      headerOnly: true,
      patterns: [
        { source: 'headers', regex: /^server:\s*cloudflare/im,                 weight: 0.60, evidence: 'Server: cloudflare header' },
      ],
      requiredMatches: 1,
    },

    /* ── Envoy ─────────────────────────────────────────────────────── */
    {
      name: 'Envoy',
      icon: '🔷',
      headerOnly: true,
      patterns: [
        { source: 'headers', regex: /^server:\s*envoy/im,                      weight: 0.60, evidence: 'Server: envoy header' },
        { source: 'headers', regex: /x-envoy-/i,                               weight: 0.50, evidence: 'X-Envoy-* headers' },
      ],
      requiredMatches: 1,
    },

    /* ── HAProxy ───────────────────────────────────────────────────── */
    {
      name: 'HAProxy',
      icon: '🔀',
      headerOnly: true,
      patterns: [
        { source: 'headers', regex: /x-haproxy-/i,                             weight: 0.55, evidence: 'X-Haproxy-* headers' },
        { source: 'headers', regex: /^server:\s*haproxy/im,                    weight: 0.60, evidence: 'Server: HAProxy header' },
      ],
      requiredMatches: 1,
    },

    /* ══════════════════════════════════════════════════════════════════
     *  NEW ADDITIONS BELOW
     * ══════════════════════════════════════════════════════════════════ */

    /* ── Tengine ───────────────────────────────────────────────────── */
    {
      name: 'Tengine',
      icon: '🟩',
      headerOnly: true,
      patterns: [
        { source: 'headers', regex: /^server:\s*tengine/im,                    weight: 0.60, evidence: 'Server: Tengine header' },
      ],
      requiredMatches: 1,
    },

    /* ── Cowboy (Erlang) ───────────────────────────────────────────── */
    {
      name: 'Cowboy',
      icon: '🤠',
      headerOnly: true,
      patterns: [
        { source: 'headers', regex: /^server:\s*cowboy/im,                     weight: 0.60, evidence: 'Server: Cowboy header' },
      ],
      requiredMatches: 1,
    },

    /* ── Kestrel (.NET) ────────────────────────────────────────────── */
    {
      name: 'Kestrel',
      icon: '🟦',
      headerOnly: true,
      patterns: [
        { source: 'headers', regex: /^server:\s*kestrel/im,                    weight: 0.60, evidence: 'Server: Kestrel header' },
      ],
      requiredMatches: 1,
    },

    /* ── Gunicorn ──────────────────────────────────────────────────── */
    {
      name: 'Gunicorn',
      icon: '🦎',
      headerOnly: true,
      patterns: [
        { source: 'headers', regex: /^server:\s*gunicorn/im,                   weight: 0.60, evidence: 'Server: gunicorn header' },
      ],
      requiredMatches: 1,
    },

    /* ── Uvicorn ───────────────────────────────────────────────────── */
    {
      name: 'Uvicorn',
      icon: '⚡',
      headerOnly: true,
      patterns: [
        { source: 'headers', regex: /^server:\s*uvicorn/im,                    weight: 0.60, evidence: 'Server: uvicorn header' },
      ],
      requiredMatches: 1,
    },

    /* ── Traefik ───────────────────────────────────────────────────── */
    {
      name: 'Traefik',
      icon: '🔀',
      headerOnly: true,
      patterns: [
        { source: 'headers', regex: /^server:\s*traefik/im,                    weight: 0.60, evidence: 'Server: Traefik header' },
        { source: 'headers', regex: /x-traefik-/i,                             weight: 0.55, evidence: 'X-Traefik-* headers' },
      ],
      requiredMatches: 1,
    },
  ];
})();
