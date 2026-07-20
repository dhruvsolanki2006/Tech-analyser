/**
 * TechStack Detector — CDN Signatures
 *
 * CDN detection primarily uses response headers and resource URLs.
 * Many CDNs inject distinctive headers (CF-Ray, X-Amz-Cf-Id, etc.)
 * that serve as strong, reliable fingerprints.
 */
(() => {
  'use strict';
  self.TechDetectors = self.TechDetectors || {};

  self.TechDetectors.cdn = [
    /* ── Cloudflare CDN ────────────────────────────────────────────── */
    {
      name: 'Cloudflare',
      icon: '☁️',
      patterns: [
        { source: 'headers',      regex: /cf-ray:/i,                           weight: 0.55, evidence: 'CF-Ray header (Cloudflare)' },
        { source: 'headers',      regex: /cf-cache-status:/i,                  weight: 0.50, evidence: 'CF-Cache-Status header' },
        { source: 'headers',      regex: /server:\s*cloudflare/i,              weight: 0.45, evidence: 'Server: cloudflare header' },
      ],
      requiredMatches: 1,
    },

    /* ── Akamai ────────────────────────────────────────────────────── */
    {
      name: 'Akamai',
      icon: '🔵',
      patterns: [
        { source: 'headers',      regex: /x-akamai-transformed/i,              weight: 0.55, evidence: 'X-Akamai-Transformed header' },
        { source: 'headers',      regex: /x-akamai-request-id/i,              weight: 0.55, evidence: 'X-Akamai-Request-ID header' },
        { source: 'resourceUrls', regex: /\.akamaized\.net/,                  weight: 0.50, evidence: '.akamaized.net domain in resources' },
        { source: 'resourceUrls', regex: /\.akamai\.net/,                     weight: 0.45, evidence: '.akamai.net domain in resources' },
        { source: 'resourceUrls', regex: /\.edgekey\.net/,                    weight: 0.40, evidence: '.edgekey.net (Akamai) domain' },
        { source: 'html',         regex: /\.akamaized\.net/,                  weight: 0.40, evidence: '.akamaized.net reference in HTML' },
      ],
      requiredMatches: 1,
    },

    /* ── Fastly ────────────────────────────────────────────────────── */
    {
      name: 'Fastly',
      icon: '⚡',
      patterns: [
        { source: 'headers',      regex: /x-fastly-request-id/i,               weight: 0.55, evidence: 'X-Fastly-Request-ID header' },
        { source: 'headers',      regex: /x-served-by:.*cache-/i,              weight: 0.45, evidence: 'X-Served-By with Fastly cache ID' },
        { source: 'headers',      regex: /x-cache:.*fastly/i,                  weight: 0.50, evidence: 'X-Cache mentions Fastly' },
        { source: 'resourceUrls', regex: /\.fastly\.net/,                      weight: 0.45, evidence: '.fastly.net domain' },
      ],
      requiredMatches: 1,
    },

    /* ── BunnyCDN ──────────────────────────────────────────────────── */
    {
      name: 'BunnyCDN',
      icon: '🐰',
      patterns: [
        { source: 'resourceUrls', regex: /\.b-cdn\.net/,                       weight: 0.55, evidence: '.b-cdn.net domain (BunnyCDN)' },
        { source: 'headers',      regex: /cdn-pullzone/i,                      weight: 0.50, evidence: 'CDN-PullZone header (BunnyCDN)' },
        { source: 'headers',      regex: /server:\s*bunnycdn/i,                weight: 0.55, evidence: 'Server: BunnyCDN header' },
        { source: 'html',         regex: /\.b-cdn\.net/,                       weight: 0.40, evidence: '.b-cdn.net reference in HTML' },
      ],
      requiredMatches: 1,
    },

    /* ── jsDelivr ──────────────────────────────────────────────────── */
    {
      name: 'jsDelivr',
      icon: '📦',
      patterns: [
        { source: 'resourceUrls', regex: /cdn\.jsdelivr\.net/,                 weight: 0.55, evidence: 'cdn.jsdelivr.net resources loaded' },
        { source: 'scriptSrcs',   regex: /cdn\.jsdelivr\.net/,                 weight: 0.50, evidence: 'Script from cdn.jsdelivr.net' },
        { source: 'linkHrefs',    regex: /cdn\.jsdelivr\.net/,                 weight: 0.45, evidence: 'Stylesheet from cdn.jsdelivr.net' },
        { source: 'html',         regex: /cdn\.jsdelivr\.net/,                 weight: 0.45, evidence: 'cdn.jsdelivr.net reference in HTML' },
      ],
      requiredMatches: 1,
    },

    /* ── CloudFront (AWS) ──────────────────────────────────────────── */
    {
      name: 'CloudFront',
      icon: '🔶',
      patterns: [
        { source: 'headers',      regex: /x-amz-cf-id/i,                       weight: 0.55, evidence: 'X-Amz-Cf-Id header (CloudFront)' },
        { source: 'headers',      regex: /x-amz-cf-pop/i,                      weight: 0.50, evidence: 'X-Amz-Cf-Pop header' },
        { source: 'resourceUrls', regex: /\.cloudfront\.net/,                  weight: 0.50, evidence: '.cloudfront.net domain' },
        { source: 'headers',      regex: /via:.*cloudfront/i,                  weight: 0.45, evidence: 'Via header mentions CloudFront' },
        { source: 'html',         regex: /\.cloudfront\.net/,                  weight: 0.40, evidence: '.cloudfront.net reference in HTML' },
      ],
      requiredMatches: 1,
    },

    /* ── Azure CDN ─────────────────────────────────────────────────── */
    {
      name: 'Azure CDN',
      icon: '🔷',
      patterns: [
        { source: 'headers',      regex: /x-msedge-ref/i,                      weight: 0.55, evidence: 'X-MSEdge-Ref header (Azure CDN)' },
        { source: 'resourceUrls', regex: /\.azureedge\.net/,                   weight: 0.55, evidence: '.azureedge.net domain' },
        { source: 'resourceUrls', regex: /\.vo\.msecnd\.net/,                  weight: 0.40, evidence: '.vo.msecnd.net (Azure CDN legacy)' },
        { source: 'html',         regex: /\.azureedge\.net/,                   weight: 0.40, evidence: '.azureedge.net reference in HTML' },
      ],
      requiredMatches: 1,
    },

    /* ══════════════════════════════════════════════════════════════════
     *  NEW ADDITIONS BELOW
     * ══════════════════════════════════════════════════════════════════ */

    /* ── StackPath / MaxCDN ────────────────────────────────────────── */
    {
      name: 'StackPath',
      icon: '📡',
      patterns: [
        { source: 'headers',      regex: /x-hw:/i,                             weight: 0.55, evidence: 'X-HW header (StackPath/Highwinds)' },
        { source: 'resourceUrls', regex: /\.stackpathdns\.com/,                weight: 0.55, evidence: '.stackpathdns.com domain' },
        { source: 'resourceUrls', regex: /\.netdna-cdn\.com/,                  weight: 0.50, evidence: '.netdna-cdn.com (MaxCDN/StackPath)' },
        { source: 'headers',      regex: /server:\s*netdna/i,                  weight: 0.50, evidence: 'Server: NetDNA header' },
      ],
      requiredMatches: 1,
    },

    /* ── KeyCDN ────────────────────────────────────────────────────── */
    {
      name: 'KeyCDN',
      icon: '🔑',
      patterns: [
        { source: 'resourceUrls', regex: /\.kxcdn\.com/,                       weight: 0.55, evidence: '.kxcdn.com domain (KeyCDN)' },
        { source: 'headers',      regex: /server:\s*keycdn/i,                  weight: 0.55, evidence: 'Server: KeyCDN header' },
        { source: 'headers',      regex: /x-edge-location/i,                   weight: 0.35, evidence: 'X-Edge-Location header' },
      ],
      requiredMatches: 1,
    },

    /* ── Google Cloud CDN ──────────────────────────────────────────── */
    {
      name: 'Google Cloud CDN',
      icon: '☁️',
      patterns: [
        { source: 'headers',      regex: /via:\s*1\.1 google/i,                weight: 0.45, evidence: 'Via: 1.1 google header' },
        { source: 'headers',      regex: /x-goog-/i,                           weight: 0.45, evidence: 'X-Goog-* header' },
        { source: 'resourceUrls', regex: /\.storage\.googleapis\.com/,         weight: 0.50, evidence: 'Google Cloud Storage domain' },
        { source: 'headers',      regex: /server:\s*gse|gws/i,                weight: 0.35, evidence: 'Server: GSE/GWS (Google)' },
      ],
      requiredMatches: 1,
    },

    /* ── Sucuri ────────────────────────────────────────────────────── */
    {
      name: 'Sucuri',
      icon: '🛡️',
      patterns: [
        { source: 'headers',      regex: /x-sucuri-id/i,                       weight: 0.55, evidence: 'X-Sucuri-ID header' },
        { source: 'headers',      regex: /server:\s*sucuri/i,                  weight: 0.55, evidence: 'Server: Sucuri header' },
        { source: 'headers',      regex: /x-sucuri-cache/i,                    weight: 0.50, evidence: 'X-Sucuri-Cache header' },
      ],
      requiredMatches: 1,
    },

    /* ── Imperva / Incapsula ───────────────────────────────────────── */
    {
      name: 'Imperva',
      icon: '🔒',
      patterns: [
        { source: 'headers',      regex: /x-iinfo:/i,                          weight: 0.55, evidence: 'X-Iinfo header (Imperva/Incapsula)' },
        { source: 'headers',      regex: /x-cdn:\s*incapsula/i,               weight: 0.55, evidence: 'X-CDN: Incapsula header' },
        { source: 'cookies',      regex: /\bvisid_incap_/,                     weight: 0.50, evidence: 'Incapsula visitor cookie' },
        { source: 'cookies',      regex: /\bincap_ses_/,                       weight: 0.50, evidence: 'Incapsula session cookie' },
      ],
      requiredMatches: 1,
    },

    /* ── cdnjs (Cloudflare) ────────────────────────────────────────── */
    {
      name: 'cdnjs',
      icon: '📦',
      patterns: [
        { source: 'resourceUrls', regex: /cdnjs\.cloudflare\.com/,            weight: 0.55, evidence: 'cdnjs.cloudflare.com resources' },
        { source: 'scriptSrcs',   regex: /cdnjs\.cloudflare\.com/,            weight: 0.50, evidence: 'Script from cdnjs.cloudflare.com' },
        { source: 'linkHrefs',    regex: /cdnjs\.cloudflare\.com/,            weight: 0.45, evidence: 'Stylesheet from cdnjs.cloudflare.com' },
        { source: 'html',         regex: /cdnjs\.cloudflare\.com/,            weight: 0.40, evidence: 'cdnjs reference in HTML' },
      ],
      requiredMatches: 1,
    },

    /* ── unpkg ─────────────────────────────────────────────────────── */
    {
      name: 'unpkg',
      icon: '📦',
      patterns: [
        { source: 'resourceUrls', regex: /unpkg\.com/,                         weight: 0.55, evidence: 'unpkg.com resources loaded' },
        { source: 'scriptSrcs',   regex: /unpkg\.com/,                         weight: 0.50, evidence: 'Script from unpkg.com' },
        { source: 'linkHrefs',    regex: /unpkg\.com/,                         weight: 0.45, evidence: 'Stylesheet from unpkg.com' },
        { source: 'html',         regex: /unpkg\.com/,                         weight: 0.40, evidence: 'unpkg.com reference in HTML' },
      ],
      requiredMatches: 1,
    },
  ];
})();
