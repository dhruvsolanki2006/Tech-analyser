/**
 * TechStack Detector — Hosting Provider Signatures
 *
 * Detection uses a combination of response headers, domain patterns,
 * and platform-specific resource URLs.
 */
(() => {
  'use strict';
  self.TechDetectors = self.TechDetectors || {};

  self.TechDetectors.hosting = [
    /* ── Vercel ────────────────────────────────────────────────────── */
    {
      name: 'Vercel',
      icon: '▲',
      patterns: [
        { source: 'headers',      regex: /x-vercel-id/i,                       weight: 0.55, evidence: 'X-Vercel-Id header' },
        { source: 'headers',      regex: /server:\s*vercel/i,                  weight: 0.55, evidence: 'Server: Vercel header' },
        { source: 'resourceUrls', regex: /\.vercel\.app/,                      weight: 0.45, evidence: '.vercel.app domain in resources' },
        { source: 'html',         regex: /\.vercel\.app/,                      weight: 0.35, evidence: '.vercel.app reference in page' },
        { source: 'resourceUrls', regex: /\/_vercel\//,                        weight: 0.40, evidence: '/_vercel/ internal path' },
      ],
      requiredMatches: 1,
    },

    /* ── Netlify ───────────────────────────────────────────────────── */
    {
      name: 'Netlify',
      icon: '🌐',
      patterns: [
        { source: 'headers',      regex: /x-nf-request-id/i,                   weight: 0.55, evidence: 'X-NF-Request-ID header' },
        { source: 'headers',      regex: /server:\s*netlify/i,                 weight: 0.55, evidence: 'Server: Netlify header' },
        { source: 'resourceUrls', regex: /\.netlify\.app/,                     weight: 0.45, evidence: '.netlify.app domain' },
        { source: 'html',         regex: /netlify-identity-widget/,            weight: 0.35, evidence: 'Netlify Identity widget' },
        { source: 'html',         regex: /netlify-cms/i,                       weight: 0.35, evidence: 'Netlify CMS integration' },
      ],
      requiredMatches: 1,
    },

    /* ── Render ────────────────────────────────────────────────────── */
    {
      name: 'Render',
      icon: '🟣',
      patterns: [
        { source: 'resourceUrls', regex: /\.onrender\.com/,                    weight: 0.55, evidence: '.onrender.com domain' },
        { source: 'headers',      regex: /x-render-origin-server/i,            weight: 0.55, evidence: 'X-Render-Origin-Server header' },
        { source: 'html',         regex: /\.onrender\.com/,                    weight: 0.35, evidence: '.onrender.com reference' },
      ],
      requiredMatches: 1,
    },

    /* ── Railway ───────────────────────────────────────────────────── */
    {
      name: 'Railway',
      icon: '🚂',
      patterns: [
        { source: 'resourceUrls', regex: /\.up\.railway\.app/,                 weight: 0.55, evidence: '.up.railway.app domain' },
        { source: 'html',         regex: /\.up\.railway\.app/,                 weight: 0.40, evidence: '.up.railway.app reference' },
        { source: 'headers',      regex: /x-railway/i,                         weight: 0.55, evidence: 'X-Railway header' },
      ],
      requiredMatches: 1,
    },

    /* ── Fly.io ────────────────────────────────────────────────────── */
    {
      name: 'Fly.io',
      icon: '✈️',
      patterns: [
        { source: 'headers',      regex: /fly-request-id/i,                    weight: 0.55, evidence: 'Fly-Request-Id header' },
        { source: 'resourceUrls', regex: /\.fly\.dev/,                         weight: 0.50, evidence: '.fly.dev domain' },
        { source: 'headers',      regex: /server:\s*fly/i,                     weight: 0.50, evidence: 'Server: Fly header' },
      ],
      requiredMatches: 1,
    },

    /* ── AWS Amplify ───────────────────────────────────────────────── */
    {
      name: 'AWS Amplify',
      icon: '🔶',
      patterns: [
        { source: 'resourceUrls', regex: /\.amplifyapp\.com/,                  weight: 0.55, evidence: '.amplifyapp.com domain' },
        { source: 'html',         regex: /\.amplifyapp\.com/,                  weight: 0.40, evidence: '.amplifyapp.com reference' },
        { source: 'headers',      regex: /x-amz-cf-id/i,                      weight: 0.20, evidence: 'AWS CloudFront distribution header' },
        { source: 'scriptSrcs',   regex: /aws-amplify/i,                       weight: 0.40, evidence: 'AWS Amplify library loaded' },
      ],
      requiredMatches: 1,
    },

    /* ── Firebase Hosting ──────────────────────────────────────────── */
    {
      name: 'Firebase Hosting',
      icon: '🔥',
      patterns: [
        { source: 'resourceUrls', regex: /\.web\.app(?:\/|$)/,                weight: 0.40, evidence: '.web.app Firebase domain' },
        { source: 'resourceUrls', regex: /\.firebaseapp\.com/,                weight: 0.50, evidence: '.firebaseapp.com domain' },
        { source: 'headers',      regex: /x-firebase/i,                        weight: 0.55, evidence: 'X-Firebase response header' },
        { source: 'html',         regex: /\.firebaseapp\.com/,                weight: 0.35, evidence: '.firebaseapp.com reference' },
      ],
      requiredMatches: 1,
    },

    /* ── Cloudflare Pages ──────────────────────────────────────────── */
    {
      name: 'Cloudflare Pages',
      icon: '☁️',
      patterns: [
        { source: 'resourceUrls', regex: /\.pages\.dev(?:\/|$)/,              weight: 0.55, evidence: '.pages.dev Cloudflare domain' },
        { source: 'html',         regex: /\.pages\.dev/,                      weight: 0.40, evidence: '.pages.dev reference' },
        { source: 'headers',      regex: /cf-ray/i,                            weight: 0.15, evidence: 'Cloudflare CF-Ray header' },
      ],
      requiredMatches: 1,
    },

    /* ── GitHub Pages ──────────────────────────────────────────────── */
    {
      name: 'GitHub Pages',
      icon: '🐙',
      patterns: [
        { source: 'resourceUrls', regex: /\.github\.io(?:\/|$)/,              weight: 0.55, evidence: '.github.io domain' },
        { source: 'headers',      regex: /x-github-request-id/i,               weight: 0.55, evidence: 'X-GitHub-Request-ID header' },
        { source: 'headers',      regex: /server:\s*github\.com/i,             weight: 0.55, evidence: 'Server: GitHub.com header' },
        { source: 'html',         regex: /\.github\.io/,                       weight: 0.35, evidence: '.github.io reference' },
      ],
      requiredMatches: 1,
    },
  ];
})();
