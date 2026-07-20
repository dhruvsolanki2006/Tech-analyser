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

    /* ══════════════════════════════════════════════════════════════════
     *  NEW ADDITIONS BELOW
     * ══════════════════════════════════════════════════════════════════ */

    /* ── Heroku ────────────────────────────────────────────────────── */
    {
      name: 'Heroku',
      icon: '🟣',
      patterns: [
        { source: 'resourceUrls', regex: /\.herokuapp\.com/,                   weight: 0.55, evidence: '.herokuapp.com domain' },
        { source: 'html',         regex: /\.herokuapp\.com/,                   weight: 0.40, evidence: '.herokuapp.com reference' },
        { source: 'headers',      regex: /via:.*heroku/i,                      weight: 0.50, evidence: 'Via header mentions Heroku' },
        { source: 'headers',      regex: /x-dyno/i,                           weight: 0.55, evidence: 'X-Dyno header (Heroku)' },
      ],
      requiredMatches: 1,
    },

    /* ── DigitalOcean App Platform ─────────────────────────────────── */
    {
      name: 'DigitalOcean',
      icon: '🔵',
      patterns: [
        { source: 'resourceUrls', regex: /\.ondigitalocean\.app/,              weight: 0.55, evidence: '.ondigitalocean.app domain' },
        { source: 'html',         regex: /\.ondigitalocean\.app/,              weight: 0.40, evidence: '.ondigitalocean.app reference' },
        { source: 'headers',      regex: /x-do-app-origin/i,                   weight: 0.55, evidence: 'X-DO-App-Origin header' },
        { source: 'headers',      regex: /server:\s*digitalocean/i,            weight: 0.55, evidence: 'Server: DigitalOcean header' },
      ],
      requiredMatches: 1,
    },

    /* ── Azure Web Apps ────────────────────────────────────────────── */
    {
      name: 'Azure Web Apps',
      icon: '🔷',
      patterns: [
        { source: 'resourceUrls', regex: /\.azurewebsites\.net/,               weight: 0.55, evidence: '.azurewebsites.net domain' },
        { source: 'html',         regex: /\.azurewebsites\.net/,               weight: 0.40, evidence: '.azurewebsites.net reference' },
        { source: 'headers',      regex: /x-azure-ref/i,                       weight: 0.50, evidence: 'X-Azure-Ref header' },
        { source: 'headers',      regex: /x-ms-request-id/i,                   weight: 0.30, evidence: 'X-MS-Request-Id header' },
      ],
      requiredMatches: 1,
    },

    /* ── AWS S3 Static Hosting ─────────────────────────────────────── */
    {
      name: 'AWS S3',
      icon: '🔶',
      patterns: [
        { source: 'headers',      regex: /x-amz-request-id/i,                  weight: 0.45, evidence: 'X-Amz-Request-Id header' },
        { source: 'headers',      regex: /server:\s*amazons3/i,                weight: 0.60, evidence: 'Server: AmazonS3 header' },
        { source: 'headers',      regex: /x-amz-bucket-region/i,               weight: 0.55, evidence: 'X-Amz-Bucket-Region header' },
        { source: 'resourceUrls', regex: /\.s3\.amazonaws\.com/,               weight: 0.50, evidence: 'S3 bucket domain in resources' },
      ],
      requiredMatches: 1,
    },

    /* ── Google Cloud Run ──────────────────────────────────────────── */
    {
      name: 'Google Cloud Run',
      icon: '☁️',
      patterns: [
        { source: 'resourceUrls', regex: /\.run\.app(?:\/|$)/,                weight: 0.55, evidence: '.run.app domain' },
        { source: 'html',         regex: /\.run\.app/,                         weight: 0.40, evidence: '.run.app reference' },
        { source: 'headers',      regex: /x-cloud-trace-context/i,             weight: 0.30, evidence: 'Google Cloud Trace header' },
      ],
      requiredMatches: 1,
    },

    /* ── Surge.sh ──────────────────────────────────────────────────── */
    {
      name: 'Surge.sh',
      icon: '⚡',
      patterns: [
        { source: 'resourceUrls', regex: /\.surge\.sh/,                        weight: 0.55, evidence: '.surge.sh domain' },
        { source: 'html',         regex: /\.surge\.sh/,                        weight: 0.40, evidence: '.surge.sh reference' },
        { source: 'headers',      regex: /server:\s*surge/i,                   weight: 0.55, evidence: 'Server: Surge header' },
      ],
      requiredMatches: 1,
    },

    /* ── GitLab Pages ──────────────────────────────────────────────── */
    {
      name: 'GitLab Pages',
      icon: '🦊',
      patterns: [
        { source: 'resourceUrls', regex: /\.gitlab\.io(?:\/|$)/,              weight: 0.55, evidence: '.gitlab.io domain' },
        { source: 'html',         regex: /\.gitlab\.io/,                       weight: 0.40, evidence: '.gitlab.io reference' },
        { source: 'headers',      regex: /x-gitlab-/i,                         weight: 0.50, evidence: 'X-GitLab-* header' },
      ],
      requiredMatches: 1,
    },

    /* ── Deno Deploy ───────────────────────────────────────────────── */
    {
      name: 'Deno Deploy',
      icon: '🦕',
      patterns: [
        { source: 'resourceUrls', regex: /\.deno\.dev/,                        weight: 0.55, evidence: '.deno.dev domain' },
        { source: 'html',         regex: /\.deno\.dev/,                        weight: 0.40, evidence: '.deno.dev reference' },
        { source: 'headers',      regex: /server:\s*deno/i,                    weight: 0.55, evidence: 'Server: deno header' },
        { source: 'headers',      regex: /x-deno-ray/i,                        weight: 0.55, evidence: 'X-Deno-Ray header' },
      ],
      requiredMatches: 1,
    },

    /* ── Supabase ──────────────────────────────────────────────────── */
    {
      name: 'Supabase',
      icon: '⚡',
      patterns: [
        { source: 'resourceUrls', regex: /\.supabase\.co/,                     weight: 0.55, evidence: '.supabase.co domain' },
        { source: 'scriptSrcs',   regex: /supabase/i,                          weight: 0.45, evidence: 'Supabase script loaded' },
        { source: 'resourceUrls', regex: /supabase-js/i,                       weight: 0.40, evidence: 'Supabase JS client in resources' },
        { source: 'html',         regex: /\.supabase\.co/,                     weight: 0.35, evidence: '.supabase.co reference in HTML' },
      ],
      requiredMatches: 1,
    },
  ];
})();
