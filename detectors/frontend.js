/**
 * TechStack Detector — Frontend Framework Signatures
 *
 * Each signature targets specific signal sources (scriptSrcs, html, globals, etc.)
 * instead of searching one giant concatenated string, dramatically reducing
 * false positives.
 *
 * Pattern weight guide:
 *   0.4 – 0.5  Definitive (unique DOM attribute, specific global)
 *   0.25– 0.35 Strong     (framework-specific URL path)
 *   0.10– 0.20 Supporting (generic pattern that corroborates)
 */
(() => {
  'use strict';
  self.TechDetectors = self.TechDetectors || {};

  self.TechDetectors.frontend = [
    /* ── React ─────────────────────────────────────────────────────── */
    {
      name: 'React',
      icon: '⚛️',
      patterns: [
        { source: 'html',        regex: /data-reactroot/,                       weight: 0.45, evidence: 'data-reactroot attribute in DOM' },
        { source: 'html',        regex: /data-reactid=/,                        weight: 0.40, evidence: 'data-reactid attribute in DOM' },
        { source: 'globals',     regex: /\bReact\b/,                            weight: 0.40, evidence: 'window.React global present' },
        { source: 'globals',     regex: /\bReactDOM\b/,                         weight: 0.40, evidence: 'window.ReactDOM global present' },
        { source: 'globals',     regex: /\b__REACT_DEVTOOLS_GLOBAL_HOOK__\b/,   weight: 0.25, evidence: 'React DevTools hook detected' },
        { source: 'scriptSrcs',  regex: /react-dom[.\-\/]/i,                    weight: 0.35, evidence: 'react-dom loaded via script' },
        { source: 'scriptSrcs',  regex: /react\.production\.min\.js/i,          weight: 0.40, evidence: 'React production bundle loaded' },
        { source: 'resourceUrls', regex: /react-dom/i,                          weight: 0.20, evidence: 'react-dom in resource URLs' },
      ],
      requiredMatches: 2,
    },

    /* ── Next.js ───────────────────────────────────────────────────── */
    {
      name: 'Next.js',
      icon: '▲',
      implies: ['React'],
      patterns: [
        { source: 'html',         regex: /<script[^>]+id="__NEXT_DATA__"/,      weight: 0.50, evidence: '__NEXT_DATA__ script tag found' },
        { source: 'globals',      regex: /\b__NEXT_DATA__\b/,                   weight: 0.45, evidence: 'window.__NEXT_DATA__ global present' },
        { source: 'resourceUrls', regex: /\/_next\//,                           weight: 0.35, evidence: '/_next/ resource paths detected' },
        { source: 'scriptSrcs',   regex: /\/_next\/static\//,                   weight: 0.35, evidence: '/_next/static/ script sources' },
        { source: 'html',         regex: /next-route-announcer/,                weight: 0.30, evidence: 'Next.js route announcer element' },
        { source: 'resourceUrls', regex: /\/_next\/image/,                      weight: 0.25, evidence: 'Next.js image optimization paths' },
      ],
      requiredMatches: 2,
    },

    /* ── Vue.js ────────────────────────────────────────────────────── */
    {
      name: 'Vue.js',
      icon: '💚',
      patterns: [
        { source: 'html',         regex: /data-v-[a-f0-9]{6,8}/,               weight: 0.45, evidence: 'Vue scoped style data-v-* attribute' },
        { source: 'globals',      regex: /\bVue\b/,                             weight: 0.40, evidence: 'window.Vue global present' },
        { source: 'globals',      regex: /\b__VUE__\b/,                         weight: 0.45, evidence: 'window.__VUE__ marker present' },
        { source: 'globals',      regex: /\b__VUE_DEVTOOLS_GLOBAL_HOOK__\b/,    weight: 0.25, evidence: 'Vue DevTools hook detected' },
        { source: 'scriptSrcs',   regex: /vue(?:\.runtime)?(?:\.global)?(?:\.prod)?(?:\.min)?\.js/i, weight: 0.35, evidence: 'Vue.js script loaded' },
        { source: 'html',         regex: /id="app"[^>]*data-v-/,               weight: 0.30, evidence: 'Vue app root with scoped data' },
      ],
      requiredMatches: 2,
    },

    /* ── Nuxt ──────────────────────────────────────────────────────── */
    {
      name: 'Nuxt',
      icon: '💚',
      implies: ['Vue.js'],
      patterns: [
        { source: 'globals',      regex: /\b__NUXT__\b/,                        weight: 0.50, evidence: 'window.__NUXT__ global present' },
        { source: 'globals',      regex: /\b\$nuxt\b/,                          weight: 0.45, evidence: 'window.$nuxt global present' },
        { source: 'resourceUrls', regex: /\/_nuxt\//,                           weight: 0.40, evidence: '/_nuxt/ resource paths detected' },
        { source: 'scriptSrcs',   regex: /\/_nuxt\//,                           weight: 0.35, evidence: '/_nuxt/ script sources' },
        { source: 'html',         regex: /nuxt-link/i,                          weight: 0.25, evidence: '<nuxt-link> element found' },
      ],
      requiredMatches: 2,
    },

    /* ── Angular ───────────────────────────────────────────────────── */
    {
      name: 'Angular',
      icon: '🅰️',
      patterns: [
        { source: 'html',         regex: /ng-version="[0-9]+/,                  weight: 0.50, evidence: 'ng-version attribute found' },
        { source: 'html',         regex: /\[_ngcontent-/,                       weight: 0.45, evidence: '_ngcontent attribute (Angular scoping)' },
        { source: 'html',         regex: /ng-app/,                              weight: 0.30, evidence: 'ng-app directive found' },
        { source: 'html',         regex: /<app-root/,                           weight: 0.35, evidence: '<app-root> Angular element' },
        { source: 'scriptSrcs',   regex: /(?:angular|polyfills|runtime)(?:\.|\-)[a-f0-9]+\.js/i, weight: 0.25, evidence: 'Angular-style hashed bundle names' },
        { source: 'globals',      regex: /\bgetAllAngularRootElements\b/,       weight: 0.45, evidence: 'getAllAngularRootElements function present' },
      ],
      requiredMatches: 2,
    },

    /* ── Svelte ────────────────────────────────────────────────────── */
    {
      name: 'Svelte',
      icon: '🔥',
      patterns: [
        { source: 'html',         regex: /data-svelte-h/,                       weight: 0.50, evidence: 'data-svelte-h hydration attribute' },
        { source: 'html',         regex: /class="svelte-[a-z0-9]+"/,           weight: 0.45, evidence: 'Svelte scoped class names' },
        { source: 'globals',      regex: /\b__svelte_meta\b/,                   weight: 0.40, evidence: '__svelte_meta global present' },
        { source: 'scriptSrcs',   regex: /svelte/i,                             weight: 0.20, evidence: 'Svelte referenced in script source' },
      ],
      requiredMatches: 2,
    },

    /* ── Astro ─────────────────────────────────────────────────────── */
    {
      name: 'Astro',
      icon: '🚀',
      patterns: [
        { source: 'html',         regex: /astro-island/,                        weight: 0.50, evidence: '<astro-island> custom element found' },
        { source: 'html',         regex: /data-astro-cid/,                      weight: 0.45, evidence: 'data-astro-cid attribute found' },
        { source: 'resourceUrls', regex: /\/_astro\//,                          weight: 0.40, evidence: '/_astro/ resource paths' },
        { source: 'metaTags',     regex: /generator[^>]*astro/i,               weight: 0.50, evidence: '<meta name="generator"> mentions Astro' },
      ],
      requiredMatches: 2,
    },

    /* ── Gatsby ────────────────────────────────────────────────────── */
    {
      name: 'Gatsby',
      icon: '💜',
      implies: ['React'],
      patterns: [
        { source: 'html',         regex: /id="___gatsby"/,                      weight: 0.50, evidence: '___gatsby root element found' },
        { source: 'html',         regex: /gatsby-focus-wrapper/,                weight: 0.45, evidence: 'gatsby-focus-wrapper element found' },
        { source: 'globals',      regex: /\b___gatsby\b/,                       weight: 0.40, evidence: 'window.___gatsby global present' },
        { source: 'resourceUrls', regex: /\/page-data\//,                       weight: 0.25, evidence: 'Gatsby page-data paths' },
        { source: 'scriptSrcs',   regex: /gatsby-chunk/i,                       weight: 0.35, evidence: 'Gatsby chunk scripts' },
      ],
      requiredMatches: 2,
    },

    /* ── Remix ─────────────────────────────────────────────────────── */
    {
      name: 'Remix',
      icon: '💿',
      implies: ['React'],
      patterns: [
        { source: 'globals',      regex: /\b__remixContext\b/,                  weight: 0.50, evidence: 'window.__remixContext global present' },
        { source: 'globals',      regex: /\b__remixManifest\b/,                weight: 0.45, evidence: 'window.__remixManifest global present' },
        { source: 'html',         regex: /data-remix/,                          weight: 0.40, evidence: 'data-remix attribute found' },
        { source: 'scriptContents', regex: /__remixContext/,                    weight: 0.35, evidence: '__remixContext in inline script' },
      ],
      requiredMatches: 2,
    },

    /* ── SolidJS ───────────────────────────────────────────────────── */
    {
      name: 'SolidJS',
      icon: '💠',
      patterns: [
        { source: 'globals',      regex: /\b_\$HY\b/,                          weight: 0.50, evidence: 'SolidJS hydration marker (_$HY)' },
        { source: 'html',         regex: /data-hk=/,                            weight: 0.45, evidence: 'data-hk hydration key attribute' },
        { source: 'scriptSrcs',   regex: /solid-js/i,                           weight: 0.35, evidence: 'solid-js in script source' },
        { source: 'resourceUrls', regex: /solid/i,                              weight: 0.15, evidence: 'solid in resource URLs' },
      ],
      requiredMatches: 2,
    },

    /* ── Preact ────────────────────────────────────────────────────── */
    {
      name: 'Preact',
      icon: '⚛️',
      patterns: [
        { source: 'globals',      regex: /\b__PREACT_DEVTOOLS__\b/,             weight: 0.50, evidence: 'Preact DevTools global present' },
        { source: 'scriptSrcs',   regex: /preact(?:\.min)?\.js/i,               weight: 0.40, evidence: 'Preact script loaded' },
        { source: 'resourceUrls', regex: /preact/i,                             weight: 0.20, evidence: 'preact in resource URLs' },
        { source: 'html',         regex: /data-preact/,                         weight: 0.40, evidence: 'data-preact attribute found' },
      ],
      requiredMatches: 2,
    },

    /* ── Qwik ──────────────────────────────────────────────────────── */
    {
      name: 'Qwik',
      icon: '⚡',
      patterns: [
        { source: 'html',         regex: /q:container/,                         weight: 0.50, evidence: 'q:container attribute found' },
        { source: 'scriptSrcs',   regex: /qwikloader/i,                         weight: 0.45, evidence: 'Qwik loader script' },
        { source: 'html',         regex: /on:q[a-z]+=/i,                        weight: 0.35, evidence: 'Qwik event handler attributes' },
        { source: 'resourceUrls', regex: /qwik/i,                               weight: 0.20, evidence: 'qwik in resource URLs' },
      ],
      requiredMatches: 2,
    },

    /* ── Tailwind CSS ──────────────────────────────────────────────── */
    {
      name: 'Tailwind CSS',
      icon: '🎨',
      patterns: [
        { source: 'linkHrefs',    regex: /tailwind/i,                           weight: 0.50, evidence: 'Tailwind CSS stylesheet loaded' },
        { source: 'resourceUrls', regex: /tailwindcss/i,                        weight: 0.45, evidence: 'tailwindcss in resource URL' },
        { source: 'scriptContents', regex: /tailwind/i,                         weight: 0.15, evidence: 'tailwind referenced in inline script' },
        { source: 'html',         regex: /class="[^"]*\b(?:flex|grid|text-(?:sm|lg|xl)|bg-(?:gray|blue|red|green)|rounded-(?:md|lg|xl)|px-\d|py-\d|mt-\d|mb-\d)[^"]*\b(?:flex|grid|text-(?:sm|lg|xl)|bg-(?:gray|blue|red|green)|rounded-(?:md|lg|xl)|px-\d|py-\d|mt-\d|mb-\d)/, weight: 0.30, evidence: 'Multiple Tailwind utility classes on elements' },
      ],
      requiredMatches: 1,
    },

    /* ── Bootstrap ─────────────────────────────────────────────────── */
    {
      name: 'Bootstrap',
      icon: '🅱️',
      patterns: [
        { source: 'linkHrefs',    regex: /bootstrap(?:\.min)?\.css/i,           weight: 0.50, evidence: 'Bootstrap CSS loaded via link' },
        { source: 'scriptSrcs',   regex: /bootstrap(?:\.bundle)?(?:\.min)?\.js/i, weight: 0.45, evidence: 'Bootstrap JS loaded via script' },
        { source: 'resourceUrls', regex: /bootstrap(?:\.min)?\.(?:css|js)/i,    weight: 0.35, evidence: 'Bootstrap in resource URLs' },
        { source: 'html',         regex: /class="[^"]*\bbootstrap\b/i,         weight: 0.20, evidence: 'bootstrap class in DOM' },
      ],
      requiredMatches: 1,
    },
  ];
})();
