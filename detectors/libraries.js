/**
 * TechStack Detector — JavaScript Library Signatures
 *
 * New detection category for popular JS libraries.
 * Primary detection via window globals (from globals-probe) and
 * CDN script URLs. requiredMatches: 1 is acceptable here because
 * globals like window.jQuery are highly specific.
 */
(() => {
  'use strict';
  self.TechDetectors = self.TechDetectors || {};

  self.TechDetectors.libraries = [
    /* ── jQuery ────────────────────────────────────────────────────── */
    {
      name: 'jQuery',
      icon: '📘',
      patterns: [
        { source: 'globals',      regex: /\bjQuery\b/,                         weight: 0.55, evidence: 'window.jQuery global present' },
        { source: 'scriptSrcs',   regex: /jquery(?:\.min)?\.js/i,              weight: 0.50, evidence: 'jQuery script loaded' },
        { source: 'resourceUrls', regex: /jquery(?:\.min)?\.js/i,              weight: 0.35, evidence: 'jQuery in resource URLs' },
        { source: 'html',         regex: /jquery(?:\.min)?\.js/i,              weight: 0.40, evidence: 'jQuery script reference in HTML' },
      ],
      requiredMatches: 1,
    },

    /* ── Lodash ────────────────────────────────────────────────────── */
    {
      name: 'Lodash',
      icon: '🔧',
      patterns: [
        { source: 'scriptSrcs',   regex: /lodash(?:\.min)?\.js/i,             weight: 0.55, evidence: 'Lodash script loaded' },
        { source: 'resourceUrls', regex: /lodash(?:\.min)?\.js/i,             weight: 0.40, evidence: 'Lodash in resource URLs' },
        { source: 'html',         regex: /lodash(?:\.min)?\.js/i,             weight: 0.40, evidence: 'Lodash script reference in HTML' },
        { source: 'scriptContents', regex: /lodash\.VERSION/i,                 weight: 0.35, evidence: 'Lodash version string in code' },
      ],
      requiredMatches: 1,
    },

    /* ── Moment.js ─────────────────────────────────────────────────── */
    {
      name: 'Moment.js',
      icon: '⏰',
      patterns: [
        { source: 'globals',      regex: /\bmoment\b/,                         weight: 0.50, evidence: 'window.moment global present' },
        { source: 'scriptSrcs',   regex: /moment(?:\.min)?\.js/i,             weight: 0.50, evidence: 'Moment.js script loaded' },
        { source: 'resourceUrls', regex: /moment(?:\.min)?\.js/i,             weight: 0.35, evidence: 'Moment.js in resource URLs' },
        { source: 'html',         regex: /moment(?:\.min)?\.js/i,             weight: 0.40, evidence: 'Moment.js script reference in HTML' },
      ],
      requiredMatches: 1,
    },

    /* ── Day.js ────────────────────────────────────────────────────── */
    {
      name: 'Day.js',
      icon: '📅',
      patterns: [
        { source: 'globals',      regex: /\bdayjs\b/,                          weight: 0.55, evidence: 'window.dayjs global present' },
        { source: 'scriptSrcs',   regex: /dayjs(?:\.min)?\.js/i,              weight: 0.50, evidence: 'Day.js script loaded' },
        { source: 'resourceUrls', regex: /dayjs(?:\.min)?\.js/i,              weight: 0.35, evidence: 'Day.js in resource URLs' },
      ],
      requiredMatches: 1,
    },

    /* ── Axios ─────────────────────────────────────────────────────── */
    {
      name: 'Axios',
      icon: '📡',
      patterns: [
        { source: 'globals',      regex: /\baxios\b/,                          weight: 0.55, evidence: 'window.axios global present' },
        { source: 'scriptSrcs',   regex: /axios(?:\.min)?\.js/i,              weight: 0.50, evidence: 'Axios script loaded' },
        { source: 'resourceUrls', regex: /axios(?:\.min)?\.js/i,              weight: 0.35, evidence: 'Axios in resource URLs' },
      ],
      requiredMatches: 1,
    },

    /* ── Alpine.js ─────────────────────────────────────────────────── */
    {
      name: 'Alpine.js',
      icon: '🏔️',
      patterns: [
        { source: 'globals',      regex: /\bAlpine\b/,                         weight: 0.50, evidence: 'window.Alpine global present' },
        { source: 'html',         regex: /x-data\s*=/,                         weight: 0.40, evidence: 'x-data Alpine directive found' },
        { source: 'scriptSrcs',   regex: /alpine(?:\.min)?\.js/i,             weight: 0.45, evidence: 'Alpine.js script loaded' },
        { source: 'html',         regex: /x-show\s*=|x-bind\s*=|x-on:/,       weight: 0.25, evidence: 'Alpine directive attributes (x-show, x-bind, x-on)' },
      ],
      requiredMatches: 2,
    },

    /* ── Three.js ──────────────────────────────────────────────────── */
    {
      name: 'Three.js',
      icon: '🎲',
      patterns: [
        { source: 'globals',      regex: /\bTHREE\b/,                          weight: 0.55, evidence: 'window.THREE global present' },
        { source: 'scriptSrcs',   regex: /three(?:\.min)?\.js/i,              weight: 0.50, evidence: 'Three.js script loaded' },
        { source: 'resourceUrls', regex: /three(?:\.min)?\.js/i,              weight: 0.35, evidence: 'Three.js in resource URLs' },
        { source: 'html',         regex: /three(?:\.min)?\.js/i,              weight: 0.40, evidence: 'Three.js script reference in HTML' },
      ],
      requiredMatches: 1,
    },

    /* ── GSAP ──────────────────────────────────────────────────────── */
    {
      name: 'GSAP',
      icon: '🎬',
      patterns: [
        { source: 'globals',      regex: /\bgsap\b/,                           weight: 0.55, evidence: 'window.gsap global present' },
        { source: 'globals',      regex: /\bTweenMax\b/,                       weight: 0.45, evidence: 'window.TweenMax global (GSAP v2)' },
        { source: 'scriptSrcs',   regex: /gsap(?:\.min)?\.js/i,               weight: 0.50, evidence: 'GSAP script loaded' },
        { source: 'resourceUrls', regex: /gsap(?:\.min)?\.js/i,               weight: 0.35, evidence: 'GSAP in resource URLs' },
        { source: 'html',         regex: /gsap(?:\.min)?\.js/i,               weight: 0.40, evidence: 'GSAP script reference in HTML' },
      ],
      requiredMatches: 1,
    },

    /* ── D3.js ─────────────────────────────────────────────────────── */
    {
      name: 'D3.js',
      icon: '📊',
      patterns: [
        { source: 'globals',      regex: /\bd3\b/,                             weight: 0.45, evidence: 'window.d3 global present' },
        { source: 'scriptSrcs',   regex: /d3(?:\.min)?\.js/i,                 weight: 0.50, evidence: 'D3.js script loaded' },
        { source: 'resourceUrls', regex: /d3(?:\.min)?\.js/i,                 weight: 0.35, evidence: 'D3.js in resource URLs' },
        { source: 'html',         regex: /<svg[^>]*class="[^"]*d3/i,           weight: 0.30, evidence: 'D3-generated SVG elements' },
      ],
      requiredMatches: 1,
    },

    /* ── Chart.js ──────────────────────────────────────────────────── */
    {
      name: 'Chart.js',
      icon: '📈',
      patterns: [
        { source: 'globals',      regex: /\bChart\b/,                          weight: 0.45, evidence: 'window.Chart global present' },
        { source: 'scriptSrcs',   regex: /chart(?:\.min)?\.js/i,              weight: 0.45, evidence: 'Chart.js script loaded' },
        { source: 'resourceUrls', regex: /chart\.js|chartjs/i,                weight: 0.35, evidence: 'Chart.js in resource URLs' },
      ],
      requiredMatches: 1,
    },

    /* ── ECharts ───────────────────────────────────────────────────── */
    {
      name: 'ECharts',
      icon: '📉',
      patterns: [
        { source: 'globals',      regex: /\becharts\b/,                        weight: 0.55, evidence: 'window.echarts global present' },
        { source: 'scriptSrcs',   regex: /echarts(?:\.min)?\.js/i,            weight: 0.50, evidence: 'ECharts script loaded' },
        { source: 'resourceUrls', regex: /echarts/i,                          weight: 0.30, evidence: 'ECharts in resource URLs' },
      ],
      requiredMatches: 1,
    },

    /* ── Anime.js ──────────────────────────────────────────────────── */
    {
      name: 'Anime.js',
      icon: '✨',
      patterns: [
        { source: 'globals',      regex: /\banime\b/,                          weight: 0.40, evidence: 'window.anime global present' },
        { source: 'scriptSrcs',   regex: /anime(?:\.min)?\.js/i,              weight: 0.50, evidence: 'Anime.js script loaded' },
        { source: 'resourceUrls', regex: /anime(?:\.min)?\.js/i,              weight: 0.35, evidence: 'Anime.js in resource URLs' },
      ],
      requiredMatches: 1,
    },

    /* ── Swiper ────────────────────────────────────────────────────── */
    {
      name: 'Swiper',
      icon: '📱',
      patterns: [
        { source: 'globals',      regex: /\bSwiper\b/,                         weight: 0.50, evidence: 'window.Swiper global present' },
        { source: 'scriptSrcs',   regex: /swiper(?:-bundle)?(?:\.min)?\.js/i,  weight: 0.50, evidence: 'Swiper script loaded' },
        { source: 'html',         regex: /class="swiper[-\s]/,                weight: 0.35, evidence: 'Swiper CSS class on element' },
        { source: 'linkHrefs',    regex: /swiper(?:-bundle)?(?:\.min)?\.css/i, weight: 0.35, evidence: 'Swiper CSS loaded' },
      ],
      requiredMatches: 1,
    },

    /* ── React Query / TanStack Query ──────────────────────────────── */
    {
      name: 'React Query',
      icon: '🔄',
      patterns: [
        { source: 'globals',      regex: /\b__REACT_QUERY_DEVTOOLS__\b/,       weight: 0.55, evidence: 'React Query DevTools global' },
        { source: 'globals',      regex: /\b__REACT_QUERY_STATE__\b/,          weight: 0.50, evidence: 'React Query state global' },
        { source: 'scriptSrcs',   regex: /@tanstack\/react-query/i,            weight: 0.50, evidence: '@tanstack/react-query in script' },
        { source: 'resourceUrls', regex: /react-query/i,                      weight: 0.30, evidence: 'react-query in resource URLs' },
      ],
      requiredMatches: 1,
    },

    /* ── Redux ─────────────────────────────────────────────────────── */
    {
      name: 'Redux',
      icon: '🔮',
      patterns: [
        { source: 'globals',      regex: /\b__REDUX_DEVTOOLS_EXTENSION__\b/,   weight: 0.55, evidence: 'Redux DevTools extension global' },
        { source: 'scriptSrcs',   regex: /redux(?:\.min)?\.js/i,              weight: 0.50, evidence: 'Redux script loaded' },
        { source: 'resourceUrls', regex: /redux/i,                            weight: 0.20, evidence: 'redux in resource URLs' },
      ],
      requiredMatches: 1,
    },

    /* ── Zustand ───────────────────────────────────────────────────── */
    {
      name: 'Zustand',
      icon: '🐻',
      patterns: [
        { source: 'scriptContents', regex: /zustand/i,                         weight: 0.40, evidence: 'zustand in bundled module' },
        { source: 'resourceUrls', regex: /zustand/i,                          weight: 0.35, evidence: 'zustand in resource URLs' },
        { source: 'scriptSrcs',   regex: /zustand/i,                          weight: 0.45, evidence: 'zustand in script source' },
      ],
      requiredMatches: 1,
    },

    /* ── Framer Motion ─────────────────────────────────────────────── */
    {
      name: 'Framer Motion',
      icon: '🎞️',
      patterns: [
        { source: 'html',         regex: /data-framer-/,                       weight: 0.50, evidence: 'data-framer-* attribute found' },
        { source: 'scriptSrcs',   regex: /framer-motion/i,                    weight: 0.50, evidence: 'framer-motion in script source' },
        { source: 'resourceUrls', regex: /framer-motion/i,                    weight: 0.35, evidence: 'framer-motion in resource URLs' },
        { source: 'html',         regex: /data-projection-id=/,               weight: 0.25, evidence: 'Framer Motion projection attribute' },
      ],
      requiredMatches: 1,
    },

    /* ── Socket.IO ─────────────────────────────────────────────────── */
    {
      name: 'Socket.IO',
      icon: '🔌',
      patterns: [
        { source: 'globals',      regex: /\bio\b/,                             weight: 0.30, evidence: 'window.io global (Socket.IO)' },
        { source: 'scriptSrcs',   regex: /socket\.io(?:\.min)?\.js/i,          weight: 0.55, evidence: 'Socket.IO script loaded' },
        { source: 'resourceUrls', regex: /\/socket\.io\//,                     weight: 0.45, evidence: '/socket.io/ resource path' },
      ],
      requiredMatches: 1,
    },

    /* ── Webpack ───────────────────────────────────────────────────── */
    {
      name: 'Webpack',
      icon: '📦',
      patterns: [
        { source: 'globals',      regex: /\bwebpackJsonp\b/,                   weight: 0.50, evidence: 'webpackJsonp global (Webpack v4)' },
        { source: 'globals',      regex: /\b__webpack_modules__\b/,            weight: 0.50, evidence: '__webpack_modules__ global' },
        { source: 'globals',      regex: /\bwebpackChunk\b/,                   weight: 0.50, evidence: 'webpackChunk global (Webpack v5)' },
        { source: 'scriptContents', regex: /webpackJsonp|__webpack_require__/, weight: 0.35, evidence: 'Webpack runtime in inline script' },
      ],
      requiredMatches: 1,
    },

    /* ── Vite ──────────────────────────────────────────────────────── */
    {
      name: 'Vite',
      icon: '⚡',
      patterns: [
        { source: 'globals',      regex: /\b__vite_plugin_react_preamble_installed__\b/, weight: 0.55, evidence: 'Vite React preamble global' },
        { source: 'html',         regex: /\/@vite\//,                          weight: 0.50, evidence: '/@vite/ module path' },
        { source: 'linkHrefs',    regex: /modulepreload/,                      weight: 0.20, evidence: 'modulepreload link (common in Vite)' },
        { source: 'scriptSrcs',   regex: /\/assets\/index-[a-zA-Z0-9]+\.js/,  weight: 0.20, evidence: 'Vite-style hashed asset paths' },
      ],
      requiredMatches: 2,
    },

    /* ── RequireJS ─────────────────────────────────────────────────── */
    {
      name: 'RequireJS',
      icon: '🔗',
      patterns: [
        { source: 'globals',      regex: /\brequirejs\b/,                      weight: 0.50, evidence: 'window.requirejs global' },
        { source: 'globals',      regex: /\bdefine\b/,                         weight: 0.20, evidence: 'AMD define() global' },
        { source: 'scriptSrcs',   regex: /require(?:\.min)?\.js/i,            weight: 0.45, evidence: 'RequireJS script loaded' },
        { source: 'html',         regex: /data-main=/,                         weight: 0.40, evidence: 'data-main attribute (RequireJS entry)' },
      ],
      requiredMatches: 2,
    },
  ];
})();
