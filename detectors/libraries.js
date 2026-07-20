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
        { source: 'globals',        regex: /\bgsap\b/,                                          weight: 0.55, evidence: 'window.gsap global present' },
        { source: 'globals',        regex: /\bTweenMax\b/,                                      weight: 0.45, evidence: 'window.TweenMax global (GSAP v2)' },
        { source: 'globals',        regex: /\bTweenLite\b/,                                     weight: 0.45, evidence: 'window.TweenLite global (GSAP v2)' },
        { source: 'globals',        regex: /\bScrollTrigger\b/,                                  weight: 0.45, evidence: 'window.ScrollTrigger global (GSAP plugin)' },
        { source: 'scriptSrcs',     regex: /gsap(?:\.min)?\.js/i,                               weight: 0.50, evidence: 'GSAP script loaded' },
        { source: 'scriptSrcs',     regex: /\/gsap(?:@[\d.]+)?(?:\/dist)?\/?/i,                  weight: 0.45, evidence: 'GSAP CDN package path in script' },
        { source: 'scriptSrcs',     regex: /ScrollTrigger(?:\.min)?\.js/i,                       weight: 0.45, evidence: 'GSAP ScrollTrigger plugin loaded' },
        { source: 'resourceUrls',   regex: /gsap(?:\.min)?\.js|\/gsap(?:@[\d.]+)?\/?/i,          weight: 0.35, evidence: 'GSAP in resource URLs' },
        { source: 'html',           regex: /gsap(?:\.min)?\.js|\/gsap(?:@[\d.]+)?\/?/i,          weight: 0.40, evidence: 'GSAP script reference in HTML' },
        { source: 'scriptContents', regex: /gsap\.registerPlugin|gsap\.to\(|gsap\.from\(|gsap\.timeline\(/i, weight: 0.50, evidence: 'GSAP API calls in inline scripts' },
        { source: 'scriptContents', regex: /ScrollTrigger\.create|ScrollTrigger\.defaults/i,     weight: 0.40, evidence: 'GSAP ScrollTrigger API in inline scripts' },
        { source: 'scriptContents', regex: /TweenMax\.to\(|TweenLite\.to\(/i,                    weight: 0.40, evidence: 'GSAP v2 TweenMax/TweenLite API calls' },
        { source: 'html',           regex: /data-gsap|data-scroll-trigger/i,                     weight: 0.35, evidence: 'GSAP-related data attributes in HTML' },
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

    /* ══════════════════════════════════════════════════════════════════
     *  NEW ADDITIONS BELOW
     * ══════════════════════════════════════════════════════════════════ */

    /* ── Underscore.js ─────────────────────────────────────────────── */
    {
      name: 'Underscore.js',
      icon: '🔧',
      patterns: [
        { source: 'scriptSrcs',   regex: /underscore(?:\.min)?\.js/i,          weight: 0.55, evidence: 'Underscore.js script loaded' },
        { source: 'resourceUrls', regex: /underscore(?:\.min)?\.js/i,          weight: 0.40, evidence: 'Underscore.js in resource URLs' },
        { source: 'scriptContents', regex: /Underscore\.VERSION/,              weight: 0.45, evidence: 'Underscore.VERSION string in code' },
      ],
      requiredMatches: 1,
    },

    /* ── Backbone.js ───────────────────────────────────────────────── */
    {
      name: 'Backbone.js',
      icon: '🦴',
      patterns: [
        { source: 'globals',      regex: /\bBackbone\b/,                       weight: 0.55, evidence: 'window.Backbone global present' },
        { source: 'scriptSrcs',   regex: /backbone(?:\.min)?\.js/i,            weight: 0.50, evidence: 'Backbone.js script loaded' },
        { source: 'resourceUrls', regex: /backbone(?:\.min)?\.js/i,            weight: 0.35, evidence: 'Backbone.js in resource URLs' },
      ],
      requiredMatches: 1,
    },

    /* ── Knockout.js ───────────────────────────────────────────────── */
    {
      name: 'Knockout.js',
      icon: '🥊',
      patterns: [
        { source: 'globals',      regex: /\bko\b/,                             weight: 0.40, evidence: 'window.ko global present' },
        { source: 'scriptSrcs',   regex: /knockout(?:\.min)?\.js/i,            weight: 0.55, evidence: 'Knockout.js script loaded' },
        { source: 'html',         regex: /data-bind="/,                        weight: 0.40, evidence: 'Knockout data-bind attribute' },
        { source: 'resourceUrls', regex: /knockout/i,                          weight: 0.30, evidence: 'Knockout in resource URLs' },
      ],
      requiredMatches: 2,
    },

    /* ── RxJS ──────────────────────────────────────────────────────── */
    {
      name: 'RxJS',
      icon: '🔄',
      patterns: [
        { source: 'scriptSrcs',   regex: /rxjs(?:\.min)?\.js/i,                weight: 0.55, evidence: 'RxJS script loaded' },
        { source: 'resourceUrls', regex: /rxjs/i,                              weight: 0.35, evidence: 'RxJS in resource URLs' },
        { source: 'scriptContents', regex: /rxjs|Observable\.subscribe/i,      weight: 0.30, evidence: 'RxJS or Observable.subscribe in code' },
      ],
      requiredMatches: 1,
    },

    /* ── Lottie ────────────────────────────────────────────────────── */
    {
      name: 'Lottie',
      icon: '🎬',
      patterns: [
        { source: 'globals',      regex: /\blottie\b/,                         weight: 0.50, evidence: 'window.lottie global present' },
        { source: 'globals',      regex: /\bbodymovin\b/,                      weight: 0.50, evidence: 'window.bodymovin global present' },
        { source: 'scriptSrcs',   regex: /lottie(?:\.min)?\.js|bodymovin/i,    weight: 0.50, evidence: 'Lottie/bodymovin script loaded' },
        { source: 'resourceUrls', regex: /lottie|bodymovin/i,                  weight: 0.35, evidence: 'Lottie/bodymovin in resources' },
        { source: 'html',         regex: /lottie-player|dotlottie-player/i,    weight: 0.50, evidence: 'Lottie player custom element' },
      ],
      requiredMatches: 1,
    },

    /* ── Highcharts ────────────────────────────────────────────────── */
    {
      name: 'Highcharts',
      icon: '📊',
      patterns: [
        { source: 'globals',      regex: /\bHighcharts\b/,                     weight: 0.55, evidence: 'window.Highcharts global present' },
        { source: 'scriptSrcs',   regex: /highcharts(?:\.min)?\.js/i,          weight: 0.55, evidence: 'Highcharts script loaded' },
        { source: 'resourceUrls', regex: /highcharts/i,                        weight: 0.35, evidence: 'Highcharts in resource URLs' },
        { source: 'html',         regex: /class="highcharts-/,                 weight: 0.40, evidence: 'Highcharts CSS classes in DOM' },
      ],
      requiredMatches: 1,
    },

    /* ── Leaflet ───────────────────────────────────────────────────── */
    {
      name: 'Leaflet',
      icon: '🗺️',
      patterns: [
        { source: 'globals',      regex: /\bL\b/,                              weight: 0.20, evidence: 'window.L global (Leaflet)' },
        { source: 'scriptSrcs',   regex: /leaflet(?:\.min)?\.js/i,             weight: 0.55, evidence: 'Leaflet script loaded' },
        { source: 'linkHrefs',    regex: /leaflet(?:\.min)?\.css/i,            weight: 0.50, evidence: 'Leaflet CSS loaded' },
        { source: 'html',         regex: /class="leaflet-/,                    weight: 0.50, evidence: 'Leaflet CSS classes in DOM' },
        { source: 'resourceUrls', regex: /leaflet/i,                           weight: 0.30, evidence: 'Leaflet in resource URLs' },
      ],
      requiredMatches: 2,
    },

    /* ── Mapbox GL JS ──────────────────────────────────────────────── */
    {
      name: 'Mapbox GL',
      icon: '🗺️',
      patterns: [
        { source: 'globals',      regex: /\bmapboxgl\b/,                       weight: 0.55, evidence: 'window.mapboxgl global present' },
        { source: 'scriptSrcs',   regex: /mapbox-gl(?:\.min)?\.js/i,           weight: 0.55, evidence: 'Mapbox GL JS script loaded' },
        { source: 'linkHrefs',    regex: /mapbox-gl(?:\.min)?\.css/i,          weight: 0.45, evidence: 'Mapbox GL CSS loaded' },
        { source: 'resourceUrls', regex: /api\.mapbox\.com/i,                  weight: 0.45, evidence: 'Mapbox API in resource URLs' },
        { source: 'html',         regex: /class="mapboxgl-/,                   weight: 0.45, evidence: 'Mapbox GL CSS classes in DOM' },
      ],
      requiredMatches: 1,
    },

    /* ── Hammer.js ─────────────────────────────────────────────────── */
    {
      name: 'Hammer.js',
      icon: '🔨',
      patterns: [
        { source: 'globals',      regex: /\bHammer\b/,                         weight: 0.50, evidence: 'window.Hammer global present' },
        { source: 'scriptSrcs',   regex: /hammer(?:\.min)?\.js/i,              weight: 0.55, evidence: 'Hammer.js script loaded' },
        { source: 'resourceUrls', regex: /hammer(?:\.min)?\.js/i,              weight: 0.35, evidence: 'Hammer.js in resource URLs' },
      ],
      requiredMatches: 1,
    },

    /* ── Popper.js / Floating UI ───────────────────────────────────── */
    {
      name: 'Popper.js',
      icon: '📌',
      patterns: [
        { source: 'globals',      regex: /\bPopper\b/,                         weight: 0.45, evidence: 'window.Popper global present' },
        { source: 'scriptSrcs',   regex: /popper(?:\.min)?\.js/i,              weight: 0.50, evidence: 'Popper.js script loaded' },
        { source: 'scriptSrcs',   regex: /@floating-ui/i,                      weight: 0.50, evidence: 'Floating UI (Popper successor) loaded' },
        { source: 'resourceUrls', regex: /popper|@floating-ui/i,               weight: 0.35, evidence: 'Popper/Floating UI in resources' },
      ],
      requiredMatches: 1,
    },

    /* ── SortableJS ────────────────────────────────────────────────── */
    {
      name: 'SortableJS',
      icon: '↕️',
      patterns: [
        { source: 'globals',      regex: /\bSortable\b/,                       weight: 0.45, evidence: 'window.Sortable global present' },
        { source: 'scriptSrcs',   regex: /Sortable(?:\.min)?\.js|sortablejs/i, weight: 0.55, evidence: 'SortableJS script loaded' },
        { source: 'resourceUrls', regex: /sortablejs|Sortable(?:\.min)?\.js/i, weight: 0.35, evidence: 'SortableJS in resource URLs' },
      ],
      requiredMatches: 1,
    },

    /* ── Masonry ───────────────────────────────────────────────────── */
    {
      name: 'Masonry',
      icon: '🧱',
      patterns: [
        { source: 'globals',      regex: /\bMasonry\b/,                        weight: 0.50, evidence: 'window.Masonry global present' },
        { source: 'scriptSrcs',   regex: /masonry(?:\.pkgd)?(?:\.min)?\.js/i,  weight: 0.55, evidence: 'Masonry script loaded' },
        { source: 'resourceUrls', regex: /masonry/i,                           weight: 0.30, evidence: 'Masonry in resource URLs' },
      ],
      requiredMatches: 1,
    },

    /* ── Prism.js ──────────────────────────────────────────────────── */
    {
      name: 'Prism.js',
      icon: '🌈',
      patterns: [
        { source: 'globals',      regex: /\bPrism\b/,                          weight: 0.45, evidence: 'window.Prism global present' },
        { source: 'scriptSrcs',   regex: /prism(?:\.min)?\.js/i,               weight: 0.55, evidence: 'Prism.js script loaded' },
        { source: 'linkHrefs',    regex: /prism(?:\.min)?\.css/i,              weight: 0.45, evidence: 'Prism.js CSS loaded' },
        { source: 'html',         regex: /class="language-[a-z]+"/,            weight: 0.25, evidence: 'Prism language-* class on code blocks' },
      ],
      requiredMatches: 2,
    },

    /* ── highlight.js ──────────────────────────────────────────────── */
    {
      name: 'highlight.js',
      icon: '🖍️',
      patterns: [
        { source: 'globals',      regex: /\bhljs\b/,                           weight: 0.55, evidence: 'window.hljs global present' },
        { source: 'scriptSrcs',   regex: /highlight(?:\.min)?\.js/i,           weight: 0.50, evidence: 'highlight.js script loaded' },
        { source: 'linkHrefs',    regex: /highlight\.js.*\.css/i,              weight: 0.40, evidence: 'highlight.js CSS theme loaded' },
        { source: 'html',         regex: /class="hljs/,                        weight: 0.45, evidence: 'hljs class on code blocks' },
      ],
      requiredMatches: 2,
    },

    /* ── Turbolinks ────────────────────────────────────────────────── */
    {
      name: 'Turbolinks',
      icon: '🔗',
      patterns: [
        { source: 'globals',      regex: /\bTurbolinks\b/,                     weight: 0.55, evidence: 'window.Turbolinks global present' },
        { source: 'scriptSrcs',   regex: /turbolinks(?:\.min)?\.js/i,          weight: 0.50, evidence: 'Turbolinks script loaded' },
        { source: 'html',         regex: /data-turbolinks-/,                   weight: 0.40, evidence: 'data-turbolinks-* attribute' },
        { source: 'metaTags',     regex: /turbolinks/i,                        weight: 0.30, evidence: 'Turbolinks meta tag' },
      ],
      requiredMatches: 1,
    },

    /* ── Barba.js ──────────────────────────────────────────────────── */
    {
      name: 'Barba.js',
      icon: '🎭',
      patterns: [
        { source: 'globals',      regex: /\bbarba\b/,                          weight: 0.50, evidence: 'window.barba global present' },
        { source: 'scriptSrcs',   regex: /barba(?:\.min)?\.js/i,               weight: 0.55, evidence: 'Barba.js script loaded' },
        { source: 'html',         regex: /data-barba/,                         weight: 0.50, evidence: 'data-barba attribute found' },
        { source: 'resourceUrls', regex: /@barba\/core/i,                      weight: 0.45, evidence: '@barba/core in resource URLs' },
      ],
      requiredMatches: 1,
    },

    /* ── ScrollReveal ──────────────────────────────────────────────── */
    {
      name: 'ScrollReveal',
      icon: '👁️',
      patterns: [
        { source: 'globals',      regex: /\bScrollReveal\b/,                   weight: 0.55, evidence: 'window.ScrollReveal global present' },
        { source: 'scriptSrcs',   regex: /scrollreveal(?:\.min)?\.js/i,        weight: 0.55, evidence: 'ScrollReveal script loaded' },
        { source: 'resourceUrls', regex: /scrollreveal/i,                      weight: 0.35, evidence: 'ScrollReveal in resource URLs' },
      ],
      requiredMatches: 1,
    },

    /* ── AOS (Animate On Scroll) ───────────────────────────────────── */
    {
      name: 'AOS',
      icon: '📜',
      patterns: [
        { source: 'globals',      regex: /\bAOS\b/,                            weight: 0.40, evidence: 'window.AOS global present' },
        { source: 'html',         regex: /data-aos="/,                         weight: 0.50, evidence: 'data-aos attribute on elements' },
        { source: 'scriptSrcs',   regex: /aos(?:\.min)?\.js/i,                 weight: 0.50, evidence: 'AOS script loaded' },
        { source: 'linkHrefs',    regex: /aos(?:\.min)?\.css/i,                weight: 0.40, evidence: 'AOS CSS loaded' },
      ],
      requiredMatches: 2,
    },

    /* ── Typed.js ──────────────────────────────────────────────────── */
    {
      name: 'Typed.js',
      icon: '⌨️',
      patterns: [
        { source: 'globals',      regex: /\bTyped\b/,                          weight: 0.45, evidence: 'window.Typed global present' },
        { source: 'scriptSrcs',   regex: /typed(?:\.min)?\.js/i,               weight: 0.55, evidence: 'Typed.js script loaded' },
        { source: 'resourceUrls', regex: /typed(?:\.min)?\.js/i,               weight: 0.35, evidence: 'Typed.js in resource URLs' },
        { source: 'html',         regex: /class="typed-cursor"/,               weight: 0.40, evidence: 'Typed.js cursor element' },
      ],
      requiredMatches: 1,
    },

    /* ── Particles.js / tsParticles ────────────────────────────────── */
    {
      name: 'Particles.js',
      icon: '✨',
      patterns: [
        { source: 'globals',      regex: /\bparticlesJS\b/,                    weight: 0.55, evidence: 'window.particlesJS global present' },
        { source: 'globals',      regex: /\btsParticles\b/,                    weight: 0.55, evidence: 'window.tsParticles global present' },
        { source: 'scriptSrcs',   regex: /particles(?:\.min)?\.js|tsparticles/i, weight: 0.50, evidence: 'Particles.js/tsParticles script loaded' },
        { source: 'html',         regex: /id="particles-js"/,                  weight: 0.45, evidence: 'particles-js container element' },
        { source: 'resourceUrls', regex: /particles|tsparticles/i,             weight: 0.30, evidence: 'Particles in resource URLs' },
      ],
      requiredMatches: 1,
    },

    /* ── Marked (Markdown Parser) ──────────────────────────────────── */
    {
      name: 'Marked',
      icon: '📝',
      patterns: [
        { source: 'globals',      regex: /\bmarked\b/,                         weight: 0.45, evidence: 'window.marked global present' },
        { source: 'scriptSrcs',   regex: /marked(?:\.min)?\.js/i,              weight: 0.55, evidence: 'Marked script loaded' },
        { source: 'resourceUrls', regex: /marked(?:\.min)?\.js/i,              weight: 0.35, evidence: 'Marked in resource URLs' },
      ],
      requiredMatches: 1,
    },
  ];
})();
