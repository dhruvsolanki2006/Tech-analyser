/**
 * TechStack Detector — Fonts & Icon Library Signatures
 *
 * Detects popular font services and icon libraries via CDN URLs,
 * stylesheet references, and class-name patterns in the DOM.
 */
(() => {
  'use strict';
  self.TechDetectors = self.TechDetectors || {};

  self.TechDetectors.fonts = [
    /* ── Google Fonts ──────────────────────────────────────────────── */
    {
      name: 'Google Fonts',
      icon: '🔤',
      patterns: [
        { source: 'linkHrefs',    regex: /fonts\.googleapis\.com/,              weight: 0.55, evidence: 'Google Fonts stylesheet loaded' },
        { source: 'resourceUrls', regex: /fonts\.gstatic\.com/,                weight: 0.50, evidence: 'Google Fonts files from gstatic' },
        { source: 'html',         regex: /fonts\.googleapis\.com/,              weight: 0.45, evidence: 'Google Fonts reference in HTML' },
        { source: 'resourceUrls', regex: /fonts\.googleapis\.com/,              weight: 0.50, evidence: 'Google Fonts API in resources' },
      ],
      requiredMatches: 1,
    },

    /* ── Adobe Fonts (Typekit) ─────────────────────────────────────── */
    {
      name: 'Adobe Fonts',
      icon: '🔤',
      patterns: [
        { source: 'linkHrefs',    regex: /use\.typekit\.net/,                   weight: 0.55, evidence: 'Adobe Fonts (Typekit) stylesheet' },
        { source: 'resourceUrls', regex: /use\.typekit\.net|p\.typekit\.net/,   weight: 0.50, evidence: 'Adobe Fonts resources loaded' },
        { source: 'scriptSrcs',   regex: /use\.typekit\.net/i,                  weight: 0.50, evidence: 'Adobe Fonts JS loader' },
        { source: 'html',         regex: /typekit/i,                            weight: 0.30, evidence: 'Typekit reference in HTML' },
      ],
      requiredMatches: 1,
    },

    /* ── Font Awesome ──────────────────────────────────────────────── */
    {
      name: 'Font Awesome',
      icon: '🎯',
      patterns: [
        { source: 'linkHrefs',    regex: /font-?awesome|fontawesome/i,          weight: 0.55, evidence: 'Font Awesome CSS loaded' },
        { source: 'scriptSrcs',   regex: /fontawesome|font-awesome/i,           weight: 0.50, evidence: 'Font Awesome JS loaded' },
        { source: 'resourceUrls', regex: /fontawesome|font-awesome/i,           weight: 0.45, evidence: 'Font Awesome in resource URLs' },
        { source: 'html',         regex: /class="[^"]*\bfa[srldb]?\s+fa-/,     weight: 0.50, evidence: 'Font Awesome fa-* icon classes' },
        { source: 'html',         regex: /class="[^"]*\bfa-solid\s|fa-regular\s|fa-brands\s/, weight: 0.45, evidence: 'Font Awesome v6 icon classes' },
      ],
      requiredMatches: 1,
    },

    /* ── Material Icons ────────────────────────────────────────────── */
    {
      name: 'Material Icons',
      icon: '🎨',
      patterns: [
        { source: 'linkHrefs',    regex: /material-icons|material\+icons/i,     weight: 0.55, evidence: 'Material Icons stylesheet loaded' },
        { source: 'html',         regex: /class="[^"]*material-icons/,          weight: 0.50, evidence: 'material-icons class in DOM' },
        { source: 'resourceUrls', regex: /material-icons/i,                     weight: 0.40, evidence: 'Material Icons in resources' },
        { source: 'html',         regex: /class="[^"]*material-symbols/,        weight: 0.50, evidence: 'Material Symbols class in DOM' },
      ],
      requiredMatches: 1,
    },

    /* ── Ionicons ──────────────────────────────────────────────────── */
    {
      name: 'Ionicons',
      icon: '⚡',
      patterns: [
        { source: 'scriptSrcs',   regex: /ionicons/i,                           weight: 0.55, evidence: 'Ionicons script loaded' },
        { source: 'resourceUrls', regex: /ionicons/i,                            weight: 0.45, evidence: 'Ionicons in resource URLs' },
        { source: 'html',         regex: /<ion-icon/,                            weight: 0.55, evidence: '<ion-icon> custom element' },
        { source: 'linkHrefs',    regex: /ionicons/i,                            weight: 0.45, evidence: 'Ionicons CSS loaded' },
      ],
      requiredMatches: 1,
    },

    /* ── Bootstrap Icons ───────────────────────────────────────────── */
    {
      name: 'Bootstrap Icons',
      icon: '🅱️',
      patterns: [
        { source: 'linkHrefs',    regex: /bootstrap-icons/i,                    weight: 0.55, evidence: 'Bootstrap Icons CSS loaded' },
        { source: 'resourceUrls', regex: /bootstrap-icons/i,                    weight: 0.45, evidence: 'Bootstrap Icons in resources' },
        { source: 'html',         regex: /class="[^"]*\bbi\s+bi-/,             weight: 0.50, evidence: 'Bootstrap Icons bi-* classes' },
      ],
      requiredMatches: 1,
    },

    /* ── Lucide Icons ──────────────────────────────────────────────── */
    {
      name: 'Lucide Icons',
      icon: '✏️',
      patterns: [
        { source: 'scriptSrcs',   regex: /lucide/i,                             weight: 0.50, evidence: 'Lucide script loaded' },
        { source: 'resourceUrls', regex: /lucide/i,                              weight: 0.40, evidence: 'Lucide in resource URLs' },
        { source: 'html',         regex: /class="[^"]*lucide/,                  weight: 0.45, evidence: 'Lucide icon classes in DOM' },
        { source: 'html',         regex: /data-lucide=/,                         weight: 0.55, evidence: 'data-lucide attribute' },
      ],
      requiredMatches: 1,
    },

    /* ── Heroicons ─────────────────────────────────────────────────── */
    {
      name: 'Heroicons',
      icon: '🦸',
      patterns: [
        { source: 'scriptSrcs',   regex: /heroicons/i,                          weight: 0.55, evidence: 'Heroicons script loaded' },
        { source: 'resourceUrls', regex: /heroicons/i,                           weight: 0.45, evidence: 'Heroicons in resource URLs' },
        { source: 'html',         regex: /heroicon/i,                            weight: 0.35, evidence: 'Heroicon reference in HTML' },
      ],
      requiredMatches: 1,
    },
  ];
})();
