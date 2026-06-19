/**
 * TechStack Detector — CMS / Commerce Signatures
 *
 * Each CMS signature uses multiple, platform-specific signals
 * (meta generator tags, unique resource paths, cookies, JS globals)
 * to avoid false positives from generic word matches.
 */
(() => {
  'use strict';
  self.TechDetectors = self.TechDetectors || {};

  self.TechDetectors.cms = [
    /* ── WordPress ─────────────────────────────────────────────────── */
    {
      name: 'WordPress',
      icon: '📝',
      patterns: [
        { source: 'resourceUrls', regex: /\/wp-content\//,                     weight: 0.45, evidence: '/wp-content/ resource path' },
        { source: 'resourceUrls', regex: /\/wp-includes\//,                    weight: 0.45, evidence: '/wp-includes/ resource path' },
        { source: 'metaTags',     regex: /generator[^>]*wordpress/i,           weight: 0.50, evidence: '<meta name="generator"> says WordPress' },
        { source: 'linkHrefs',    regex: /\/wp-json\//,                        weight: 0.40, evidence: 'WP REST API link present' },
        { source: 'html',         regex: /wp-emoji-release/,                   weight: 0.30, evidence: 'WordPress emoji loader script' },
        { source: 'scriptSrcs',   regex: /\/wp-content\/|\/wp-includes\//,     weight: 0.35, evidence: 'Script loaded from wp-content/includes' },
        { source: 'cookies',      regex: /wordpress_logged_in/i,               weight: 0.25, evidence: 'WordPress login cookie' },
        { source: 'globals',      regex: /\bwp\b/,                             weight: 0.20, evidence: 'window.wp global object' },
      ],
      requiredMatches: 2,
    },

    /* ── Shopify ───────────────────────────────────────────────────── */
    {
      name: 'Shopify',
      icon: '🛍️',
      patterns: [
        { source: 'resourceUrls', regex: /cdn\.shopify\.com/,                  weight: 0.50, evidence: 'cdn.shopify.com resource loaded' },
        { source: 'globals',      regex: /\bShopify\b/,                        weight: 0.50, evidence: 'window.Shopify global present' },
        { source: 'html',         regex: /shopify-section/,                    weight: 0.40, evidence: 'shopify-section element found' },
        { source: 'metaTags',     regex: /shopify-digital-wallet/i,            weight: 0.35, evidence: 'Shopify digital wallet meta tag' },
        { source: 'scriptSrcs',   regex: /cdn\.shopify\.com/,                  weight: 0.40, evidence: 'Script from cdn.shopify.com' },
        { source: 'linkHrefs',    regex: /cdn\.shopify\.com/,                  weight: 0.30, evidence: 'Stylesheet from cdn.shopify.com' },
        { source: 'html',         regex: /myshopify\.com/,                     weight: 0.25, evidence: 'myshopify.com domain reference' },
      ],
      requiredMatches: 2,
    },

    /* ── Magento / Adobe Commerce ──────────────────────────────────── */
    {
      name: 'Magento',
      icon: '🧲',
      patterns: [
        { source: 'scriptSrcs',   regex: /\/mage\/|mage\/cookies/i,           weight: 0.45, evidence: 'Magento mage/ script path' },
        { source: 'globals',      regex: /\bMage\b/,                           weight: 0.45, evidence: 'window.Mage global present' },
        { source: 'html',         regex: /\/static\/version[0-9]+\//,         weight: 0.35, evidence: 'Magento versioned static path' },
        { source: 'metaTags',     regex: /generator[^>]*magento/i,             weight: 0.50, evidence: '<meta name="generator"> says Magento' },
        { source: 'cookies',      regex: /\bform_key\b/,                       weight: 0.20, evidence: 'Magento form_key cookie' },
        { source: 'html',         regex: /data-mage-init/,                     weight: 0.40, evidence: 'data-mage-init attribute' },
        { source: 'scriptContents', regex: /require\.config.*Magento/i,        weight: 0.35, evidence: 'Magento RequireJS configuration' },
      ],
      requiredMatches: 2,
    },

    /* ── Drupal ────────────────────────────────────────────────────── */
    {
      name: 'Drupal',
      icon: '💧',
      patterns: [
        { source: 'globals',      regex: /\bDrupal\b/,                         weight: 0.50, evidence: 'window.Drupal global present' },
        { source: 'metaTags',     regex: /generator[^>]*drupal/i,              weight: 0.50, evidence: '<meta name="generator"> says Drupal' },
        { source: 'scriptContents', regex: /drupalSettings/i,                  weight: 0.40, evidence: 'drupalSettings in inline script' },
        { source: 'resourceUrls', regex: /\/sites\/default\/files\//,          weight: 0.40, evidence: 'Drupal /sites/default/files/ path' },
        { source: 'scriptSrcs',   regex: /drupal\.js/i,                        weight: 0.35, evidence: 'drupal.js script loaded' },
        { source: 'html',         regex: /data-drupal-/,                       weight: 0.35, evidence: 'data-drupal-* attribute found' },
      ],
      requiredMatches: 2,
    },

    /* ── Joomla ────────────────────────────────────────────────────── */
    {
      name: 'Joomla',
      icon: '🟣',
      patterns: [
        { source: 'globals',      regex: /\bJoomla\b/,                         weight: 0.50, evidence: 'window.Joomla global present' },
        { source: 'metaTags',     regex: /generator[^>]*joomla/i,              weight: 0.50, evidence: '<meta name="generator"> says Joomla' },
        { source: 'resourceUrls', regex: /\/media\/jui\//,                     weight: 0.40, evidence: 'Joomla /media/jui/ path' },
        { source: 'scriptSrcs',   regex: /\/media\/system\/js\//,              weight: 0.30, evidence: 'Joomla system JS path' },
        { source: 'html',         regex: /\/components\/com_/,                 weight: 0.35, evidence: 'Joomla component path' },
        { source: 'scriptContents', regex: /Joomla\.optionsStorage/i,          weight: 0.40, evidence: 'Joomla.optionsStorage in inline script' },
      ],
      requiredMatches: 2,
    },

    /* ── Ghost ─────────────────────────────────────────────────────── */
    {
      name: 'Ghost',
      icon: '👻',
      patterns: [
        { source: 'metaTags',     regex: /generator[^>]*ghost/i,               weight: 0.50, evidence: '<meta name="generator"> says Ghost' },
        { source: 'html',         regex: /ghost-portal-root/,                  weight: 0.45, evidence: 'ghost-portal-root element found' },
        { source: 'scriptSrcs',   regex: /ghost\/api\//,                       weight: 0.45, evidence: 'Ghost API script loaded' },
        { source: 'linkHrefs',    regex: /ghost\/api\//,                       weight: 0.35, evidence: 'Ghost API link href' },
        { source: 'html',         regex: /class="gh-/,                         weight: 0.25, evidence: 'Ghost theme gh- prefixed classes' },
        { source: 'scriptContents', regex: /ghost\.url/i,                      weight: 0.30, evidence: 'ghost.url in inline script' },
      ],
      requiredMatches: 2,
    },

    /* ── Wix ───────────────────────────────────────────────────────── */
    {
      name: 'Wix',
      icon: '🌐',
      patterns: [
        { source: 'resourceUrls', regex: /static\.wixstatic\.com/,            weight: 0.50, evidence: 'static.wixstatic.com resources' },
        { source: 'resourceUrls', regex: /static\.parastorage\.com/,          weight: 0.40, evidence: 'Wix parastorage resources' },
        { source: 'html',         regex: /wix-warmup-data/,                   weight: 0.40, evidence: 'wix-warmup-data element' },
        { source: 'cookies',      regex: /_wixCIDX/,                          weight: 0.35, evidence: '_wixCIDX cookie' },
        { source: 'metaTags',     regex: /generator[^>]*wix/i,                weight: 0.50, evidence: '<meta name="generator"> says Wix' },
        { source: 'html',         regex: /data-mesh-id=/,                     weight: 0.25, evidence: 'Wix Corvid mesh container' },
      ],
      requiredMatches: 2,
    },

    /* ── Webflow ───────────────────────────────────────────────────── */
    {
      name: 'Webflow',
      icon: '🔷',
      patterns: [
        { source: 'html',         regex: /data-wf-site/,                      weight: 0.50, evidence: 'data-wf-site attribute found' },
        { source: 'html',         regex: /data-wf-page/,                      weight: 0.45, evidence: 'data-wf-page attribute found' },
        { source: 'metaTags',     regex: /generator[^>]*webflow/i,            weight: 0.50, evidence: '<meta name="generator"> says Webflow' },
        { source: 'scriptSrcs',   regex: /assets\.website-files\.com/,        weight: 0.40, evidence: 'Webflow assets domain' },
        { source: 'resourceUrls', regex: /assets\.website-files\.com/,        weight: 0.35, evidence: 'Webflow resources from assets domain' },
        { source: 'linkHrefs',    regex: /assets\.website-files\.com/,        weight: 0.30, evidence: 'Webflow CSS from assets domain' },
      ],
      requiredMatches: 2,
    },

    /* ── Squarespace ───────────────────────────────────────────────── */
    {
      name: 'Squarespace',
      icon: '⬛',
      patterns: [
        { source: 'resourceUrls', regex: /static1\.squarespace\.com/,         weight: 0.50, evidence: 'Squarespace static CDN resources' },
        { source: 'metaTags',     regex: /generator[^>]*squarespace/i,        weight: 0.50, evidence: '<meta name="generator"> says Squarespace' },
        { source: 'globals',      regex: /\bsquarespace\b/,                   weight: 0.40, evidence: 'window.squarespace global' },
        { source: 'html',         regex: /class="sqs-/,                       weight: 0.35, evidence: 'Squarespace sqs- prefixed classes' },
        { source: 'html',         regex: /squarespace-headers/,               weight: 0.40, evidence: 'squarespace-headers element' },
        { source: 'scriptSrcs',   regex: /static\.squarespace\.com/,          weight: 0.35, evidence: 'Script from static.squarespace.com' },
      ],
      requiredMatches: 2,
    },

    /* ── HubSpot CMS ───────────────────────────────────────────────── */
    {
      name: 'HubSpot CMS',
      icon: '🟠',
      patterns: [
        { source: 'scriptSrcs',   regex: /js\.hs-scripts\.com/,               weight: 0.50, evidence: 'HubSpot tracking script loaded' },
        { source: 'scriptSrcs',   regex: /js\.hs-analytics\.net/,             weight: 0.40, evidence: 'HubSpot analytics script loaded' },
        { source: 'html',         regex: /hubspot-messages-iframe/,            weight: 0.40, evidence: 'HubSpot messages iframe element' },
        { source: 'scriptContents', regex: /_hsp\.push/,                       weight: 0.35, evidence: '_hsp.push in inline script' },
        { source: 'html',         regex: /hs-cta-wrapper/,                    weight: 0.30, evidence: 'HubSpot CTA wrapper element' },
        { source: 'cookies',      regex: /__hs_opt_out/,                       weight: 0.25, evidence: 'HubSpot opt-out cookie' },
      ],
      requiredMatches: 2,
    },

    /* ── Adobe Commerce (Magento 2 / Adobe) ────────────────────────── */
    {
      name: 'Adobe Commerce',
      icon: '🔴',
      patterns: [
        { source: 'html',         regex: /commerce\.adobe\.com/,               weight: 0.50, evidence: 'Adobe Commerce domain reference' },
        { source: 'metaTags',     regex: /generator[^>]*adobe commerce/i,      weight: 0.50, evidence: '<meta name="generator"> says Adobe Commerce' },
        { source: 'scriptContents', regex: /adobe.*commerce/i,                 weight: 0.30, evidence: 'Adobe Commerce in inline script' },
        { source: 'html',         regex: /data-mage-init.*configurable/i,      weight: 0.35, evidence: 'Adobe Commerce configurable product' },
      ],
      requiredMatches: 2,
    },
  ];
})();
