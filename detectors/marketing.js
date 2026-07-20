/**
 * TechStack Detector — Email, Marketing & Live Chat Signatures
 *
 * Detects marketing automation, email tools, and live chat widgets
 * via script URLs, globals, and DOM element patterns.
 */
(() => {
  'use strict';
  self.TechDetectors = self.TechDetectors || {};

  self.TechDetectors.marketing = [
    /* ── Mailchimp ─────────────────────────────────────────────────── */
    {
      name: 'Mailchimp',
      icon: '📧',
      patterns: [
        { source: 'scriptSrcs',    regex: /chimpstatic\.com|list-manage\.com/i,  weight: 0.55, evidence: 'Mailchimp script loaded' },
        { source: 'resourceUrls',  regex: /mailchimp\.com|chimpstatic/i,         weight: 0.50, evidence: 'Mailchimp resources loaded' },
        { source: 'html',          regex: /mc-embedded-subscribe|mailchimp/i,    weight: 0.45, evidence: 'Mailchimp form/subscribe element' },
        { source: 'html',          regex: /list-manage\.com/i,                   weight: 0.40, evidence: 'Mailchimp list-manage domain in HTML' },
      ],
      requiredMatches: 1,
    },

    /* ── Intercom ──────────────────────────────────────────────────── */
    {
      name: 'Intercom',
      icon: '💬',
      patterns: [
        { source: 'scriptSrcs',    regex: /widget\.intercom\.io/i,               weight: 0.55, evidence: 'Intercom widget script loaded' },
        { source: 'resourceUrls',  regex: /intercom\.io/i,                       weight: 0.55, evidence: 'Intercom resources loaded' },
        { source: 'globals',       regex: /\bIntercom\b/,                        weight: 0.55, evidence: 'window.Intercom global present' },
        { source: 'html',          regex: /intercom-lightweight-app|intercom-container/i, weight: 0.50, evidence: 'Intercom widget container' },
        { source: 'scriptContents', regex: /intercomSettings/i,                  weight: 0.40, evidence: 'intercomSettings in inline script' },
      ],
      requiredMatches: 1,
    },

    /* ── Drift ─────────────────────────────────────────────────────── */
    {
      name: 'Drift',
      icon: '💬',
      patterns: [
        { source: 'scriptSrcs',    regex: /js\.driftt\.com|drift\.com/i,         weight: 0.55, evidence: 'Drift chat script loaded' },
        { source: 'resourceUrls',  regex: /drift\.com|driftt\.com/i,             weight: 0.55, evidence: 'Drift resources loaded' },
        { source: 'globals',       regex: /\bdrift\b/,                           weight: 0.40, evidence: 'window.drift global' },
        { source: 'html',          regex: /drift-frame-controller|drift-widget/i, weight: 0.50, evidence: 'Drift widget elements' },
      ],
      requiredMatches: 1,
    },

    /* ── Crisp ─────────────────────────────────────────────────────── */
    {
      name: 'Crisp',
      icon: '💬',
      patterns: [
        { source: 'scriptSrcs',    regex: /client\.crisp\.chat/i,                weight: 0.55, evidence: 'Crisp chat script loaded' },
        { source: 'resourceUrls',  regex: /crisp\.chat/i,                        weight: 0.55, evidence: 'Crisp resources loaded' },
        { source: 'globals',       regex: /\bCRISP_WEBSITE_ID\b/,                weight: 0.55, evidence: 'CRISP_WEBSITE_ID global' },
        { source: 'globals',       regex: /\b\$crisp\b/,                         weight: 0.50, evidence: 'window.$crisp global' },
        { source: 'html',          regex: /crisp-client/i,                       weight: 0.45, evidence: 'Crisp client element in DOM' },
      ],
      requiredMatches: 1,
    },

    /* ── Zendesk ───────────────────────────────────────────────────── */
    {
      name: 'Zendesk',
      icon: '🎧',
      patterns: [
        { source: 'scriptSrcs',    regex: /static\.zdassets\.com|zendesk/i,      weight: 0.55, evidence: 'Zendesk script loaded' },
        { source: 'resourceUrls',  regex: /zendesk\.com|zdassets\.com/i,         weight: 0.55, evidence: 'Zendesk resources loaded' },
        { source: 'globals',       regex: /\bzE\b/,                              weight: 0.45, evidence: 'window.zE global (Zendesk)' },
        { source: 'html',          regex: /zendesk|zd-chat/i,                   weight: 0.35, evidence: 'Zendesk elements in DOM' },
        { source: 'html',          regex: /launcher-frame|web-widget/i,          weight: 0.25, evidence: 'Zendesk widget launcher frame' },
      ],
      requiredMatches: 1,
    },

    /* ── Tawk.to ───────────────────────────────────────────────────── */
    {
      name: 'Tawk.to',
      icon: '💬',
      patterns: [
        { source: 'scriptSrcs',    regex: /embed\.tawk\.to/i,                   weight: 0.55, evidence: 'Tawk.to embed script loaded' },
        { source: 'resourceUrls',  regex: /tawk\.to/i,                          weight: 0.55, evidence: 'Tawk.to resources loaded' },
        { source: 'globals',       regex: /\bTawk_API\b/,                        weight: 0.55, evidence: 'window.Tawk_API global' },
        { source: 'html',          regex: /tawk-messenger/i,                     weight: 0.50, evidence: 'Tawk messenger container' },
        { source: 'scriptContents', regex: /tawk\.to/i,                          weight: 0.35, evidence: 'tawk.to in inline script' },
      ],
      requiredMatches: 1,
    },

    /* ── LiveChat ──────────────────────────────────────────────────── */
    {
      name: 'LiveChat',
      icon: '💬',
      patterns: [
        { source: 'scriptSrcs',    regex: /cdn\.livechatinc\.com/i,              weight: 0.55, evidence: 'LiveChat CDN script loaded' },
        { source: 'resourceUrls',  regex: /livechatinc\.com/i,                   weight: 0.55, evidence: 'LiveChat resources loaded' },
        { source: 'globals',       regex: /\bLC_API\b/,                          weight: 0.55, evidence: 'window.LC_API global' },
        { source: 'globals',       regex: /\bLiveChat\b/,                        weight: 0.45, evidence: 'window.LiveChat global' },
        { source: 'html',          regex: /livechat/i,                           weight: 0.25, evidence: 'LiveChat reference in HTML' },
      ],
      requiredMatches: 1,
    },

    /* ── HubSpot Chat ──────────────────────────────────────────────── */
    {
      name: 'HubSpot Chat',
      icon: '🟠',
      patterns: [
        { source: 'scriptSrcs',    regex: /js\.usemessages\.com/i,               weight: 0.55, evidence: 'HubSpot Conversations script' },
        { source: 'html',          regex: /hubspot-messages-iframe/,             weight: 0.55, evidence: 'HubSpot messages iframe' },
        { source: 'resourceUrls',  regex: /js\.usemessages\.com/i,               weight: 0.50, evidence: 'HubSpot messages resources' },
        { source: 'globals',       regex: /\bHubSpotConversations\b/,            weight: 0.55, evidence: 'HubSpotConversations global' },
        { source: 'html',          regex: /hs-chat-widget/i,                     weight: 0.45, evidence: 'HubSpot chat widget element' },
      ],
      requiredMatches: 1,
    },
  ];
})();
