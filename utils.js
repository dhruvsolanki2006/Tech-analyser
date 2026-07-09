/**
 * TechStack Detector — Shared Utilities
 * Eliminates duplication of common helpers across extension scripts.
 * @module utils
 */
(() => {
  'use strict';

  self.TechStackUtils = {
    /**
     * Normalize a URL to origin + pathname for consistent storage keys.
     * @param {string} rawUrl
     * @returns {string}
     */
    normalizePageKey(rawUrl) {
      try {
        const url = new URL(rawUrl);
        return `${url.origin}${url.pathname}`;
      } catch {
        return rawUrl || '';
      }
    },

    /**
     * Escape HTML special characters to prevent XSS in rendered output.
     * @param {*} value
     * @returns {string}
     */
    escapeHtml(value) {
      return String(value)
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
    },

    /**
     * Extract the host portion of a URL for user-friendly display.
     * @param {string} rawUrl
     * @returns {string}
     */
    formatHost(rawUrl) {
      try {
        return new URL(rawUrl).host;
      } catch {
        return rawUrl || 'Unknown site';
      }
    }
  };
})();

