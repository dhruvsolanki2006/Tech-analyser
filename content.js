/**
 * TechStack Detector — Content Script
 *
 * Injected into the active tab after all detector modules and the
 * scan engine have been loaded. Runs the scan and sends results
 * back to the background service worker via chrome.runtime messaging.
 */
(() => {
  'use strict';

  /* No re-execution guard — each scan must run fresh */

  const utils = self.TechStackUtils || {};

  function normalizePageKey(rawUrl) {
    if (utils.normalizePageKey) return utils.normalizePageKey(rawUrl);
    try {
      const url = new URL(rawUrl);
      return `${url.origin}${url.pathname}`;
    } catch {
      return rawUrl || '';
    }
  }

  async function run() {
    try {
      if (!self.TechScanEngine || typeof self.TechScanEngine.scan !== 'function') {
        throw new Error('Scan engine was not loaded.');
      }

      const result = await self.TechScanEngine.scan();

      chrome.runtime.sendMessage({
        type: 'TECHSTACK_RESULT',
        pageKey: result.pageKey || normalizePageKey(location.href),
        url: result.url,
        title: result.title,
        result,
      });
    } catch (error) {
      chrome.runtime.sendMessage({
        type: 'TECHSTACK_RESULT',
        pageKey: normalizePageKey(location.href),
        url: location.href,
        title: document.title || '',
        error: error?.message || String(error),
      });
    } finally {
      /* Clean up probe data attributes AFTER scan completes */
      try {
        document.documentElement.removeAttribute('data-techstack-globals');
        document.documentElement.removeAttribute('data-techstack-headers');
      } catch { /* ignore */ }
    }
  }

  run();
})();