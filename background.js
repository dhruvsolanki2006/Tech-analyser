/**
 * CyberScope — Background Service Worker (Manifest V3)
 *
 * Responsibilities:
 *  1. Handle SCAN_ACTIVE_TAB messages from the popup
 *  2. Inject globals-probe.js in MAIN world, then all detector
 *     modules + scan engine + content script in ISOLATED world
 *  3. Store scan results keyed by page URL
 */

/* ── Installation log ─────────────────────────────────────────────── */
chrome.runtime.onInstalled.addListener(() => {
  console.log('[TechStack] Extension installed / updated');
});

/* ── Files to inject (order matters) ──────────────────────────────── */
const DETECTOR_FILES = [
  'utils.js',
  'detectors/frontend.js',
  'detectors/cms.js',
  'detectors/libraries.js',
  'detectors/backend.js',
  'detectors/webserver.js',
  'detectors/hosting.js',
  'detectors/cdn.js',
  'detectors/analytics.js',
  'detectors/security.js',
  'detectors/payments.js',
  'detectors/fonts.js',
  'detectors/tagmanagers.js',
  'detectors/marketing.js',
  'scanEngine.js',
  'content.js',
];

/**
 * Small delay helper — gives globals-probe time to
 * write its data attribute before the content script reads it.
 */
function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/* ── Message handler ──────────────────────────────────────────────── */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  /* ── Popup requests a scan ──────────────────────────────────────── */
  if (message?.type === 'SCAN_ACTIVE_TAB') {
    (async () => {
      try {
        const { tabId } = message;

        /* Step 1: Inject globals probe in MAIN world */
        await chrome.scripting.executeScript({
          target: { tabId },
          files: ['globals-probe.js'],
          world: 'MAIN',
        });

        /* Wait for MAIN-world probe to complete:
           - globals are written synchronously (instant)
           - headers are fetched via async HEAD request (needs time) */
        await delay(500);

        /* Step 2: Inject all detector modules + engine + content
           in the ISOLATED world (default) */
        await chrome.scripting.executeScript({
          target: { tabId },
          files: DETECTOR_FILES,
        });

        sendResponse({ ok: true });
      } catch (error) {
        console.error('[TechStack] Scan injection failed:', error);
        sendResponse({
          ok: false,
          error: error?.message || String(error),
        });
      }
    })();

    return true; // keep channel open for async sendResponse
  }

  /* ── Content script sends back results ──────────────────────────── */
  if (message?.type === 'TECHSTACK_RESULT') {
    const key = `scan:${message.pageKey}`;
    chrome.storage.local.set({
      [key]: {
        pageKey: message.pageKey,
        title: message.title || '',
        url: message.url || '',
        result: message.result || null,
        error: message.error || null,
        storedAt: Date.now(),
      },
    });
  }
});