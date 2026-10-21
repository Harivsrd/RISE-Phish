/**
 * RISE-Phish Browser Extension — Content Script Orchestrator
 * 
 * Bridges page DOM lifecycle with website adapters and the background service worker.
 * Observes dynamic webmail updates, extracts message candidates, and renders in-page warnings.
 */

(function () {
  'use strict';

  // Instantiate available adapters
  const adapters = [
    new window.GmailAdapter()
  ];

  // Find matching adapter for current URL
  const currentUrl = window.location.href;
  const activeAdapter = adapters.find(a => a.matches(currentUrl));

  if (!activeAdapter) {
    // Current page is not a supported webmail/messaging platform
    return;
  }

  console.log(`[RISE-Phish] Active adapter initialized: ${activeAdapter.siteIdentifier}`);

  let isScanning = false;
  let cachedSettings = {
    enabled: true,
    autoScan: true,
    showBanner: true
  };

  // Sync settings with background worker
  function refreshSettings() {
    chrome.runtime.sendMessage({ type: 'GET_SETTINGS' }, (response) => {
      if (chrome.runtime.lastError) return;
      if (response && response.settings) {
        cachedSettings = { ...cachedSettings, ...response.settings };
      }
    });
  }

  refreshSettings();

  /**
   * Scans a specific open message container.
   */
  async function scanMessageContainer(container, forceFresh = false) {
    if (!cachedSettings.enabled) return;
    if (isScanning && !forceFresh) return;

    const payload = activeAdapter.extractMessage(container);
    if (!payload || (!payload.body_text && !payload.subject)) {
      return;
    }

    const messageHash = window.MessageContract.hashMessage({
      subject: payload.subject,
      sender: payload.sender,
      bodyText: payload.body_text,
      linksCount: payload.embedded_links.length
    });

    if (!forceFresh && activeAdapter.processedMessageHashes.has(messageHash)) {
      return; // Already scanned
    }

    isScanning = true;
    activeAdapter.processedMessageHashes.add(messageHash);

    try {
      chrome.runtime.sendMessage(
        {
          type: 'ANALYZE_MESSAGE',
          payload: payload
        },
        (response) => {
          isScanning = false;
          if (chrome.runtime.lastError) {
            console.warn('[RISE-Phish] Service worker error:', chrome.runtime.lastError.message);
            return;
          }

          if (response && response.success && response.data) {
            const analysis = response.data;
            if (cachedSettings.showBanner) {
              activeAdapter.injectBanner(container, analysis, () => {
                scanMessageContainer(container, true);
              });
            }
          } else {
            console.error('[RISE-Phish] Analysis failed:', response?.error);
          }
        }
      );
    } catch (err) {
      isScanning = false;
      console.error('[RISE-Phish] Error submitting message scan:', err);
    }
  }

  /**
   * Scans all currently open messages.
   */
  function scanAllOpenMessages(forceFresh = false) {
    const containers = activeAdapter.findOpenMessages();
    containers.forEach(container => {
      scanMessageContainer(container, forceFresh);
    });
  }

  // Set up debounced DOM observer to automatically detect opened messages
  let debounceTimer = null;
  const observer = new MutationObserver(() => {
    if (!cachedSettings.enabled || !cachedSettings.autoScan) return;

    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      scanAllOpenMessages(false);
    }, 600); // 600ms settling time for Gmail dynamic rendering
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true
  });

  // Listen for messages from popup or background worker
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'SCAN_PAGE_MANUAL') {
      const openContainers = activeAdapter.findOpenMessages();
      if (openContainers.length === 0) {
        sendResponse({ success: false, message: 'No open message found on screen.' });
      } else {
        scanAllOpenMessages(true);
        sendResponse({ success: true, message: `Scanning ${openContainers.length} message(s)...` });
      }
      return true;
    }

    if (message.type === 'GET_PAGE_STATUS') {
      const openContainers = activeAdapter.findOpenMessages();
      sendResponse({
        isSupported: true,
        siteIdentifier: activeAdapter.siteIdentifier,
        openMessagesCount: openContainers.length
      });
      return true;
    }
  });

  // Initial scan in case message is already loaded on script injection
  setTimeout(() => {
    if (cachedSettings.autoScan) {
      scanAllOpenMessages(false);
    }
  }, 1000);

})();
