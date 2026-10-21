/**
 * RISE-Phish Browser Extension — Base Website Adapter Interface
 * 
 * Defines standard lifecycle hooks for webmail and messaging platforms:
 * 1. URL pattern matching
 * 2. Message container discovery in dynamic DOM
 * 3. Safe, privacy-preserving extraction of message fields
 * 4. In-page warning banner and badge injection
 */

class BaseSiteAdapter {
  constructor(siteIdentifier = 'generic') {
    this.siteIdentifier = siteIdentifier;
    this.processedMessageHashes = new Set();
  }

  /**
   * Evaluates if this adapter supports the given webpage URL.
   * @param {string} url - Current window.location.href
   * @returns {boolean}
   */
  matches(url) {
    throw new Error('Adapter must implement matches(url)');
  }

  /**
   * Discovers all open/active message containers currently rendered on screen.
   * @returns {HTMLElement[]}
   */
  findOpenMessages() {
    throw new Error('Adapter must implement findOpenMessages()');
  }

  /**
   * Safely extracts message subject, sender, body text, and links from a message container.
   * @param {HTMLElement} container - The DOM element containing the message
   * @returns {Object|null}
   */
  extractMessage(container) {
    throw new Error('Adapter must implement extractMessage(container)');
  }

  /**
   * Injects an explainable security advisory banner into the message view.
   * @param {HTMLElement} container - Message DOM container
   * @param {Object} analysis - Analysis response from backend
   * @param {Function} onRescan - Callback to trigger a fresh scan
   */
  injectBanner(container, analysis, onRescan) {
    throw new Error('Adapter must implement injectBanner(...)');
  }

  /**
   * Injects warning chips or indicators adjacent to analyzed links.
   * @param {HTMLElement} container - Message DOM container
   * @param {Object[]} linkAnalyses - List of link verdict objects
   */
  injectLinkBadges(container, linkAnalyses) {
    // Default no-op if adapter does not support inline link badges
  }

  /**
   * Removes injected UI components when navigating away or closing message.
   * @param {HTMLElement} container
   */
  cleanup(container) {
    if (!container) return;
    const existing = container.querySelector('.rise-phish-banner-container');
    if (existing) existing.remove();
  }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { BaseSiteAdapter };
} else {
  window.BaseSiteAdapter = BaseSiteAdapter;
}
