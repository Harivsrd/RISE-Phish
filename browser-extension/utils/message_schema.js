/**
 * RISE-Phish Browser Extension — Client Message Contract & Utilities
 * 
 * Provides client-side normalization, sanitization, and deduplication hashing.
 * Strict Privacy: Never collects passwords, tokens, cookies, form inputs, or attachments.
 */

class MessageContract {
  /**
   * Sanitizes and bounds extracted email or message content.
   */
  static createMessagePayload({
    subject = '',
    sender = '',
    senderAddress = '',
    bodyText = '',
    embeddedLinks = [],
    siteIdentifier = 'gmail',
    scanMode = 'auto'
  }) {
    // Sanitize and trim strings
    const cleanSubject = String(subject || '').trim().slice(0, 500);
    const cleanSender = String(sender || '').trim().slice(0, 500);
    const cleanSenderAddress = String(senderAddress || '').trim().toLowerCase().slice(0, 300);
    
    // Limit body to 50KB to preserve network and browser performance
    const cleanBody = String(bodyText || '').trim().slice(0, 50000);

    // Sanitize links and extract valid HTTP/HTTPS URLs only
    const validLinks = (embeddedLinks || [])
      .map(item => {
        const rawUrl = typeof item === 'string' ? item : item.url;
        const rawText = typeof item === 'object' && item.text ? item.text : '';
        return {
          url: String(rawUrl || '').trim(),
          text: String(rawText || '').trim().slice(0, 300)
        };
      })
      .filter(item => {
        try {
          const parsed = new URL(item.url);
          // Block javascript:, data:, file: links from extension scan requests
          return parsed.protocol === 'http:' || parsed.protocol === 'https:';
        } catch {
          return false;
        }
      })
      .slice(0, 25); // Cap to 25 links max

    return {
      subject: cleanSubject,
      sender: cleanSender,
      sender_address: cleanSenderAddress,
      body_text: cleanBody,
      embedded_links: validLinks,
      site_identifier: String(siteIdentifier || 'webmail'),
      scan_mode: scanMode
    };
  }

  /**
   * Generates a fast 32-bit FNV-1a hash of a message to deduplicate re-scans.
   */
  static hashMessage({ subject = '', sender = '', bodyText = '', linksCount = 0 }) {
    const raw = `${subject}|${sender}|${bodyText.slice(0, 1000)}|${linksCount}`;
    let hash = 0x811c9dc5;
    for (let i = 0; i < raw.length; i++) {
      hash ^= raw.charCodeAt(i);
      hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
    }
    return (hash >>> 0).toString(16);
  }
}

// Support both ES module and plain script loading in content scripts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { MessageContract };
} else {
  window.MessageContract = MessageContract;
}
