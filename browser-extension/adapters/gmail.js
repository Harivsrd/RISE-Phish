/**
 * RISE-Phish Browser Extension — Gmail Webmail Adapter
 * 
 * Specialized DOM extraction for mail.google.com:
 * - Robust selector queries for virtualized Gmail threads
 * - Extracts subject, sender display name, email address, body text, and links
 * - Injects security advisory banners above email body
 * - Marks suspicious or hijacked links with warning badges
 */

class GmailAdapter extends (window.BaseSiteAdapter || require('./base').BaseSiteAdapter) {
  constructor() {
    super('gmail');
  }

  matches(url) {
    if (!url) return false;
    return url.startsWith('https://mail.google.com/');
  }

  findOpenMessages() {
    // Gmail renders individual messages within div[role="listitem"] or div.gs
    const messageContainers = Array.from(document.querySelectorAll('div[role="listitem"]'));
    const activeMessages = messageContainers.filter(container => {
      // Must contain an expanded visible message body
      return container.querySelector('div.a3s, div.ii.gt') !== null;
    });

    if (activeMessages.length > 0) {
      return activeMessages;
    }

    // Fallback for full conversation view or single message mode
    const fallbackBodies = Array.from(document.querySelectorAll('div.a3s.aiL, div.ii.gt'));
    return fallbackBodies.map(body => body.closest('div.gs') || body.parentElement).filter(Boolean);
  }

  extractMessage(container) {
    if (!container) return null;

    // 1. Extract Subject Line
    let subject = '';
    const subjectEl = document.querySelector('h2.hP, h2[data-thread-perm-id], div[role="main"] h2');
    if (subjectEl) {
      subject = subjectEl.innerText.trim();
    }

    // 2. Extract Sender Information
    let sender = '';
    let senderAddress = '';

    // Primary Gmail sender selector: <span class="gD" email="user@domain.com" name="Display Name">
    const senderEl = container.querySelector('span.gD, span[email]');
    if (senderEl) {
      senderAddress = (senderEl.getAttribute('email') || '').trim();
      sender = (senderEl.getAttribute('name') || senderEl.innerText || '').trim();
    } else {
      // Fallback selector for compact headers
      const altSenderEl = container.querySelector('span[role="gridcell"] span, span.zF');
      if (altSenderEl) {
        sender = altSenderEl.innerText.trim();
      }
    }

    // 3. Extract Visible Body Text
    const bodyEl = container.querySelector('div.a3s, div.ii.gt, div[dir="ltr"]');
    if (!bodyEl) return null;

    const bodyText = (bodyEl.innerText || '').trim();
    if (!bodyText && !subject) {
      // Empty placeholder or unrendered virtual item
      return null;
    }

    // 4. Extract Embedded Links
    const linkElements = Array.from(bodyEl.querySelectorAll('a[href]'));
    const embeddedLinks = linkElements.map(a => {
      let href = a.getAttribute('href') || a.href || '';
      
      // Unwrap Google redirect links if wrapped in google.com/url?q=...
      if (href.includes('google.com/url?') && href.includes('q=')) {
        try {
          const parsed = new URL(href);
          const trueTarget = parsed.searchParams.get('q');
          if (trueTarget) href = trueTarget;
        } catch {
          // Ignore URL parse failure
        }
      }

      return {
        url: href,
        text: (a.innerText || a.textContent || '').trim()
      };
    }).filter(link => {
      return link.url && (link.url.startsWith('http://') || link.url.startsWith('https://'));
    });

    // Use MessageContract to sanitize and bound
    const contract = window.MessageContract || (typeof require !== 'undefined' ? require('../utils/message_schema').MessageContract : null);
    if (!contract) return null;

    return contract.createMessagePayload({
      subject,
      sender,
      senderAddress,
      bodyText,
      embeddedLinks,
      siteIdentifier: 'gmail',
      scanMode: 'auto'
    });
  }

  injectBanner(container, analysis, onRescan) {
    if (!container || !analysis) return;

    // Remove existing banner if present
    this.cleanup(container);

    const bodyEl = container.querySelector('div.a3s, div.ii.gt') || container;
    const banner = document.createElement('div');
    banner.className = `rise-phish-banner-container rise-banner-${(analysis.verdict || 'INVESTIGATE').toLowerCase()}`;

    const verdict = analysis.verdict || 'INVESTIGATE';
    const isPhishing = verdict === 'PHISHING';
    const isInvestigate = verdict === 'INVESTIGATE';
    const isSafe = verdict === 'SAFE';

    let iconSvg = '';
    let statusClass = '';

    if (isPhishing) {
      statusClass = 'rise-status-phishing';
      iconSvg = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" class="rise-icon"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>`;
    } else if (isInvestigate) {
      statusClass = 'rise-status-investigate';
      iconSvg = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" class="rise-icon"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>`;
    } else {
      statusClass = 'rise-status-safe';
      iconSvg = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" class="rise-icon"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="m9 12 2 2 4-4"></path></svg>`;
    }

    const keyFindingsHtml = (analysis.key_findings || [])
      .map(finding => `<li>${this._escapeHtml(finding)}</li>`)
      .join('');

    banner.innerHTML = `
      <div class="rise-banner-inner ${statusClass}">
        <div class="rise-banner-header">
          <div class="rise-icon-wrapper">${iconSvg}</div>
          <div class="rise-header-text">
            <div class="rise-title-row">
              <span class="rise-badge">${this._escapeHtml(verdict)}</span>
              <span class="rise-headline">${this._escapeHtml(analysis.summary_headline || 'Security Analysis Completed')}</span>
              <span class="rise-score-pill">Threat: ${((analysis.composite_threat_score || 0) * 100).toFixed(0)}%</span>
            </div>
            <p class="rise-explanation">${this._escapeHtml(analysis.explanation || '')}</p>
          </div>
          <div class="rise-actions">
            <button type="button" class="rise-btn-rescan" title="Execute fresh security scan">Scan Again</button>
            <a href="http://localhost:5173" target="_blank" rel="noopener noreferrer" class="rise-btn-dashboard" title="Open Forensic Dashboard">Forensics &rarr;</a>
          </div>
        </div>
        ${keyFindingsHtml ? `<ul class="rise-findings-list">${keyFindingsHtml}</ul>` : ''}
      </div>
    `;

    // Hook rescan button
    const rescanBtn = banner.querySelector('.rise-btn-rescan');
    if (rescanBtn && typeof onRescan === 'function') {
      rescanBtn.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        rescanBtn.innerText = 'Scanning...';
        rescanBtn.disabled = true;
        onRescan();
      });
    }

    // Insert banner immediately above message body
    bodyEl.parentNode.insertBefore(banner, bodyEl);

    // Also mark malicious or mismatched links inside the body
    if (analysis.link_analyses && analysis.link_analyses.length > 0) {
      this.injectLinkBadges(container, analysis.link_analyses);
    }
  }

  injectLinkBadges(container, linkAnalyses) {
    if (!container || !linkAnalyses) return;

    const linksMap = new Map();
    linkAnalyses.forEach(item => {
      linksMap.set(item.url, item);
    });

    const anchorEls = container.querySelectorAll('a[href]');
    anchorEls.forEach(a => {
      let href = a.getAttribute('href') || a.href || '';
      if (href.includes('google.com/url?') && href.includes('q=')) {
        try {
          const parsed = new URL(href);
          const target = parsed.searchParams.get('q');
          if (target) href = target;
        } catch {}
      }

      const match = linksMap.get(href);
      if (match && (match.verdict === 'PHISHING' || match.is_mismatch || match.ssrf_blocked)) {
        a.classList.add('rise-phish-flagged-link');
        if (!a.querySelector('.rise-link-pill')) {
          const pill = document.createElement('span');
          pill.className = `rise-link-pill ${match.verdict === 'PHISHING' ? 'rise-pill-phish' : 'rise-pill-warn'}`;
          pill.innerText = match.is_mismatch ? '⚠️ Mismatched Target' : '🚨 Malicious Link';
          a.appendChild(pill);
        }
      }
    });
  }

  _escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { GmailAdapter };
} else {
  window.GmailAdapter = GmailAdapter;
}
