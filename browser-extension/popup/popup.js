/**
 * RISE-Phish Browser Extension — Popup Controller
 */

document.addEventListener('DOMContentLoaded', async () => {
  const statusIndicator = document.getElementById('connection-status');
  const statusDot = statusIndicator.querySelector('.status-dot');
  const statusText = document.getElementById('status-text');
  const siteStatus = document.getElementById('site-status');
  const toggleProtection = document.getElementById('toggle-protection');

  const btnScanMessage = document.getElementById('btn-scan-message');
  const btnToggleLinkScan = document.getElementById('btn-toggle-link-scan');
  const quickLinkBox = document.getElementById('quick-link-box');
  const quickUrlInput = document.getElementById('quick-url-input');
  const btnSubmitUrl = document.getElementById('btn-submit-url');

  const emptyState = document.getElementById('empty-state');
  const resultCard = document.getElementById('result-card');
  const verdictBanner = document.getElementById('verdict-banner');
  const verdictBadge = document.getElementById('verdict-badge');
  const threatScore = document.getElementById('threat-score');
  const verdictHeadline = document.getElementById('verdict-headline');
  const verdictExplanation = document.getElementById('verdict-explanation');
  const findingsSection = document.getElementById('findings-section');
  const findingsList = document.getElementById('findings-list');
  const linksSection = document.getElementById('links-section');
  const linksList = document.getElementById('links-list');
  const linksCount = document.getElementById('links-count');
  const btnClearHistory = document.getElementById('btn-clear-history');

  // 1. Check Backend Connectivity
  function checkBackendHealth() {
    chrome.runtime.sendMessage({ type: 'CHECK_HEALTH' }, (response) => {
      if (chrome.runtime.lastError || !response || !response.success) {
        statusDot.className = 'status-dot offline';
        statusText.innerText = 'Offline';
        statusIndicator.title = response?.error || 'Backend unreachable';
      } else {
        statusDot.className = 'status-dot online';
        statusText.innerText = 'Connected';
        statusIndicator.title = `RISE-Phish API v${response.data?.extension_api_version || '2.0'}`;
      }
    });
  }

  checkBackendHealth();

  // 2. Load Settings & Latest Result
  chrome.runtime.sendMessage({ type: 'GET_SETTINGS' }, (response) => {
    if (response && response.settings) {
      toggleProtection.checked = Boolean(response.settings.enabled);
      if (response.settings.latestResult) {
        renderResult(response.settings.latestResult);
      }
    }
  });

  // Toggle protection state
  toggleProtection.addEventListener('change', () => {
    chrome.runtime.sendMessage({
      type: 'SET_SETTINGS',
      settings: { enabled: toggleProtection.checked }
    });
  });

  // 3. Inspect Active Tab
  const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const isGmail = activeTab?.url && activeTab.url.startsWith('https://mail.google.com/');

  if (isGmail) {
    siteStatus.innerText = 'Gmail Webmail Active';
    siteStatus.style.color = '#38bdf8';
    btnScanMessage.disabled = false;
  } else {
    siteStatus.innerText = 'Active on Gmail Webmail';
    btnScanMessage.disabled = false; // Allow click to prompt or attempt scan
  }

  // 4. Manual Scan Message Action
  btnScanMessage.addEventListener('click', async () => {
    if (!activeTab || !activeTab.id) return;

    btnScanMessage.innerText = 'Scanning...';
    btnScanMessage.disabled = true;

    chrome.tabs.sendMessage(activeTab.id, { type: 'SCAN_PAGE_MANUAL' }, (response) => {
      btnScanMessage.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="btn-icon">
          <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path>
          <polyline points="22,6 12,13 2,6"></polyline>
        </svg>
        Scan Message
      `;
      btnScanMessage.disabled = false;

      if (chrome.runtime.lastError || !response || !response.success) {
        alert(response?.message || 'Please open an email message in Gmail before scanning.');
      }
    });
  });

  // 5. Toggle Quick Link Input
  btnToggleLinkScan.addEventListener('click', () => {
    quickLinkBox.classList.toggle('hidden');
    if (!quickLinkBox.classList.contains('hidden')) {
      quickUrlInput.focus();
    }
  });

  // Submit Quick Link
  btnSubmitUrl.addEventListener('click', () => {
    const url = quickUrlInput.value.trim();
    if (!url) return;

    btnSubmitUrl.innerText = 'Analyzing...';
    btnSubmitUrl.disabled = true;

    chrome.runtime.sendMessage({ type: 'ANALYZE_URL', url }, (response) => {
      btnSubmitUrl.innerText = 'Analyze';
      btnSubmitUrl.disabled = false;

      if (response && response.success && response.data) {
        renderResult(response.data);
      } else {
        alert(response?.error || 'Link analysis failed.');
      }
    });
  });

  // 6. Clear History
  btnClearHistory.addEventListener('click', () => {
    chrome.runtime.sendMessage({ type: 'CLEAR_HISTORY' }, () => {
      emptyState.classList.remove('hidden');
      resultCard.classList.add('hidden');
    });
  });

  // 7. Render Result Card
  function renderResult(result) {
    if (!result) return;

    emptyState.classList.add('hidden');
    resultCard.classList.remove('hidden');

    const verdict = (result.verdict || 'INVESTIGATE').toUpperCase();
    const score = result.composite_threat_score ?? 0.0;
    const headline = result.summary_headline || (verdict === 'PHISHING' ? 'Confirmed Phishing' : 'Analysis Complete');
    const explanation = result.explanation || result.analyst_explanation || '';

    // Apply verdict classes
    verdictBanner.className = `verdict-banner verdict-${verdict.toLowerCase()}`;
    verdictBadge.innerText = verdict;
    threatScore.innerText = `Threat: ${(score * 100).toFixed(0)}%`;
    verdictHeadline.innerText = headline;
    verdictExplanation.innerText = explanation;

    // Key Findings
    const findings = result.key_findings || [];
    findingsList.innerHTML = '';
    if (findings.length > 0) {
      findingsSection.classList.remove('hidden');
      findings.forEach(item => {
        const li = document.createElement('li');
        li.innerText = item;
        findingsList.appendChild(li);
      });
    } else {
      findingsSection.classList.add('hidden');
    }

    // Embedded Links
    const links = result.link_analyses || [];
    linksList.innerHTML = '';
    linksCount.innerText = links.length;

    if (links.length > 0) {
      linksSection.classList.remove('hidden');
      links.slice(0, 10).forEach(link => {
        const item = document.createElement('div');
        item.className = 'link-item';

        const linkEl = document.createElement('a');
        linkEl.className = 'link-url';
        linkEl.href = link.url;
        linkEl.target = '_blank';
        linkEl.innerText = link.url;
        linkEl.title = link.finding_summary || link.url;

        const chip = document.createElement('span');
        const linkV = (link.verdict || 'SAFE').toUpperCase();
        chip.className = `link-chip chip-${linkV.toLowerCase()}`;
        chip.innerText = link.is_mismatch ? 'Spoofed' : (link.ssrf_blocked ? 'SSRF Block' : linkV);

        item.appendChild(linkEl);
        item.appendChild(chip);
        linksList.appendChild(item);
      });
    } else {
      linksSection.classList.add('hidden');
    }
  }

  // Listen for real-time background results arriving while popup is open
  chrome.storage.onChanged.addListener((changes) => {
    if (changes.latestResult && changes.latestResult.newValue) {
      renderResult(changes.latestResult.newValue);
    }
  });
});
