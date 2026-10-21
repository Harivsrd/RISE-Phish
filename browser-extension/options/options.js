/**
 * RISE-Phish Browser Extension — Options Page Controller
 */

document.addEventListener('DOMContentLoaded', () => {
  const backendUrlInput = document.getElementById('backend-url');
  const btnTestConnection = document.getElementById('btn-test-connection');
  const connectionFeedback = document.getElementById('connection-feedback');

  const chkEnabled = document.getElementById('chk-enabled');
  const chkAutoScan = document.getElementById('chk-auto-scan');
  const chkShowBanner = document.getElementById('chk-show-banner');

  const btnClearCache = document.getElementById('btn-clear-cache');
  const clearFeedback = document.getElementById('clear-feedback');

  const btnSave = document.getElementById('btn-save');
  const saveToast = document.getElementById('save-toast');

  // 1. Load current settings from background worker
  chrome.runtime.sendMessage({ type: 'GET_SETTINGS' }, (response) => {
    if (response && response.settings) {
      const s = response.settings;
      backendUrlInput.value = s.backendUrl || 'http://127.0.0.1:8000';
      chkEnabled.checked = s.enabled !== false;
      chkAutoScan.checked = s.autoScan !== false;
      chkShowBanner.checked = s.showBanner !== false;
    }
  });

  // 2. Test Connection
  btnTestConnection.addEventListener('click', async () => {
    const testUrl = (backendUrlInput.value || 'http://127.0.0.1:8000').replace(/\/+$/, '');
    connectionFeedback.className = 'field-hint';
    connectionFeedback.innerText = 'Connecting...';
    btnTestConnection.disabled = true;

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 4000);

      const resp = await fetch(`${testUrl}/api/v1/extension/health`, {
        signal: controller.signal
      });
      clearTimeout(timer);

      if (resp.ok) {
        const data = await resp.json();
        connectionFeedback.className = 'field-hint success';
        connectionFeedback.innerText = `Connected! Service: ${data.status} (v${data.extension_api_version || '2.0.0'})`;
      } else {
        throw new Error(`HTTP ${resp.status}`);
      }
    } catch (err) {
      connectionFeedback.className = 'field-hint error';
      connectionFeedback.innerText = `Failed to connect to ${testUrl}: ${err.message}`;
    } finally {
      btnTestConnection.disabled = false;
    }
  });

  // 3. Clear Stored Findings
  btnClearCache.addEventListener('click', () => {
    btnClearCache.disabled = true;
    chrome.runtime.sendMessage({ type: 'CLEAR_HISTORY' }, (response) => {
      btnClearCache.disabled = false;
      clearFeedback.className = 'field-hint success';
      clearFeedback.innerText = 'All cached findings and badge alerts cleared.';
      setTimeout(() => {
        clearFeedback.innerText = '';
      }, 4000);
    });
  });

  // 4. Save Settings
  btnSave.addEventListener('click', () => {
    const newSettings = {
      backendUrl: (backendUrlInput.value || 'http://127.0.0.1:8000').trim().replace(/\/+$/, ''),
      enabled: chkEnabled.checked,
      autoScan: chkAutoScan.checked,
      showBanner: chkShowBanner.checked
    };

    chrome.runtime.sendMessage({ type: 'SET_SETTINGS', settings: newSettings }, (response) => {
      if (response && response.success) {
        saveToast.classList.remove('hidden');
        setTimeout(() => {
          saveToast.classList.add('hidden');
        }, 3000);
      }
    });
  });
});
