/**
 * RISE-Phish Browser Extension — Background Service Worker
 * 
 * Central coordinator for:
 * - Persistent extension settings & preferences in chrome.storage
 * - Secure background HTTP requests to FastAPI backend
 * - Global badge state and threat level indications
 * - Caching and history lifecycle
 */

import { RisePhishApiClient } from '../utils/api.js';

const DEFAULT_SETTINGS = {
  backendUrl: 'http://127.0.0.1:8000',
  enabled: true,
  autoScan: true,
  showBanner: true,
  latestResult: null
};

let currentSettings = { ...DEFAULT_SETTINGS };
let apiClient = new RisePhishApiClient(currentSettings.backendUrl);

// Initialize settings from storage on startup
chrome.runtime.onInstalled.addListener(async () => {
  const stored = await chrome.storage.local.get(null);
  currentSettings = { ...DEFAULT_SETTINGS, ...stored };
  apiClient.setBaseUrl(currentSettings.backendUrl);
  await chrome.storage.local.set(currentSettings);
  console.log('[RISE-Phish] Service worker initialized with backend:', currentSettings.backendUrl);
});

// Update badge appearance on active tab
function updateBadge(verdict, tabId = null) {
  if (!verdict) {
    chrome.action.setBadgeText({ text: '', tabId });
    return;
  }

  const v = verdict.toUpperCase();
  if (v === 'PHISHING') {
    chrome.action.setBadgeText({ text: 'PHISH', tabId });
    chrome.action.setBadgeBackgroundColor({ color: '#e03131', tabId });
  } else if (v === 'INVESTIGATE') {
    chrome.action.setBadgeText({ text: 'WARN', tabId });
    chrome.action.setBadgeBackgroundColor({ color: '#f59f00', tabId });
  } else if (v === 'SAFE') {
    chrome.action.setBadgeText({ text: 'SAFE', tabId });
    chrome.action.setBadgeBackgroundColor({ color: '#2b8a3e', tabId });
  } else {
    chrome.action.setBadgeText({ text: '', tabId });
  }
}

// Handle messages from content scripts and popup UI
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  const senderTabId = sender?.tab?.id || null;

  if (request.type === 'CHECK_HEALTH') {
    apiClient.checkHealth()
      .then(data => sendResponse({ success: true, data }))
      .catch(err => sendResponse({ success: false, error: err.message }));
    return true; // Keep message channel open for async response
  }

  if (request.type === 'ANALYZE_MESSAGE') {
    apiClient.analyzeMessage(request.payload)
      .then(async (data) => {
        currentSettings.latestResult = data;
        await chrome.storage.local.set({ latestResult: data });
        updateBadge(data.verdict, senderTabId);
        sendResponse({ success: true, data });
      })
      .catch(err => {
        sendResponse({ success: false, error: err.message });
      });
    return true;
  }

  if (request.type === 'ANALYZE_URL') {
    apiClient.analyzeUrl(request.url)
      .then(async (data) => {
        currentSettings.latestResult = data;
        await chrome.storage.local.set({ latestResult: data });
        updateBadge(data.verdict, senderTabId);
        sendResponse({ success: true, data });
      })
      .catch(err => {
        sendResponse({ success: false, error: err.message });
      });
    return true;
  }

  if (request.type === 'GET_SETTINGS') {
    chrome.storage.local.get(null).then(stored => {
      currentSettings = { ...DEFAULT_SETTINGS, ...stored };
      apiClient.setBaseUrl(currentSettings.backendUrl);
      sendResponse({ success: true, settings: currentSettings });
    });
    return true;
  }

  if (request.type === 'SET_SETTINGS') {
    const newSettings = { ...currentSettings, ...request.settings };
    currentSettings = newSettings;
    apiClient.setBaseUrl(newSettings.backendUrl);
    chrome.storage.local.set(newSettings).then(() => {
      sendResponse({ success: true, settings: newSettings });
    });
    return true;
  }

  if (request.type === 'CLEAR_HISTORY') {
    currentSettings.latestResult = null;
    chrome.storage.local.remove(['latestResult']).then(() => {
      updateBadge(null);
      sendResponse({ success: true });
    });
    return true;
  }
});
