/**
 * RISE-Phish Browser Extension — API Communication Client
 * 
 * Provides resilient, timeout-guarded HTTP communication with the RISE-Phish FastAPI backend.
 */

export class RisePhishApiClient {
  constructor(baseUrl = 'http://127.0.0.1:8000') {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
  }

  setBaseUrl(url) {
    if (url) {
      this.baseUrl = url.replace(/\/+$/, '');
    }
  }

  /**
   * Health and connectivity check.
   */
  async checkHealth(timeoutMs = 4000) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(`${this.baseUrl}/api/v1/extension/health`, {
        method: 'GET',
        headers: { 'Accept': 'application/json' },
        signal: controller.signal
      });

      clearTimeout(timer);
      if (!response.ok) {
        throw new Error(`HTTP error ${response.status}`);
      }
      return await response.json();
    } catch (err) {
      clearTimeout(timer);
      if (err.name === 'AbortError') {
        throw new Error(`Connection timed out after ${timeoutMs}ms.`);
      }
      throw new Error(`Backend unreachable at ${this.baseUrl}: ${err.message}`);
    }
  }

  /**
   * Submits an email or web message for multi-signal phishing analysis.
   */
  async analyzeMessage(payload, timeoutMs = 25000) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(`${this.baseUrl}/api/v1/message-analysis`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify(payload),
        signal: controller.signal
      });

      clearTimeout(timer);
      if (!response.ok) {
        const errorBody = await response.text();
        throw new Error(`Backend analysis failed (${response.status}): ${errorBody}`);
      }
      return await response.json();
    } catch (err) {
      clearTimeout(timer);
      if (err.name === 'AbortError') {
        throw new Error(`Analysis timed out after ${timeoutMs}ms.`);
      }
      throw err;
    }
  }

  /**
   * Submits an individual URL to the core RISE-Phish pipeline.
   */
  async analyzeUrl(targetUrl, timeoutMs = 30000) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(`${this.baseUrl}/api/v1/analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({
          url: targetUrl,
          force_fresh: true
        }),
        signal: controller.signal
      });

      clearTimeout(timer);
      if (!response.ok) {
        const errorBody = await response.text();
        throw new Error(`URL analysis failed (${response.status}): ${errorBody}`);
      }
      return await response.json();
    } catch (err) {
      clearTimeout(timer);
      if (err.name === 'AbortError') {
        throw new Error(`URL analysis timed out after ${timeoutMs}ms.`);
      }
      throw err;
    }
  }
}
