# RISE-Phish v2 — Chrome & Microsoft Edge Browser Extension
## AI-Powered Email & Message Phishing Guard (Manifest V3)

The **RISE-Phish Browser Extension** extends the RISE-Phish cross-representation discrepancy detection engine directly into desktop webmail and messaging clients. It analyzes incoming emails, sender authenticity, anchor text hijacking, coercive urgency, and embedded hyperlinks in real time.

---

## 1. Directory Structure

```text
browser-extension/
├── manifest.json              # Chrome/Edge Manifest V3 specification
├── README.md                  # Installation, configuration, and testing manual
├── background/
│   └── background.js          # Service worker (state, caching, badge alerts, API client)
├── content/
│   ├── content.js             # Content script orchestrator & DOM observer
│   └── content.css            # Security banner & inline link badge styling
├── adapters/
│   ├── base.js                # Abstract BaseSiteAdapter lifecycle interface
│   └── gmail.js               # Gmail Webmail specialized extraction & UI injection
├── popup/
│   ├── popup.html             # Extension action popup markup
│   ├── popup.css              # Dark-mode dashboard stylesheet
│   └── popup.js               # Popup interactive controller
├── options/
│   ├── options.html           # Settings & configuration interface
│   ├── options.css            # Options page stylesheet
│   └── options.js             # Settings persistence controller
├── utils/
│   ├── api.js                 # Resilient HTTP client with timeout guards
│   └── message_schema.js      # Client data contract, sanitization & FNV-1a hashing
└── icons/
    ├── icon.svg               # Vector master icon
    ├── icon16.png             # 16x16 action icon
    ├── icon32.png             # 32x32 action icon
    ├── icon48.png             # 48x48 extension management icon
    └── icon128.png            # 128x128 Chrome Web Store icon
```

---

## 2. Installation Guide (Chrome & Microsoft Edge)

Both Google Chrome and Microsoft Edge support Manifest V3 unpacked extensions natively:

### For Google Chrome:
1. Open Google Chrome.
2. Navigate to `chrome://extensions/`.
3. In the top-right corner, toggle **Developer mode** to **ON**.
4. Click the **Load unpacked** button in the top-left toolbar.
5. Select the `browser-extension` folder located at:
   `C:\Users\Asus\.gemini\antigravity\scratch\RISE-Phish\browser-extension`
6. The **RISE-Phish — AI Email & Message Phishing Guard** icon will appear in your browser toolbar. Pin it for easy access.

### For Microsoft Edge:
1. Open Microsoft Edge.
2. Navigate to `edge://extensions/`.
3. In the bottom-left sidebar, toggle **Developer mode** to **ON**.
4. Click the **Load unpacked** button at the top.
5. Select the `browser-extension` folder.
6. The extension is now active in Microsoft Edge.

---

## 3. Starting the Backend Server

Ensure the RISE-Phish FastAPI backend is running on `http://127.0.0.1:8000`:

```powershell
# Open Windows PowerShell
cd C:\Users\Asus\.gemini\antigravity\scratch\RISE-Phish

# Start the FastAPI backend with uvicorn
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

To verify backend connectivity:
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/extension/health"
```

Expected output:
```json
{
  "status": "ok",
  "extension_api_version": "0.2.0",
  "supported_sites": ["mail.google.com"],
  "ssrf_protection_active": true
}
```

---

## 4. Manual Testing Guide

### Scenario A: Real-Time Gmail Webmail Inspection
1. Navigate to **[https://mail.google.com](https://mail.google.com)**.
2. Open any email message.
3. If **Automatic Scanning** is enabled, the extension will observe the open message, submit its content to `POST /api/v1/message-analysis`, and render an advisory banner directly above the email body:
   - <span style="color:#22c55e; font-weight:bold;">SAFE (Green):</span> Clean communication, authentic sender, safe links.
   - <span style="color:#f59e0b; font-weight:bold;">INVESTIGATE (Amber):</span> Coercive urgency, unverified sender, or elevated entropy.
   - <span style="color:#ef4444; font-weight:bold;">PHISHING (Red):</span> Brand impersonation, anchor text hijacking, or credential harvesting.
4. If automatic scanning is disabled in Settings, click the extension toolbar icon and click **Scan Message**.

### Scenario B: Testing Deceptive Anchor Text (Link Hijacking) via Popup
1. Click the RISE-Phish extension icon in the toolbar.
2. Click **Scan Link**.
3. Input a test link: `http://127.0.0.1:8000/demo/zero-day-math`
4. Click **Analyze**.
5. The popup will immediately return <span style="color:#ef4444; font-weight:bold;">PHISHING</span> (Threat Score: 100%, Brand: Microsoft) with the recommended action `BLOCK_ACCESS`.

### Scenario C: Testing SSRF Protection
The extension enforces strict Server-Side Request Forgery protections:
- Private IPv4 addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) are blocked before fetching.
- Cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`) are strictly blocked.
- Loopback addresses (`127.0.0.1`, `localhost`) are blocked by default unless explicitly in testing mode.

---

## 5. Privacy & Data Minimization Guarantees

1. **Zero Credential Collection:** The extension never inspects passwords, authentication tokens, cookies, form fields, or local storage.
2. **Ephemeral Processing:** Message text is analyzed in memory; raw message content is never stored on disk or in the database.
3. **Targeted Extraction:** The adapter extracts only the active, visible message container; it never crawls your inbox, contacts, or unread email list.
4. **Local Host Access:** Default backend requests communicate strictly with `http://127.0.0.1:8000` on your workstation. No third-party tracking or external telemetry is transmitted.

---

## 6. Known Limitations & Scope

- **Supported Platforms:** Currently optimized for desktop Gmail Webmail (`mail.google.com`). Support for Microsoft Outlook Web (`outlook.office.com`) and Yahoo Mail is architected via `BaseSiteAdapter` and planned for v2.1.
- **Attachments:** Email attachments (PDF, DOCX, ZIP) are not analyzed in this version.
- **Drafts:** Composing drafts are deliberately excluded from extraction to prevent interrupting user typing.
