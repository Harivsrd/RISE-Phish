# RISE-Phish — REST API Reference Specification

**Specification Version:** `2.0.0`  
**Base URL:** `http://localhost:8000/api/v1`  
**OpenAPI Specification:** `http://localhost:8000/openapi.json`  
**Interactive Swagger UI:** `http://localhost:8000/docs`  
**ReDoc Documentation:** `http://localhost:8000/redoc`  

---

## 1. Core Analysis Endpoints

### 1.1 POST `/api/v1/analyze`
Executes the full RISE-Phish multi-representation pipeline on a target URL: crawling, screenshot capture, Tesseract OCR, representation suite compilation ($R_1-R_5$), CRCE discrepancy evaluation, SLM reasoning, deterministic evidence fusion, decision calibration, and dual-audience explanation generation.

- **Method:** `POST`
- **Request Content-Type:** `application/json`
- **Request Body Schema (`AnalysisRequest`):**
  ```json
  {
    "url": "https://portal-session-sync.net/auth",
    "force_fresh": false
  }
  ```
  | Field | Type | Required | Default | Description |
  | :--- | :--- | :---: | :---: | :--- |
  | `url` | `string` | **Yes** | — | Target webpage URL to analyze (must have http or https scheme). |
  | `force_fresh` | `boolean` | No | `false` | If `true`, bypasses SQLite cache and executes a fresh crawl. |

- **Response Status Codes:**
  - `200 OK`: Analysis completed successfully (or retrieved from cache).
  - `422 Unprocessable Entity`: Malformed request schema or missing required URL.
  - `500 Internal Server Error`: Pipeline execution failure.

- **Response Body Schema (`AnalysisDetailResponse`):**
  ```json
  {
    "analysis_id": "c8f2a1b4-5678-4321-9abc-def012345678",
    "url": "https://portal-session-sync.net/auth",
    "status": "COMPLETED",
    "verdict": "PHISHING",
    "recommended_action": "BLOCK_ACCESS",
    "composite_threat_score": 0.925,
    "confidence_score": 0.95,
    "target_brand": "Microsoft",
    "registered_domain": "portal-session-sync.net",
    "visual_normalization_convergence": true,
    "crawler_result": {
      "success": true,
      "elapsed_ms": 612,
      "title": "Sign in to Microsoft Online",
      "forms_count": 1,
      "has_password_field": true
    },
    "crce_result": {
      "ned_r1_r2": 0.124,
      "ned_r1_r3": 0.145,
      "ned_r2_r3": 0.012,
      "visual_normalization_convergence": true,
      "is_brand_mismatch": true,
      "overall_discrepancy": 0.78
    },
    "fused_evidence": {
      "composite_threat_score": 0.925,
      "factors": [
        {
          "component": "brand_spoofing",
          "raw_score": 1.0,
          "weight": 0.25,
          "weighted_score": 0.25
        }
      ]
    },
    "explanation": {
      "user_advisory": {
        "headline": "MALICIOUS PHISHING PAGE DETECTED",
        "action_advice": "Do NOT enter passwords or personal credentials.",
        "risk_badge": "CRITICAL"
      },
      "soc_analyst_report": {
        "summary": "Visual-Normalization Convergence detected on unauthorized domain.",
        "triggered_rules": ["RULE-CRIT-01: VNC Evasion Signature"]
      }
    },
    "created_at": "2026-10-26T15:30:00Z",
    "completed_at": "2026-10-26T15:30:01Z"
  }
  ```

---

### 1.2 GET `/api/v1/analysis/{analysis_id}`
Retrieves a complete stored forensic analysis report by its unique UUID.

- **Method:** `GET`
- **Path Parameters:**
  - `analysis_id` (`string`, required): UUIDv4 of the analysis record.
- **Response Status Codes:**
  - `200 OK`: Record found and returned (`AnalysisDetailResponse`).
  - `404 Not Found`: Record with specified ID does not exist.
  - `500 Internal Server Error`: Deserialization error.

---

### 1.3 GET `/api/v1/history`
Returns paginated historical scans from SQLite storage with optional verdict filtering.

- **Method:** `GET`
- **Query Parameters:**
  | Parameter | Type | Required | Default | Description |
  | :--- | :--- | :---: | :---: | :--- |
  | `limit` | `integer` | No | `50` | Maximum items to return ($1 \le \text{limit} \le 200$). |
  | `offset` | `integer` | No | `0` | Pagination offset ($\ge 0$). |
  | `verdict` | `string` | No | `null` | Optional filter (`SAFE`, `INVESTIGATE`, `PHISHING`). |
- **Response Status Codes:**
  - `200 OK`: `AnalysisHistoryResponse` containing list of `AnalysisSummary` items and `total` count.

---

### 1.4 DELETE `/api/v1/analysis/{analysis_id}`
Removes a historical scan record from the database.

- **Method:** `DELETE`
- **Path Parameters:**
  - `analysis_id` (`string`, required): UUIDv4 of the record to delete.
- **Response Status Codes:**
  - `200 OK`: `{"status": "deleted", "analysis_id": "..."}`
  - `404 Not Found`: Record not found.

---

### 1.5 GET `/api/v1/stats`
Computes aggregate dashboard statistics across all stored scans.

- **Method:** `GET`
- **Response Status Codes:**
  - `200 OK`: `DashboardStatsResponse` containing `total_scans`, `phishing_detected`, `benign_count`, `investigate_count`, `vnc_convergences_detected`, `mean_composite_threat_score`, and `top_targeted_brands`.

---

### 1.6 GET `/api/v1/health`
System operational status and environment probe.

- **Method:** `GET`
- **Response Status Codes:**
  - `200 OK`: `{"status": "ok", "app_name": "RISE-Phish API", "version": "0.1.0", "environment": "development"}`

---

## 2. Browser Extension Endpoints

### 2.1 GET `/api/v1/extension/health`
Extension connectivity probe confirming backend readiness, supported origin sites, and active SSRF defenses.

- **Method:** `GET`
- **Response Status Codes:**
  - `200 OK`:
    ```json
    {
      "status": "ok",
      "extension_api_version": "0.2.0",
      "supported_sites": ["mail.google.com"],
      "ssrf_protection_active": true,
      "timestamp": "2026-10-26T15:30:00Z"
    }
    ```

---

### 2.2 POST `/api/v1/message-analysis`
Analyzes webmail content extracted by browser extension content scripts. Evaluates sender authenticity, psychological urgency, prompt injection attempts, Unicode homoglyphs, and embedded hyperlinks with live SSRF checks and ESP relay recognition.

- **Method:** `POST`
- **Request Content-Type:** `application/json`
- **Request Body Schema (`MessageAnalysisRequest`):**
  ```json
  {
    "subject": "Action Required: Verify Account Security",
    "sender": "LinkedIn Notifications",
    "sender_address": "notifications@news.linkedin.com",
    "body_text": "Please review new sign-in activity on your LinkedIn account.",
    "embedded_links": [
      {
        "url": "https://www.linkedin.com/notifications",
        "text": "Review Activity"
      }
    ],
    "site_identifier": "gmail",
    "scan_mode": "auto",
    "allow_loopback_for_test": false
  }
  ```

- **Response Status Codes:**
  - `200 OK`:
    ```json
    {
      "analysis_id": "5a4b3c2d-1234-5678-90ab-cdef12345678",
      "verdict": "SAFE",
      "composite_threat_score": 0.0,
      "confidence_score": 0.92,
      "recommended_action": "ALLOW",
      "site_identifier": "gmail",
      "indicators": {
        "urgency_score": 0.0,
        "urgency_triggers_found": [],
        "sender_discrepancy_detected": false,
        "sender_finding": "",
        "link_text_mismatches_count": 0,
        "homoglyphs_detected_count": 0,
        "homoglyph_samples": [],
        "prompt_injection_flags": []
      },
      "link_analyses": [
        {
          "url": "https://www.linkedin.com/notifications",
          "displayed_text": "Review Activity",
          "is_mismatch": false,
          "ssrf_blocked": false,
          "verdict": "SAFE",
          "composite_threat_score": 0.0,
          "target_brand": "linkedin",
          "finding_summary": "URL syntax and registered domain appear consistent"
        }
      ],
      "summary_headline": "NO PHISHING INDICATORS DETECTED",
      "explanation": "The sender identity, visible text, and embedded hyperlinks appear consistent with standard benign communication.",
      "key_findings": [],
      "privacy_notice": "Zero raw message content is stored on disk or database. Analysis executed ephemerally.",
      "analyzed_at": "2026-10-26T15:30:00Z"
    }
    ```

---

## 3. Demo Target Simulation Endpoints

These endpoints provide live, deterministic demonstration fixtures used during evaluations and viva presentations without relying on volatile external websites.

| Endpoint | Method | Format | Description |
| :--- | :---: | :---: | :--- |
| `/demo/zero-day-math` | `GET` | HTML | Serves a simulated Microsoft login page employing Mathematical Bold Alphanumeric Unicode symbols (`U+1D400-U+1D7FF`) to bypass raw text filters while optically mimicking authentic typography. |
| `/demo/cyrillic-homoglyph`| `GET` | HTML | Serves a simulated PayPal login portal utilizing Cyrillic lookalikes (`U+0430` for 'a', `U+043E` for 'o') in page titles and headings. |
| `/demo/credential-harvest`| `GET` | HTML | Serves a deceptive Google Workspace authentication screen containing username and password inputs submitting to a local sink. |
| `/demo/authentic-portal` | `GET` | HTML | Serves a legitimate open-access documentation repository (benign baseline control with clean English text and zero credential fields). |
| `/demo/harvest` | `POST` | JSON | Dummy sink endpoint logging received form data and returning `{"status": "received"}`. |
