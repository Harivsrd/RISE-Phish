# RISE-Phish — Comprehensive Codebase Audit Report

**Document ID:** `DOC-AUDIT-2026-V2`  
**Target Milestone:** Academic B.Tech Capstone Project Report & Technical Deliverables  
**Audit Protocol:** Strictly Read-Only Inspection of Verified Repository Assets  
**Audit Date:** October 26, 2026  
**Auditor Profile:** Senior Software Documentation Engineer & Academic Project-Report Analyst  
**Codebase Root:** `C:\Users\Asus\.gemini\antigravity\scratch\RISE-Phish`  

---

## 1. Project Directory Structure and Component Responsibilities

The RISE-Phish repository is organized into distinct functional subsystems covering backend API services, browser automation, multi-representation analysis, supervised ML baseline models, browser extension client, web frontend, datasets, and automated test suites.

```
RISE-Phish/
├── backend/
│   ├── app/
│   │   ├── api/                   # FastAPI route definitions and service orchestrators
│   │   │   ├── demo.py            # Viva presentation synthetic target simulation endpoints
│   │   │   ├── extension_routes.py# Browser extension API endpoints (/extension/health, /message-analysis)
│   │   │   ├── message_service.py # Email and message forensic engine with SSRF & ESP recognition
│   │   │   ├── routes.py          # Core URL analysis, history, statistics, and health endpoints
│   │   │   └── service.py         # End-to-end URL analysis pipeline orchestrator
│   │   ├── core/                  # Configuration, logging, and networking security
│   │   │   ├── config.py          # Pydantic Settings singleton reading .env
│   │   │   ├── logging.py         # Standardized structured logging configuration
│   │   │   └── ssrf.py            # SSRF, RFC 1918 private IP, and RFC 6052 NAT64 validation
│   │   ├── crawler/               # Dynamic web content acquisition
│   │   │   ├── browser.py         # Sandboxed Playwright Chromium context manager
│   │   │   └── collector.py       # Webpage collector (HTML, viewport screenshots, form AST)
│   │   ├── crce/                  # Cross-Representation Discrepancy Engine (CRCE)
│   │   │   ├── brand_detector.py  # Canonical brand catalog, OAuth/SSO mention stripping
│   │   │   ├── discrepancy.py     # Pairwise NED, Token Jaccard, and VNC signature detector
│   │   │   └── similarity.py      # RapidFuzz-backed normalized edit distance utilities
│   │   ├── datasets/              # Procedural dataset synthesis and split management
│   │   │   ├── pipeline.py        # Stratified dataset generator and partitioner
│   │   │   └── synthesizers/      # Homoglyph, zero-width, leetspeak, and composite generators
│   │   ├── decision/              # Policy thresholding and operational posture engine
│   │   │   └── risk.py            # Calibrated thresholds (BALANCED, STRICT, PERMISSIVE) and overrides
│   │   ├── explanation/           # Dual-audience explainability engine
│   │   │   └── explanation_engine.py # Generates User Advisory Cards and SOC Forensic reports
│   │   ├── fusion/                # Deterministic multi-source evidence fusion
│   │   │   └── evidence_fusion.py # 7-factor weighted scoring and non-linear interaction boosts
│   │   ├── ml/                    # Supervised machine learning baseline (control experiment)
│   │   │   ├── baseline_features.py# 26-dimensional URL + HTML feature vector extractor
│   │   │   └── baseline_model.py  # Scikit-learn RandomForest and LogisticRegression classifiers
│   │   ├── models/                # Pydantic v2 data contracts and schemas
│   │   │   ├── extension_schemas.py# Browser extension request and response schemas
│   │   │   └── schemas.py         # Core URL analysis, representation, and forensic schemas
│   │   ├── preprocessing/         # Modality-specific preprocessors
│   │   │   ├── html_processor.py  # DOM tag stripping, credential input detection, structure
│   │   │   ├── ocr_engine.py      # Tesseract OCR wrapper and Mock OCR oracle
│   │   │   ├── unicode_processor.py# Homoglyph, zero-width, BiDi override, and tag char detector
│   │   │   └── url_processor.py   # Lexical decomposition, Shannon entropy, Punycode IDN parser
│   │   ├── representations/       # Multi-representation compilation suite (R1 - R5)
│   │   │   ├── builder.py         # Master representation set orchestrator
│   │   │   ├── normalized.py      # R2: Canonical NFKC + traceable homoglyph mapping
│   │   │   ├── raw.py             # R1: Verbatim DOM visible text
│   │   │   ├── semantic.py        # R4: Headings, document title, forms, credential fields
│   │   │   ├── url_repr.py        # R5: URL syntactic and lexical decomposition
│   │   │   └── visual.py          # R3: Tesseract OCR optical ground truth
│   │   ├── slm/                   # Lightweight Small Language Model abstraction layer
│   │   │   ├── api_engine.py      # OpenAI-compatible HTTPX async client
│   │   │   ├── factory.py         # Dependency injection factory (mock, local, api)
│   │   │   ├── interface.py       # BaseSLMEngine abstract base class
│   │   │   ├── local_engine.py    # HuggingFace Transformers wrapper (Phi-3/Qwen lazy loader)
│   │   │   ├── mock_engine.py     # Deterministic zero-VRAM test oracle
│   │   │   ├── reasoning.py       # Task 2: Phishing threat reasoning prompt & parser
│   │   │   └── recovery.py        # Task 1: Semantic de-obfuscation prompt & parser
│   │   ├── storage/               # Persistence layer
│   │   │   └── database.py        # SQLite DatabaseManager with WAL mode concurrency
│   │   └── main.py                # FastAPI ASGI application entrypoint & CORS middleware
├── browser-extension/             # Chrome & Edge Manifest V3 extension (v2)
│   ├── adapters/                  # Webmail DOM extraction adapters (base.js, gmail.js)
│   ├── background/                # Service worker background dispatcher (background.js)
│   ├── content/                   # Content scripts & in-page warning banner injector
│   ├── options/                   # Options UI for backend URL and scanning toggles
│   ├── popup/                     # Main toolbar interface (scan trigger, risk meter, link list)
│   ├── utils/                     # Schema converters and API fetch clients
│   └── manifest.json              # Extension Manifest V3 configuration
├── frontend/                      # React 18 + Tailwind CSS explainable web dashboard
│   ├── src/components/            # UI components (VerdictBanner, RepresentationViewer, AnalystDrawer)
│   ├── App.jsx                    # Master dashboard application
│   └── nginx.conf                 # Production Nginx reverse-proxy configuration
├── datasets/                      # Benchmark dataset storage
│   └── splits/                    # Stratified JSON splits (train: 140, val: 30, test: 30)
├── docs/                          # Academic documentation and architectural specifications
├── reports/                       # Pre-computed benchmark results across experiments
├── scripts/                       # Container automation scripts (.ps1, .sh)
├── tests/                         # 177 automated test cases across 23 test modules
├── Dockerfile.backend             # Container specification for FastAPI + Playwright + OCR
├── Dockerfile.frontend            # Container specification for React + Nginx
├── docker-compose.yml             # Container topology linking backend, frontend & storage
└── pyproject.toml                 # Build configuration, metadata, and pytest options
```

---

## 2. Actual Execution Flow for System Capabilities

### 2.1 URL Analysis Pipeline (`POST /api/v1/analyze`)
*Code Reference:* [`backend/app/api/service.py::analyze_url_pipeline`](file:///C:/Users/Asus/.gemini/antigravity/scratch/RISE-Phish/backend/app/api/service.py)

1. **Request Ingestion & Cache Check:**
   - Client sends JSON payload `{"url": "...", "force_fresh": false}` to `/api/v1/analyze`.
   - `service.py` queries `DatabaseManager.find_latest_by_url(url)`. If a record exists and `force_fresh` is `false`, the serialized `report_json` is deserialized and returned immediately.
2. **Dynamic Web Acquisition (Crawler Stage):**
   - If cache miss or `force_fresh` is `true`, `collector.py::collect_page()` initializes a sandboxed Playwright Chromium context via `browser.py::BrowserManager`.
   - Navigates to the URL with a 30,000 ms timeout.
   - Saves a full-viewport rasterized screenshot to `temp/screenshots/{analysis_id}.png`.
   - Executes `EXTRACTION_SCRIPT` in the browser context to extract form fields, password inputs, submit buttons, links, and DOM visible text.
3. **Optical Character Recognition (OCR Stage):**
   - `ocr_engine.py::TesseractOCREngine` reads the screenshot PNG using Pillow.
   - Invokes `pytesseract.image_to_string()` with English dictionary config.
   - Computes OCR confidence score and returns raw optical text ($R_3$).
4. **Lexical URL & Structural HTML Preprocessing:**
   - `url_processor.py::analyze_url()` computes hostname entropy, path entropy, Punycode IDN decoding, and TLD reputation ($R_5$).
   - `html_processor.py::extract_html_features()` extracts document title, heading tags ($H_1-H_6$), form action endpoints, and credential inputs ($R_4$).
5. **Multi-Representation Suite Compilation ($R_1-R_5$):**
   - `builder.py::build_representation_set()` compiles the 5-tuple:
     - $R_1$: Verbatim visible DOM text nodes (`raw.py`).
     - $R_2$: Normalized canonical text with NFKC decomposition and auditable mixed-script homoglyph resolution to Latin ASCII (`normalized.py`).
     - $R_3$: Tesseract OCR optical ground truth (`visual.py`).
     - $R_4$: Structural intent and credential inputs (`semantic.py`).
     - $R_5$: URL syntactic and lexical tokens (`url_repr.py`).
6. **Unicode Anomaly Detection:**
   - `unicode_processor.py::analyze_unicode()` inspects visible text for Cyrillic/Greek lookalikes in Latin words, zero-width characters (`\u200B`, `\u200C`, `\u200D`, `\uFEFF`, `\u00AD`), BiDi directional overrides (`\u202E`), and Plane 14 tag characters.
7. **Cross-Representation Discrepancy Engine (CRCE):**
   - `discrepancy.py::evaluate_discrepancies()` calculates Normalized Edit Distance (NED) via RapidFuzz:
     $$\text{NED}(s_a, s_b) = \frac{\text{Levenshtein}(s_a, s_b)}{\max(|s_a|, |s_b|)}$$
   - Computes pairwise NED: $\text{NED}(R_1, R_2)$, $\text{NED}(R_1, R_3)$, and $\text{NED}(R_2, R_3)$.
   - Computes Token Jaccard Divergence: $J_\delta(s_a, s_b) = 1.0 - \frac{|T_a \cap T_b|}{|T_a \cup T_b|}$.
   - **Visual-Normalization Convergence (VNC) Signature:** Evaluates whether raw text diverges from normalized and visual OCR, but normalized text converges with visual OCR:
     $$\Delta(R_1, R_2) \ge 0.02 \;\land\; \Delta(R_1, R_3) \ge 0.05 \;\land\; \Delta(R_2, R_3) < 0.35 \;\land\; \Delta(R_2, R_3) \le \Delta(R_1, R_3)$$
   - Evaluates Brand-to-Domain Discrepancy via `brand_detector.py::identify_claimed_brand()` using canonical domain sets, filtering out third-party OAuth Single Sign-On phrases.
8. **SLM Semantic Recovery & Threat Reasoning:**
   - `slm/factory.py::get_slm_engine()` obtains the configured engine (default: `MockSLMEngine`).
   - Task 1: `recover_semantics(R_1)` de-obfuscates adversarial tokens.
   - Task 2: `reason_phishing(Evidence)` synthesizes findings into structured threat rationale.
9. **Deterministic Evidence Fusion:**
   - `evidence_fusion.py::fuse_evidence()` synthesizes 7 weighted dimensions: Brand Spoofing (0.25), Credential Harvesting (0.20), CRCE Discrepancy (0.20), SLM Reasoning (0.15), URL Lexical Risk (0.10), Unicode Anomaly (0.05), Social Engineering (0.05).
   - Applies non-linear interaction boosts: VNC Convergence Boost (+0.25) and Credential Spoofing Boost (+0.20), capped at max interaction boost of +0.40. Produces continuous `composite_threat_score` ($S \in [0.0, 1.0]$).
10. **Calibrated Decision & Operational Posture:**
    - `risk.py::DecisionEngine.evaluate()` evaluates score against active policy thresholds (`BALANCED`: Safe $< 0.35$, Phishing $\ge 0.65$).
    - Applies deterministic rule overrides (`RULE-SAFE-01` Whitelisted Canonical Domain Guard, `RULE-CRIT-01` VNC Evasion Signature, `RULE-CRIT-02` Credential Theft on Spoofed Brand, `RULE-INV-01` Unverified Credentials Guard).
    - Maps verdict to defensive action: `SAFE` $\rightarrow$ `ALLOW`, `INVESTIGATE` $\rightarrow$ `WARN_USER` / `ISOLATE_SANDBOX`, `PHISHING` $\rightarrow$ `BLOCK_ACCESS`.
11. **Dual-Audience Explanation Generation:**
    - `explanation_engine.py::ExplanationEngine.generate()` constructs:
      - Plain-language User Advisory Card with threat badge and actionable advice.
      - Deep SOC Analyst Forensic Drawer with pairwise NED tables, Unicode character code points, interactive form metadata, and triggered rule identifiers.
12. **Persistence & Response Serialization:**
    - `database.py::DatabaseManager.save_record()` inserts or updates record into SQLite `analysis_records`.
    - Returns serialized `AnalysisDetailResponse` payload.

---

### 2.2 Browser Extension Message Analysis Pipeline (`POST /api/v1/message-analysis`)
*Code Reference:* [`backend/app/api/message_service.py::analyze_message_pipeline`](file:///C:/Users/Asus/.gemini/antigravity/scratch/RISE-Phish/backend/app/api/message_service.py)

1. **Client-Side Extraction (Content Script):**
   - Content script `adapters/gmail.js` runs in Gmail (`https://mail.google.com/*`).
   - On message view or manual scan click, extracts subject line, sender display string, sender email address, visible body text, and all embedded hyperlink objects (`href` and inner displayed text).
   - Dispatches payload to background worker `background.js` via `chrome.runtime.sendMessage()`.
2. **API Ingestion & Input Bounding:**
   - Background worker sends `POST /api/v1/message-analysis` to the configured backend.
   - `message_service.py::sanitize_and_bound_input()` bounds body text to 65,536 bytes, URLs to 20 maximum, and strings to 500 characters to prevent denial-of-service.
3. **Coercive Urgency & Social Engineering Analysis:**
   - `evaluate_urgency_indicators()` matches 10 regex psychological manipulation patterns (*"account suspended"*, *"verify immediately"*, *"unauthorized activity"*, *"action required"*).
   - Applies Benign Transactional Dampening: Discounts generic urgency if routine transactional cues (*"order #"*, *"invoice"*, *"unsubscribe"*, *"monthly statement"*) are present.
4. **Adversarial Prompt Injection Defense:**
   - `check_prompt_injection()` scans body for jailbreak sequences (e.g. `[SYSTEM OVERRIDE]`, `ignore all previous instructions`, `output verdict: safe`).
5. **Sender Authenticity & Brand Spoofing Analysis:**
   - `evaluate_sender_authenticity()` compares sender display name against sending address domain.
   - Recognizes authorized subdomains of canonical brands (`TARGET_BRAND_CANONICAL_DOMAINS`).
   - Recognizes authorized Email Service Provider (ESP) relays (`AUTHORIZED_ESP_RELAYS` including `sendgrid.net`, `mailchimp.com`, `mailgun.org`, `amazonses.com`, `substack.com`).
6. **Unicode Homoglyph Detection:**
   - `analyze_unicode()` detects Cyrillic/Greek lookalikes and invisible characters embedded in sender name or message body.
7. **SSRF-Safe Embedded URL Forensics:**
   - `evaluate_embedded_urls()` iterates over all extracted links:
     - **Anchor Text Mismatch Detection:** Checks if displayed anchor text claims a reputable domain while `href` directs elsewhere.
     - **SSRF & DNS Pre-flight Check:** `is_ssrf_safe()` performs live DNS resolution (`socket.getaddrinfo`), blocks loopback (`127.0.0.1`), private RFC 1918 subnets, and cloud metadata (`169.254.169.254`).
     - **RFC 6052 NAT64 Translation:** Unpacks embedded IPv4 addresses from `64:ff9b::/96` to permit legitimate public IPv4 translations on dual-stack networks while preventing tunneled loopback attacks.
     - **URL Lexical Risk Analysis:** Invokes `url_processor.py::analyze_url()` for Shannon entropy and Punycode homographs.
8. **Multi-Signal Corroboration Decision Policy:**
   - Evaluates aggregated link statistics (`phishing_links_count`, `mismatch_count`, `all_links_safe`).
   - Requires at least ONE definitive threat or TWO corroborated attack signals for `PHISHING`:
     - Confirmed phishing or anchor-hijacked URL destination, OR
     - Sender brand spoofing corroborated by an unverified/risky link or severe urgency ($\ge 0.40$), OR
     - Multi-signal convergence ($\ge 0.65$) where links are not verified safe.
   - If an email has an ambiguous sender but all links lead to verified safe domains, it is categorized as `INVESTIGATE` (`WARN_USER`) rather than triggering a false `PHISHING` alarm.
9. **Response Serialization:**
   - Returns `MessageAnalysisResponse` containing threat verdict, composite score, indicators, link verdicts, summary headline, and key findings.
   - Content script renders a color-coded warning banner in Gmail, and popup displays detailed indicators.

---

## 3. Actual API Routes, Schemas, and HTTP Specifications

All endpoints are hosted by FastAPI and documented interactively via OpenAPI/Swagger at `/docs`.

| Method | Endpoint | Router Module | Request Schema | Response Schema | Status | Description |
| :--- | :--- | :--- | :--- | :--- | :---: | :--- |
| `GET` | `/api/v1/health` | `routes.py` | None | `HealthResponse` | 200 | Returns backend operational status, version, environment |
| `POST` | `/api/v1/analyze` | `routes.py` | `AnalysisRequest` | `AnalysisDetailResponse` | 200 | Executes full URL crawling, OCR, CRCE, SLM analysis |
| `GET` | `/api/v1/history` | `routes.py` | Query params | `AnalysisHistoryResponse` | 200 | Retrieves paginated historical scans with verdict filters |
| `GET` | `/api/v1/analysis/{id}`| `routes.py` | Path param (`id`) | `AnalysisDetailResponse` | 200/404 | Fetches complete stored forensic report by UUID |
| `DELETE`| `/api/v1/analysis/{id}`| `routes.py` | Path param (`id`) | `dict` | 200/404 | Deletes historical scan record from database |
| `GET` | `/api/v1/stats` | `routes.py` | None | `DashboardStatsResponse`| 200 | Returns aggregate scan metrics, counts, and brand telemetry |
| `GET` | `/api/v1/extension/health`| `extension_routes.py` | None | `ExtensionHealthResponse` | 200 | Extension connectivity, supported sites, SSRF status |
| `POST` | `/api/v1/message-analysis`| `extension_routes.py` | `MessageAnalysisRequest` | `MessageAnalysisResponse`| 200 | Analyzes email content, sender, and embedded hyperlinks |
| `GET` | `/demo/zero-day-math` | `demo.py` | None | HTML | 200 | Serves live phishing lure with Math Alphanumerics |
| `GET` | `/demo/cyrillic-homoglyph`| `demo.py` | None | HTML | 200 | Serves live phishing lure with Cyrillic homoglyphs |
| `GET` | `/demo/credential-harvest`| `demo.py` | None | HTML | 200 | Serves live credential harvesting login portal |
| `GET` | `/demo/authentic-portal` | `demo.py` | None | HTML | 200 | Serves authentic documentation portal (benign baseline) |
| `POST` | `/demo/harvest` | `demo.py` | Form data | `dict` | 200 | Sink endpoint for simulated form submissions |

---

## 4. Database Architecture and Data Storage

*Code Reference:* [`backend/app/storage/database.py`](file:///C:/Users/Asus/.gemini/antigravity/scratch/RISE-Phish/backend/app/storage/database.py)

### 4.1 SQLite Database Schema (`rise_phish.db`)
The database operates in Write-Ahead Logging (WAL) mode (`PRAGMA journal_mode=WAL;`) with foreign keys enabled.

```sql
CREATE TABLE IF NOT EXISTS analysis_records (
    analysis_id TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    status TEXT NOT NULL,
    verdict TEXT NOT NULL,
    recommended_action TEXT NOT NULL,
    composite_threat_score REAL NOT NULL,
    confidence_score REAL NOT NULL,
    target_brand TEXT,
    registered_domain TEXT,
    visual_normalization_convergence INTEGER NOT NULL DEFAULT 0,
    report_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_records_url ON analysis_records(url);
CREATE INDEX IF NOT EXISTS idx_records_verdict ON analysis_records(verdict);
CREATE INDEX IF NOT EXISTS idx_records_created_at ON analysis_records(created_at);
```

### 4.2 Stored Fields Breakdown
- `analysis_id`: UUIDv4 string uniquely identifying the analysis job.
- `url`: Target URL analyzed.
- `status`: Execution state (`COMPLETED`, `FAILED`).
- `verdict`: Operational classification (`SAFE`, `INVESTIGATE`, `PHISHING`).
- `recommended_action`: Security policy posture (`ALLOW`, `WARN_USER`, `ISOLATE_SANDBOX`, `BLOCK_ACCESS`).
- `composite_threat_score`: Floating-point continuous score in $[0.0, 1.0]$.
- `confidence_score`: Decision confidence metric in $[0.0, 1.0]$.
- `target_brand`: Detected claimed brand entity or `null`.
- `registered_domain`: Base registered domain from `tldextract`.
- `visual_normalization_convergence`: Binary flag (1 if VNC signature present, 0 otherwise).
- `report_json`: Full serialized JSON string of `AnalysisDetailResponse` containing all five representations ($R_1-R_5$), CRCE pairwise metrics, SLM outputs, evidence factors, user advisory card, and SOC analyst drawer payload.
- `created_at` / `completed_at`: ISO 8601 UTC timestamps.

### 4.3 Ephemeral File Storage
- Screenshots: Saved to `temp/screenshots/{analysis_id}.png`. Used by Tesseract OCR during pipeline execution. Not stored in SQLite database.

---

## 5. Algorithmic Logic Breakdown

### 5.1 Preprocessing and Extraction
- **HTML Hierarchy (`html_processor.py`):** Uses BeautifulSoup4 and `lxml`. Strips non-content tags (`<script>`, `<style>`, `<svg>`). Extracts document title, heading tags ($H_1-H_6$), form action endpoints, input field types (`password`, `text`, `email`), and computes credential form ratios.
- **Lexical URL Decomposition (`url_processor.py`):** Uses `tldextract` for domain parsing. Calculates Shannon entropy of hostname and path:
  $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
  Detects Punycode IDN homographs (`xn--...`), IP-based hostnames, credential confusion markers (`@`), and excessive subdomain depth.
- **Unicode Analysis (`unicode_processor.py`):** Scans character codepoints using `unicodedata`. Identifies mixed-script tokens containing Latin with Cyrillic or Greek homoglyphs, zero-width characters (`U+200B-U+200D`, `U+FEFF`, `U+00AD`), BiDi directional overrides (`U+202E`), and Plane 14 language tag characters.
- **Optical Character Recognition (`ocr_engine.py`):** Verifies image validity using Pillow. Invokes Tesseract OCR via `pytesseract.image_to_string()`. Extracts optical visual text ($R_3$) and confidence metrics.

### 5.2 Multi-Representation Suite ($R_1 - R_5$)
- **$R_1$ (Raw DOM):** Verbatim visible text extracted from DOM text nodes before string mutation.
- **$R_2$ (Normalized Representation):** Canonical text derived by applying `unicodedata.normalize("NFKC", text)` followed by traceable homoglyph substitution mapping (`HOMOGLYPH_TO_LATIN`).
- **$R_3$ (Visual OCR Ground Truth):** Text extracted by Tesseract OCR from the rasterized viewport screenshot.
- **$R_4$ (Semantic Intent):** Structured layout model containing document title, headings, forms, inputs, and submission actions.
- **$R_5$ (URL Lexical Representation):** Registered domain, TLD, subdomain depth, path tokens, and entropy.

### 5.3 Cross-Representation Discrepancy Engine (CRCE)
*Code Reference:* [`backend/app/crce/discrepancy.py`](file:///C:/Users/Asus/.gemini/antigravity/scratch/RISE-Phish/backend/app/crce/discrepancy.py)

- **Normalized Edit Distance (NED):** Measures character-level divergence using RapidFuzz Levenshtein distance:
  $$\text{NED}(s_a, s_b) = \frac{\text{Levenshtein}(s_a, s_b)}{\max(|s_a|, |s_b|)}$$
- **Token Jaccard Divergence:** Measures word-level divergence:
  $$J_\delta(s_a, s_b) = 1.0 - \frac{|T_a \cap T_b|}{|T_a \cup T_b|}$$
- **Visual-Normalization Convergence (VNC) Detection:** Identifies deceptive evasion payloads where raw HTML differs from normalized and visual OCR, but normalized converges with visual OCR:
  $$\Delta(R_1, R_2) \ge 0.02 \;\land\; \Delta(R_1, R_3) \ge 0.05 \;\land\; \Delta(R_2, R_3) < 0.35 \;\land\; \Delta(R_2, R_3) \le \Delta(R_1, R_3)$$
- **Brand Identification:** Matches detected brand names against `TARGET_BRAND_CANONICAL_DOMAINS`. Strips third-party OAuth Single Sign-On phrases (*"Sign in with Google"*, *"Continue with Apple"*) to prevent false positive discrepancy penalties on authentic third-party integrations.

### 5.4 Evidence Fusion Engine
*Code Reference:* [`backend/app/fusion/evidence_fusion.py`](file:///C:/Users/Asus/.gemini/antigravity/scratch/RISE-Phish/backend/app/fusion/evidence_fusion.py)

Computes the weighted composite threat score across 7 evidence dimensions:
- Brand Spoofing: `0.25`
- Credential Harvesting: `0.20`
- CRCE Discrepancy: `0.20`
- SLM Threat Reasoning: `0.15`
- URL Lexical Risk: `0.10`
- Unicode Anomaly: `0.05`
- Social Engineering Urgency: `0.05`

Applies non-linear interaction boosts:
- Convergence Boost: `+0.25` when VNC signature coincides with brand mismatch.
- Credential Spoofing Boost: `+0.20` when password forms coincide with unauthorized brand claims.
- Max Interaction Boost Cap: `+0.40`.

### 5.5 Calibrated Decision Engine
*Code Reference:* [`backend/app/decision/risk.py`](file:///C:/Users/Asus/.gemini/antigravity/scratch/RISE-Phish/backend/app/decision/risk.py)

- Threshold Cutoffs for `BALANCED` Policy:
  - Score $< 0.35$: `SAFE` $\rightarrow$ `ALLOW`
  - $0.35 \le \text{Score} < 0.65$: `INVESTIGATE` $\rightarrow$ `WARN_USER`
  - Score $\ge 0.65$: `PHISHING` $\rightarrow$ `BLOCK_ACCESS`
- Deterministic Rule Overrides:
  - `RULE-SAFE-01`: Verified Canonical Domain Guard (whitelists official infrastructure).
  - `RULE-CRIT-01`: VNC Evasion Signature on spoofed brand forces `PHISHING` + `BLOCK_ACCESS`.
  - `RULE-CRIT-02`: Credential harvesting on spoofed brand forces `PHISHING` + `BLOCK_ACCESS`.
  - `RULE-INV-01`: Password input on unverified brand forces minimum `INVESTIGATE`.

---

## 6. Small Language Model (SLM) Subsystem Reality Check

*Code Reference:* [`backend/app/slm/`](file:///C:/Users/Asus/.gemini/antigravity/scratch/RISE-Phish/backend/app/slm/)

Section 6 provides an unvarnished audit of all AI/LLM claims in the codebase:

1. **Configured Model Names in Source Code:**
   - Default setting in `backend/app/core/config.py`: `SLM_MODEL_NAME = "microsoft/Phi-3-mini-4k-instruct"`
   - Model name in `docker-compose.yml`: `SLM_MODEL_NAME = "Qwen/Qwen2.5-0.5B-Instruct"`
   - Default model name in `MockSLMEngine`: `model_name = "mock-slm-oracle-v1"`
2. **Actual Loading and Inference Mechanism:**
   - **Active Running Engine: MOCK / RULE-BASED.**
   - In `.env`, `SLM_BACKEND=mock`.
   - The system executes `MockSLMEngine` backed by deterministic rule-based algorithms:
     - Task 1 (Semantic Recovery): `algorithmic_semantic_recovery()` in `recovery.py` uses regex, `unicodedata`, and a static 88-character homoglyph mapping table (`HOMOGLYPH_TO_LATIN`) to restore obfuscated tokens.
     - Task 2 (Phishing Reasoning): `algorithmic_phishing_reasoning()` in `reasoning.py` calculates heuristic threat points from brand mismatches, credential fields, and VNC flags to output JSON reasoning.
3. **Model Weights Presence:**
   - **Zero model weights are stored in the repository.** No `.safetensors`, `.bin`, `.pt`, or `.onnx` files exist in the project tree.
4. **Dependency Status:**
   - Neither `torch` nor `transformers` is installed in `.venv` or declared in `backend/requirements.txt`.
   - Executing `python -c "import torch"` confirms `ModuleNotFoundError: No module named 'torch'`.
5. **Hardware Usage & GPU Reality Check:**
   - Claims in `README.md` stating *"Hardware-Calibrated Lightweight SLM (0.5B–1.5B)... Peak VRAM: < 2.0 GB on RTX 3050"* represent **theoretical hardware sizing specifications and design profiles**, not an active CUDA tensor runtime.
6. **Influence on Threat Score:**
   - The SLM output is **not purely explanatory**. It directly contributes **15%** of the composite threat score in `evidence_fusion.py`:
     $$\text{weighted\_score} = (\text{base\_slm} \times \text{confidence}) \times 0.15$$
   - The recovered brand from Task 1 feeds directly into the brand spoofing evaluation.

---

## 7. Test Commands and Verified Test Results

*Verification Command:* `pytest tests/ -q`  
*Test Framework:* Pytest 9.1.1, Python 3.12.5 (Windows 11)

### 7.1 Test Suite Inventory
The automated test suite contains **177 automated test cases** across 23 test modules:

| Test Module File | Test Count | Scope & Focus Area | Status |
| :--- | :---: | :--- | :---: |
| `tests/api/test_analysis_endpoints.py` | 8 | URL analysis route, caching, pagination, deletion | **PASSED** |
| `tests/api/test_health.py` | 2 | Health check and Swagger documentation routes | **PASSED** |
| `tests/crawler/test_crawler.py` | 6 | URL validation, synthetic crawling, DNS failures | **PASSED** |
| `tests/crce/test_crce.py` | 6 | Similarity metrics, character mismatches, VNC signature | **PASSED** |
| `tests/datasets/test_datasets.py` | 9 | Synthesizers, split creation, stratification | **PASSED** |
| `tests/decision/test_decision_engine.py` | 9 | Policy thresholds, overrides (`SAFE-01`, `CRIT-01`), bounds | **PASSED** |
| `tests/deployment/test_deployment_config.py` | 6 | Dockerfiles, Compose syntax, Nginx configuration | **PASSED** |
| `tests/edge_cases/test_comprehensive_edge_cases.py` | 15 | Huge DOMs, null bytes, IPv6, emoji floods, SQL payloads | **PASSED** |
| `tests/experiments/test_ablation.py` | 1 | Component ablation experiment protocol | **PASSED** |
| `tests/experiments/test_experiments.py` | 4 | Experiments 1–4 execution protocols | **PASSED** |
| `tests/experiments/test_unseen_attacks.py` | 5 | Zero-day attack family evaluation protocols | **PASSED** |
| `tests/explanation/test_explanation_engine.py` | 4 | User advisory and SOC forensic report generation | **PASSED** |
| `tests/extension/test_browser_extension.py` | 15 | Gmail adapter, sender discrepancy, ESP relays, anchor spoofing | **PASSED** |
| `tests/extension/test_ssrf_and_security.py` | 8 | Loopback blocking, metadata blocking, NAT64 parsing | **PASSED** |
| `tests/fusion/test_evidence_fusion.py` | 9 | 7-factor weights, convergence boost, brand extraction | **PASSED** |
| `tests/integration/test_e2e_pipeline.py` | 8 | End-to-end pipeline execution from URL to SQLite | **PASSED** |
| `tests/ml/test_baseline.py` | 4 | RandomForest feature extraction, scaling, evaluation | **PASSED** |
| `tests/preprocessing/test_html_processor.py` | 8 | HTML cleaning, credential detection, text stripping | **PASSED** |
| `tests/preprocessing/test_ocr_engine.py` | 7 | Tesseract OCR, Mock OCR fallback, corrupt images | **PASSED** |
| `tests/preprocessing/test_url_processor.py` | 6 | Shannon entropy, Punycode IDN homographs, IP hosts | **PASSED** |
| `tests/representations/test_representations.py` | 6 | Immutability of R1, traceability of R2, assembly | **PASSED** |
| `tests/slm/test_slm.py` | 17 | Task 1 de-homoglyphing, Task 2 reasoning, fallbacks | **PASSED** |
| `tests/unicode/test_unicode_processor.py` | 9 | Monolingual Cyrillic, zero-width, BiDi, Plane 14 tags | **PASSED** |
| **Total Test Count** | **177** | **100% Pass Rate (0 Failures, 1 Warning)** | **PASSED** |

*Execution Duration:* 33.03 seconds.  
*Deprecation Warning:* Starlette testclient httpx warning (`StarletteDeprecationWarning`).

---

## 8. Security Assessment, Limitations, and Missing Components

### 8.1 Verified Security Protections
1. **SSRF Defense with RFC 6052 NAT64 Support (`backend/app/core/ssrf.py`):**
   - Strictly enforced in `message_service.py` for embedded links.
   - Blocks destination ports outside 1–65535, invalid schemes, cloud metadata IPs (`169.254.169.254`, `fd00:ec2::254`), loopback (`127.0.0.0/8`, `::1`), and RFC 1918 private subnets.
   - Correctly unpacks embedded IPv4 addresses from RFC 6052 NAT64 prefixes (`64:ff9b::/96`), permitting public NAT64 IPv4 addresses while blocking tunneled loopback/private destinations.
2. **Hardened Chromium Sandbox:**
   - 21 Chromium launch arguments enforce isolation (`--no-sandbox`, `--disable-gpu`, `--disable-extensions`, `--disable-default-apps`).
   - Disables file downloads and destroys browser contexts per job.
3. **SQL Injection Neutralization:**
   - All SQLite database queries use parameterized SQL (`?` placeholders).
4. **Extension Privacy Boundaries:**
   - Extracts only visible subject, sender, body text, and links from the active message.
   - Does not request cookies, passwords, browsing history, or full inbox scanning.

### 8.2 Security Issues & Gaps
1. **SSRF Omission on URL Crawler:**
   - `collect_page()` in `backend/app/crawler/collector.py` does **not** call `is_ssrf_safe()` prior to `page.goto()`. A caller submitting `http://169.254.169.254/latest/meta-data` to `/api/v1/analyze` will cause Chromium to request cloud metadata.
2. **Permissive CORS Extension Regex:**
   - `backend/app/main.py` uses `allow_origin_regex=r"^chrome-extension://.*$"`. Any installed Chrome extension on the client browser can query the local backend.
3. **Lack of Rate Limiting & Authentication:**
   - Analysis endpoints lack API keys and IP rate limiting.

### 8.3 Limitations & Unverified Claims
1. **Dataset Nature:**
   - The evaluation corpus in `datasets/splits/` consists of **200 synthetically generated samples** produced via procedural scripts. Reported benchmark results (100% recall, 0.0% FPR) are derived from this curated synthetic dataset, not a live internet feed.
2. **Dynamic Client-Side Single Page Apps (SPAs):**
   - Sites requiring multi-step human interaction (CAPTCHAs, 2FA, biometric challenges) cannot be fully analyzed.
3. **Screenshot Ephemerality:**
   - Viewport screenshots are stored as local files in `temp/screenshots/` and not persisted in SQLite. Purging `temp/` breaks screenshot previews in the SOC drawer.
