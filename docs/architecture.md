# RISE-Phish Architecture Specification

## 1. Research Motivation & Core Premise

Traditional phishing detection approaches generally fall into three categories:
1. **Lexical URL Classifiers**: Fast, but blind to sophisticated rendering tricks, obfuscated DOMs, and brand spoofing hosted on legitimate CDNs or cloud providers.
2. **HTML/DOM Parsers**: Effective for static pages, but easily deceived by homoglyphs, bidirectional overrides, zero-width characters, or dynamic JavaScript rendering.
3. **Multimodal LLM Classifiers**: Powerful, but computationally expensive, prone to hallucinations, non-deterministic, and frequently exceed the VRAM constraints of operational deployment environments.

### The RISE-Phish Insight: Discrepancy as First-Class Evidence
Attackers deliberately introduce discrepancies between what the browser security layer / DOM parser sees and what the human victim perceives visually. For instance:
- An attacker writes `Mіcrosoft` in HTML using Cyrillic Small Letter Byelorussian-Ukrainian I (`U+0456`).
- The victim sees `Microsoft` visually.
- A naive ASCII/Unicode filter might flag any Cyrillic character, triggering false positives on legitimate Ukrainian or Russian websites.
- However, if `Raw != Normalized` and `Raw != OCR`, but `Normalized == OCR` and the domain is not `microsoft.com`, this multi-representation discrepancy provides rigorous evidence of brand spoofing.

---

## 2. Multi-Representation System

| Representation | ID | Source | Description |
| :--- | :--- | :--- | :--- |
| **Raw** | $R_1$ | DOM / Text nodes | Extracted character sequences directly from the browser-rendered DOM, preserving raw Unicode code points and HTML entities. |
| **Normalized** | $R_2$ | Canonical Unicode | Canonical decomposition and composition (NFKC/NFC), HTML entity unescaping, and standardized whitespace collapsing. |
| **Visual / OCR** | $R_3$ | Rendered Screenshot | Optical Character Recognition text extracted from the Chromium rasterized viewport. |
| **Semantic** | $R_4$ | SLM Semantic Recovery | De-obfuscated semantic intent reconstructed by a lightweight SLM. |
| **URL** | $R_5$ | Address Bar | Syntactic and lexical URL decomposition, including Punycode transcription, registered domain, and path tokens. |

---

## 3. Cross-Representation Discrepancy Engine (CRCE)

CRCE evaluates pairwise divergences between representations:

```
          ┌─────────────┐
          │   Raw R1    │
          └──────┬──────┘
                 │
       ┌─────────┴─────────┐
       ▼                   ▼
┌─────────────┐     ┌─────────────┐
│Normalized R2│◄───►│ Visual  R3  │
└──────┬──────┘     └──────┬──────┘
       │                   │
       └─────────┬─────────┘
                 ▼
          ┌─────────────┐
          │ Semantic R4 │
          └──────┬──────┘
                 │
                 ▼
          ┌─────────────┐
          │   URL R5    │ (vs Detected Brand)
          └─────────────┘
```

### Discrepancy Metrics
1. **Normalized Edit Distance (NED)**: Character-level Levenshtein distance normalized by string length:
   $$\text{NED}(A, B) = \frac{\text{Levenshtein}(A, B)}{\max(|A|, |B|)}$$
2. **Token Jaccard & Cosine Divergence**: Token-level mismatch ratio across word boundaries.
3. **Unicode Anomaly Density**: Frequency of zero-width characters, bidirectional control marks, tag characters, and mixed-script homoglyphs per token.
4. **Visual-to-Lexical Alignment**: Discrepancy between OCR tokens and raw DOM tokens.
5. **Domain-to-Brand Semantic Mismatch**: Divergence between detected brand entities (e.g. PayPal, Apple, Google) and the registered domain of $R_5$.

---

## 4. Lightweight SLM Architecture (Dual-Task)

To satisfy the **RTX 3050 (4 GB VRAM)** hardware constraint:
- **SLM Engine Interface (`SLMEngine`)** cleanly decouples the detection logic from the model backend.
- Supported Backends:
  - **Local Small Quantized SLM**: e.g., `Phi-3-mini-4k-instruct` (4-bit AWQ / GGUF) or `Qwen2.5-1.5B/3B-Instruct`.
  - **External API Fallback**: Remote inference for research experimentation.
  - **Mock SLMEngine**: Deterministic rule/dictionary-based semantic recovery for rapid unit testing and CI/CD pipelines.

### Task 1: Semantic Recovery
- Recovers obfuscated text sequences (e.g. leetspeak, zero-width spaced tokens, mixed scripts) into canonical human-intended semantics.

### Task 2: Phishing Reasoning
- Ingests structured evidence vectors (CRCE scores, form presence, password inputs, brand/domain alignment).
- Produces structured JSON containing semantic urgency ratings, impersonation indicators, and targeted hypothesis reasoning.

---

## 5. Evidence Fusion & Decision Engine

The final decision is computed via a calibrated, deterministic fusion module:

$$\text{Risk Score} = \sum_{i} w_i \cdot \text{Evidence}_i$$

Where evidence sources include:
- URL Risk Score ($w_{\text{url}}$)
- Unicode Anomaly Score ($w_{\text{unicode}}$)
- CRCE Discrepancy Score ($w_{\text{crce}}$)
- Brand Impersonation Divergence ($w_{\text{brand}}$)
- Credential Harvesting Evidence ($w_{\text{credential}}$)
- SLM Semantic Urgency Score ($w_{\text{slm}}$)

### Decision Bands:
- $\text{Risk} < \tau_{\text{safe}}$: **SAFE**
- $\tau_{\text{safe}} \le \text{Risk} < \tau_{\text{phish}}$: **INVESTIGATE**
- $\text{Risk} \ge \tau_{\text{phish}}$: **PHISHING**

*Note: Initial weights and thresholds are strictly designated as initial hypotheses and will be empirically calibrated through validation experiments in Phase 14.*
