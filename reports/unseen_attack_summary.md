# Experiment 6: Unseen Representation Attack Generalization Evaluation
**Project:** RISE-Phish (Capstone B.Tech Project)  
**Evaluation Date:** 2026-10-21T06:00:08.182680+00:00  
**Corpus Size:** 100 test samples (50 Phishing, 50 Benign)  
**Random Seed:** 42 | **SLM Backend:** `mock`  

---

## 1. Executive Summary & Research Hypothesis
Standard machine learning classifiers trained purely on surface-level syntactic and lexical features overfit to known attack representations. When faced with novel zero-day evasion vectors withheld during training, standard classifiers experience substantial performance degradation.

**Core Research Finding:**  
RISE-Phish demonstrates superior out-of-distribution generalization on zero-day attacks without requiring retraining or manual rule updates:
- **Generalization Recall Advantage:** `+100.0%` improvement over baseline Random Forest (`0.0%` $\rightarrow$ `100.0%`).
- **Generalization F1 Advantage:** `+100.0%` improvement in balanced F1-score (`0.0%` $\rightarrow$ `100.0%`).
- **Zero-Day Deception Detection:** The **Visual-Normalization Convergence** signature ($R_1 \neq R_2$, $R_1 \neq R_3$, $R_2 \approx R_3$) reliably flags novel Unicode blocks and discretionary break attacks.

---

## 2. Overall Performance Comparison Table

| Architecture / Configuration | Accuracy | Precision | Recall | F1-Score | FPR | FNR |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Baseline Random Forest** (Pure URL + HTML) | `0.5000` | `0.0000` | `0.0000` | `0.0000` | `0.0000` | `1.0000` |
| **Baseline + CRCE Augmented** | `0.5000` | `0.0000` | `0.0000` | `0.0000` | `0.0000` | `1.0000` |
| **Full RISE-Phish System (Zero-Shot)** | **`1.0000`** | **`1.0000`** | **`1.0000`** | **`1.0000`** | **`0.0000`** | **`0.0000`** |

---

## 3. Attack-Specific Zero-Day Recall Breakdown

| Novel Evasion Technique | Codepoints / Mechanism | Baseline Recall | Baseline+CRCE | RISE-Phish Recall | $\Delta$ Recall |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Mathematical Alphanumerics** | `U+1D400-U+1D7FF` Bold/Sans symbols | `0.00%` | `0.00%` | **`100.00%`** | `+100.0%` |
| **Soft Hyphen Break Splitting** | `U+00AD` Discretionary breaks | `0.00%` | `0.00%` | **`100.00%`** | `+100.0%` |
| **Combining Diacritics Flooding** | `U+0300-U+036F` Non-spacing overlays | `0.00%` | `0.00%` | **`100.00%`** | `+100.0%` |
| **Enclosed / Circled Characters** | `U+24B6-U+24E9` Circled Latin | `0.00%` | `0.00%` | **`100.00%`** | `+100.0%` |
| **Chameleon Multi-Vector** | Math + Soft Hyphen + Form Lure | `0.00%` | `0.00%` | **`100.00%`** | `+100.0%` |

---

## 4. Key Security Insights
1. **Structural Evasion Immunity**: By decoupling text rendering into five distinct representations, RISE-Phish does not need to maintain blacklists of specific homoglyphs or bypass sequences.
2. **Preserving Internationalization**: Accented Latin characters (e.g. French, German, Spanish) are preserved under NFKC and do not trigger false positive convergence alerts (Localized Benign FPR: `0.00%`).
3. **Synergistic Evidence Amplification**: When an unseen representation divergence coincides with credential entry forms and unauthorized hostnames, non-linear evidence fusion drives confident detection.
