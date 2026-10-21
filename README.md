# RISE-Phish: Cross-Representation Discrepancy-Aware Phishing Detection Using Lightweight Language Models

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18+-61DAFB.svg)](https://react.dev/)
[![Vite](https://img.shields.io/badge/Vite-6+-646CFF.svg)](https://vitejs.dev/)
[![License](https://img.shields.io/badge/License-Academic-green.svg)]()

> **Final-Year B.Tech Research & Capstone Project**  
> Lead Research & Development: Final Year Team

---

## 1. Project Overview

**RISE-Phish** is a research-oriented phishing detection architecture designed to overcome the vulnerabilities of traditional URL/HTML classifiers and naive multimodal LLM systems.

Attackers frequently bypass defenses by exploiting discrepancies across representations:
- Rendering text via Unicode homoglyphs, zero-width characters, or bidirectional overrides.
- Generating HTML with obfuscated or hidden DOM nodes that visually look like trusted brands to human eyes and OCR.
- Presenting mismatched domains alongside genuine brand visual assets.

Rather than treating discrepancies in isolation or assuming every non-ASCII character is malicious, **RISE-Phish** introduces the **Cross-Representation Discrepancy Engine (CRCE)** coupled with an **Evidence Fusion Engine** and a **Small Language Model (SLM)** for semantic recovery and structured reasoning.

---

## 2. High-Level Architecture Flow

```
USER
  │
  ▼
URL INPUT
  │
  ▼
PLAYWRIGHT + CHROMIUM (Controlled Sandbox)
  │
  ├── Browser-rendered HTML
  ├── Screenshot
  ├── Visible Text
  └── Final Resolved URL / Redirect Chain
  │
  ▼
PREPROCESSING PIPELINE
  ├── HTML Processing (DOM, Forms, Inputs, Buttons)
  ├── URL Analysis (Lexical, Punycode, TLD, Domain)
  ├── Unicode Analysis (Homoglyphs, Zero-Width, BiDi, Tags)
  └── OCR Extraction (Visual text extraction via Tesseract/PaddleOCR)
  │
  ▼
REPRESENTATION GENERATION
  ├── R1: Raw Representation
  ├── R2: Normalized Representation
  ├── R3: Visual/OCR Representation
  ├── R4: Semantic Representation
  └── R5: URL Representation
  │
  ▼
CRCE (Cross-Representation Discrepancy Engine)
  ├── Raw vs Normalized Comparison
  ├── Raw vs OCR Comparison
  ├── Normalized vs OCR Comparison
  └── URL vs Detected Brand Comparison
  │
  ▼
SLM ENGINE (Phi-3 / Small Quantized Model / Fallback Interface)
  ├── Task 1: Semantic Recovery (de-obfuscation)
  └── Task 2: Phishing Reasoning (structured hypothesis validation)
  │
  ▼
EVIDENCE FUSION
  └── Multi-modal risk synthesis & anomaly scoring
  │
  ▼
DECISION ENGINE
  ├── SAFE
  ├── INVESTIGATE
  └── PHISHING
  │
  ▼
EXPLANATION & EVIDENCE VISUALIZATION
```

---

## 3. Technology Stack & Constraints

- **Hardware Target**: NVIDIA RTX 3050 Laptop GPU (4 GB VRAM), 16 GB RAM, Windows 11.
- **Backend**: Python 3.12, FastAPI, Pydantic v2, Uvicorn, Playwright Chromium.
- **Computer Vision & OCR**: Pillow, Tesseract OCR (behind an abstract OCR engine interface).
- **Text & Discrepancy Metrics**: RapidFuzz, Python `unicodedata`, Levenshtein metrics.
- **Machine Learning & NLP**: scikit-learn, Hugging Face Transformers (quantized SLM / API fallback).
- **Frontend**: React 18, Vite, Tailwind CSS, Lucide Icons.
- **Database**: SQLite (initial storage for analysis artifacts and history).

---

## 4. Repository Layout

```
RISE-Phish/
├── backend/
│   ├── app/
│   │   ├── main.py                     # FastAPI application entry point
│   │   ├── core/                       # Settings, logging, configuration
│   │   ├── api/                        # API route controllers
│   │   ├── crawler/                    # Controlled Playwright crawler (Phase 1)
│   │   ├── preprocessing/              # HTML, URL, Unicode, Text processors
│   │   ├── representations/            # R1-R5 representation generators
│   │   ├── crce/                       # Discrepancy calculation engine
│   │   ├── slm/                        # SLM interfaces (Local/Quantized/API/Mock)
│   │   ├── fusion/                     # Deterministic evidence fusion
│   │   ├── decision/                   # Decision engine (SAFE/INVESTIGATE/PHISHING)
│   │   └── models/                     # Strongly-typed Pydantic schemas
│   └── requirements.txt
├── frontend/                           # React + Vite + Tailwind CSS dashboard
├── datasets/                           # Controlled research datasets
│   ├── raw/
│   ├── processed/
│   ├── obfuscated/
│   └── splits/
├── experiments/                        # Reproducible evaluation protocols
│   ├── baseline/                       # Exp 1: Baseline URL+HTML classifier
│   ├── crce/                           # Exp 2: Baseline + CRCE
│   ├── slm/                            # Exp 3: CRCE + SLM
│   ├── ablation/                       # Exp 5: Ablation study
│   └── unseen_attack/                  # Exp 6: Zero-shot/unseen attack generalization
├── notebooks/                          # Research exploratory notebooks
├── reports/                            # Generated evaluation figures & tables
├── docs/                               # Formal architectural & API documentation
├── tests/                              # Comprehensive test suite (pytest)
├── .env.example                        # Template environment variables
├── pyproject.toml                      # Build and pytest configuration
└── README.md
```

---

## 5. Development Setup (Windows 11 / PowerShell)

### Step 1: Clone and Enter Repository
```powershell
cd RISE-Phish
```

### Step 2: Configure Virtual Environment
```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r backend/requirements.txt
```

### Step 3: Install Playwright Browsers
```powershell
playwright install chromium
```

### Step 4: Environment Variables
```powershell
Copy-Item .env.example .env
```

### Step 5: Run Tests
```powershell
pytest -v
```

### Step 6: Start Backend
```powershell
uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```
- Interactive API Docs: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- Health Endpoint: [http://127.0.0.1:8000/api/v1/health](http://127.0.0.1:8000/api/v1/health)

### Step 7: Start Frontend
```powershell
cd frontend
npm install
npm run dev
```
- Frontend UI: [http://localhost:5173](http://localhost:5173)

---

## 6. Phased Implementation Roadmap

- [x] **Phase 0: Project Initialization & Health Verification**
- [ ] **Phase 1: Controlled Playwright Crawler**
- [ ] **Phase 2: HTML Feature Processor**
- [ ] **Phase 3: Lexical & Punycode URL Analyzer**
- [ ] **Phase 4: Unicode Anomaly & Homoglyph Analyzer**
- [ ] **Phase 5: Abstract OCR Pipeline (Tesseract / PaddleOCR)**
- [ ] **Phase 6: Multi-Representation Generator (R1 - R5)**
- [ ] **Phase 7: CRCE Discrepancy Engine v1**
- [ ] **Phase 8: Baseline Classifier & Benchmarks**
- [ ] **Phase 9: SLM Integration & Semantic Recovery**
- [ ] **Phase 10: Deterministic Evidence Fusion**
- [ ] **Phase 11: Calibration & Decision Engine**
- [ ] **Phase 12: Explainability Engine**
- [ ] **Phase 13: Dataset Pipelines & Attack Synthesizer**
- [ ] **Phase 14: Experimental Protocol & Baseline Comparisons**
- [ ] **Phase 15: Ablation Studies**
- [ ] **Phase 16: Unseen Representation Attack Evaluation**
- [ ] **Phase 17: Full API Endpoint Integration**
- [ ] **Phase 18: Explainable React Dashboard**
- [ ] **Phase 19: End-to-End System Integration**
- [ ] **Phase 20: Comprehensive System Testing & Edge Cases**
- [ ] **Phase 21: Containerization & Reproducibility Packaging**
- [ ] **Phase 22: Academic Documentation, Final Report & Presentation Assets**
