"""Pydantic schemas and data contracts for RISE-Phish.
"""
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
from pydantic import BaseModel, Field, HttpUrl


class HealthResponse(BaseModel):
    """Health check response schema."""
    status: str = Field(default="ok", description="Service status indicator")
    app_name: str = Field(description="Name of the application")
    version: str = Field(default="0.1.0", description="Backend API version")
    environment: str = Field(description="Current deployment environment")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Current UTC timestamp"
    )


class AnalysisRequest(BaseModel):
    """Incoming request to analyze a URL."""
    url: str = Field(..., description="The target webpage URL to analyze")
    force_fresh: bool = Field(default=False, description="Bypass cache if set to True")


class AnalysisStatusResponse(BaseModel):
    """Async status tracking response."""
    analysis_id: str
    status: str
    created_at: datetime
    completed_at: Optional[datetime] = None


# ============================================================
# CRAWLER MODELS (Phase 1)
# ============================================================

class RedirectHop(BaseModel):
    """Details of a single redirection step."""
    url: str
    status_code: Optional[int] = None
    headers: Dict[str, str] = Field(default_factory=dict)


class FormInput(BaseModel):
    """Details of an input field discovered inside or outside forms."""
    input_type: str = Field(default="text", description="HTML input type attribute (e.g., text, password, email)")
    name: Optional[str] = Field(default=None, description="Input name attribute")
    id: Optional[str] = Field(default=None, description="Input element id attribute")
    placeholder: Optional[str] = Field(default=None, description="Placeholder text")
    is_password: bool = Field(default=False, description="Whether this input accepts credentials/passwords")


class FormSummary(BaseModel):
    """Summary of a web form on the rendered page."""
    action: Optional[str] = Field(default=None, description="Form action target URL")
    method: str = Field(default="get", description="HTTP submission method (get/post)")
    id: Optional[str] = Field(default=None, description="Form element id")
    name: Optional[str] = Field(default=None, description="Form element name")
    inputs: List[FormInput] = Field(default_factory=list, description="Inputs contained within this form")
    has_password: bool = Field(default=False, description="True if form contains one or more password inputs")


class CrawlerResult(BaseModel):
    """Structured output from the controlled Playwright web crawler."""
    analysis_id: str = Field(description="Unique tracking UUID for this crawl job")
    input_url: str = Field(description="Initial user-provided URL")
    final_url: Optional[str] = Field(default=None, description="Final resolved URL after redirects")
    status_code: Optional[int] = Field(default=None, description="HTTP response status code")
    redirect_chain: List[str] = Field(default_factory=list, description="Ordered list of redirect URLs")
    redirect_hops: List[RedirectHop] = Field(default_factory=list, description="Detailed redirect hop metadata")
    title: Optional[str] = Field(default=None, description="Rendered document title")
    html: Optional[str] = Field(default=None, description="Fully rendered DOM HTML markup")
    visible_text: Optional[str] = Field(default=None, description="Extracted visible text from page body")
    screenshot_path: Optional[str] = Field(default=None, description="Local file path to captured PNG screenshot")
    links: List[str] = Field(default_factory=list, description="Extracted hyperlinks on the page")
    forms: List[FormSummary] = Field(default_factory=list, description="Extracted form elements")
    input_fields: List[FormInput] = Field(default_factory=list, description="All discovered input fields")
    password_fields: List[FormInput] = Field(default_factory=list, description="All discovered password inputs")
    buttons: List[str] = Field(default_factory=list, description="Text and labels of interactive buttons")
    
    # Execution state & diagnostics
    success: bool = Field(default=True, description="Indicates whether navigation and collection succeeded")
    error_type: Optional[str] = Field(default=None, description="Category of failure if unsuccessful")
    error_message: Optional[str] = Field(default=None, description="Human-readable error diagnostic")
    elapsed_ms: int = Field(default=0, description="Collection latency in milliseconds")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp of collection"
    )


# ============================================================
# HTML PROCESSING MODELS (Phase 2)
# ============================================================

class HeadingItem(BaseModel):
    """Extracted HTML heading tag details."""
    level: int = Field(description="Heading depth (1 for h1, 2 for h2, etc.)")
    text: str = Field(description="Cleaned text content of heading")


class ImageSummary(BaseModel):
    """Image element metadata."""
    src: Optional[str] = Field(default=None, description="Image source URI")
    alt: Optional[str] = Field(default=None, description="Alternative text description")
    title: Optional[str] = Field(default=None, description="Title attribute")


class HTMLFeatures(BaseModel):
    """Structured extraction of features from rendered HTML.
    
    Prevents flooding the SLM with raw HTML while retaining critical
    structural, lexical, and credential-seeking context.
    """
    title: Optional[str] = Field(default=None, description="Document title")
    headings: List[HeadingItem] = Field(default_factory=list, description="All extracted heading items (h1-h6)")
    paragraphs: List[str] = Field(default_factory=list, description="Non-empty paragraph texts")
    visible_text: str = Field(default="", description="Sanitized, script/style-free visible body text")
    links: List[str] = Field(default_factory=list, description="Unique hyperlinks discovered in markup")
    forms: List[FormSummary] = Field(default_factory=list, description="Structured summaries of all form elements")
    buttons: List[str] = Field(default_factory=list, description="Extracted text and labels of interactive buttons")
    input_fields: List[FormInput] = Field(default_factory=list, description="All input fields found across DOM")
    password_inputs: List[FormInput] = Field(default_factory=list, description="Identified credential/password fields")
    images: List[ImageSummary] = Field(default_factory=list, description="Extracted image elements")
    alt_texts: List[str] = Field(default_factory=list, description="Non-empty image alt attribute descriptions")
    placeholders: List[str] = Field(default_factory=list, description="All input/textarea placeholder labels")
    meta_attributes: Dict[str, str] = Field(default_factory=dict, description="Metadata tags (description, keywords, og:*)")
    
    # Statistical / heuristic indicators
    total_tags: int = Field(default=0, description="Count of HTML tags parsed")
    script_count: int = Field(default=0, description="Count of script elements present")
    iframe_count: int = Field(default=0, description="Count of iframe elements present")
    has_password_field: bool = Field(default=False, description="True if any password inputs are present")
    
    # Structured representation for SLM ingestion
    structured_slm_text: str = Field(
        default="", 
        description="Concise, structured plain-text representation suitable for SLM context without DOM bloat"
    )


# ============================================================
# URL ANALYSIS MODELS (Phase 3)
# ============================================================

class URLFeatures(BaseModel):
    """Structured lexical, syntactic, and structural evidence extracted from a URL."""
    raw_url: str = Field(description="Original input or evaluated URL string")
    url_length: int = Field(description="Total character length of the URL")
    scheme: str = Field(description="URL protocol scheme (e.g., http, https)")
    hostname: str = Field(description="Fully qualified domain name or IP host")
    registered_domain: str = Field(description="Registrable domain including suffix (e.g., example.com)")
    subdomain: str = Field(description="Subdomain prefix (e.g., login.account)")
    path: str = Field(description="URL path component")
    query: str = Field(description="Query string parameters")
    tld: str = Field(description="Top-level domain suffix (e.g., com, org, xyz)")
    
    # Character & Syntactic counts
    num_dots: int = Field(default=0, description="Total count of '.' characters")
    num_hyphens: int = Field(default=0, description="Total count of '-' characters")
    num_digits: int = Field(default=0, description="Total count of numeric digits")
    num_special_chars: int = Field(default=0, description="Count of non-alphanumeric characters (excluding standard delimiters)")
    
    # Anomaly flags
    has_at_symbol: bool = Field(default=False, description="Presence of '@' symbol (often used for credential confusion/obfuscation)")
    has_ip_address: bool = Field(default=False, description="True if host is an IPv4 or IPv6 address")
    is_ipv4: bool = Field(default=False, description="True if host is an IPv4 address")
    is_ipv6: bool = Field(default=False, description="True if host is an IPv6 address")
    has_percent_encoding: bool = Field(default=False, description="Presence of percent-encoded sequences (%XX)")
    percent_encoding_count: int = Field(default=0, description="Number of percent-encoded characters")
    has_punycode: bool = Field(default=False, description="Presence of Punycode IDN prefix (xn--) in hostname")
    punycode_decoded_domain: Optional[str] = Field(default=None, description="Decoded Unicode string if Punycode is present")
    
    # Advanced lexical metrics
    redirect_count: int = Field(default=0, description="Number of redirects observed leading to this URL")
    subdomain_parts_count: int = Field(default=0, description="Number of labels in subdomain")
    shannon_entropy: float = Field(default=0.0, description="Shannon entropy of the hostname character distribution")
    suspicious_tld: bool = Field(default=False, description="True if the TLD has historically elevated abuse rates")
    suspicious_keywords_found: List[str] = Field(default_factory=list, description="Phishing-correlated keywords discovered in URL")
    
    # Synthesized risk estimation
    url_risk_score: float = Field(default=0.0, description="Normalized lexical risk score (0.0 to 1.0)")
    risk_reasons: List[str] = Field(default_factory=list, description="Structured human-readable justifications for URL risk")


# ============================================================
# UNICODE ANALYSIS MODELS (Phase 4)
# ============================================================

class UnicodeAnomaly(BaseModel):
    """Preserves exact, un-modified evidence of a detected Unicode anomaly.
    
    Retains codepoint, character name, position, context token, normalized form,
    and technical explanation of why it was flagged.
    """
    character: str = Field(description="Original Unicode character")
    codepoint: str = Field(description="Formatted Unicode hex code point (e.g. U+0456)")
    codepoint_int: int = Field(description="Integer code point value")
    name: str = Field(description="Standard Unicode character name")
    category: str = Field(description="Unicode general category (e.g., Ll, Cf, Cc, Mn)")
    script: str = Field(description="Detected Unicode script (e.g., Latin, Cyrillic, Greek, Common)")
    position: int = Field(description="0-based index offset in the inspected text")
    context_token: Optional[str] = Field(default=None, description="Word/token containing the character")
    anomaly_type: str = Field(
        description="Classification: zero_width, bidi_control, tag_character, homoglyph, normalization_change, invisible_format"
    )
    normalized_nfkc: str = Field(description="Canonical NFKC decomposition/composition character")
    is_mixed_script_token: bool = Field(
        default=False, 
        description="True if character script conflicts with the dominant script of its context token"
    )
    reason: str = Field(description="Human-readable justification for flagging this anomaly")
    severity: float = Field(default=0.5, description="Anomaly severity rating from 0.0 to 1.0")


class UnicodeAnalysisResult(BaseModel):
    """Structured output of comprehensive Unicode anomaly inspection."""
    total_characters: int = Field(default=0, description="Total characters analyzed")
    ascii_characters: int = Field(default=0, description="Count of standard ASCII characters (0-127)")
    non_ascii_characters: int = Field(default=0, description="Count of non-ASCII characters")
    anomalies: List[UnicodeAnomaly] = Field(default_factory=list, description="Detailed list of flagged anomalies")
    
    # Category counts
    zero_width_count: int = Field(default=0, description="Number of zero-width / joiner characters")
    bidi_control_count: int = Field(default=0, description="Number of bidirectional override characters")
    tag_character_count: int = Field(default=0, description="Number of Plane 14 tag characters")
    homoglyph_count: int = Field(default=0, description="Number of cross-script lookalike / homoglyph characters")
    normalization_change_count: int = Field(default=0, description="Characters altered under NFKC normalization")
    mixed_script_token_count: int = Field(default=0, description="Number of tokens with conflicting scripts")
    
    detected_scripts: List[str] = Field(default_factory=list, description="Unique scripts discovered across text")
    unicode_anomaly_score: float = Field(
        default=0.0, 
        description="Normalized anomaly score (0.0 to 1.0) calibrated against text length and anomaly severity"
    )
    summary: str = Field(default="", description="Executive research summary of Unicode findings")


# ============================================================
# OCR PIPELINE MODELS (Phase 5)
# ============================================================

class OCRWord(BaseModel):
    """Word-level extraction detail from an OCR pass."""
    text: str = Field(description="Recognized word or token string")
    confidence: float = Field(default=0.0, description="Confidence score from 0.0 to 100.0")
    box: Optional[Tuple[int, int, int, int]] = Field(
        default=None, 
        description="Bounding box coordinates (left, top, width, height)"
    )


class OCRResult(BaseModel):
    """Structured result of optical character recognition on page screenshot."""
    text: str = Field(default="", description="Full extracted text content from image")
    confidence: float = Field(default=0.0, description="Average confidence score across all detected words")
    words: List[OCRWord] = Field(default_factory=list, description="Word tokens with confidence metrics")
    available: bool = Field(default=True, description="True if OCR engine executed successfully")
    engine_name: str = Field(description="Name of the active OCR engine backend")
    error_message: Optional[str] = Field(default=None, description="Diagnostic details if OCR failed or was unavailable")
    latency_ms: int = Field(default=0, description="OCR extraction latency in milliseconds")


# ============================================================
# MULTI-REPRESENTATION MODELS (Phase 6)
# ============================================================

class RawRepresentation(BaseModel):
    """R1: Unaltered, raw character representation extracted directly from DOM text nodes.
    
    Never normalized, keeping exact homoglyphs, zero-width characters, and encoding entities.
    """
    text: str = Field(description="Exact raw text sequence extracted from page")
    character_count: int = Field(description="Total raw character count")
    source_type: str = Field(default="dom_text_nodes", description="Source extraction mechanism")


class NormalizedRepresentation(BaseModel):
    """R2: Traceably normalized representation derived from R1.
    
    Applies NFKC canonical decomposition/composition, HTML entity decoding,
    and invisible character stripping with full audit of applied transformations.
    """
    text: str = Field(description="Standardized normalized text sequence")
    character_count: int = Field(description="Total normalized character count")
    transformations_applied: List[str] = Field(
        default_factory=list,
        description="Ordered list of transformation stages executed"
    )
    characters_altered_count: int = Field(
        default=0,
        description="Number of characters modified, added, or stripped during normalization"
    )


class VisualRepresentation(BaseModel):
    """R3: Visual / OCR representation captured from rasterized screenshot."""
    text: str = Field(default="", description="Text extracted via Optical Character Recognition")
    confidence: float = Field(default=0.0, description="Average confidence rating of OCR extraction")
    available: bool = Field(default=True, description="True if screenshot and OCR succeeded")
    screenshot_path: Optional[str] = Field(default=None, description="Path to screenshot asset")
    words_count: int = Field(default=0, description="Total word tokens recognized")
    engine_name: str = Field(default="TesseractOCR", description="OCR engine utilized")
    error_message: Optional[str] = Field(default=None, description="Diagnostic note if OCR failed")


class SemanticRepresentation(BaseModel):
    """R4: Structured semantic representation extracting core intent and claims.
    
    Distills page title, headings hierarchy, credential form intent,
    and key action tokens while removing layout noise.
    """
    title: Optional[str] = Field(default=None, description="Document title")
    headings_text: str = Field(default="", description="Flattened text of all headings")
    form_intent_summary: str = Field(default="", description="Summary of credential forms and inputs")
    action_tokens: List[str] = Field(default_factory=list, description="Interactive action verbs and button labels")
    structured_content: str = Field(default="", description="Clean semantic summary for downstream modeling")


class URLRepresentation(BaseModel):
    """R5: Decomposed address bar / URL representation."""
    raw_url: str = Field(description="Complete resolved target URL")
    hostname: str = Field(description="Full hostname or IP host")
    registered_domain: str = Field(description="Registrable domain (e.g. example.com)")
    subdomain: str = Field(description="Subdomain hierarchy")
    path: str = Field(description="URL path hierarchy")
    tld: str = Field(description="Top-level domain")
    punycode_decoded: Optional[str] = Field(default=None, description="Decoded Unicode string if Punycode present")
    domain_tokens: List[str] = Field(default_factory=list, description="Individual lexical tokens from domain and subdomains")


class RepresentationSet(BaseModel):
    """Unified container for all 5 representations (R1 - R5) of a target webpage."""
    analysis_id: str = Field(description="Unique analysis tracking UUID")
    r1_raw: RawRepresentation = Field(description="R1: Raw DOM representation")
    r2_normalized: NormalizedRepresentation = Field(description="R2: Traceably normalized representation")
    r3_visual: VisualRepresentation = Field(description="R3: Visual / OCR representation")
    r4_semantic: SemanticRepresentation = Field(description="R4: Semantic intent representation")
    r5_url: URLRepresentation = Field(description="R5: Decomposed URL representation")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp of representation set creation"
    )


# ============================================================
# CRCE DISCREPANCY ENGINE MODELS (Phase 7)
# ============================================================

class DiscrepancyFinding(BaseModel):
    """Detailed evidence unit representing a single identified representation discrepancy."""
    source: str = Field(description="Source representation identifier (e.g., r1_raw, r2_normalized, r5_url)")
    target: str = Field(description="Target representation identifier (e.g., r2_normalized, r3_visual, target_brand)")
    discrepancy_type: str = Field(
        description="Type: character_mismatch, length_discrepancy, token_divergence, brand_domain_mismatch, invisible_char_discrepancy"
    )
    position: Optional[int] = Field(default=None, description="Character offset where discrepancy manifests")
    source_character: Optional[str] = Field(default=None, description="Character in source representation")
    target_character: Optional[str] = Field(default=None, description="Character in target representation")
    severity: float = Field(default=0.5, description="Discrepancy severity score between 0.0 and 1.0")
    supporting_evidence: str = Field(description="Technical explanation justifying the discrepancy evidence")


class CRCEResult(BaseModel):
    """Structured output of the Cross-Representation Discrepancy Engine."""
    # Pairwise Discrepancy Scores (0.0 to 1.0)
    raw_normalized_discrepancy: float = Field(
        default=0.0, 
        description="Divergence between R1 (Raw) and R2 (Normalized)"
    )
    raw_visual_discrepancy: float = Field(
        default=0.0, 
        description="Divergence between R1 (Raw DOM) and R3 (Visual OCR)"
    )
    normalized_visual_discrepancy: float = Field(
        default=0.0, 
        description="Divergence between R2 (Normalized) and R3 (Visual OCR)"
    )
    url_brand_discrepancy: float = Field(
        default=0.0, 
        description="Discrepancy between R5 (URL Domain) and detected brand claims"
    )
    unicode_anomaly_score: float = Field(
        default=0.0, 
        description="Synthesized score from Phase 4 Unicode analysis"
    )
    overall_discrepancy: float = Field(
        default=0.0, 
        description="Composite cross-representation discrepancy index (0.0 to 1.0)"
    )

    # Core Research Indicator: Visual Normalization Convergence
    # True if R1 != R2 and R1 != R3, but R2 == R3 (visual and normalized match, raw is obfuscated)
    visual_normalization_convergence: bool = Field(
        default=False,
        description="True if normalized text aligns with visual OCR while raw text diverges"
    )
    
    # Detailed granular discrepancy findings
    findings: List[DiscrepancyFinding] = Field(
        default_factory=list,
        description="Collection of specific discrepancy evidence items"
    )
    summary: str = Field(default="", description="Executive summary of cross-representation findings")


# ============================================================
# BASELINE CLASSIFIER & EXPERIMENT MODELS (Phase 8)
# ============================================================

class BaselinePrediction(BaseModel):
    """Output prediction and confidence from the baseline URL + HTML classifier."""
    is_phishing: bool = Field(description="Binary classification prediction")
    probability: float = Field(description="Predicted phishing probability score (0.0 to 1.0)")
    model_name: str = Field(description="Name of the underlying classifier model")
    feature_contributions: Dict[str, float] = Field(
        default_factory=dict,
        description="Top contributing feature importances or values"
    )


class EvaluationMetrics(BaseModel):
    """Standard evaluation metrics for academic reporting across experiments."""
    accuracy: float = Field(description="Proportion of true results: (TP + TN) / Total")
    precision: float = Field(description="Precision: TP / (TP + FP)")
    recall: float = Field(description="Recall / True Positive Rate: TP / (TP + FN)")
    f1_score: float = Field(description="Harmonic mean of precision and recall")
    roc_auc: Optional[float] = Field(default=None, description="Area Under the ROC Curve")
    false_positive_rate: float = Field(description="FPR / Fall-out: FP / (FP + TN)")
    false_negative_rate: float = Field(description="FNR / Miss rate: FN / (FN + TP)")
    confusion_matrix: List[List[int]] = Field(
        default_factory=list,
        description="Confusion matrix [[TN, FP], [FN, TP]]"
    )
    total_samples: int = Field(description="Total evaluation samples evaluated")
    evaluated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp of evaluation run"
    )


# ============================================================
# SLM DUAL-TASK MODELS (Phase 9)
# ============================================================

class SemanticRecoveryResult(BaseModel):
    """Task 1: Semantic recovery output identifying and reversing text obfuscation.
    
    Recovers canonical text from homoglyph substitutions, zero-width characters,
    leetspeak, and rendering discrepancies.
    """
    recovered_text: str = Field(description="Canonical recovered text string with obfuscation resolved")
    manipulation_detected: bool = Field(description="True if adversarial or evasive manipulation was discovered")
    manipulation_tactics: List[str] = Field(
        default_factory=list,
        description="Identified manipulation tactics (e.g. homoglyph_substitution, zero_width_insertion, leetspeak)"
    )
    recovery_explanation: str = Field(
        default="",
        description="Explanation detailing which tokens were reconstructed and why"
    )
    confidence_score: float = Field(
        default=1.0,
        description="Confidence score in the semantic recovery output (0.0 to 1.0)"
    )
    recovered_tokens_count: int = Field(
        default=0,
        description="Number of distinct tokens modified or recovered"
    )


class SLMEvidenceInput(BaseModel):
    """Structured evidence payload provided as input to the SLM Phishing Reasoning task (Task 2).
    
    Aggregates multi-representation findings, lexical URL metrics, CRCE discrepancy
    indicators, and credential vectors for structured LLM reasoning.
    """
    url: str = Field(description="Target analyzed URL")
    domain: str = Field(description="Extracted domain hostname")
    registered_domain: str = Field(description="Registrable domain (e.g. example.com)")
    page_title: Optional[str] = Field(default=None, description="Document title")
    visible_text_snippet: str = Field(default="", description="Sanitized excerpt of page visible text")
    recovered_text_snippet: Optional[str] = Field(
        default=None, 
        description="Recovered semantic text snippet from Task 1"
    )
    has_password_field: bool = Field(default=False, description="Presence of password/credential input fields")
    form_count: int = Field(default=0, description="Total number of web forms on page")
    detected_brands: List[str] = Field(default_factory=list, description="Brands claimed or referenced on page")
    url_risk_score: float = Field(default=0.0, description="Synthesized lexical URL risk score (0.0 to 1.0)")
    url_risk_reasons: List[str] = Field(default_factory=list, description="URL risk indicators flagged by Phase 3")
    unicode_anomaly_score: float = Field(default=0.0, description="Unicode anomaly score from Phase 4")
    crce_overall_discrepancy: float = Field(default=0.0, description="Overall cross-representation discrepancy score")
    visual_normalization_convergence: bool = Field(
        default=False,
        description="True if R1 diverges from R2 and R3 while R2 converges with R3 (classic evasion signature)"
    )
    discrepancy_findings_summary: List[str] = Field(
        default_factory=list,
        description="Summary list of CRCE discrepancy findings"
    )
    social_engineering_indicators: List[str] = Field(
        default_factory=list,
        description="Discovered urgency, fear, account suspension, or verify-credential triggers"
    )


class SLMReasoningResult(BaseModel):
    """Task 2: Structured phishing reasoning output from lightweight language model.
    
    Synthesizes representation discrepancies, URL context, credential vectors,
    and brand alignment to deliver explainable, audit-grade threat conclusions.
    """
    phishing_intent_detected: bool = Field(description="Whether the webpage exhibits malicious/phishing intent")
    risk_level: str = Field(
        description="Threat classification: LOW, MEDIUM, HIGH, or CRITICAL"
    )
    target_brand: Optional[str] = Field(
        default=None,
        description="Target brand identified as being impersonated or spoofed, if any"
    )
    confidence_score: float = Field(
        default=0.0,
        description="Model confidence score in threat determination (0.0 to 1.0)"
    )
    deception_techniques: List[str] = Field(
        default_factory=list,
        description="Deception techniques identified (e.g. brand_spoofing, credential_harvesting, homoglyph_evasion)"
    )
    inconsistency_analysis: str = Field(
        default="",
        description="Specific analysis of cross-representation discrepancies and semantic contradictions"
    )
    reasoning_summary: str = Field(
        default="",
        description="Structured, evidence-grounded research narrative explaining the conclusion"
    )
    recommended_action: str = Field(
        default="ALLOW",
        description="Recommended defensive posture: ALLOW, INSPECT_FURTHER, or BLOCK"
    )


class SLMDualTaskResult(BaseModel):
    """Unified container encapsulating both SLM tasks (Semantic Recovery + Phishing Reasoning)."""
    recovery: SemanticRecoveryResult = Field(description="Task 1: Semantic recovery output")
    reasoning: SLMReasoningResult = Field(description="Task 2: Phishing reasoning output")
    backend_used: str = Field(description="SLM backend engine utilized (mock, api, local)")
    model_name: str = Field(description="Name or identifier of the underlying language model")
    latency_ms: int = Field(default=0, description="Total execution latency in milliseconds")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp of SLM execution"
    )


# ============================================================
# EVIDENCE FUSION MODELS (Phase 10)
# ============================================================

class EvidenceFactor(BaseModel):
    """Granular contributing factor within the multi-source evidence fusion framework."""
    component: str = Field(description="Evidence vector identifier (e.g. brand_spoofing, crce_discrepancy)")
    raw_score: float = Field(description="Unweighted score normalized to [0.0, 1.0]")
    weight: float = Field(description="Configured importance weight for this dimension")
    weighted_score: float = Field(description="Raw score multiplied by weight")
    description: str = Field(description="Human-readable justification for this factor's contribution")


class FusedEvidence(BaseModel):
    """Structured output of the Deterministic Evidence Fusion Engine.
    
    Synthesizes multi-representation discrepancies, brand authenticity, credential
    seeking vectors, URL lexical metrics, and SLM reasoning into a unified,
    explainable composite threat assessment.
    """
    composite_threat_score: float = Field(
        description="Calibrated threat score from 0.0 (benign) to 1.0 (definitive malicious attack)"
    )
    vector_scores: Dict[str, float] = Field(
        default_factory=dict,
        description="Normalized component scores across all evidence dimensions"
    )
    evidence_weights: Dict[str, float] = Field(
        default_factory=dict,
        description="Importance weights utilized in this fusion calculation"
    )
    interaction_boost: float = Field(
        default=0.0,
        description="Non-linear synergistic boost applied when evasive discrepancies coincide with credential theft"
    )
    key_indicators: List[str] = Field(
        default_factory=list,
        description="High-salience security indicators discovered across webpage representations"
    )
    factors: List[EvidenceFactor] = Field(
        default_factory=list,
        description="Granular component breakdown explaining each factor's numerical contribution"
    )
    discrepancy_significant: bool = Field(
        default=False,
        description="True if cross-representation divergence exceeds significance threshold"
    )
    visual_normalization_convergence: bool = Field(
        default=False,
        description="Core research indicator: DOM text diverges while visual rendering converges with normalized form"
    )
    target_brand: Optional[str] = Field(
        default=None,
        description="Target brand identified as being impersonated or spoofed"
    )
    is_brand_mismatch: bool = Field(
        default=False,
        description="True if page claims a brand not authorized by the registered domain"
    )
    has_credential_seeking: bool = Field(
        default=False,
        description="True if page contains password inputs or credential entry forms"
    )
    fusion_rationale: str = Field(
        default="",
        description="Explainable narrative detailing the multi-source evidence synthesis"
    )
    fused_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp of evidence fusion calculation"
    )


# ============================================================
# DECISION ENGINE MODELS (Phase 11)
# ============================================================

class ThreatVerdict(str, Enum):
    """Operational security threat classification verdict."""
    SAFE = "SAFE"
    INVESTIGATE = "INVESTIGATE"
    PHISHING = "PHISHING"


class DefensiveAction(str, Enum):
    """Prescribed automated defensive posture response."""
    ALLOW = "ALLOW"
    WARN_USER = "WARN_USER"
    ISOLATE_SANDBOX = "ISOLATE_SANDBOX"
    BLOCK_ACCESS = "BLOCK_ACCESS"


class ThreatPosturePolicy(str, Enum):
    """Configurable organization security posture policy."""
    BALANCED = "balanced"
    STRICT = "strict"
    PERMISSIVE = "permissive"


class DecisionResult(BaseModel):
    """Final operational decision emitted by the RISE-Phish Decision Engine.
    
    Transforms continuous composite evidence into definitive policy-grounded
    verdicts with actionable defensive recommendations.
    """
    verdict: ThreatVerdict = Field(
        description="Primary security verdict: SAFE, INVESTIGATE, or PHISHING"
    )
    recommended_action: DefensiveAction = Field(
        description="Defensive posture: ALLOW, WARN_USER, ISOLATE_SANDBOX, or BLOCK_ACCESS"
    )
    composite_threat_score: float = Field(
        description="Calibrated threat score from Phase 10 evidence fusion (0.0 to 1.0)"
    )
    confidence_score: float = Field(
        description="Statistical confidence in verdict determination (0.0 to 1.0)"
    )
    policy_applied: ThreatPosturePolicy = Field(
        default=ThreatPosturePolicy.BALANCED,
        description="Security posture threshold policy evaluated"
    )
    policy_thresholds: Dict[str, float] = Field(
        default_factory=dict,
        description="Threshold cutoffs utilized for SAFE, INVESTIGATE, and PHISHING"
    )
    triggered_rules: List[str] = Field(
        default_factory=list,
        description="Deterministic security policy rules that were satisfied"
    )
    risk_reasons: List[str] = Field(
        default_factory=list,
        description="Executive risk factors justifying the verdict"
    )
    target_brand: Optional[str] = Field(
        default=None,
        description="Target brand identified as being impersonated or spoofed, if any"
    )
    decision_summary: str = Field(
        default="",
        description="Comprehensive explainable research narrative detailing the final verdict"
    )
    decided_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp of decision generation"
    )


# ============================================================
# EXPLANATION ENGINE MODELS (Phase 12)
# ============================================================

class UserAdvisory(BaseModel):
    """User-facing explainable security guidance for non-technical audiences."""
    headline: str = Field(description="High-level advisory headline (e.g. Danger: Phishing Site Detected)")
    status_level: str = Field(description="Advisory category: SAFE, CAUTION, or DANGER")
    summary: str = Field(description="Plain-English summary of the webpage's risk posture")
    bullet_points: List[str] = Field(
        default_factory=list,
        description="Clear, non-technical explanatory bullet points highlighting key observations"
    )
    action_advice: str = Field(
        description="Concrete, actionable safety guidance for the end-user"
    )


class DiscrepancyForensicSummary(BaseModel):
    """Forensic breakdown of cross-representation divergence for cybersecurity analysts."""
    pairwise_scores: Dict[str, float] = Field(
        default_factory=dict,
        description="Pairwise discrepancy metrics (R1 vs R2, R1 vs R3, R2 vs R3, R5 vs Brand)"
    )
    visual_normalization_convergence: bool = Field(
        default=False,
        description="True if normalized DOM text matches visual OCR while raw DOM text diverges"
    )
    evasion_signature_detected: bool = Field(
        default=False,
        description="True if discrepancy indicates intentional anti-analysis evasion"
    )
    top_findings: List[str] = Field(
        default_factory=list,
        description="Primary discrepancy findings discovered across representations"
    )


class AnalystForensicReport(BaseModel):
    """In-depth, auditable evidentiary report tailored for SOC analysts and researchers."""
    verdict: ThreatVerdict = Field(description="Operational security threat classification")
    recommended_action: DefensiveAction = Field(description="Prescribed automated posture response")
    composite_threat_score: float = Field(description="Fused composite threat rating from 0.0 to 1.0")
    confidence_score: float = Field(description="Statistical confidence in threat assessment")
    target_brand: Optional[str] = Field(default=None, description="Impersonated or spoofed brand name")
    registered_domain: str = Field(description="Registered domain parsed from address bar representation")
    discrepancy_forensics: DiscrepancyForensicSummary = Field(
        description="Forensic breakdown of cross-representation divergence"
    )
    unicode_anomalies_count: int = Field(default=0, description="Total count of flagged Unicode anomalies")
    key_unicode_findings: List[str] = Field(
        default_factory=list,
        description="Specific character and codepoint findings (homoglyphs, zero-width, bidi)"
    )
    credential_vectors: List[str] = Field(
        default_factory=list,
        description="Discovered password inputs, forms, and credential entry targets"
    )
    url_lexical_indicators: List[str] = Field(
        default_factory=list,
        description="URL risk indicators (subdomains, suspicious TLD, entropy, punycode)"
    )
    slm_recovery_summary: Optional[str] = Field(
        default=None,
        description="Task 1 Semantic Recovery findings and de-obfuscation tactics"
    )
    slm_reasoning_summary: Optional[str] = Field(
        default=None,
        description="Task 2 SLM Threat Reasoning narrative"
    )
    rules_triggered: List[str] = Field(
        default_factory=list,
        description="Deterministic security policy rules activated during decision evaluation"
    )
    contributing_factors: List[EvidenceFactor] = Field(
        default_factory=list,
        description="Detailed numerical breakdown of weighted evidence contributions"
    )


class ExplanationReport(BaseModel):
    """Unified container encapsulating both User Advisory and Analyst Forensic Report."""
    analysis_id: str = Field(description="Tracking UUID for the analyzed webpage")
    url: str = Field(description="Target analyzed URL")
    user_advisory: UserAdvisory = Field(description="User-facing plain-language security advisory")
    analyst_report: AnalystForensicReport = Field(description="Auditable evidentiary report for SOC analysts")
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp of explanation generation"
    )
