"""Pydantic schemas and data contracts for RISE-Phish.
"""
from datetime import datetime, timezone
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
