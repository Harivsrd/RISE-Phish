"""Pydantic schemas and data contracts for RISE-Phish.
"""
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
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
