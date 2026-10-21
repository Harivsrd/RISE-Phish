"""Pydantic schemas and data contracts for RISE-Phish Browser Extension.

Defines the API contracts for message and email analysis, embedded link validation,
sender authenticity checks, and threat explainability.
"""
from datetime import datetime, timezone
from typing import Dict, List, Optional
from pydantic import BaseModel, Field

from backend.app.models.schemas import DefensiveAction, ThreatVerdict


class MessageEmbeddedLink(BaseModel):
    """An embedded hyperlink extracted from an email or message."""
    url: str = Field(..., description="Target hyperlink URL (href)")
    text: Optional[str] = Field(default="", description="Anchor text displayed to the victim")


class MessageAnalysisRequest(BaseModel):
    """Payload submitted by the browser extension to analyze an email or message."""
    subject: Optional[str] = Field(default="", description="Message subject line, when present")
    sender: Optional[str] = Field(default="", description="Sender display name or raw From string")
    sender_address: Optional[str] = Field(default="", description="Extracted sender email address")
    body_text: str = Field(..., description="Visible plain-text content of the message body")
    embedded_links: List[MessageEmbeddedLink] = Field(
        default_factory=list,
        description="List of hyperlinks found inside the message"
    )
    site_identifier: str = Field(
        default="gmail",
        description="Identifier of the origin website adapter (e.g., 'gmail', 'webmail')"
    )
    scan_mode: str = Field(
        default="auto",
        description="Scanning initiation mode ('auto' for page load, 'manual' for user click)"
    )
    allow_loopback_for_test: bool = Field(
        default=False,
        description="Internal flag to allow loopback resolution during automated test runs"
    )


class ExtractedLinkVerdict(BaseModel):
    """Forensic assessment of an individual embedded hyperlink."""
    url: str = Field(..., description="Evaluated destination URL")
    displayed_text: Optional[str] = Field(default="", description="Anchor text in message")
    is_mismatch: bool = Field(
        default=False,
        description="True if anchor text claimed a reputable domain while href directed elsewhere"
    )
    ssrf_blocked: bool = Field(
        default=False,
        description="True if the URL was blocked from crawling due to SSRF/internal IP restrictions"
    )
    verdict: ThreatVerdict = Field(
        default=ThreatVerdict.SAFE,
        description="Verdict for this specific URL: SAFE, INVESTIGATE, or PHISHING"
    )
    composite_threat_score: float = Field(
        default=0.0,
        description="Threat score for this URL [0.0, 1.0]"
    )
    target_brand: Optional[str] = Field(
        default=None,
        description="Identified brand targeted by the URL, if any"
    )
    finding_summary: str = Field(
        default="",
        description="Forensic observation explaining why this link was flagged or approved"
    )


class MessageIndicators(BaseModel):
    """High-salience phishing indicators extracted directly from the message content."""
    urgency_score: float = Field(
        default=0.0,
        description="Quantified urgency and coercive psychological manipulation score [0.0, 1.0]"
    )
    urgency_triggers_found: List[str] = Field(
        default_factory=list,
        description="Specific urgency or fear tokens discovered in subject and body"
    )
    sender_discrepancy_detected: bool = Field(
        default=False,
        description="True if sender display name mimics a brand but sender domain differs"
    )
    sender_finding: Optional[str] = Field(
        default=None,
        description="Detailed explanation of sender brand mismatch"
    )
    link_text_mismatches_count: int = Field(
        default=0,
        description="Count of links where displayed text contradicts the underlying href"
    )
    homoglyphs_detected_count: int = Field(
        default=0,
        description="Count of suspicious non-ASCII homoglyphs found in sender or message body"
    )
    homoglyph_samples: List[str] = Field(
        default_factory=list,
        description="Samples of identified homoglyph tokens"
    )
    prompt_injection_flags: List[str] = Field(
        default_factory=list,
        description="Adversarial prompt injection attempts detected in message body"
    )


class MessageAnalysisResponse(BaseModel):
    """Unified security analysis response returned to the browser extension."""
    analysis_id: str = Field(..., description="Unique tracking identifier for this message scan")
    verdict: ThreatVerdict = Field(..., description="Overall operational verdict: SAFE, INVESTIGATE, PHISHING")
    composite_threat_score: float = Field(
        ...,
        description="Composite threat score normalized between 0.0 (safe) and 1.0 (phishing)"
    )
    confidence_score: float = Field(
        default=0.90,
        description="Calibrated system confidence score [0.0, 1.0]"
    )
    recommended_action: DefensiveAction = Field(
        ...,
        description="Recommended defensive posture: ALLOW, WARN_USER, ISOLATE_SANDBOX, or BLOCK_ACCESS"
    )
    site_identifier: str = Field(default="gmail", description="Origin platform of the message")
    indicators: MessageIndicators = Field(
        default_factory=MessageIndicators,
        description="Message-level linguistic, sender, and heuristic indicators"
    )
    link_analyses: List[ExtractedLinkVerdict] = Field(
        default_factory=list,
        description="Forensic analysis results for each extracted embedded URL"
    )
    summary_headline: str = Field(
        ...,
        description="Concise warning headline suitable for badge and banner display"
    )
    explanation: str = Field(
        ...,
        description="User-friendly explanation of why the message received this classification"
    )
    key_findings: List[str] = Field(
        default_factory=list,
        description="List of bullet points outlining the primary security risks"
    )
    privacy_notice: str = Field(
        default="Zero raw message content is permanently stored. Analysis was performed ephemerally.",
        description="Privacy confirmation notice"
    )
    analyzed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC completion timestamp"
    )


class ExtensionHealthResponse(BaseModel):
    """Health and status check schema tailored for the browser extension."""
    status: str = Field(default="ok", description="Service status")
    extension_api_version: str = Field(default="0.2.0", description="Extension API version")
    supported_sites: List[str] = Field(
        default_factory=lambda: ["mail.google.com"],
        description="Domains officially supported by extraction adapters"
    )
    ssrf_protection_active: bool = Field(default=True, description="Whether SSRF filters are active")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Current server timestamp"
    )
