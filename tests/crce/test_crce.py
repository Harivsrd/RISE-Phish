"""Comprehensive test suite for Phase 7 CRCE v1 (Cross-Representation Discrepancy Engine).

Verifies:
- String similarity, Levenshtein NED, and Jaccard token metrics
- Legitimate webpage consistency across all layers (zero discrepancy)
- The core research contribution: Visual-Normalization Convergence
  (R1 != R2 and R1 != R3, but R2 == R3)
- Brand-to-domain mismatch and subdomain brand spoofing detection
- Graceful degradation when OCR visual evidence is unavailable
"""
import pytest
from backend.app.crce.brand_detector import (
    calculate_brand_domain_discrepancy,
    identify_claimed_brand,
)
from backend.app.crce.discrepancy import evaluate_discrepancies
from backend.app.crce.similarity import (
    calculate_normalized_edit_distance,
    calculate_token_jaccard_divergence,
    find_pairwise_character_mismatches,
)
from backend.app.models.schemas import (
    NormalizedRepresentation,
    RawRepresentation,
    RepresentationSet,
    SemanticRepresentation,
    UnicodeAnalysisResult,
    UnicodeAnomaly,
    URLRepresentation,
    VisualRepresentation,
)


def test_similarity_metrics():
    """Verify Normalized Edit Distance (NED) and Token Jaccard Divergence."""
    # Identical strings
    assert calculate_normalized_edit_distance("Microsoft", "Microsoft") == 0.0
    assert calculate_token_jaccard_divergence("Microsoft Account", "Microsoft Account") == 0.0

    # Completely disjoint
    assert calculate_normalized_edit_distance("ABC", "XYZ") == 1.0
    assert calculate_token_jaccard_divergence("Apple iPhone", "PayPal Payment") == 1.0

    # Single character difference ("Microsoft" vs Cyrillic "Mіcrosoft")
    ned = calculate_normalized_edit_distance("Microsoft", "M\u0456crosoft")
    assert ned > 0.0
    assert ned < 0.20


def test_find_pairwise_character_mismatches():
    """Verify granular character mismatch location and evidence generation."""
    s1 = "M\u0456crosoft"
    s2 = "Microsoft"
    findings = find_pairwise_character_mismatches(s1, s2, "r1_raw", "r2_normalized")

    assert len(findings) == 1
    f = findings[0]
    assert f.discrepancy_type == "character_mismatch"
    assert f.position == 1
    assert f.source_character == "\u0456"
    assert f.target_character == "i"
    assert "U+0456" in f.supporting_evidence


def test_brand_domain_discrepancy():
    """Verify brand detection and brand-to-domain mismatch scoring."""
    # 1. Legitimate domain match
    url_legit = URLRepresentation(
        raw_url="https://login.microsoft.com/auth",
        hostname="login.microsoft.com",
        registered_domain="microsoft.com",
        subdomain="login",
        path="/auth",
        tld="com",
        domain_tokens=["login", "microsoft", "com"],
    )
    score_legit, finding_legit = calculate_brand_domain_discrepancy("microsoft", url_legit)
    assert score_legit == 0.0
    assert finding_legit is None

    # 2. Subdomain brand spoofing
    url_spoofed = URLRepresentation(
        raw_url="https://paypal.security-verify.xyz/login",
        hostname="paypal.security-verify.xyz",
        registered_domain="security-verify.xyz",
        subdomain="paypal",
        path="/login",
        tld="xyz",
        domain_tokens=["paypal", "security", "verify", "xyz"],
    )
    score_spoofed, finding_spoofed = calculate_brand_domain_discrepancy("paypal", url_spoofed)
    assert score_spoofed >= 0.90
    assert finding_spoofed is not None
    assert "Severe Brand Impersonation" in finding_spoofed.supporting_evidence


def test_crce_legitimate_webpage_consistency():
    """Verify legitimate websites show minimal/zero discrepancy across all layers."""
    rep_set = RepresentationSet(
        analysis_id="legit-test-1",
        r1_raw=RawRepresentation(text="Welcome to Microsoft Official Support Portal", character_count=44),
        r2_normalized=NormalizedRepresentation(text="Welcome to Microsoft Official Support Portal", character_count=44),
        r3_visual=VisualRepresentation(text="Welcome to Microsoft Official Support Portal", available=True, confidence=95.0),
        r4_semantic=SemanticRepresentation(title="Microsoft Official Support", headings_text="Welcome"),
        r5_url=URLRepresentation(
            raw_url="https://support.microsoft.com/en-us",
            hostname="support.microsoft.com",
            registered_domain="microsoft.com",
            subdomain="support",
            path="/en-us",
            tld="com",
            domain_tokens=["support", "microsoft", "com"],
        ),
    )

    result = evaluate_discrepancies(rep_set)
    assert result.raw_normalized_discrepancy == 0.0
    assert result.raw_visual_discrepancy == 0.0
    assert result.url_brand_discrepancy == 0.0
    assert result.visual_normalization_convergence is False
    assert result.overall_discrepancy == 0.0
    assert len(result.findings) == 0


def test_crce_visual_normalization_convergence_obfuscation():
    """Verify the core research premise:
    
    Raw != Normalized
    Raw != OCR
    but:
    Normalized == OCR
    and URL != Brand -> Triggers Visual-Normalization Convergence and high discrepancy.
    """
    raw_text = "Sign in to your M\u0456crosoft Online Account"  # Cyrillic 'і'
    norm_text = "Sign in to your Microsoft Online Account"   # Normalized ASCII 'i'
    vis_text = "Sign in to your Microsoft Online Account"    # OCR visual reading

    rep_set = RepresentationSet(
        analysis_id="convergence-test-1",
        r1_raw=RawRepresentation(text=raw_text, character_count=len(raw_text)),
        r2_normalized=NormalizedRepresentation(
            text=norm_text,
            character_count=len(norm_text),
            transformations_applied=["nfkc_unicode_normalization"],
            characters_altered_count=1,
        ),
        r3_visual=VisualRepresentation(
            text=vis_text,
            available=True,
            confidence=94.0,
            words_count=6,
        ),
        r4_semantic=SemanticRepresentation(
            title="Microsoft Login",
            headings_text="Sign in to your Microsoft Account",
        ),
        r5_url=URLRepresentation(
            raw_url="https://secure-login-portal.xyz/auth",
            hostname="secure-login-portal.xyz",
            registered_domain="secure-login-portal.xyz",
            subdomain="",
            path="/auth",
            tld="xyz",
            domain_tokens=["secure", "login", "portal", "xyz"],
        ),
    )

    unicode_res = UnicodeAnalysisResult(
        total_characters=len(raw_text),
        non_ascii_characters=1,
        homoglyph_count=1,
        unicode_anomaly_score=0.85,
    )

    result = evaluate_discrepancies(rep_set, unicode_result=unicode_res)

    # 1. Verify pairwise discrepancies
    assert result.raw_normalized_discrepancy > 0.0
    assert result.raw_visual_discrepancy > 0.0
    assert result.normalized_visual_discrepancy == 0.0

    # 2. Confirm core research indicator: Visual-Normalization Convergence
    assert result.visual_normalization_convergence is True

    # 3. Confirm brand/domain mismatch against 'microsoft'
    assert result.url_brand_discrepancy >= 0.85

    # 4. Elevated overall discrepancy
    assert result.overall_discrepancy >= 0.70
    assert len(result.findings) >= 2


def test_crce_ocr_unavailable_graceful_handling():
    """Verify CRCE continues operating when OCR visual representation is unavailable."""
    rep_set = RepresentationSet(
        analysis_id="no-ocr-test",
        r1_raw=RawRepresentation(text="M\u0456crosoft Portal", character_count=16),
        r2_normalized=NormalizedRepresentation(
            text="Microsoft Portal",
            character_count=16,
            transformations_applied=["nfkc_unicode_normalization"],
            characters_altered_count=1,
        ),
        r3_visual=VisualRepresentation(
            text="",
            available=False,
            error_message="OCR unavailable",
        ),
        r4_semantic=SemanticRepresentation(title="Microsoft Portal"),
        r5_url=URLRepresentation(
            raw_url="https://microsoft-login.top/auth",
            hostname="microsoft-login.top",
            registered_domain="microsoft-login.top",
            subdomain="",
            path="/auth",
            tld="top",
            domain_tokens=["microsoft", "login", "top"],
        ),
    )

    result = evaluate_discrepancies(rep_set)

    # R3 visual divergence is zero since OCR was unavailable (no fabricated data)
    assert result.raw_visual_discrepancy == 0.0
    assert result.visual_normalization_convergence is False

    # But R1 vs R2 and URL vs Brand are still evaluated accurately!
    assert result.raw_normalized_discrepancy > 0.0
    assert result.url_brand_discrepancy >= 0.85
    assert result.overall_discrepancy > 0.30
