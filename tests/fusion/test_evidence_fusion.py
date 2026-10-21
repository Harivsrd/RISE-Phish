"""Unit tests for RISE-Phish Evidence Fusion Engine (Phase 10).

Validates:
1. Multi-source evidence synthesis across URL, HTML, Unicode, CRCE, and SLM.
2. Synergistic interaction boosts (Visual-Normalization Convergence on spoofed brands).
3. Legitimate domain safety guard (dampening threat scores on authentic brand domains).
4. Discrepancy-alone safety (zero false positives on benign rendering variance).
5. Explainable factor breakdown and schema validity.
"""
import pytest

from backend.app.fusion.evidence_fusion import (
    DEFAULT_FUSION_WEIGHTS,
    EvidenceFusionEngine,
    fuse_evidence,
)
from backend.app.models.schemas import (
    CRCEResult,
    DiscrepancyFinding,
    FusedEvidence,
    HTMLFeatures,
    NormalizedRepresentation,
    RawRepresentation,
    RepresentationSet,
    SemanticRecoveryResult,
    SemanticRepresentation,
    SLMDualTaskResult,
    SLMReasoningResult,
    UnicodeAnalysisResult,
    URLFeatures,
    URLRepresentation,
    VisualRepresentation,
)


def _build_dummy_rep_set(
    title: str = "Test Title",
    raw_text: str = "Raw text content",
    registered_domain: str = "example.com",
    has_pwd: bool = False,
) -> RepresentationSet:
    """Helper to construct a mock RepresentationSet for fusion tests."""
    return RepresentationSet(
        analysis_id="test-rep-id",
        r1_raw=RawRepresentation(text=raw_text, character_count=len(raw_text)),
        r2_normalized=NormalizedRepresentation(text=raw_text, character_count=len(raw_text)),
        r3_visual=VisualRepresentation(text=raw_text, confidence=90.0),
        r4_semantic=SemanticRepresentation(
            title=title,
            headings_text=title,
            form_intent_summary="password credentials login" if has_pwd else "general info",
        ),
        r5_url=URLRepresentation(
            raw_url=f"https://{registered_domain}/login",
            hostname=registered_domain,
            registered_domain=registered_domain,
            subdomain="",
            path="/login",
            tld="com",
        ),
    )


def test_evidence_fusion_weights_normalization():
    """Validates that non-normalized custom weights are normalized to sum to 1.0."""
    unnormalized_weights = {
        "brand_spoofing": 5.0,
        "credential_harvesting": 5.0,
        "crce_discrepancy": 5.0,
        "slm_reasoning": 5.0,
        "url_risk": 0.0,
        "unicode_anomaly": 0.0,
        "social_engineering": 0.0,
    }
    engine = EvidenceFusionEngine(weights=unnormalized_weights)
    assert sum(engine.weights.values()) == pytest.approx(1.0, rel=1e-3)
    assert engine.weights["brand_spoofing"] == pytest.approx(0.25, rel=1e-3)


def test_evidence_fusion_critical_phishing_with_evasion_synergy():
    """Validates that brand spoofing + password collection + Visual-Normalization Convergence
    triggers a high composite threat score with an evasion synergy boost.
    """
    url_feat = URLFeatures(
        raw_url="https://verify.paypal-security-auth.xyz/signin",
        url_length=47,
        scheme="https",
        hostname="verify.paypal-security-auth.xyz",
        registered_domain="paypal-security-auth.xyz",
        subdomain="verify",
        path="/signin",
        query="",
        tld="xyz",
        url_risk_score=0.85,
        risk_reasons=["excessive_subdomains", "suspicious_tld", "brand_in_subdomain"],
    )

    crce_res = CRCEResult(
        raw_normalized_discrepancy=0.75,
        raw_visual_discrepancy=0.80,
        normalized_visual_discrepancy=0.02,
        url_brand_discrepancy=0.95,
        overall_discrepancy=0.85,
        visual_normalization_convergence=True,
        findings=[
            DiscrepancyFinding(
                source="r1_raw",
                target="r3_visual",
                discrepancy_type="character_mismatch",
                severity=0.90,
                supporting_evidence="Homoglyph substitution in brand token",
            )
        ],
    )

    rep_set = _build_dummy_rep_set(
        title="PayPal - Security Verification",
        raw_text="Please sign in to PayPal to restore your suspended account",
        registered_domain="paypal-security-auth.xyz",
        has_pwd=True,
    )

    slm_res = SLMDualTaskResult(
        recovery=SemanticRecoveryResult(
            recovered_text="PayPal Security",
            manipulation_detected=True,
            manipulation_tactics=["homoglyph_substitution"],
        ),
        reasoning=SLMReasoningResult(
            phishing_intent_detected=True,
            risk_level="CRITICAL",
            target_brand="PayPal",
            confidence_score=0.95,
            deception_techniques=["brand_spoofing", "credential_harvesting", "visual_evasion"],
        ),
        backend_used="mock",
        model_name="mock-oracle",
    )

    fused = fuse_evidence(
        url_features=url_feat,
        crce_result=crce_res,
        rep_set=rep_set,
        slm_result=slm_res,
        has_password_field=True,
    )

    assert isinstance(fused, FusedEvidence)
    assert fused.composite_threat_score >= 0.85
    assert fused.interaction_boost > 0.0
    assert fused.visual_normalization_convergence is True
    assert fused.is_brand_mismatch is True
    assert fused.has_credential_seeking is True
    assert "visual_normalization_convergence" in fused.key_indicators
    assert "CRITICAL MALICIOUS THREAT" in fused.fusion_rationale


def test_evidence_fusion_legitimate_brand_safety_guard():
    """Validates that authentic canonical brand domains (e.g., paypal.com) are protected
    from false alarms by the safety guard, even with password login forms.
    """
    url_feat = URLFeatures(
        raw_url="https://www.paypal.com/signin",
        url_length=30,
        scheme="https",
        hostname="www.paypal.com",
        registered_domain="paypal.com",
        subdomain="www",
        path="/signin",
        query="",
        tld="com",
        url_risk_score=0.0,
        risk_reasons=[],
    )

    crce_res = CRCEResult(
        raw_normalized_discrepancy=0.0,
        raw_visual_discrepancy=0.02,
        normalized_visual_discrepancy=0.02,
        url_brand_discrepancy=0.0,
        overall_discrepancy=0.02,
        visual_normalization_convergence=False,
    )

    rep_set = _build_dummy_rep_set(
        title="Log in to your PayPal account",
        raw_text="Log in to your PayPal account to manage payments",
        registered_domain="paypal.com",
        has_pwd=True,
    )

    slm_res = SLMDualTaskResult(
        recovery=SemanticRecoveryResult(
            recovered_text="PayPal",
            manipulation_detected=False,
        ),
        reasoning=SLMReasoningResult(
            phishing_intent_detected=False,
            risk_level="LOW",
            target_brand="PayPal",
            confidence_score=0.90,
            recommended_action="ALLOW",
        ),
        backend_used="mock",
        model_name="mock-oracle",
    )

    fused = fuse_evidence(
        url_features=url_feat,
        crce_result=crce_res,
        rep_set=rep_set,
        slm_result=slm_res,
        has_password_field=True,
    )

    # Legitimate safety guard must keep threat score low
    assert fused.composite_threat_score <= 0.15
    assert fused.is_brand_mismatch is False
    assert "VERIFIED BENIGN" in fused.fusion_rationale


def test_evidence_fusion_discrepancy_alone_not_phishing():
    """Core research validation: Discrepancy by itself without brand spoofing or credential
    harvesting does NOT result in a high threat score.
    """
    url_feat = URLFeatures(
        raw_url="https://www.universite-paris.fr/recherche",
        url_length=42,
        scheme="https",
        hostname="www.universite-paris.fr",
        registered_domain="universite-paris.fr",
        subdomain="www",
        path="/recherche",
        query="",
        tld="fr",
        url_risk_score=0.0,
        risk_reasons=[],
    )

    # Moderate rendering/OCR font discrepancy on legitimate French academic text
    crce_res = CRCEResult(
        raw_normalized_discrepancy=0.10,
        raw_visual_discrepancy=0.55,
        normalized_visual_discrepancy=0.52,
        url_brand_discrepancy=0.0,
        overall_discrepancy=0.50,
        visual_normalization_convergence=False,
    )

    unicode_res = UnicodeAnalysisResult(
        total_characters=150,
        ascii_characters=135,
        non_ascii_characters=15,
        unicode_anomaly_score=0.10,  # Accents
    )

    rep_set = _build_dummy_rep_set(
        title="Recherche scientifique et publications",
        raw_text="Département des sciences informatiques et modélisation avancée",
        registered_domain="universite-paris.fr",
        has_pwd=False,
    )

    fused = fuse_evidence(
        url_features=url_feat,
        unicode_result=unicode_res,
        crce_result=crce_res,
        rep_set=rep_set,
        has_password_field=False,
    )

    # Discrepancy alone must NOT push score into suspicious or phishing zone
    assert fused.composite_threat_score <= 0.25
    assert fused.is_brand_mismatch is False
    assert fused.has_credential_seeking is False
    assert "BENIGN/LOW RISK" in fused.fusion_rationale


def test_evidence_fusion_credential_harvesting_without_brand():
    """Validates that a generic login form on an unknown domain produces a moderate,
    non-critical score without triggering evasion synergy boosts.
    """
    url_feat = URLFeatures(
        raw_url="https://portal.mycompany-intranet.com/login",
        url_length=43,
        scheme="https",
        hostname="portal.mycompany-intranet.com",
        registered_domain="mycompany-intranet.com",
        subdomain="portal",
        path="/login",
        query="",
        tld="com",
        url_risk_score=0.10,
        risk_reasons=[],
    )

    rep_set = _build_dummy_rep_set(
        title="Employee Portal Login",
        raw_text="Enter your employee ID and password to access the internal dashboard.",
        registered_domain="mycompany-intranet.com",
        has_pwd=True,
    )

    fused = fuse_evidence(
        url_features=url_feat,
        rep_set=rep_set,
        has_password_field=True,
    )

    # Has credential field (+0.20), but no brand mismatch and no convergence boost
    assert 0.15 <= fused.composite_threat_score <= 0.40
    assert fused.interaction_boost == 0.0
    assert fused.is_brand_mismatch is False
    assert fused.has_credential_seeking is True


def test_evidence_fusion_social_engineering_detection():
    """Validates that social engineering cues raise the social_engineering vector score."""
    rep_set = _build_dummy_rep_set(
        title="Urgent Security Alert: Account Suspended",
        raw_text="Immediate attention required! Verify your account credentials to avoid permanent closure.",
        registered_domain="account-resolve-service.com",
        has_pwd=True,
    )

    fused = fuse_evidence(rep_set=rep_set, has_password_field=True)

    assert fused.vector_scores["social_engineering"] >= 0.60
    assert "social_engineering_triggers_present" in fused.key_indicators


def test_evidence_fusion_slm_reasoning_contribution():
    """Validates that SLM risk level and confidence modulate the slm_reasoning factor."""
    slm_res = SLMDualTaskResult(
        recovery=SemanticRecoveryResult(recovered_text="Clean text", manipulation_detected=False),
        reasoning=SLMReasoningResult(
            phishing_intent_detected=True,
            risk_level="HIGH",  # 0.80 base
            confidence_score=0.90,  # 0.80 * 0.90 = 0.72 raw
            reasoning_summary="Suspicious credential portal targeting bank customers.",
        ),
        backend_used="mock",
        model_name="mock-oracle",
    )

    fused = fuse_evidence(slm_result=slm_res)

    assert fused.vector_scores["slm_reasoning"] == pytest.approx(0.72, rel=1e-2)
    slm_factor = next(f for f in fused.factors if f.component == "slm_reasoning")
    assert slm_factor.weighted_score == pytest.approx(0.72 * DEFAULT_FUSION_WEIGHTS["slm_reasoning"], rel=1e-2)


def test_evidence_fusion_html_features_direct_extraction():
    """Validates that HTMLFeatures forms and password fields are correctly extracted."""
    html_feat = HTMLFeatures(
        has_password_field=True,
        visible_text="Login to your internal company account",
    )

    fused = fuse_evidence(html_features=html_feat)

    assert fused.has_credential_seeking is True
    assert fused.vector_scores["credential_harvesting"] == 1.0


def test_evidence_fusion_empty_inputs_graceful_handling():
    """Validates that calling fuse_evidence with zero arguments returns a valid zero-threat FusedEvidence."""
    fused = fuse_evidence()

    assert isinstance(fused, FusedEvidence)
    assert fused.composite_threat_score == 0.0
    assert fused.is_brand_mismatch is False
    assert fused.has_credential_seeking is False
    assert fused.interaction_boost == 0.0
    assert len(fused.factors) == 7
