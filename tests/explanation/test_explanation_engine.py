"""Unit tests for RISE-Phish Explanation Engine (Phase 12).

Validates:
1. UserAdvisory generation (DANGER, CAUTION, SAFE status levels, bullet points, actionable guidance).
2. AnalystForensicReport generation (CRCE discrepancy forensics, Unicode codepoints, credential vectors, SLM logs).
3. End-to-end ExplanationReport orchestration and schema validity.
"""
from datetime import datetime, timezone
import pytest

from backend.app.explanation.explanation_engine import (
    ExplanationEngine,
    generate_explanation,
)
from backend.app.models.schemas import (
    AnalystForensicReport,
    CRCEResult,
    DecisionResult,
    DefensiveAction,
    DiscrepancyFinding,
    EvidenceFactor,
    ExplanationReport,
    FormInput,
    FormSummary,
    FusedEvidence,
    HTMLFeatures,
    NormalizedRepresentation,
    RawRepresentation,
    RepresentationSet,
    SemanticRecoveryResult,
    SemanticRepresentation,
    SLMDualTaskResult,
    SLMReasoningResult,
    ThreatPosturePolicy,
    ThreatVerdict,
    UnicodeAnalysisResult,
    UnicodeAnomaly,
    URLFeatures,
    URLRepresentation,
    UserAdvisory,
    VisualRepresentation,
)


def _build_test_context(
    verdict: ThreatVerdict = ThreatVerdict.PHISHING,
    score: float = 0.88,
    target_brand: str = "PayPal",
    is_brand_mismatch: bool = True,
    has_pwd: bool = True,
    convergence: bool = True,
):
    """Helper to assemble a synchronized test context across all upstream stages."""
    analysis_id = "test-analysis-uuid-1234"
    registered_domain = "paypal-security-update.xyz" if is_brand_mismatch else "paypal.com"
    raw_url = f"https://{registered_domain}/signin"

    rep_set = RepresentationSet(
        analysis_id=analysis_id,
        r1_raw=RawRepresentation(text="Sign in to P\u0456pay", character_count=16),
        r2_normalized=NormalizedRepresentation(text="Sign in to Pipay", character_count=16),
        r3_visual=VisualRepresentation(text="Sign in to Paypal", confidence=95.0),
        r4_semantic=SemanticRepresentation(
            title=f"{target_brand} Login",
            headings_text=f"{target_brand} Security",
            form_intent_summary="password credentials login" if has_pwd else "general",
        ),
        r5_url=URLRepresentation(
            raw_url=raw_url,
            hostname=registered_domain,
            registered_domain=registered_domain,
            subdomain="login",
            path="/signin",
            tld="xyz" if is_brand_mismatch else "com",
        ),
    )

    crce_result = CRCEResult(
        raw_normalized_discrepancy=0.65,
        raw_visual_discrepancy=0.85,
        normalized_visual_discrepancy=0.05,
        url_brand_discrepancy=0.95 if is_brand_mismatch else 0.0,
        overall_discrepancy=0.75,
        visual_normalization_convergence=convergence,
        findings=[
            DiscrepancyFinding(
                source="r1_raw",
                target="r3_visual",
                discrepancy_type="character_mismatch",
                severity=0.90,
                supporting_evidence="Homoglyph substitution detected between DOM and visual OCR",
            )
        ],
    )

    unicode_result = UnicodeAnalysisResult(
        total_characters=30,
        ascii_characters=29,
        non_ascii_characters=1,
        homoglyph_count=1,
        unicode_anomaly_score=0.70,
        anomalies=[
            UnicodeAnomaly(
                character="\u0456",
                codepoint="U+0456",
                codepoint_int=1110,
                name="CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I",
                category="Ll",
                script="Cyrillic",
                position=11,
                context_token="P\u0456pay",
                anomaly_type="homoglyph",
                normalized_nfkc="i",
                reason="Cross-script lookalike inside Latin token",
            )
        ],
    )

    url_features = URLFeatures(
        raw_url=raw_url,
        url_length=len(raw_url),
        scheme="https",
        hostname=registered_domain,
        registered_domain=registered_domain,
        subdomain="login",
        path="/signin",
        query="",
        tld="xyz" if is_brand_mismatch else "com",
        shannon_entropy=3.85,
        url_risk_score=0.75 if is_brand_mismatch else 0.05,
        risk_reasons=["excessive_subdomains", "suspicious_tld", "brand_in_subdomain"] if is_brand_mismatch else [],
    )

    html_features = HTMLFeatures(
        has_password_field=has_pwd,
        forms=[
            FormSummary(
                action="/api/auth",
                method="post",
                has_password=has_pwd,
                inputs=[
                    FormInput(input_type="text", name="username"),
                    FormInput(input_type="password", name="pwd", is_password=True),
                ] if has_pwd else [],
            )
        ],
        password_inputs=[FormInput(input_type="password", name="pwd", is_password=True)] if has_pwd else [],
    )

    slm_result = SLMDualTaskResult(
        recovery=SemanticRecoveryResult(
            recovered_text="Sign in to Paypal",
            manipulation_detected=True,
            manipulation_tactics=["homoglyph_substitution"],
            recovery_explanation="Reconstructed 'Paypal' from Cyrillic 'і' homoglyph.",
            recovered_tokens_count=1,
        ),
        reasoning=SLMReasoningResult(
            phishing_intent_detected=(verdict == ThreatVerdict.PHISHING),
            risk_level="CRITICAL" if verdict == ThreatVerdict.PHISHING else "LOW",
            target_brand=target_brand,
            confidence_score=0.94,
            deception_techniques=["brand_spoofing", "credential_harvesting", "homoglyph_evasion"],
            reasoning_summary="Adversarial credential harvester targeting PayPal users.",
        ),
        backend_used="mock",
        model_name="mock-oracle",
    )

    fused_evidence = FusedEvidence(
        composite_threat_score=score,
        vector_scores={"brand_spoofing": 1.0, "credential_harvesting": 1.0, "crce_discrepancy": 0.8},
        evidence_weights={"brand_spoofing": 0.25, "credential_harvesting": 0.20, "crce_discrepancy": 0.20},
        interaction_boost=0.25 if convergence else 0.0,
        key_indicators=["visual_normalization_convergence", "unauthorized_brand_spoofing"],
        factors=[
            EvidenceFactor(
                component="brand_spoofing",
                raw_score=1.0 if is_brand_mismatch else 0.0,
                weight=0.25,
                weighted_score=0.25 if is_brand_mismatch else 0.0,
                description=f"Brand spoofing targeting {target_brand}",
            ),
            EvidenceFactor(
                component="crce_discrepancy",
                raw_score=0.75,
                weight=0.20,
                weighted_score=0.15,
                description="Cross-representation discrepancy",
            ),
        ],
        discrepancy_significant=True,
        visual_normalization_convergence=convergence,
        target_brand=target_brand,
        is_brand_mismatch=is_brand_mismatch,
        has_credential_seeking=has_pwd,
        fusion_rationale="CRITICAL MALICIOUS THREAT: Multiple convergent evidence sources confirm attack.",
        fused_at=datetime.now(timezone.utc),
    )

    action = (
        DefensiveAction.BLOCK_ACCESS 
        if verdict == ThreatVerdict.PHISHING 
        else (DefensiveAction.WARN_USER if verdict == ThreatVerdict.INVESTIGATE else DefensiveAction.ALLOW)
    )

    decision = DecisionResult(
        verdict=verdict,
        recommended_action=action,
        composite_threat_score=score,
        confidence_score=0.95,
        policy_applied=ThreatPosturePolicy.BALANCED,
        policy_thresholds={"safe_ceiling": 0.35, "phishing_floor": 0.65},
        triggered_rules=["RULE-CRIT-01: Visual-Normalization Convergence Evasion"],
        risk_reasons=["Unauthorized brand impersonation", "Visual-Normalization convergence"],
        target_brand=target_brand,
        decision_summary=f"VERDICT: {verdict.value} under BALANCED policy.",
        decided_at=datetime.now(timezone.utc),
    )

    return (
        decision,
        fused_evidence,
        rep_set,
        crce_result,
        unicode_result,
        url_features,
        slm_result,
        html_features,
    )


def test_user_advisory_phishing_danger_status():
    """Validates that a phishing verdict produces DANGER status with clear user guidance."""
    decision, fused, rep_set, crce, uni, url_feat, slm, html = _build_test_context(
        verdict=ThreatVerdict.PHISHING,
        score=0.90,
        target_brand="PayPal",
        is_brand_mismatch=True,
        has_pwd=True,
        convergence=True,
    )

    engine = ExplanationEngine()
    advisory = engine.build_user_advisory(decision, fused, rep_set)

    assert isinstance(advisory, UserAdvisory)
    assert advisory.status_level == "DANGER"
    assert "PayPal" in advisory.headline
    assert "DO NOT enter passwords" in advisory.action_advice
    assert any("does not belong to PayPal" in b for b in advisory.bullet_points)
    assert any("lookalike characters" in b for b in advisory.bullet_points)


def test_user_advisory_investigate_caution_status():
    """Validates that an investigate verdict produces CAUTION status and safety checks."""
    decision, fused, rep_set, crce, uni, url_feat, slm, html = _build_test_context(
        verdict=ThreatVerdict.INVESTIGATE,
        score=0.48,
        target_brand=None,
        is_brand_mismatch=False,
        has_pwd=True,
        convergence=False,
    )

    engine = ExplanationEngine()
    advisory = engine.build_user_advisory(decision, fused, rep_set)

    assert advisory.status_level == "CAUTION"
    assert "Suspicious" in advisory.headline
    assert "double-check the web address" in advisory.action_advice
    assert any("login or password entry fields" in b for b in advisory.bullet_points)


def test_user_advisory_safe_status():
    """Validates that a safe verdict produces SAFE status with reassuring feedback."""
    decision, fused, rep_set, crce, uni, url_feat, slm, html = _build_test_context(
        verdict=ThreatVerdict.SAFE,
        score=0.08,
        target_brand="PayPal",
        is_brand_mismatch=False,
        has_pwd=False,
        convergence=False,
    )

    engine = ExplanationEngine()
    advisory = engine.build_user_advisory(decision, fused, rep_set)

    assert advisory.status_level == "SAFE"
    assert "Authentic Webpage" in advisory.headline
    assert "continue browsing normally" in advisory.action_advice
    assert any("matches the official, verified domain" in b for b in advisory.bullet_points)


def test_analyst_forensic_report_comprehensive_evidence():
    """Validates that the AnalystForensicReport contains exact technical evidence logs."""
    decision, fused, rep_set, crce, uni, url_feat, slm, html = _build_test_context(
        verdict=ThreatVerdict.PHISHING,
        score=0.92,
        target_brand="PayPal",
        is_brand_mismatch=True,
        has_pwd=True,
        convergence=True,
    )

    engine = ExplanationEngine()
    report = engine.build_analyst_report(
        decision=decision,
        fused_evidence=fused,
        rep_set=rep_set,
        crce_result=crce,
        unicode_result=uni,
        url_features=url_feat,
        slm_result=slm,
        html_features=html,
    )

    assert isinstance(report, AnalystForensicReport)
    assert report.verdict == ThreatVerdict.PHISHING
    assert report.recommended_action == DefensiveAction.BLOCK_ACCESS
    assert report.composite_threat_score == 0.92
    assert report.discrepancy_forensics.visual_normalization_convergence is True
    assert report.discrepancy_forensics.evasion_signature_detected is True
    assert report.discrepancy_forensics.pairwise_scores["r1_raw_vs_r3_visual"] == 0.85

    # Check Unicode forensics
    assert report.unicode_anomalies_count == 1
    assert any("U+0456" in f for f in report.key_unicode_findings)

    # Check Credential vectors
    assert any("password" in v.lower() for v in report.credential_vectors)

    # Check SLM summaries
    assert "homoglyph_substitution" in report.slm_recovery_summary
    assert "credential harvester" in report.slm_reasoning_summary.lower()

    # Check rules and factors
    assert "RULE-CRIT-01: Visual-Normalization Convergence Evasion" in report.rules_triggered
    assert len(report.contributing_factors) > 0


def test_generate_explanation_orchestration():
    """Validates the high-level generate_explanation wrapper produces a valid ExplanationReport."""
    decision, fused, rep_set, crce, uni, url_feat, slm, html = _build_test_context()

    explanation = generate_explanation(
        decision=decision,
        fused_evidence=fused,
        rep_set=rep_set,
        crce_result=crce,
        unicode_result=uni,
        url_features=url_feat,
        slm_result=slm,
        html_features=html,
    )

    assert isinstance(explanation, ExplanationReport)
    assert explanation.analysis_id == rep_set.analysis_id
    assert explanation.url == rep_set.r5_url.raw_url
    assert explanation.user_advisory.status_level == "DANGER"
    assert explanation.analyst_report.verdict == ThreatVerdict.PHISHING
    assert explanation.generated_at is not None
