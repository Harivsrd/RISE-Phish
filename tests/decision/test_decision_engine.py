"""Unit tests for RISE-Phish Decision Engine (Phase 11).

Validates:
1. Operational verdict generation (SAFE, INVESTIGATE, PHISHING).
2. Actionable posture mapping (ALLOW, WARN_USER, ISOLATE_SANDBOX, BLOCK_ACCESS).
3. Security posture policy calibration (BALANCED, STRICT, PERMISSIVE).
4. Deterministic security rule overrides (Convergence Evasion, Canonical Whitelist, Credential Guard).
5. Statistical confidence calibration and schema adherence.
"""
from datetime import datetime, timezone
import pytest

from backend.app.decision.risk import (
    POLICY_THRESHOLDS,
    DecisionEngine,
    evaluate_decision,
)
from backend.app.models.schemas import (
    DecisionResult,
    DefensiveAction,
    EvidenceFactor,
    FusedEvidence,
    ThreatPosturePolicy,
    ThreatVerdict,
)


def _build_dummy_fused_evidence(
    composite_score: float = 0.10,
    target_brand: str = None,
    is_brand_mismatch: bool = False,
    has_credential_seeking: bool = False,
    visual_convergence: bool = False,
    is_whitelisted: bool = False,
) -> FusedEvidence:
    """Helper to synthesize a test FusedEvidence instance."""
    rationale = "VERIFIED BENIGN: Webpage belongs to authorized domain." if is_whitelisted else "Standard test evidence."
    return FusedEvidence(
        composite_threat_score=composite_score,
        vector_scores={
            "brand_spoofing": 1.0 if is_brand_mismatch else 0.0,
            "credential_harvesting": 1.0 if has_credential_seeking else 0.0,
            "crce_discrepancy": 0.8 if visual_convergence else 0.1,
            "slm_reasoning": composite_score,
            "url_risk": composite_score,
            "unicode_anomaly": 0.0,
            "social_engineering": 0.0,
        },
        evidence_weights={
            "brand_spoofing": 0.25,
            "credential_harvesting": 0.20,
            "crce_discrepancy": 0.20,
            "slm_reasoning": 0.15,
            "url_risk": 0.10,
            "unicode_anomaly": 0.05,
            "social_engineering": 0.05,
        },
        interaction_boost=0.25 if (visual_convergence and is_brand_mismatch) else 0.0,
        key_indicators=["visual_normalization_convergence"] if visual_convergence else [],
        factors=[
            EvidenceFactor(
                component="brand_spoofing",
                raw_score=1.0 if is_brand_mismatch else 0.0,
                weight=0.25,
                weighted_score=0.25 if is_brand_mismatch else 0.0,
                description="Brand test factor",
            )
        ],
        discrepancy_significant=visual_convergence,
        visual_normalization_convergence=visual_convergence,
        target_brand=target_brand,
        is_brand_mismatch=is_brand_mismatch,
        has_credential_seeking=has_credential_seeking,
        fusion_rationale=rationale,
        fused_at=datetime.now(timezone.utc),
    )


def test_decision_engine_phishing_verdict_balanced_policy():
    """Validates that a high threat score triggers PHISHING and BLOCK_ACCESS under BALANCED policy."""
    evidence = _build_dummy_fused_evidence(
        composite_score=0.85,
        target_brand="PayPal",
        is_brand_mismatch=True,
        has_credential_seeking=True,
    )

    decision = evaluate_decision(evidence, policy=ThreatPosturePolicy.BALANCED)

    assert isinstance(decision, DecisionResult)
    assert decision.verdict == ThreatVerdict.PHISHING
    assert decision.recommended_action == DefensiveAction.BLOCK_ACCESS
    assert decision.policy_applied == ThreatPosturePolicy.BALANCED
    assert decision.confidence_score >= 0.85
    assert "BLOCK_ACCESS" in decision.decision_summary


def test_decision_engine_investigate_verdict_balanced_policy():
    """Validates that an intermediate score produces INVESTIGATE and WARN_USER."""
    evidence = _build_dummy_fused_evidence(
        composite_score=0.50,
        target_brand=None,
        is_brand_mismatch=False,
        has_credential_seeking=False,
    )

    decision = evaluate_decision(evidence, policy=ThreatPosturePolicy.BALANCED)

    assert decision.verdict == ThreatVerdict.INVESTIGATE
    assert decision.recommended_action == DefensiveAction.WARN_USER
    assert decision.confidence_score >= 0.70
    assert "WARN_USER" in decision.decision_summary


def test_decision_engine_safe_verdict_balanced_policy():
    """Validates that a low threat score without credential inputs produces SAFE and ALLOW."""
    evidence = _build_dummy_fused_evidence(
        composite_score=0.10,
        target_brand=None,
        is_brand_mismatch=False,
        has_credential_seeking=False,
    )

    decision = evaluate_decision(evidence, policy=ThreatPosturePolicy.BALANCED)

    assert decision.verdict == ThreatVerdict.SAFE
    assert decision.recommended_action == DefensiveAction.ALLOW
    assert decision.confidence_score >= 0.85
    assert "ALLOW" in decision.decision_summary


def test_decision_engine_strict_policy_behavior():
    """Validates that the STRICT policy lowers thresholds and recommends ISOLATE_SANDBOX for investigation."""
    # Score 0.55 is INVESTIGATE in Balanced (0.35 - 0.65), but PHISHING in Strict (>= 0.50)
    evidence = _build_dummy_fused_evidence(composite_score=0.55)

    decision_strict = evaluate_decision(evidence, policy=ThreatPosturePolicy.STRICT)
    assert decision_strict.verdict == ThreatVerdict.PHISHING
    assert decision_strict.recommended_action == DefensiveAction.BLOCK_ACCESS

    # Score 0.30 is SAFE in Balanced (< 0.35), but INVESTIGATE in Strict (0.20 - 0.50)
    evidence_mild = _build_dummy_fused_evidence(composite_score=0.30)
    decision_mild = evaluate_decision(evidence_mild, policy=ThreatPosturePolicy.STRICT)
    assert decision_mild.verdict == ThreatVerdict.INVESTIGATE
    assert decision_mild.recommended_action == DefensiveAction.ISOLATE_SANDBOX


def test_decision_engine_permissive_policy_behavior():
    """Validates that the PERMISSIVE policy requires higher threat certainty before declaring PHISHING."""
    # Score 0.70 is PHISHING in Balanced (>= 0.65), but INVESTIGATE in Permissive (< 0.75)
    evidence = _build_dummy_fused_evidence(composite_score=0.70)

    decision_perm = evaluate_decision(evidence, policy=ThreatPosturePolicy.PERMISSIVE)
    assert decision_perm.verdict == ThreatVerdict.INVESTIGATE
    assert decision_perm.recommended_action == DefensiveAction.WARN_USER


def test_decision_engine_override_crit_01_convergence_evasion():
    """Validates Rule CRIT-01: Visual-Normalization Convergence on spoofed brand overrides score to PHISHING."""
    evidence = _build_dummy_fused_evidence(
        composite_score=0.30,  # Marginal base score
        target_brand="Microsoft",
        is_brand_mismatch=True,
        visual_convergence=True,
    )

    decision = evaluate_decision(evidence, policy=ThreatPosturePolicy.BALANCED)

    assert decision.verdict == ThreatVerdict.PHISHING
    assert decision.recommended_action == DefensiveAction.BLOCK_ACCESS
    assert any("RULE-CRIT-01" in r for r in decision.triggered_rules)
    assert decision.confidence_score >= 0.95


def test_decision_engine_override_safe_01_whitelisted_canonical_domain():
    """Validates Rule SAFE-01: Canonical authorized brand domain forces SAFE regardless of sub-scores."""
    evidence = _build_dummy_fused_evidence(
        composite_score=0.15,
        target_brand="PayPal",
        is_brand_mismatch=False,
        has_credential_seeking=True,  # Login form on official paypal.com
        is_whitelisted=True,
    )

    decision = evaluate_decision(evidence, policy=ThreatPosturePolicy.BALANCED)

    assert decision.verdict == ThreatVerdict.SAFE
    assert decision.recommended_action == DefensiveAction.ALLOW
    assert any("RULE-SAFE-01" in r for r in decision.triggered_rules)
    assert decision.confidence_score >= 0.95


def test_decision_engine_override_inv_01_unverified_credentials_guard():
    """Validates Rule INV-01: Soliciting credentials on an unverified domain elevates a SAFE score to INVESTIGATE."""
    evidence = _build_dummy_fused_evidence(
        composite_score=0.18,  # Below safe threshold
        target_brand=None,
        is_brand_mismatch=False,
        has_credential_seeking=True,  # Password field on random unknown domain
        is_whitelisted=False,
    )

    decision = evaluate_decision(evidence, policy=ThreatPosturePolicy.BALANCED)

    assert decision.verdict == ThreatVerdict.INVESTIGATE
    assert decision.recommended_action == DefensiveAction.WARN_USER
    assert any("RULE-INV-01" in r for r in decision.triggered_rules)


def test_decision_engine_confidence_bounds_and_structure():
    """Validates that confidence scores are strictly within [0.0, 1.0] and fields are populated."""
    for score in [0.0, 0.25, 0.35, 0.50, 0.65, 0.85, 1.0]:
        evidence = _build_dummy_fused_evidence(composite_score=score)
        decision = evaluate_decision(evidence)
        assert 0.0 <= decision.confidence_score <= 1.0
        assert decision.decided_at is not None
        assert len(decision.policy_thresholds) == 2
