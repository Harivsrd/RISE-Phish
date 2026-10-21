"""Decision Engine and Threat Posture Calibration module for RISE-Phish.

Translates continuous composite threat scores and structured evidence from
Phase 10 (FusedEvidence) into auditable operational verdicts:
- SAFE: Benign, verified authentic domains, or non-malicious localized content.
- INVESTIGATE: Ambiguous signals, unverified credential entry, or moderate discrepancy.
- PHISHING: Confirmed adversarial attacks, brand spoofing, or evasion convergence.
"""
from datetime import datetime, timezone
import logging
from typing import Dict, List, Optional, Tuple

from backend.app.models.schemas import (
    DecisionResult,
    DefensiveAction,
    FusedEvidence,
    ThreatPosturePolicy,
    ThreatVerdict,
)

logger = logging.getLogger("rise_phish.decision")

# Calibrated policy threshold cutoffs: {policy: (safe_ceiling, phishing_floor)}
POLICY_THRESHOLDS: Dict[ThreatPosturePolicy, Tuple[float, float]] = {
    ThreatPosturePolicy.BALANCED: (0.35, 0.65),
    ThreatPosturePolicy.STRICT: (0.20, 0.50),
    ThreatPosturePolicy.PERMISSIVE: (0.45, 0.75),
}


class DecisionEngine:
    """Evaluates fused security evidence against calibrated policy thresholds and rules."""

    def __init__(
        self,
        default_policy: ThreatPosturePolicy = ThreatPosturePolicy.BALANCED,
        custom_thresholds: Optional[Dict[ThreatPosturePolicy, Tuple[float, float]]] = None,
    ) -> None:
        self.default_policy = default_policy
        self.thresholds = custom_thresholds or dict(POLICY_THRESHOLDS)

    def evaluate(
        self,
        fused_evidence: FusedEvidence,
        policy: Optional[ThreatPosturePolicy] = None,
    ) -> DecisionResult:
        """Evaluates fused evidence to produce an operational security decision.
        
        Args:
            fused_evidence: Synthesized multi-representation evidence from Phase 10.
            policy: Threat posture policy (BALANCED, STRICT, PERMISSIVE). Defaults to engine policy.
            
        Returns:
            DecisionResult adhering to RISE-Phish data contract.
        """
        active_policy = policy or self.default_policy
        safe_cutoff, phish_cutoff = self.thresholds.get(
            active_policy, 
            POLICY_THRESHOLDS[ThreatPosturePolicy.BALANCED]
        )

        score = fused_evidence.composite_threat_score
        triggered_rules: List[str] = []
        risk_reasons: List[str] = []

        # -------------------------------------------------------------
        # Step 1: Base Threshold Classification
        # -------------------------------------------------------------
        if score >= phish_cutoff:
            verdict = ThreatVerdict.PHISHING
            action = DefensiveAction.BLOCK_ACCESS
        elif score >= safe_cutoff:
            verdict = ThreatVerdict.INVESTIGATE
            action = (
                DefensiveAction.ISOLATE_SANDBOX 
                if active_policy == ThreatPosturePolicy.STRICT 
                else DefensiveAction.WARN_USER
            )
        else:
            verdict = ThreatVerdict.SAFE
            action = DefensiveAction.ALLOW

        # -------------------------------------------------------------
        # Step 2: Deterministic Rule Overrides (High-Certainty Signatures)
        # -------------------------------------------------------------
        is_whitelisted = "VERIFIED BENIGN" in fused_evidence.fusion_rationale

        # Rule SAFE-01: Verified canonical domain guard
        if is_whitelisted:
            verdict = ThreatVerdict.SAFE
            action = DefensiveAction.ALLOW
            rule_id = "RULE-SAFE-01: Verified Canonical Domain Guard"
            triggered_rules.append(rule_id)
            risk_reasons.append(
                f"Domain is verified as official canonical infrastructure for '{fused_evidence.target_brand}'. "
                "Any localized representation differences are classified as benign."
            )

        # Rule CRIT-01: Visual-Normalization Convergence on spoofed brand
        elif fused_evidence.visual_normalization_convergence and fused_evidence.is_brand_mismatch:
            verdict = ThreatVerdict.PHISHING
            action = DefensiveAction.BLOCK_ACCESS
            rule_id = "RULE-CRIT-01: Visual-Normalization Convergence Evasion"
            triggered_rules.append(rule_id)
            risk_reasons.append(
                f"Adversarial representation discrepancy detected: Raw HTML diverges while visual OCR matches "
                f"normalized brand '{fused_evidence.target_brand}'. Confirms active signature scanner evasion."
            )

        # Rule CRIT-02: Unauthorized brand credential harvesting
        elif fused_evidence.is_brand_mismatch and fused_evidence.has_credential_seeking and score >= 0.45:
            verdict = ThreatVerdict.PHISHING
            action = DefensiveAction.BLOCK_ACCESS
            rule_id = "RULE-CRIT-02: Unauthorized Brand Credential Harvesting"
            triggered_rules.append(rule_id)
            risk_reasons.append(
                f"Unauthorized domain is soliciting user credentials while impersonating '{fused_evidence.target_brand}'."
            )

        # Rule INV-01: Unverified credential solicitation guard
        elif fused_evidence.has_credential_seeking and verdict == ThreatVerdict.SAFE and not is_whitelisted:
            verdict = ThreatVerdict.INVESTIGATE
            action = DefensiveAction.WARN_USER
            rule_id = "RULE-INV-01: Unverified Credential Solicitation Guard"
            triggered_rules.append(rule_id)
            risk_reasons.append(
                "Page solicits password or authentication credentials on an unverified domain. "
                "Elevated to INVESTIGATE to caution the user."
            )

        # -------------------------------------------------------------
        # Step 3: Populate Key Contributing Risk Reasons
        # -------------------------------------------------------------
        for factor in fused_evidence.factors:
            if factor.raw_score >= 0.50 and factor.weighted_score >= 0.05:
                factor_reason = f"{factor.component.replace('_', ' ').capitalize()}: {factor.description}"
                if factor_reason not in risk_reasons:
                    risk_reasons.append(factor_reason)

        if fused_evidence.interaction_boost > 0.0:
            risk_reasons.append(
                f"Synergistic Threat Boost (+{fused_evidence.interaction_boost:.2f}): "
                "Adversarial evasion vectors compound the risk of credential theft."
            )

        # -------------------------------------------------------------
        # Step 4: Confidence Score Calculation
        # -------------------------------------------------------------
        if triggered_rules and verdict in (ThreatVerdict.PHISHING, ThreatVerdict.SAFE):
            confidence = 0.96
        elif verdict == ThreatVerdict.PHISHING:
            distance = (score - phish_cutoff) / max(0.01, (1.0 - phish_cutoff))
            confidence = min(0.99, max(0.80, 0.85 + (0.14 * distance)))
        elif verdict == ThreatVerdict.SAFE:
            distance = (safe_cutoff - score) / max(0.01, safe_cutoff)
            confidence = min(0.99, max(0.80, 0.85 + (0.14 * distance)))
        else:  # INVESTIGATE
            band_width = max(0.01, phish_cutoff - safe_cutoff)
            center_dist = abs((score - safe_cutoff) / band_width - 0.5)
            confidence = min(0.92, max(0.70, 0.88 - (0.30 * center_dist)))

        # -------------------------------------------------------------
        # Step 5: Decision Summary Synthesis
        # -------------------------------------------------------------
        policy_label = active_policy.value.upper()
        if verdict == ThreatVerdict.PHISHING:
            summary = (
                f"VERDICT: PHISHING (Action: {action.value}) under {policy_label} policy (Score: {score:.2f}). "
                f"Webpage exhibits definitive adversarial phishing characteristics"
                f"{f' targeting {fused_evidence.target_brand}' if fused_evidence.target_brand else ''}. "
                "Immediate defensive blocking is recommended."
            )
        elif verdict == ThreatVerdict.INVESTIGATE:
            summary = (
                f"VERDICT: INVESTIGATE (Action: {action.value}) under {policy_label} policy (Score: {score:.2f}). "
                "Webpage contains ambiguous or elevated risk signals that warrant caution or manual analyst inspection. "
                "Automated access without user warning is restricted."
            )
        else:
            summary = (
                f"VERDICT: SAFE (Action: {action.value}) under {policy_label} policy (Score: {score:.2f}). "
                "Webpage appears authentic and benign. No coherent pattern of credential harvesting, "
                "brand spoofing, or cross-representation evasion was discovered."
            )

        return DecisionResult(
            verdict=verdict,
            recommended_action=action,
            composite_threat_score=score,
            confidence_score=round(confidence, 4),
            policy_applied=active_policy,
            policy_thresholds={"safe_ceiling": safe_cutoff, "phishing_floor": phish_cutoff},
            triggered_rules=triggered_rules,
            risk_reasons=risk_reasons,
            target_brand=fused_evidence.target_brand,
            decision_summary=summary,
            decided_at=datetime.now(timezone.utc),
        )


def evaluate_decision(
    fused_evidence: FusedEvidence,
    policy: Optional[ThreatPosturePolicy] = None,
    engine: Optional[DecisionEngine] = None,
) -> DecisionResult:
    """Convenience functional wrapper for evaluating final operational decisions."""
    active_engine = engine or DecisionEngine()
    return active_engine.evaluate(fused_evidence=fused_evidence, policy=policy)
