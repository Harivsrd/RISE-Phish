"""Deterministic Evidence Fusion Engine for RISE-Phish.

Systematically synthesizes multi-representation discrepancies, brand authenticity,
credential harvesting vectors, URL lexical metrics, Unicode anomalies, and SLM reasoning
into an explainable, calibrated composite threat score.

Adheres to the core research principle:
Discrepancy alone does not equal phishing. Discrepancy is an evidence vector
whose threat magnitude multiplies when coinciding with brand spoofing and
credential harvesting (Visual-Normalization Convergence signature).
"""
from datetime import datetime, timezone
import logging
from typing import Dict, List, Optional, Tuple

from backend.app.crce.brand_detector import (
    TARGET_BRAND_CANONICAL_DOMAINS,
    identify_claimed_brand,
)
from backend.app.models.schemas import (
    CRCEResult,
    EvidenceFactor,
    FusedEvidence,
    HTMLFeatures,
    RepresentationSet,
    SLMDualTaskResult,
    UnicodeAnalysisResult,
    URLFeatures,
)

logger = logging.getLogger("rise_phish.fusion")

# Default calibrated weights across all 7 evidence dimensions (sums to 1.0)
DEFAULT_FUSION_WEIGHTS: Dict[str, float] = {
    "brand_spoofing": 0.25,
    "credential_harvesting": 0.20,
    "crce_discrepancy": 0.20,
    "slm_reasoning": 0.15,
    "url_risk": 0.10,
    "unicode_anomaly": 0.05,
    "social_engineering": 0.05,
}

# High-salience social engineering keyword triggers in visible text / titles
SOCIAL_ENGINEERING_KEYWORDS = [
    "verify your account", "account suspended", "urgent action required",
    "unusual activity", "security alert", "confirm your identity",
    "immediate attention", "temporarily locked", "billing issue",
    "restore access", "unauthorized login", "update payment",
]


class EvidenceFusionEngine:
    """Multi-source evidence fusion engine with non-linear interaction modeling."""

    def __init__(
        self,
        weights: Optional[Dict[str, float]] = None,
        convergence_boost: float = 0.25,
        credential_spoofing_boost: float = 0.20,
        max_interaction_boost: float = 0.40,
    ) -> None:
        self.weights = weights or dict(DEFAULT_FUSION_WEIGHTS)
        self.convergence_boost = convergence_boost
        self.credential_spoofing_boost = credential_spoofing_boost
        self.max_interaction_boost = max_interaction_boost

        # Validate that weights sum approximately to 1.0
        total_w = sum(self.weights.values())
        if not (0.99 <= total_w <= 1.01):
            logger.warning("Fusion weights do not sum to 1.0 (sum=%.3f); normalizing.", total_w)
            self.weights = {k: v / total_w for k, v in self.weights.items()}

    def _extract_brand_status(
        self,
        url_features: Optional[URLFeatures],
        rep_set: Optional[RepresentationSet],
        crce_result: Optional[CRCEResult],
        slm_result: Optional[SLMDualTaskResult],
    ) -> Tuple[Optional[str], bool, float, str]:
        """Evaluates brand presence and brand-to-domain mismatch.
        
        Returns:
            (target_brand, is_brand_mismatch, brand_score, explanation)
        """
        registered_domain = ""
        if url_features and url_features.registered_domain:
            registered_domain = url_features.registered_domain.lower().strip()
        elif rep_set and rep_set.r5_url and rep_set.r5_url.registered_domain:
            registered_domain = rep_set.r5_url.registered_domain.lower().strip()

        # Step 1: Discover claimed brand
        detected_brand = None
        
        # Check SLM reasoning target brand first
        if slm_result and slm_result.reasoning.target_brand:
            detected_brand = slm_result.reasoning.target_brand.lower().strip()
            
        # Check semantic representation claims if not found
        if not detected_brand and rep_set and rep_set.r4_semantic:
            search_text = f"{rep_set.r4_semantic.title or ''} {rep_set.r4_semantic.headings_text}"
            detected_brand = identify_claimed_brand(search_text)

        # Check CRCE url_brand_discrepancy
        if not detected_brand and crce_result and crce_result.url_brand_discrepancy > 0.0:
            for finding in crce_result.findings:
                if finding.discrepancy_type == "brand_domain_mismatch":
                    detected_brand = "unknown_brand"
                    break

        if not detected_brand:
            return None, False, 0.0, "No brand impersonation or trademark claims detected."

        canonical_domains = TARGET_BRAND_CANONICAL_DOMAINS.get(
            detected_brand, 
            {f"{detected_brand.replace(' ', '')}.com"}
        )

        if registered_domain in canonical_domains:
            return (
                detected_brand.capitalize(), 
                False, 
                0.0, 
                f"Page claims brand '{detected_brand.capitalize()}', which matches authorized domain '{registered_domain}'."
            )
        else:
            return (
                detected_brand.capitalize(),
                True,
                1.0,
                f"Unauthorized Brand Spoofing: Page claims '{detected_brand.capitalize()}', but is hosted on unauthorized domain '{registered_domain or 'unknown'}'."
            )

    def _extract_credential_status(
        self,
        html_features: Optional[HTMLFeatures],
        rep_set: Optional[RepresentationSet],
        has_password_field: Optional[bool] = None,
    ) -> Tuple[bool, float, str]:
        """Detects presence of credential harvesting vectors."""
        has_pwd = False
        has_forms = False

        if has_password_field is not None:
            has_pwd = has_password_field

        if not has_pwd and html_features:
            has_pwd = html_features.has_password_field or len(html_features.password_inputs) > 0
            has_forms = len(html_features.forms) > 0

        if not has_pwd and rep_set and rep_set.r4_semantic:
            intent = rep_set.r4_semantic.form_intent_summary.lower()
            if "password" in intent or "credentials" in intent:
                has_pwd = True

        if has_pwd:
            return True, 1.0, "Password input field detected; page solicits sensitive authentication credentials."
        elif has_forms:
            return False, 0.30, "Web form present without password fields; intermediate input collection."
        else:
            return False, 0.0, "No interactive credential forms or password inputs discovered."

    def _extract_social_engineering(
        self,
        rep_set: Optional[RepresentationSet],
        slm_result: Optional[SLMDualTaskResult],
    ) -> Tuple[float, List[str]]:
        """Identifies urgency, fear, account suspension, or verify-credential triggers."""
        triggers: List[str] = []
        
        # Check SLM deception techniques
        if slm_result:
            for tech in slm_result.reasoning.deception_techniques:
                if any(k in tech.lower() for k in ("social_engineering", "urgency", "scare")):
                    triggers.append(tech)

        # Inspect semantic and visible text
        text_to_scan = ""
        if rep_set:
            if rep_set.r4_semantic:
                text_to_scan += f"{rep_set.r4_semantic.title or ''} {rep_set.r4_semantic.headings_text} "
            if rep_set.r1_raw:
                text_to_scan += rep_set.r1_raw.text[:1000]

        lower_scan = text_to_scan.lower()
        for kw in SOCIAL_ENGINEERING_KEYWORDS:
            if kw in lower_scan and kw not in triggers:
                triggers.append(kw)

        if len(triggers) >= 2:
            return 1.0, triggers
        elif len(triggers) == 1:
            return 0.60, triggers
        return 0.0, []

    def fuse(
        self,
        url_features: Optional[URLFeatures] = None,
        unicode_result: Optional[UnicodeAnalysisResult] = None,
        crce_result: Optional[CRCEResult] = None,
        rep_set: Optional[RepresentationSet] = None,
        slm_result: Optional[SLMDualTaskResult] = None,
        html_features: Optional[HTMLFeatures] = None,
        claimed_brand: Optional[str] = None,
        has_password_field: Optional[bool] = None,
    ) -> FusedEvidence:
        """Executes multi-source deterministic evidence fusion.
        
        Args:
            url_features: Lexical and structural URL analysis from Phase 3.
            unicode_result: Detailed Unicode anomaly findings from Phase 4.
            crce_result: Cross-representation discrepancy metrics from Phase 7.
            rep_set: Multi-representation set (R1-R5) from Phase 6.
            slm_result: Dual-task recovery and reasoning output from Phase 9.
            html_features: Structural HTML DOM features from Phase 2.
            claimed_brand: Explicit brand override if known.
            has_password_field: Explicit credential flag override if known.
            
        Returns:
            FusedEvidence object containing calibrated composite threat score,
            component factor breakdown, and explainable rationale.
        """
        key_indicators: List[str] = []
        factors: List[EvidenceFactor] = []
        vector_scores: Dict[str, float] = {}

        # 1. Brand Spoofing Dimension
        target_brand, is_brand_mismatch, brand_score, brand_desc = self._extract_brand_status(
            url_features=url_features,
            rep_set=rep_set,
            crce_result=crce_result,
            slm_result=slm_result,
        )
        if claimed_brand:
            target_brand = claimed_brand
        vector_scores["brand_spoofing"] = brand_score
        if is_brand_mismatch:
            key_indicators.append(f"unauthorized_brand_spoofing_{target_brand.lower() if target_brand else 'generic'}")
        factors.append(EvidenceFactor(
            component="brand_spoofing",
            raw_score=brand_score,
            weight=self.weights["brand_spoofing"],
            weighted_score=brand_score * self.weights["brand_spoofing"],
            description=brand_desc,
        ))

        # 2. Credential Harvesting Dimension
        has_credentials, cred_score, cred_desc = self._extract_credential_status(
            html_features=html_features,
            rep_set=rep_set,
            has_password_field=has_password_field,
        )
        vector_scores["credential_harvesting"] = cred_score
        if has_credentials:
            key_indicators.append("password_credential_harvesting")
        factors.append(EvidenceFactor(
            component="credential_harvesting",
            raw_score=cred_score,
            weight=self.weights["credential_harvesting"],
            weighted_score=cred_score * self.weights["credential_harvesting"],
            description=cred_desc,
        ))

        # 3. CRCE Cross-Representation Discrepancy Dimension
        crce_score = 0.0
        is_convergence = False
        crce_desc = "No cross-representation discrepancy analysis available."
        if crce_result:
            crce_score = crce_result.overall_discrepancy
            is_convergence = crce_result.visual_normalization_convergence
            if is_convergence:
                key_indicators.append("visual_normalization_convergence")
                crce_desc = (
                    f"Visual-Normalization Convergence signature detected (discrepancy={crce_score:.2f}). "
                    "Raw HTML diverges from normalized and visual OCR text while normalized aligns with OCR."
                )
            elif crce_score > 0.40:
                key_indicators.append("elevated_cross_representation_divergence")
                crce_desc = f"Elevated cross-representation discrepancy ({crce_score:.2f}) observed across representations."
            else:
                crce_desc = f"Cross-representation consistency confirmed (discrepancy={crce_score:.2f})."
        
        vector_scores["crce_discrepancy"] = crce_score
        factors.append(EvidenceFactor(
            component="crce_discrepancy",
            raw_score=crce_score,
            weight=self.weights["crce_discrepancy"],
            weighted_score=crce_score * self.weights["crce_discrepancy"],
            description=crce_desc,
        ))

        # 4. SLM Threat Reasoning Dimension
        slm_score = 0.0
        slm_desc = "SLM reasoning not executed or skipped."
        if slm_result:
            risk_level = slm_result.reasoning.risk_level.upper()
            confidence = slm_result.reasoning.confidence_score
            level_map = {"CRITICAL": 1.0, "HIGH": 0.80, "MEDIUM": 0.45, "LOW": 0.0}
            base_slm = level_map.get(risk_level, 0.0)
            slm_score = base_slm * confidence
            slm_desc = (
                f"SLM classified threat as {risk_level} (confidence={confidence:.2f}): "
                f"{slm_result.reasoning.reasoning_summary[:120]}..."
            )
            if slm_result.reasoning.phishing_intent_detected:
                key_indicators.append("slm_phishing_intent_confirmed")
        
        vector_scores["slm_reasoning"] = slm_score
        factors.append(EvidenceFactor(
            component="slm_reasoning",
            raw_score=slm_score,
            weight=self.weights["slm_reasoning"],
            weighted_score=slm_score * self.weights["slm_reasoning"],
            description=slm_desc,
        ))

        # 5. URL Lexical Risk Dimension
        url_score = 0.0
        url_desc = "No URL lexical analysis supplied."
        if url_features:
            url_score = url_features.url_risk_score
            reasons = "; ".join(url_features.risk_reasons[:3]) if url_features.risk_reasons else "clean"
            url_desc = f"Lexical URL risk score {url_score:.2f} (indicators: {reasons})."
            if url_score > 0.60:
                key_indicators.append("high_risk_lexical_url")
        
        vector_scores["url_risk"] = url_score
        factors.append(EvidenceFactor(
            component="url_risk",
            raw_score=url_score,
            weight=self.weights["url_risk"],
            weighted_score=url_score * self.weights["url_risk"],
            description=url_desc,
        ))

        # 6. Unicode Anomaly Dimension
        unicode_score = 0.0
        unicode_desc = "No Unicode anomalies flagged."
        if unicode_result:
            unicode_score = unicode_result.unicode_anomaly_score
            if unicode_score > 0.30:
                key_indicators.append("suspicious_unicode_artifacts")
                unicode_desc = (
                    f"Unicode anomaly score {unicode_score:.2f}: "
                    f"{unicode_result.homoglyph_count} homoglyphs, {unicode_result.zero_width_count} zero-width chars."
                )
            else:
                unicode_desc = f"Unicode distribution within benign parameters (score={unicode_score:.2f})."
        
        vector_scores["unicode_anomaly"] = unicode_score
        factors.append(EvidenceFactor(
            component="unicode_anomaly",
            raw_score=unicode_score,
            weight=self.weights["unicode_anomaly"],
            weighted_score=unicode_score * self.weights["unicode_anomaly"],
            description=unicode_desc,
        ))

        # 7. Social Engineering Dimension
        se_score, se_triggers = self._extract_social_engineering(rep_set, slm_result)
        vector_scores["social_engineering"] = se_score
        se_desc = f"Social engineering cues: {', '.join(se_triggers)}" if se_triggers else "No urgency/fear triggers detected."
        if se_score > 0.5:
            key_indicators.append("social_engineering_triggers_present")
        factors.append(EvidenceFactor(
            component="social_engineering",
            raw_score=se_score,
            weight=self.weights["social_engineering"],
            weighted_score=se_score * self.weights["social_engineering"],
            description=se_desc,
        ))

        # Calculate base linear weighted score
        base_threat_score = sum(f.weighted_score for f in factors)

        # -------------------------------------------------------------
        # Non-Linear Synergistic Boosts (The Core RISE-Phish Innovation)
        # -------------------------------------------------------------
        interaction_boost = 0.0
        interaction_notes: List[str] = []

        # Synergistic interaction 1: Visual-Normalization Convergence on spoofed brand
        if is_convergence and is_brand_mismatch:
            interaction_boost += self.convergence_boost
            interaction_notes.append(
                f"+{self.convergence_boost:.2f} Evasion Synergy Boost: Attacker deployed representation discrepancies "
                f"specifically targeting brand '{target_brand}' to evade automated DOM scanners."
            )

        # Synergistic interaction 2: Brand Mismatch + Credential Solicitation
        if is_brand_mismatch and has_credentials:
            interaction_boost += self.credential_spoofing_boost
            interaction_notes.append(
                f"+{self.credential_spoofing_boost:.2f} Credential Theft Boost: Unauthorized host is collecting "
                f"credentials under the guise of '{target_brand}'."
            )

        # Bound interaction boost
        interaction_boost = min(self.max_interaction_boost, interaction_boost)
        composite_score = base_threat_score + interaction_boost

        # -------------------------------------------------------------
        # Legitimate Safety Guard: Dampen if domain matches brand
        # -------------------------------------------------------------
        is_legitimate_verified_domain = False
        registered_domain = (url_features.registered_domain if url_features else "").lower()
        if target_brand:
            canonical_domains = TARGET_BRAND_CANONICAL_DOMAINS.get(
                target_brand.lower(), 
                {f"{target_brand.lower().replace(' ', '')}.com"}
            )
            if registered_domain in canonical_domains and url_score <= 0.20:
                is_legitimate_verified_domain = True
                # Cap threat score at benign threshold for verified brand domains
                composite_score = min(composite_score, 0.15)
                interaction_notes.append(
                    f"Legitimate Domain Guard: Registered domain '{registered_domain}' matches official canonical "
                    f"domain for '{target_brand}'. Minor discrepancies dampener applied."
                )

        composite_score = max(0.0, min(1.0, composite_score))

        # Compile explainable narrative
        rationale_parts = []
        if is_legitimate_verified_domain:
            rationale_parts.append(
                f"VERIFIED BENIGN: Webpage belongs to authorized domain '{registered_domain}' for '{target_brand}'. "
                "Any localized representation variance is non-malicious."
            )
        elif composite_score >= 0.70:
            rationale_parts.append(
                f"CRITICAL MALICIOUS THREAT: Multiple convergent evidence sources confirm an adversarial phishing attack"
                f"{f' impersonating {target_brand}' if target_brand else ''}."
            )
        elif composite_score >= 0.45:
            rationale_parts.append(
                f"SUSPICIOUS HIGH RISK: Substantial evidence of brand discrepancy and risk indicators detected."
            )
        else:
            rationale_parts.append(
                "BENIGN/LOW RISK: No coherent evidence of credential harvesting, brand spoofing, or adversarial evasion."
            )

        if interaction_notes:
            rationale_parts.extend(interaction_notes)

        fusion_rationale = " ".join(rationale_parts)

        return FusedEvidence(
            composite_threat_score=round(composite_score, 4),
            vector_scores=vector_scores,
            evidence_weights=self.weights,
            interaction_boost=round(interaction_boost, 4),
            key_indicators=key_indicators,
            factors=factors,
            discrepancy_significant=(crce_score >= 0.40 or is_convergence),
            visual_normalization_convergence=is_convergence,
            target_brand=target_brand,
            is_brand_mismatch=is_brand_mismatch,
            has_credential_seeking=has_credentials,
            fusion_rationale=fusion_rationale,
            fused_at=datetime.now(timezone.utc),
        )


def fuse_evidence(
    url_features: Optional[URLFeatures] = None,
    unicode_result: Optional[UnicodeAnalysisResult] = None,
    crce_result: Optional[CRCEResult] = None,
    rep_set: Optional[RepresentationSet] = None,
    slm_result: Optional[SLMDualTaskResult] = None,
    html_features: Optional[HTMLFeatures] = None,
    claimed_brand: Optional[str] = None,
    has_password_field: Optional[bool] = None,
    engine: Optional[EvidenceFusionEngine] = None,
) -> FusedEvidence:
    """Convenience functional wrapper for executing evidence fusion."""
    active_engine = engine or EvidenceFusionEngine()
    return active_engine.fuse(
        url_features=url_features,
        unicode_result=unicode_result,
        crce_result=crce_result,
        rep_set=rep_set,
        slm_result=slm_result,
        html_features=html_features,
        claimed_brand=claimed_brand,
        has_password_field=has_password_field,
    )
