"""Explanation Engine for RISE-Phish.

Transforms multi-representation discrepancy evidence, Unicode forensic logs,
SLM reasoning narratives, and operational decisions into two tailored presentations:
1. UserAdvisory: Plain-language security advice for everyday users.
2. AnalystForensicReport: In-depth technical forensics for SOC teams and researchers.
"""
from datetime import datetime, timezone
import logging
from typing import List, Optional

from backend.app.models.schemas import (
    AnalystForensicReport,
    CRCEResult,
    DecisionResult,
    DiscrepancyForensicSummary,
    EvidenceFactor,
    ExplanationReport,
    FusedEvidence,
    HTMLFeatures,
    RepresentationSet,
    SLMDualTaskResult,
    ThreatVerdict,
    UnicodeAnalysisResult,
    URLFeatures,
    UserAdvisory,
)

logger = logging.getLogger("rise_phish.explanation")


class ExplanationEngine:
    """Synthesizes technical evidence into dual-audience explainability reports."""

    def build_user_advisory(
        self,
        decision: DecisionResult,
        fused_evidence: FusedEvidence,
        rep_set: RepresentationSet,
    ) -> UserAdvisory:
        """Constructs an accessible, non-technical plain-language security advisory."""
        verdict = decision.verdict
        target_brand = fused_evidence.target_brand
        registered_domain = rep_set.r5_url.registered_domain or rep_set.r5_url.hostname

        bullet_points: List[str] = []

        if verdict == ThreatVerdict.PHISHING:
            status_level = "DANGER"
            headline = f"Dangerous Site: Phishing Attack Detected{' (' + target_brand + ')' if target_brand else ''}"
            summary = (
                f"This webpage is pretending to be {target_brand or 'a legitimate service'}, "
                f"but is hosted on an unauthorized website ({registered_domain}) designed to steal your credentials."
            )

            # Bullet points
            if fused_evidence.is_brand_mismatch:
                bullet_points.append(
                    f"The page displays the branding of '{target_brand}', but the actual web address "
                    f"({registered_domain}) does not belong to {target_brand}."
                )

            if fused_evidence.has_credential_seeking:
                bullet_points.append(
                    "This unauthorized site requests your sensitive password or account credentials."
                )

            if fused_evidence.visual_normalization_convergence:
                bullet_points.append(
                    "The webpage uses deceptive lookalike characters (homoglyphs) to trick your eyes while trying "
                    "to hide from automated security scanners."
                )
            elif fused_evidence.discrepancy_significant:
                bullet_points.append(
                    "Significant inconsistencies were detected between the page's code and what is visually shown on screen."
                )

            if fused_evidence.vector_scores.get("social_engineering", 0.0) > 0.5:
                bullet_points.append(
                    "The page employs urgent psychological pressure (such as account suspension warnings) to induce panic."
                )

            action_advice = (
                f"DO NOT enter passwords, phone numbers, or credit card details on this site. "
                f"Close this tab immediately and access {target_brand or 'the official service'} only through "
                f"your verified bookmarks or official app."
            )

        elif verdict == ThreatVerdict.INVESTIGATE:
            status_level = "CAUTION"
            headline = "Suspicious Site: Exercise Caution"
            summary = (
                f"This webpage on '{registered_domain}' contains unusual signals or unverified forms. "
                "Its identity cannot be verified with certainty."
            )

            if fused_evidence.has_credential_seeking:
                bullet_points.append(
                    "The page contains login or password entry fields on an unverified domain."
                )

            if fused_evidence.discrepancy_significant:
                bullet_points.append(
                    "Minor rendering differences were detected between the page markup and its visual layout."
                )

            if fused_evidence.vector_scores.get("url_risk", 0.0) > 0.4:
                bullet_points.append(
                    "The web address exhibits unusual characteristics (such as unexpected subdomains or domain extensions)."
                )

            if not bullet_points:
                bullet_points.append(
                    "The domain is unverified and requires caution before submitting personal information."
                )

            action_advice = (
                "Verify the sender and double-check the web address before entering any personal data or credentials."
            )

        else:  # SAFE
            status_level = "SAFE"
            headline = "Authentic Webpage: No Threat Detected"
            summary = (
                f"The webpage on '{registered_domain}' appears authentic and consistent with its claimed service."
            )

            bullet_points.append(
                f"The web address matches the official, verified domain for this service."
            )
            bullet_points.append(
                "No deceptive character tricks, brand impersonation, or evasion attempts were detected."
            )
            if not fused_evidence.has_credential_seeking:
                bullet_points.append("The page does not solicit confidential authentication credentials.")

            action_advice = "You may continue browsing normally."

        return UserAdvisory(
            headline=headline,
            status_level=status_level,
            summary=summary,
            bullet_points=bullet_points,
            action_advice=action_advice,
        )

    def build_analyst_report(
        self,
        decision: DecisionResult,
        fused_evidence: FusedEvidence,
        rep_set: RepresentationSet,
        crce_result: CRCEResult,
        unicode_result: Optional[UnicodeAnalysisResult] = None,
        url_features: Optional[URLFeatures] = None,
        slm_result: Optional[SLMDualTaskResult] = None,
        html_features: Optional[HTMLFeatures] = None,
    ) -> AnalystForensicReport:
        """Constructs an in-depth evidentiary forensic report for security operations teams."""
        registered_domain = rep_set.r5_url.registered_domain or rep_set.r5_url.hostname

        # 1. Discrepancy Forensics
        top_findings_desc = [
            f"[{f.source}->{f.target}] {f.discrepancy_type.upper()}: {f.supporting_evidence}"
            for f in crce_result.findings[:5]
        ]
        discrepancy_forensics = DiscrepancyForensicSummary(
            pairwise_scores={
                "r1_raw_vs_r2_normalized": crce_result.raw_normalized_discrepancy,
                "r1_raw_vs_r3_visual": crce_result.raw_visual_discrepancy,
                "r2_normalized_vs_r3_visual": crce_result.normalized_visual_discrepancy,
                "r5_url_vs_brand": crce_result.url_brand_discrepancy,
                "overall_discrepancy": crce_result.overall_discrepancy,
            },
            visual_normalization_convergence=crce_result.visual_normalization_convergence,
            evasion_signature_detected=(
                crce_result.visual_normalization_convergence or fused_evidence.interaction_boost > 0.0
            ),
            top_findings=top_findings_desc,
        )

        # 2. Unicode Forensics
        unicode_anomalies_count = 0
        key_unicode_findings: List[str] = []
        if unicode_result:
            unicode_anomalies_count = len(unicode_result.anomalies)
            for anomaly in unicode_result.anomalies[:6]:
                key_unicode_findings.append(
                    f"[{anomaly.codepoint}] '{anomaly.character}' ({anomaly.name}) "
                    f"in token '{anomaly.context_token or ''}' - {anomaly.reason}"
                )

        # 3. Credential Harvesting Vectors
        credential_vectors: List[str] = []
        if html_features:
            if html_features.has_password_field:
                credential_vectors.append(
                    f"Discovered {len(html_features.password_inputs)} password input field(s)"
                )
            for form in html_features.forms:
                if form.has_password or form.action:
                    credential_vectors.append(
                        f"Form [action='{form.action or 'none'}', method='{form.method.upper()}'] "
                        f"with {len(form.inputs)} inputs (has_pwd={form.has_password})"
                    )
        elif fused_evidence.has_credential_seeking:
            credential_vectors.append("Interactive credential entry vector discovered in document DOM.")

        # 4. URL Lexical Indicators
        url_lexical_indicators: List[str] = []
        if url_features:
            url_lexical_indicators.extend(url_features.risk_reasons)
            url_lexical_indicators.append(f"Shannon Entropy: {url_features.shannon_entropy:.2f}")
            if url_features.has_punycode:
                url_lexical_indicators.append(
                    f"Punycode Host: {url_features.hostname} -> Decoded: {url_features.punycode_decoded_domain}"
                )

        # 5. SLM Audits
        slm_recovery_summary = None
        slm_reasoning_summary = None
        if slm_result:
            slm_recovery_summary = (
                f"Tactics: {', '.join(slm_result.recovery.manipulation_tactics) or 'none'}; "
                f"Tokens Recovered: {slm_result.recovery.recovered_tokens_count}; "
                f"Explanation: {slm_result.recovery.recovery_explanation}"
            )
            slm_reasoning_summary = slm_result.reasoning.reasoning_summary

        return AnalystForensicReport(
            verdict=decision.verdict,
            recommended_action=decision.recommended_action,
            composite_threat_score=decision.composite_threat_score,
            confidence_score=decision.confidence_score,
            target_brand=decision.target_brand,
            registered_domain=registered_domain,
            discrepancy_forensics=discrepancy_forensics,
            unicode_anomalies_count=unicode_anomalies_count,
            key_unicode_findings=key_unicode_findings,
            credential_vectors=credential_vectors,
            url_lexical_indicators=url_lexical_indicators,
            slm_recovery_summary=slm_recovery_summary,
            slm_reasoning_summary=slm_reasoning_summary,
            rules_triggered=decision.triggered_rules,
            contributing_factors=fused_evidence.factors,
        )

    def explain(
        self,
        decision: DecisionResult,
        fused_evidence: FusedEvidence,
        rep_set: RepresentationSet,
        crce_result: CRCEResult,
        unicode_result: Optional[UnicodeAnalysisResult] = None,
        url_features: Optional[URLFeatures] = None,
        slm_result: Optional[SLMDualTaskResult] = None,
        html_features: Optional[HTMLFeatures] = None,
        analysis_id: Optional[str] = None,
    ) -> ExplanationReport:
        """Generates unified ExplanationReport bundling UserAdvisory and AnalystForensicReport.
        
        Args:
            decision: Final decision emitted by Phase 11.
            fused_evidence: Fused evidence from Phase 10.
            rep_set: Multi-representation set from Phase 6.
            crce_result: Cross-representation discrepancy metrics from Phase 7.
            unicode_result: Unicode forensic findings from Phase 4.
            url_features: URL analysis from Phase 3.
            slm_result: Dual-task SLM outputs from Phase 9.
            html_features: Structured DOM features from Phase 2.
            analysis_id: Optional analysis UUID override.
            
        Returns:
            ExplanationReport instance.
        """
        active_analysis_id = analysis_id or rep_set.analysis_id
        target_url = rep_set.r5_url.raw_url

        user_advisory = self.build_user_advisory(
            decision=decision,
            fused_evidence=fused_evidence,
            rep_set=rep_set,
        )

        analyst_report = self.build_analyst_report(
            decision=decision,
            fused_evidence=fused_evidence,
            rep_set=rep_set,
            crce_result=crce_result,
            unicode_result=unicode_result,
            url_features=url_features,
            slm_result=slm_result,
            html_features=html_features,
        )

        return ExplanationReport(
            analysis_id=active_analysis_id,
            url=target_url,
            user_advisory=user_advisory,
            analyst_report=analyst_report,
            generated_at=datetime.now(timezone.utc),
        )


def generate_explanation(
    decision: DecisionResult,
    fused_evidence: FusedEvidence,
    rep_set: RepresentationSet,
    crce_result: CRCEResult,
    unicode_result: Optional[UnicodeAnalysisResult] = None,
    url_features: Optional[URLFeatures] = None,
    slm_result: Optional[SLMDualTaskResult] = None,
    html_features: Optional[HTMLFeatures] = None,
    analysis_id: Optional[str] = None,
    engine: Optional[ExplanationEngine] = None,
) -> ExplanationReport:
    """Convenience functional wrapper for generating comprehensive explanations."""
    active_engine = engine or ExplanationEngine()
    return active_engine.explain(
        decision=decision,
        fused_evidence=fused_evidence,
        rep_set=rep_set,
        crce_result=crce_result,
        unicode_result=unicode_result,
        url_features=url_features,
        slm_result=slm_result,
        html_features=html_features,
        analysis_id=analysis_id,
    )
