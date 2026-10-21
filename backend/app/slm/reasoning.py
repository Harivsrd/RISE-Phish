"""Task 2: Phishing Reasoning Implementation.

Generates structured JSON prompts, provides schema validation, and includes
deterministic evidence reasoning for lightweight language models in RISE-Phish.
"""
import json
import re
from typing import Any, Dict, List, Optional

from backend.app.crce.brand_detector import TARGET_BRAND_CANONICAL_DOMAINS
from backend.app.models.schemas import SLMEvidenceInput, SLMReasoningResult


PHISHING_REASONING_SYSTEM_PROMPT = """You are RISE-Phish's specialized Cybersecurity Reasoning Engine for cross-representation phishing detection.
Your purpose is to synthesize multi-representation evidence from a target webpage and produce structured threat reasoning.

CRITICAL RESEARCH GUIDELINES:
1. A representation discrepancy or Unicode anomaly alone does NOT automatically mean phishing.
   Legitimate websites often feature localization, internationalization, or innocent rendering variance.
2. Threat evaluation requires EVIDENCE FUSION:
   - Cross-representation discrepancy (e.g. Visual-Normalization convergence, raw != visual)
   - Brand impersonation (page claims or displays a brand while the domain does not belong to that brand)
   - Credential harvesting (password fields, authentication forms, token prompts)
   - Lexical URL anomalies (suspicious TLDs, IP hosts, homograph punycode, high entropy)
   - Social engineering cues (urgent account suspension, security alert, verify credentials)
3. When discrepancies coincide with brand spoofing and credential inputs, this indicates deliberate evasion (adversarial obfuscation to evade static security scanners while deceiving human users visually).

SCHEMA INSTRUCTIONS:
You MUST respond strictly with valid JSON conforming to this schema:
{
    "phishing_intent_detected": <true or false>,
    "risk_level": "<LOW | MEDIUM | HIGH | CRITICAL>",
    "target_brand": "<impersonated brand name or null>",
    "confidence_score": <float between 0.0 and 1.0>,
    "deception_techniques": ["<technique_1>", "<technique_2>"],
    "inconsistency_analysis": "<analysis of representation discrepancies and contradictions>",
    "reasoning_summary": "<concise academic rationale justifying the verdict>",
    "recommended_action": "<ALLOW | INSPECT_FURTHER | BLOCK>"
}
Return ONLY raw JSON. Do NOT wrap in markdown or include extraneous commentary.
"""


def build_phishing_reasoning_prompt(evidence: SLMEvidenceInput) -> str:
    """Formats structured webpage evidence into a token-efficient prompt for SLM reasoning."""
    brands_str = ", ".join(evidence.detected_brands) if evidence.detected_brands else "None detected"
    url_reasons_str = "; ".join(evidence.url_risk_reasons) if evidence.url_risk_reasons else "None"
    findings_str = "; ".join(evidence.discrepancy_findings_summary) if evidence.discrepancy_findings_summary else "No discrepancies"
    social_str = "; ".join(evidence.social_engineering_indicators) if evidence.social_engineering_indicators else "None"

    return f"""Synthesize the following webpage evidence and determine whether phishing intent is present:

WEBPAGE EVIDENCE:
- Target URL: {evidence.url}
- Registered Domain: {evidence.registered_domain} (Hostname: {evidence.domain})
- Page Title: {evidence.page_title or 'None'}
- Claimed Brands: {brands_str}
- Credential Harvesting: Password Fields = {evidence.has_password_field}, Total Forms = {evidence.form_count}
- URL Lexical Risk Score: {evidence.url_risk_score:.2f} (Reasons: {url_reasons_str})
- Unicode Anomaly Score: {evidence.unicode_anomaly_score:.2f}
- CRCE Discrepancy Score: {evidence.crce_overall_discrepancy:.2f}
- Visual-Normalization Convergence Signature: {evidence.visual_normalization_convergence}
- Discrepancy Findings: {findings_str}
- Social Engineering Indicators: {social_str}

REPRESENTATION SNIPPETS:
- Visible Text Snippet:
\"\"\"{evidence.visible_text_snippet[:400]}\"\"\"
- Recovered Semantic Snippet:
\"\"\"{(evidence.recovered_text_snippet or '')[:400]}\"\"\"

Provide your threat reasoning strictly as valid JSON matching the specified schema."""


def parse_phishing_reasoning_response(
    raw_response: str, 
    evidence: SLMEvidenceInput
) -> SLMReasoningResult:
    """Robustly extracts and validates the SLM output for Task 2.
    
    If the response is corrupted or invalid, falls back to deterministic
    evidence reasoning without failing or halting the pipeline.
    """
    cleaned = raw_response.strip()

    # Strip markdown formatting if present
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
        cleaned = cleaned.strip()

    try:
        data = json.loads(cleaned)
        
        risk_level = str(data.get("risk_level", "LOW")).upper()
        if risk_level not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            risk_level = "MEDIUM" if data.get("phishing_intent_detected") else "LOW"

        action = str(data.get("recommended_action", "ALLOW")).upper()
        if action not in ("ALLOW", "INSPECT_FURTHER", "BLOCK"):
            action = "BLOCK" if risk_level in ("HIGH", "CRITICAL") else "ALLOW"

        target_brand = data.get("target_brand")
        if target_brand and str(target_brand).lower() in ("none", "null", "false"):
            target_brand = None

        return SLMReasoningResult(
            phishing_intent_detected=bool(data.get("phishing_intent_detected", False)),
            risk_level=risk_level,
            target_brand=target_brand,
            confidence_score=float(data.get("confidence_score", 0.8)),
            deception_techniques=list(data.get("deception_techniques", [])),
            inconsistency_analysis=str(data.get("inconsistency_analysis", "")),
            reasoning_summary=str(data.get("reasoning_summary", "")),
            recommended_action=action,
        )
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        # Fall back to deterministic reasoning oracle
        fallback = algorithmic_phishing_reasoning(evidence)
        fallback.reasoning_summary += (
            f" [Note: Model response failed JSON validation ({str(exc)}); fallback heuristic applied.]"
        )
        return fallback


def algorithmic_phishing_reasoning(evidence: SLMEvidenceInput) -> SLMReasoningResult:
    """Deterministic evidence reasoning oracle.
    
    Combines brand mismatch, credential harvesting, representation discrepancy,
    and URL risk into explainable threat classifications.
    
    Args:
        evidence: Comprehensive structured evidence payload.
        
    Returns:
        SLMReasoningResult adhering strictly to the RISE-Phish data contract.
    """
    deception_techniques: List[str] = []
    inconsistency_notes: List[str] = []
    
    # 1. Brand Impersonation Evaluation
    brand_impersonated = None
    has_brand_mismatch = False
    
    if evidence.detected_brands:
        for brand in evidence.detected_brands:
            brand_lower = brand.lower().strip()
            registered_domain = (evidence.registered_domain or "").lower().strip()
            
            canonical_domains = TARGET_BRAND_CANONICAL_DOMAINS.get(
                brand_lower, 
                {f"{brand_lower.replace(' ', '')}.com"}
            )
            
            if registered_domain not in canonical_domains:
                has_brand_mismatch = True
                brand_impersonated = brand
                deception_techniques.append(f"brand_impersonation_{brand_lower.replace(' ', '_')}")
                break

    # 2. Credential Harvesting Check
    has_credentials = evidence.has_password_field or evidence.form_count > 0
    if evidence.has_password_field:
        deception_techniques.append("credential_harvesting")

    # 3. Discrepancy & Convergence Evaluation
    if evidence.visual_normalization_convergence:
        deception_techniques.append("visual_normalization_evasion")
        inconsistency_notes.append(
            "Raw DOM text diverges from normalized and visual OCR text, while normalized and OCR converge. "
            "This confirms visual deception designed to mislead human perception while confusing signature filters."
        )
    elif evidence.crce_overall_discrepancy > 0.4:
        deception_techniques.append("cross_representation_divergence")
        inconsistency_notes.append(
            f"Elevated representation discrepancy ({evidence.crce_overall_discrepancy:.2f}) observed across DOM, OCR, and URL."
        )

    # 4. Unicode Anomaly Check
    if evidence.unicode_anomaly_score > 0.3:
        deception_techniques.append("homoglyph_unicode_obfuscation")
        inconsistency_notes.append(
            f"Suspicious Unicode artifacts detected (anomaly score: {evidence.unicode_anomaly_score:.2f})."
        )

    # 5. Social Engineering Cues
    if evidence.social_engineering_indicators:
        deception_techniques.append("social_engineering_triggers")

    # 6. URL Risk Check
    if evidence.url_risk_score > 0.5:
        deception_techniques.append("lexical_url_spoofing")

    # Synthesize threat score & classification
    threat_points = 0.0
    if has_brand_mismatch and has_credentials:
        threat_points += 0.50
    elif has_brand_mismatch:
        threat_points += 0.30
    
    if evidence.visual_normalization_convergence:
        threat_points += 0.30
    elif evidence.crce_overall_discrepancy > 0.4:
        threat_points += 0.15

    if evidence.url_risk_score > 0.5:
        threat_points += 0.20
    
    if evidence.social_engineering_indicators:
        threat_points += 0.15

    # Determine risk level and verdict
    if threat_points >= 0.70 or (has_brand_mismatch and has_credentials and (evidence.visual_normalization_convergence or evidence.url_risk_score > 0.4)):
        phishing_intent = True
        risk_level = "CRITICAL"
        action = "BLOCK"
        confidence = 0.95
    elif threat_points >= 0.45:
        phishing_intent = True
        risk_level = "HIGH"
        action = "BLOCK"
        confidence = 0.85
    elif threat_points >= 0.25 or has_brand_mismatch or evidence.crce_overall_discrepancy > 0.5:
        phishing_intent = False
        risk_level = "MEDIUM"
        action = "INSPECT_FURTHER"
        confidence = 0.75
    else:
        phishing_intent = False
        risk_level = "LOW"
        action = "ALLOW"
        confidence = 0.90

    inconsistency_analysis = " ".join(inconsistency_notes) if inconsistency_notes else (
        "Representations are mutually consistent. No significant divergence detected between DOM, visual OCR, and URL."
    )

    if phishing_intent:
        brand_desc = f" targeting '{brand_impersonated}'" if brand_impersonated else ""
        reasoning_summary = (
            f"Page exhibits deceptive phishing characteristics{brand_desc}. "
            f"Identified discrepancies and credential-harvesting cues indicate an adversarial spoofing attempt. "
            f"Recommended defensive action: {action}."
        )
    else:
        reasoning_summary = (
            f"Page shows no coherent pattern of credential harvesting or brand impersonation. "
            f"Registered domain '{evidence.registered_domain}' appears consistent with page contents. "
            f"Assessed risk level: {risk_level}."
        )

    return SLMReasoningResult(
        phishing_intent_detected=phishing_intent,
        risk_level=risk_level,
        target_brand=brand_impersonated,
        confidence_score=confidence,
        deception_techniques=sorted(list(set(deception_techniques))),
        inconsistency_analysis=inconsistency_analysis,
        reasoning_summary=reasoning_summary,
        recommended_action=action,
    )
