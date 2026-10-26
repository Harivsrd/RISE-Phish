"""Message and email phishing detection service for RISE-Phish v2.

Orchestrates multi-signal analysis of emails and web messages:
1. Sender Authenticity & Brand Spoofing Analysis
2. Embedded Link Lexical Forensics & Link-Text Discrepancy (Anchor Hijacking)
3. Urgency & Coercive Social Engineering Detection
4. Unicode Homoglyph & Script Mixing Identification
5. SSRF-Safe Embedded URL Security Evaluation (Reusing RISE-Phish URL Pipeline)
6. Calibrated Evidence Synthesis & Decision Policy
"""
import hashlib
import logging
import re
from typing import Dict, List, Optional, Set, Tuple
import uuid
from urllib.parse import urlparse

from backend.app.api.service import analyze_url_pipeline
from backend.app.core.config import get_settings
from backend.app.core.ssrf import is_ssrf_safe, validate_url_syntax
from backend.app.crce.brand_detector import (
    TARGET_BRAND_CANONICAL_DOMAINS,
    identify_claimed_brand,
)
from backend.app.models.extension_schemas import (
    ExtractedLinkVerdict,
    MessageAnalysisRequest,
    MessageAnalysisResponse,
    MessageEmbeddedLink,
    MessageIndicators,
)
from backend.app.models.schemas import DefensiveAction, ThreatVerdict
from backend.app.preprocessing.unicode_processor import analyze_unicode
from backend.app.preprocessing.url_processor import analyze_url

logger = logging.getLogger("rise_phish.message_service")
settings = get_settings()

# Urgency, fear, and coercive social engineering trigger lexicons
URGENCY_TRIGGERS: List[Tuple[str, float]] = [
    (r"\baccount\s+(?:suspended|locked|terminated|disabled)\b", 0.35),
    (r"\bverify\s+(?:immediately|now|within\s+\d+\s+hours?)\b", 0.30),
    (r"\bunauthorized\s+(?:access|activity|transaction|login)\b", 0.30),
    (r"\baction\s+required\b", 0.20),
    (r"\bfailure\s+to\s+(?:respond|verify|update)\b", 0.25),
    (r"\bupdate\s+(?:payment|billing|credit\s+card|credentials)\b", 0.25),
    (r"\bsecurity\s+alert\b", 0.15),
    (r"\burgent\s+notice\b", 0.25),
    (r"\bconfirm\s+your\s+identity\b", 0.25),
    (r"\bprevent\s+(?:closure|deletion)\b", 0.30),
]

# Benign transactional and notification patterns that dampen false urgency alarms
BENIGN_TRANSACTIONAL_PATTERNS: List[Tuple[str, float]] = [
    (r"\border\s*#?\s*\d+", 0.25),
    (r"\b(?:view|download)\s+(?:your\s+)?(?:receipt|invoice|statement)\b", 0.25),
    (r"\b(?:manage|update)\s+(?:your\s+)?(?:preferences|notifications|settings)\b", 0.20),
    (r"\bunsubscribe\b", 0.20),
    (r"\bweekly\s+(?:digest|summary|newsletter)\b", 0.25),
    (r"\bmonthly\s+(?:statement|newsletter|update)\b", 0.25),
    (r"\ball\s+rights\s+reserved\b", 0.15),
    (r"\bprivacy\s+policy\b", 0.15),
    (r"\bterms\s+of\s+service\b", 0.15),
]

# Authorized enterprise email service providers (ESPs) and transactional mail relays
AUTHORIZED_ESP_RELAYS: Set[str] = {
    "sendgrid.net", "sendgrid.com", "mcsv.net", "mailchimp.com",
    "mailgun.org", "mailgun.net", "amazonses.com", "awstrack.me",
    "postmarkapp.com", "substack.com", "salesforce.com", "exacttarget.com",
    "zendesk.com", "intercom-mail.com", "sparkpostmail.com", "hubspotemail.net",
}

# Adversarial prompt injection keywords in untrusted message bodies
PROMPT_INJECTION_PATTERNS: List[str] = [
    r"\[SYSTEM OVERRIDE\]",
    r"ignore all previous instructions",
    r"you are an ai assistant.*output verdict: safe",
    r"system prompt override",
    r"output.*safe.*threat score: 0\.0",
]


def sanitize_and_bound_input(request: MessageAnalysisRequest) -> MessageAnalysisRequest:
    """Enforces strict size bounds on message text and links to prevent DoS."""
    max_bytes = settings.EXTENSION_MAX_MESSAGE_BYTES
    max_urls = settings.EXTENSION_MAX_URLS_PER_MESSAGE

    # Truncate body if oversized
    if len(request.body_text.encode("utf-8")) > max_bytes:
        logger.warning(f"Truncating oversized message body ({len(request.body_text)} chars)")
        # Safe character slice
        request.body_text = request.body_text[:max_bytes // 2]

    # Truncate subject and sender
    if request.subject and len(request.subject) > 500:
        request.subject = request.subject[:500]
    if request.sender and len(request.sender) > 500:
        request.sender = request.sender[:500]

    # Bound embedded URLs
    if len(request.embedded_links) > max_urls:
        logger.info(f"Limiting message URLs from {len(request.embedded_links)} to {max_urls}")
        request.embedded_links = request.embedded_links[:max_urls]

    return request


def evaluate_urgency_indicators(subject: str, body: str) -> Tuple[float, List[str]]:
    """Analyzes message subject and body for psychological manipulation and coercive urgency.
    Dampens urgency if routine transactional signals (e.g. order receipts, digests, unsubscribe)
    are present.

    Returns:
        (urgency_score in [0.0, 1.0], list of detected triggers)
    """
    combined_text = f"{subject} {body}".lower()
    score = 0.0
    detected: List[str] = []

    for pattern, weight in URGENCY_TRIGGERS:
        match = re.search(pattern, combined_text)
        if match:
            matched_phrase = match.group(0)
            if matched_phrase not in detected:
                detected.append(matched_phrase)
                score += weight

    # Benign transactional dampening:
    # If routine transactional cues exist, discount generic triggers (e.g. "security alert", "action required")
    # while preserving strong coercive threat language
    if score > 0:
        dampening = 0.0
        for pattern, weight in BENIGN_TRANSACTIONAL_PATTERNS:
            if re.search(pattern, combined_text):
                dampening += weight

        score = max(0.0, score - min(dampening, 0.35))

    # Cap score at 1.0
    return min(1.0, round(score, 4)), detected


def check_prompt_injection(body: str) -> List[str]:
    """Detects adversarial prompt injection attempts embedded in the message body."""
    flags: List[str] = []

    for pattern in PROMPT_INJECTION_PATTERNS:
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            flags.append(f"Prompt injection pattern detected: '{match.group(0)}'")

    return flags


def evaluate_sender_authenticity(
    sender_raw: str,
    sender_address: str,
) -> Tuple[bool, Optional[str], Optional[str]]:
    """Detects brand spoofing where sender display name mimics a brand but domain differs.

    Example:
        Display Name: "PayPal Security Support"
        Address: "support@billing-update-994.xyz"
        -> Discrepancy detected: Claims PayPal but domain is billing-update-994.xyz

    Returns:
        (is_discrepancy, finding_description, claimed_brand)
    """
    if not sender_raw and not sender_address:
        return False, None, None

    # Identify brand claimed in the display name
    claimed_brand = identify_claimed_brand(sender_raw)
    if not claimed_brand:
        return False, None, None

    # Extract domain from email address
    email_domain = ""
    if "@" in sender_address:
        email_domain = sender_address.split("@")[-1].lower().strip()
    elif "@" in sender_raw:
        # Extract from raw string like "PayPal <support@domain.com>"
        match = re.search(r"@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", sender_raw)
        if match:
            email_domain = match.group(1).lower().strip()

    if not email_domain:
        return False, None, claimed_brand

    # Check if domain belongs to the claimed brand's canonical domains
    canonical_domains = TARGET_BRAND_CANONICAL_DOMAINS.get(claimed_brand, set())
    
    # Check exact match or valid subdomain of canonical domain
    is_authorized = any(
        email_domain == c or email_domain.endswith(f".{c}")
        for c in canonical_domains
    )

    if is_authorized:
        return False, None, claimed_brand

    # Check if sending domain is an authorized transactional ESP relay
    is_esp_relay = any(
        email_domain == esp or email_domain.endswith(f".{esp}")
        for esp in AUTHORIZED_ESP_RELAYS
    )
    if is_esp_relay:
        finding = (
            f"Message sent via third-party email relay service '@{email_domain}' on behalf of '{claimed_brand.title()}'."
        )
        return False, finding, claimed_brand

    finding = (
        f"Sender display name impersonates '{claimed_brand.title()}', "
        f"but email is sent from unauthorized domain '@{email_domain}'."
    )
    return True, finding, claimed_brand


def evaluate_link_text_mismatch(link: MessageEmbeddedLink) -> Tuple[bool, str]:
    """Detects anchor text hijacking where displayed text shows a reputable brand/domain
    while the underlying href destination leads to a different domain.

    Example:
        Displayed Text: "https://www.paypal.com/signin"
        Actual URL: "http://malicious-harvest.net/account"
    """
    text = (link.text or "").strip()
    href = link.url.strip()

    if not text:
        return False, ""

    # 1. Check if displayed text explicitly looks like a URL or claims a domain
    url_like_match = re.search(r"(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", text)
    if url_like_match:
        displayed_host = url_like_match.group(1).lower().lstrip("www.")
        href_host = (urlparse(href).hostname or "").lower().lstrip("www.")

        if not href_host:
            return False, ""

        # Extract base registered domains to allow legitimate subdomains (e.g. click.linkedin.com vs linkedin.com)
        disp_parts = displayed_host.split(".")
        href_parts = href_host.split(".")
        disp_root = ".".join(disp_parts[-2:]) if len(disp_parts) >= 2 else displayed_host
        href_root = ".".join(href_parts[-2:]) if len(href_parts) >= 2 else href_host

        # If base roots differ and neither is a subdomain of the other
        if disp_root != href_root and not href_host.endswith(f".{displayed_host}") and not displayed_host.endswith(f".{href_host}"):
            return True, f"Displayed link text claims '{displayed_host}', but destination leads to '{href_host}'."

        return False, ""

    # 2. Check if text explicitly prompts credentials / login for a specific brand
    auth_intent_match = re.search(r"\b(?:sign\s*in|log\s*in|verify|update\s*credentials|re-authenticate)\b", text, re.IGNORECASE)
    if auth_intent_match:
        claimed_brand = identify_claimed_brand(text)
        if claimed_brand:
            href_domain = urlparse(href).hostname or ""
            canonical = TARGET_BRAND_CANONICAL_DOMAINS.get(claimed_brand, set())
            if not any(href_domain == c or href_domain.endswith(f".{c}") for c in canonical):
                return True, f"Link text prompts sign-in for '{claimed_brand.title()}' but target leads to '{href_domain}'."

    return False, ""


async def evaluate_embedded_urls(
    links: List[MessageEmbeddedLink],
    allow_loopback: bool = False,
) -> List[ExtractedLinkVerdict]:
    """Evaluates all embedded links safely against SSRF rules and the URL analysis pipeline."""
    results: List[ExtractedLinkVerdict] = []

    for item in links:
        raw_url = item.url.strip()
        display_text = item.text or ""

        # Check for link-text mismatch
        is_mismatch, mismatch_finding = evaluate_link_text_mismatch(item)

        # 1. SSRF Safety Check
        is_safe, ssrf_err, resolved_ips = is_ssrf_safe(
            raw_url,
            allow_loopback=allow_loopback or settings.SSRF_ALLOW_LOOPBACK_ANALYSIS,
        )

        if not is_safe:
            is_dns_failure = "DNS resolution failed" in (ssrf_err or "") or "No IP addresses" in (ssrf_err or "")
            is_true_ssrf = not is_dns_failure

            finding = f"SSRF Blocked: {ssrf_err}" if is_true_ssrf else f"Host Unreachable: {ssrf_err}"
            if is_mismatch:
                finding += f" | {mismatch_finding}"

            results.append(
                ExtractedLinkVerdict(
                    url=raw_url,
                    displayed_text=display_text,
                    is_mismatch=is_mismatch,
                    ssrf_blocked=is_true_ssrf,
                    verdict=ThreatVerdict.PHISHING if (is_mismatch and is_true_ssrf) else ThreatVerdict.INVESTIGATE,
                    composite_threat_score=0.70 if is_true_ssrf else (0.75 if is_mismatch else 0.25),
                    target_brand=None,
                    finding_summary=finding,
                )
            )
            continue

        # 2. URL Lexical & Heuristic Evaluation
        url_features = analyze_url(raw_url)
        brand = identify_claimed_brand(raw_url)

        # Base score from URL lexical risk
        threat_score = url_features.url_risk_score
        verdict = ThreatVerdict.SAFE

        if is_mismatch:
            threat_score = max(threat_score, 0.75)
            verdict = ThreatVerdict.PHISHING
            finding = f"Anchor Text Spoofing: {mismatch_finding}"
        elif threat_score >= 0.65:
            verdict = ThreatVerdict.PHISHING
            finding = f"High-risk lexical URL indicators (Entropy: {url_features.entropy:.2f})"
        elif threat_score >= 0.35:
            verdict = ThreatVerdict.INVESTIGATE
            finding = "Suspicious URL structure or elevated entropy"
        else:
            finding = "URL syntax and registered domain appear consistent"

        results.append(
            ExtractedLinkVerdict(
                url=raw_url,
                displayed_text=display_text,
                is_mismatch=is_mismatch,
                ssrf_blocked=False,
                verdict=verdict,
                composite_threat_score=round(threat_score, 4),
                target_brand=brand,
                finding_summary=finding,
            )
        )

    return results


async def analyze_message_pipeline(
    request: MessageAnalysisRequest,
) -> MessageAnalysisResponse:
    """Executes the comprehensive message and email phishing analysis pipeline."""
    # 1. Validate & bound input
    bounded_req = sanitize_and_bound_input(request)
    analysis_id = str(uuid.uuid4())

    # 2. Urgency & Coercion Evaluation
    urgency_score, urgency_triggers = evaluate_urgency_indicators(
        subject=bounded_req.subject or "",
        body=bounded_req.body_text,
    )

    # 3. Prompt Injection Defense
    injection_flags = check_prompt_injection(bounded_req.body_text)

    # 4. Sender Authenticity & Brand Spoofing Check
    sender_discrepancy, sender_finding, claimed_brand = evaluate_sender_authenticity(
        sender_raw=bounded_req.sender or "",
        sender_address=bounded_req.sender_address or "",
    )

    # 5. Unicode Homoglyph Analysis on Sender and Body
    combined_content = f"{bounded_req.subject} {bounded_req.sender} {bounded_req.body_text[:2000]}"
    unicode_res = analyze_unicode(combined_content)

    homoglyphs_count = unicode_res.homoglyph_count + unicode_res.zero_width_count + unicode_res.bidi_control_count
    homoglyph_samples = [
        f"{a.character} ({a.script} {a.codepoint})"
        for a in unicode_res.anomalies[:5]
    ]

    # 6. Evaluate Embedded URLs with SSRF Protection
    link_verdicts = await evaluate_embedded_urls(
        links=bounded_req.embedded_links,
        allow_loopback=bounded_req.allow_loopback_for_test,
    )

    # 7. Aggregate Link Statistics
    mismatch_count = sum(1 for link in link_verdicts if link.is_mismatch)
    ssrf_blocked_count = sum(1 for link in link_verdicts if link.ssrf_blocked)
    phishing_links_count = sum(1 for link in link_verdicts if link.verdict == ThreatVerdict.PHISHING)
    max_link_threat = max((link.composite_threat_score for link in link_verdicts), default=0.0)
    all_links_safe = len(link_verdicts) > 0 and all(
        link.verdict == ThreatVerdict.SAFE and not link.is_mismatch and not link.ssrf_blocked
        for link in link_verdicts
    )

    # 8. Multi-Signal Evidence Fusion for Messages
    indicators = MessageIndicators(
        urgency_score=urgency_score,
        urgency_triggers_found=urgency_triggers,
        sender_discrepancy_detected=sender_discrepancy,
        sender_finding=sender_finding,
        link_text_mismatches_count=mismatch_count,
        homoglyphs_detected_count=homoglyphs_count,
        homoglyph_samples=homoglyph_samples,
        prompt_injection_flags=injection_flags,
    )

    # Decision Matrix Calculation
    # Factors contributing to message threat score:
    # - Sender impersonation: +0.40 (or +0.25 if all links are verified safe)
    # - Link-text mismatch: +0.35
    # - Max link threat score: up to +0.45
    # - Urgency score: up to +0.25
    # - Homoglyphs: up to +0.20
    # - Prompt injection: +0.35
    threat_components = []
    threat_components.append(max_link_threat * 0.45)

    if sender_discrepancy:
        threat_components.append(0.25 if all_links_safe else 0.40)
    if mismatch_count > 0:
        threat_components.append(0.35)
    if urgency_score > 0.4:
        threat_components.append(urgency_score * 0.40)
    if homoglyphs_count > 0:
        threat_components.append(min(0.20, homoglyphs_count * 0.05))
    if injection_flags:
        threat_components.append(0.35)

    # Composite Threat Score Calculation
    raw_threat = sum(threat_components)
    composite_threat = min(1.0, round(raw_threat, 4))

    # Determine Operational Verdict and Posture
    key_findings: List[str] = []

    if sender_finding:
        key_findings.append(sender_finding)
    if mismatch_count > 0:
        key_findings.append(f"{mismatch_count} embedded link(s) conceal their true destination (anchor hijacking).")
    if phishing_links_count > 0:
        key_findings.append(f"{phishing_links_count} embedded link(s) classified as high-risk phishing destinations.")
    if urgency_triggers:
        key_findings.append(f"Urgency / coercive language detected: {', '.join(urgency_triggers[:4])}.")
    if homoglyphs_count > 0:
        key_findings.append(f"{homoglyphs_count} non-standard Unicode lookalike characters detected.")
    if injection_flags:
        key_findings.append("Adversarial prompt injection attempt detected inside message body.")
    if ssrf_blocked_count > 0:
        key_findings.append(f"{ssrf_blocked_count} link(s) blocked due to internal/loopback IP restrictions.")

    # Multi-Signal Corroboration Decision Policy:
    # A CONFIRMED PHISHING verdict requires at least ONE definitive threat or TWO corroborated attack signals:
    # 1. Direct confirmed phishing or anchor-hijacked destination (phishing_links_count > 0)
    # 2. Confirmed anchor text hijacking (mismatch_count > 0) corroborated by urgency, sender spoofing, or unverified target
    # 3. Sender brand spoofing corroborated by an unverified/risky link OR severe coercive urgency (>=0.40)
    # 4. Multi-signal convergence (composite_threat >= 0.65) where links are NOT verified safe.
    # Note: If all embedded links are verified 100% safe, sender ambiguity alone cannot trigger CONFIRMED PHISHING.
    is_phishing = (
        phishing_links_count > 0
        or (mismatch_count > 0 and (urgency_score > 0.15 or sender_discrepancy or not all_links_safe))
        or (sender_discrepancy and (max_link_threat > 0.35 or urgency_score >= 0.40 or homoglyphs_count > 0) and not all_links_safe)
        or (composite_threat >= 0.65 and not all_links_safe)
    )

    if is_phishing:
        verdict = ThreatVerdict.PHISHING
        action = DefensiveAction.BLOCK_ACCESS
        headline = "CONFIRMED PHISHING MESSAGE"
        explanation = (
            "This message exhibits definitive deceptive phishing characteristics, including "
            f"{'sender brand impersonation, ' if sender_discrepancy else ''}"
            f"{'mismatched hyperlink targets, ' if mismatch_count > 0 else ''}"
            f"{'high-risk embedded URLs, ' if phishing_links_count > 0 else ''}"
            "and coercive urgency. Do not click any links or provide personal credentials."
        )
    elif composite_threat >= 0.35 or urgency_score >= 0.40 or sender_discrepancy or mismatch_count > 0 or ssrf_blocked_count > 0:
        verdict = ThreatVerdict.INVESTIGATE
        action = DefensiveAction.WARN_USER
        headline = "SUSPICIOUS MESSAGE — PROCEED WITH CAUTION"
        explanation = (
            "This message contains elevated risk signals such as coercive urgency, "
            "unverified sender claims, or suspicious link structures. Inspect links carefully before interacting."
        )
    else:
        verdict = ThreatVerdict.SAFE
        action = DefensiveAction.ALLOW
        headline = "NO PHISHING INDICATORS DETECTED"
        explanation = (
            "The sender identity, visible text, and embedded hyperlinks appear consistent "
            "with standard benign communication. No brand spoofing or deceptive links were found."
        )

    # Privacy preservation: compute SHA-256 fingerprint for audit without storing raw content
    body_hash = hashlib.sha256(bounded_req.body_text.encode("utf-8")).hexdigest()
    logger.info(
        f"Completed message scan {analysis_id} for site '{bounded_req.site_identifier}': "
        f"Verdict={verdict.value}, Threat={composite_threat}, Links={len(link_verdicts)}, BodyHash={body_hash[:12]}..."
    )

    return MessageAnalysisResponse(
        analysis_id=analysis_id,
        verdict=verdict,
        composite_threat_score=composite_threat,
        confidence_score=0.92 if verdict != ThreatVerdict.INVESTIGATE else 0.75,
        recommended_action=action,
        site_identifier=bounded_req.site_identifier,
        indicators=indicators,
        link_analyses=link_verdicts,
        summary_headline=headline,
        explanation=explanation,
        key_findings=key_findings,
        privacy_notice="Zero raw message content is stored on disk or database. Analysis executed ephemerally.",
    )
