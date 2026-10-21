"""Brand identification and Brand-to-Domain discrepancy detection module.

Maps detected entity claims in page content against the actual registered
domain authority in R5 to detect brand spoofing and impersonation.
"""
import re
from typing import Dict, List, Optional, Set, Tuple

from backend.app.models.schemas import DiscrepancyFinding, URLRepresentation

# Canonical legitimate domains for high-profile target brands
TARGET_BRAND_CANONICAL_DOMAINS: Dict[str, Set[str]] = {
    "microsoft": {
        "microsoft.com", "live.com", "office.com", "outlook.com", "msn.com",
        "microsoftonline.com", "skype.com", "bing.com", "xbox.com",
        "linkedin.com", "licdn.com", "github.com", "github.io"
    },
    "apple": {"apple.com", "icloud.com", "me.com", "mzstatic.com"},
    "google": {
        "google.com", "gmail.com", "youtube.com", "googleblog.com",
        "kaggle.com", "blogger.com", "android.com", "googleusercontent.com", "gstatic.com"
    },
    "linkedin": {"linkedin.com", "licdn.com"},
    "kaggle": {"kaggle.com"},
    "github": {"github.com", "github.io", "githubassets.com"},
    "paypal": {"paypal.com", "paypal-communication.com", "paypalobjects.com"},
    "netflix": {"netflix.com"},
    "amazon": {"amazon.com", "aws.amazon.com", "amazon.co.uk", "amazon.de"},
    "facebook": {"facebook.com", "meta.com", "fb.com", "instagram.com", "whatsapp.com", "threads.net"},
    "instagram": {"instagram.com"},
    "chase": {"chase.com", "jpmorganchase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com", "bofa.com"},
    "dropbox": {"dropbox.com"},
    "adobe": {"adobe.com"},
    "dhl": {"dhl.com", "dhl-express.com"},
    "usps": {"usps.com"},
    "twitter": {"twitter.com", "x.com", "t.co"},
}


OAUTH_AND_SOCIAL_PATTERNS = [
    r"\b(?:sign\s*in|log\s*in|continue|auth(?:enticate)?)\s+with\s+(?:google|apple|facebook|microsoft|github|linkedin)\b",
    r"\b(?:download|get\s*it|available)\s+(?:on|at)\s+(?:google\s*play|apple\s*app\s*store|app\s*store)\b",
    r"\b(?:follow|like|connect|share)\s+(?:on|with)\s+(?:twitter|facebook|linkedin|instagram|youtube)\b",
    r"\bcopyright\s+(?:©|\(c\))?\s*\d{4}\s+(?:microsoft|google|apple|meta|facebook)\b",
]


def identify_claimed_brand(
    text_content: str,
    explicit_brand: Optional[str] = None,
    registered_domain: Optional[str] = None,
) -> Optional[str]:
    """Identifies if any monitored brand name is claimed in the provided text.

    Args:
        text_content: Searchable text (e.g. title, headings, or OCR text).
        explicit_brand: Pre-detected or manually specified brand target.
        registered_domain: Optional registered domain of the page to contextualize identity.

    Returns:
        Brand name string (lowercase) or None.
    """
    if explicit_brand:
        return explicit_brand.lower().strip()

    if not text_content:
        return None

    # 1. Domain alignment: If registered_domain directly matches a known canonical brand, check if that brand is claimed
    if registered_domain:
        reg_clean = registered_domain.lower().strip()
        for brand, canonicals in TARGET_BRAND_CANONICAL_DOMAINS.items():
            if reg_clean in canonicals:
                if re.search(rf"\b{re.escape(brand)}\b", text_content, re.IGNORECASE):
                    return brand

    # 2. Strip standard third-party OAuth, app store, and footer mentions to avoid false brand hijacking
    sanitized_text = text_content
    for pattern in OAUTH_AND_SOCIAL_PATTERNS:
        sanitized_text = re.sub(pattern, " ", sanitized_text, flags=re.IGNORECASE)

    lower_text = sanitized_text.lower()
    for brand in TARGET_BRAND_CANONICAL_DOMAINS.keys():
        # Word boundary match to prevent partial substring matches (e.g., 'chase' in 'purchase')
        if re.search(rf"\b{re.escape(brand)}\b", lower_text):
            return brand

    return None


def calculate_brand_domain_discrepancy(
    claimed_brand: Optional[str],
    url_repr: URLRepresentation,
) -> Tuple[float, Optional[DiscrepancyFinding]]:
    """Evaluates discrepancy between a claimed brand and the actual domain in R5.

    Returns:
        (discrepancy_score, finding) where discrepancy_score is in [0.0, 1.0].
    """
    if not claimed_brand:
        return 0.0, None

    brand = claimed_brand.lower()
    registered_domain = (url_repr.registered_domain or "").lower()
    hostname = (url_repr.hostname or "").lower()

    canonical_domains = TARGET_BRAND_CANONICAL_DOMAINS.get(brand, {f"{brand}.com"})

    # Case 1: Legitimate match - registered domain is in brand's canonical domains
    if registered_domain in canonical_domains:
        return 0.0, None

    # Case 2: Subdomain brand spoofing
    # e.g., 'paypal' is present in subdomain, but registered domain is 'security-portal.xyz'
    if brand in url_repr.domain_tokens and brand not in registered_domain:
        finding = DiscrepancyFinding(
            source="r4_semantic",
            target="r5_url",
            discrepancy_type="brand_domain_mismatch",
            severity=0.95,
            supporting_evidence=(
                f"Severe Brand Impersonation: Page claims brand '{brand.capitalize()}', "
                f"which appears in subdomain '{url_repr.subdomain}', "
                f"but destination is an unrelated domain '{registered_domain}'."
            ),
        )
        return 0.95, finding

    # Case 3: Complete brand mismatch
    # Page claims brand, but registered domain has zero relation
    finding = DiscrepancyFinding(
        source="r4_semantic",
        target="r5_url",
        discrepancy_type="brand_domain_mismatch",
        severity=0.85,
        supporting_evidence=(
            f"Brand Discrepancy: Webpage claims '{brand.capitalize()}', "
            f"but registered domain '{registered_domain or hostname}' is not an authorized canonical domain."
        ),
    )
    return 0.85, finding
