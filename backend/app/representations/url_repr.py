"""R5: URL representation generator.

Encapsulates lexical, syntactic, and domain token representations from URL features.
"""
import re
from typing import List, Optional

from backend.app.models.schemas import URLFeatures, URLRepresentation


def build_url_representation(
    url_features: Optional[URLFeatures],
) -> URLRepresentation:
    """Builds R5 URLRepresentation from extracted URL features.

    Args:
        url_features: Processed URLFeatures model from Phase 3.

    Returns:
        Structured URLRepresentation instance.
    """
    if not url_features:
        return URLRepresentation(
            raw_url="",
            hostname="",
            registered_domain="",
            subdomain="",
            path="",
            tld="",
            domain_tokens=[],
        )

    # Break domain and subdomains into individual lexical tokens
    # e.g., 'login.microsoft.security-verify.com' -> ['login', 'microsoft', 'security', 'verify', 'com']
    tokens = re.split(r"[\.\-_]", url_features.hostname)
    cleaned_tokens = [t.lower() for t in tokens if t and not t.isdigit()]

    return URLRepresentation(
        raw_url=url_features.raw_url,
        hostname=url_features.hostname,
        registered_domain=url_features.registered_domain,
        subdomain=url_features.subdomain,
        path=url_features.path,
        tld=url_features.tld,
        punycode_decoded=url_features.punycode_decoded_domain,
        domain_tokens=cleaned_tokens,
    )
