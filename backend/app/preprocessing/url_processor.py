"""URL feature extraction and lexical risk analysis module.

Extracts syntactic components, IP address usage, Punycode/IDN homograph indicators,
percent-encoding anomalies, character entropy, and suspicious structural patterns.
"""
import ipaddress
import math
import re
from typing import List, Optional, Set, Tuple
from urllib.parse import unquote, urlsplit

import tldextract

from backend.app.core.logging import logger
from backend.app.models.schemas import URLFeatures

# Set of TLDs historically correlated with elevated phishing/abuse or disposable domains
SUSPICIOUS_TLDS: Set[str] = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "work", "loan", "click",
    "country", "stream", "download", "racing", "science", "party", "gdn",
    "kim", "men", "bid", "vip", "fit", "buzz"
}

# High-risk keywords commonly used in phishing subdomains or paths to spoof services
SUSPICIOUS_KEYWORDS: Set[str] = {
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "secure", "security", "account", "update", "banking", "billing",
    "confirm", "confirmation", "wallet", "support", "service", "portal",
    "password", "credential", "authenticate", "auth", "recover", "unlock",
    "re-verify", "webscr", "ebayisapi"
}

# Pre-compiled regex for percent-encoding detection
PERCENT_ENCODING_REGEX = re.compile(r"%[0-9a-fA-F]{2}")

# Offline-safe TLDExtract instance (does not block on remote suffix downloads)
_extractor = tldextract.TLDExtract(suffix_list_urls=None)


def calculate_shannon_entropy(text: str) -> float:
    """Calculates Shannon entropy in bits for a given character sequence.
    
    Higher values indicate random strings / DGAs (Domain Generation Algorithms).
    """
    if not text:
        return 0.0

    length = len(text)
    freq: dict = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1

    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 4)


def detect_ip_address(host: str) -> Tuple[bool, bool, bool]:
    """Determines whether a host string represents an IP address.

    Returns:
        (has_ip, is_ipv4, is_ipv6)
    """
    if not host:
        return False, False, False

    clean_host = host.strip("[]")  # Strip brackets for IPv6 notation
    try:
        ip = ipaddress.ip_address(clean_host)
        if isinstance(ip, ipaddress.IPv4Address):
            return True, True, False
        elif isinstance(ip, ipaddress.IPv6Address):
            return True, False, True
    except ValueError:
        pass

    return False, False, False


def analyze_url(
    url: str,
    redirect_count: int = 0,
) -> URLFeatures:
    """Performs deep lexical and syntactic analysis of a target URL.

    Args:
        url: The URL string to inspect.
        redirect_count: Number of observed redirects leading to this URL.

    Returns:
        Strongly-typed URLFeatures model with structured risk reasons.
    """
    if not url or not isinstance(url, str):
        logger.warning("Empty or invalid URL provided to analyze_url.")
        return URLFeatures(
            raw_url="",
            url_length=0,
            scheme="",
            hostname="",
            registered_domain="",
            subdomain="",
            path="",
            query="",
            tld="",
        )

    raw_url = url.strip()
    url_length = len(raw_url)

    # 1. Parse URL components
    parsed = urlsplit(raw_url)
    scheme = parsed.scheme.lower()

    # urlsplit extracts actual hostname (handles userinfo like user@host correctly)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path
    query = parsed.query

    # 2. Decompose domain with tldextract
    extracted = _extractor(hostname)
    subdomain = extracted.subdomain
    # Use top_domain_under_public_suffix without triggering deprecated property evaluation
    if hasattr(extracted, "top_domain_under_public_suffix"):
        registered_domain = extracted.top_domain_under_public_suffix
    else:
        registered_domain = extracted.registered_domain
    tld = extracted.suffix.lower()

    # 3. Basic character counts
    num_dots = raw_url.count(".")
    num_hyphens = raw_url.count("-")
    num_digits = sum(c.isdigit() for c in raw_url)
    # Special characters outside standard URL separators
    num_special_chars = len(re.findall(r"[^a-zA-Z0-9\-_./?:=&%#]", raw_url))

    # 4. Anomaly flags
    has_at_symbol = "@" in raw_url
    has_ip, is_ipv4, is_ipv6 = detect_ip_address(hostname)

    # Percent encoding
    encoded_matches = PERCENT_ENCODING_REGEX.findall(raw_url)
    has_percent_encoding = len(encoded_matches) > 0
    percent_encoding_count = len(encoded_matches)

    # Punycode / IDN detection
    has_punycode = "xn--" in hostname
    punycode_decoded_domain: Optional[str] = None
    if has_punycode:
        try:
            punycode_decoded_domain = hostname.encode("ascii").decode("idna")
        except Exception as puny_exc:
            logger.debug(f"Punycode decode error on '{hostname}': {puny_exc}")
            punycode_decoded_domain = None

    # Subdomain depth
    subdomain_parts = [p for p in subdomain.split(".") if p]
    subdomain_parts_count = len(subdomain_parts)

    # Shannon Entropy of hostname
    shannon_entropy = calculate_shannon_entropy(hostname)

    # Suspicious TLD
    suspicious_tld = tld in SUSPICIOUS_TLDS

    # Keyword hunting across subdomain and path
    searchable_url_text = f"{subdomain}.{path}.{query}".lower()
    keywords_found = [
        kw for kw in SUSPICIOUS_KEYWORDS 
        if re.search(rf"\b{re.escape(kw)}\b", searchable_url_text) or kw in searchable_url_text
    ]
    unique_keywords = list(dict.fromkeys(keywords_found))

    # 5. Synthesize Lexical Risk Score & Structured Reasons
    risk_score = 0.0
    risk_reasons: List[str] = []

    if has_ip:
        risk_score += 0.45
        risk_reasons.append(f"Host uses direct IP address ({hostname}) instead of a registered domain.")

    if has_at_symbol:
        risk_score += 0.35
        risk_reasons.append("URL contains '@' symbol, which can mislead users about the actual destination host.")

    if has_punycode:
        risk_score += 0.30
        risk_reasons.append(
            f"Host uses Punycode IDN encoding ({hostname} -> {punycode_decoded_domain or 'unknown'}), "
            "often indicative of character homoglyph attacks."
        )

    if suspicious_tld:
        risk_score += 0.20
        risk_reasons.append(f"TLD '.{tld}' is associated with elevated rates of abuse or disposable hosting.")

    if subdomain_parts_count >= 3:
        risk_score += 0.25
        risk_reasons.append(f"Excessive subdomain depth ({subdomain_parts_count} labels in '{subdomain}').")

    if unique_keywords:
        risk_score += min(0.35, 0.15 * len(unique_keywords))
        risk_reasons.append(f"Phishing-correlated keywords identified in URL: {', '.join(unique_keywords)}.")

    if url_length > 100:
        risk_score += 0.15
        risk_reasons.append(f"Abnormally long URL ({url_length} characters).")

    if num_dots > 4 and not has_ip:
        risk_score += 0.15
        risk_reasons.append(f"High dot count ({num_dots} dots).")

    if hostname.count("-") >= 3:
        risk_score += 0.15
        risk_reasons.append(f"Excessive hyphenation in hostname ({hostname.count('-')} hyphens in '{hostname}').")

    if shannon_entropy > 3.8 and len(hostname) > 12:
        risk_score += 0.20
        risk_reasons.append(f"High hostname entropy ({shannon_entropy} bits), suggesting randomized generation.")

    if percent_encoding_count >= 3:
        risk_score += 0.10
        risk_reasons.append(f"Multiple percent-encoded characters ({percent_encoding_count} occurrences).")

    # Bound risk score between 0.0 and 1.0
    normalized_risk_score = round(min(1.0, max(0.0, risk_score)), 4)

    return URLFeatures(
        raw_url=raw_url,
        url_length=url_length,
        scheme=scheme,
        hostname=hostname,
        registered_domain=registered_domain,
        subdomain=subdomain,
        path=path,
        query=query,
        tld=tld,
        num_dots=num_dots,
        num_hyphens=num_hyphens,
        num_digits=num_digits,
        num_special_chars=num_special_chars,
        has_at_symbol=has_at_symbol,
        has_ip_address=has_ip,
        is_ipv4=is_ipv4,
        is_ipv6=is_ipv6,
        has_percent_encoding=has_percent_encoding,
        percent_encoding_count=percent_encoding_count,
        has_punycode=has_punycode,
        punycode_decoded_domain=punycode_decoded_domain,
        redirect_count=redirect_count,
        subdomain_parts_count=subdomain_parts_count,
        shannon_entropy=shannon_entropy,
        suspicious_tld=suspicious_tld,
        suspicious_keywords_found=unique_keywords,
        url_risk_score=normalized_risk_score,
        risk_reasons=risk_reasons,
    )
