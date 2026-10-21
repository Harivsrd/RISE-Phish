"""Comprehensive test suite for Phase 3 URL Analyzer.
"""
import pytest
from backend.app.preprocessing.url_processor import (
    analyze_url,
    calculate_shannon_entropy,
    detect_ip_address,
)


def test_detect_ip_address():
    """Verify IPv4 and IPv6 detection."""
    assert detect_ip_address("192.168.1.1") == (True, True, False)
    assert detect_ip_address("10.0.0.1") == (True, True, False)
    assert detect_ip_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == (True, False, True)
    assert detect_ip_address("[::1]") == (True, False, True)
    assert detect_ip_address("example.com") == (False, False, False)
    assert detect_ip_address("") == (False, False, False)


def test_calculate_shannon_entropy():
    """Verify entropy bounds and calculation."""
    # Zero entropy for identical repeated characters
    assert calculate_shannon_entropy("aaaaaaa") == 0.0
    assert calculate_shannon_entropy("") == 0.0

    # Varied characters produce positive entropy
    low_entropy = calculate_shannon_entropy("google.com")
    high_entropy = calculate_shannon_entropy("7f9x2k1m8b0zp4q")
    assert high_entropy > low_entropy
    assert high_entropy > 3.0


def test_analyze_url_legitimate():
    """Verify legitimate URL parsing results in low risk and clean domain extraction."""
    url = "https://www.microsoft.com/en-us/software-download"
    features = analyze_url(url)

    assert features.scheme == "https"
    assert features.hostname == "www.microsoft.com"
    assert features.registered_domain == "microsoft.com"
    assert features.subdomain == "www"
    assert features.tld == "com"
    assert features.has_ip_address is False
    assert features.has_at_symbol is False
    assert features.has_punycode is False
    assert features.suspicious_tld is False
    assert features.url_risk_score < 0.25


def test_analyze_url_ip_host():
    """Verify raw IP host triggers elevated risk indicators."""
    url = "http://192.168.0.10:8080/auth/login"
    features = analyze_url(url)

    assert features.has_ip_address is True
    assert features.is_ipv4 is True
    assert features.hostname == "192.168.0.10"
    assert "login" in features.suspicious_keywords_found
    assert features.url_risk_score >= 0.45
    assert any("IP address" in reason for reason in features.risk_reasons)


def test_analyze_url_at_symbol_credential_confusion():
    """Verify '@' symbol in URL is flagged as high-risk deceptive syntax."""
    url = "https://legitimate-bank.com@malicious-harvest.xyz/account/login"
    features = analyze_url(url)

    assert features.has_at_symbol is True
    assert features.hostname == "malicious-harvest.xyz"
    assert features.suspicious_tld is True  # .xyz is flagged
    assert features.url_risk_score >= 0.50
    assert any("@" in reason for reason in features.risk_reasons)


def test_analyze_url_punycode_idn_homograph():
    """Verify Punycode IDN homograph domains are detected and decoded."""
    # xn--microsft-7za.com is "microsоft.com" with Cyrillic small letter 'о'
    url = "https://xn--microsft-7za.com/security/verify"
    features = analyze_url(url)

    assert features.has_punycode is True
    assert features.punycode_decoded_domain is not None
    assert "verify" in features.suspicious_keywords_found
    assert features.url_risk_score >= 0.40
    assert any("Punycode" in reason for reason in features.risk_reasons)


def test_analyze_url_excessive_subdomain_and_suspicious_tld():
    """Verify deep subdomain nesting, keywords, and suspicious TLDs accumulate risk."""
    url = "http://account.verification.update.paypal.support.phish-portal.tk/confirm"
    features = analyze_url(url)

    assert features.subdomain_parts_count >= 5
    assert features.suspicious_tld is True  # .tk
    assert "verification" in features.suspicious_keywords_found
    assert "update" in features.suspicious_keywords_found
    assert "confirm" in features.suspicious_keywords_found
    assert features.url_risk_score >= 0.60
    assert len(features.risk_reasons) >= 3


def test_analyze_url_empty_and_malformed():
    """Verify empty or non-string inputs are handled without throwing unhandled exceptions."""
    empty_features = analyze_url("")
    assert empty_features.url_length == 0
    assert empty_features.url_risk_score == 0.0

    none_features = analyze_url(None)
    assert none_features.url_length == 0
    assert none_features.url_risk_score == 0.0
