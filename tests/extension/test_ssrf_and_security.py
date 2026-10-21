"""Security and SSRF test suite for RISE-Phish v2 extension integration.
"""
import pytest
from backend.app.core.ssrf import is_ssrf_safe, validate_url_syntax


def test_ssrf_disallowed_schemes():
    """Verify non-HTTP/HTTPS schemes are blocked before resolution."""
    bad_urls = [
        "file:///C:/Windows/System32/drivers/etc/hosts",
        "gopher://127.0.0.1:70/1",
        "ftp://ftp.example.com/file.txt",
        "javascript:alert(1)",
        "data:text/html,<h1>Test</h1>",
    ]
    for url in bad_urls:
        safe, reason, _ = is_ssrf_safe(url)
        assert safe is False, f"Scheme in '{url}' should be blocked."
        assert reason is not None


def test_ssrf_cloud_metadata_blocked():
    """Verify AWS/GCP/Azure cloud metadata endpoints are strictly blocked."""
    metadata_targets = [
        "http://169.254.169.254/latest/meta-data",
        "https://169.254.169.254/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1",
        "http://instance-data/latest/meta-data",
    ]
    for target in metadata_targets:
        safe, reason, _ = is_ssrf_safe(target)
        assert safe is False, f"Target '{target}' must be blocked by SSRF filter."
        assert "metadata" in reason.lower() or "link-local" in reason.lower()


def test_ssrf_loopback_blocked_by_default():
    """Verify loopback addresses are blocked when allow_loopback is False."""
    loopback_urls = [
        "http://127.0.0.1:8000/api",
        "http://127.0.0.2:9000",
        "http://localhost:5000/admin",
    ]
    for url in loopback_urls:
        safe, reason, _ = is_ssrf_safe(url, allow_loopback=False)
        assert safe is False, f"Loopback '{url}' must be blocked by default."
        assert "loopback" in reason.lower() or "ssrf" in reason.lower()


def test_ssrf_private_rf1918_blocked():
    """Verify private internal subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) are blocked."""
    private_ips = [
        "http://10.0.0.1/admin",
        "http://10.254.1.1:8080",
        "http://172.16.0.1/internal",
        "http://172.31.255.255",
        "http://192.168.1.1/router",
        "http://192.168.100.50",
    ]
    for url in private_ips:
        safe, reason, _ = is_ssrf_safe(url, allow_private=False)
        assert safe is False, f"Private address '{url}' must be blocked."
        assert "private" in reason.lower() or "rfc 1918" in reason.lower()


def test_ssrf_allow_loopback_override_for_internal_tests():
    """Verify allow_loopback=True flag permits local resolution when explicitly enabled for unit tests."""
    safe, reason, ips = is_ssrf_safe("http://127.0.0.1:8000/test", allow_loopback=True)
    assert safe is True
    assert "127.0.0.1" in ips
    assert reason is None


def test_url_syntax_validation():
    """Verify maximum length and syntax boundaries."""
    assert validate_url_syntax("")[0] is False
    assert validate_url_syntax("not-a-url")[0] is False
    assert validate_url_syntax("http://")[0] is False
    assert validate_url_syntax("http://" + "a" * 5000 + ".com")[0] is False
    assert validate_url_syntax("https://example.com/path")[0] is True
