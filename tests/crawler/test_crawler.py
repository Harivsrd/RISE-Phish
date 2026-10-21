"""Comprehensive test suite for Phase 1 Playwright Web Crawler.
"""
import os
import pytest
import urllib.parse
from backend.app.crawler.browser import BrowserManager
from backend.app.crawler.collector import collect_page, validate_url


def test_validate_url_accepts_valid_urls():
    """Verify standard HTTP, HTTPS, and data URLs pass validation."""
    valid_cases = [
        "https://example.com",
        "http://sub.domain.example.com/path?query=1",
        "https://login.example.org:8443/auth/login",
        "data:text/html,<html><body>Hello</body></html>",
    ]
    for url in valid_cases:
        is_valid, reason = validate_url(url)
        assert is_valid is True, f"Failed for valid URL {url}: {reason}"
        assert reason is None


def test_validate_url_rejects_dangerous_or_malformed_urls():
    """Verify unauthorized schemes, missing hosts, or empty URLs are rejected."""
    invalid_cases = [
        ("", "non-empty string"),
        ("file:///etc/passwd", "Unsupported scheme"),
        ("javascript:alert(1)", "Unsupported scheme"),
        ("ftp://ftp.example.com/file", "Unsupported scheme"),
        ("http://", "hostname is missing"),
        ("not_a_url", "Missing scheme"),
    ]
    for url, expected_err in invalid_cases:
        is_valid, reason = validate_url(url)
        assert is_valid is False, f"Expected {url} to be invalid"
        assert expected_err in reason


@pytest.mark.asyncio
async def test_collect_page_synthetic_html():
    """Test full crawler pipeline using an inline data: URL.
    
    Verifies:
    - DOM extraction
    - Title parsing
    - Form and credential (password) identification
    - Interactive button detection
    - Screenshot creation and disk persistence
    """
    synthetic_html = """
    <!DOCTYPE html>
    <html>
    <head><title>Secure Account Verification</title></head>
    <body>
        <h1>Please Verify Your Credentials</h1>
        <p>Your session has expired. Enter your email and password below to continue.</p>
        <a href="https://example.com/terms">Terms and Privacy</a>
        <form action="/auth/login" method="post" id="loginForm">
            <input type="text" name="username" id="user_id" placeholder="User ID" />
            <input type="password" name="passwd" id="user_pwd" placeholder="Password" />
            <button type="submit">Log In</button>
        </form>
    </body>
    </html>
    """
    encoded_url = "data:text/html;charset=utf-8," + urllib.parse.quote(synthetic_html)

    result = await collect_page(
        url=encoded_url,
        capture_screenshot=True,
        timeout_ms=15000,
    )

    # 1. Verify general execution success
    assert result.success is True
    assert result.error_type is None
    assert result.title == "Secure Account Verification"

    # 2. Verify HTML and visible text extraction
    assert "<form" in result.html.lower()
    assert "Your session has expired" in result.visible_text

    # 3. Verify Links and Buttons
    assert any("terms" in link for link in result.links)
    assert any("Log In" in btn for btn in result.buttons)

    # 4. Verify Form extraction
    assert len(result.forms) == 1
    form = result.forms[0]
    assert form.method == "post"
    assert form.id == "loginForm"
    assert form.has_password is True
    assert len(form.inputs) == 2

    # 5. Verify Password Field detection
    assert len(result.password_fields) == 1
    pwd_field = result.password_fields[0]
    assert pwd_field.name == "passwd"
    assert pwd_field.input_type == "password"
    assert pwd_field.is_password is True

    # 6. Verify Screenshot existence and validity
    assert result.screenshot_path is not None
    assert os.path.exists(result.screenshot_path)
    assert os.path.getsize(result.screenshot_path) > 0

    # Cleanup temporary screenshot
    if os.path.exists(result.screenshot_path):
        os.remove(result.screenshot_path)


@pytest.mark.asyncio
async def test_collect_page_graceful_dns_failure():
    """Verify that network/DNS failures return a structured failure result without crashing."""
    bogus_url = "https://this-fake-phishing-test-domain-never-resolves-1234987.com/login"
    result = await collect_page(url=bogus_url, timeout_ms=5000)

    assert result.success is False
    assert result.error_type in ["dns_failure", "connection_error", "timeout"]
    assert result.error_message is not None
    assert result.input_url == bogus_url


@pytest.mark.asyncio
async def test_collect_page_invalid_scheme():
    """Verify that invalid schemes fail before browser invocation."""
    file_url = "file:///C:/Windows/System32/drivers/etc/hosts"
    result = await collect_page(url=file_url)

    assert result.success is False
    assert result.error_type == "invalid_url"
    assert "Unsupported scheme" in result.error_message


@pytest.mark.asyncio
async def test_browser_manager_context_security_flags():
    """Verify that BrowserManager provides isolated ephemeral contexts."""
    manager = BrowserManager(headless=True)
    async with manager.get_context() as context:
        assert context is not None
        page = await context.new_page()
        # Ensure page operates normally in sandbox
        await page.goto("about:blank")
        content = await page.content()
        assert "<html>" in content
        await page.close()
