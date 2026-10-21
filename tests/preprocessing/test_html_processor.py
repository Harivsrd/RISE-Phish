"""Comprehensive test suite for Phase 2 HTML Feature Processor.
"""
import pytest
from backend.app.preprocessing.html_processor import extract_html_features, clean_text


def test_clean_text():
    """Verify whitespace collapsing and edge trimming."""
    assert clean_text("   Hello   World \n\t  ") == "Hello World"
    assert clean_text(None) == ""
    assert clean_text("") == ""


def test_extract_html_features_structured():
    """Verify extraction of title, headings, paragraphs, buttons, and links."""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Account Security Alert</title>
        <meta name="description" content="Important account verification required">
        <meta property="og:title" content="Security Center">
    </head>
    <body>
        <h1>Immediate Action Required</h1>
        <h2>Verify Identity</h2>
        <p>We detected an unauthorized sign-in attempt from an unrecognized device.</p>
        <p>Please confirm your credentials within 24 hours.</p>
        <a href="/help/support">Customer Support</a>
        <a href="https://legit.org/privacy">Privacy Policy</a>
        <button type="button">Dismiss</button>
        <img src="/static/logo.png" alt="Company Logo" title="Official Logo" />
    </body>
    </html>
    """
    features = extract_html_features(html, base_url="https://example.com")

    # 1. Document title & metadata
    assert features.title == "Account Security Alert"
    assert features.meta_attributes.get("description") == "Important account verification required"
    assert features.meta_attributes.get("og:title") == "Security Center"

    # 2. Headings hierarchy
    assert len(features.headings) == 2
    assert features.headings[0].level == 1
    assert features.headings[0].text == "Immediate Action Required"
    assert features.headings[1].level == 2
    assert features.headings[1].text == "Verify Identity"

    # 3. Paragraphs & visible text
    assert len(features.paragraphs) == 2
    assert "unauthorized sign-in attempt" in features.paragraphs[0]
    assert "Immediate Action Required" in features.visible_text
    assert "Please confirm your credentials" in features.visible_text

    # 4. Links with base_url resolution
    assert "https://example.com/help/support" in features.links
    assert "https://legit.org/privacy" in features.links

    # 5. Buttons and Images
    assert "Dismiss" in features.buttons
    assert len(features.images) == 1
    assert features.images[0].src == "https://example.com/static/logo.png"
    assert features.images[0].alt == "Company Logo"
    assert "Company Logo" in features.alt_texts


def test_credential_and_form_detection():
    """Verify extraction of forms, actions, input fields, and password inputs."""
    html = """
    <html>
    <body>
        <form action="/auth/verify" method="POST" id="login_form">
            <input type="text" name="user_email" placeholder="Enter your email" />
            <input type="password" name="user_password" placeholder="Account password" />
            <input type="submit" value="Sign In Now" />
        </form>
        <input type="text" name="standalone_search" placeholder="Search knowledgebase" />
    </body>
    </html>
    """
    features = extract_html_features(html, base_url="https://secure-portal.com")

    # Form checks
    assert len(features.forms) == 1
    form = features.forms[0]
    assert form.action == "https://secure-portal.com/auth/verify"
    assert form.method == "post"
    assert form.has_password is True
    assert len(form.inputs) == 3

    # Password input checks
    assert features.has_password_field is True
    assert len(features.password_inputs) == 1
    pwd = features.password_inputs[0]
    assert pwd.name == "user_password"
    assert pwd.is_password is True
    assert pwd.placeholder == "Account password"

    # Placeholders checks
    assert "Enter your email" in features.placeholders
    assert "Account password" in features.placeholders
    assert "Search knowledgebase" in features.placeholders

    # Buttons checks (input[type=submit] should be captured)
    assert "Sign In Now" in features.buttons


def test_script_and_style_stripping():
    """Ensure scripts and styles do not contaminate the sanitized visible text."""
    html = """
    <html>
    <head>
        <style>body { background: red; } .hidden { display: none; }</style>
    </head>
    <body>
        <script>var secret_token = "EVIL_MALICIOUS_TOKEN"; console.log(secret_token);</script>
        <p>Visible greeting message</p>
        <noscript>JavaScript is required.</noscript>
    </body>
    </html>
    """
    features = extract_html_features(html)

    assert "Visible greeting message" in features.visible_text
    assert "EVIL_MALICIOUS_TOKEN" not in features.visible_text
    assert "background: red" not in features.visible_text
    assert features.script_count == 1


def test_slm_structured_prompt_text_formatting():
    """Ensure the SLM structured representation is concise, readable, and free of raw HTML tags."""
    html = """
    <html>
    <head><title>Online Banking Verification</title></head>
    <body>
        <h1>Welcome Back</h1>
        <form action="https://external-harvest.xyz/steal" method="post">
            <input type="text" name="user" placeholder="Online ID" />
            <input type="password" name="pass" placeholder="Password" />
            <button type="submit">Log On</button>
        </form>
        <p>Need assistance? Contact support immediately.</p>
    </body>
    </html>
    """
    features = extract_html_features(html)
    slm_text = features.structured_slm_text

    # Must contain structural markers
    assert "[TITLE]" in slm_text
    assert "Online Banking Verification" in slm_text
    assert "[HEADINGS]" in slm_text
    assert "- (H1) Welcome Back" in slm_text
    assert "[FORMS & INPUTS]" in slm_text
    assert "https://external-harvest.xyz/steal" in slm_text
    assert "[PASSWORD FIELD]" in slm_text
    assert "[BUTTONS]" in slm_text
    assert "Log On" in slm_text
    assert "[VISIBLE CONTENT SAMPLE]" in slm_text

    # Must NOT contain raw markup tags
    assert "<html>" not in slm_text
    assert "<form" not in slm_text
    assert "<input" not in slm_text


def test_empty_and_broken_html_handling():
    """Ensure empty or malformed HTML does not crash the parser."""
    # None input
    features_none = extract_html_features(None)
    assert features_none.title is None
    assert features_none.total_tags == 0
    assert features_none.has_password_field is False

    # Broken markup input
    broken_html = "<div><p>Unclosed paragraph<span>Nested without end"
    features_broken = extract_html_features(broken_html)
    assert "Unclosed paragraph" in features_broken.visible_text
    assert features_broken.total_tags > 0
