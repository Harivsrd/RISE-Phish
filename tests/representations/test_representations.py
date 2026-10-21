"""Comprehensive test suite for Phase 6 Multi-Representation Generator (R1 - R5).

Verifies:
- R1 Raw Representation immutability and raw evidence preservation
- R2 Normalized Representation transformation traceability
- R3 Visual / OCR Representation integration and fallback handling
- R4 Semantic Representation structural intent synthesis
- R5 URL Representation domain token decomposition
- End-to-end RepresentationSet builder orchestration
"""
import pytest
from backend.app.models.schemas import (
    CrawlerResult,
    FormInput,
    FormSummary,
    HeadingItem,
    HTMLFeatures,
    URLFeatures,
)
from backend.app.preprocessing.ocr_engine import MockOCREngine
from backend.app.representations.builder import build_representation_set
from backend.app.representations.normalized import build_normalized_representation
from backend.app.representations.raw import build_raw_representation
from backend.app.representations.semantic import build_semantic_representation
from backend.app.representations.url_repr import build_url_representation
from backend.app.representations.visual import build_visual_representation


def test_r1_raw_representation_immutability():
    """Verify R1 preserves exact raw text, code points, entities, and zero-width characters."""
    obfuscated_text = "M\u0456crosoft Pass\u200Bword &amp; &quot;Billing&quot;"
    r1 = build_raw_representation(obfuscated_text)

    assert r1.text == obfuscated_text
    assert r1.character_count == len(obfuscated_text)
    assert r1.source_type == "dom_text_nodes"
    # Ensure raw codepoints are completely preserved
    assert "\u0456" in r1.text
    assert "\u200B" in r1.text
    assert "&amp;" in r1.text


def test_r2_normalized_traceability_and_audit():
    """Verify R2 records all transformation stages while R1 remains unchanged."""
    raw_input = "  &lt;Pay&gt; \uFF30\uFF41\uFF59\u200BPal   \n\t Sign-In  "
    r1 = build_raw_representation(raw_input)
    r2 = build_normalized_representation(r1.text)

    # 1. Verify R1 was NOT mutated
    assert r1.text == raw_input

    # 2. Verify all transformations were recorded traceably
    assert "html_entity_unescaping" in r2.transformations_applied
    assert "nfkc_unicode_normalization" in r2.transformations_applied
    assert "invisible_character_stripping" in r2.transformations_applied
    assert "whitespace_collapsing" in r2.transformations_applied

    # 3. Verify clean output
    assert r2.text == "<Pay> PayPal Sign-In"
    assert r2.characters_altered_count > 0
    assert "\u200B" not in r2.text
    assert "\uFF30" not in r2.text


@pytest.mark.asyncio
async def test_r3_visual_representation_success_and_fallback():
    """Verify R3 visual text extraction via OCR and graceful handling of missing screenshots."""
    mock_ocr = MockOCREngine(default_text="Visual Screenshot Text", default_confidence=92.0)

    # Success case with screenshot path
    r3_success = await build_visual_representation(
        screenshot_path="temp/screenshots/mock.png",
        ocr_engine=mock_ocr,
    )
    assert r3_success.available is True
    assert r3_success.text == "Visual Screenshot Text"
    assert r3_success.confidence == 92.0
    assert r3_success.words_count == 3
    assert r3_success.engine_name == "MockOCR"

    # Fallback case without screenshot path
    r3_fallback = await build_visual_representation(
        screenshot_path=None,
        ocr_engine=mock_ocr,
    )
    assert r3_fallback.available is False
    assert r3_fallback.text == ""
    assert "No screenshot" in r3_fallback.error_message


def test_r4_semantic_representation():
    """Verify R4 synthesizes structural intent, headings, forms, and action tokens."""
    html_features = HTMLFeatures(
        title="Official Verification Portal",
        headings=[
            HeadingItem(level=1, text="Security Checkpoint"),
            HeadingItem(level=2, text="Confirm Credentials"),
        ],
        forms=[
            FormSummary(
                action="https://auth-server.com/login",
                method="post",
                has_password=True,
                inputs=[
                    FormInput(name="email", input_type="email"),
                    FormInput(name="pass", input_type="password", is_password=True),
                ],
            )
        ],
        buttons=["Verify Identity", "Cancel"],
        structured_slm_text="[TITLE]\nOfficial Verification Portal\n[HEADINGS]\n- (H1) Security Checkpoint",
    )

    r4 = build_semantic_representation(html_features)
    assert r4.title == "Official Verification Portal"
    assert "Security Checkpoint | Confirm Credentials" in r4.headings_text
    assert "[Credential/Password Form]" in r4.form_intent_summary
    assert "Verify Identity" in r4.action_tokens
    assert "Cancel" in r4.action_tokens
    assert "[TITLE]" in r4.structured_content


def test_r5_url_representation():
    """Verify R5 decomposes hostname, paths, and domain tokens."""
    url_features = URLFeatures(
        raw_url="https://login.security-update.microsoft.com/auth/verify?id=123",
        url_length=62,
        scheme="https",
        hostname="login.security-update.microsoft.com",
        registered_domain="microsoft.com",
        subdomain="login.security-update",
        path="/auth/verify",
        query="id=123",
        tld="com",
    )

    r5 = build_url_representation(url_features)
    assert r5.raw_url == "https://login.security-update.microsoft.com/auth/verify?id=123"
    assert r5.registered_domain == "microsoft.com"
    assert r5.subdomain == "login.security-update"
    assert "login" in r5.domain_tokens
    assert "security" in r5.domain_tokens
    assert "update" in r5.domain_tokens
    assert "microsoft" in r5.domain_tokens


@pytest.mark.asyncio
async def test_build_representation_set_orchestration():
    """Verify end-to-end assembly of R1 through R5 in RepresentationSet."""
    crawler_res = CrawlerResult(
        analysis_id="test-job-uuid-12345",
        input_url="https://example.com/login",
        final_url="https://example.com/login",
        status_code=200,
        visible_text="M\u0456crosoft Online Account",
        screenshot_path=None,  # Tests graceful OCR fallback
    )

    html_feat = HTMLFeatures(
        title="Sign In",
        visible_text="M\u0456crosoft Online Account",
        buttons=["Next"],
    )

    url_feat = URLFeatures(
        raw_url="https://example.com/login",
        url_length=26,
        scheme="https",
        hostname="example.com",
        registered_domain="example.com",
        subdomain="",
        path="/login",
        query="",
        tld="com",
    )

    rep_set = await build_representation_set(
        crawler_result=crawler_res,
        html_features=html_feat,
        url_features=url_feat,
        ocr_engine=MockOCREngine(),
    )

    assert rep_set.analysis_id == "test-job-uuid-12345"
    assert rep_set.r1_raw.text == "M\u0456crosoft Online Account"
    assert rep_set.r2_normalized.text == "Mіcrosoft Online Account"
    assert rep_set.r3_visual.available is False  # Screenshot was None
    assert rep_set.r4_semantic.title == "Sign In"
    assert "example" in rep_set.r5_url.domain_tokens
