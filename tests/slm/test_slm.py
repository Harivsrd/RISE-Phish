"""Comprehensive unit test suite for RISE-Phish SLM (Small Language Model) module (Phase 9).

Validates:
1. Task 1: Semantic Recovery (homoglyphs, zero-width, leetspeak, legitimate accents).
2. Task 2: Phishing Reasoning (phishing detection, legitimate alignment, discrepancy-without-malice).
3. Mock SLM engine & dual-task orchestration pipeline.
4. Remote API engine with mocked network responses and failure fallback.
5. Local engine lazy-load behavior and availability detection.
6. Engine factory configuration and error handling.
"""
import json
import pytest
import httpx

from backend.app.models.schemas import (
    SemanticRecoveryResult,
    SLMEvidenceInput,
    SLMReasoningResult,
    SLMDualTaskResult,
)
from backend.app.slm.factory import get_slm_engine
from backend.app.slm.mock_engine import MockSLMEngine
from backend.app.slm.api_engine import APIModelEngine
from backend.app.slm.local_engine import LocalSLMEngine
from backend.app.slm.recovery import (
    algorithmic_semantic_recovery,
    build_semantic_recovery_prompt,
    parse_semantic_recovery_response,
)
from backend.app.slm.reasoning import (
    algorithmic_phishing_reasoning,
    build_phishing_reasoning_prompt,
    parse_phishing_reasoning_response,
)


# ============================================================
# TASK 1: SEMANTIC RECOVERY TESTS
# ============================================================

def test_semantic_recovery_homoglyph_substitution():
    """Validates that cross-script lookalikes (Cyrillic inside Latin brand) are detected and resolved."""
    # Cyrillic small 'і' (U+0456) inside "Microsoft"
    obfuscated_text = "M\u0456crosoft Online Account Login"
    result = algorithmic_semantic_recovery(obfuscated_text)

    assert result.manipulation_detected is True
    assert result.recovered_text == "Microsoft Online Account Login"
    assert "homoglyph_substitution" in result.manipulation_tactics
    assert result.recovered_tokens_count >= 1
    assert result.confidence_score >= 0.90


def test_semantic_recovery_zero_width_and_tag_characters():
    """Validates stripping of zero-width spaces and Plane 14 tag characters."""
    # Zero-width space U+200B and Plane 14 tag char U+E0001
    obfuscated_text = "P\u200bay\u200bpal\U000e0001 Security Center"
    result = algorithmic_semantic_recovery(obfuscated_text)

    assert result.manipulation_detected is True
    assert result.recovered_text == "Paypal Security Center"
    assert "zero_width_insertion" in result.manipulation_tactics
    assert "tag_character_injection" in result.manipulation_tactics


def test_semantic_recovery_leetspeak_target_brands():
    """Validates de-obfuscation of symbol substitutions in target brands."""
    obfuscated_text = "Sign in to p@ypal to confirm your payment"
    result = algorithmic_semantic_recovery(obfuscated_text)

    assert result.manipulation_detected is True
    assert "paypal" in result.recovered_text.lower()
    assert "leetspeak" in result.manipulation_tactics


def test_semantic_recovery_clean_text_no_false_positive():
    """Validates that clean, normal English text is left intact with zero manipulation flags."""
    clean_text = "Welcome to the official developer documentation center."
    result = algorithmic_semantic_recovery(clean_text)

    assert result.manipulation_detected is False
    assert result.recovered_text == clean_text
    assert result.recovered_tokens_count == 0
    assert result.manipulation_tactics == []


def test_semantic_recovery_legitimate_accents_preserved():
    """Validates that legitimate international accented characters are not corrupted."""
    french_text = "Bienvenue sur le portail sécurisé de votre compte bancaire"
    result = algorithmic_semantic_recovery(french_text)

    assert result.manipulation_detected is False
    assert result.recovered_text == french_text
    assert "sécurisé" in result.recovered_text


def test_parse_semantic_recovery_markdown_wrapping():
    """Validates parser handles raw JSON as well as Markdown code blocks."""
    json_payload = {
        "recovered_text": "Google Workspace Login",
        "manipulation_detected": True,
        "manipulation_tactics": ["homoglyph_substitution"],
        "recovery_explanation": "Replaced Cyrillic 'о' characters.",
        "confidence_score": 0.96,
        "recovered_tokens_count": 1,
    }
    raw_markdown = f"```json\n{json.dumps(json_payload)}\n```"

    result = parse_semantic_recovery_response(raw_markdown)
    assert isinstance(result, SemanticRecoveryResult)
    assert result.recovered_text == "Google Workspace Login"
    assert result.manipulation_detected is True


def test_parse_semantic_recovery_corrupted_json_fallback():
    """Validates that unparseable model output falls back to deterministic recovery gracefully."""
    corrupted_output = "I cannot fulfill this request as JSON but the text has M\u0456crosoft"
    result = parse_semantic_recovery_response(corrupted_output)

    assert isinstance(result, SemanticRecoveryResult)
    assert "Microsoft" in result.recovered_text
    assert result.manipulation_detected is True


# ============================================================
# TASK 2: PHISHING REASONING TESTS
# ============================================================

def test_phishing_reasoning_high_threat_phishing_scenario():
    """Validates that brand spoofing + password inputs + visual convergence triggers CRITICAL phishing."""
    evidence = SLMEvidenceInput(
        url="https://secure-login.paypal-verification-alert.xyz/signin",
        domain="secure-login.paypal-verification-alert.xyz",
        registered_domain="paypal-verification-alert.xyz",
        page_title="PayPal - Security Verification",
        visible_text_snippet="Please verify your PayPal credentials to restore account access.",
        recovered_text_snippet="Please verify your PayPal credentials to restore account access.",
        has_password_field=True,
        form_count=1,
        detected_brands=["PayPal"],
        url_risk_score=0.85,
        url_risk_reasons=["excessive_subdomains", "suspicious_tld", "brand_in_subdomain"],
        unicode_anomaly_score=0.75,
        crce_overall_discrepancy=0.82,
        visual_normalization_convergence=True,
        discrepancy_findings_summary=["Visual-Normalization Convergence detected on brand name"],
        social_engineering_indicators=["account_suspension_threat", "urgent_verification"],
    )

    result = algorithmic_phishing_reasoning(evidence)

    assert result.phishing_intent_detected is True
    assert result.risk_level in ("HIGH", "CRITICAL")
    assert result.recommended_action == "BLOCK"
    assert result.target_brand == "PayPal"
    assert "credential_harvesting" in result.deception_techniques
    assert "visual_normalization_evasion" in result.deception_techniques
    assert result.confidence_score >= 0.85


def test_phishing_reasoning_legitimate_aligned_domain():
    """Validates that authentic brand presence with matching domain is classified as SAFE / LOW risk."""
    evidence = SLMEvidenceInput(
        url="https://www.paypal.com/signin",
        domain="www.paypal.com",
        registered_domain="paypal.com",
        page_title="Log in to your PayPal account",
        visible_text_snippet="Log in to your PayPal account with your email and password.",
        has_password_field=True,
        form_count=1,
        detected_brands=["PayPal"],
        url_risk_score=0.0,
        url_risk_reasons=[],
        unicode_anomaly_score=0.0,
        crce_overall_discrepancy=0.02,
        visual_normalization_convergence=False,
    )

    result = algorithmic_phishing_reasoning(evidence)

    assert result.phishing_intent_detected is False
    assert result.risk_level == "LOW"
    assert result.recommended_action == "ALLOW"
    assert result.confidence_score >= 0.80


def test_phishing_reasoning_discrepancy_alone_not_phishing():
    """Core research validation: Discrepancy by itself without brand spoofing or credential theft does NOT equal phishing."""
    evidence = SLMEvidenceInput(
        url="https://www.service-public.fr/particuliers",
        domain="www.service-public.fr",
        registered_domain="service-public.fr",
        page_title="Accueil Particuliers | Service-Public.fr",
        visible_text_snippet="Portail officiel d'information administrative pour les citoyens français.",
        has_password_field=False,
        form_count=0,
        detected_brands=[],
        url_risk_score=0.0,
        url_risk_reasons=[],
        unicode_anomaly_score=0.20,
        crce_overall_discrepancy=0.55,  # Moderate discrepancy due to OCR/rendering differences
        visual_normalization_convergence=False,
    )

    result = algorithmic_phishing_reasoning(evidence)

    # Discrepancy alone must NOT cause a false positive phishing detection
    assert result.phishing_intent_detected is False
    assert result.risk_level in ("LOW", "MEDIUM")
    assert result.recommended_action in ("ALLOW", "INSPECT_FURTHER")


def test_parse_phishing_reasoning_json_and_markdown():
    """Validates parser on Task 2 markdown-wrapped responses."""
    json_data = {
        "phishing_intent_detected": True,
        "risk_level": "CRITICAL",
        "target_brand": "Microsoft",
        "confidence_score": 0.94,
        "deception_techniques": ["brand_spoofing", "credential_harvesting"],
        "inconsistency_analysis": "DOM contains homoglyphs matching Microsoft visual OCR.",
        "reasoning_summary": "Malicious credential harvester spoofing Microsoft Office 365.",
        "recommended_action": "BLOCK"
    }
    raw = f"```json\n{json.dumps(json_data)}\n```"
    dummy_evidence = SLMEvidenceInput(
        url="https://login.micr0soft.xyz",
        domain="login.micr0soft.xyz",
        registered_domain="micr0soft.xyz",
        visible_text_snippet="Sign in to Microsoft"
    )

    result = parse_phishing_reasoning_response(raw, dummy_evidence)
    assert isinstance(result, SLMReasoningResult)
    assert result.phishing_intent_detected is True
    assert result.target_brand == "Microsoft"
    assert result.recommended_action == "BLOCK"


# ============================================================
# MOCK ENGINE & DUAL-TASK PIPELINE TESTS
# ============================================================

@pytest.mark.asyncio
async def test_mock_slm_engine_dual_task_pipeline():
    """Validates end-to-end execution of both tasks through MockSLMEngine."""
    engine = MockSLMEngine()
    assert engine.is_available() is True
    assert engine.get_backend_name() == "mock"

    raw_text = "Sign in to M\u0456crosoft to secure your account"
    evidence = SLMEvidenceInput(
        url="https://office-login.verify-auth.xyz/login",
        domain="office-login.verify-auth.xyz",
        registered_domain="verify-auth.xyz",
        page_title="Microsoft Login",
        visible_text_snippet=raw_text,
        has_password_field=True,
        form_count=1,
        detected_brands=["Microsoft"],
        url_risk_score=0.80,
        visual_normalization_convergence=True,
    )

    dual_result = await engine.execute_dual_task(raw_text, evidence)

    assert isinstance(dual_result, SLMDualTaskResult)
    assert dual_result.backend_used == "mock"
    assert dual_result.latency_ms >= 0

    # Task 1 checks
    assert dual_result.recovery.manipulation_detected is True
    assert "Microsoft" in dual_result.recovery.recovered_text

    # Task 2 checks
    assert dual_result.reasoning.phishing_intent_detected is True
    assert dual_result.reasoning.risk_level in ("HIGH", "CRITICAL")
    assert dual_result.reasoning.recommended_action == "BLOCK"


@pytest.mark.asyncio
async def test_mock_slm_engine_failure_simulation():
    """Validates that simulate_failure flag properly simulates unavailable backend."""
    engine = MockSLMEngine(simulate_failure=True)
    assert engine.is_available() is False

    with pytest.raises(RuntimeError):
        await engine.recover_semantics("Sample text")


# ============================================================
# REMOTE API ENGINE TESTS (MOCKED HTTP)
# ============================================================

@pytest.mark.asyncio
async def test_api_slm_engine_mocked_http_success():
    """Validates APIModelEngine using an in-memory mocked HTTPX client."""
    mock_payload = {
        "choices": [
            {
                "message": {
                    "content": json.dumps({
                        "recovered_text": "Recovered Brand Text",
                        "manipulation_detected": True,
                        "manipulation_tactics": ["homoglyph_substitution"],
                        "recovery_explanation": "Recovered mock brand",
                        "confidence_score": 0.95,
                        "recovered_tokens_count": 1,
                    })
                }
            }
        ]
    }

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=mock_payload)

    transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        engine = APIModelEngine(
            api_url="https://api.openai.com/v1",
            api_key="test-key",
            model_name="gpt-4o-mini",
            client=client,
        )

        assert engine.is_available() is True
        assert engine.get_backend_name() == "api"

        recovery = await engine.recover_semantics("Raw Text")
        assert recovery.recovered_text == "Recovered Brand Text"
        assert recovery.manipulation_detected is True


@pytest.mark.asyncio
async def test_api_slm_engine_http_error_graceful_fallback():
    """Validates that an HTTP error triggers graceful degradation without throwing uncaught exceptions."""
    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "Internal Server Error"})

    transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        engine = APIModelEngine(
            api_url="https://api.openai.com/v1",
            api_key="test-key",
            client=client,
        )

        recovery = await engine.recover_semantics("M\u0456crosoft")
        assert isinstance(recovery, SemanticRecoveryResult)
        assert "API fallback engaged" in recovery.recovery_explanation
        assert recovery.recovered_text == "Microsoft"


# ============================================================
# LOCAL ENGINE & FACTORY TESTS
# ============================================================

def test_local_engine_availability_and_fallback():
    """Validates LocalSLMEngine reports availability and falls back gracefully if weights absent."""
    engine = LocalSLMEngine(model_name="microsoft/Phi-3-mini-4k-instruct")
    assert engine.get_backend_name() == "local"
    # availability reflects environment support (torch/transformers presence)
    assert isinstance(engine.is_available(), bool)


@pytest.mark.asyncio
async def test_local_engine_unloaded_fallback_oracle():
    """Validates that LocalSLMEngine gracefully engages fallback oracle when model weights are not loaded."""
    engine = LocalSLMEngine(model_name="nonexistent-local-test-model")
    recovery = await engine.recover_semantics("M\u0456crosoft Account")

    assert isinstance(recovery, SemanticRecoveryResult)
    assert "Microsoft Account" in recovery.recovered_text


def test_slm_factory_selection():
    """Validates factory instantiates appropriate concrete engine based on backend string."""
    mock_eng = get_slm_engine("mock")
    assert isinstance(mock_eng, MockSLMEngine)
    assert mock_eng.get_backend_name() == "mock"

    api_eng = get_slm_engine("api", api_url="https://api.test.com/v1")
    assert isinstance(api_eng, APIModelEngine)
    assert api_eng.get_backend_name() == "api"

    local_eng = get_slm_engine("local")
    assert isinstance(local_eng, LocalSLMEngine)
    assert local_eng.get_backend_name() == "local"

    with pytest.raises(ValueError, match="Unsupported SLM backend"):
        get_slm_engine("quantum_ai_engine")
