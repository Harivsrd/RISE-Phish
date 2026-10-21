"""SLM (Small Language Model) module for RISE-Phish.

Provides dual-task semantic recovery and phishing threat reasoning across
Mock, API, and Local quantized models.
"""
from backend.app.slm.interface import BaseSLMEngine
from backend.app.slm.mock_engine import MockSLMEngine
from backend.app.slm.api_engine import APIModelEngine
from backend.app.slm.local_engine import LocalSLMEngine
from backend.app.slm.factory import get_slm_engine
from backend.app.slm.recovery import (
    algorithmic_semantic_recovery,
    build_semantic_recovery_prompt,
    parse_semantic_recovery_response,
    SEMANTIC_RECOVERY_SYSTEM_PROMPT,
)
from backend.app.slm.reasoning import (
    algorithmic_phishing_reasoning,
    build_phishing_reasoning_prompt,
    parse_phishing_reasoning_response,
    PHISHING_REASONING_SYSTEM_PROMPT,
)

__all__ = [
    "BaseSLMEngine",
    "MockSLMEngine",
    "APIModelEngine",
    "LocalSLMEngine",
    "get_slm_engine",
    "algorithmic_semantic_recovery",
    "build_semantic_recovery_prompt",
    "parse_semantic_recovery_response",
    "SEMANTIC_RECOVERY_SYSTEM_PROMPT",
    "algorithmic_phishing_reasoning",
    "build_phishing_reasoning_prompt",
    "parse_phishing_reasoning_response",
    "PHISHING_REASONING_SYSTEM_PROMPT",
]
