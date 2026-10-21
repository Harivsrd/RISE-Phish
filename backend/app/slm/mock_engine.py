"""Deterministic Mock SLM Engine for RISE-Phish.

Enables ultra-fast, zero-VRAM, reproducible unit and integration testing without
requiring GPU resources, HuggingFace model weights, or remote API network connectivity.
"""
from typing import Any, Dict, Optional

from backend.app.models.schemas import (
    SemanticRecoveryResult,
    SLMEvidenceInput,
    SLMReasoningResult,
)
from backend.app.slm.interface import BaseSLMEngine
from backend.app.slm.recovery import algorithmic_semantic_recovery
from backend.app.slm.reasoning import algorithmic_phishing_reasoning


class MockSLMEngine(BaseSLMEngine):
    """High-fidelity deterministic SLM engine for testing and offline environments.
    
    Provides rule-grounded semantic recovery (de-homoglyphing, zero-width stripping,
    leetspeak recovery) and evidence fusion reasoning without allocating GPU VRAM.
    """

    def __init__(
        self, 
        model_name: str = "mock-slm-oracle-v1",
        simulate_failure: bool = False
    ) -> None:
        self.model_name = model_name
        self.simulate_failure = simulate_failure

    def is_available(self) -> bool:
        """Mock engine is always available unless explicitly set to simulate failure."""
        return not self.simulate_failure

    def get_backend_name(self) -> str:
        return "mock"

    def get_model_name(self) -> str:
        return self.model_name

    async def recover_semantics(
        self, 
        text: str, 
        context: Optional[Dict[str, Any]] = None
    ) -> SemanticRecoveryResult:
        """Executes deterministic semantic recovery algorithm."""
        if self.simulate_failure:
            raise RuntimeError("Mock SLM engine simulated failure during Semantic Recovery.")
        return algorithmic_semantic_recovery(text)

    async def reason_phishing(
        self, 
        evidence: SLMEvidenceInput
    ) -> SLMReasoningResult:
        """Executes deterministic multi-representation phishing reasoning algorithm."""
        if self.simulate_failure:
            raise RuntimeError("Mock SLM engine simulated failure during Phishing Reasoning.")
        return algorithmic_phishing_reasoning(evidence)
