"""Abstract base class interface for RISE-Phish Small Language Model (SLM) engines.

Defines the contract for Task 1 (Semantic Recovery) and Task 2 (Phishing Reasoning),
ensuring zero tight coupling to specific local or remote LLM backends.
"""
from abc import ABC, abstractmethod
import time
from typing import Any, Dict, Optional

from backend.app.models.schemas import (
    SemanticRecoveryResult,
    SLMEvidenceInput,
    SLMReasoningResult,
    SLMDualTaskResult,
)


class BaseSLMEngine(ABC):
    """Abstract interface for all SLM backend implementations.
    
    Adheres to the dependency inversion principle, enabling seamless switching
    between Mock (for testing/offline), Local (Quantized Phi-3/Qwen), and API
    backends (OpenAI-compatible endpoints).
    """

    @abstractmethod
    async def recover_semantics(
        self, 
        text: str, 
        context: Optional[Dict[str, Any]] = None
    ) -> SemanticRecoveryResult:
        """Task 1: Semantic Recovery.
        
        Analyzes raw or obfuscated text strings to detect adversarial manipulations
        (homoglyphs, zero-width spaces, leetspeak, tag characters) and reconstructs
        the canonical semantic text.
        
        Args:
            text: Raw input text sequence from webpage representation.
            context: Optional contextual metadata (e.g., detected scripts, token offsets).
            
        Returns:
            SemanticRecoveryResult containing canonical recovered text and manipulation flags.
        """
        pass

    @abstractmethod
    async def reason_phishing(
        self, 
        evidence: SLMEvidenceInput
    ) -> SLMReasoningResult:
        """Task 2: Phishing Reasoning.
        
        Synthesizes structured evidence from URL lexical metrics, HTML DOM layout,
        Unicode analysis, CRCE discrepancy metrics, and brand claims to generate
        structured reasoning and threat classification.
        
        Args:
            evidence: Comprehensive structured evidence payload.
            
        Returns:
            SLMReasoningResult containing threat level, confidence, and explainable analysis.
        """
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Checks if the SLM engine backend is operational and ready to serve requests.
        
        Returns:
            True if configured and weights/endpoints are accessible, False otherwise.
        """
        pass

    @abstractmethod
    def get_backend_name(self) -> str:
        """Returns the identifier name of this backend (e.g., 'mock', 'api', 'local')."""
        pass

    @abstractmethod
    def get_model_name(self) -> str:
        """Returns the specific model name or checkpoint identifier in use."""
        pass

    async def execute_dual_task(
        self, 
        raw_text: str, 
        evidence: SLMEvidenceInput
    ) -> SLMDualTaskResult:
        """Coordinates sequential execution of both SLM tasks with latency telemetry.
        
        1. Executes Task 1 (Semantic Recovery) on raw text.
        2. Injects the recovered semantic text into the structured evidence payload.
        3. Executes Task 2 (Phishing Reasoning) on enriched evidence.
        4. Packages outputs into a unified SLMDualTaskResult container.
        
        Args:
            raw_text: Raw webpage text to de-obfuscate.
            evidence: Initial structured evidence payload.
            
        Returns:
            SLMDualTaskResult containing recovery, reasoning, metadata, and execution latency.
        """
        start_time = time.perf_counter()

        # Step 1: Run Semantic Recovery
        recovery_result = await self.recover_semantics(raw_text)

        # Step 2: Feed recovered snippet into Task 2 evidence if not already populated
        enriched_evidence = evidence.model_copy()
        if not enriched_evidence.recovered_text_snippet and recovery_result.recovered_text:
            snippet_limit = 500
            enriched_evidence.recovered_text_snippet = (
                recovery_result.recovered_text[:snippet_limit]
            )

        # Step 3: Run Phishing Reasoning
        reasoning_result = await self.reason_phishing(enriched_evidence)

        elapsed_ms = int((time.perf_counter() - start_time) * 1000)

        return SLMDualTaskResult(
            recovery=recovery_result,
            reasoning=reasoning_result,
            backend_used=self.get_backend_name(),
            model_name=self.get_model_name(),
            latency_ms=elapsed_ms,
        )
