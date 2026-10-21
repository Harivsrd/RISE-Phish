"""OpenAI-compatible remote API SLM engine for RISE-Phish.

Connects asynchronously via HTTPX to remote inference endpoints (Groq, OpenAI,
Ollama, vLLM, Together AI, or local OpenAI-compatible sidecars).
"""
import logging
from typing import Any, Dict, List, Optional
import httpx

from backend.app.models.schemas import (
    SemanticRecoveryResult,
    SLMEvidenceInput,
    SLMReasoningResult,
)
from backend.app.slm.interface import BaseSLMEngine
from backend.app.slm.recovery import (
    SEMANTIC_RECOVERY_SYSTEM_PROMPT,
    build_semantic_recovery_prompt,
    parse_semantic_recovery_response,
    algorithmic_semantic_recovery,
)
from backend.app.slm.reasoning import (
    PHISHING_REASONING_SYSTEM_PROMPT,
    build_phishing_reasoning_prompt,
    parse_phishing_reasoning_response,
    algorithmic_phishing_reasoning,
)

logger = logging.getLogger("rise_phish.slm.api")


class APIModelEngine(BaseSLMEngine):
    """Asynchronous client for OpenAI-compatible Chat Completion APIs."""

    def __init__(
        self,
        api_url: str = "https://api.openai.com/v1",
        api_key: str = "",
        model_name: str = "gpt-4o-mini",
        temperature: float = 0.1,
        max_tokens: int = 1024,
        timeout_seconds: float = 30.0,
        client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.model_name = model_name
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout_seconds = timeout_seconds
        self._external_client = client

    def is_available(self) -> bool:
        """Available if a valid endpoint URL is provided."""
        return bool(self.api_url and self.api_url.startswith(("http://", "https://")))

    def get_backend_name(self) -> str:
        return "api"

    def get_model_name(self) -> str:
        return self.model_name

    def _get_headers(self) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    async def _post_chat_completion(self, messages: List[Dict[str, str]]) -> str:
        """Dispatches an async chat completion POST request."""
        endpoint = f"{self.api_url}/chat/completions"
        payload = {
            "model": self.model_name,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "response_format": {"type": "json_object"},
        }

        if self._external_client:
            response = await self._external_client.post(
                endpoint,
                headers=self._get_headers(),
                json=payload,
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]

        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            response = await client.post(
                endpoint,
                headers=self._get_headers(),
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]

    async def recover_semantics(
        self, 
        text: str, 
        context: Optional[Dict[str, Any]] = None
    ) -> SemanticRecoveryResult:
        """Executes Task 1 via remote API with fallback resilience."""
        messages = [
            {"role": "system", "content": SEMANTIC_RECOVERY_SYSTEM_PROMPT},
            {"role": "user", "content": build_semantic_recovery_prompt(text)},
        ]

        try:
            raw_content = await self._post_chat_completion(messages)
            return parse_semantic_recovery_response(raw_content)
        except Exception as exc:
            logger.warning(
                "Remote API call failed for recover_semantics (%s); falling back to deterministic oracle.",
                exc
            )
            fallback = algorithmic_semantic_recovery(text)
            fallback.recovery_explanation += f" (API fallback engaged due to: {type(exc).__name__})"
            return fallback

    async def reason_phishing(
        self, 
        evidence: SLMEvidenceInput
    ) -> SLMReasoningResult:
        """Executes Task 2 via remote API with fallback resilience."""
        messages = [
            {"role": "system", "content": PHISHING_REASONING_SYSTEM_PROMPT},
            {"role": "user", "content": build_phishing_reasoning_prompt(evidence)},
        ]

        try:
            raw_content = await self._post_chat_completion(messages)
            return parse_phishing_reasoning_response(raw_content, evidence)
        except Exception as exc:
            logger.warning(
                "Remote API call failed for reason_phishing (%s); falling back to deterministic oracle.",
                exc
            )
            fallback = algorithmic_phishing_reasoning(evidence)
            fallback.reasoning_summary += f" (API fallback engaged due to: {type(exc).__name__})"
            return fallback
