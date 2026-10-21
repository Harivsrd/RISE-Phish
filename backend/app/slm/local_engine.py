"""Local lightweight SLM engine for RISE-Phish.

Optimized for lightweight inference within an NVIDIA RTX 3050 4GB VRAM constraint.
Supports lazy loading of quantized open-weight models (Phi-3-mini, Qwen2.5-0.5B/1.5B)
with CPU fallback and graceful offline degradation.
"""
import logging
from typing import Any, Dict, List, Optional

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

logger = logging.getLogger("rise_phish.slm.local")


class LocalSLMEngine(BaseSLMEngine):
    """Local inference engine leveraging HuggingFace Transformers.
    
    Adheres strictly to the 4 GB VRAM development constraint by supporting
    small model architectures (0.5B - 3.8B) and quantized execution.
    """

    def __init__(
        self,
        model_name: str = "microsoft/Phi-3-mini-4k-instruct",
        device: str = "cpu",
        max_tokens: int = 512,
        temperature: float = 0.1,
    ) -> None:
        self.model_name = model_name
        self.device = device
        self.max_tokens = max_tokens
        self.temperature = temperature
        self._model = None
        self._tokenizer = None
        self._load_attempted = False
        self._load_error: Optional[str] = None

    def is_available(self) -> bool:
        """Determines if torch and transformers packages are importable."""
        try:
            import torch  # noqa: F401
            import transformers  # noqa: F401
            return True
        except ImportError:
            return False

    def get_backend_name(self) -> str:
        return "local"

    def get_model_name(self) -> str:
        return self.model_name

    def _ensure_loaded(self) -> bool:
        """Lazy-loads the model and tokenizer upon first execution."""
        if self._model is not None and self._tokenizer is not None:
            return True

        if self._load_attempted and self._load_error:
            return False

        self._load_attempted = True

        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer

            target_device = self.device
            if target_device == "cuda" and not torch.cuda.is_available():
                logger.warning("CUDA requested but not available; defaulting to CPU.")
                target_device = "cpu"

            logger.info("Loading local SLM checkpoint '%s' on %s...", self.model_name, target_device)
            self._tokenizer = AutoTokenizer.from_pretrained(
                self.model_name, 
                trust_remote_code=True
            )

            # Select appropriate dtype
            dtype = torch.float16 if target_device == "cuda" else torch.float32

            self._model = AutoModelForCausalLM.from_pretrained(
                self.model_name,
                torch_dtype=dtype,
                trust_remote_code=True,
                device_map=target_device if target_device == "cuda" else None,
            )

            if target_device == "cpu":
                self._model = self._model.to("cpu")

            self._model.eval()
            logger.info("Local SLM '%s' successfully initialized.", self.model_name)
            return True

        except Exception as exc:
            self._load_error = str(exc)
            logger.warning(
                "Unable to load local SLM checkpoint '%s': %s. Fallback oracle will be used.",
                self.model_name,
                exc
            )
            return False

    def _generate_completion(self, messages: List[Dict[str, str]]) -> str:
        """Runs local model forward pass to generate completion string."""
        import torch

        if self._tokenizer.chat_template:
            prompt = self._tokenizer.apply_chat_template(
                messages, 
                tokenize=False, 
                add_generation_prompt=True
            )
        else:
            prompt = (
                f"System: {messages[0]['content']}\n\n"
                f"User: {messages[1]['content']}\n\n"
                f"Assistant:"
            )

        inputs = self._tokenizer(prompt, return_tensors="pt")
        target_device = next(self._model.parameters()).device
        inputs = {k: v.to(target_device) for k, v in inputs.items()}

        with torch.no_grad():
            outputs = self._model.generate(
                **inputs,
                max_new_tokens=self.max_tokens,
                temperature=self.temperature,
                do_sample=self.temperature > 0.0,
                pad_token_id=self._tokenizer.eos_token_id,
            )

        input_len = inputs["input_ids"].shape[1]
        generated_tokens = outputs[0][input_len:]
        return self._tokenizer.decode(generated_tokens, skip_special_tokens=True)

    async def recover_semantics(
        self, 
        text: str, 
        context: Optional[Dict[str, Any]] = None
    ) -> SemanticRecoveryResult:
        """Task 1 execution via local model or fallback oracle."""
        if not self._ensure_loaded():
            fallback = algorithmic_semantic_recovery(text)
            fallback.recovery_explanation += (
                f" (Local engine weights unavailable: {self._load_error}; deterministic recovery engaged)"
            )
            return fallback

        messages = [
            {"role": "system", "content": SEMANTIC_RECOVERY_SYSTEM_PROMPT},
            {"role": "user", "content": build_semantic_recovery_prompt(text)},
        ]

        try:
            raw_output = self._generate_completion(messages)
            return parse_semantic_recovery_response(raw_output)
        except Exception as exc:
            logger.warning("Local generation failed for recover_semantics: %s", exc)
            fallback = algorithmic_semantic_recovery(text)
            fallback.recovery_explanation += f" (Local execution fallback: {exc})"
            return fallback

    async def reason_phishing(
        self, 
        evidence: SLMEvidenceInput
    ) -> SLMReasoningResult:
        """Task 2 execution via local model or fallback oracle."""
        if not self._ensure_loaded():
            fallback = algorithmic_phishing_reasoning(evidence)
            fallback.reasoning_summary += (
                f" (Local engine weights unavailable: {self._load_error}; deterministic oracle engaged)"
            )
            return fallback

        messages = [
            {"role": "system", "content": PHISHING_REASONING_SYSTEM_PROMPT},
            {"role": "user", "content": build_phishing_reasoning_prompt(evidence)},
        ]

        try:
            raw_output = self._generate_completion(messages)
            return parse_phishing_reasoning_response(raw_output, evidence)
        except Exception as exc:
            logger.warning("Local generation failed for reason_phishing: %s", exc)
            fallback = algorithmic_phishing_reasoning(evidence)
            fallback.reasoning_summary += f" (Local execution fallback: {exc})"
            return fallback
