"""Factory module for instantiating SLM backend engines in RISE-Phish.

Provides unified dependency injection and runtime switching across Mock,
Remote API, and Local quantized HuggingFace model backends.
"""
import logging
from typing import Optional

from backend.app.core.config import Settings, get_settings
from backend.app.slm.api_engine import APIModelEngine
from backend.app.slm.interface import BaseSLMEngine
from backend.app.slm.local_engine import LocalSLMEngine
from backend.app.slm.mock_engine import MockSLMEngine

logger = logging.getLogger("rise_phish.slm.factory")


def get_slm_engine(
    backend: Optional[str] = None,
    settings: Optional[Settings] = None,
    **kwargs
) -> BaseSLMEngine:
    """Instantiates and returns the configured SLM engine backend.
    
    Args:
        backend: Engine identifier ('mock', 'api', 'local'). If None, defaults to settings.SLM_BACKEND.
        settings: Application settings instance. If None, uses cached singleton.
        **kwargs: Optional overrides passed to engine constructor.
        
    Returns:
        Concrete instance conforming to BaseSLMEngine interface.
        
    Raises:
        ValueError: If an unsupported backend identifier is specified.
    """
    if settings is None:
        settings = get_settings()

    target_backend = (backend or settings.SLM_BACKEND or "mock").lower().strip()

    logger.debug("Initializing SLM backend: '%s'", target_backend)

    if target_backend == "mock":
        model_name = kwargs.get("model_name", "mock-slm-oracle-v1")
        return MockSLMEngine(model_name=model_name, **kwargs)

    elif target_backend == "api":
        return APIModelEngine(
            api_url=kwargs.get("api_url", settings.SLM_API_URL),
            api_key=kwargs.get("api_key", settings.SLM_API_KEY),
            model_name=kwargs.get("model_name", settings.SLM_MODEL_NAME),
            temperature=kwargs.get("temperature", settings.SLM_TEMPERATURE),
            max_tokens=kwargs.get("max_tokens", settings.SLM_MAX_TOKENS),
            timeout_seconds=kwargs.get("timeout_seconds", settings.SLM_TIMEOUT_SECONDS),
            client=kwargs.get("client", None),
        )

    elif target_backend == "local":
        return LocalSLMEngine(
            model_name=kwargs.get("model_name", settings.SLM_MODEL_NAME),
            device=kwargs.get("device", settings.SLM_DEVICE),
            max_tokens=kwargs.get("max_tokens", settings.SLM_MAX_TOKENS),
            temperature=kwargs.get("temperature", settings.SLM_TEMPERATURE),
        )

    else:
        raise ValueError(
            f"Unsupported SLM backend '{target_backend}'. Supported backends: 'mock', 'api', 'local'."
        )
