"""FastAPI router for RISE-Phish Chrome and Edge Browser Extension.

Provides endpoints for:
1. Extension connectivity & health checks
2. In-depth email and web message phishing analysis
3. Quick link scanning with SSRF defenses
"""
from typing import Dict
from fastapi import APIRouter, HTTPException, status

from backend.app.api.message_service import analyze_message_pipeline
from backend.app.core.config import get_settings
from backend.app.core.logging import logger
from backend.app.models.extension_schemas import (
    ExtensionHealthResponse,
    MessageAnalysisRequest,
    MessageAnalysisResponse,
)

settings = get_settings()
router = APIRouter(tags=["Browser Extension API"])


@router.get(
    "/extension/health",
    response_model=ExtensionHealthResponse,
    summary="Extension Health & Connectivity Check",
    description="Validates that the RISE-Phish backend is reachable and ready to process extension requests.",
)
async def extension_health_check() -> ExtensionHealthResponse:
    """Verifies service readiness for browser extension integration."""
    logger.debug("Extension health queried.")
    return ExtensionHealthResponse(
        status="ok",
        extension_api_version="0.2.0",
        supported_sites=["mail.google.com"],
        ssrf_protection_active=True,
    )


@router.post(
    "/message-analysis",
    response_model=MessageAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze Email or Message Content for Phishing",
    description=(
        "Executes multi-representation discrepancy checks, sender spoofing detection, "
        "anchor text mismatch forensics, coercive urgency scoring, and SSRF-safe link evaluation."
    ),
)
async def analyze_message_endpoint(
    request: MessageAnalysisRequest,
) -> MessageAnalysisResponse:
    """Ingests email/message payload from extension content script or popup and returns threat verdict."""
    logger.info(
        f"Received message analysis request from site '{request.site_identifier}' "
        f"(mode={request.scan_mode}, links={len(request.embedded_links)})"
    )
    try:
        response = await analyze_message_pipeline(request)
        return response
    except Exception as exc:
        logger.error(f"Error during message analysis: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Message analysis pipeline failed: {str(exc)}",
        )
