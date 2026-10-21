"""API routes for RISE-Phish backend.
"""
from fastapi import APIRouter
from backend.app.core.config import get_settings
from backend.app.models.schemas import HealthResponse
from backend.app.core.logging import logger

settings = get_settings()
router = APIRouter()


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check endpoint",
    description="Returns the health status and current configuration environment of the service."
)
async def get_health() -> HealthResponse:
    """Provides system health status."""
    logger.debug("Health endpoint queried.")
    return HealthResponse(
        status="ok",
        app_name=settings.APP_NAME,
        version="0.1.0",
        environment=settings.APP_ENV
    )
