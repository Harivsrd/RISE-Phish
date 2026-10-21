"""Pydantic schemas and data contracts for RISE-Phish.
"""
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, HttpUrl


class HealthResponse(BaseModel):
    """Health check response schema."""
    status: str = Field(default="ok", description="Service status indicator")
    app_name: str = Field(description="Name of the application")
    version: str = Field(default="0.1.0", description="Backend API version")
    environment: str = Field(description="Current deployment environment")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Current UTC timestamp"
    )


class AnalysisRequest(BaseModel):
    """Incoming request to analyze a URL."""
    url: str = Field(..., description="The target webpage URL to analyze")
    force_fresh: bool = Field(default=False, description="Bypass cache if set to True")


class AnalysisStatusResponse(BaseModel):
    """Async status tracking response."""
    analysis_id: str
    status: str
    created_at: datetime
    completed_at: Optional[datetime] = None
