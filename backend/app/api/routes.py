"""API routes for RISE-Phish backend.
"""
from datetime import datetime
import json
from typing import Optional
from fastapi import APIRouter, HTTPException, Query, status

from backend.app.api.service import analyze_url_pipeline
from backend.app.core.config import get_settings
from backend.app.core.logging import logger
from backend.app.models.schemas import (
    AnalysisDetailResponse,
    AnalysisHistoryResponse,
    AnalysisRequest,
    AnalysisSummary,
    DashboardStatsResponse,
    HealthResponse,
)
from backend.app.storage.database import get_db_manager

settings = get_settings()
router = APIRouter()


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check endpoint",
    description="Returns the health status and current configuration environment of the service.",
)
async def get_health() -> HealthResponse:
    """Provides system health status."""
    logger.debug("Health endpoint queried.")
    return HealthResponse(
        status="ok",
        app_name=settings.APP_NAME,
        version="0.1.0",
        environment=settings.APP_ENV,
    )


@router.post(
    "/analyze",
    response_model=AnalysisDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze target URL for representation discrepancy and phishing",
    description="Executes the full RISE-Phish pipeline: crawling, representation generation, CRCE, SLM, and evidence fusion.",
)
async def analyze_url_endpoint(
    request: AnalysisRequest,
) -> AnalysisDetailResponse:
    """Initiates an end-to-end security analysis for a target URL."""
    logger.info(f"Received analysis request for URL: {request.url} (force_fresh={request.force_fresh})")
    try:
        response = await analyze_url_pipeline(
            url=request.url,
            force_fresh=request.force_fresh,
        )
        return response
    except Exception as exc:
        logger.error(f"Error during analysis of {request.url}: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis pipeline execution failed: {str(exc)}",
        )


@router.get(
    "/history",
    response_model=AnalysisHistoryResponse,
    summary="List historical URL scans",
    description="Returns paginated summaries of past scans with optional verdict filtering.",
)
async def get_history_endpoint(
    limit: int = Query(default=50, ge=1, le=200, description="Max items per page"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
    verdict: Optional[str] = Query(default=None, description="Filter by verdict: SAFE, INVESTIGATE, PHISHING"),
) -> AnalysisHistoryResponse:
    """Retrieves paginated scan history from SQLite storage."""
    db = get_db_manager()
    rows, total = db.list_records(limit=limit, offset=offset, verdict=verdict)

    summaries = []
    for r in rows:
        summaries.append(
            AnalysisSummary(
                analysis_id=r["analysis_id"],
                url=r["url"],
                status=r["status"],
                verdict=r["verdict"],
                recommended_action=r["recommended_action"],
                composite_threat_score=r["composite_threat_score"],
                confidence_score=r["confidence_score"],
                target_brand=r["target_brand"],
                registered_domain=r["registered_domain"],
                visual_normalization_convergence=bool(r["visual_normalization_convergence"]),
                created_at=datetime.fromisoformat(r["created_at"]),
                completed_at=datetime.fromisoformat(r["completed_at"]) if r["completed_at"] else None,
            )
        )

    return AnalysisHistoryResponse(
        items=summaries,
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/analysis/{analysis_id}",
    response_model=AnalysisDetailResponse,
    summary="Get detailed forensic analysis by ID",
    description="Retrieves the full technical and explainability report for a completed analysis.",
)
async def get_analysis_by_id_endpoint(
    analysis_id: str,
) -> AnalysisDetailResponse:
    """Fetches a full forensic report from database."""
    db = get_db_manager()
    record = db.get_record(analysis_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis record with ID '{analysis_id}' not found.",
        )

    try:
        report_data = json.loads(record["report_json"])
        return AnalysisDetailResponse.model_validate(report_data)
    except Exception as exc:
        logger.error(f"Failed to parse report JSON for ID {analysis_id}: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Stored analysis payload could not be deserialized.",
        )


@router.delete(
    "/analysis/{analysis_id}",
    status_code=status.HTTP_200_OK,
    summary="Delete analysis record by ID",
    description="Removes a scan record from historical storage.",
)
async def delete_analysis_endpoint(
    analysis_id: str,
) -> dict:
    """Deletes an analysis record."""
    db = get_db_manager()
    deleted = db.delete_record(analysis_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis record with ID '{analysis_id}' not found.",
        )
    return {"status": "deleted", "analysis_id": analysis_id}


@router.get(
    "/stats",
    response_model=DashboardStatsResponse,
    summary="Get dashboard aggregate metrics",
    description="Returns aggregate scan telemetry, threat score distributions, and brand attack counts.",
)
async def get_stats_endpoint() -> DashboardStatsResponse:
    """Computes aggregated telemetry metrics."""
    db = get_db_manager()
    stats = db.get_stats()
    return DashboardStatsResponse(**stats)
