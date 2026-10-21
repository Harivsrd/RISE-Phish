"""End-to-end analysis orchestration service for RISE-Phish.

Coordinates all system layers:
Crawler -> Preprocessing -> Multi-Representation Suite -> CRCE -> SLM ->
Evidence Fusion -> Decision Engine -> Explanation Engine -> SQLite Persistence.
"""
from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, Optional
import uuid

from backend.app.core.config import get_settings
from backend.app.crawler.collector import collect_page
from backend.app.crce.brand_detector import identify_claimed_brand
from backend.app.crce.discrepancy import evaluate_discrepancies
from backend.app.decision.risk import DecisionEngine, evaluate_decision
from backend.app.explanation.explanation_engine import ExplanationEngine
from backend.app.fusion.evidence_fusion import fuse_evidence
from backend.app.models.schemas import (
    AnalysisDetailResponse,
    CrawlerResult,
    DefensiveAction,
    HTMLFeatures,
    RepresentationSet,
    SLMEvidenceInput,
    ThreatPosturePolicy,
    ThreatVerdict,
    UnicodeAnalysisResult,
    URLFeatures,
)
from backend.app.preprocessing.html_processor import extract_html_features
from backend.app.preprocessing.ocr_engine import get_ocr_engine
from backend.app.preprocessing.unicode_processor import analyze_unicode
from backend.app.preprocessing.url_processor import analyze_url
from backend.app.representations.builder import build_representation_set
from backend.app.slm.factory import get_slm_engine
from backend.app.storage.database import get_db_manager

logger = logging.getLogger("rise_phish.service")
settings = get_settings()


async def analyze_url_pipeline(
    url: str,
    force_fresh: bool = False,
    custom_html: Optional[str] = None,
    browser_manager: Optional[Any] = None,
) -> AnalysisDetailResponse:
    """Executes the complete multi-representation analysis pipeline on a target URL.

    Args:
        url: Webpage URL to analyze.
        force_fresh: If True, bypasses SQLite cache.
        custom_html: Optional HTML string to bypass crawler (useful in testing).
        browser_manager: Optional BrowserManager override for testing.

    Returns:
        Structured AnalysisDetailResponse with complete technical evidence.
    """
    db = get_db_manager()
    created_at = datetime.now(timezone.utc)

    # 1. Cache Check
    if not force_fresh and not custom_html:
        cached_row = db.find_latest_by_url(url)
        if cached_row:
            try:
                cached_data = json.loads(cached_row["report_json"])
                logger.info(f"Returning cached analysis for {url} (ID: {cached_row['analysis_id']})")
                return AnalysisDetailResponse.model_validate(cached_data)
            except Exception as parse_err:
                logger.warning(f"Failed to parse cached report JSON: {parse_err}. Re-analyzing.")

    analysis_id = str(uuid.uuid4())
    logger.info(f"Starting analysis job {analysis_id} for URL: {url}")

    # 2. Crawler Stage
    if custom_html is not None:
        # Synthetic / Direct HTML path
        crawler_result = CrawlerResult(
            analysis_id=analysis_id,
            input_url=url,
            final_url=url,
            success=True,
            html=custom_html,
            title=url,
            visible_text=custom_html,
        )
    else:
        try:
            crawler_result = await collect_page(
                url=url,
                analysis_id=analysis_id,
                browser_manager=browser_manager,
            )
        except Exception as crawl_err:
            logger.error(f"Crawler encountered unhandled exception for {url}: {crawl_err}")
            crawler_result = CrawlerResult(
                analysis_id=analysis_id,
                input_url=url,
                final_url=url,
                success=False,
                error_type="crawler_exception",
                error_message=str(crawl_err),
            )

    # 3. URL Lexical & Syntactic Analysis
    effective_url = crawler_result.final_url or url
    url_f = analyze_url(effective_url)

    # If crawler completely failed on invalid URL
    if not crawler_result.success and crawler_result.error_type == "invalid_url":
        completed_at = datetime.now(timezone.utc)
        failed_response = AnalysisDetailResponse(
            analysis_id=analysis_id,
            url=url,
            status="FAILED",
            verdict=ThreatVerdict.INVESTIGATE,
            recommended_action=DefensiveAction.WARN_USER,
            composite_threat_score=0.5,
            confidence_score=0.3,
            url_features=url_f,
            error_message=crawler_result.error_message or "Invalid URL syntax",
            created_at=created_at,
            completed_at=completed_at,
        )
        db.save_record(
            analysis_id=analysis_id,
            url=url,
            status="FAILED",
            verdict="INVESTIGATE",
            recommended_action="WARN_USER",
            composite_threat_score=0.5,
            confidence_score=0.3,
            target_brand=None,
            registered_domain=url_f.registered_domain,
            visual_normalization_convergence=False,
            report_json=failed_response.model_dump_json(),
            created_at=created_at.isoformat(),
            completed_at=completed_at.isoformat(),
            error_message=failed_response.error_message,
        )
        return failed_response

    # 4. HTML DOM Feature Extraction
    html_content = crawler_result.html or f"<html><body><p>{url}</p></body></html>"
    html_f = extract_html_features(html_content, base_url=effective_url)

    # 5. Multi-Representation Suite (R1-R5) Construction
    ocr_engine = get_ocr_engine(engine_type=settings.OCR_ENGINE)
    rep_set = await build_representation_set(
        crawler_result=crawler_result,
        html_features=html_f,
        url_features=url_f,
        ocr_engine=ocr_engine,
    )

    # 6. Unicode Analysis
    uni_res = analyze_unicode(rep_set.r1_raw.text)

    # 7. CRCE Discrepancy Evaluation
    crce_res = evaluate_discrepancies(rep_set)
    detected_brand = (
        identify_claimed_brand(rep_set.r2_normalized.text)
        or identify_claimed_brand(rep_set.r3_visual.text)
        or identify_claimed_brand(rep_set.r1_raw.text)
    )

    # 8. SLM Dual-Task Reasoning & Recovery
    slm_engine = get_slm_engine(backend=settings.SLM_BACKEND)
    slm_evidence = SLMEvidenceInput(
        url=effective_url,
        domain=rep_set.r5_url.hostname,
        registered_domain=rep_set.r5_url.registered_domain,
        page_title=html_f.title or rep_set.r4_semantic.title or "Portal",
        visible_text_snippet=rep_set.r1_raw.text[:600],
        has_password_field=html_f.has_password_field,
        detected_brands=[detected_brand] if detected_brand else [],
        url_risk_score=url_f.url_risk_score,
        unicode_anomaly_score=uni_res.unicode_anomaly_score,
        crce_overall_discrepancy=crce_res.overall_discrepancy,
        visual_normalization_convergence=crce_res.visual_normalization_convergence,
    )
    slm_dual = await slm_engine.execute_dual_task(
        raw_text=rep_set.r1_raw.text,
        evidence=slm_evidence,
    )

    # 9. Evidence Fusion
    claimed_brand = detected_brand or (slm_dual.reasoning.target_brand if slm_dual else None)
    fused = fuse_evidence(
        url_features=url_f,
        unicode_result=uni_res,
        crce_result=crce_res,
        rep_set=rep_set,
        slm_result=slm_dual,
        html_features=html_f,
        claimed_brand=claimed_brand,
        has_password_field=html_f.has_password_field,
    )

    # 10. Operational Decision Engine
    decision_engine = DecisionEngine(default_policy=ThreatPosturePolicy.BALANCED)
    decision = decision_engine.evaluate(fused)

    # If the network crawler could not reach or resolve the target, it cannot be certified safe
    if not crawler_result.success and decision.verdict == ThreatVerdict.SAFE:
        decision.verdict = ThreatVerdict.INVESTIGATE
        decision.recommended_action = DefensiveAction.WARN_USER
        decision.composite_threat_score = max(decision.composite_threat_score, 0.45)
        decision.confidence_score = 0.50
        decision.decision_summary = (
            f"VERDICT: INVESTIGATE (Action: WARN_USER). Target could not be reached ({crawler_result.error_type or 'network error'}). "
            f"Unreachable domains or inactive links cannot be validated as authentic."
        )

    # 11. Dual-Audience Explainability Engine
    explanation_engine = ExplanationEngine()
    explanation = explanation_engine.explain(
        decision=decision,
        fused_evidence=fused,
        rep_set=rep_set,
        crce_result=crce_res,
        unicode_result=uni_res,
        url_features=url_f,
        slm_result=slm_dual,
        html_features=html_f,
        analysis_id=analysis_id,
    )

    completed_at = datetime.now(timezone.utc)
    status_val = "COMPLETED" if crawler_result.success else "DEGRADED"
    error_msg = crawler_result.error_message if not crawler_result.success else None

    # 12. Assemble Full Technical Response
    response = AnalysisDetailResponse(
        analysis_id=analysis_id,
        url=url,
        status=status_val,
        verdict=decision.verdict,
        recommended_action=decision.recommended_action,
        composite_threat_score=decision.composite_threat_score,
        confidence_score=decision.confidence_score,
        target_brand=decision.target_brand,
        registered_domain=rep_set.r5_url.registered_domain,
        visual_normalization_convergence=crce_res.visual_normalization_convergence,
        representations=rep_set,
        crce=crce_res,
        unicode_analysis=uni_res,
        url_features=url_f,
        html_features=html_f,
        decision=decision,
        fused_evidence=fused,
        explanation=explanation,
        error_message=error_msg,
        created_at=created_at,
        completed_at=completed_at,
    )

    # 13. Persist to SQLite
    db.save_record(
        analysis_id=analysis_id,
        url=url,
        status=status_val,
        verdict=decision.verdict.value,
        recommended_action=decision.recommended_action.value,
        composite_threat_score=decision.composite_threat_score,
        confidence_score=decision.confidence_score,
        target_brand=decision.target_brand,
        registered_domain=rep_set.r5_url.registered_domain,
        visual_normalization_convergence=crce_res.visual_normalization_convergence,
        report_json=response.model_dump_json(),
        created_at=created_at.isoformat(),
        completed_at=completed_at.isoformat(),
        error_message=error_msg,
    )
    logger.info(f"Completed analysis {analysis_id}: Verdict={decision.verdict.value}, Score={decision.composite_threat_score}")

    return response
