"""Representation builder orchestrating the construction of R1 through R5.
"""
from typing import Optional

from backend.app.core.logging import logger
from backend.app.models.schemas import (
    CrawlerResult,
    HTMLFeatures,
    RepresentationSet,
    URLFeatures,
)
from backend.app.preprocessing.ocr_engine import BaseOCREngine
from backend.app.representations.normalized import build_normalized_representation
from backend.app.representations.raw import build_raw_representation
from backend.app.representations.semantic import build_semantic_representation
from backend.app.representations.url_repr import build_url_representation
from backend.app.representations.visual import build_visual_representation


async def build_representation_set(
    crawler_result: CrawlerResult,
    html_features: HTMLFeatures,
    url_features: URLFeatures,
    ocr_engine: Optional[BaseOCREngine] = None,
) -> RepresentationSet:
    """Constructs the complete 5-layer representation suite (R1 - R5).

    Pipeline:
    1. R1: Raw extracted text nodes directly from rendered DOM.
    2. R2: Normalized text (NFKC, HTML unescape, zero-width stripping) derived from R1.
    3. R3: Visual / OCR text extracted from rasterized screenshot.
    4. R4: Semantic representation synthesized from HTML structures and intents.
    5. R5: URL representation decomposed into lexical tokens.

    Args:
        crawler_result: CrawlerResult from Phase 1.
        html_features: HTMLFeatures from Phase 2.
        url_features: URLFeatures from Phase 3.
        ocr_engine: Optional OCR engine override.

    Returns:
        Unified RepresentationSet instance.
    """
    logger.info(f"Building multi-representation set for Job: {crawler_result.analysis_id}")

    # R1: Raw
    # Use visible_text from crawler or HTML features as base text nodes
    raw_source = crawler_result.visible_text or html_features.visible_text or ""
    r1_raw = build_raw_representation(raw_source)

    # R2: Normalized (traceably derived from R1)
    r2_normalized = build_normalized_representation(r1_raw.text)

    # R3: Visual / OCR (async extraction from screenshot)
    r3_visual = await build_visual_representation(
        screenshot_path=crawler_result.screenshot_path,
        ocr_engine=ocr_engine,
    )

    # R4: Semantic (intent, headings, form goals)
    r4_semantic = build_semantic_representation(html_features)

    # R5: URL (lexical and domain tokens)
    r5_url = build_url_representation(url_features)

    return RepresentationSet(
        analysis_id=crawler_result.analysis_id,
        r1_raw=r1_raw,
        r2_normalized=r2_normalized,
        r3_visual=r3_visual,
        r4_semantic=r4_semantic,
        r5_url=r5_url,
    )
