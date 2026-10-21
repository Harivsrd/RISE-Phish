"""R3: Visual / OCR representation generator.

Derives visual text from screenshot assets using the pluggable OCR pipeline.
"""
from typing import Optional

from backend.app.core.logging import logger
from backend.app.models.schemas import VisualRepresentation
from backend.app.preprocessing.ocr_engine import BaseOCREngine, get_ocr_engine


async def build_visual_representation(
    screenshot_path: Optional[str],
    ocr_engine: Optional[BaseOCREngine] = None,
) -> VisualRepresentation:
    """Derives R3 VisualRepresentation from a page screenshot.

    Args:
        screenshot_path: Local filesystem path to captured PNG screenshot.
        ocr_engine: Active OCR engine (defaults to configured engine via factory).

    Returns:
        Structured VisualRepresentation instance.
    """
    if not screenshot_path:
        logger.debug("No screenshot path provided; R3 visual text will be empty.")
        return VisualRepresentation(
            text="",
            confidence=0.0,
            available=False,
            screenshot_path=None,
            words_count=0,
            engine_name="None",
            error_message="OCR unavailable: No screenshot captured or available.",
        )

    engine = ocr_engine or get_ocr_engine()
    ocr_result = await engine.extract_text(screenshot_path)

    return VisualRepresentation(
        text=ocr_result.text,
        confidence=ocr_result.confidence,
        available=ocr_result.available,
        screenshot_path=screenshot_path,
        words_count=len(ocr_result.words),
        engine_name=ocr_result.engine_name,
        error_message=ocr_result.error_message,
    )
