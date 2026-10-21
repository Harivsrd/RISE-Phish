"""Comprehensive test suite for Phase 5 OCR Pipeline.

Verifies:
- Abstract OCR engine contract and polymorphism
- Production Tesseract OCR extraction on rendered synthetic images
- Bounding box and confidence score calculations
- Graceful failure containment when files are missing or corrupt
- Mock OCR engine for fast testing and simulated failure states
- OCR factory initialization
"""
import io
import pytest
from PIL import Image, ImageDraw

from backend.app.preprocessing.ocr_engine import (
    BaseOCREngine,
    MockOCREngine,
    TesseractOCREngine,
    get_ocr_engine,
)


@pytest.mark.asyncio
async def test_mock_ocr_engine_success():
    """Verify MockOCREngine produces expected tokens and metrics."""
    engine = MockOCREngine(default_text="Online Banking Secure Login", default_confidence=98.5)
    assert engine.is_ready() is True
    assert engine.engine_name == "MockOCR"

    # Dummy byte input
    result = await engine.extract_text(b"mock_bytes")
    assert result.available is True
    assert result.text == "Online Banking Secure Login"
    assert result.confidence == 98.5
    assert len(result.words) == 4
    assert result.words[0].text == "Online"


@pytest.mark.asyncio
async def test_mock_ocr_engine_failure_simulation():
    """Verify MockOCREngine gracefully reports simulated unavailability."""
    engine = MockOCREngine(simulate_failure=True)
    assert engine.is_ready() is False

    result = await engine.extract_text("dummy_path.png")
    assert result.available is False
    assert "OCR unavailable" in result.error_message
    assert result.text == ""


@pytest.mark.asyncio
async def test_tesseract_ocr_synthetic_image():
    """Verify live Tesseract OCR extraction on a freshly generated synthetic PIL image."""
    engine = TesseractOCREngine()

    # Skip test only if Tesseract binary is not installed on host
    if not engine.is_ready():
        pytest.skip("Tesseract binary not installed on host machine.")

    # Create high-contrast test image with crisp resolution
    img = Image.new("RGB", (400, 80), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    draw.text((15, 25), "Account Verification", fill=(0, 0, 0))
    # Scale up so default bitmap font characters match OCR DPI expectations
    scaled_img = img.resize((1200, 240), Image.Resampling.NEAREST)

    result = await engine.extract_text(scaled_img)

    assert result.available is True
    assert result.engine_name == "TesseractOCR"
    assert "Account" in result.text
    assert "Verification" in result.text
    assert result.confidence > 50.0
    assert len(result.words) >= 2
    assert result.latency_ms > 0


@pytest.mark.asyncio
async def test_tesseract_missing_file_graceful_handling():
    """Verify that non-existent image paths do not crash the pipeline."""
    engine = TesseractOCREngine()
    result = await engine.extract_text("C:/non_existent_directory/fake_screenshot_1234.png")

    assert result.available is False
    assert "Image file not found" in result.error_message


@pytest.mark.asyncio
async def test_tesseract_corrupt_bytes_handling():
    """Verify that corrupted image bytes do not raise unhandled exceptions."""
    engine = TesseractOCREngine()
    if not engine.is_ready():
        pytest.skip("Tesseract binary not installed on host machine.")

    corrupt_data = b"THIS IS NOT A VALID IMAGE STREAM"
    result = await engine.extract_text(corrupt_data)

    assert result.available is False
    assert "Invalid or corrupt image format" in result.error_message


def test_ocr_factory_initialization():
    """Verify get_ocr_engine factory resolves implementations correctly."""
    tesseract_engine = get_ocr_engine("tesseract")
    assert isinstance(tesseract_engine, TesseractOCREngine)

    mock_engine = get_ocr_engine("mock")
    assert isinstance(mock_engine, MockOCREngine)

    # PaddleOCR is reserved for future evaluation
    with pytest.raises(NotImplementedError):
        get_ocr_engine("paddleocr")


@pytest.mark.asyncio
async def test_tesseract_unconfigured_binary_reports_unavailable():
    """Verify engine reports unavailable when pointed to a non-existent binary."""
    engine = TesseractOCREngine(tesseract_cmd="C:/fake_path/fake_tesseract.exe")
    assert engine.is_ready() is False

    result = await engine.extract_text(b"some_bytes")
    assert result.available is False
    assert "OCR unavailable" in result.error_message
