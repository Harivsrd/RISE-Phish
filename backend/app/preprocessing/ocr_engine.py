"""Abstract OCR engine interface and implementations for RISE-Phish.

Provides a unified contract for Optical Character Recognition, with production
implementations for Tesseract OCR, fallback simulation for tests, and architectural
hooks for future PaddleOCR evaluation.
"""
from abc import ABC, abstractmethod
import io
import os
import shutil
import time
from typing import List, Optional, Union
from PIL import Image, UnidentifiedImageError
import pytesseract
from pytesseract import Output

from backend.app.core.config import get_settings
from backend.app.core.logging import logger
from backend.app.models.schemas import OCRResult, OCRWord

settings = get_settings()

# Standard Windows installation paths for Tesseract OCR
COMMON_TESSERACT_WINDOWS_PATHS = [
    r"C:\Program Files\Tesseract-OCR\tesseract.exe",
    r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Programs\Tesseract-OCR\tesseract.exe"),
]


class BaseOCREngine(ABC):
    """Abstract interface defining the contract for OCR visual text extraction."""

    @property
    @abstractmethod
    def engine_name(self) -> str:
        """Identifier name of the active OCR engine."""
        pass

    @abstractmethod
    def is_ready(self) -> bool:
        """Returns True if the engine's dependencies and binaries are accessible."""
        pass

    @abstractmethod
    async def extract_text(
        self,
        image_input: Union[str, bytes, Image.Image],
    ) -> OCRResult:
        """Extracts optical character text and token confidences from an image.

        Args:
            image_input: File path, raw bytes, or PIL Image instance.

        Returns:
            Structured OCRResult containing extracted text, word confidences, and diagnostics.
        """
        pass


class TesseractOCREngine(BaseOCREngine):
    """Production OCR engine utilizing Tesseract via pytesseract.

    Features automatic binary path discovery on Windows and robust
    exception containment.
    """

    def __init__(self, tesseract_cmd: Optional[str] = None):
        self._cmd_path: Optional[str] = None
        self._ready: bool = False
        self._configure_binary(tesseract_cmd)

    @property
    def engine_name(self) -> str:
        return "TesseractOCR"

    def is_ready(self) -> bool:
        return self._ready

    def _configure_binary(self, custom_cmd: Optional[str] = None):
        """Discovers and verifies the Tesseract executable path."""
        if custom_cmd:
            if os.path.exists(custom_cmd) and os.path.isfile(custom_cmd):
                self._cmd_path = custom_cmd
                pytesseract.pytesseract.tesseract_cmd = custom_cmd
                self._ready = True
                logger.debug(f"Configured custom Tesseract binary: {custom_cmd}")
            else:
                logger.warning(f"Specified Tesseract binary does not exist: {custom_cmd}")
                self._cmd_path = None
                self._ready = False
            return

        candidates = []
        if settings.TESSERACT_CMD:
            candidates.append(settings.TESSERACT_CMD)

        which_path = shutil.which("tesseract")
        if which_path:
            candidates.append(which_path)

        candidates.extend(COMMON_TESSERACT_WINDOWS_PATHS)

        for path in candidates:
            if path and os.path.exists(path) and os.path.isfile(path):
                self._cmd_path = path
                pytesseract.pytesseract.tesseract_cmd = path
                self._ready = True
                logger.debug(f"Configured Tesseract OCR binary: {path}")
                return

        logger.warning(
            "Tesseract binary not found in PATH or standard directories. "
            "OCR will report as unavailable unless configured."
        )
        self._ready = False

    async def extract_text(
        self,
        image_input: Union[str, bytes, Image.Image],
    ) -> OCRResult:
        """Extracts text and word confidences using Tesseract."""
        start_time = time.perf_counter()

        if not self._ready:
            elapsed = int((time.perf_counter() - start_time) * 1000)
            logger.warning("OCR requested but Tesseract engine is unavailable.")
            return OCRResult(
                text="",
                confidence=0.0,
                words=[],
                available=False,
                engine_name=self.engine_name,
                error_message="OCR unavailable: Tesseract executable not found on host system.",
                latency_ms=elapsed,
            )

        # 1. Resolve and open image input
        pil_image: Optional[Image.Image] = None
        try:
            if isinstance(image_input, Image.Image):
                pil_image = image_input
            elif isinstance(image_input, str):
                if not os.path.exists(image_input):
                    elapsed = int((time.perf_counter() - start_time) * 1000)
                    return OCRResult(
                        text="",
                        confidence=0.0,
                        words=[],
                        available=False,
                        engine_name=self.engine_name,
                        error_message=f"Image file not found: {image_input}",
                        latency_ms=elapsed,
                    )
                pil_image = Image.open(image_input)
            elif isinstance(image_input, (bytes, bytearray)):
                pil_image = Image.open(io.BytesIO(image_input))
            else:
                elapsed = int((time.perf_counter() - start_time) * 1000)
                return OCRResult(
                    text="",
                    confidence=0.0,
                    words=[],
                    available=False,
                    engine_name=self.engine_name,
                    error_message=f"Unsupported image input type: {type(image_input).__name__}",
                    latency_ms=elapsed,
                )
        except UnidentifiedImageError as img_err:
            elapsed = int((time.perf_counter() - start_time) * 1000)
            logger.warning(f"Failed to identify image format: {img_err}")
            return OCRResult(
                text="",
                confidence=0.0,
                words=[],
                available=False,
                engine_name=self.engine_name,
                error_message=f"Invalid or corrupt image format: {img_err}",
                latency_ms=elapsed,
            )
        except Exception as open_err:
            elapsed = int((time.perf_counter() - start_time) * 1000)
            logger.warning(f"Failed to open image for OCR: {open_err}")
            return OCRResult(
                text="",
                confidence=0.0,
                words=[],
                available=False,
                engine_name=self.engine_name,
                error_message=f"Failed to load image: {open_err}",
                latency_ms=elapsed,
            )

        # 2. Execute Tesseract OCR with detailed output data
        try:
            data = pytesseract.image_to_data(pil_image, output_type=Output.DICT)

            words: List[OCRWord] = []
            extracted_tokens: List[str] = []
            confidences: List[float] = []

            n_boxes = len(data.get("text", []))
            for i in range(n_boxes):
                token = data["text"][i].strip()
                conf_raw = data["conf"][i]

                # Tesseract returns -1 confidence for spaces/blank lines
                try:
                    conf_val = float(conf_raw)
                except (ValueError, TypeError):
                    conf_val = -1.0

                if token and conf_val >= 0:
                    extracted_tokens.append(token)
                    confidences.append(conf_val)
                    box = (
                        int(data["left"][i]),
                        int(data["top"][i]),
                        int(data["width"][i]),
                        int(data["height"][i]),
                    )
                    words.append(
                        OCRWord(
                            text=token,
                            confidence=round(conf_val, 2),
                            box=box,
                        )
                    )

            full_text = " ".join(extracted_tokens)
            avg_confidence = round(sum(confidences) / len(confidences), 2) if confidences else 0.0
            elapsed = int((time.perf_counter() - start_time) * 1000)

            logger.info(f"Tesseract OCR extracted {len(words)} words ({elapsed}ms, avg conf: {avg_confidence}%)")
            return OCRResult(
                text=full_text,
                confidence=avg_confidence,
                words=words,
                available=True,
                engine_name=self.engine_name,
                latency_ms=elapsed,
            )

        except pytesseract.TesseractNotFoundError as tnf_err:
            elapsed = int((time.perf_counter() - start_time) * 1000)
            logger.error(f"Tesseract binary execution failed: {tnf_err}")
            return OCRResult(
                text="",
                confidence=0.0,
                words=[],
                available=False,
                engine_name=self.engine_name,
                error_message="OCR unavailable: Tesseract executable not found or failed to execute.",
                latency_ms=elapsed,
            )
        except Exception as ocr_err:
            elapsed = int((time.perf_counter() - start_time) * 1000)
            logger.error(f"Tesseract OCR processing error: {ocr_err}")
            return OCRResult(
                text="",
                confidence=0.0,
                words=[],
                available=False,
                engine_name=self.engine_name,
                error_message=f"OCR processing failed: {ocr_err}",
                latency_ms=elapsed,
            )


class MockOCREngine(BaseOCREngine):
    """Deterministic mock OCR engine for testing and simulating failure states."""

    def __init__(
        self,
        default_text: str = "Mock OCR Text",
        default_confidence: float = 95.0,
        simulate_failure: bool = False,
    ):
        self._default_text = default_text
        self._default_confidence = default_confidence
        self._simulate_failure = simulate_failure

    @property
    def engine_name(self) -> str:
        return "MockOCR"

    def is_ready(self) -> bool:
        return not self._simulate_failure

    async def extract_text(
        self,
        image_input: Union[str, bytes, Image.Image],
    ) -> OCRResult:
        if self._simulate_failure:
            return OCRResult(
                text="",
                confidence=0.0,
                words=[],
                available=False,
                engine_name=self.engine_name,
                error_message="OCR unavailable: Simulated mock failure condition.",
                latency_ms=5,
            )

        tokens = self._default_text.split()
        words = [
            OCRWord(text=t, confidence=self._default_confidence, box=(0, 0, 50, 20))
            for t in tokens
        ]
        return OCRResult(
            text=self._default_text,
            confidence=self._default_confidence,
            words=words,
            available=True,
            engine_name=self.engine_name,
            latency_ms=10,
        )


def get_ocr_engine(engine_type: Optional[str] = None) -> BaseOCREngine:
    """Factory creating an OCR engine based on configuration or explicit request.

    Args:
        engine_type: 'tesseract', 'mock', or 'paddleocr'. Defaults to settings.OCR_ENGINE.

    Returns:
        Instance conforming to BaseOCREngine.
    """
    selected_type = (engine_type or settings.OCR_ENGINE).lower()

    if selected_type == "tesseract":
        return TesseractOCREngine()
    elif selected_type == "mock":
        return MockOCREngine()
    elif selected_type == "paddleocr":
        raise NotImplementedError(
            "PaddleOCR engine is reserved for later research evaluation. "
            "Use 'tesseract' or 'mock'."
        )
    else:
        logger.warning(f"Unknown OCR engine type '{selected_type}', falling back to Tesseract.")
        return TesseractOCREngine()
