"""Preprocessing package for RISE-Phish.
"""
from backend.app.preprocessing.html_processor import clean_text, extract_html_features
from backend.app.preprocessing.unicode_processor import (
    analyze_unicode,
    get_character_script,
    ZERO_WIDTH_CODEPOINTS,
    BIDI_CONTROL_CODEPOINTS,
    HOMOGLYPH_MAP,
)
from backend.app.preprocessing.url_processor import (
    analyze_url,
    calculate_shannon_entropy,
    detect_ip_address,
)

__all__ = [
    "extract_html_features",
    "clean_text",
    "analyze_url",
    "calculate_shannon_entropy",
    "detect_ip_address",
    "analyze_unicode",
    "get_character_script",
    "ZERO_WIDTH_CODEPOINTS",
    "BIDI_CONTROL_CODEPOINTS",
    "HOMOGLYPH_MAP",
]
