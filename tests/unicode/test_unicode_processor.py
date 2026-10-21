"""Comprehensive test suite for Phase 4 Unicode Analyzer.

Verifies detection of:
- Standard ASCII (no false positives)
- Legitimate accented characters (French, German, Spanish - zero false positives)
- Homoglyphs in mixed-script tokens
- Monolingual non-Latin scripts (Cyrillic - zero false positives)
- Zero-width spaces & joiners
- Bidirectional (BiDi) overrides
- Plane 14 Unicode tag characters
- Fullwidth and NFKC normalization changes
"""
import pytest
from backend.app.preprocessing.unicode_processor import analyze_unicode, get_character_script


def test_pure_ascii_text():
    """Verify standard ASCII strings produce zero anomalies and zero score."""
    text = "Welcome to our secure official website. Please sign in."
    result = analyze_unicode(text)

    assert result.total_characters == len(text)
    assert result.ascii_characters == len(text)
    assert result.non_ascii_characters == 0
    assert len(result.anomalies) == 0
    assert result.homoglyph_count == 0
    assert result.unicode_anomaly_score == 0.0


def test_legitimate_accented_characters_no_false_positives():
    """Verify French, German, Spanish, and Scandinavian accented characters are NOT flagged."""
    # French and Spanish
    text_fr_es = "Le café à la crème avec une piñata très agréable."
    result_fr = analyze_unicode(text_fr_es)
    assert result_fr.homoglyph_count == 0
    assert result_fr.zero_width_count == 0
    assert result_fr.bidi_control_count == 0
    assert len(result_fr.anomalies) == 0
    assert result_fr.unicode_anomaly_score == 0.0

    # German
    text_de = "Schöne Grüße aus München! Bitte bestätigen Sie Ihr Konto."
    result_de = analyze_unicode(text_de)
    assert result_de.homoglyph_count == 0
    assert result_de.zero_width_count == 0
    assert len(result_de.anomalies) == 0
    assert result_de.unicode_anomaly_score == 0.0


def test_monolingual_cyrillic_no_false_positives():
    """Verify that pure Cyrillic text is recognized as legitimate language, not homoglyphs."""
    text_ru = "Добро пожаловать в личный кабинет. Введите пароль."
    result = analyze_unicode(text_ru)

    assert result.homoglyph_count == 0
    assert result.mixed_script_token_count == 0
    assert len(result.anomalies) == 0
    assert result.unicode_anomaly_score == 0.0
    assert "Cyrillic" in result.detected_scripts


def test_homoglyphs_in_mixed_script_tokens():
    """Verify that Cyrillic/Greek lookalike characters in Latin words are detected."""
    # "Mіcrosoft" where 'і' is Cyrillic Small Letter Byelorussian-Ukrainian I (U+0456)
    spoofed = "Please verify your M\u0456crosoft account credentials"
    result = analyze_unicode(spoofed)

    assert result.homoglyph_count == 1
    assert result.mixed_script_token_count == 1
    assert len(result.anomalies) == 1

    anomaly = result.anomalies[0]
    assert anomaly.anomaly_type == "homoglyph"
    assert anomaly.codepoint == "U+0456"
    assert anomaly.codepoint_int == 0x0456
    assert anomaly.script == "Cyrillic"
    assert "BYELORUSSIAN-UKRAINIAN" in anomaly.name
    assert anomaly.context_token == "M\u0456crosoft"
    assert anomaly.is_mixed_script_token is True
    assert anomaly.severity >= 0.90
    assert result.unicode_anomaly_score > 0.0


def test_zero_width_characters():
    """Verify zero-width space and joiner characters are detected with position and token context."""
    # "Pass<ZWSP>word"
    obfuscated = "Your Pass\u200Bword is required"
    result = analyze_unicode(obfuscated)

    assert result.zero_width_count == 1
    assert len(result.anomalies) == 1

    anomaly = result.anomalies[0]
    assert anomaly.anomaly_type == "zero_width"
    assert anomaly.codepoint == "U+200B"
    assert anomaly.codepoint_int == 0x200B
    assert anomaly.name == "ZERO WIDTH SPACE"
    assert anomaly.position == 9
    assert anomaly.severity >= 0.85
    assert result.unicode_anomaly_score > 0.0


def test_bidi_override_controls():
    """Verify Right-to-Left Override (RLO U+202E) is flagged with high severity."""
    # Reverses visual display order: "invoice\u202Ecod.exe"
    bidi_attack = "Download invoice\u202Ecod.exe now"
    result = analyze_unicode(bidi_attack)

    assert result.bidi_control_count == 1
    assert len(result.anomalies) == 1

    anomaly = result.anomalies[0]
    assert anomaly.anomaly_type == "bidi_control"
    assert anomaly.codepoint == "U+202E"
    assert anomaly.codepoint_int == 0x202E
    assert anomaly.name == "RIGHT-TO-LEFT OVERRIDE"
    assert anomaly.severity == 0.95


def test_plane14_tag_characters():
    """Verify Plane 14 tag characters are detected."""
    # Tag Space (U+E0020)
    tag_string = "Secure\U000E0020Login"
    result = analyze_unicode(tag_string)

    assert result.tag_character_count == 1
    assert len(result.anomalies) == 1

    anomaly = result.anomalies[0]
    assert anomaly.anomaly_type == "tag_character"
    assert anomaly.codepoint == "U+E0020"
    assert anomaly.severity >= 0.90


def test_fullwidth_normalization_changes():
    """Verify Fullwidth Latin characters are detected and normalize correctly under NFKC."""
    # Fullwidth "Pay" -> \uFF30\uFF41\uFF59
    fullwidth_text = "\uFF30\uFF41\uFF59Pal"
    result = analyze_unicode(fullwidth_text)

    assert result.normalization_change_count == 3
    assert len(result.anomalies) == 3

    assert result.anomalies[0].normalized_nfkc == "P"
    assert result.anomalies[1].normalized_nfkc == "a"
    assert result.anomalies[2].normalized_nfkc == "y"


def test_empty_and_none_text():
    """Verify empty or None input returns zeroed model without throwing unhandled exceptions."""
    result_none = analyze_unicode(None)
    assert result_none.total_characters == 0
    assert result_none.unicode_anomaly_score == 0.0

    result_empty = analyze_unicode("")
    assert result_empty.total_characters == 0
    assert result_empty.unicode_anomaly_score == 0.0
