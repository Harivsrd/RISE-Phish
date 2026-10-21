"""Unicode feature extraction and homoglyph/anomaly analysis module.

Detects zero-width characters, bidirectional control marks, Plane 14 tags,
mixed-script homoglyphs, and normalization discrepancies while explicitly
respecting legitimate internationalization and accented characters.
"""
import re
import unicodedata
from typing import Dict, List, Optional, Set, Tuple

from backend.app.core.logging import logger
from backend.app.models.schemas import UnicodeAnomaly, UnicodeAnalysisResult

# ============================================================
# UNICODE CODEPOINT DEFINITIONS
# ============================================================

# Zero-width, invisible joiner, and separation characters
ZERO_WIDTH_CODEPOINTS: Set[int] = {
    0x200B,  # ZERO WIDTH SPACE
    0x200C,  # ZERO WIDTH NON-JOINER
    0x200D,  # ZERO WIDTH JOINER
    0xFEFF,  # ZERO WIDTH NO-BREAK SPACE / BYTE ORDER MARK
    0x2060,  # WORD JOINER
    0x180E,  # MONGOLIAN VOWEL SEPARATOR
    0x200E,  # LEFT-TO-RIGHT MARK
    0x200F,  # RIGHT-TO-LEFT MARK
}

# Bidirectional (BiDi) overrides and embeddings
BIDI_CONTROL_CODEPOINTS: Set[int] = {
    0x202A,  # LEFT-TO-RIGHT EMBEDDING (LRE)
    0x202B,  # RIGHT-TO-LEFT EMBEDDING (RLE)
    0x202C,  # POP DIRECTIONAL FORMATTING (PDF)
    0x202D,  # LEFT-TO-RIGHT OVERRIDE (LRO)
    0x202E,  # RIGHT-TO-LEFT OVERRIDE (RLO) - Extremely high abuse profile
    0x2066,  # LEFT-TO-RIGHT ISOLATE (LRI)
    0x2067,  # RIGHT-TO-LEFT ISOLATE (RLI)
    0x2068,  # FIRST STRONG ISOLATE (FSI)
    0x2069,  # POP DIRECTIONAL ISOLATE (PDI)
}

# Common lookalike mapping dictionary: Non-Latin to ASCII Latin visual equivalents
HOMOGLYPH_MAP: Dict[str, str] = {
    # Cyrillic small letters
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ԛ": "q", "ѵ": "v", "ѡ": "w",
    # Cyrillic capital letters
    "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "І": "I", "Ј": "J",
    "К": "K", "М": "M", "О": "O", "Р": "P", "Ѕ": "S", "Т": "T", "Х": "X",
    # Greek letters
    "α": "a", "ο": "o", "ν": "v", "ρ": "p", "ι": "i", "κ": "k",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
}


def get_character_script(char: str) -> str:
    """Classifies a character into its high-level Unicode script family."""
    cp = ord(char)

    # Fast-path ASCII
    if cp < 128:
        if char.isalnum():
            return "Latin"
        return "Common"

    # Query Unicode database name
    try:
        char_name = unicodedata.name(char, "").upper()
    except Exception:
        char_name = ""

    if char_name.startswith("LATIN"):
        return "Latin"
    elif char_name.startswith("CYRILLIC"):
        return "Cyrillic"
    elif char_name.startswith("GREEK"):
        return "Greek"
    elif char_name.startswith("ARABIC"):
        return "Arabic"
    elif char_name.startswith("HEBREW"):
        return "Hebrew"
    elif any(term in char_name for term in ("CJK", "HIRAGANA", "KATAKANA", "HANGUL")):
        return "EastAsian"

    # General category fallback
    category = unicodedata.category(char)
    if category.startswith("P") or category.startswith("Z") or category.startswith("S"):
        return "Common"

    return "Other"


def is_plane14_tag(cp: int) -> bool:
    """Checks whether a codepoint belongs to the Plane 14 Tag characters range."""
    return cp == 0xE0001 or (0xE0020 <= cp <= 0xE007F)


def is_fullwidth_character(cp: int) -> bool:
    """Checks whether a codepoint is a Fullwidth form (U+FF01 to U+FF5E)."""
    return 0xFF01 <= cp <= 0xFF5E


def analyze_unicode(text: Optional[str]) -> UnicodeAnalysisResult:
    """Performs rigorous Unicode anomaly, homoglyph, and normalization inspection.

    Args:
        text: Target text sequence (HTML visible text, domain name, or title).

    Returns:
        Structured UnicodeAnalysisResult containing detailed anomaly objects,
        script counts, and an anomaly score.
    """
    if not text or not isinstance(text, str):
        return UnicodeAnalysisResult()

    total_chars = len(text)
    ascii_chars = sum(1 for c in text if ord(c) < 128)
    non_ascii_chars = total_chars - ascii_chars

    anomalies: List[UnicodeAnomaly] = []
    zero_width_count = 0
    bidi_control_count = 0
    tag_character_count = 0
    homoglyph_count = 0
    normalization_change_count = 0

    # 1. Tokenize words to inspect context and detect mixed-script tokens
    token_spans: List[Tuple[str, int, int]] = []
    for match in re.finditer(r"\S+", text):
        token_spans.append((match.group(0), match.start(), match.end()))

    # Build token-to-scripts map
    mixed_script_tokens: Set[str] = set()
    token_lookup: Dict[int, str] = {}

    for token, start, end in token_spans:
        # Map each character position to its parent token
        for pos in range(start, end):
            token_lookup[pos] = token

        # Extract letter scripts present in this token
        letters = [c for c in token if c.isalpha()]
        scripts_in_token = {get_character_script(c) for c in letters if get_character_script(c) not in ("Common", "Other")}

        # Confirmed mixed script: Contains Latin along with Cyrillic or Greek
        if "Latin" in scripts_in_token and len(scripts_in_token) > 1:
            mixed_script_tokens.add(token)

    # 2. Character-by-character inspection
    unique_scripts: Set[str] = set()

    for idx, char in enumerate(text):
        cp = ord(char)
        char_name = unicodedata.name(char, "UNKNOWN")
        category = unicodedata.category(char)
        script = get_character_script(char)
        unique_scripts.add(script)
        hex_codepoint = f"U+{cp:04X}"
        normalized_char = unicodedata.normalize("NFKC", char)
        parent_token = token_lookup.get(idx)
        is_mixed_token = parent_token in mixed_script_tokens if parent_token else False

        # --- Check 1: Zero-Width & Invisible Characters ---
        if cp in ZERO_WIDTH_CODEPOINTS:
            zero_width_count += 1
            anomalies.append(
                UnicodeAnomaly(
                    character=char,
                    codepoint=hex_codepoint,
                    codepoint_int=cp,
                    name=char_name,
                    category=category,
                    script=script,
                    position=idx,
                    context_token=parent_token,
                    anomaly_type="zero_width",
                    normalized_nfkc=normalized_char,
                    is_mixed_script_token=is_mixed_token,
                    reason=f"Zero-width/invisible separator character '{char_name}' ({hex_codepoint})",
                    severity=0.85,
                )
            )
            continue

        # --- Check 2: Bidirectional (BiDi) Overrides ---
        if cp in BIDI_CONTROL_CODEPOINTS:
            bidi_control_count += 1
            severity = 0.95 if cp == 0x202E else 0.80  # RLO (U+202E) is highest threat
            anomalies.append(
                UnicodeAnomaly(
                    character=char,
                    codepoint=hex_codepoint,
                    codepoint_int=cp,
                    name=char_name,
                    category=category,
                    script=script,
                    position=idx,
                    context_token=parent_token,
                    anomaly_type="bidi_control",
                    normalized_nfkc=normalized_char,
                    is_mixed_script_token=is_mixed_token,
                    reason=f"Bidirectional control character '{char_name}' ({hex_codepoint}) can reverse rendered text flow",
                    severity=severity,
                )
            )
            continue

        # --- Check 3: Unicode Tag Characters (Plane 14) ---
        if is_plane14_tag(cp):
            tag_character_count += 1
            anomalies.append(
                UnicodeAnomaly(
                    character=char,
                    codepoint=hex_codepoint,
                    codepoint_int=cp,
                    name=char_name,
                    category=category,
                    script=script,
                    position=idx,
                    context_token=parent_token,
                    anomaly_type="tag_character",
                    normalized_nfkc=normalized_char,
                    is_mixed_script_token=is_mixed_token,
                    reason=f"Plane 14 Unicode Tag character '{char_name}' ({hex_codepoint})",
                    severity=0.90,
                )
            )
            continue

        # --- Check 4: Cross-Script Homoglyphs in Mixed-Script Context ---
        if char in HOMOGLYPH_MAP:
            target_ascii = HOMOGLYPH_MAP[char]
            if is_mixed_token:
                # Character is embedded inside a predominantly Latin token
                homoglyph_count += 1
                anomalies.append(
                    UnicodeAnomaly(
                        character=char,
                        codepoint=hex_codepoint,
                        codepoint_int=cp,
                        name=char_name,
                        category=category,
                        script=script,
                        position=idx,
                        context_token=parent_token,
                        anomaly_type="homoglyph",
                        normalized_nfkc=normalized_char,
                        is_mixed_script_token=True,
                        reason=(
                            f"{script} homoglyph '{char}' ({hex_codepoint}) looks like ASCII '{target_ascii}' "
                            f"inside Latin token '{parent_token}'"
                        ),
                        severity=0.90,
                    )
                )
                continue

        # --- Check 5: Fullwidth Forms & Normalization Discrepancies ---
        if is_fullwidth_character(cp):
            normalization_change_count += 1
            anomalies.append(
                UnicodeAnomaly(
                    character=char,
                    codepoint=hex_codepoint,
                    codepoint_int=cp,
                    name=char_name,
                    category=category,
                    script=script,
                    position=idx,
                    context_token=parent_token,
                    anomaly_type="normalization_change",
                    normalized_nfkc=normalized_char,
                    is_mixed_script_token=is_mixed_token,
                    reason=f"Fullwidth character '{char}' ({hex_codepoint}) normalizes to '{normalized_char}' under NFKC",
                    severity=0.70,
                )
            )
            continue

        # General invisible / unassigned format control
        if category == "Cf" and cp not in ZERO_WIDTH_CODEPOINTS and cp not in BIDI_CONTROL_CODEPOINTS:
            anomalies.append(
                UnicodeAnomaly(
                    character=char,
                    codepoint=hex_codepoint,
                    codepoint_int=cp,
                    name=char_name,
                    category=category,
                    script=script,
                    position=idx,
                    context_token=parent_token,
                    anomaly_type="invisible_format",
                    normalized_nfkc=normalized_char,
                    is_mixed_script_token=is_mixed_token,
                    reason=f"Invisible format character '{char_name}' ({hex_codepoint}) of category Cf",
                    severity=0.60,
                )
            )

    # 3. Calculate Normalized Unicode Anomaly Score
    # Scientifically grounded: We penalize deliberate anomalies while NOT penalizing
    # natural international text (accented Latin, monolingual Cyrillic, etc.)
    score = 0.0
    if total_chars > 0:
        critical_anomaly_weight = (
            (bidi_control_count * 0.95) +
            (tag_character_count * 0.90) +
            (zero_width_count * 0.85) +
            (homoglyph_count * 0.90) +
            (normalization_change_count * 0.50)
        )
        # Normalize relative to token density
        score = min(1.0, critical_anomaly_weight / max(1.0, len(token_spans)))

    unicode_anomaly_score = round(score, 4)

    # 4. Generate Research Summary
    summary_parts = []
    if homoglyph_count > 0:
        summary_parts.append(f"{homoglyph_count} mixed-script homoglyphs")
    if zero_width_count > 0:
        summary_parts.append(f"{zero_width_count} zero-width characters")
    if bidi_control_count > 0:
        summary_parts.append(f"{bidi_control_count} BiDi override controls")
    if tag_character_count > 0:
        summary_parts.append(f"{tag_character_count} Plane 14 tag characters")
    if normalization_change_count > 0:
        summary_parts.append(f"{normalization_change_count} fullwidth/normalization changes")

    if summary_parts:
        summary = f"Detected: {', '.join(summary_parts)} across {len(mixed_script_tokens)} mixed-script tokens."
    else:
        summary = "No suspicious Unicode anomalies detected. Character distributions conform to standard scripts."

    return UnicodeAnalysisResult(
        total_characters=total_chars,
        ascii_characters=ascii_chars,
        non_ascii_characters=non_ascii_chars,
        anomalies=anomalies,
        zero_width_count=zero_width_count,
        bidi_control_count=bidi_control_count,
        tag_character_count=tag_character_count,
        homoglyph_count=homoglyph_count,
        normalization_change_count=normalization_change_count,
        mixed_script_token_count=len(mixed_script_tokens),
        detected_scripts=sorted(list(unique_scripts)),
        unicode_anomaly_score=unicode_anomaly_score,
        summary=summary,
    )
