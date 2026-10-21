"""R2: Normalized representation generator.

Applies canonical NFKC composition/decomposition, HTML entity decoding,
and invisible character stripping with full transformation traceability.
"""
import html
import re
import unicodedata
from typing import List, Tuple

from backend.app.models.schemas import NormalizedRepresentation
from backend.app.preprocessing.unicode_processor import (
    ZERO_WIDTH_CODEPOINTS,
    BIDI_CONTROL_CODEPOINTS,
    HOMOGLYPH_MAP,
    get_character_script,
)


def build_normalized_representation(
    r1_text: str,
) -> NormalizedRepresentation:
    """Traceably derives R2 NormalizedRepresentation from R1 raw text.

    Executes:
    1. HTML entity unescaping (&amp; -> &, &quot; -> ", etc.)
    2. NFKC canonical Unicode composition/decomposition
    3. Zero-width and invisible control character stripping
    4. Uniform whitespace collapsing

    Args:
        r1_text: Source text from R1.

    Returns:
        Structured NormalizedRepresentation containing audit records.
    """
    if not r1_text:
        return NormalizedRepresentation(
            text="",
            character_count=0,
            transformations_applied=[],
            characters_altered_count=0,
        )

    current_text = r1_text
    transformations: List[str] = []

    # 1. HTML Entity Decoding
    unescaped = html.unescape(current_text)
    if unescaped != current_text:
        transformations.append("html_entity_unescaping")
        current_text = unescaped

    # 2. Canonical NFKC Normalization
    nfkc_text = unicodedata.normalize("NFKC", current_text)
    if nfkc_text != current_text:
        transformations.append("nfkc_unicode_normalization")
        current_text = nfkc_text

    # 3. Strip zero-width, invisible format, and uncomposed combining diacritical marks
    stripped_chars = []
    zero_width_stripped = False
    combining_stripped = False
    for char in current_text:
        if ord(char) in ZERO_WIDTH_CODEPOINTS or ord(char) in BIDI_CONTROL_CODEPOINTS:
            zero_width_stripped = True
        elif unicodedata.combining(char) > 0:
            combining_stripped = True
        else:
            stripped_chars.append(char)

    if zero_width_stripped:
        transformations.append("invisible_character_stripping")
    if combining_stripped:
        transformations.append("combining_diacritic_stripping")
    if zero_width_stripped or combining_stripped:
        current_text = "".join(stripped_chars)

    # 4. Resolve mixed-script homoglyphs to canonical ASCII
    homoglyphs_resolved = False
    tokens = re.split(r"(\s+)", current_text)
    resolved_tokens = []
    for tok in tokens:
        if not tok.isspace() and tok:
            letters = [c for c in tok if c.isalpha()]
            scripts = {get_character_script(c) for c in letters if get_character_script(c) not in ("Common", "Other")}
            if "Latin" in scripts and len(scripts) > 1:
                new_tok = []
                for c in tok:
                    if c in HOMOGLYPH_MAP:
                        new_tok.append(HOMOGLYPH_MAP[c])
                        homoglyphs_resolved = True
                    else:
                        new_tok.append(c)
                resolved_tokens.append("".join(new_tok))
            else:
                resolved_tokens.append(tok)
        else:
            resolved_tokens.append(tok)

    if homoglyphs_resolved:
        transformations.append("homoglyph_resolution")
        current_text = "".join(resolved_tokens)

    # 5. Standardized Whitespace Collapsing
    collapsed = re.sub(r"\s+", " ", current_text).strip()
    if collapsed != current_text:
        transformations.append("whitespace_collapsing")
        current_text = collapsed

    # Calculate altered character divergence
    # Simple Levenshtein or length difference metric
    altered_count = abs(len(r1_text) - len(current_text)) + sum(
        1 for c1, c2 in zip(r1_text, current_text) if c1 != c2
    )

    return NormalizedRepresentation(
        text=current_text,
        character_count=len(current_text),
        transformations_applied=transformations,
        characters_altered_count=altered_count,
    )
