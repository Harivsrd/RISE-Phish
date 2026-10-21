"""Task 1: Semantic Recovery Implementation.

Provides prompt engineering, response parsing, and deterministic de-obfuscation
algorithms to recover canonical text from adversarial representation attacks
(homoglyphs, zero-width characters, leetspeak, and rendering discrepancies).
"""
import json
import re
import unicodedata
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.app.models.schemas import SemanticRecoveryResult


# Standardized System Prompt for Task 1
SEMANTIC_RECOVERY_SYSTEM_PROMPT = """You are RISE-Phish's specialized Semantic Recovery engine for cybersecurity text analysis.
Your task is to analyze potentially obfuscated, manipulated, or adversarial text extracted from a webpage and recover its canonical, human-intended semantic representation.

Attackers frequently use:
1. Homoglyphs (e.g., Cyrillic 'а', 'е', 'о', 'р', 'с', 'у', 'х', 'і' inside Latin brand names like 'Mіcrosoft', 'Paypаl').
2. Invisible zero-width characters (e.g., U+200B, U+200C, U+200D, U+FEFF) to break keyword filters.
3. Leetspeak substitutions (e.g., '@' for 'a', '0' for 'o', '1' for 'i'/'l', '$' for 's').
4. Fullwidth or anomalous Unicode normalizations.
5. Bidirectional override characters (U+202E) reversing character sequences.

INSTRUCTIONS:
- Analyze the input text carefully.
- If obfuscation or manipulation is detected, resolve it and restore the canonical brand names and words.
- If the text is natural, authentic language (including valid accented French, German, Spanish, or legitimate non-English scripts), do NOT alter it or flag manipulation unless mixed-script evasion or invisible tricks are present.
- Output MUST be valid JSON adhering strictly to this schema:
{
    "recovered_text": "<the canonical de-obfuscated text>",
    "manipulation_detected": <true or false>,
    "manipulation_tactics": ["<tactic_1>", "<tactic_2>"],
    "recovery_explanation": "<concise explanation of modifications made>",
    "confidence_score": <float between 0.0 and 1.0>,
    "recovered_tokens_count": <integer count of modified tokens>
}
Return ONLY raw JSON without markdown formatting or code blocks.
"""

# Homoglyph substitution map for common lookalikes across Cyrillic and Greek to Latin
HOMOGLYPH_TO_LATIN: Dict[str, str] = {
    # Cyrillic small letters
    "\u0430": "a",  # Cyrillic small letter a
    "\u0441": "c",  # Cyrillic small letter es
    "\u0434": "d",  # Cyrillic small letter de (italic lookalike)
    "\u0435": "e",  # Cyrillic small letter ie
    "\u04bb": "h",  # Cyrillic small letter shha
    "\u0456": "i",  # Cyrillic small letter byelorussian-ukrainian i
    "\u0458": "j",  # Cyrillic small letter je
    "\u043a": "k",  # Cyrillic small letter ka
    "\u043e": "o",  # Cyrillic small letter o
    "\u0440": "p",  # Cyrillic small letter er
    "\u0443": "y",  # Cyrillic small letter u
    "\u0455": "s",  # Cyrillic small letter dze
    "\u0445": "x",  # Cyrillic small letter ha
    # Cyrillic capital letters
    "\u0410": "A",  # Cyrillic capital letter A
    "\u0412": "B",  # Cyrillic capital letter Ve
    "\u0421": "C",  # Cyrillic capital letter Es
    "\u0415": "E",  # Cyrillic capital letter Ie
    "\u041d": "H",  # Cyrillic capital letter En
    "\u0406": "I",  # Cyrillic capital letter Byelorussian-Ukrainian I
    "\u0408": "J",  # Cyrillic capital letter Je
    "\u041a": "K",  # Cyrillic capital letter Ka
    "\u041c": "M",  # Cyrillic capital letter Em
    "\u041e": "O",  # Cyrillic capital letter O
    "\u0420": "P",  # Cyrillic capital letter Er
    "\u0422": "T",  # Cyrillic capital letter Te
    "\u0425": "X",  # Cyrillic capital letter Ha
    "\u0423": "Y",  # Cyrillic capital letter U
    # Greek letters
    "\u03bf": "o",  # Greek small letter omicron
    "\u03bd": "v",  # Greek small letter nu
    "\u0391": "A",  # Greek capital letter Alpha
    "\u0392": "B",  # Greek capital letter Beta
    "\u0395": "E",  # Greek capital letter Epsilon
    "\u0397": "H",  # Greek capital letter Eta
    "\u0399": "I",  # Greek capital letter Iota
    "\u039a": "K",  # Greek capital letter Kappa
    "\u039c": "M",  # Greek capital letter Mu
    "\u039d": "N",  # Greek capital letter Nu
    "\u039f": "O",  # Greek capital letter Omicron
    "\u03a1": "P",  # Greek capital letter Rho
    "\u03a4": "T",  # Greek capital letter Tau
    "\u03a7": "X",  # Greek capital letter Chi
}

# Invisible characters to strip
ZERO_WIDTH_CHARS: Set[str] = {
    "\u200b",  # Zero-width space
    "\u200c",  # Zero-width non-joiner
    "\u200d",  # Zero-width joiner
    "\ufeff",  # Zero-width no-break space (BOM)
    "\u2060",  # Word joiner
    "\u00ad",  # Soft hyphen
}

# BiDi directional control characters
BIDI_CONTROLS: Set[str] = {
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",  # LRE, RLE, PDF, LRO, RLO
    "\u2066", "\u2067", "\u2068", "\u2069",            # LRI, RLI, FSI, PDI
}

# Well-known brand names targeted by leetspeak / homoglyphs
CANONICAL_TARGET_BRANDS: List[str] = [
    "microsoft", "paypal", "google", "apple", "amazon", "netflix",
    "facebook", "instagram", "chase", "bankofamerica", "wellsfargo",
    "binance", "coinbase", "metamask", "dhl", "fedex", "dropbox",
]


def build_semantic_recovery_prompt(text: str) -> str:
    """Constructs the user prompt for Task 1 Semantic Recovery."""
    return f"""Analyze the following input text for adversarial obfuscation, homoglyphs, or rendering manipulation.
Recover the canonical text if manipulation is found.

INPUT TEXT:
\"\"\"{text}\"\"\"

Return your response strictly as valid JSON adhering to the specified schema."""


def parse_semantic_recovery_response(raw_response: str) -> SemanticRecoveryResult:
    """Robustly parses, cleans, and validates the SLM output for Task 1."""
    cleaned = raw_response.strip()

    # Strip markdown code blocks if the SLM wrapped the JSON
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
        cleaned = cleaned.strip()

    try:
        data = json.loads(cleaned)
        return SemanticRecoveryResult(
            recovered_text=str(data.get("recovered_text", "")),
            manipulation_detected=bool(data.get("manipulation_detected", False)),
            manipulation_tactics=list(data.get("manipulation_tactics", [])),
            recovery_explanation=str(data.get("recovery_explanation", "")),
            confidence_score=float(data.get("confidence_score", 1.0)),
            recovered_tokens_count=int(data.get("recovered_tokens_count", 0)),
        )
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        # Fallback: Perform deterministic algorithmic recovery if JSON was malformed
        fallback = algorithmic_semantic_recovery(raw_response)
        fallback.recovery_explanation = (
            f"SLM output was not valid JSON ({str(exc)}); fell back to deterministic recovery."
        )
        fallback.confidence_score = 0.70
        return fallback


def _detect_dominant_script(token: str) -> str:
    """Determines dominant Unicode script of a token ('Latin', 'Cyrillic', etc.)."""
    scripts: Dict[str, int] = {}
    for ch in token:
        name = unicodedata.name(ch, "").upper()
        if "LATIN" in name:
            scripts["Latin"] = scripts.get("Latin", 0) + 1
        elif "CYRILLIC" in name:
            scripts["Cyrillic"] = scripts.get("Cyrillic", 0) + 1
        elif "GREEK" in name:
            scripts["Greek"] = scripts.get("Greek", 0) + 1
    if not scripts:
        return "Unknown"
    return max(scripts.items(), key=lambda x: x[1])[0]


def algorithmic_semantic_recovery(text: str) -> SemanticRecoveryResult:
    """Deterministic, rule-assisted de-obfuscation pipeline.
    
    Acts as a high-precision baseline and test oracle, resolving:
    - Homoglyph lookalikes in mixed-script tokens
    - Invisible zero-width and Plane 14 tag characters
    - Directional BiDi override sequences
    - Fullwidth NFKC normalizations
    - Targeted brand leetspeak obfuscation
    
    Args:
        text: Raw input text sequence.
        
    Returns:
        SemanticRecoveryResult with canonical text and manipulation audit.
    """
    if not text:
        return SemanticRecoveryResult(
            recovered_text="",
            manipulation_detected=False,
            manipulation_tactics=[],
            recovery_explanation="Input text was empty.",
            confidence_score=1.0,
            recovered_tokens_count=0,
        )

    tactics: Set[str] = set()
    explanations: List[str] = []
    
    # 1. Check for Plane 14 tag characters (U+E0001 - U+E007F)
    has_tag_chars = any(0xE0001 <= ord(ch) <= 0xE007F for ch in text)
    if has_tag_chars:
        tactics.add("tag_character_injection")
        explanations.append("Stripped Plane 14 invisible tag characters.")
        text = "".join(ch for ch in text if not (0xE0001 <= ord(ch) <= 0xE007F))

    # 2. Check for BiDi override characters
    has_bidi = any(ch in BIDI_CONTROLS for ch in text)
    if has_bidi:
        tactics.add("bidi_override")
        explanations.append("Removed bidirectional override control characters.")
        text = "".join(ch for ch in text if ch not in BIDI_CONTROLS)

    # 3. Check for zero-width characters
    has_zero_width = any(ch in ZERO_WIDTH_CHARS for ch in text)
    if has_zero_width:
        tactics.add("zero_width_insertion")
        explanations.append("Stripped zero-width formatting characters.")
        text = "".join(ch for ch in text if ch not in ZERO_WIDTH_CHARS)

    # 4. Check for Fullwidth normalization differences
    nfkc_text = unicodedata.normalize("NFKC", text)
    if nfkc_text != text:
        # Check if fullwidth ASCII was resolved
        has_fullwidth = any(0xFF01 <= ord(ch) <= 0xFF5E for ch in text)
        if has_fullwidth:
            tactics.add("fullwidth_normalization")
            explanations.append("Normalized fullwidth ASCII variants.")
        text = nfkc_text

    # 5. Token-level analysis: Homoglyphs & Leetspeak
    tokens = text.split()
    recovered_tokens: List[str] = []
    tokens_modified_count = 0

    for token in tokens:
        modified_token = token
        token_tactics: Set[str] = set()
        
        # Check dominant script of the token
        dominant_script = _detect_dominant_script(token)

        # Homoglyph detection: if token is predominantly Latin or mixed, check for lookalikes
        if dominant_script == "Latin" or any(ch in HOMOGLYPH_TO_LATIN for ch in token):
            # Check if token contains a homoglyph
            chars = list(token)
            homoglyph_found = False
            for idx, ch in enumerate(chars):
                if ch in HOMOGLYPH_TO_LATIN:
                    # In a Latin context, replace with Latin equivalent
                    # But don't do it if the entire token is monolingual Cyrillic / Greek
                    if dominant_script in ("Latin", "Unknown"):
                        chars[idx] = HOMOGLYPH_TO_LATIN[ch]
                        homoglyph_found = True
            
            if homoglyph_found:
                new_token = "".join(chars)
                if new_token != token:
                    modified_token = new_token
                    token_tactics.add("homoglyph_substitution")

        # Leetspeak detection for high-profile targeted brands
        # e.g., p@ypal -> paypal, micr0s0ft -> microsoft, g00gle -> google
        cleaned_alpha = re.sub(r"[^a-zA-Z0-9@\$_]", "", modified_token).lower()
        de_leet = (
            cleaned_alpha
            .replace("@", "a")
            .replace("0", "o")
            .replace("1", "l")
            .replace("$", "s")
            .replace("3", "e")
            .replace("5", "s")
        )

        for brand in CANONICAL_TARGET_BRANDS:
            if de_leet == brand and cleaned_alpha != brand:
                # Target brand obfuscated via leetspeak
                # Restore canonical brand casing/format
                modified_token = brand
                token_tactics.add("leetspeak")
                break

        if modified_token != token:
            tokens_modified_count += 1
            tactics.update(token_tactics)

        recovered_tokens.append(modified_token)

    reconstructed_text = " ".join(recovered_tokens)
    manipulation_detected = len(tactics) > 0 or tokens_modified_count > 0

    if manipulation_detected and not explanations:
        if "homoglyph_substitution" in tactics:
            explanations.append("Replaced cross-script homoglyphs with canonical Latin letters.")
        if "leetspeak" in tactics:
            explanations.append("Decoded leetspeak character substitutions targeting protected brands.")

    confidence = 0.95 if manipulation_detected else 1.0

    return SemanticRecoveryResult(
        recovered_text=reconstructed_text,
        manipulation_detected=manipulation_detected,
        manipulation_tactics=sorted(list(tactics)),
        recovery_explanation=" ".join(explanations) if explanations else "No adversarial manipulation detected.",
        confidence_score=confidence,
        recovered_tokens_count=tokens_modified_count,
    )
