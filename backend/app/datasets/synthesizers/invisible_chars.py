"""Invisible and Control Character Adversarial Attack Synthesizer for RISE-Phish.

Injects zero-width formatting spaces, Plane 14 invisible tag characters,
and bidirectional override control sequences to evade signature-based detection.
"""
import random
from typing import List, Optional

from backend.app.models.schemas import SynthesizedAttackResult

ZERO_WIDTH_CANDIDATES = [
    "\u200b",  # Zero-width space
    "\u200c",  # Zero-width non-joiner
    "\u200d",  # Zero-width joiner
    "\ufeff",  # Zero-width no-break space (BOM)
]

PLANE14_TAG_BASE = 0xE0000  # Plane 14 tag prefix


def inject_zero_width(
    text: str,
    target_brand: Optional[str] = None,
    frequency: float = 0.4,
    seed: Optional[int] = None,
) -> SynthesizedAttackResult:
    """Injects invisible zero-width spaces within words to break tokenizer/regex boundaries.
    
    Args:
        text: Input string.
        target_brand: If specified, targets the brand token.
        frequency: Probability of inserting an invisible char between adjacent characters.
        seed: Random seed for deterministic reproducibility.
    """
    if seed is not None:
        rng = random.Random(seed)
    else:
        rng = random.Random()

    result_chars: List[str] = []
    injected_count = 0

    target = target_brand.lower() if target_brand else None

    words = text.split(" ")
    out_words = []

    for word in words:
        if target and target in word.lower():
            # Intersperse zero-width characters inside target brand
            chars = list(word)
            new_chars = []
            for i, ch in enumerate(chars):
                new_chars.append(ch)
                if i < len(chars) - 1 and rng.random() <= frequency:
                    new_chars.append(rng.choice(ZERO_WIDTH_CANDIDATES))
                    injected_count += 1
            out_words.append("".join(new_chars))
        elif not target:
            chars = list(word)
            new_chars = []
            for i, ch in enumerate(chars):
                new_chars.append(ch)
                if i < len(chars) - 1 and rng.random() <= frequency:
                    new_chars.append(rng.choice(ZERO_WIDTH_CANDIDATES))
                    injected_count += 1
            out_words.append("".join(new_chars))
        else:
            out_words.append(word)

    # Guarantee at least 1 insertion if frequency > 0
    if injected_count == 0 and len(text) > 1 and frequency > 0.0:
        pos = len(text) // 2
        obfuscated = text[:pos] + "\u200b" + text[pos:]
        injected_count = 1
    else:
        obfuscated = " ".join(out_words)

    perturbation_rate = (injected_count / len(text)) if text else 0.0

    return SynthesizedAttackResult(
        original_text=text,
        obfuscated_text=obfuscated,
        attack_types_applied=["zero_width_insertion"],
        characters_perturbed_count=injected_count,
        perturbation_rate=round(perturbation_rate, 4),
        metadata={
            "technique": "zero_width_spaces",
            "seed": seed,
            "target_brand": target_brand,
        },
    )


def inject_tag_characters(
    text: str,
    target_brand: Optional[str] = None,
    seed: Optional[int] = None,
) -> SynthesizedAttackResult:
    """Injects Plane 14 invisible tag characters (U+E0001 - U+E007F) mirroring ASCII payload."""
    target = target_brand if target_brand else text.split()[0]
    
    # Generate tag characters matching target characters
    tag_chars = "".join(chr(PLANE14_TAG_BASE + ord(c)) for c in target if ord(c) < 128)
    obfuscated = text.replace(target, target + tag_chars, 1)

    return SynthesizedAttackResult(
        original_text=text,
        obfuscated_text=obfuscated,
        attack_types_applied=["tag_character_injection"],
        characters_perturbed_count=len(tag_chars),
        perturbation_rate=round(len(tag_chars) / max(1, len(text)), 4),
        metadata={"injected_tag_length": len(tag_chars), "seed": seed},
    )


def inject_bidi_override(
    text: str,
    rlo_char: str = "\u202e",  # Right-to-Left Override
) -> SynthesizedAttackResult:
    """Injects Right-to-Left Override (RLO) control characters to visually invert text display."""
    words = text.split()
    if not words:
        return SynthesizedAttackResult(
            original_text=text,
            obfuscated_text=text,
            attack_types_applied=["bidi_override"],
        )

    # Invert one word using RLO
    target_idx = len(words) // 2
    reversed_word = words[target_idx][::-1]
    obfuscated_word = rlo_char + reversed_word + "\u202c"  # Pop directional formatting
    words[target_idx] = obfuscated_word
    obfuscated = " ".join(words)

    return SynthesizedAttackResult(
        original_text=text,
        obfuscated_text=obfuscated,
        attack_types_applied=["bidi_override"],
        characters_perturbed_count=2,
        perturbation_rate=round(2 / len(text), 4),
        metadata={"rlo_codepoint": f"U+{ord(rlo_char):04X}"},
    )
