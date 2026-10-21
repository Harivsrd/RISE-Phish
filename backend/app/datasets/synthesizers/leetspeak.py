"""Leetspeak Obfuscation Synthesizer for RISE-Phish.

Applies common visual symbol and digit substitutions targeted at protected brand names
(e.g., 'PayPal' -> 'P@ypal', 'Microsoft' -> 'Micr0s0ft', 'Google' -> 'G00gle').
"""
import random
from typing import Dict, List, Optional

from backend.app.models.schemas import SynthesizedAttackResult

LEET_MAP: Dict[str, List[str]] = {
    "a": ["@", "4"],
    "e": ["3"],
    "i": ["1", "!"],
    "l": ["1", "|"],
    "o": ["0"],
    "s": ["$", "5"],
    "t": ["7", "+"],
}


def inject_leetspeak(
    text: str,
    target_brand: Optional[str] = None,
    rate: float = 0.5,
    seed: Optional[int] = None,
) -> SynthesizedAttackResult:
    """Substitutes letters with leetspeak symbols."""
    if seed is not None:
        rng = random.Random(seed)
    else:
        rng = random.Random()

    chars = list(text)
    perturbed_count = 0

    if target_brand and target_brand.lower() in text.lower():
        start = text.lower().find(target_brand.lower())
        brand_len = len(target_brand)
        for i in range(start, start + brand_len):
            low = chars[i].lower()
            if low in LEET_MAP and rng.random() <= rate:
                chars[i] = rng.choice(LEET_MAP[low])
                perturbed_count += 1
    else:
        for i, ch in enumerate(chars):
            low = ch.lower()
            if low in LEET_MAP and rng.random() <= rate:
                chars[i] = rng.choice(LEET_MAP[low])
                perturbed_count += 1

    # Guarantee at least 1 mutation if possible
    if perturbed_count == 0 and rate > 0.0:
        candidates = [i for i, c in enumerate(chars) if c.lower() in LEET_MAP]
        if candidates:
            idx = rng.choice(candidates)
            chars[idx] = rng.choice(LEET_MAP[chars[idx].lower()])
            perturbed_count = 1

    obfuscated_str = "".join(chars)
    perturbation_rate = (perturbed_count / len(text)) if text else 0.0

    return SynthesizedAttackResult(
        original_text=text,
        obfuscated_text=obfuscated_str,
        attack_types_applied=["leetspeak"],
        characters_perturbed_count=perturbed_count,
        perturbation_rate=round(perturbation_rate, 4),
        metadata={"target_brand": target_brand, "seed": seed},
    )
