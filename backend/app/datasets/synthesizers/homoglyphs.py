"""Homoglyph Adversarial Attack Synthesizer for RISE-Phish.

Generates realistic cross-script visual spoofing attacks by substituting Latin
characters in target brands with lookalike characters from Cyrillic and Greek scripts.
"""
import random
from typing import Dict, List, Optional, Tuple

from backend.app.models.schemas import SynthesizedAttackResult

# Comprehensive Latin-to-Lookalike mapping across Cyrillic and Greek
LATIN_TO_HOMOGLYPH: Dict[str, List[str]] = {
    # Small letters
    "a": ["\u0430"],          # Cyrillic small letter a
    "c": ["\u0441"],          # Cyrillic small letter es
    "d": ["\u0434"],          # Cyrillic small letter de
    "e": ["\u0435"],          # Cyrillic small letter ie
    "h": ["\u04bb"],          # Cyrillic small letter shha
    "i": ["\u0456", "\u0458"], # Cyrillic small letter byelorussian-ukrainian i, je
    "j": ["\u0458"],          # Cyrillic small letter je
    "k": ["\u043a"],          # Cyrillic small letter ka
    "o": ["\u043e", "\u03bf"], # Cyrillic small letter o, Greek small omicron
    "p": ["\u0440"],          # Cyrillic small letter er
    "s": ["\u0455"],          # Cyrillic small letter dze
    "v": ["\u03bd"],          # Greek small letter nu (lookalike for v)
    "x": ["\u0445"],          # Cyrillic small letter ha
    "y": ["\u0443"],          # Cyrillic small letter u
    # Capital letters
    "A": ["\u0410", "\u0391"], # Cyrillic A, Greek Alpha
    "B": ["\u0412", "\u0392"], # Cyrillic Ve, Greek Beta
    "C": ["\u0421"],          # Cyrillic Es
    "E": ["\u0415", "\u0395"], # Cyrillic Ie, Greek Epsilon
    "H": ["\u041d", "\u0397"], # Cyrillic En, Greek Eta
    "I": ["\u0406", "\u0399"], # Cyrillic I, Greek Iota
    "J": ["\u0408"],          # Cyrillic Je
    "K": ["\u041a", "\u039a"], # Cyrillic Ka, Greek Kappa
    "M": ["\u041c", "\u039c"], # Cyrillic Em, Greek Mu
    "N": ["\u039d"],          # Greek Nu
    "O": ["\u041e", "\u039f"], # Cyrillic O, Greek Omicron
    "P": ["\u0420", "\u03a1"], # Cyrillic Er, Greek Rho
    "T": ["\u0422", "\u03a4"], # Cyrillic Te, Greek Tau
    "X": ["\u0425", "\u03a7"], # Cyrillic Ha, Greek Chi
    "Y": ["\u0423"],          # Cyrillic U
}


def inject_homoglyphs(
    text: str,
    target_brand: Optional[str] = None,
    rate: float = 0.5,
    seed: Optional[int] = None,
) -> SynthesizedAttackResult:
    """Injects lookalike homoglyphs into text or specific brand occurrences.
    
    Args:
        text: Input text sequence.
        target_brand: If specified, restricts homoglyphs primarily to that brand word.
        rate: Probability of replacing a candidate character (0.0 to 1.0).
        seed: Random seed for deterministic reproducibility.
        
    Returns:
        SynthesizedAttackResult with obfuscated string, perturbed count, and metadata.
    """
    if seed is not None:
        rng = random.Random(seed)
    else:
        rng = random.Random()

    chars = list(text)
    perturbed_indices: List[Tuple[int, str, str]] = []

    if target_brand and target_brand.lower() in text.lower():
        # Find occurrences of the target brand
        lower_text = text.lower()
        brand_len = len(target_brand)
        start = 0
        while True:
            idx = lower_text.find(target_brand.lower(), start)
            if idx == -1:
                break
            # Mutate characters within this brand token
            for i in range(idx, idx + brand_len):
                orig_ch = chars[i]
                if orig_ch in LATIN_TO_HOMOGLYPH and rng.random() <= rate:
                    replacement = rng.choice(LATIN_TO_HOMOGLYPH[orig_ch])
                    chars[i] = replacement
                    perturbed_indices.append((i, orig_ch, replacement))
            start = idx + brand_len
    else:
        # Global substitution based on rate
        for i, ch in enumerate(chars):
            if ch in LATIN_TO_HOMOGLYPH and rng.random() <= rate:
                replacement = rng.choice(LATIN_TO_HOMOGLYPH[ch])
                chars[i] = replacement
                perturbed_indices.append((i, ch, replacement))

    # Guarantee at least 1 substitution if candidates exist and rate > 0
    if not perturbed_indices and rate > 0.0:
        candidates = [i for i, ch in enumerate(chars) if ch in LATIN_TO_HOMOGLYPH]
        if candidates:
            chosen = rng.choice(candidates)
            orig_ch = chars[chosen]
            rep = rng.choice(LATIN_TO_HOMOGLYPH[orig_ch])
            chars[chosen] = rep
            perturbed_indices.append((chosen, orig_ch, rep))

    obfuscated_str = "".join(chars)
    perturbed_count = len(perturbed_indices)
    perturbation_rate = (perturbed_count / len(text)) if text else 0.0

    return SynthesizedAttackResult(
        original_text=text,
        obfuscated_text=obfuscated_str,
        attack_types_applied=["homoglyph_substitution"],
        characters_perturbed_count=perturbed_count,
        perturbation_rate=round(perturbation_rate, 4),
        metadata={
            "substitutions": [
                {"pos": pos, "from": f, "to": t, "codepoint": f"U+{ord(t):04X}"}
                for pos, f, t in perturbed_indices
            ],
            "target_brand": target_brand,
            "seed": seed,
        },
    )
